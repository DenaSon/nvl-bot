"""CZ-03: Cloudzy purchase + Legacy Edge onboarding, never a customer cutover.

Safeguards: explicit operator approval, SQLite durable single-flight receipt BEFORE
chargeable API call, provider idempotency key, no blind retry of uncertain writes,
independent SSH-host-key approval, Legacy protected gate, and inactive host_pool
registration. A crashed/ambiguous provisioning is HOLD, never blindly replayed.
No K2 transfer, account host assignment, DNS or Relay switch exists here.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
from html import escape
import ipaddress
import re
import secrets
import socket
import time
import uuid

from cloudzy_service import (
    CloudzyAPIError, CloudzyError, CloudzyService, CloudzyUncertainError,
    CloudzyTimeout,
)

CHARGEABLE_STATES = frozenset({
    "CREATING", "CREATE_UNCERTAIN", "CREATED", "WAITING", "HOLD_WAIT",
    "HOLD_IP", "HOLD_SSH", "HOSTKEY_PENDING", "PROVISIONING",
    "HOLD_PROVISION", "HOLD_PREFLIGHT", "HOLD_PROVIDER", "HOLD_UNKNOWN",
})
CYCLES = {"monthly": "ماهانه", "hourly": "ساعتی",
          "quarterly": "سه‌ماهه", "annually": "سالانه"}
TTL_SECONDS = 600
PAGE_SIZE = 6
OS_TEMPLATE = "ubuntu-24.04"
ID_PATTERN = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,98}\Z")


class QuickEdgeHold(RuntimeError):
    """Safe failure: action cannot be repeated until explicit reconciliation."""


def _safe_id(v):
    if not isinstance(v, str) or not ID_PATTERN.fullmatch(v):
        raise QuickEdgeHold("INVALID_PROVIDER_IDENTIFIER")
    return v


def _obj(value):
    if not isinstance(value, dict):
        return {}
    inner = value.get("data")
    root = inner if isinstance(inner, dict) else value
    for field in ("service", "server", "result"):
        if isinstance(root.get(field), dict):
            return root[field]
    return root


def _items(value):
    if isinstance(value, list):
        return [x for x in value if isinstance(x, dict)]
    if isinstance(value, dict):
        for root in (value, _obj(value)):
            for k in ("regions", "services", "items", "data"):
                if isinstance(root.get(k), list):
                    return [x for x in root[k] if isinstance(x, dict)]
    return []


def _val(record, *keys):
    if not isinstance(record, dict):
        return None
    for name in keys:
        v = record.get(name)
        if v is not None and v != "":
            return v
    return None


def _text(s):
    return escape(str(s)[:90])


def _server_id(response):
    v = _val(_obj(response), "id", "serviceId", "serverId", "uuid")
    return _safe_id(v)


def _public_ipv4(response):
    root = _obj(response)
    candidates = []
    for key in ("primaryIpv4", "primaryIPv4", "ipv4", "publicIp", "ipAddress", "ip"):
        v = root.get(key)
        if isinstance(v, str):
            candidates.append(v)
    for key in ("ips", "ipAddresses", "addresses"):
        iplist = root.get(key)
        if isinstance(iplist, list):
            for item in iplist:
                if isinstance(item, str):
                    candidates.append(item)
                elif isinstance(item, dict):
                    candidates.extend(str(x) for x in (
                        _val(item, "address", "ip", "ipAddress", "ipv4"),) if x is not None)
    for candidate in candidates:
        try:
            ip = ipaddress.IPv4Address(candidate)
            if ip.is_global:
                return str(ip)
        except (ipaddress.AddressValueError, ValueError):
            pass
    raise QuickEdgeHold("CLOUDZY_PUBLIC_IPV4_NOT_ATTESTED")


def capture_ssh_host_key(ip, *, timeout=10):
    """Untrusted first observation only. Operator MUST compare fingerprint independently."""
    import paramiko
    ipaddress.IPv4Address(ip)
    with socket.create_connection((ip, 22), timeout=timeout) as connection:
        transport = paramiko.Transport(connection)
        try:
            transport.banner_timeout = timeout
            transport.start_client(timeout=timeout)
            host_key = transport.get_remote_server_key()
            if host_key is None:
                raise QuickEdgeHold("SSH_HOST_KEY_MISSING")
            encoded = host_key.get_base64()
            fingerprint = base64.b64encode(hashlib.sha256(host_key.asbytes()).digest()).decode("ascii").rstrip("=")
            return host_key.get_name(), encoded, "SHA256:" + fingerprint
        finally:
            transport.close()


class ReceiptStore:
    """Small local SQLite journal; no raw provider response, private keys or root password."""

    def __init__(self, conn_factory, *, now=time.time):
        self.db = conn_factory
        self.now = now

    def initialize(self):
        with self.db() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS cloudzy_edge_operations (
                id TEXT PRIMARY KEY,
                actor_id INTEGER NOT NULL,
                chat_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                hostname TEXT NOT NULL UNIQUE,
                region TEXT NOT NULL,
                plan_id TEXT NOT NULL,
                billing_cycle TEXT NOT NULL,
                price_cents INTEGER NOT NULL,
                customer_port INTEGER NOT NULL,
                public_key_sha TEXT NOT NULL,
                idempotency_key TEXT NOT NULL UNIQUE,
                provider_server_id TEXT UNIQUE,
                public_ipv4 TEXT,
                host_key_type TEXT,
                host_key_base64 TEXT,
                host_key_fingerprint TEXT,
                hold_reason TEXT
            )""")
            db.execute("""CREATE UNIQUE INDEX IF NOT EXISTS cloudzy_edge_one_unfinished
                ON cloudzy_edge_operations((1)) WHERE status != 'EDGE_READY'""")

    def reserve(self, *, actor, chat, region, plan, cycle, price, port, pubkey):
        region, plan = _safe_id(region), _safe_id(plan)
        if cycle not in CYCLES or not (isinstance(price, int) and price > 0):
            raise QuickEdgeHold("INVALID_PURCHASE_SELECTION")
        if type(actor) is not int or type(chat) is not int or not 1 <= port <= 65535:
            raise QuickEdgeHold("INVALID_OWNER_OR_PORT")
        self.initialize()
        operation_id = uuid.uuid4().hex
        hostname = "nvl-edge-" + operation_id[:12]
        key = "nvl-cz03-" + operation_id
        timestamp = int(self.now())
        try:
            with self.db() as db:
                db.execute("BEGIN IMMEDIATE")
                prior = db.execute(
                    "SELECT id FROM cloudzy_edge_operations WHERE status!='EDGE_READY' LIMIT 1"
                ).fetchone()
                if prior:
                    raise QuickEdgeHold("PREVIOUS_CLOUDZY_OPERATION_UNSETTLED")
                db.execute("""INSERT INTO cloudzy_edge_operations
                    (id,actor_id,chat_id,status,created_at,updated_at,
                     hostname,region,plan_id,billing_cycle,price_cents,customer_port,
                     public_key_sha,idempotency_key)
                    VALUES (?,?,?,'CREATING',?,?,?,?,?,?,?,?,?,?)""",
                    (operation_id, actor, chat, timestamp, timestamp, hostname,
                     region, plan, cycle, price, port,
                     hashlib.sha256(pubkey.encode("utf-8")).hexdigest(), key))
        except Exception as exc:
            if isinstance(exc, QuickEdgeHold):
                raise
            raise QuickEdgeHold("OPERATION_JOURNAL_FAILED") from None
        return operation_id

    def get(self, operation_id):
        if not isinstance(operation_id, str) or not re.fullmatch("[0-9a-f]{32}", operation_id):
            raise QuickEdgeHold("INVALID_OPERATION")
        self.initialize()
        with self.db() as db:
            db.row_factory = __import__("sqlite3").Row
            row = db.execute("SELECT * FROM cloudzy_edge_operations WHERE id=?", (operation_id,)).fetchone()
            if row is None:
                raise QuickEdgeHold("OPERATION_MISSING")
            return dict(row)

    def latest(self):
        self.initialize()
        with self.db() as db:
            row = db.execute("SELECT id FROM cloudzy_edge_operations ORDER BY created_at DESC LIMIT 1").fetchone()
        return self.get(row[0]) if row else None

    def change(self, operation_id, old, new, **fields):
        permitted = {"provider_server_id", "public_ipv4", "host_key_type",
                     "host_key_base64", "host_key_fingerprint", "hold_reason"}
        if any(k not in permitted for k in fields):
            raise QuickEdgeHold("UNSAFE_JOURNAL_FIELD")
        assignments = ", ".join([f"{k}=?" for k in fields] + ["status=?", "updated_at=?"])
        with self.db() as db:
            cur = db.execute(
                f"UPDATE cloudzy_edge_operations SET {assignments} WHERE id=? AND status=?",
                [*fields.values(), new, int(self.now()), operation_id, old]
            )
            if cur.rowcount != 1:
                raise QuickEdgeHold("STATE_CHANGED_OR_OPERATION_UNSETTLED")


class QuickEdgeWizard:
    def __init__(self, *, conn_factory, preflight, provision, verify,
                 cloudzy_factory=CloudzyService, fingerprint=capture_ssh_host_key,
                 now=time.time):
        self.store = ReceiptStore(conn_factory, now=now)
        self.preflight = preflight
        self.provision = provision
        self.verify = verify
        self.cloudzy_factory = cloudzy_factory
        self.fingerprint = fingerprint
        self.now = now

    async def _cloudzy(self, method, *args, **kwargs):
        return await asyncio.to_thread(
            lambda: getattr(self.cloudzy_factory(), method)(*args, **kwargs)
        )

    async def _preflight(self):
        # Implemented by NVL Core, not the provider; validates protected mode,
        # current failover journal, exact Core files, key and current customer port.
        return await asyncio.to_thread(self.preflight)

    def _session(self, ctx, actor, chat):
        session = ctx.user_data.get("cz3")
        if (not isinstance(session, dict) or session.get("actor") != actor
                or session.get("chat") != chat or self.now() >= session.get("expires", 0)):
            raise QuickEdgeHold("SESSION_EXPIRED")
        return session

    @staticmethod
    def _token(items):
        return {secrets.token_hex(4): item for item in items}

    async def _display(self, query, text, rows, markup):
        await query.edit_message_text(text, parse_mode="HTML", reply_markup=markup(rows))

    async def handle_callback(self, query, context, data, *, actor, chat, role, app, markup):
        if role != "admin":
            await query.message.reply_text("⛔️ فقط مدیر مجاز است.")
            return
        try:
            if data == "apps_cz_wizard":
                self.store.initialize()
                old = await asyncio.to_thread(self.store.latest)
                if old and old["status"] != "EDGE_READY":
                    await self._operation_screen(query, old, markup, actor, chat)
                    return
                port, pub = await self._preflight()
                regions = _items(await self._cloudzy("list_regions"))
                valid = [(str(_val(r, "id", "code") or ""), str(_val(r, "name", "id") or "منطقه")) for r in regions]
                valid = [(v, title) for v, title in valid if ID_PATTERN.fullmatch(v)]
                tokens = self._token(valid[:48])
                context.user_data["cz3"] = {
                    "actor": actor, "chat": chat, "expires": self.now() + TTL_SECONDS,
                    "regions": tokens, "port": port,
                    "pub_sha": hashlib.sha256(pub.encode()).hexdigest(),
                    "cycle": "monthly"
                }
                rows = [[("🌍 " + name[:27], "apps_cz_qr_" + token)] for token, (_, name) in tokens.items()]
                rows.append([("↩️ Cloudzy", "apps_cz_home")])
                await self._display(query, "⚡ <b>ساخت سریع Edge</b>\n\n"
                    "۱. منطقه Cloudzy را انتخاب کنید.\n"
                    "✅ نصب با مسیر Legacy؛ سیستم‌عامل ثابت و بدون انتخاب.\n"
                    "⚠️ هنوز خریدی انجام نشده و Relay فعلی تغییر نمی‌کند.",
                    rows, markup)
            elif data.startswith("apps_cz_qr_"):
                s = self._session(context, actor, chat)
                chosen = s["regions"].get(data[len("apps_cz_qr_"):])
                if not chosen:
                    raise QuickEdgeHold("INVALID_REGION")
                s["region"], s["region_name"] = chosen
                await self._plans(query, s, markup)
            elif data.startswith("apps_cz_qcy_"):
                s = self._session(context, actor, chat)
                cycle = data[len("apps_cz_qcy_"):]
                if cycle not in CYCLES or "region" not in s:
                    raise QuickEdgeHold("INVALID_CYCLE_OR_REGION")
                s["cycle"] = cycle
                await self._plans(query, s, markup)
            elif data.startswith("apps_cz_qpg_"):
                s = self._session(context, actor, chat)
                page = data[len("apps_cz_qpg_"):]
                if not re.fullmatch("[0-9]{1,3}", page):
                    raise QuickEdgeHold("INVALID_PAGE")
                await self._plans(query, s, markup, page=int(page))
            elif data.startswith("apps_cz_qp_"):
                s = self._session(context, actor, chat)
                selected = s.get("plans", {}).get(data[len("apps_cz_qp_"):])
                if not selected:
                    raise QuickEdgeHold("INVALID_PLAN")
                plan_id, name, price, scope, price_basis = selected
                s.update(plan=plan_id, name=name, price=price,
                         scope=scope, price_basis=price_basis)
                s["nonce"] = secrets.token_hex(8)
                await self._display(query,
                    "⚠️ <b>تأیید خرید VPS جدید</b>\n\n"
                    f"منطقه: {_text(s['region_name'])}\n"
                    f"پلن: {_text(name)}\n"
                    f"دوره: {CYCLES[s['cycle']]}\n"
                    f"قیمت پایه کاتالوگ: {_text(price)} سنت ({_text(s['price_basis'])}، {_text(scope)})\n"
                    f"پورت سرویس SSH: {_text(s['port'])}\n\n"
                    "⚠️ هزینه IPv4 و سایر افزونه‌ها ممکن است جدا محاسبه شود. "
                    "این عدد قیمت نهایی تضمین‌شده نیست.\n"
                    "✅ با تأیید، درخواست خرید واقعی و پرداخت از موجودی Cloudzy ارسال می‌شود.\n"
                    "🛡 هیچ کاربر، DNS یا Relay فعلی منتقل نمی‌شود.",
                    [[("✅ خرید VPS با شرایط اعلام‌شده", "apps_cz_qbuy_" + s["nonce"])],
                     [("❌ انصراف", "apps_cz_home")]], markup)
            elif data.startswith("apps_cz_qbuy_"):
                s = self._session(context, actor, chat)
                nonce = s.pop("nonce", None)  # one-use, even across duplicate callback
                if not nonce or nonce != data[len("apps_cz_qbuy_"):]:
                    raise QuickEdgeHold("CONFIRMATION_EXPIRED")
                if not all(k in s for k in ("region", "plan", "price", "cycle", "port", "pub_sha")):
                    raise QuickEdgeHold("INVALID_SELECTION")
                port, pub = await self._preflight()
                if port != s["port"] or hashlib.sha256(pub.encode()).hexdigest() != s["pub_sha"]:
                    raise QuickEdgeHold("SSH_PORT_OR_KEY_CHANGED")
                opid = await asyncio.to_thread(
                    self.store.reserve, actor=actor, chat=chat, region=s["region"],
                    plan=s["plan"], cycle=s["cycle"], price=s["price"],
                    port=port, pubkey=pub,
                )
                context.user_data.pop("cz3", None)
                await self._display(query,
                    f"⏳ <b>درخواست خرید Cloudzy ثبت شد</b>\n"
                    f"شناسه عملیات: <code>{opid[:16]}</code>\n"
                    "نتیجه را از «وضعیت عملیات» بررسی کنید؛ تأیید مجدد خرید نزنید.",
                    [[("📋 وضعیت عملیات", "apps_cz_operations")]], markup)
                app.create_task(self._buy(opid, chat, pub, app))
            elif data == "apps_cz_operations":
                op = await asyncio.to_thread(self.store.latest)
                if not op:
                    await self._display(query, "📋 هنوز عملیات Cloudzy ثبت نشده است.",
                        [[("↩️ Cloudzy", "apps_cz_home")]], markup)
                else:
                    await self._operation_screen(query, op, markup, actor, chat)
            elif data.startswith("apps_cz_qview_"):
                op = await asyncio.to_thread(self.store.get, data[len("apps_cz_qview_"):])
                await self._operation_screen(query, op, markup, actor, chat)
            elif data.startswith("apps_cz_qcheck_"):
                opid = data[len("apps_cz_qcheck_"):]
                op = await asyncio.to_thread(self.store.get, opid)
                if op["actor_id"] != actor or op["chat_id"] != chat:
                    raise QuickEdgeHold("OPERATION_OWNER_MISMATCH")
                if op["status"] not in ("CREATE_UNCERTAIN", "CREATED", "HOLD_WAIT", "HOLD_IP", "HOLD_SSH"):
                    raise QuickEdgeHold("RECONCILIATION_UNAVAILABLE")
                # Only ONE read-only reconciliation task; no create/provision retry.
                await self._display(query, "🔎 در حال بررسی مجدد وضعیت VPS بدون خرید تازه...",
                    [[("📋 وضعیت", "apps_cz_operations")]], markup)
                app.create_task(self._reconcile(opid, chat, app))
            elif data.startswith("apps_cz_qreview_"):
                opid = data[len("apps_cz_qreview_"):]
                op = await asyncio.to_thread(self.store.get, opid)
                if op["actor_id"] != actor or op["chat_id"] != chat or op["status"] != "HOSTKEY_PENDING":
                    raise QuickEdgeHold("NOT_READY_FOR_HOST_KEY_APPROVAL")
                context.user_data["cz3_host_review"] = {
                    "id": opid, "actor": actor, "chat": chat,
                    "expires": self.now() + 180,
                    "fingerprint": op["host_key_fingerprint"]
                }
                await self._display(query,
                    "🔐 <b>آخرین بررسی هویت SSH</b>\n\n"
                    f"IP: <code>{_text(op['public_ipv4'])}</code>\n"
                    f"اثر انگشت: <code>{_text(op['host_key_fingerprint'])}</code>\n\n"
                    "⚠️ فقط اگر این اثر انگشت را با یک منبع مستقل و مورداعتماد "
                    "(مثل کنسول سرور در Cloudzy) تطبیق داده‌اید، تأیید کنید. "
                    "مقایسه با همان اتصال SSH کافی نیست.",
                    [[("✅ اثر انگشت را مستقل بررسی کردم", "apps_cz_qaccept_" + opid)],
                     [("❌ بازگشت بدون نصب", "apps_cz_operations")]], markup)
            elif data.startswith("apps_cz_qaccept_"):
                opid = data[len("apps_cz_qaccept_"):]
                op = await asyncio.to_thread(self.store.get, opid)
                if op["actor_id"] != actor or op["chat_id"] != chat or op["status"] != "HOSTKEY_PENDING":
                    raise QuickEdgeHold("NOT_READY_FOR_HOST_KEY_APPROVAL")
                expected = context.user_data.pop("cz3_host_review", None)
                if (not isinstance(expected, dict) or expected.get("id") != opid
                        or expected.get("actor") != actor or expected.get("chat") != chat
                        or self.now() >= expected.get("expires", 0)
                        or expected.get("fingerprint") != op["host_key_fingerprint"]):
                    raise QuickEdgeHold("HOST_FINGERPRINT_APPROVAL_EXPIRED")
                # Fresh Core/Legacy preflight before any external provisioning.
                port, pub = await self._preflight()
                if port != op["customer_port"] or hashlib.sha256(pub.encode()).hexdigest() != op["public_key_sha"]:
                    raise QuickEdgeHold("PORT_OR_SSH_KEY_CHANGED")
                await asyncio.to_thread(self.store.change, opid, "HOSTKEY_PENDING", "PROVISIONING")
                await self._display(query, "🛠 شروع نصب Legacy Edge با کلید SSH تأییدشده.\n"
                    "این مرحله ممکن است بخشی از سرور و WireGuard را تغییر دهد؛ "
                    "اگر عملیات نامعلوم ماند، نصب را دوباره شروع نکنید.",
                    [[("📋 وضعیت", "apps_cz_operations")]], markup)
                app.create_task(self._install(opid, chat, app))
            elif data == "apps_cz_qsavekey":
                port, pub = await self._preflight()
                digest = hashlib.sha256(pub.encode()).hexdigest()
                nonce = secrets.token_hex(8)
                context.user_data["cz3_addkey"] = {
                    "actor": actor, "chat": chat,
                    "expires": self.now() + 180, "nonce": nonce, "digest": digest}
                await self._display(query, "🔑 <b>ثبت کلید عمومی مدیریت Core در Cloudzy</b>\n"
                    "فقط Public Key ارسال می‌شود؛ کلید خصوصی از Core خارج نمی‌شود.\n"
                    "این عملیات کلید ذخیره‌شده جدیدی در حساب Cloudzy ایجاد می‌کند.",
                    [[("✅ ثبت کلید عمومی Core", "apps_cz_qkeyyes_" + nonce)],
                     [("❌ انصراف", "apps_cz_keys_0")]], markup)
            elif data.startswith("apps_cz_qkeyyes_"):
                pending = context.user_data.pop("cz3_addkey", None)
                if (not isinstance(pending, dict) or pending.get("actor") != actor
                        or pending.get("chat") != chat
                        or self.now() >= pending.get("expires", 0)
                        or pending.get("nonce") != data[len("apps_cz_qkeyyes_"):]):
                    raise QuickEdgeHold("SSH_KEY_CONFIRMATION_EXPIRED")
                _, pub = await self._preflight()
                if hashlib.sha256(pub.encode()).hexdigest() != pending["digest"]:
                    raise QuickEdgeHold("SSH_KEY_CHANGED")
                existing = _items(await self._cloudzy("list_ssh_keys"))
                if any(str(_val(item, "publicKey", "public_key") or "").strip() == pub for item in existing):
                    await self._display(query, "ℹ️ کلید عمومی Core قبلاً در Cloudzy وجود دارد.",
                        [[("↩️ کلیدها", "apps_cz_keys_0")]], markup)
                    return
                # Write is explicit and never repeated automatically on timeout.
                await self._cloudzy("add_ssh_key", "nvl-core-legacy-edge", pub)
                await self._display(query, "✅ کلید عمومی Core در Cloudzy ثبت شد.",
                    [[("↩️ کلیدها", "apps_cz_keys_0")]], markup)
            else:
                raise QuickEdgeHold("INVALID_CALLBACK")
        except CloudzyUncertainError:
            await query.message.reply_text(
                "⚠️ پاسخ Cloudzy نامعلوم است. ابتدا کلیدها/سرورها را بررسی کنید؛ عملیات را کورکورانه تکرار نکنید.")
        except CloudzyAPIError as e:
            await query.message.reply_text(
                f"⛔️ Cloudzy درخواست را رد کرد (HTTP {e.status}). مجوز یا وضعیت حساب را بررسی کنید.")
        except (QuickEdgeHold, CloudzyError, ValueError, TypeError, KeyError):
            await query.message.reply_text(
                "⛔️ عملیات متوقف شد؛ مرحله، مجوز، تنظیمات Core یا وضعیت عملیات تغییر کرده است. "
                "از «وضعیت عملیات» بررسی کنید. خرید تکراری انجام ندهید.")
        except Exception:
            await query.message.reply_text(
                "⛔️ خطای غیرمنتظره. وضعیت عملیات را بررسی کنید؛ خرید یا نصب را تکرار نکنید.")

    async def _plans(self, query, session, markup, page=0):
        raw = await self._cloudzy(
            "list_plans", region=session["region"], billing_cycle=session["cycle"])
        plans = raw.get("plans", []) if isinstance(raw, dict) else []
        all_rows = []
        for item in plans if isinstance(plans, list) else []:
            if not isinstance(item, dict):
                continue
            pid = _val(item, "id")
            price = item.get("price")
            if not isinstance(pid, str) or not ID_PATTERN.fullmatch(pid) or not isinstance(price, dict):
                continue
            cents = _val(price, "amountCents", "priceCents", "monthlyEquivCents")
            if type(cents) is not int or cents <= 0:
                continue
            scope = str(item.get("priceScope", "catalog_base"))
            label = str(_val(item, "name", "slug", "id") or "plan")[:34]
            basis = ("معادل ماهانه" if _val(price, "monthlyEquivCents") is not None
                     and _val(price, "amountCents", "priceCents") is None
                     else CYCLES[session["cycle"]])
            all_rows.append((pid, label, cents, scope, basis))
        all_rows = all_rows[:120]
        max_page = max(1, (len(all_rows) + PAGE_SIZE - 1) // PAGE_SIZE)
        page = min(page, max_page - 1)
        tokens = self._token(all_rows[page*PAGE_SIZE:(page+1)*PAGE_SIZE])
        session["plans"] = tokens
        rows = [[(f"📦 {name[:22]} · {price} سنت ({basis})", "apps_cz_qp_" + token)]
                for token, (_, name, price, _, basis) in tokens.items()]
        rows.extend([[("◀️ قبلی", f"apps_cz_qpg_{page-1}")] if page else []])
        if page + 1 < max_page:
            rows.append([("بعدی ▶️", f"apps_cz_qpg_{page+1}")])
        rows.extend([
            [("ساعتی", "apps_cz_qcy_hourly"), ("ماهانه", "apps_cz_qcy_monthly")],
            [("سه‌ماهه", "apps_cz_qcy_quarterly"), ("سالانه", "apps_cz_qcy_annually")],
            [("↩️ شروع مجدد", "apps_cz_wizard")],
        ])
        rows = [row for row in rows if row]
        await self._display(query,
            "📦 <b>انتخاب پلن Cloudzy</b>\n"
            f"منطقه: {_text(session['region_name'])}\n"
            f"دوره پرداخت: {CYCLES[session['cycle']]}\n"
            f"صفحه {page+1}/{max_page}\n\n"
            "⚠️ این مبالغ پایه و تخمینی‌اند، نه قیمت نهایی شامل IPv4.\n"
            "اگر پلنی نمایش داده نمی‌شود، قیمت معتبر برای این دوره در کاتالوگ موجود نیست.",
            rows, markup)

    async def _operation_screen(self, query, op, markup, actor, chat):
        status = op["status"]
        rows = []
        if op["actor_id"] == actor and op["chat_id"] == chat:
            if status in ("CREATE_UNCERTAIN", "CREATED", "HOLD_WAIT", "HOLD_IP", "HOLD_SSH"):
                rows.append([("🔎 بررسی بدون خرید مجدد", "apps_cz_qcheck_" + op["id"])])
        rows.append([("🔄 تازه‌سازی", "apps_cz_qview_" + op["id"])])
        rows.append([("↩️ Cloudzy", "apps_cz_home")])
        text = ("📋 <b>عملیات ساخت Edge</b>\n\n"
                f"شناسه: <code>{op['id'][:16]}</code>\n"
                f"مرحله: <b>{_text(status)}</b>\n"
                f"VPS: <code>{_text(op.get('provider_server_id') or 'ثبت نشده')}</code>\n"
                f"IP: <code>{_text(op.get('public_ipv4') or 'نامشخص')}</code>\n\n"
                "⚠️ هیچ سرور قدیمی حذف نشده و هیچ Relay/DNS/اکانتی منتقل نشده است.\n")
        if status in ("CREATING", "PROVISIONING"):
            text += "\n⏳ پس از ری‌استارت بات، این مرحله ممکن است نامعلوم باشد؛ درخواست تکراری نفرستید."
        if status == "HOSTKEY_PENDING":
            text += (f"\n🔐 <b>SSH host-key fingerprint</b>\n"
                     f"<code>{_text(op.get('host_key_fingerprint') or 'نامشخص')}</code>\n\n"
                     "این اثرانگشت را با یک منبع مستقل و مورداعتماد، "
                     "مثلاً کنسول Cloudzy، مقایسه کنید. مشاهده آن از همین IP کافی نیست.")
            if op["actor_id"] == actor and op["chat_id"] == chat:
                rows.insert(0, [("🔐 بررسی و تأیید اثرانگشت", "apps_cz_qreview_" + op["id"])])
        if status.startswith("HOLD") or status == "CREATE_UNCERTAIN":
            text += f"\n⚠️ نیازمند بررسی: {_text(op.get('hold_reason') or 'UNKNOWN')}"
        if status == "EDGE_READY":
            text += "\n✅ Edge در host_pool به‌صورت غیرفعال ثبت شده و آماده بررسی دستی است."
        await self._display(query, text, rows, markup)

    async def _buy(self, opid, chat, pub, app):
        try:
            op = await asyncio.to_thread(self.store.get, opid)
            data = await self._cloudzy(
                "create_server", hostname=op["hostname"], plan_id=op["plan_id"],
                region=op["region"], os_template_id=OS_TEMPLATE,
                ip_version="ipv4", billing_cycle=op["billing_cycle"],
                ssh_public_keys=[pub], idempotency_key=op["idempotency_key"],
                confirm=True)
            server_id = _server_id(data)
            await asyncio.to_thread(
                self.store.change, opid, "CREATING", "CREATED", provider_server_id=server_id)
        except (CloudzyUncertainError, QuickEdgeHold, CloudzyError, Exception) as exc:
            # No second create. Even HTTP 4xx is left for manual review rather
            # than allowing another chargeable attempt on an ambiguous deployment.
            reason = ("CREATE_RESULT_UNCERTAIN" if isinstance(exc, CloudzyUncertainError)
                      else "CREATE_OR_RECEIPT_FAILED")
            try:
                await asyncio.to_thread(self.store.change, opid, "CREATING",
                    "CREATE_UNCERTAIN", hold_reason=reason)
            except QuickEdgeHold:
                pass
            await app.bot.send_message(chat, "⚠️ وضعیت خرید Cloudzy نامشخص است؛ خرید را تکرار نکنید. "
                                           "از «وضعیت عملیات» بررسی کنید.")
            return
        try:
            await asyncio.to_thread(self.store.change, opid, "CREATED", "WAITING")
            server = await self._cloudzy("wait_for_ready", server_id, timeout=900, interval=6)
            ip = _public_ipv4(server)
            await asyncio.to_thread(self.store.change, opid, "WAITING", "HOLD_SSH", public_ipv4=ip)
            await self._capture(opid, chat, app, from_state="HOLD_SSH")
        except Exception:
            try:
                record = await asyncio.to_thread(self.store.get, opid)
                if record["status"] == "WAITING":
                    await asyncio.to_thread(
                        self.store.change, opid, "WAITING", "HOLD_WAIT",
                        hold_reason="PROVIDER_OR_IP_NOT_READY")
            except Exception:
                pass
            await app.bot.send_message(
                chat, "⚠️ VPS ساخته شده، ولی آماده‌سازی یا IP/SSH هنوز تأیید نشده است. "
                "هیچ نصب یا انتقالی انجام نمی‌شود. از «وضعیت عملیات» بررسی کنید.")

    async def _capture(self, opid, chat, app, *, from_state="HOLD_SSH"):
        op = await asyncio.to_thread(self.store.get, opid)
        if not op["public_ipv4"]:
            raise QuickEdgeHold("MISSING_IPV4")
        key_type, key_base64, fingerprint = await asyncio.to_thread(self.fingerprint, op["public_ipv4"])
        await asyncio.to_thread(
            self.store.change, opid, from_state, "HOSTKEY_PENDING",
            host_key_type=key_type, host_key_base64=key_base64,
            host_key_fingerprint=fingerprint, hold_reason=None)
        await app.bot.send_message(
            chat,
            "🔐 VPS Cloudzy ساخته شد. قبل از نصب، اثرانگشت SSH را "
            "از طریق کنسول معتبر Cloudzy مستقل بررسی کنید:\n\n"
            f"<code>{_text(fingerprint)}</code>\n"
            f"IP: <code>{_text(op['public_ipv4'])}</code>\n"
            "سپس از «وضعیت عملیات» وارد بررسی و تأیید شوید.",
            parse_mode="HTML")

    async def _reconcile(self, opid, chat, app):
        try:
            op = await asyncio.to_thread(self.store.get, opid)
            current = op["status"]
            server_id = op.get("provider_server_id")
            if current == "CREATE_UNCERTAIN":
                matches = [
                    _obj(entry) for entry in _items(await self._cloudzy("list_servers"))
                    if str(_val(entry, "hostname", "name") or "") == op["hostname"]
                ]
                if len(matches) != 1:
                    raise QuickEdgeHold("PROVIDER_CREATION_UNPROVEN")
                server_id = _server_id(matches[0])
                await asyncio.to_thread(
                    self.store.change, opid, "CREATE_UNCERTAIN", "CREATED",
                    provider_server_id=server_id, hold_reason=None)
                current = "CREATED"
            if current in ("CREATED", "HOLD_WAIT", "HOLD_IP"):
                server = await self._cloudzy("get_server", server_id)
                obj = _obj(server)
                if str(_val(obj, "state", "status") or "").lower() != "active":
                    raise QuickEdgeHold("CLOUDZY_NOT_ACTIVE")
                ip = _public_ipv4(obj)
                await asyncio.to_thread(
                    self.store.change, opid, current, "HOLD_SSH",
                    public_ipv4=ip, hold_reason=None)
                current = "HOLD_SSH"
            if current == "HOLD_SSH":
                await self._capture(opid, chat, app, from_state="HOLD_SSH")
            else:
                raise QuickEdgeHold("NOT_RECONCILABLE")
        except Exception:
            await app.bot.send_message(
                chat, "⚠️ بررسی بدون خرید انجام شد، اما وضعیت VPS/SSH هنوز قابل تأیید نیست. "
                "بدون بررسی دستی، درخواست خرید یا نصب جدید ثبت نکنید.")

    async def _install(self, opid, chat, app):
        try:
            op = await asyncio.to_thread(self.store.get, opid)
            port, pub = await self._preflight()
            if port != op["customer_port"] or hashlib.sha256(pub.encode()).hexdigest() != op["public_key_sha"]:
                raise QuickEdgeHold("CORE_IDENTITY_CHANGED")
            latest_type, latest_b64, _ = await asyncio.to_thread(
                self.fingerprint, op["public_ipv4"])
            if latest_type != op["host_key_type"] or latest_b64 != op["host_key_base64"]:
                raise QuickEdgeHold("HOST_KEY_CHANGED")
            ok, _ip, details = await self.provision(
                op["public_ipv4"], port, op["hostname"], chat, app, op["provider_server_id"],
                (latest_type, latest_b64),
            )
            if not ok or not isinstance(details, dict) or not details.get("tunnel_ok"):
                raise QuickEdgeHold("LEGACY_PROVISION_OR_WG_TUNNEL_NOT_VERIFIED")
            verified = await self.verify(
                op["public_ipv4"], port, op["provider_server_id"])
            if verified is not True:
                raise QuickEdgeHold("LEGACY_EDGE_POSTCHECK_FAILED")
            await asyncio.to_thread(self.store.change, opid, "PROVISIONING", "EDGE_READY")
            await app.bot.send_message(
                chat, f"✅ Edge <code>{_text(op['public_ipv4'])}</code> با منطق Legacy آماده شد.\n"
                "در host_pool فعلاً غیرفعال است؛ DNS، Relay و کاربران تغییر نکرده‌اند.\n"
                "تأیید اتصال مشتری و فعال‌سازی Relay در فاز ۳ انجام می‌شود.",
                parse_mode="HTML")
        except Exception:
            try:
                await asyncio.to_thread(self.store.change, opid, "PROVISIONING",
                    "HOLD_PROVISION", hold_reason="PARTIAL_OR_UNVERIFIED_LEGACY_INSTALL")
            except Exception:
                pass
            await app.bot.send_message(chat,
                "⛔️ نصب Edge نتیجه قطعی ندارد؛ ممکن است VPS یا WireGuard بخشی از تغییرات را دریافت کرده باشد. "
                "نصب را دوباره اجرا نکنید؛ وضعیت را دستی بررسی کنید.")
