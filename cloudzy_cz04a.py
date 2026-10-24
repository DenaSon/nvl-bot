"""CZ-04A: guarded Cloudzy VPS controls and no-cutover Legacy Relay standby activation.

A Relay becoming standby-ready is NOT a DNS/default/NAT/user cutover. All
mutations are restricted to VPSs purchased and verified by CZ-03. No imported
Cloudzy VPS and no Legacy manual UI can be mutated here.
"""
from __future__ import annotations

import asyncio
from html import escape
import ipaddress
import secrets
import sqlite3
import time

from cloudzy_service import CloudzyService, CloudzyAPIError, CloudzyUncertainError, CloudzyError

TTL = 600
CONFIRM_TTL = 180
INVENTORY_PAGE_SIZE = 8
ACTIONS = {"start", "stop", "reboot", "relay"}
FINAL = ("DONE", "REJECTED")
RELAY_BLOCKED_FLAGS = ("phase6h_auto_failover_enabled", "auto_failover_mode")


class Cloudzy04AHold(RuntimeError):
    """Deterministic fail-closed safety condition."""


def _object(value):
    if not isinstance(value, dict):
        return {}
    cur = value
    for _ in range(3):
        inner = next((cur[k] for k in ("data", "service", "server", "result")
                      if isinstance(cur.get(k), dict)), None)
        if inner is None:
            break
        cur = inner
    return cur


def _safe(value):
    return escape(str(value or "—")[:90])


def _ipv4(value):
    try:
        ip = ipaddress.IPv4Address(str(value))
        return str(ip) if ip.is_global else None
    except ValueError:
        return None


def _provider_ipv4(obj):
    for field in ("primaryIpv4", "primaryIPv4", "ipv4", "publicIp", "ipAddress", "ip"):
        candidate = _ipv4(obj.get(field))
        if candidate:
            return candidate
    return None


class Cloudzy04A:
    def __init__(self, *, conn_factory, guard, probe,
                 cloudzy_factory=CloudzyService, now=time.time):
        self.db = conn_factory
        self.guard = guard
        self.probe = probe
        self.cloudzy = cloudzy_factory
        self.now = now

    def _init(self, db):
        db.execute("""CREATE TABLE IF NOT EXISTS cloudzy_cz04a_actions (
            id TEXT PRIMARY KEY, actor_id INTEGER NOT NULL, chat_id INTEGER NOT NULL,
            provider_id TEXT NOT NULL, host TEXT NOT NULL, action TEXT NOT NULL,
            status TEXT NOT NULL, started_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
            note TEXT DEFAULT NULL
        )""")
        db.execute("""CREATE UNIQUE INDEX IF NOT EXISTS cloudzy_cz04a_one_pending
            ON cloudzy_cz04a_actions((1)) WHERE status NOT IN ('DONE','REJECTED')""")

    def _read(self):
        """Only CZ03 completed, provider-bound NVL records are manageable."""
        with self.db() as db:
            self._init(db)
            rows = db.execute("""
                SELECT h.host,h.active,h.is_default,h.is_standby,h.service_port,
                       h.admin_ssh_port,h.provider_instance_id
                FROM host_pool h
                WHERE h.provider='cloudzy' AND h.provider_instance_id IS NOT NULL
                ORDER BY h.host
            """).fetchall()
            try:
                accepted = db.execute(
                    "SELECT provider_server_id, public_ipv4 FROM cloudzy_edge_operations "
                    "WHERE status='EDGE_READY'"
                ).fetchall()
            except sqlite3.OperationalError:
                accepted = []
            accepted_set = {(str(pid), str(ip)) for pid, ip in accepted}
            ret = []
            for host, active, default, standby, port, admin_port, pid in rows:
                if (str(pid), str(host)) not in accepted_set:
                    continue
                ret.append({
                    "host": str(host), "provider_id": str(pid),
                    "active": bool(active), "is_default": bool(default),
                    "is_standby": bool(standby), "port": int(port or 22),
                    "admin_port": int(admin_port or 22),
                })
            return ret

    def _inventory(self):
        """Read all NVL host_pool records, including unmanaged/manual entries.

        Membership and last recorded health are different dimensions. Counts
        include only SSH service_type accounts, not V2Ray or K2 users. NULL/empty
        host accounts inherit the current default for display purposes only.
        No Cloudzy API call and no host/account/route mutation occurs here.
        """
        with self.db() as db:
            rows = db.execute("""
                SELECT host, active, is_default, is_standby, provider,
                       provider_instance_id, health_state, health_updated_at,
                       service_ok, admin_ok, wg_peer_ok, core_path_ok
                FROM host_pool
                ORDER BY is_default DESC, active DESC, host
            """).fetchall()
            assignments = db.execute("""
                SELECT COALESCE(host, ''), COUNT(*),
                       SUM(CASE WHEN status LIKE '%فعال%'
                                AND status NOT LIKE '%غیر%' THEN 1 ELSE 0 END)
                FROM ssh_accounts
                WHERE service_type='ssh'
                GROUP BY COALESCE(host, '')
            """).fetchall()
            assignment_map = {
                str(host): (int(total), int(active or 0))
                for host, total, active in assignments
            }
            core_row = db.execute(
                "SELECT value FROM settings WHERE key='core_wg_public_ip'"
            ).fetchone()
            core_ip = str(core_row[0] or "") if core_row else ""
            try:
                receipts = db.execute("""
                    SELECT provider_server_id, public_ipv4, COUNT(*)
                    FROM cloudzy_edge_operations
                    WHERE status='EDGE_READY'
                    GROUP BY provider_server_id, public_ipv4
                """).fetchall()
            except sqlite3.OperationalError:
                receipts = []
            verified = {
                (str(pid), str(ip)) for pid, ip, total in receipts
                if total == 1 and pid and ip
            }
        unassigned_all, unassigned_active = assignment_map.get("", (0, 0))
        inventory = []
        for (host, active, default, standby, provider, instance,
             health, health_at, service_ok, admin_ok, wg_ok, path_ok) in rows:
            host = str(host)
            explicit_all, explicit_active = assignment_map.get(host, (0, 0))
            default = bool(default)
            provider_name = str(provider or "")
            provider_id = str(instance or "")
            inventory.append({
                "host": host, "active": bool(active),
                "default": default, "standby": bool(standby),
                "core": bool(core_ip and host == core_ip),
                "provider": provider_name,
                "provider_id": provider_id,
                "verified_cloudzy": provider_name == "cloudzy"
                    and (provider_id, host) in verified,
                "health": str(health or "UNKNOWN"),
                "health_at": str(health_at or ""),
                "service_ok": service_ok,
                "admin_ok": admin_ok,
                "wg_ok": wg_ok,
                "path_ok": path_ok,
                "explicit_all": explicit_all,
                "explicit_active": explicit_active,
                "inherited_all": unassigned_all if default else 0,
                "inherited_active": unassigned_active if default else 0,
            })
        return inventory

    @staticmethod
    def _inventory_role(item):
        if item["default"]:
            return "⭐ پیش‌فرض"
        if item["core"]:
            return "🛟 Core"
        if item["standby"]:
            return "🟡 Standby"
        return "🟢 فعال" if item["active"] else "⚪️ غیرفعال"

    def _inventory_ref(self, context, actor, chat, token):
        state = context.user_data.get("cz4_nvl_refs")
        if (not isinstance(state, dict) or state.get("actor") != actor
                or state.get("chat") != chat
                or self.now() >= state.get("expires", 0)):
            raise Cloudzy04AHold("EXPIRED_INVENTORY_SELECTION")
        host = state.get("items", {}).get(token)
        if not isinstance(host, str) or not host:
            raise Cloudzy04AHold("UNKNOWN_INVENTORY_SELECTION")
        return host

    def _state(self, host, provider_id, *, mutation):
        with self.db() as db:
            self._init(db)
            if mutation:
                self.guard(db)  # protected K2/failover/security gates from current Core
            row = db.execute("""
                SELECT active,is_default,is_standby,service_port,admin_ssh_port,
                       provider,provider_instance_id
                FROM host_pool WHERE host=?""", (host,)).fetchone()
            if not row or row[5] != "cloudzy" or str(row[6]) != provider_id:
                raise Cloudzy04AHold("PROVIDER_OWNERSHIP_CHANGED")
            receipt = db.execute("""
                SELECT COUNT(*) FROM cloudzy_edge_operations
                WHERE status='EDGE_READY' AND provider_server_id=? AND public_ipv4=?
            """, (provider_id, host)).fetchone()[0]
            if receipt != 1:
                raise Cloudzy04AHold("CZ03_ACCEPTANCE_NOT_VERIFIED")
            count = db.execute(
                "SELECT COUNT(*) FROM ssh_accounts WHERE host=?", (host,)
            ).fetchone()[0]
            settings = dict(db.execute(
                "SELECT key,value FROM settings WHERE key IN "
                "('dns_current_ip','hosts','phase6h_auto_failover_enabled',"
                "'auto_failover_mode','edge_egress_v1_onboard_enabled')"
            ).fetchall())
            record = {
                "active": bool(row[0]), "default": bool(row[1]),
                "standby": bool(row[2]), "port": int(row[3] or 22),
                "admin_port": int(row[4] or 22), "users": int(count),
                "dns": settings.get("dns_current_ip", ""),
                "listed": host in [x.strip() for x in settings.get("hosts", "").split(",")],
                "auto": any(settings.get(k) == "1" for k in RELAY_BLOCKED_FLAGS),
                "k2_onboard": settings.get("edge_egress_v1_onboard_enabled") == "1",
            }
            if mutation:
                running = db.execute(
                    "SELECT id FROM cloudzy_cz04a_actions "
                    "WHERE status NOT IN ('DONE','REJECTED') LIMIT 1"
                ).fetchone()
                if running:
                    raise Cloudzy04AHold("PREVIOUS_OPERATION_NEEDS_RECONCILIATION")
            return record

    @staticmethod
    def _isolated(state):
        if (state["default"] or state["standby"] or state["active"] or
                state["users"] or state["listed"]):
            raise Cloudzy04AHold("VPS_STILL_LINKED_TO_CUSTOMERS_OR_ROUTING")

    async def _provider(self, provider_id, host):
        live = _object(await asyncio.to_thread(self.cloudzy().get_server, provider_id))
        live_id = str(live.get("id") or live.get("serviceId") or live.get("uuid") or "")
        live_ip = _provider_ipv4(live)
        if live_id != provider_id or live_ip != host:
            raise Cloudzy04AHold("PROVIDER_ID_OR_IP_MISMATCH")
        status = str(live.get("state") or live.get("status") or "").lower()
        if not status:
            raise Cloudzy04AHold("PROVIDER_STATE_UNKNOWN")
        return status

    def _reserve(self, actor, chat, host, provider_id, action):
        with self.db() as db:
            self._init(db)
            db.execute("BEGIN IMMEDIATE")
            self.guard(db)
            if db.execute(
                "SELECT 1 FROM cloudzy_cz04a_actions "
                "WHERE status NOT IN ('DONE','REJECTED') LIMIT 1"
            ).fetchone():
                raise Cloudzy04AHold("PREVIOUS_OPERATION_NEEDS_RECONCILIATION")
            if not db.execute(
                "SELECT 1 FROM host_pool h JOIN cloudzy_edge_operations c "
                "ON h.provider_instance_id=c.provider_server_id "
                "AND h.host=c.public_ipv4 "
                "WHERE h.host=? AND h.provider=? AND h.provider_instance_id=? "
                "AND c.status='EDGE_READY'",
                (host, "cloudzy", provider_id)
            ).fetchone():
                raise Cloudzy04AHold("PROVIDER_OWNERSHIP_CHANGED")
            op_id = secrets.token_hex(16)
            ts = int(self.now())
            db.execute(
                "INSERT INTO cloudzy_cz04a_actions "
                "(id,actor_id,chat_id,provider_id,host,action,status,started_at,updated_at) "
                "VALUES (?,?,?,?,?,?,'IN_FLIGHT',?,?)",
                (op_id, actor, chat, provider_id, host, action, ts, ts)
            )
            return op_id

    def _finish(self, op_id, status, note=""):
        if status not in ("DONE", "REJECTED", "HOLD"):
            raise ValueError("invalid operation outcome")
        with self.db() as db:
            db.execute(
                "UPDATE cloudzy_cz04a_actions SET status=?,note=?,updated_at=? "
                "WHERE id=? AND status='IN_FLIGHT'",
                (status, str(note)[:90], int(self.now()), op_id)
            )

    def _promote(self, op_id, host, provider_id):
        """Atomic local standby registration; NEVER modify DNS, default or users."""
        with self.db() as db:
            self._init(db)
            db.execute("BEGIN IMMEDIATE")
            self.guard(db)
            if not db.execute(
                "SELECT 1 FROM cloudzy_cz04a_actions WHERE id=? AND status='IN_FLIGHT' "
                "AND host=? AND provider_id=? AND action='relay'",
                (op_id, host, provider_id)
            ).fetchone():
                raise Cloudzy04AHold("OPERATION_LEASE_CHANGED")
            row = db.execute("""
                SELECT active,is_default,is_standby,provider,provider_instance_id
                FROM host_pool WHERE host=?""", (host,)).fetchone()
            if not row or row[0] or row[1] or row[2] or row[3] != "cloudzy" or row[4] != provider_id:
                raise Cloudzy04AHold("HOST_CHANGED_DURING_ACTIVATION")
            if db.execute("SELECT COUNT(*) FROM ssh_accounts WHERE host=?", (host,)).fetchone()[0]:
                raise Cloudzy04AHold("USERS_APPEARED")
            st = dict(db.execute(
                "SELECT key,value FROM settings WHERE key IN "
                "('dns_current_ip','hosts','phase6h_auto_failover_enabled','auto_failover_mode')"
            ).fetchall())
            if st.get("dns_current_ip") == host or host in st.get("hosts","").split(","):
                raise Cloudzy04AHold("ROUTE_CHANGED")
            if any(st.get(k) == "1" for k in RELAY_BLOCKED_FLAGS):
                raise Cloudzy04AHold("AUTO_FAILOVER_MUST_BE_DISABLED")
            changed = db.execute(
                "UPDATE host_pool SET active=1,is_standby=1,disabled_reason=NULL,disabled_at=NULL "
                "WHERE host=? AND provider='cloudzy' AND provider_instance_id=? "
                "AND active=0 AND is_default=0 AND is_standby=0",
                (host, provider_id)
            ).rowcount
            if changed != 1:
                raise Cloudzy04AHold("CONCURRENT_HOST_UPDATE")
            db.execute(
                "UPDATE cloudzy_cz04a_actions SET status='DONE',updated_at=?,note=? "
                "WHERE id=? AND status='IN_FLIGHT'",
                (int(self.now()), "STANDBY_ONLY_NO_CUSTOMER_CUTOVER", op_id)
            )

    def _latest(self):
        with self.db() as db:
            self._init(db)
            return db.execute(
                "SELECT action,status,host,note FROM cloudzy_cz04a_actions "
                "ORDER BY started_at DESC LIMIT 1"
            ).fetchone()

    def _ref(self, context, actor, chat, token):
        state = context.user_data.get("cz4_refs")
        if (not isinstance(state, dict) or state.get("actor") != actor
                or state.get("chat") != chat or self.now() > state.get("expires", 0)):
            raise Cloudzy04AHold("EXPIRED_SELECTION")
        value = state.get("items", {}).get(token)
        if not value:
            raise Cloudzy04AHold("INVALID_SELECTION")
        return value

    async def _display(self, query, message, rows, markup):
        await query.edit_message_text(message, parse_mode="HTML", reply_markup=markup(rows))

    async def handle_callback(self, query, context, data, *, role, actor, chat, markup):
        if role != "admin":
            await query.message.reply_text("⛔️ فقط مدیر مجاز است.")
            return
        try:
            if data == "apps_cz_edge":
                hosts = await asyncio.to_thread(self._inventory)
                count_active = sum(item["active"] for item in hosts)
                count_standby = sum(item["standby"] for item in hosts)
                count_managed = sum(item["verified_cloudzy"] for item in hosts)
                await self._display(
                    query,
                    "🌐 <b>مرکز مدیریت Edge و Relay</b>\n\n"
                    f"🖥 کل IPهای ثبت‌شده در NVL: <b>{len(hosts)}</b>\n"
                    f"🟢 فعال: {count_active} · ⚪️ غیرفعال: {len(hosts) - count_active}\n"
                    f"⭐ پیش‌فرض: {sum(item['default'] for item in hosts)}"
                    f" · 🟡 Standby: {count_standby}\n"
                    f"☁️ VPSهای Cloudzy قابل مدیریت: {count_managed}\n\n"
                    "وضعیت‌ها از دیتابیس NVL هستند؛ سلامت آنلاین تضمین نشده است.\n"
                    "انتقال مسیر پیش‌فرض، DNS و کاربران در CZ-04B خواهد بود.",
                    [
                        [("🖥 فهرست همه Edgeهای NVL", "apps_cz4_hosts_0")],
                        [("☁️ مدیریت VPSهای Cloudzy", "apps_cz4_vps")],
                        [("↩️ Cloudzy", "apps_cz_home")],
                    ], markup,
                )
                return
            if data.startswith("apps_cz4_hosts_"):
                raw_page = data[len("apps_cz4_hosts_"):]
                if not raw_page.isascii() or not raw_page.isdecimal() or len(raw_page) > 3:
                    raise Cloudzy04AHold("INVALID_PAGE")
                inventory = await asyncio.to_thread(self._inventory)
                pages = max(1, (len(inventory) + INVENTORY_PAGE_SIZE - 1)
                            // INVENTORY_PAGE_SIZE)
                page = min(int(raw_page), pages - 1)
                start = page * INVENTORY_PAGE_SIZE
                current = inventory[start:start + INVENTORY_PAGE_SIZE]
                refs, rows = {}, []
                for item in current:
                    token = secrets.token_hex(4)
                    refs[token] = item["host"]
                    rows.append([(
                        f"{self._inventory_role(item)} · {item['host']}",
                        "apps_cz4_host_" + token
                    )])
                context.user_data["cz4_nvl_refs"] = {
                    "actor": actor, "chat": chat,
                    "expires": self.now() + TTL, "items": refs,
                }
                paging = []
                if page:
                    paging.append(("◀️ قبلی", f"apps_cz4_hosts_{page - 1}"))
                if page < pages - 1:
                    paging.append(("بعدی ▶️", f"apps_cz4_hosts_{page + 1}"))
                if paging:
                    rows.append(paging)
                rows.append([("↩️ Edge و Relay", "apps_cz_edge")])
                await self._display(
                    query,
                    "🖥 <b>همه Edgeهای NVL</b>\n"
                    f"تعداد: {len(inventory)} · صفحه {page + 1} از {pages}\n\n"
                    "تمام ردیف‌های host_pool، شامل دستی و Cloudzy.\n"
                    "🛡 فهرست فقط خواندنی است؛ سلامت ثبت‌شده ممکن است قدیمی باشد.",
                    rows, markup,
                )
                return
            if data.startswith("apps_cz4_host_"):
                host = self._inventory_ref(
                    context, actor, chat, data[len("apps_cz4_host_"):]
                )
                inventory = await asyncio.to_thread(self._inventory)
                item = next((x for x in inventory if x["host"] == host), None)
                if not item:
                    raise Cloudzy04AHold("HOST_REMOVED")
                def flag(v):
                    return "✅" if v == 1 else ("❌" if v == 0 else "—")
                provider_label = (
                    "ثبت‌نشده / دستی" if not item["provider"]
                    else item["provider"]
                )
                rows = []
                if item["verified_cloudzy"]:
                    rows.append([("☁️ مدیریت VPS Cloudzy", "apps_cz4_vps")])
                rows.append([("↩️ فهرست Edgeها", "apps_cz4_hosts_0")])
                await self._display(
                    query,
                    f"🖥 <b>جزئیات NVL Edge</b>\n\n"
                    f"IP: <code>{_safe(host)}</code>\n"
                    f"نقش: {self._inventory_role(item)}\n"
                    f"عضویت فعال: {'بله' if item['active'] else 'خیر'}\n"
                    f"پیش‌فرض: {'بله' if item['default'] else 'خیر'}"
                    f" · Standby: {'بله' if item['standby'] else 'خیر'}\n"
                    f"Provider: {_safe(provider_label)}\n"
                    f"مالکیت Cloudzy تأییدشده: {'بله' if item['verified_cloudzy'] else 'خیر'}\n\n"
                    f"👥 کاربران SSH با Host صریح: {item['explicit_all']}"
                    f" (فعال: {item['explicit_active']})\n"
                    f"👥 کاربران SSH بدون Host، منتسب به پیش‌فرض: {item['inherited_all']}"
                    f" (فعال: {item['inherited_active']})\n\n"
                    f"🩺 سلامت ثبت‌شده: {_safe(item['health'])}\n"
                    f"آخرین ثبت سلامت: {_safe(item['health_at'])}\n"
                    f"SSH سرویس: {flag(item['service_ok'])}"
                    f" · SSH مدیر: {flag(item['admin_ok'])}\n"
                    f"WireGuard: {flag(item['wg_ok'])}"
                    f" · مسیر Core: {flag(item['path_ok'])}\n\n"
                    "⚠️ این داده‌ها Snapshot دیتابیس‌اند؛ تست زنده انجام نشده است.\n"
                    "این صفحه هیچ عملیات Cloudzy یا تغییر Relay انجام نمی‌دهد.",
                    rows, markup,
                )
                return
            if data == "apps_cz4_vps":
                hosts = await asyncio.to_thread(self._read)
                refs = {}
                buttons = []
                for item in hosts[:25]:
                    key = secrets.token_hex(4)
                    refs[key] = (item["host"], item["provider_id"])
                    icon = "🟡" if item["is_standby"] else "⚪️"
                    buttons.append([(f"{icon} {item['host']}", f"apps_cz4_detail_{key}")])
                context.user_data["cz4_refs"] = {
                    "actor": actor, "chat": chat, "expires": self.now() + TTL,
                    "items": refs,
                }
                last = await asyncio.to_thread(self._latest)
                last_label = (f"\nآخرین عملیات: {_safe(last[0])} · {_safe(last[1])}"
                              if last else "")
                await self._display(
                    query,
                    "🌐 <b>مدیریت Cloudzy / Relay</b>\n\n"
                    "فقط VPSهای خریداری و تأییدشده توسط CZ-03 قابل مدیریت‌اند.\n"
                    "🟡 Relay آماده‌به‌کار: بدون جابه‌جایی DNS، پیش‌فرض و کاربران.\n"
                    "فعال‌سازی مسیر کاربران در CZ-04B خواهد بود.\n"
                    f"Edgeهای مدیریت‌شده: {len(hosts)}{last_label}",
                    buttons + [[("↩️ Cloudzy", "apps_cz_home")]], markup,
                )
                return
            if data.startswith("apps_cz4_detail_"):
                host, pid = self._ref(context, actor, chat, data[len("apps_cz4_detail_"):])
                state = await asyncio.to_thread(self._state, host, pid, mutation=False)
                status = await self._provider(pid, host)
                token = data[len("apps_cz4_detail_"):]
                rows = []
                if not state["active"] and not state["standby"] and not state["default"]:
                    rows.append([("🎯 آماده‌سازی Relay Standby", f"apps_cz4_pick_relay_{token}")])
                    rows.append([("▶️ روشن‌کردن VPS", f"apps_cz4_pick_start_{token}")])
                    rows.append([("⏹ خاموش‌کردن VPS", f"apps_cz4_pick_stop_{token}")])
                    rows.append([("🔁 راه‌اندازی مجدد VPS", f"apps_cz4_pick_reboot_{token}")])
                rows.append([("↩️ Edgeها", "apps_cz_edge")])
                await self._display(
                    query,
                    f"🖥 <b>Cloudzy Edge</b>\n\n"
                    f"IP: <code>{_safe(host)}</code>\n"
                    f"VPS ID: <code>{_safe(pid)}</code>\n"
                    f"وضعیت Cloudzy: {_safe(status)}\n"
                    f"NVL فعال: {'بله' if state['active'] else 'خیر'}\n"
                    f"Standby: {'بله' if state['standby'] else 'خیر'}\n"
                    f"کاربران منتسب: {state['users']}\n\n"
                    "⚠️ خاموش/ری‌استارت تنها برای Edge جدا از سرویس ممکن است.\n"
                    "⚠️ خرید، حذف، Rebuild و Reset Password در این صفحه انجام نمی‌شوند.",
                    rows, markup,
                )
                return
            if data.startswith("apps_cz4_pick_"):
                spec = data[len("apps_cz4_pick_"):]
                action, sep, token = spec.partition("_")
                if not sep or action not in ACTIONS:
                    raise Cloudzy04AHold("INVALID_ACTION")
                host, pid = self._ref(context, actor, chat, token)
                state = await asyncio.to_thread(self._state, host, pid, mutation=True)
                self._isolated(state)
                if action == "relay":
                    if state["auto"] or state["k2_onboard"]:
                        raise Cloudzy04AHold("AUTOMATIC_OR_K2_ROUTING_ENABLED")
                else:
                    if state["auto"]:
                        raise Cloudzy04AHold("AUTOMATIC_FAILOVER_ENABLED")
                live_status = await self._provider(pid, host)
                if action == "relay" and live_status != "active":
                    raise Cloudzy04AHold("VPS_NOT_ACTIVE")
                if action == "start" and live_status in ("active", "running"):
                    raise Cloudzy04AHold("VPS_ALREADY_RUNNING")
                if action in ("stop", "reboot") and live_status not in ("active", "running"):
                    raise Cloudzy04AHold("VPS_NOT_RUNNING")
                nonce = secrets.token_hex(8)
                context.user_data["cz4_confirm"] = {
                    "actor": actor, "chat": chat, "expires": self.now() + CONFIRM_TTL,
                    "nonce": nonce, "host": host, "pid": pid, "action": action,
                }
                labels = {
                    "relay": "ثبت Relay به‌صورت Standby",
                    "start": "روشن‌کردن VPS", "stop": "خاموش‌کردن VPS",
                    "reboot": "راه‌اندازی مجدد VPS",
                }
                await self._display(query,
                    f"🔐 <b>تأیید عملیات</b>\n\n"
                    f"{_safe(labels[action])}\n"
                    f"IP: <code>{_safe(host)}</code>\n"
                    f"VPS: <code>{_safe(pid)}</code>\n\n"
                    "هویت، مجوزها و سلامت مجدداً کنترل می‌شوند.\n"
                    "Relay Standby هیچ مشتری یا DNS را جابه‌جا نمی‌کند.",
                    [[("✅ تأیید نهایی", "apps_cz4_go_" + nonce)],
                     [("❌ انصراف", "apps_cz_edge")]], markup)
                return
            if data.startswith("apps_cz4_go_"):
                conf = context.user_data.pop("cz4_confirm", None)
                if (not isinstance(conf, dict) or conf.get("actor") != actor
                        or conf.get("chat") != chat or self.now() >= conf.get("expires", 0)
                        or data[len("apps_cz4_go_"):] != conf.get("nonce")):
                    raise Cloudzy04AHold("CONFIRMATION_EXPIRED")
                host, pid, action = conf["host"], conf["pid"], conf["action"]
                state = await asyncio.to_thread(self._state, host, pid, mutation=True)
                self._isolated(state)
                if state["auto"] or state["k2_onboard"]:
                    raise Cloudzy04AHold("AUTOMATIC_OR_K2_ROUTING_ENABLED")
                live_status = await self._provider(pid, host)
                if action == "relay":
                    if live_status != "active":
                        raise Cloudzy04AHold("VPS_NOT_ACTIVE")
                    ok = await self.probe(host, state["port"], state["admin_port"])
                    if ok is not True:
                        raise Cloudzy04AHold("FRESH_SSH_WG_PREFLIGHT_FAILED")
                elif action == "start":
                    if live_status in ("active", "running"):
                        raise Cloudzy04AHold("VPS_ALREADY_RUNNING")
                elif live_status not in ("active", "running"):
                    raise Cloudzy04AHold("VPS_NOT_RUNNING")
                op = await asyncio.to_thread(self._reserve, actor, chat, host, pid, action)
                if action == "relay":
                    try:
                        await asyncio.to_thread(self._promote, op, host, pid)
                    except Exception:
                        await asyncio.to_thread(self._finish, op, "HOLD",
                                                "STANDBY_COMMIT_REQUIRES_REVIEW")
                        raise
                    await self._display(query,
                        f"✅ <b>Relay آماده‌به‌کار شد</b>\n\nIP: <code>{_safe(host)}</code>\n"
                        "فقط active=1 و is_standby=1 ثبت شد.\n"
                        "DNS، IP پیش‌فرض، NAT و کاربران تغییر نکردند.\n"
                        "انتقال واقعی در CZ-04B انجام می‌شود.",
                        [[("↩️ Edgeها", "apps_cz_edge")]], markup)
                    return
                methods = {"start": "power_on", "stop": "power_off", "reboot": "restart_server"}
                try:
                    await asyncio.to_thread(getattr(self.cloudzy(), methods[action]), pid)
                except CloudzyAPIError as exc:
                    await asyncio.to_thread(self._finish, op, "REJECTED",
                                            f"HTTP_{exc.status}")
                    raise
                except Exception:
                    await asyncio.to_thread(self._finish, op, "HOLD",
                                            "PROVIDER_OUTCOME_UNCERTAIN")
                    raise Cloudzy04AHold("PROVIDER_OUTCOME_UNCERTAIN") from None
                await asyncio.to_thread(self._finish, op, "DONE",
                                        "REQUEST_ACCEPTED_VERIFY_PROVIDER_STATE")
                await self._display(query,
                    "✅ Cloudzy درخواست را پذیرفت.\n"
                    "تغییر نهایی وضعیت VPS را در فهرست سرورها بررسی کنید.\n"
                    "درخواست خودکار تکرار نمی‌شود.",
                    [[("↩️ Edgeها", "apps_cz_edge")]], markup)
                return
            raise Cloudzy04AHold("INVALID_CALLBACK")
        except CloudzyAPIError as exc:
            await query.message.reply_text(
                f"⛔️ Cloudzy درخواست را رد کرد (HTTP {exc.status}). وضعیت سرور را بررسی کنید.")
        except (Cloudzy04AHold, CloudzyError, ValueError, TypeError, sqlite3.Error):
            await query.message.reply_text(
                "⛔️ عملیات HOLD شد؛ مالکیت، قفل‌ها، مسیر فعلی یا سلامت سرور تأیید نشد. "
                "هیچ دستور دیگری را بدون بررسی وضعیت اجرا نکنید.")
        except Exception:
            await query.message.reply_text(
                "⛔️ نتیجه عملیات نامشخص است. وضعیت سرویس و Journal را بررسی کنید؛ "
                "هیچ عملیات VPS را تکرار نکنید.")
