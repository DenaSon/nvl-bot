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
import logging
import os
import re
import secrets
import socket
import sqlite3
import time
import uuid

from cloudzy_service import (
    CloudzyAPIError, CloudzyError, CloudzyService, CloudzyUncertainError,
    CloudzyTimeout,
)
from cloudzy_cz05_catalog import CatalogHold, eligible_offers, preferred_regions
from cloudzy_unified_native import (
    register_native_purchase, mark_paid_intent, observe_native_status,
    observe_native_cancellation, UnifiedLinkHold,
)
from cloudzy_purchase_guard import (
    PurchaseHold, classify_preflight, classify_create,
    exact_existing_server, require_base_hourly_ceiling,
)
from cloudzy_cz06_orchestrator import (
    QuickRelayHold, QuickRelayJournal, progress_html, promote_standby_once,
)
from cloudzy_phase1_ui import receipt_title, receipt_result, technical_receipt
from cloudzy_recovery import (
    RecoveryHold, RECONCILABLE, recovery_kind, recovery_message,
    inspect_inactive_install, commit_existing_install, commit_standby_resume,
)

log = logging.getLogger(__name__)

CHARGEABLE_STATES = frozenset({
    "CREATING", "CREATE_UNCERTAIN", "CREATED", "WAITING", "HOLD_WAIT",
    "HOLD_IP", "HOLD_SSH", "HOSTKEY_PENDING", "PROVISIONING",
    "HOLD_PROVISION", "HOLD_PREFLIGHT", "HOLD_PROVIDER", "HOLD_UNKNOWN",
})
# A cancellation closes only a local operation journal; it never deletes a VPS.
# CREATE_UNCERTAIN and running purchase/install states deliberately stay fenced.
CANCELLABLE_STATES = frozenset({
    "HOSTKEY_PENDING", "HOLD_WAIT", "HOLD_IP", "HOLD_SSH",
    "HOLD_PROVISION", "HOLD_PREFLIGHT", "HOLD_PROVIDER", "HOLD_UNKNOWN",
    "CREATE_UNCERTAIN",  # opt-in quarantine requires explicit risk acknowledgement
})
CLOSED_STATES = ("EDGE_READY", "REJECTED", "CANCELLED")
CYCLES = {"hourly": "ساعتی"}
TTL_SECONDS = 600
PAGE_SIZE = 6
OS_TEMPLATE = "ubuntu-24.04"
ID_PATTERN = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,98}\Z")


def _safe_read_selection_callback(data):
    """Only these UI callbacks re-read provider catalog/region data.

    Never suggest an operator retry for paid purchase, SSH-key registration,
    Edge installs or journal-changing recovery callbacks.
    """
    return (
        data in ("apps_cz_wizard", "apps_cz6_start", "apps_cz_qauto")
        or data.startswith(("apps_cz_qr_", "apps_cz_qcy_", "apps_cz_qpg_"))
    )


def _cloudzy_http_hint(status, *, read_only):
    """User-facing HTTP guidance, with no raw provider data or secrets."""
    if status in (401, 403):
        return ("🔐 دسترسی به API کلودزی تأیید نشد. "
                "لطفاً اعتبار توکن و مجوزهای حساب را بررسی کنید.")
    if status == 429:
        if read_only:
            return ("⏳ درخواست‌های Cloudzy موقتاً محدود شده‌اند. "
                    "لطفاً کمی بعد دوباره بخش پلن‌ها را باز کنید.")
        return ("⚠️ Cloudzy درخواست را به دلیل محدودیت تعداد درخواست‌ها نپذیرفت. "
                "پیش از هر اقدام مجدد، وضعیت عملیات را بررسی کنید.")
    if status >= 500:
        if read_only:
            return ("☁️ سرویس Cloudzy موقتاً پاسخ مناسبی نمی‌دهد. "
                    "لطفاً چند ثانیه بعد دوباره تلاش کنید.")
        return ("⚠️ پاسخ Cloudzy قابل اتکا نیست. "
                "وضعیت عملیات را بررسی کنید و درخواست تغییردهنده را تکرار نکنید.")
    return (f"⛔️ Cloudzy درخواست را نپذیرفت (HTTP {status}). "
            + ("لطفاً تنظیمات و دسترسی API را بررسی کنید."
               if read_only else
               "پیش از اقدام مجدد، وضعیت عملیات را بررسی کنید."))


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
            # Remove the legacy global lease. Only running work for the
            # same admin/chat is mutually exclusive; uncertain and paused
            # order receipts are retained without freezing new purchases.
            db.execute("DROP INDEX IF EXISTS cloudzy_edge_one_unfinished")
            db.execute("""CREATE UNIQUE INDEX IF NOT EXISTS cloudzy_edge_active_owner_v2
                ON cloudzy_edge_operations(actor_id,chat_id)
                WHERE status IN ('CREATING','CREATED','WAITING','PROVISIONING')""")
            db.execute("""CREATE INDEX IF NOT EXISTS cloudzy_edge_status_v2
                ON cloudzy_edge_operations(status,updated_at)""")
            db.execute("""CREATE TABLE IF NOT EXISTS cloudzy_edge_cancel_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation_id TEXT NOT NULL,
                actor_id INTEGER NOT NULL,
                chat_id INTEGER NOT NULL,
                previous_status TEXT NOT NULL,
                previous_reason TEXT,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(operation_id) REFERENCES cloudzy_edge_operations(id)
            )""")
            # Restart-safe, provider-independent one-use confirmation for
            # uncertain purchases. Never contains Cloudzy tokens/secrets.
            db.execute("""CREATE TABLE IF NOT EXISTS cloudzy_edge_cancel_intents (
                operation_id TEXT PRIMARY KEY,
                actor_id INTEGER NOT NULL,
                chat_id INTEGER NOT NULL,
                expected_status TEXT NOT NULL,
                nonce TEXT NOT NULL UNIQUE,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            )""")

    def reserve(self, *, actor, chat, region, plan, cycle, price, port, pubkey,
                quick_relay=False, message_id=None):
        region, plan = _safe_id(region), _safe_id(plan)
        if cycle != "hourly" or not (type(price) is int and price > 0):
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
                    "SELECT id FROM cloudzy_edge_operations "
                    "WHERE actor_id=? AND chat_id=? "
                    "AND status IN ('CREATING','CREATED','WAITING','PROVISIONING') "
                    "LIMIT 1", (actor, chat)
                ).fetchone()
                if prior:
                    raise QuickEdgeHold("ACTIVE_PURCHASE_FOR_SAME_OPERATOR")
                db.execute("""INSERT INTO cloudzy_edge_operations
                    (id,actor_id,chat_id,status,created_at,updated_at,
                     hostname,region,plan_id,billing_cycle,price_cents,customer_port,
                     public_key_sha,idempotency_key)
                    VALUES (?,?,?,'CREATING',?,?,?,?,?,?,?,?,?,?)""",
                    (operation_id, actor, chat, timestamp, timestamp, hostname,
                     region, plan, cycle, price, port,
                     hashlib.sha256(pubkey.encode("utf-8")).hexdigest(), key))
                if quick_relay:
                    QuickRelayJournal(self.db, now=self.now).create_in_receipt_transaction(
                        db, opid=operation_id, actor=actor, chat=chat, message_id=message_id
                    )
                # The purchase receipt and UO owner must become durable in
                # the SAME transaction, before any paid Cloudzy POST.
                register_native_purchase(
                    db, operation_id=operation_id, actor=actor, chat=chat,
                    now=timestamp,
                )
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
            row = db.execute("SELECT id FROM cloudzy_edge_operations ORDER BY created_at DESC, rowid DESC LIMIT 1").fetchone()
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
            # Source CZ03 CAS and coordinator checkpoint commit together.
            # Historical receipts without a UO link remain untouched.
            observe_native_status(db, operation_id=operation_id,
                                  status=new, now=int(self.now()))


    def mark_paid_intent(self, operation_id):
        """Hold paid request unless the coordinator intent is persisted first."""
        self.initialize()
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            return mark_paid_intent(
                db, operation_id=operation_id, now=int(self.now()))

    def existing_host(self, ip):
        """Read-only Legacy host identity check before remote provisioning."""
        self.initialize()
        with self.db() as db:
            return db.execute(
                "SELECT 1 FROM host_pool WHERE host=? LIMIT 1", (ip,)
            ).fetchone() is not None

    def begin_uncertain_cancel(self, operation_id, *, actor, chat, nonce):
        """Persist a time-limited local cancel intent; no Cloudzy requests."""
        if (not isinstance(operation_id, str) or
                not re.fullmatch(r"[0-9a-f]{32}", operation_id) or
                not isinstance(nonce, str) or
                not re.fullmatch(r"[0-9a-f]{16}", nonce)):
            raise QuickEdgeHold("CANCEL_INTENT_INVALID")
        self.initialize()
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            rec = db.execute(
                "SELECT actor_id,chat_id,status,provider_server_id,public_ipv4 "
                "FROM cloudzy_edge_operations WHERE id=?", (operation_id,),
            ).fetchone()
            if not rec or (rec[0], rec[1]) != (actor, chat):
                raise QuickEdgeHold("CANCEL_OWNER_MISMATCH")
            if rec[2] != "CREATE_UNCERTAIN":
                raise QuickEdgeHold("CANCEL_STATE_CHANGED")
            if rec[3] or rec[4]:
                raise QuickEdgeHold("UNCERTAIN_CREATE_HAS_PROVIDER_IDENTITY")
            ts = int(self.now())
            db.execute(
                "INSERT INTO cloudzy_edge_cancel_intents "
                "(operation_id,actor_id,chat_id,expected_status,nonce,expires_at,created_at) "
                "VALUES (?,?,?,?,?,?,?) "
                "ON CONFLICT(operation_id) DO UPDATE SET "
                "actor_id=excluded.actor_id,chat_id=excluded.chat_id,"
                "expected_status=excluded.expected_status,nonce=excluded.nonce,"
                "expires_at=excluded.expires_at,created_at=excluded.created_at",
                (operation_id, actor, chat, "CREATE_UNCERTAIN", nonce,
                 ts + 900, ts),
            )

    def get_uncertain_cancel_intent(self, nonce, *, actor, chat):
        """Read only a matching unexpired owner-bound intent after a bot restart."""
        if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{16}", nonce):
            return None
        self.initialize()
        with self.db() as db:
            row = db.execute(
                "SELECT operation_id,expected_status FROM cloudzy_edge_cancel_intents "
                "WHERE nonce=? AND actor_id=? AND chat_id=? AND expires_at>?",
                (nonce, actor, chat, int(self.now())),
            ).fetchone()
        return ({"id": row[0], "status": row[1], "actor": actor, "chat": chat,
                 "nonce": nonce, "uncertain_ack": True} if row else None)

    def cancel(self, operation_id, *, actor, chat, expected_status,
               uncertain_ack=False, provider_observation=None,
               confirmation_nonce=None):
        """Cancel an idle failed/paused purchase ledger, never provider/Edge resources.

        Caller must enforce admin permission and the absence of a live local worker.
        State is checked again under BEGIN IMMEDIATE, with a durable audit event.
        """
        if not isinstance(operation_id, str) or not re.fullmatch(r"[0-9a-f]{32}", operation_id):
            raise QuickEdgeHold("INVALID_OPERATION")
        if type(actor) is not int or type(chat) is not int:
            raise QuickEdgeHold("INVALID_OWNER_OR_CHAT")
        if expected_status not in CANCELLABLE_STATES:
            raise QuickEdgeHold("CANCEL_STATE_NOT_ALLOWED")
        if expected_status == "CREATE_UNCERTAIN":
            if (uncertain_ack is not True or provider_observation != "NOT_CHECKED"
                    or not isinstance(confirmation_nonce, str)
                    or not re.fullmatch(r"[0-9a-f]{16}", confirmation_nonce)):
                raise QuickEdgeHold("UNCERTAIN_CREATE_REQUIRES_EXPLICIT_RISK_ACK")
        self.initialize()
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT status,public_ipv4,provider_server_id,hold_reason,"
                "actor_id,chat_id FROM cloudzy_edge_operations WHERE id=?",
                (operation_id,),
            ).fetchone()
            if not row or row[0] != expected_status:
                raise QuickEdgeHold("CANCEL_STATE_CHANGED")
            status, ip, provider_id, original_reason, owner, owner_chat = row
            if (owner, owner_chat) != (actor, chat):
                raise QuickEdgeHold("CANCEL_OWNER_MISMATCH")
            if status == "CREATE_UNCERTAIN":
                if ip or provider_id:
                    # This local-only path cannot discard a known provider asset.
                    raise QuickEdgeHold("UNCERTAIN_CREATE_HAS_PROVIDER_IDENTITY")
                intent = db.execute(
                    "SELECT 1 FROM cloudzy_edge_cancel_intents "
                    "WHERE operation_id=? AND actor_id=? AND chat_id=? "
                    "AND nonce=? AND expected_status='CREATE_UNCERTAIN' "
                    "AND expires_at>?",
                    (operation_id, actor, chat, confirmation_nonce, int(self.now())),
                ).fetchone()
                if not intent:
                    raise QuickEdgeHold("CANCEL_CONFIRMATION_EXPIRED")
                last_changed = db.execute(
                    "SELECT updated_at FROM cloudzy_edge_operations WHERE id=?",
                    (operation_id,),
                ).fetchone()[0]
                if int(self.now()) - int(last_changed) < 120:
                    raise QuickEdgeHold("UNCERTAIN_CREATE_SETTLEMENT_GRACE")

            # A previously RETIRED host may hold the same recycled public IP.
            # The purchase receipt identifies the NEW provider VPS; never
            # mistake a completely detached, unowned legacy host_pool row for
            # this operation's attached Edge. Do not delete/update that row.
            # Reject registered, routed, standby, provider-owned or ambiguous
            # hosts; subsequent checks enforce DNS, route and migration safety.
            registered = db.execute(
                "SELECT host,active,is_default,is_standby,provider,provider_instance_id "
                "FROM host_pool WHERE host=? OR provider_instance_id=?",
                (ip, provider_id)
            ).fetchall()
            if registered:
                if (not ip or not provider_id or len(registered) != 1
                        or registered[0][0] != ip
                        or any(registered[0][i] != 0 for i in (1, 2, 3))
                        or registered[0][4] not in (None, "")
                        or registered[0][5] not in (None, "")):
                    raise QuickEdgeHold("CANCEL_HOST_REGISTERED")
                # SSH users still assigned to this host (including unknown
                # service types) are real blockers. Marzban-only account rows
                # are independent of the Legacy SSH Relay.
                active_ssh_like = db.execute(
                    "SELECT COUNT(*) FROM ssh_accounts WHERE host=? "
                    "AND status LIKE '%فعال%' AND status NOT LIKE '%غیر%' "
                    "AND COALESCE(NULLIF(service_type,''),'ssh') "
                    "NOT IN ('v2ray','v2ray_vol')", (ip,)
                ).fetchone()[0]
                if active_ssh_like:
                    raise QuickEdgeHold("CANCEL_ACTIVE_SSH_ACCOUNTS_ATTACHED")
            settings = dict(db.execute(
                "SELECT key,value FROM settings "
                "WHERE key IN ('hosts','dns_current_ip','core_wg_public_ip')"
            ).fetchall())
            if not settings.get("hosts") or not settings.get("dns_current_ip"):
                raise QuickEdgeHold("CANCEL_ROUTE_STATE_UNVERIFIED")
            if ip and (ip in [host.strip() for host in settings["hosts"].split(",")]
                       or ip in (settings["dns_current_ip"], settings.get("core_wg_public_ip"))):
                raise QuickEdgeHold("CANCEL_ROUTE_REFERENCES_TARGET")
            for table, field in (
                ("cloudzy_cz04b_operations", "target"),
                ("cloudzy_cz07_jobs", "target"),
            ):
                if db.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                    (table,)
                ).fetchone() and db.execute(
                    f"SELECT 1 FROM {table} WHERE {field}=? AND "
                    "status NOT IN ('READY','DONE','ABORTED') LIMIT 1", (ip,)
                ).fetchone():
                    raise QuickEdgeHold("CANCEL_CUTOVER_OR_MIGRATION_UNRESOLVED")

            # Both receipts are updated in one transaction: no orphan CZ06
            # running state and no prematurely freed purchase lease.
            from cloudzy_cz06_orchestrator import QuickRelayJournal
            QuickRelayJournal.initialize(db)
            quick = db.execute(
                "SELECT stage FROM cloudzy_cz06_runs WHERE operation_id=?",
                (operation_id,)
            ).fetchone()
            if quick and quick[0] in ("READY", "CANCELLED"):
                raise QuickEdgeHold("CANCEL_QUICK_STAGE_INVALID")
            ts = int(self.now())
            if db.execute(
                "UPDATE cloudzy_edge_operations "
                "SET status='CANCELLED',hold_reason='OPERATOR_CANCELLED',updated_at=? "
                "WHERE id=? AND status=?", (ts, operation_id, status)
            ).rowcount != 1:
                raise QuickEdgeHold("CANCEL_CONCURRENT_CHANGE")
            if quick:
                db.execute(
                    "UPDATE cloudzy_cz06_runs SET stage='CANCELLED',"
                    "detail_code='OPERATOR_CANCELLED',updated_at=? WHERE operation_id=?",
                    (ts, operation_id)
                )
            db.execute(
                "INSERT INTO cloudzy_edge_cancel_events "
                "(operation_id,actor_id,chat_id,previous_status,previous_reason,created_at) "
                "VALUES (?,?,?,?,?,?)",
                (operation_id, actor, chat, status, original_reason, ts)
            )
            if status == "CREATE_UNCERTAIN":
                # This is NOT proof that Cloudzy did not charge/create a VPS.
                # The immutable receipt, idempotency key and hostname survive.
                db.execute("""CREATE TABLE IF NOT EXISTS cloudzy_purchase_quarantine(
                    operation_id TEXT PRIMARY KEY,
                    actor_id INTEGER NOT NULL,chat_id INTEGER NOT NULL,
                    hostname TEXT NOT NULL,provider_observation TEXT NOT NULL,
                    disposition TEXT NOT NULL,created_at INTEGER NOT NULL
                )""")
                original_hostname = db.execute(
                    "SELECT hostname FROM cloudzy_edge_operations WHERE id=?",
                    (operation_id,),
                ).fetchone()[0]
                db.execute(
                    "INSERT INTO cloudzy_purchase_quarantine "
                    "(operation_id,actor_id,chat_id,hostname,provider_observation,"
                    "disposition,created_at) VALUES (?,?,?,?,?,?,?)",
                    (operation_id, actor, chat, original_hostname,
                     provider_observation, "PENDING_PROVIDER_RECONCILIATION", ts),
                )
            # CZ03, CZ06 and UO checkpoint in the SAME transaction.
            # UO stays RECONCILE_REQUIRED for any possible paid effect.
            observe_native_cancellation(
                db, operation_id=operation_id,
                uncertain=status == "CREATE_UNCERTAIN", now=ts,
            )
            if status == "CREATE_UNCERTAIN":
                db.execute("DELETE FROM cloudzy_edge_cancel_intents WHERE operation_id=?",
                           (operation_id,))
        return "CANCELLED"


class QuickEdgeWizard:
    def __init__(self, *, conn_factory, preflight, provision, verify,
                 cloudzy_factory=CloudzyService, fingerprint=capture_ssh_host_key,
                 now=time.time, standby_service=None, cz06_enabled=None):
        self.store = ReceiptStore(conn_factory, now=now)
        self.preflight = preflight
        self.provision = provision
        self.verify = verify
        self.cloudzy_factory = cloudzy_factory
        self.fingerprint = fingerprint
        self.now = now
        self._running = set()  # same-process single-flight, DB journal survives restarts
        self.quick_runs = QuickRelayJournal(conn_factory, now=now)
        self.standby_service = standby_service  # Wired after CZ-04A construction.
        self.cz06_enabled = (cz06_enabled if cz06_enabled is not None else
                             lambda: os.environ.get("NVL_CZ06_ENABLE") == "1")

    def _launch(self, app, opid, task):
        if opid in self._running:
            raise QuickEdgeHold("OPERATION_ALREADY_RUNNING")
        self._running.add(opid)

        async def wrapped():
            # Only one transient UI clock per in-process operation. The durable
            # operation journal, not this clock, is the source of truth.
            clock = asyncio.create_task(self._progress_clock(app, opid))
            try:
                await task
            finally:
                clock.cancel()
                try:
                    await clock
                except asyncio.CancelledError:
                    pass
                self._running.discard(opid)
        try:
            app.create_task(wrapped())
        except Exception:
            self._running.discard(opid)
            task.close()
            raise

    async def _progress_clock(self, app, opid):
        """Update the existing CZ-06 Telegram progress message every 30 seconds.

        Never restarts Cloudzy/SSH operations. Stops when the worker finishes,
        progress is blocked, or the message cannot be tracked.
        """
        try:
            run = await asyncio.to_thread(self.quick_runs.get, opid)
            if not run or run.get("message_id") is None:
                return
            while True:
                await asyncio.sleep(30)
                if opid not in self._running:
                    return
                run = await asyncio.to_thread(self.quick_runs.get, opid)
                if not run or run["stage"] not in (
                        "PURCHASING", "WAITING_PROVIDER", "INSTALLING", "STANDBY_VERIFYING"):
                    return
                receipt = await asyncio.to_thread(self.store.get, opid)
                from telegram import InlineKeyboardButton, InlineKeyboardMarkup
                try:
                    await app.bot.edit_message_text(
                        chat_id=run["chat_id"], message_id=run["message_id"],
                        text=progress_html(run, receipt, now=self.now()),
                        parse_mode="HTML",
                        reply_markup=InlineKeyboardMarkup([[
                            InlineKeyboardButton("📋 وضعیت عملیات",
                                                 callback_data="apps_cz_operations")
                        ]]),
                    )
                except Exception:
                    # UI delivery is best effort; never affect provisioning.
                    log.warning("CZ06_CLOCK_DELIVERY_FAILED op=%s", opid[:16])
        except asyncio.CancelledError:
            raise
        except Exception:
            log.warning("CZ06_CLOCK_UNAVAILABLE op=%s", opid[:16])

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
        try:
            await query.edit_message_text(text, parse_mode="HTML", reply_markup=markup(rows))
        except Exception as exc:
            # A repeated "Refresh" on an unchanged Telegram message is
            # idempotent, not a Cloudzy failure. Do not swallow other errors.
            if type(exc).__name__ == "BadRequest" and (
                    "Message is not modified" in str(exc)):
                return
            raise

    async def handle_callback(self, query, context, data, *, actor, chat, role, app, markup):
        if role != "admin":
            await query.message.reply_text("⛔️ فقط مدیر مجاز است.")
            return
        try:
            if data in ("apps_cz_wizard", "apps_cz6_start"):
                if data == "apps_cz6_start" and (
                        not self.cz06_enabled() or self.standby_service is None):
                    raise QuickRelayHold("CZ06_DISABLED_OR_STANDBY_ADAPTER_MISSING")
                self.store.initialize()
                old = await asyncio.to_thread(self.store.latest)
                if old and old["status"] not in CLOSED_STATES:
                    await self._operation_screen(query, old, markup, actor, chat)
                    return
                port, pub = await self._preflight()
                regions = _items(await self._cloudzy("list_regions"))
                valid = preferred_regions(regions)
                if not valid:
                    raise CatalogHold("NO_ELIGIBLE_PREFERRED_REGION")
                tokens = self._token(valid)
                context.user_data["cz3"] = {
                    "actor": actor, "chat": chat, "expires": self.now() + TTL_SECONDS,
                    "regions": tokens, "port": port,
                    "pub_sha": hashlib.sha256(pub.encode()).hexdigest(),
                    "cycle": "hourly", "quick_relay": data == "apps_cz6_start"
                }
                rows = [[("⚡ انتخاب خودکار منطقه", "apps_cz_qauto")]]
                rows.extend([("🌍 " + name[:27], "apps_cz_qr_" + token)] for token, (_, name) in tokens.items())
                rows.append([("↩️ Cloudzy", "apps_cz_home")])
                await self._display(query,
                    ("⚡ <b>Quick Relay · CZ-06</b>\n\n"
                     if data == "apps_cz6_start" else "⚡ <b>ساخت سریع Edge</b>\n\n")
                    + "۱. انتخاب خودکار بر اساس اولویت یا انتخاب دستی منطقه.\n"
                    "✅ فقط Regular CPU با ظرفیت زنده و پرداخت ساعتی.\n"
                    "✅ نصب با مسیر Legacy؛ سیستم‌عامل ثابت و بدون انتخاب.\n"
                    + ("⚠️ بعد از تأیید خرید، آماده‌سازی Standby خودکار است؛ "
                       "تأیید مستقل SSH همچنان الزامی است. "
                       if data == "apps_cz6_start" else
                       "🛠 نصب و ثبت Standby در مسیر دستی و با کنترل مجزا انجام می‌شود. ")
                    + "هیچ DNS یا کاربری منتقل نمی‌شود.",
                    rows, markup)
            elif data == "apps_cz_qauto":
                s = self._session(context, actor, chat)
                # On unknown stock/API failure, STOP; never silently mark a region available.
                for region, name in s["regions"].values():
                    offers = await self._eligible_for_region(region)
                    if offers:
                        s["region"], s["region_name"] = region, name
                        await self._plans(query, s, markup, offers=offers)
                        break
                else:
                    raise CatalogHold("NO_AVAILABLE_HOURLY_STANDARD_PLAN")
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
                if cycle != "hourly" or "region" not in s:
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
                    + ("⚡ پس از تأیید مستقل SSH، نصب Edge و Standby خودکار انجام می‌شود.\n"
                       if s.get("quick_relay") else "")
                    + "🛡 هیچ کاربر، DNS یا Relay پیش‌فرض منتقل نمی‌شود.",
                    [[("✅ خرید VPS با شرایط اعلام‌شده", "apps_cz_qbuy_" + s["nonce"])],
                     [("❌ انصراف", "apps_cz_home")]], markup)
            elif data.startswith("apps_cz_qbuy_"):
                s = self._session(context, actor, chat)
                nonce = s.pop("nonce", None)  # one-use, even across duplicate callback
                if not nonce or nonce != data[len("apps_cz_qbuy_"):]:
                    raise QuickEdgeHold("CONFIRMATION_EXPIRED")
                if not all(k in s for k in ("region", "plan", "price", "cycle", "port", "pub_sha")):
                    raise QuickEdgeHold("INVALID_SELECTION")
                if s.get("quick_relay") and (
                        not self.cz06_enabled() or self.standby_service is None):
                    raise QuickRelayHold("CZ06_DISABLED_OR_STANDBY_ADAPTER_MISSING")
                port, pub = await self._preflight()
                if port != s["port"] or hashlib.sha256(pub.encode()).hexdigest() != s["pub_sha"]:
                    raise QuickEdgeHold("SSH_PORT_OR_KEY_CHANGED")
                await self._check_offer_current(s["region"], s["plan"], s["price"])
                opid = await asyncio.to_thread(
                    self.store.reserve, actor=actor, chat=chat, region=s["region"],
                    plan=s["plan"], cycle=s["cycle"], price=s["price"],
                    port=port, pubkey=pub,
                    quick_relay=s.get("quick_relay") is True,
                    message_id=(getattr(query.message, "message_id", None)
                                if s.get("quick_relay") is True else None),
                )
                context.user_data.pop("cz3", None)
                run = await asyncio.to_thread(self.quick_runs.get, opid)
                await self._display(
                    query,
                    (progress_html(run, await asyncio.to_thread(self.store.get, opid))
                     if run else
                     f"⏳ <b>درخواست خرید Cloudzy ثبت شد</b>\n"
                     f"شناسه عملیات: <code>{opid[:16]}</code>\n"
                     "نتیجه را از «وضعیت عملیات» بررسی کنید؛ تأیید مجدد خرید نزنید."),
                    [[("📋 وضعیت عملیات", "apps_cz_operations")]], markup)
                self._launch(app, opid, self._buy(opid, chat, pub, app))
            elif data in ("apps_cz_operations", "apps_cz6_status"):
                op = await asyncio.to_thread(self.store.latest)
                if not op:
                    await self._display(query, "📋 هنوز عملیات Cloudzy ثبت نشده است.",
                        [[("↩️ Cloudzy", "apps_cz_home")]], markup)
                else:
                    await self._operation_screen(query, op, markup, actor, chat)
            elif data.startswith("apps_cz_qcancelyes_"):
                nonce = data[len("apps_cz_qcancelyes_"):]
                pending = context.user_data.get("cz3_cancel")
                valid = (isinstance(pending, dict) and pending.get("nonce") == nonce
                         and pending.get("actor") == actor and pending.get("chat") == chat
                         and self.now() < pending.get("expires", 0))
                if not valid:
                    # Uncertain purchase confirmations survive bot restarts;
                    # no provider API request is necessary to close local intent.
                    pending = await asyncio.to_thread(
                        self.store.get_uncertain_cancel_intent, nonce,
                        actor=actor, chat=chat)
                if not pending:
                    raise QuickEdgeHold("CANCEL_CONFIRMATION_EXPIRED")
                opid = pending["id"]
                if opid in self._running:
                    raise QuickEdgeHold("CANCEL_WORKER_STILL_RUNNING")
                await asyncio.to_thread(
                    self.store.cancel, opid, actor=actor, chat=chat,
                    expected_status=pending["status"],
                    uncertain_ack=pending.get("uncertain_ack", False),
                    provider_observation=("NOT_CHECKED"
                                          if pending["status"] == "CREATE_UNCERTAIN"
                                          else None),
                    confirmation_nonce=(nonce if pending["status"] == "CREATE_UNCERTAIN"
                                        else None),
                )
                # Consume confirmation only after durable journal cancellation.
                # A rejected safety check must not silently invalidate the
                # operator's confirmation page.
                context.user_data.pop("cz3_cancel", None)
                log.warning("CZ06_CANCEL op=%s actor=%s code=OPERATOR_CANCELLED",
                            opid[:16], actor)
                await self._display(query,
                    "✅ <b>پرونده محلی بسته و قفل خرید آزاد شد.</b>\n\n"
                    f"شناسه: <code>{opid[:16]}</code>\n"
                    "🛡 هیچ VPS حذف نشده و Relay/DNS/کاربران تغییر نکرده‌اند.\n"
                    + ("⚠️ نتیجه خرید Cloudzy هنوز نامشخص است. پرونده هزینه "
                       "در قرنطینه و در انتظار تطبیق با Cloudzy باقی می‌ماند؛ "
                       "در صورت وجود VPS، هزینه آن ادامه خواهد داشت."
                       if pending["status"] == "CREATE_UNCERTAIN" else
                       "⚠️ آثار نصب احتمالی و هزینه VPS باید جداگانه بررسی شوند."),
                    [[("⚡ ساخت Edge جدید", "apps_cz_wizard")],
                     [("📋 وضعیت عملیات", "apps_cz_operations")]], markup)
            elif data.startswith("apps_cz_qcancel_"):
                opid = data[len("apps_cz_qcancel_"):]
                op = await asyncio.to_thread(self.store.get, opid)
                if (op["actor_id"], op["chat_id"]) != (actor, chat):
                    raise QuickEdgeHold("CANCEL_OWNER_MISMATCH")
                if op["status"] not in CANCELLABLE_STATES or opid in self._running:
                    raise QuickEdgeHold("CANCEL_NOT_ALLOWED_OR_RUNNING")
                uncertain = op["status"] == "CREATE_UNCERTAIN"
                if uncertain and (op.get("provider_server_id") or op.get("public_ipv4")):
                    raise QuickEdgeHold("UNCERTAIN_CREATE_HAS_PROVIDER_IDENTITY")
                nonce = secrets.token_hex(8 if uncertain else 6)
                if uncertain:
                    # Durable confirmation replaces volatile Telegram user_data.
                    await asyncio.to_thread(
                        self.store.begin_uncertain_cancel, opid,
                        actor=actor, chat=chat, nonce=nonce)
                else:
                    context.user_data["cz3_cancel"] = {
                        "id": opid, "status": op["status"], "actor": actor,
                        "chat": chat, "nonce": nonce, "expires": self.now() + 180,
                        "uncertain_ack": False,
                    }
                await self._display(query,
                    ("🛡 <b>تأیید لغو محلی خرید نامشخص</b>\n\n" if uncertain
                     else "⚠️ <b>تأیید لغو عملیات Cloudzy</b>\n\n")
                    + f"شناسه: <code>{opid[:16]}</code>\n"
                    f"وضعیت: <b>{_text(op['status'])}</b>\n"
                    f"IP: <code>{_text(op.get('public_ipv4') or 'نامشخص')}</code>\n\n"
                    "این اقدام فقط پرونده عملیات را می‌بندد و قفل خرید را آزاد می‌کند؛ "
                    "VPS، WireGuard، DNS و کاربران را حذف یا جابه‌جا نمی‌کند.\n"
                    + (f"⚠️ نتیجه POST خرید نامشخص است؛ لغو محلی بدون تماس با Cloudzy انجام می‌شود.\n"
                       f"Hostname: <code>{_text(op['hostname'])}</code>\n"
                       "VPS احتمالی حذف یا لغو نمی‌شود و هزینه آن ممکن است ادامه داشته باشد. "
                       "برای تعیین تکلیف مالی، پنل Cloudzy را جداگانه بررسی کنید. "
                       "با تأیید، پرونده در Journal قرنطینه و قفل خرید محلی آزاد می‌شود."
                       if uncertain else
                       "❗ اگر VPS هنوز وجود دارد، هزینه‌های آن متوقف نمی‌شود. "
                       "آثار احتمالی نصب ناقص نیازمند رسیدگی جداگانه‌اند."),
                    [[("✅ پذیرش ریسک و خروج از قفل خرید" if uncertain
                       else "✅ لغو قطعی و آزادسازی قفل",
                       "apps_cz_qcancelyes_" + nonce)],
                     [("↩️ بازگشت بدون لغو", "apps_cz_qview_" + opid)]], markup)
            elif data.startswith("apps_cz_qview_"):
                op = await asyncio.to_thread(self.store.get, data[len("apps_cz_qview_"):])
                if not op:
                    raise QuickEdgeHold("OPERATION_NOT_FOUND")
                await self._operation_screen(query, op, markup, actor, chat)
            elif data.startswith("apps_cz_qdetails_"):
                opid = data[len("apps_cz_qdetails_"):]
                op = await asyncio.to_thread(self.store.get, opid)
                if not op or (op["actor_id"], op["chat_id"]) != (actor, chat):
                    raise QuickEdgeHold("OPERATION_OWNER_MISMATCH")
                run = await asyncio.to_thread(self.quick_runs.get, opid)
                await self._display(query, technical_receipt(op, run),
                    [[("↩️ بازگشت به وضعیت عملیات", "apps_cz_qview_" + opid)]],
                    markup)
            elif data.startswith("apps_cz_qrecover_"):
                opid = data[len("apps_cz_qrecover_"):]
                op = await asyncio.to_thread(self.store.get, opid)
                if (op["actor_id"], op["chat_id"]) != (actor, chat):
                    raise RecoveryHold("RECOVERY_OWNER_MISMATCH")
                await self._recovery_screen(query, op, markup, actor, chat)
            elif data.startswith("apps_cz_qrinstalled_"):
                opid = data[len("apps_cz_qrinstalled_"):]
                op = await asyncio.to_thread(self.store.get, opid)
                if (op["actor_id"], op["chat_id"]) != (actor, chat) or op["status"] != "HOLD_PROVISION":
                    raise RecoveryHold("RECOVERY_NOT_AVAILABLE")
                if opid in self._running:
                    raise RecoveryHold("OPERATION_ALREADY_RUNNING")
                # A receipt alone is NOT proof of an installed Edge.
                await asyncio.to_thread(self._check_install_evidence, op)
                nonce = secrets.token_hex(6)
                context.user_data["cz_recovery"] = {
                    "id": opid, "kind": "existing", "actor": actor, "chat": chat,
                    "nonce": nonce, "expires": self.now() + 180,
                }
                await self._display(query,
                    "🔎 <b>تأیید نصب موجود Edge</b>\n\n"
                    f"IP: <code>{_text(op['public_ipv4'])}</code>\n"
                    "✅ رکورد Edge موجود با VPS مطابقت دارد و در مسیر کاربران نیست.\n"
                    "⚠️ این بررسی هنوز سلامت زنده SSH، WireGuard و Provider را ثابت نکرده است.\n"
                    "با تأیید، فقط این شواهد زنده بررسی می‌شوند و در صورت موفقیت، "
                    "Journal نصب موجود ثبت می‌شود. اسکریپت نصب اجرا نخواهد شد.",
                    [[("✅ بررسی زنده و ثبت نصب موجود", "apps_cz_qryes_" + nonce)],
                     [("↩️ بازگشت", "apps_cz_qrecover_" + opid)]], markup)
            elif data.startswith("apps_cz_qrstandby_"):
                opid = data[len("apps_cz_qrstandby_"):]
                op = await asyncio.to_thread(self.store.get, opid)
                run = await asyncio.to_thread(self.quick_runs.get, opid)
                if (op["actor_id"], op["chat_id"]) != (actor, chat) or op["status"] != "EDGE_READY":
                    raise RecoveryHold("RECOVERY_OWNER_MISMATCH")
                if not run or run["stage"] != "HOLD" or opid in self._running:
                    raise RecoveryHold("RECOVERY_STANDBY_NOT_RESUMABLE")
                nonce = secrets.token_hex(6)
                context.user_data["cz_recovery"] = {
                    "id": opid, "kind": "standby", "actor": actor, "chat": chat,
                    "nonce": nonce, "expires": self.now() + 180,
                }
                await self._display(query,
                    "🎯 <b>ادامه کنترل‌شده Standby</b>\n\n"
                    f"Edge: <code>{_text(op['public_ipv4'])}</code>\n"
                    "نصب Edge قبلاً تأیید شده است. بررسی‌های تازه Core، "
                    "Cloudzy، SSH و WireGuard با همان VPS انجام می‌شوند.\n"
                    "✅ هیچ خرید یا نصب جدید و هیچ انتقال کاربری انجام نمی‌شود.\n"
                    "⚠️ اگر نتیجه نامعلوم بماند، عملیات دوباره وارد توقف امن خواهد شد.",
                    [[("✅ شروع بررسی و ادامه امن", "apps_cz_qryes_" + nonce)],
                     [("↩️ بازگشت", "apps_cz_qrecover_" + opid)]], markup)
            elif data.startswith("apps_cz_qryes_"):
                pending = context.user_data.get("cz_recovery")
                nonce = data[len("apps_cz_qryes_"):]
                if (not isinstance(pending, dict) or pending.get("nonce") != nonce
                        or pending.get("actor") != actor or pending.get("chat") != chat
                        or self.now() >= pending.get("expires", 0)):
                    raise RecoveryHold("RECOVERY_CONFIRMATION_EXPIRED")
                opid = pending["id"]
                if opid in self._running:
                    raise RecoveryHold("OPERATION_ALREADY_RUNNING")
                context.user_data.pop("cz_recovery", None)  # single-use approval
                if pending["kind"] == "existing":
                    # No automatic retries: this worker only reads live evidence
                    # and conditionally commits a previously installed Edge.
                    self._launch(app, opid, self._recover_existing_edge(
                        opid, actor, chat, app))
                elif pending["kind"] == "standby":
                    if not self.cz06_enabled() or self.standby_service is None:
                        raise RecoveryHold("RECOVERY_STANDBY_DISABLED")
                    op = await asyncio.to_thread(self.store.get, opid)
                    if (op["actor_id"], op["chat_id"]) != (actor, chat) or op["status"] != "EDGE_READY":
                        raise RecoveryHold("RECOVERY_EDGE_NOT_READY_OR_OWNER_CHANGED")
                    await self._preflight()
                    await asyncio.to_thread(
                        commit_standby_resume, self.store.db, opid,
                        actor=actor, chat=chat, now=self.now())
                    self._launch(app, opid, self._activate_standby(opid, chat, app))
                else:
                    raise RecoveryHold("RECOVERY_UNKNOWN_ACTION")
                await self._display(query,
                    "🔍 <b>بازیابی کنترل‌شده آغاز شد.</b>\n"
                    "نتیجه را از وضعیت عملیات بررسی کنید. هیچ خرید یا نصب دوباره‌ای آغاز نشده است.",
                    [[("📋 وضعیت همان عملیات", "apps_cz_qview_" + opid)]], markup)
            elif data.startswith("apps_cz6_resume_"):
                opid = data[len("apps_cz6_resume_"):]
                op = await asyncio.to_thread(self.store.get, opid)
                run = await asyncio.to_thread(self.quick_runs.get, opid)
                if not run or run["actor_id"] != actor or run["chat_id"] != chat:
                    raise QuickRelayHold("WORKFLOW_OWNER_MISMATCH")
                if op["status"] != "EDGE_READY" or run["stage"] not in (
                        "INSTALLING", "EDGE_READY", "STANDBY_VERIFYING"):
                    raise QuickRelayHold("WORKFLOW_NOT_RESUMABLE")
                if run["stage"] == "INSTALLING":
                    await self._quick_stage(opid, "EDGE_READY", "INSTALLING", app)
                if opid in self._running:
                    raise QuickRelayHold("OPERATION_ALREADY_RUNNING")
                await self._display(query,
                    "🔍 در حال بررسی ادامه امن Standby؛ خرید یا نصب دوباره انجام نمی‌شود.",
                    [[("📋 وضعیت", "apps_cz_operations")]], markup)
                self._launch(app, opid, self._activate_standby(opid, chat, app))
            elif data.startswith("apps_cz_qcheck_"):
                opid = data[len("apps_cz_qcheck_"):]
                op = await asyncio.to_thread(self.store.get, opid)
                if op["actor_id"] != actor or op["chat_id"] != chat:
                    raise QuickEdgeHold("OPERATION_OWNER_MISMATCH")
                if op["status"] not in ("CREATING", "CREATE_UNCERTAIN", "CREATED",
                                      "WAITING", "HOLD_WAIT", "HOLD_IP", "HOLD_SSH"):
                    raise QuickEdgeHold("RECONCILIATION_UNAVAILABLE")
                # Only ONE read-only reconciliation task; no create/provision retry.
                await self._display(query, "🔎 در حال بررسی مجدد وضعیت VPS بدون خرید تازه...",
                    [[("📋 وضعیت", "apps_cz_operations")]], markup)
                self._launch(app, opid, self._reconcile(opid, chat, app))
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
                    f"نوع کلید: <code>{_text(op['host_key_type'])}</code>\n"
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
                await self._quick_stage(opid, "INSTALLING", ("HOSTKEY_PENDING",), app)
                await self._display(query, "🛠 شروع نصب Legacy Edge با کلید SSH تأییدشده.\n"
                    "این مرحله ممکن است بخشی از سرور و WireGuard را تغییر دهد؛ "
                    "اگر عملیات نامعلوم ماند، نصب را دوباره شروع نکنید.",
                    [[("📋 وضعیت", "apps_cz_operations")]], markup)
                self._launch(app, opid, self._install(opid, chat, app))
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
                pending = context.user_data.get("cz3_addkey")
                if (not isinstance(pending, dict) or pending.get("actor") != actor
                        or pending.get("chat") != chat
                        or self.now() >= pending.get("expires", 0)
                        or pending.get("nonce") != data[len("apps_cz_qkeyyes_"):]):
                    raise QuickEdgeHold("SSH_KEY_CONFIRMATION_EXPIRED")
                context.user_data.pop("cz3_addkey", None)  # consumed once by correct operator
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
            ref = secrets.token_hex(4)
            log.error("CZ05_CALLBACK ref=%s stage=provider_write status=UNCERTAIN", ref)
            await query.message.reply_text(
                f"⚠️ نتیجه درخواست Cloudzy نامشخص است. پیگیری: CZ05-{ref}. "
                "ابتدا وضعیت عملیات را بررسی کنید؛ خرید را تکرار نکنید.")
        except CloudzyAPIError as exc:
            ref = secrets.token_hex(4)
            read_only = _safe_read_selection_callback(data)
            log.warning("CZ05_CALLBACK ref=%s stage=%s http=%s",
                        ref, "provider_read" if read_only else "provider_action",
                        exc.status)
            hint = _cloudzy_http_hint(exc.status, read_only=read_only)
            await query.message.reply_text(f"{hint}\nپیگیری: CZ05-{ref}")
        except CloudzyError:
            ref = secrets.token_hex(4)
            read_only = _safe_read_selection_callback(data)
            log.warning("CZ05_CALLBACK ref=%s stage=%s code=PROVIDER_RESPONSE_UNAVAILABLE",
                        ref, "provider_read" if read_only else "provider_action")
            if read_only:
                hint = ("☁️ ارتباط با Cloudzy موقتاً برقرار نشد یا پاسخ معتبری دریافت نشد. "
                        "لطفاً چند ثانیه بعد دوباره تلاش کنید. "
                        "هیچ خریدی انجام نشده است.")
            else:
                hint = ("⚠️ پاسخ Cloudzy قابل تأیید نیست. "
                        "وضعیت عملیات را بررسی کنید و درخواست را تکرار نکنید.")
            await query.message.reply_text(f"{hint}\nپیگیری: CZ05-{ref}")
        except (QuickEdgeHold, QuickRelayHold, RecoveryHold, CatalogHold, ValueError, TypeError, KeyError) as exc:
            ref = secrets.token_hex(4)
            code = str(exc) if isinstance(exc, (QuickEdgeHold, QuickRelayHold, RecoveryHold, CatalogHold)) else type(exc).__name__
            log.warning("CZ05_CALLBACK ref=%s stage=selection reason=%s", ref, code)
            if code == "CANCEL_CONFIRMATION_EXPIRED":
                await self._display(
                    query, "⌛️ <b>تأیید لغو منقضی یا جایگزین شده است.</b>\n"
                    "این خطا مربوط به Cloudzy نیست؛ پرونده را دوباره باز کنید "
                    "و یک تأیید لغو جدید بگیرید. هیچ خرید یا حذفی انجام نشد.",
                    [[("📋 سوابق و وضعیت عملیات", "apps_cz_operations")]], markup)
            else:
                await query.message.reply_text(
                    f"⛔️ بررسی Cloudzy متوقف شد. کد: {_text(code)} | پیگیری: CZ05-{ref}. "
                    "هیچ خریدی انجام ندهید تا علت بررسی شود.")
        except Exception:
            ref = secrets.token_hex(4)
            log.exception("CZ05_CALLBACK ref=%s stage=unexpected", ref)
            await query.message.reply_text(
                f"⛔️ خطای غیرمنتظره Cloudzy. پیگیری: CZ05-{ref}. وضعیت عملیات را بررسی کنید.")

    async def _quick_stage(self, opid, stage, expected, app=None, *, code=""):
        run = await asyncio.to_thread(self.quick_runs.get, opid)
        if run is None:
            return
        await asyncio.to_thread(self.quick_runs.advance, opid, stage,
                                expected=expected, code=code)
        if app is None or run["message_id"] is None:
            return
        try:
            updated = await asyncio.to_thread(self.quick_runs.get, opid)
            receipt = await asyncio.to_thread(self.store.get, opid)
            # Preserve a direct return to the operation journal on every
            # automatic progress edit, including the terminal READY screen.
            from telegram import InlineKeyboardButton, InlineKeyboardMarkup
            await app.bot.edit_message_text(
                chat_id=run["chat_id"], message_id=run["message_id"],
                text=progress_html(updated, receipt), parse_mode="HTML",
                reply_markup=InlineKeyboardMarkup([[
                    InlineKeyboardButton("📋 وضعیت عملیات",
                                         callback_data="apps_cz_operations")
                ]]))
        except Exception:
            # A Telegram edit failure must never re-run a paid or remote operation.
            log.warning("CZ06_PROGRESS_DELIVERY_FAILED op=%s stage=%s", opid[:16], stage)

    async def _activate_standby(self, opid, chat, app):
        run = await asyncio.to_thread(self.quick_runs.get, opid)
        if run is None:
            return  # Legacy CZ-03 flow has no auto promotion.
        receipt = await asyncio.to_thread(self.store.get, opid)
        if receipt["status"] != "EDGE_READY" or not receipt.get("provider_server_id") or not receipt.get("public_ipv4"):
            raise QuickRelayHold("EDGE_RECEIPT_NOT_READY")
        try:
            if run["stage"] == "EDGE_READY":
                await self._quick_stage(opid, "STANDBY_VERIFYING", "EDGE_READY", app)
            elif run["stage"] != "STANDBY_VERIFYING":
                raise QuickRelayHold("INVALID_STANDBY_STAGE")
            await self._preflight()  # Protected Core security gate, without creating VPS.
            await promote_standby_once(
                self.standby_service,
                actor=run["actor_id"], chat=run["chat_id"],
                host=receipt["public_ipv4"], provider_id=receipt["provider_server_id"],
            )
            await self._quick_stage(opid, "READY", "STANDBY_VERIFYING", app)
            await app.bot.send_message(chat,
                f"✅ CZ-06 آماده: Edge {receipt['public_ipv4']} به Standby تبدیل شد. "
                "DNS، Relay پیش‌فرض و کاربران بدون تغییر هستند.")
        except Exception as exc:
            code = ("STANDBY_VERIFICATION_HOLD" if isinstance(exc, QuickRelayHold)
                    else "STANDBY_OPERATION_REQUIRES_RECONCILIATION")
            log.exception("CZ06_STANDBY_HOLD op=%s code=%s", opid[:16], code)
            try:
                await self._quick_stage(opid, "HOLD", ("STANDBY_VERIFYING", "EDGE_READY"),
                                        app, code=code)
            except QuickRelayHold:
                pass
            await app.bot.send_message(chat,
                f"⛔️ CZ-06 در Standby متوقف شد. کد: {code}. "
                f"پیگیری: {opid[:16]}. هیچ انتقال کاربری انجام نشد.")

    async def _eligible_for_region(self, region):
        # Two independently fetched, exact-region reads; no generic price fallback.
        # Only read-only GET calls may be repeated, at most once, on transient
        # transport errors. HTTP 401/403/429 and charged POST are never retried.
        async def read_once(method, *args, **kwargs):
            for attempt in range(2):
                try:
                    return await self._cloudzy(method, *args, **kwargs)
                except CloudzyAPIError:
                    raise
                except CloudzyError:
                    if attempt:
                        raise
                    await asyncio.sleep(0.25)
        catalog = await read_once(
            "list_plans", region=region, billing_cycle="hourly")
        availability = await read_once("list_plan_availability", region)
        return eligible_offers(catalog, availability, region=region)

    async def _check_offer_current(self, region, plan_id, cents):
        offers = await self._eligible_for_region(region)
        if not any(pid == plan_id and amount == cents for pid, _name, amount, _scope, _basis in offers):
            raise CatalogHold("PLAN_STOCK_OR_HOURLY_PRICE_CHANGED")
        try:
            require_base_hourly_ceiling(
                cents, os.environ.get("NVL_CLOUDZY_MAX_BASE_HOURLY_CENTS"))
        except PurchaseHold as exc:
            raise CatalogHold(str(exc)) from None

    async def _plans(self, query, session, markup, page=0, *, offers=None):
        if session.get("cycle") != "hourly":
            raise CatalogHold("HOURLY_ONLY")
        all_rows = offers if offers is not None else await self._eligible_for_region(session["region"])
        all_rows = all_rows[:120]
        max_page = max(1, (len(all_rows) + PAGE_SIZE - 1) // PAGE_SIZE)
        page = min(page, max_page - 1)
        tokens = self._token(all_rows[page*PAGE_SIZE:(page+1)*PAGE_SIZE])
        session["plans"] = tokens
        rows = [[(f"📦 {name[:22]} · {price} سنت/ساعت", "apps_cz_qp_" + token)]
                for token, (_, name, price, _, _) in tokens.items()]
        if page:
            rows.append([("◀️ قبلی", f"apps_cz_qpg_{page-1}")])
        if page + 1 < max_page:
            rows.append([("بعدی ▶️", f"apps_cz_qpg_{page+1}")])
        rows.append([("↩️ انتخاب منطقه", "apps_cz_wizard")])
        await self._display(query,
            "📦 <b>پلن‌های ساعتی و موجود Regular CPU</b>\n"
            f"منطقه: {_text(session['region_name'])}\n"
            f"صفحه {page+1}/{max_page}\n"
            f"پلن‌های واجد شرایط: {len(all_rows)}\n\n"
            "⚠️ قیمت کاتالوگ برحسب سنت/ساعت و تقریبی است؛ هزینه IPv4 "
            "و مبلغ نهایی سفارش ممکن است متفاوت باشد.\n"
            "موجودی لحظه‌ای پیش از خرید دوباره کنترل می‌شود.",
            rows, markup)

    async def _operation_screen(self, query, op, markup, actor, chat):
        """One readable status for an existing receipt; buttons are pure gates.

        Only legacy handlers execute mutations. A visible navigation button
        never qualifies an Edge, repairs a HOLD, or bypasses the CZ-06 journal.
        """
        status = op["status"]
        opid = op["id"]
        run = await asyncio.to_thread(self.quick_runs.get, opid)
        owner = (op["actor_id"], op["chat_id"]) == (actor, chat)
        is_running = opid in self._running
        rows = []

        if owner:
            if status in ("CREATING", "CREATE_UNCERTAIN", "CREATED", "WAITING",
                          "HOLD_WAIT", "HOLD_IP", "HOLD_SSH") and not is_running:
                rows.append([("🔎 بررسی همان VPS؛ بدون خرید", "apps_cz_qcheck_" + opid)])

            if status == "HOSTKEY_PENDING":
                rows.append([("🔐 تأیید مستقل اثرانگشت SSH", "apps_cz_qreview_" + opid)])

            if status == "EDGE_READY":
                if run and run["stage"] in ("INSTALLING", "EDGE_READY", "STANDBY_VERIFYING"):
                    if not is_running:
                        rows.append([("▶️ بررسی و ادامه امن Standby", "apps_cz6_resume_" + opid)])
                elif run and run["stage"] == "READY":
                    rows.append([("🔍 بررسی آمادگی انتقال CZ-07", "apps_cz7_home")])
                else:
                    # Navigates to the existing guarded manual standby flow.
                    # Does NOT mark CZ06 READY or enable automatic CZ07.
                    rows.append([("🎯 مدیریت Standby همین Edge", "apps_cz4_vps")])
                    rows.append([("↪️ مسیر کنترل‌شده دستی", "apps_cz5_home")])

            if status.startswith("HOLD") or status == "CREATE_UNCERTAIN":
                rows.append([("🖥 مشاهده VPSهای موجود", "apps_cz_servers_0")])
                rows.append([("🌐 مشاهده فهرست Edgeها", "apps_cz_edge")])

            if (status not in ("REJECTED", "CANCELLED")
                    and not is_running
                    and recovery_kind(op, run) not in ("READY", "MANUAL_EDGE")):
                rows.append([("🩺 مسیر بازیابی همین VPS", "apps_cz_qrecover_" + opid)])

            if status in CANCELLABLE_STATES and not is_running:
                rows.append([("🛡 درخواست لغو و تعیین تکلیف خرید نامشخص"
                             if status == "CREATE_UNCERTAIN"
                             else "❌ بررسی بستن پرونده (بدون حذف VPS)",
                             "apps_cz_qcancel_" + opid)])

            rows.append([("🔎 جزئیات فنی و کد خطا", "apps_cz_qdetails_" + opid)])
        rows.append([("🔄 تازه‌سازی وضعیت", "apps_cz_qview_" + opid)])
        rows.append([("↩️ Cloudzy", "apps_cz_home")])

        if run:
            text = progress_html(run, op, now=self.now())
        else:
            text = ("📋 <b>پرونده ساخت Edge</b>\n"
                    f"مرحله: <b>{_text(receipt_title(status))}</b>\n"
                    f"IP: <code>{_text(op.get('public_ipv4') or 'نامشخص')}</code>\n"
                    f"شناسه: <code>{opid[:16]}</code>")

        text += "\n\n<b>نتیجه فعلی</b>\n" + receipt_result(op, run)
        if status in ("CREATING", "WAITING", "PROVISIONING") and not run:
            elapsed = max(0, int(self.now()) - int(op.get("updated_at") or self.now()))
            minutes, seconds = divmod(elapsed, 60)
            text += f"\n\n⏱ زمان سپری‌شده این مرحله: {minutes:02d}:{seconds:02d}"
        if status in ("CREATING", "PROVISIONING"):
            text += ("\n⚠️ اگر بات ری‌استارت شده، وضعیت مرحله ممکن است نامشخص باشد؛"
                     " به‌جای نصب مجدد، سوابق را بررسی کنید.")
        if status == "HOSTKEY_PENDING":
            text += (f"\n\n🔐 اثرانگشت SSH: "
                     f"<code>{_text(op.get('host_key_fingerprint') or 'نامشخص')}</code>"
                     "\nفقط پس از تطبیق با منبع مستقل آن را تأیید کنید.")
        text += "\n\n🛡 تا قبل از تأییدهای جداگانه، DNS و کاربران منتقل نمی‌شوند."
        await self._display(query, text, rows, markup)

    def _check_install_evidence(self, op):
        with self.store.db() as db:
            return inspect_inactive_install(db, op)

    async def _recovery_screen(self, query, op, markup, actor, chat):
        if (op["actor_id"], op["chat_id"]) != (actor, chat):
            raise RecoveryHold("RECOVERY_OWNER_MISMATCH")
        run = await asyncio.to_thread(self.quick_runs.get, op["id"])
        kind = recovery_kind(op, run)
        opid = op["id"]
        rows = []
        if opid not in self._running:
            if kind == "NEEDS_PROVIDER_CHECK" and op["status"] in RECONCILABLE:
                rows.append([("🔎 بررسی Cloudzy بدون خرید", "apps_cz_qcheck_" + opid)])
            if kind == "NEEDS_FINGERPRINT":
                rows.append([("🔐 تأیید مستقل SSH همان VPS", "apps_cz_qreview_" + opid)])
            if kind in ("IN_PROGRESS", "REVIEW_ONLY"):
                rows.append([("🖥 مشاهده VPSهای موجود", "apps_cz_servers_0")])
                rows.append([("🌐 بررسی فهرست Edgeها", "apps_cz_edge")])
            if kind == "EXISTING_INSTALL_CHECK":
                try:
                    await asyncio.to_thread(self._check_install_evidence, op)
                except (RecoveryHold, __import__("sqlite3").Error):
                    # A partial/uncertain install cannot be automatically replayed.
                    rows.append([("🖥 بررسی VPS موجود", "apps_cz_servers_0")])
                    rows.append([("🌐 بررسی فهرست Edgeها", "apps_cz_edge")])
                else:
                    rows.append([("🔍 بررسی و تأیید نصب موجود", "apps_cz_qrinstalled_" + opid)])
            if kind == "STANDBY_RECHECK" and run and run["stage"] == "HOLD":
                rows.append([("🎯 ادامه امن Standby", "apps_cz_qrstandby_" + opid)])
            if kind in ("STANDBY_RECHECK", "MANUAL_EDGE"):
                rows.append([("↪️ مدیریت Standby دستی", "apps_cz4_vps")])
                rows.append([("↪️ انتقال کنترل‌شده دستی", "apps_cz5_home")])
            if kind == "CANCELLED":
                rows.append([("🖥 VPSهای Cloudzy", "apps_cz_servers_0")])
        rows.append([("📋 وضعیت پرونده", "apps_cz_qview_" + opid)])
        rows.append([("↩️ Cloudzy", "apps_cz_home")])
        text = recovery_message(op, run)
        if kind == "EXISTING_INSTALL_CHECK":
            text += ("\n\n⚠️ اگر شواهد نصب موجود معتبر نباشند، فقط بررسی دستی مجاز است؛"
                     " تکرار کامل نصب توسط بات ارائه نمی‌شود.")
        if kind == "STANDBY_RECHECK" and run and run["stage"] == "HOLD":
            text += ("\n\n✅ Edge قبلاً تأیید شده است؛ فقط مرحله Standby"
                     " با گیت‌های قبلی دوباره بررسی می‌شود.")
        await self._display(query, text, rows, markup)

    async def _recover_existing_edge(self, opid, actor, chat, app):
        """Read-only remote proofs then atomic journal commit, never re-install."""
        safe_code = "RECOVERY_EVIDENCE_UNVERIFIED"
        try:
            op = await asyncio.to_thread(self.store.get, opid)
            if ((op["actor_id"], op["chat_id"]) != (actor, chat)
                    or op["status"] != "HOLD_PROVISION"):
                raise RecoveryHold("RECOVERY_STATE_CHANGED")
            await asyncio.to_thread(self._check_install_evidence, op)
            port, pub = await self._preflight()
            if port != op["customer_port"] or hashlib.sha256(pub.encode()).hexdigest() != op["public_key_sha"]:
                raise RecoveryHold("RECOVERY_CORE_IDENTITY_CHANGED")
            if not op.get("host_key_type") or not op.get("host_key_base64"):
                raise RecoveryHold("RECOVERY_SSH_PIN_MISSING")
            key_type, key_b64, _fp = await asyncio.to_thread(self.fingerprint, op["public_ipv4"])
            if (key_type, key_b64) != (op["host_key_type"], op["host_key_base64"]):
                raise RecoveryHold("RECOVERY_SSH_HOST_KEY_CHANGED")
            if self.standby_service is None:
                raise RecoveryHold("RECOVERY_STANDBY_ADAPTER_MISSING")
            server_state = await self.standby_service._provider(
                op["provider_server_id"], op["public_ipv4"])
            if server_state != "active":
                raise RecoveryHold("RECOVERY_PROVIDER_NOT_ACTIVE")
            # The actual Legacy postcheck also verifies provider ownership and
            # service reachability; probe additionally requires WG/Core path.
            if await self.verify(
                    op["public_ipv4"], op["customer_port"],
                    op["provider_server_id"]) is not True:
                raise RecoveryHold("RECOVERY_LEGACY_POSTCHECK_FAILED")
            with self.store.db() as db:
                network_row = db.execute(
                    "SELECT service_port,admin_ssh_port FROM host_pool WHERE host=?",
                    (op["public_ipv4"],)
                ).fetchone()
                if (not network_row or int(network_row[0] or 0) != op["customer_port"]):
                    raise RecoveryHold("RECOVERY_PORT_CHANGED")
                management_port = int(network_row[1] or 22)
            if await self.standby_service.probe(
                    op["public_ipv4"], op["customer_port"], management_port) is not True:
                raise RecoveryHold("RECOVERY_WIREGUARD_NOT_VERIFIED")
            await asyncio.to_thread(
                commit_existing_install, self.store.db, opid,
                actor=actor, chat=chat, now=self.now())
        except Exception as exc:
            if isinstance(exc, RecoveryHold):
                safe_code = str(exc)
            log.warning("CZ_RECOVERY_INSTALL_HOLD op=%s code=%s", opid[:16], safe_code)
            try:
                await app.bot.send_message(
                    chat, f"⛔️ شواهد برای پذیرش نصب موجود کافی نیست. "
                          f"کد: {safe_code} | عملیات: {opid[:16]}. "
                          "وضعیت قبلی حفظ شده است؛ نصب را تکرار نکنید.")
            except Exception:
                log.warning("CZ_RECOVERY_HOLD_DELIVERY_FAILED op=%s", opid[:16])
            return
        # Telegram delivery is not part of the committed journal transaction.
        # Failure to send a success message must not be reported as a rollback.
        try:
            await app.bot.send_message(
                chat, f"✅ نصب موجود Edge {op['public_ipv4']} با شواهد زنده تأیید شد. "
                      "هیچ اسکریپتی دوباره اجرا نشد. اکنون از «وضعیت عملیات»"
                      " آماده‌سازی Standby را ادامه دهید.")
        except Exception:
            log.warning("CZ_RECOVERY_SUCCESS_DELIVERY_FAILED op=%s", opid[:16])

    async def _buy(self, opid, chat, pub, app):
        # No Cloudzy POST until fresh stock and price still match the receipt.
        try:
            op = await asyncio.to_thread(self.store.get, opid)
            if op["billing_cycle"] != "hourly":
                raise CatalogHold("HOURLY_ONLY")
            await self._check_offer_current(op["region"], op["plan_id"], op["price_cents"])
        except (CatalogHold, CloudzyAPIError, CloudzyError, QuickEdgeHold) as exc:
            issue = classify_preflight(exc)
            # No POST happened. Keep the historic CZ05 reason for catalog
            # rejection and use distinct stable codes for provider GET errors.
            reason = ("CZ05_STOCK_OR_PRICE_UNVERIFIED"
                      if isinstance(exc, CatalogHold) else issue.code)
            stage_code = ("PREPURCHASE_STOCK_UNVERIFIED"
                          if isinstance(exc, CatalogHold) else "PREPURCHASE_API_READ_FAILED")
            log.warning("CZ05_PRE_PURCHASE_BLOCK op=%s stage=preflight code=%s",
                        opid[:16], reason)
            try:
                await asyncio.to_thread(
                    self.store.change, opid, "CREATING", "REJECTED",
                    hold_reason=reason)
            except QuickEdgeHold:
                log.exception("CZ05_PRE_PURCHASE_JOURNAL_FAILED op=%s", opid[:16])
            await self._quick_stage(opid, "HOLD", "PURCHASING", app, code=stage_code)
            try:
                await app.bot.send_message(
                    chat, f"⛔️ {issue.title_fa}. {issue.next_action_fa} "
                          f"کد: {reason} | عملیات: {opid[:16]}")
            except Exception:
                log.warning("CZ05_PREPURCHASE_DELIVERY_FAILED op=%s", opid[:16])
            return
        except Exception:
            log.exception("CZ05_PRE_PURCHASE_UNEXPECTED op=%s", opid[:16])
            try:
                await asyncio.to_thread(self.store.change, opid, "CREATING", "REJECTED",
                                        hold_reason="CZ05_PREFLIGHT_ERROR")
            except QuickEdgeHold:
                pass
            await self._quick_stage(opid, "HOLD", "PURCHASING", app,
                                    code="PREPURCHASE_PREFLIGHT_FAILED")
            await app.bot.send_message(chat,
                f"⛔️ بررسی پیش از خرید ناموفق بود. کد: CZ05_PREFLIGHT_ERROR | عملیات: {opid[:16]}")
            return
        # The coordinator records an external-effect intent BEFORE entering
        # the paid POST. On journal failure we never contact Cloudzy.
        try:
            await asyncio.to_thread(self.store.mark_paid_intent, opid)
        except (UnifiedLinkHold, QuickEdgeHold, sqlite3.Error):
            log.error("UNIFIED_PRECHARGE_INTENT_HOLD op=%s", opid[:16])
            try:
                await app.bot.send_message(
                    chat, "⛔️ ثبت ایمن قصد خرید در دفتر عملیات ناموفق بود؛ "
                          "هیچ سفارش جدیدی ارسال نشد. Journal را بررسی کنید.")
            except Exception:
                pass
            return
        try:
            data = await self._cloudzy(
                "create_server", hostname=op["hostname"], plan_id=op["plan_id"],
                region=op["region"], os_template_id=OS_TEMPLATE,
                ip_version="ipv4", billing_cycle=op["billing_cycle"],
                ssh_public_keys=[pub], idempotency_key=op["idempotency_key"],
                confirm=True)
            server_id = _server_id(data)
            await asyncio.to_thread(
                self.store.change, opid, "CREATING", "CREATED", provider_server_id=server_id)
        except CloudzyAPIError as exc:
            issue = classify_create(exc)
            # Definite 4xx rejections are not confused with read failures.
            try:
                await asyncio.to_thread(self.store.change, opid, "CREATING", "REJECTED",
                                        hold_reason="CLOUDZY_HTTP_REJECTED_" + str(exc.status))
            except QuickEdgeHold:
                pass
            await self._quick_stage(opid, "HOLD", ("PURCHASING", "WAITING_PROVIDER"),
                                    app, code="PROVIDER_REJECTED")
            log.warning("CZ05_PURCHASE_REJECTED op=%s http=%s",
                        opid[:16], exc.status)
            try:
                await app.bot.send_message(
                    chat, f"⛔️ {issue.title_fa}. {issue.next_action_fa} "
                          f"HTTP {exc.status} | عملیات: {opid[:16]}")
            except Exception:
                log.warning("CZ05_CREATE_REJECTION_DELIVERY_FAILED op=%s", opid[:16])
            return
        except (CloudzyUncertainError, QuickEdgeHold, CloudzyError, Exception) as exc:
            # An ambiguous charged POST or failed receipt remains held. This
            # failure handler does not perform any second provider POST.
            reason = classify_create(exc).code
            log.error("CZ05_PURCHASE_UNCERTAIN op=%s reason=%s exception=%s",
                      opid[:16], reason, type(exc).__name__)
            await self._quick_stage(opid, "HOLD", ("PURCHASING", "WAITING_PROVIDER"),
                                    app, code=reason)
            try:
                await asyncio.to_thread(self.store.change, opid, "CREATING",
                    "CREATE_UNCERTAIN", hold_reason=reason)
            except QuickEdgeHold:
                pass
            try:
                await app.bot.send_message(chat, "⚠️ وضعیت خرید Cloudzy نامشخص است؛ خرید را تکرار نکنید. "
                                               "از «وضعیت عملیات» بررسی کنید.")
            except Exception:
                log.warning("CZ05_CREATE_UNCERTAIN_DELIVERY_FAILED op=%s", opid[:16])
            return
        # The provider POST and its receipt are already committed. Never
        # misclassify a progress-journal error as an uncertain charged POST.
        try:
            await self._quick_stage(opid, "WAITING_PROVIDER", "PURCHASING", app)
        except Exception:
            log.exception("CZ06_AFTER_CHARGE_JOURNAL_HOLD op=%s", opid[:16])
            await app.bot.send_message(
                chat, f"⚠️ خرید در Cloudzy ثبت شده، اما ثبت پیشرفت قطع شده است. "
                      f"پیگیری: {opid[:16]}. خرید را تکرار نکنید.")
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
        await self._quick_stage(opid, "HOSTKEY_PENDING",
                                ("PURCHASING", "WAITING_PROVIDER"), app)
        await app.bot.send_message(
            chat,
            "🔐 VPS Cloudzy ساخته شد. قبل از نصب، اثرانگشت SSH را "
            "از طریق کنسول معتبر Cloudzy مستقل بررسی کنید:\n\n"
            f"<code>{_text(fingerprint)}</code>\n"
            f"نوع کلید: <code>{_text(key_type)}</code>\n"
            f"IP: <code>{_text(op['public_ipv4'])}</code>\n"
            "سپس از «وضعیت عملیات» وارد بررسی و تأیید شوید.",
            parse_mode="HTML")

    async def _reconcile(self, opid, chat, app):
        try:
            op = await asyncio.to_thread(self.store.get, opid)
            current = op["status"]
            server_id = op.get("provider_server_id")
            # Crash-recovered CREATING is UNKNOWN, not proof no server was bought.
            # Never replay POST; only search exact unique op hostname.
            if current == "CREATING":
                await asyncio.to_thread(
                    self.store.change, opid, "CREATING", "CREATE_UNCERTAIN",
                    hold_reason="INTERRUPTED_CREATE_UNKNOWN")
                current = "CREATE_UNCERTAIN"
            if current == "WAITING":
                await asyncio.to_thread(
                    self.store.change, opid, "WAITING", "HOLD_WAIT",
                    hold_reason="INTERRUPTED_WAIT_RECHECK")
                current = "HOLD_WAIT"
            if current == "CREATE_UNCERTAIN":
                # Exact, unique hostname and provider ID are mandatory.
                # Missing VPS remains uncertain; never authorize re-purchase.
                inventory = _items(await self._cloudzy("list_servers"))
                try:
                    server_id = exact_existing_server(
                        inventory, hostname=op["hostname"],
                        provider_id=op.get("provider_server_id"))
                except PurchaseHold as exc:
                    raise QuickEdgeHold(str(exc)) from None
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

    async def _attest_install_provider_identity(self, op):
        """Fail closed on recycled IP or replaced VPS; GET only, no mutation.

        The provider ID is the primary identity; the public IPv4 and optional
        hostname must still match the original purchase receipt.
        """
        if not op.get("provider_server_id") or not op.get("public_ipv4"):
            raise QuickEdgeHold("INSTALL_PROVIDER_IDENTITY_MISSING")
        live = _obj(await self._cloudzy("get_server", op["provider_server_id"]))
        if _server_id(live) != op["provider_server_id"]:
            raise QuickEdgeHold("INSTALL_PROVIDER_ID_CHANGED")
        if _public_ipv4(live) != op["public_ipv4"]:
            raise QuickEdgeHold("INSTALL_PROVIDER_IP_CHANGED")
        live_name = _val(live, "hostname", "name")
        if live_name and str(live_name) != op.get("hostname"):
            raise QuickEdgeHold("INSTALL_PROVIDER_HOSTNAME_CHANGED")
        if str(_val(live, "state", "status") or "").lower() != "active":
            raise QuickEdgeHold("INSTALL_PROVIDER_NOT_ACTIVE")

    async def _install(self, opid, chat, app):
        stage = "CORE_PREFLIGHT"
        ip = "UNKNOWN"
        try:
            op = await asyncio.to_thread(self.store.get, opid)
            ip = op["public_ipv4"]
            port, pub = await self._preflight()
            if port != op["customer_port"] or hashlib.sha256(pub.encode()).hexdigest() != op["public_key_sha"]:
                raise QuickEdgeHold("CORE_IDENTITY_CHANGED")
            stage = "HOST_KEY_RECHECK"
            latest_type, latest_b64, _ = await asyncio.to_thread(
                self.fingerprint, op["public_ipv4"])
            if latest_type != op["host_key_type"] or latest_b64 != op["host_key_base64"]:
                raise QuickEdgeHold("HOST_KEY_CHANGED")
            # A stable receipt and SSH host key do not prove Cloudzy still
            # owns this exact VPS/IP. Never run legacy setup on recycled IPs.
            stage = "PROVIDER_IDENTITY"
            await self._attest_install_provider_identity(op)
            # The Legacy adapter rejects an already registered IP before
            # touching the provider or WireGuard. Make it an explicit, audited
            # early HOLD code instead of reporting an opaque RuntimeError.
            stage = "HOST_POOL_IDENTITY"
            collision = await asyncio.to_thread(self.store.existing_host, ip)
            if collision:
                raise QuickEdgeHold("CLOUDZY_IP_ALREADY_REGISTERED")
            stage = "LEGACY_PROVISION"
            log.info("CZ06_INSTALL op=%s ip=%s stage=%s code=START", opid[:16], ip, stage)
            ok, _ip, details = await self.provision(
                op["public_ipv4"], port, op["hostname"], chat, app, op["provider_server_id"],
                (latest_type, latest_b64),
            )
            if not ok or not isinstance(details, dict) or not details.get("tunnel_ok"):
                if isinstance(details, dict) and details.get("error_code") == "APT_LOCK_BUSY":
                    raise QuickEdgeHold("EDGE_APT_LOCK_BUSY")
                raise QuickEdgeHold("LEGACY_PROVISION_OR_WG_TUNNEL_NOT_VERIFIED")
            stage = "EDGE_POSTCHECK"
            log.info("CZ06_INSTALL op=%s ip=%s stage=%s code=START", opid[:16], ip, stage)
            verified = await self.verify(
                op["public_ipv4"], port, op["provider_server_id"])
            if verified is not True:
                raise QuickEdgeHold("LEGACY_EDGE_POSTCHECK_FAILED")
            # Re-read live provider ownership AFTER a potentially effectful
            # installer and BEFORE accepting the receipt. A failed check
            # holds the existing VPS; setup_edge_relay.sh is never replayed.
            stage = "PROVIDER_POSTCHECK"
            await self._attest_install_provider_identity(op)
            stage = "HOST_KEY_POSTCHECK"
            latest_type, latest_b64, _ = await asyncio.to_thread(
                self.fingerprint, op["public_ipv4"])
            if (latest_type, latest_b64) != (
                    op["host_key_type"], op["host_key_base64"]):
                raise QuickEdgeHold("HOST_KEY_CHANGED_AFTER_INSTALL")
            stage = "CORE_IDENTITY_POSTCHECK"
            port_again, public_again = await self._preflight()
            if (port_again != op["customer_port"]
                    or hashlib.sha256(public_again.encode()).hexdigest()
                    != op["public_key_sha"]):
                raise QuickEdgeHold("CORE_IDENTITY_CHANGED_AFTER_INSTALL")
            stage = "RECEIPT_COMMIT"
            await asyncio.to_thread(self.store.change, opid, "PROVISIONING", "EDGE_READY")
            run = await asyncio.to_thread(self.quick_runs.get, opid)
            if run:
                stage = "CZ06_STANDBY"
                await self._quick_stage(opid, "EDGE_READY", "INSTALLING", app)
                await self._activate_standby(opid, chat, app)
                return
            log.info("CZ06_INSTALL op=%s ip=%s stage=EDGE_READY code=SUCCESS", opid[:16], ip)
            await app.bot.send_message(
                chat, f"✅ Edge <code>{_text(op['public_ipv4'])}</code> با منطق Legacy آماده شد.\n"
                "در host_pool فعلاً غیرفعال است؛ DNS، Relay و کاربران تغییر نکرده‌اند.\n"
                "تأیید اتصال مشتری و فعال‌سازی Relay در فاز ۳ انجام می‌شود.",
                parse_mode="HTML")
        except Exception as exc:
            # Never log raw exception messages, provider payloads or SSH secrets.
            code = str(exc) if isinstance(exc, QuickEdgeHold) else type(exc).__name__
            if not re.fullmatch(r"[A-Z0-9_]{1,90}", code):
                code = "UNCLASSIFIED_INSTALL_ERROR"
            log.error("CZ06_INSTALL_HOLD op=%s ip=%s stage=%s code=%s",
                      opid[:16], ip, stage, code)
            try:
                reason = ("EDGE_APT_LOCK_BUSY" if code == "EDGE_APT_LOCK_BUSY"
                          else "CLOUDZY_IP_ALREADY_REGISTERED"
                          if stage == "HOST_POOL_IDENTITY" and
                          code == "CLOUDZY_IP_ALREADY_REGISTERED"
                          else "PARTIAL_OR_UNVERIFIED_LEGACY_INSTALL")
                await asyncio.to_thread(self.store.change, opid, "PROVISIONING",
                    "HOLD_PROVISION", hold_reason=reason)
            except Exception:
                log.error("CZ06_INSTALL_HOLD op=%s stage=RECEIPT_COMMIT code=JOURNAL_UPDATE_FAILED",
                          opid[:16])
            try:
                await self._quick_stage(opid, "HOLD", ("INSTALLING", "HOSTKEY_PENDING"),
                                        app, code="INSTALL_REQUIRES_RECONCILIATION")
            except Exception:
                log.error("CZ06_INSTALL_HOLD op=%s stage=CZ06_JOURNAL code=STAGE_UPDATE_FAILED",
                          opid[:16])
            if code == "EDGE_APT_LOCK_BUSY":
                await app.bot.send_message(
                    chat,
                    "⚠️ <b>آماده‌سازی بسته‌های Edge متوقف شد.</b>\n"
                    "APT سرور مشغول بود و پس از انتظار محدود آزاد نشد.\n"
                    "✅ هیچ اجرای مجدد خودکاری انجام نشده است.\n"
                    "🔒 پرونده در وضعیت توقف امن باقی مانده؛ نصب را از ابتدا تکرار نکنید.\n"
                    f"کد: <code>{code}</code> | پیگیری: <code>{opid[:16]}</code>",
                    parse_mode="HTML")
            else:
                await app.bot.send_message(chat,
                    f"⛔️ نصب Edge نتیجه قطعی ندارد. مرحله: {stage} | کد: {code} | "
                    f"پیگیری: {opid[:16]}. "
                    "ممکن است بخشی از WireGuard تغییر کرده باشد؛ نصب را دوباره اجرا نکنید.")
