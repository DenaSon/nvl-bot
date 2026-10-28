"""CZ-06: durable, opt-in Quick Relay journal and guarded CZ-04A Standby adapter.

No Cloudzy order, SSH install, DNS or user migration originates here.
The existing CZ-03 receipt is the charged-operation source of truth.
"""
from __future__ import annotations

import re
import time


STAGES = (
    "PURCHASING", "WAITING_PROVIDER", "HOSTKEY_PENDING", "INSTALLING",
    "EDGE_READY", "STANDBY_VERIFYING", "READY", "HOLD", "CANCELLED",
)


from cloudzy_unified_native import observe_cz06_status


class QuickRelayHold(RuntimeError):
    pass


class QuickRelayJournal:
    def __init__(self, conn_factory, *, now=time.time):
        self.db = conn_factory
        self.now = now

    @staticmethod
    def initialize(conn):
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cloudzy_cz06_runs (
                operation_id TEXT PRIMARY KEY REFERENCES cloudzy_edge_operations(id),
                actor_id INTEGER NOT NULL,
                chat_id INTEGER NOT NULL,
                message_id INTEGER,
                stage TEXT NOT NULL,
                detail_code TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
        """)
        existing = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='index' "
            "AND name='cloudzy_cz06_one_open'"
        ).fetchone()
        if existing and "'CANCELLED'" not in (existing[0] or ""):
            conn.execute("DROP INDEX cloudzy_cz06_one_open")
        conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS cloudzy_cz06_one_open
            ON cloudzy_cz06_runs((1))
            WHERE stage NOT IN ('READY','HOLD','CANCELLED')
        """)

    def create_in_receipt_transaction(self, conn, *, opid, actor, chat, message_id=None):
        self.initialize(conn)
        if message_id is not None and (type(message_id) is not int or message_id <= 0):
            raise QuickRelayHold("INVALID_PROGRESS_MESSAGE")
        ts = int(self.now())
        conn.execute("""
            INSERT INTO cloudzy_cz06_runs
            (operation_id,actor_id,chat_id,message_id,stage,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?)
        """, (opid, actor, chat, message_id, "PURCHASING", ts, ts))

    def get(self, opid):
        with self.db() as conn:
            self.initialize(conn)
            conn.row_factory = __import__("sqlite3").Row
            row = conn.execute(
                "SELECT * FROM cloudzy_cz06_runs WHERE operation_id=?", (opid,)
            ).fetchone()
            return dict(row) if row else None

    def advance(self, opid, stage, *, expected, code=""):
        if stage not in STAGES:
            raise QuickRelayHold("INVALID_STAGE")
        if (not isinstance(code, str) or
                not re.fullmatch(r"[A-Z0-9_]{0,90}", code)):
            raise QuickRelayHold("INVALID_DETAIL_CODE")
        expect = (expected,) if isinstance(expected, str) else tuple(expected)
        if not expect or any(value not in STAGES for value in expect):
            raise QuickRelayHold("INVALID_EXPECTED_STAGE")
        with self.db() as conn:
            self.initialize(conn)
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT stage FROM cloudzy_cz06_runs WHERE operation_id=?", (opid,)
            ).fetchone()
            if not row or row[0] not in expect:
                raise QuickRelayHold("WORKFLOW_STAGE_CHANGED")
            if conn.execute(
                "UPDATE cloudzy_cz06_runs SET stage=?,detail_code=?,updated_at=? "
                "WHERE operation_id=? AND stage=?",
                (stage, code, int(self.now()), opid, row[0])
            ).rowcount != 1:
                raise QuickRelayHold("WORKFLOW_CAS_FAILED")
            observe_cz06_status(conn, operation_id=opid, stage=stage,
                                now=int(self.now()))


def progress_html(run, receipt, *, now=None):
    # Elapsed time is an observation, not an ETA or a promise of completion.
    current_time = int(time.time() if now is None else now)
    stage_started = int(run.get("updated_at") or current_time)
    elapsed = max(0, current_time - stage_started)
    minutes, seconds = divmod(elapsed, 60)
    stages = [
        ("خرید VPS", "PURCHASING"),
        ("دریافت IP", "WAITING_PROVIDER"),
        ("تأیید مستقل SSH", "HOSTKEY_PENDING"),
        ("نصب و بررسی Edge", "INSTALLING"),
        ("فعال‌سازی Standby", "STANDBY_VERIFYING"),
    ]
    current = run["stage"]
    stage_title = {
        "PURCHASING": "ثبت خرید VPS",
        "WAITING_PROVIDER": "آماده‌شدن سرور و دریافت IP",
        "HOSTKEY_PENDING": "منتظر تأیید اثرانگشت SSH مدیر",
        "INSTALLING": "نصب و بررسی Edge",
        "EDGE_READY": "نصب Edge تأیید شد",
        "STANDBY_VERIFYING": "بررسی و فعال‌سازی Standby",
        "READY": "آماده ✅",
        "HOLD": "توقف امن؛ نیازمند بررسی",
        "CANCELLED": "لغوشده",
    }.get(current, current)
    position = {"PURCHASING": 0, "WAITING_PROVIDER": 1,
                "HOSTKEY_PENDING": 2, "INSTALLING": 3, "EDGE_READY": 4,
                "STANDBY_VERIFYING": 4, "READY": 5}.get(current, -1)
    rows = []
    edge_installed = receipt.get("status") == "EDGE_READY"
    for i, (title, _) in enumerate(stages):
        if current == "HOLD" and edge_installed:
            # The install receipt proves steps through Edge install, but NOT
            # standby. HOLD must never erase completed steps or imply READY.
            icon = "✅" if i < 4 else "⚠️"
        else:
            icon = "✅" if current == "READY" or (position > i) else "⏳" if position == i else "▫️"
        rows.append(f"{icon} {title}")
    warning = (
        "\n✅ عملیات لغو شده است؛ هیچ VPS یا تنظیمات Core خودکار حذف نشده‌اند."
        if current == "CANCELLED" else
        "\n⚠️ توقف امن؛ خرید یا نصب را بدون بررسی تکرار نکنید."
        if current == "HOLD" else
        "\n🔐 اثر انگشت SSH باید با منبع مستقل بررسی شود."
        if current == "HOSTKEY_PENDING" else ""
    )
    from html import escape
    return (
        "⚡ <b>Quick Relay | CZ-06</b>\n"
        f"پیگیری: <code>{escape(run['operation_id'][:16])}</code>\n"
        f"وضعیت: <b>{escape(stage_title)}</b> <code>{escape(current)}</code>\n"
        f"IP: <code>{escape(str(receipt.get('public_ipv4') or '—'))}</code>\n"
        + (f"⏱ سپری‌شده از شروع این مرحله: <b>{minutes:02d}:{seconds:02d}</b>\n"
           "🔒 عملیات در حال اجراست؛ درخواست خرید یا نصب تازه نزنید.\n"
           if current in ("PURCHASING", "WAITING_PROVIDER", "INSTALLING", "STANDBY_VERIFYING")
           else "")
        + "\n" + "\n".join(rows) + warning +
        (f"\nکد: <code>{escape(run['detail_code'])}</code>"
         if run["detail_code"] else "") +
        "\n\n🛡 DNS، Relay پیش‌فرض و کاربران تا CZ-07 تغییر نمی‌کنند."
    )


async def _attest_standby_live(service, host, provider_id, state):
    """Read-only postcheck; trust no stale host_pool/old promotion alone."""
    if (state["default"] or state["listed"] or state["users"]
            or state["auto"] or state["k2_onboard"]):
        raise QuickRelayHold("STANDBY_ROUTE_OR_AUTOMATION_CHANGED")
    if await service._provider(provider_id, host) != "active":
        raise QuickRelayHold("PROVIDER_NOT_ACTIVE")
    # The existing CZ04A probe is the authoritative fresh SSH/WG/Core-path
    # preflight. No new install, DNS write, worker or provider POST is allowed.
    if await service.probe(host, state["port"], state["admin_port"]) is not True:
        raise QuickRelayHold("FRESH_SSH_WG_PREFLIGHT_FAILED")


async def promote_standby_once(service, *, actor, chat, host, provider_id):
    """Adopt/promote one existing Cloudzy Edge with fresh fenced postchecks.

    An already-committed Standby is never accepted from the SQLite flags alone:
    protected CZ04A/6G gates, exact provider identity, and fresh SSH/WG must
    pass again, even following bot crashes or ambiguous Telegram delivery.
    """
    if service is None:
        raise QuickRelayHold("STANDBY_ADAPTER_UNAVAILABLE")
    import asyncio
    state = await asyncio.to_thread(service._state, host, provider_id, mutation=True)
    if state["active"] and state["standby"]:
        await _attest_standby_live(service, host, provider_id, state)
        return "READY"  # Reconcile an existing committed Standby; no write.
    service._isolated(state)
    await _attest_standby_live(service, host, provider_id, state)
    opid = await asyncio.to_thread(
        service._reserve, actor, chat, host, provider_id, "relay")
    try:
        await asyncio.to_thread(service._promote, opid, host, provider_id)
    except Exception:
        await asyncio.to_thread(service._finish, opid, "HOLD",
                                "CZ06_STANDBY_COMMIT_REQUIRES_REVIEW")
        raise
    # The DB mutation may have committed even if the following remote
    # observation fails: HOLD and recover this SAME provider ID; never
    # re-promote without a fresh verified read.
    committed = await asyncio.to_thread(
        service._state, host, provider_id, mutation=True)
    if not (committed["active"] and committed["standby"]):
        raise QuickRelayHold("STANDBY_POSTCOMMIT_STATE_UNVERIFIED")
    await _attest_standby_live(service, host, provider_id, committed)
    return "READY"
