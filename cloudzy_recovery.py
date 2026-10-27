"""CZ Phase 2: inspect and safely recover *existing* Edge evidence.

No package installs, VPS purchases, WireGuard writes, DNS updates or customer
moves are implemented here. Recovery is consented, owner-bound, and fail-closed.
"""
from __future__ import annotations

from html import escape
import sqlite3


class RecoveryHold(RuntimeError):
    """Safe machine-readable refusal; do not include remote payloads."""


RECONCILABLE = frozenset({
    "CREATING", "CREATE_UNCERTAIN", "CREATED", "WAITING",
    "HOLD_WAIT", "HOLD_IP", "HOLD_SSH",
})

REASONS = {
    "NEEDS_PROVIDER_CHECK": "ابتدا همان VPS نزد Cloudzy بررسی می‌شود؛ خرید تازه لازم نیست.",
    "NEEDS_FINGERPRINT": "اثر انگشت SSH باید مستقلاً با کنسول VPS تطبیق داده شود.",
    "STANDBY_RECHECK": "نصب Edge تأیید شده است؛ می‌توان آماده‌سازی Standby را پس از بررسی‌های تازه ادامه داد.",
    "EXISTING_INSTALL_CHECK": "نصب کامل نشده یا نتیجه نامشخص است؛ فقط در صورت وجود شواهد معتبر، نصب موجود تأیید می‌شود.",
    "IN_PROGRESS": "مرحله در حال اجرا یا نامشخص است؛ هیچ نصب یا خرید تکراری مجاز نیست.",
    "MANUAL_EDGE": "نصب Edge تأیید شده است؛ مسیر کنترل‌شده دستی در دسترس است.",
    "READY": "Standby آماده است؛ انتقال نیازمند بررسی جداگانه CZ-07 است.",
    "CANCELLED": "پرونده بسته شده است؛ بررسی VPS موجود همچنان امکان‌پذیر است.",
    "REVIEW_ONLY": "بازگشت خودکار مجاز نیست؛ وضعیت عملیات، منابع و Journal را بررسی کنید.",
}


def recovery_kind(receipt, run=None):
    status = str(receipt.get("status") or "")
    stage = str((run or {}).get("stage") or "")
    if status in RECONCILABLE:
        return "NEEDS_PROVIDER_CHECK"
    if status == "HOSTKEY_PENDING":
        return "NEEDS_FINGERPRINT"
    if status == "EDGE_READY" and stage == "READY":
        return "READY"
    if status == "EDGE_READY" and stage == "HOLD":
        return "STANDBY_RECHECK"
    if status == "EDGE_READY" and run and stage in (
            "INSTALLING", "EDGE_READY", "STANDBY_VERIFYING"):
        return "STANDBY_RECHECK"
    if status == "EDGE_READY":
        return "MANUAL_EDGE"
    if status == "HOLD_PROVISION":
        return "EXISTING_INSTALL_CHECK"
    if status == "PROVISIONING":
        return "IN_PROGRESS"
    if status == "CANCELLED":
        return "CANCELLED"
    return "REVIEW_ONLY"


def recovery_message(receipt, run=None):
    kind = recovery_kind(receipt, run)
    return (
        "🩺 <b>Smart Recovery | همان VPS</b>\n\n"
        f"IP: <code>{escape(str(receipt.get('public_ipv4') or 'نامشخص'))}</code>\n"
        f"شناسه: <code>{escape(str(receipt.get('id') or '')[:16])}</code>\n"
        f"وضعیت: <b>{escape(REASONS[kind])}</b>\n\n"
        "🛡 بررسی این صفحه هیچ خرید، نصب، DNS یا انتقال کاربری انجام نمی‌دهد. "
        "عملیات‌های تغییردهنده فقط با تأیید جداگانه و بررسی مجدد مجازند."
    )


def inspect_inactive_install(conn, receipt):
    """Assert exact Cloudzy identity + isolated state using SQLite truth.

    Call once for read-only preview and again inside BEGIN IMMEDIATE immediately
    before the atomic journal update. This NEVER infers WG health from a row.
    """
    ip = receipt.get("public_ipv4")
    provider = receipt.get("provider_server_id")
    if not isinstance(ip, str) or not ip or not isinstance(provider, str) or not provider:
        raise RecoveryHold("RECOVERY_IDENTITY_MISSING")
    required = ("host_pool", "settings", "ssh_accounts")
    existing = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}
    if any(name not in existing for name in required):
        raise RecoveryHold("RECOVERY_DATABASE_INCOMPLETE")
    host = conn.execute(
        "SELECT host,active,is_default,is_standby,provider,provider_instance_id "
        "FROM host_pool WHERE host=? OR provider_instance_id=?",
        (ip, provider),
    ).fetchall()
    if len(host) != 1 or tuple(host[0]) != (ip, 0, 0, 0, "cloudzy", provider):
        raise RecoveryHold("RECOVERY_HOST_NOT_ISOLATED")
    count = conn.execute("SELECT COUNT(*) FROM ssh_accounts WHERE host=?", (ip,)).fetchone()[0]
    if count:
        raise RecoveryHold("RECOVERY_USERS_ASSIGNED")
    settings = dict(conn.execute(
        "SELECT key,value FROM settings WHERE key IN "
        "('hosts','dns_current_ip','core_wg_public_ip',"
        "'auto_failover_mode','phase6h_auto_failover_enabled',"
        "'edge_egress_v1_onboard_enabled')"
    ).fetchall())
    if not settings.get("hosts") or not settings.get("dns_current_ip"):
        raise RecoveryHold("RECOVERY_ROUTE_UNKNOWN")
    if (ip in [x.strip() for x in settings["hosts"].split(",")]
            or ip in (settings["dns_current_ip"], settings.get("core_wg_public_ip"))):
        raise RecoveryHold("RECOVERY_ROUTE_ALREADY_REFERENCES_EDGE")
    if any(settings.get(k) == "1" for k in (
            "auto_failover_mode","phase6h_auto_failover_enabled",
            "edge_egress_v1_onboard_enabled")):
        raise RecoveryHold("RECOVERY_AUTOMATION_OR_K2_ACTIVE")
    blockers = (
        ("cloudzy_cz04a_actions", "status NOT IN ('DONE','REJECTED')"),
        ("cloudzy_cz04b_operations", "status NOT IN ('READY','DONE','ABORTED')"),
        ("cloudzy_cz07_jobs", "status NOT IN ('DONE','ABORTED')"),
        ("failover_operations", "status='RUNNING'"),
    )
    for table, where in blockers:
        if table in existing and conn.execute(
                f"SELECT 1 FROM {table} WHERE {where} LIMIT 1").fetchone():
            raise RecoveryHold("RECOVERY_OTHER_OPERATION_RUNNING")
    return {"ip": ip, "provider_id": provider}


def commit_existing_install(db_factory, opid, *, actor, chat, now):
    """Atomic, fenced receipt/CZ-06 promotion after independent live proofs.

    Caller must first check pinned SSH key, provider IP/status, SSH and WG;
    those remote proofs are repeated on the caller's explicit confirmation.
    This local transaction does NOT touch host_pool or WireGuard.
    """
    with db_factory() as db:
        db.execute("BEGIN IMMEDIATE")
        db.row_factory = sqlite3.Row
        row = db.execute(
            "SELECT * FROM cloudzy_edge_operations WHERE id=?", (opid,)
        ).fetchone()
        if row is None or (row["actor_id"], row["chat_id"]) != (actor, chat):
            raise RecoveryHold("RECOVERY_OWNER_MISMATCH")
        if row["status"] != "HOLD_PROVISION":
            raise RecoveryHold("RECOVERY_STATE_CHANGED")
        data = dict(row)
        inspect_inactive_install(db, data)
        quick_exists = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='cloudzy_cz06_runs'"
        ).fetchone()
        if quick_exists:
            quick = db.execute(
                "SELECT stage FROM cloudzy_cz06_runs WHERE operation_id=?", (opid,)
            ).fetchone()
            if quick and quick[0] != "HOLD":
                raise RecoveryHold("RECOVERY_QUICK_STAGE_CHANGED")
        else:
            quick = None
        if db.execute(
            "UPDATE cloudzy_edge_operations SET status='EDGE_READY',"
            "hold_reason=NULL,updated_at=? WHERE id=? AND status='HOLD_PROVISION'",
            (int(now), opid)
        ).rowcount != 1:
            raise RecoveryHold("RECOVERY_CONCURRENT_CHANGE")
        if quick:
            if db.execute(
                "UPDATE cloudzy_cz06_runs SET stage='EDGE_READY',"
                "detail_code='RECOVERED_INSTALLED_EDGE',updated_at=? "
                "WHERE operation_id=? AND stage='HOLD'",
                (int(now), opid)
            ).rowcount != 1:
                raise RecoveryHold("RECOVERY_QUICK_CAS_FAILED")
        db.execute("""CREATE TABLE IF NOT EXISTS cloudzy_edge_recovery_audit(
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            operation_id TEXT NOT NULL,
            actor_id INTEGER NOT NULL,
            chat_id INTEGER NOT NULL,
            kind TEXT NOT NULL,
            at INTEGER NOT NULL
        )""")
        db.execute(
            "INSERT INTO cloudzy_edge_recovery_audit "
            "(operation_id,actor_id,chat_id,kind,at) VALUES (?,?,?,?,?)",
            (opid, actor, chat, "VERIFIED_EXISTING_INSTALL", int(now)),
        )
    return "EDGE_READY"


def commit_standby_resume(db_factory, opid, *, actor, chat, now):
    """Reopen only CZ-06 HOLD for an already accepted Edge; no remote mutation."""
    with db_factory() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT status,actor_id,chat_id FROM cloudzy_edge_operations WHERE id=?",
            (opid,)
        ).fetchone()
        if not row or tuple(row) != ("EDGE_READY", actor, chat):
            raise RecoveryHold("RECOVERY_EDGE_NOT_READY_OR_OWNER_CHANGED")
        run = db.execute(
            "SELECT stage,actor_id,chat_id FROM cloudzy_cz06_runs "
            "WHERE operation_id=?", (opid,)
        ).fetchone()
        if not run or tuple(run) != ("HOLD", actor, chat):
            raise RecoveryHold("RECOVERY_STANDBY_STAGE_CHANGED")
        for table, where in (
            ("cloudzy_cz04a_actions", "status NOT IN ('DONE','REJECTED')"),
            ("cloudzy_cz04b_operations", "status NOT IN ('READY','DONE','ABORTED')"),
            ("cloudzy_cz07_jobs", "status NOT IN ('DONE','ABORTED')"),
            ("failover_operations", "status='RUNNING'"),
        ):
            exists = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (table,)
            ).fetchone()
            if exists and db.execute(f"SELECT 1 FROM {table} WHERE {where} LIMIT 1").fetchone():
                raise RecoveryHold("RECOVERY_OTHER_OPERATION_RUNNING")
        if db.execute(
            "UPDATE cloudzy_cz06_runs SET stage='STANDBY_VERIFYING',"
            "detail_code='RECOVERY_RECHECK',updated_at=? "
            "WHERE operation_id=? AND stage='HOLD'",
            (int(now), opid)
        ).rowcount != 1:
            raise RecoveryHold("RECOVERY_STANDBY_CAS_FAILED")
        db.execute("""CREATE TABLE IF NOT EXISTS cloudzy_edge_recovery_audit(
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            operation_id TEXT NOT NULL,
            actor_id INTEGER NOT NULL,
            chat_id INTEGER NOT NULL,
            kind TEXT NOT NULL,
            at INTEGER NOT NULL
        )""")
        db.execute(
            "INSERT INTO cloudzy_edge_recovery_audit "
            "(operation_id,actor_id,chat_id,kind,at) VALUES (?,?,?,?,?)",
            (opid, actor, chat, "STANDBY_RECHECK_REQUESTED", int(now)),
        )
    return "STANDBY_VERIFYING"
