"""NVL Stage 3C: admin-only, plan-only SSH Egress intent registry.

This module deliberately NEVER changes Linux routes, SSHD, WireGuard, DNS,
ssh_accounts.host, or a customer's live endpoint. A PLANNED operation is not
proof that an Egress switch has occurred.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sqlite3
import uuid
from datetime import datetime, timezone

_USERNAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z", re.ASCII)
_TARGET_ID = re.compile(r"[a-z][a-z0-9]{0,11}\Z", re.ASCII)
_NAMESPACE = re.compile(r"[a-z][a-z0-9_-]{0,62}\Z", re.ASCII)
_PLAN_ID = re.compile(r"[0-9a-f]{20}\Z", re.ASCII)


class EgressIntentError(ValueError):
    """Operator-visible validation error; does not imply a route change."""


def _ipv4(value: str, *, public: bool) -> str:
    try:
        addr = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise EgressIntentError("IPV4_REQUIRED") from exc
    if public and not addr.is_global:
        raise EgressIntentError("EDGE_PUBLIC_IP_REQUIRED")
    if not public and (not addr.is_private or addr.is_loopback):
        raise EgressIntentError("NAMESPACE_PRIVATE_IP_REQUIRED")
    return str(addr)


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Additive schema only. Never touches or modifies the existing host mapping."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ssh_egress_targets (
            target_id TEXT PRIMARY KEY,
            edge_public_ip TEXT NOT NULL,
            namespace TEXT NOT NULL,
            internal_ip TEXT NOT NULL,
            local_port INTEGER NOT NULL CHECK(local_port BETWEEN 1024 AND 65535),
            status TEXT NOT NULL DEFAULT 'DRAFT'
                CHECK(status IN ('DRAFT', 'RETIRED')),
            registered_at TEXT NOT NULL,
            UNIQUE(local_port)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ssh_egress_intents (
            operation_id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            target_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'PLANNED'
                CHECK(status IN ('PLANNED', 'CANCELLED')),
            actor_telegram_id INTEGER NOT NULL,
            requested_at TEXT NOT NULL,
            cancelled_at TEXT,
            FOREIGN KEY(target_id) REFERENCES ssh_egress_targets(target_id)
        )
    """)
    conn.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_ssh_egress_one_plan_per_user
        ON ssh_egress_intents(username) WHERE status='PLANNED'
    """)


def register_draft_target(
    conn: sqlite3.Connection,
    *,
    target_id: str,
    edge_public_ip: str,
    namespace: str,
    internal_ip: str,
    local_port: int,
) -> None:
    """Register metadata only. NEVER enables a network route/listener."""
    if not _TARGET_ID.fullmatch(target_id):
        raise EgressIntentError("INVALID_TARGET_ID")
    if not _NAMESPACE.fullmatch(namespace):
        raise EgressIntentError("INVALID_NAMESPACE")
    public_ip = _ipv4(edge_public_ip, public=True)
    private_ip = _ipv4(internal_ip, public=False)
    if isinstance(local_port, bool) or not isinstance(local_port, int) or not 1024 <= local_port <= 65535:
        raise EgressIntentError("INVALID_LOCAL_PORT")
    ensure_schema(conn)
    try:
        conn.execute(
            "INSERT INTO ssh_egress_targets "
            "(target_id,edge_public_ip,namespace,internal_ip,local_port,status,registered_at) "
            "VALUES (?,?,?,?,?,'DRAFT',?)",
            (target_id, public_ip, namespace, private_ip, local_port, _utc_now()),
        )
    except sqlite3.IntegrityError as exc:
        raise EgressIntentError("TARGET_ALREADY_EXISTS_OR_PORT_CONFLICT") from exc


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def list_targets(conn: sqlite3.Connection) -> list[dict]:
    ensure_schema(conn)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT target_id,edge_public_ip,namespace,internal_ip,local_port,status "
        "FROM ssh_egress_targets WHERE status='DRAFT' ORDER BY target_id"
    ).fetchall()
    return [dict(row) for row in rows]


def get_intent(conn: sqlite3.Connection, operation_id: str) -> dict | None:
    if not _PLAN_ID.fullmatch(operation_id):
        raise EgressIntentError("INVALID_OPERATION_ID")
    ensure_schema(conn)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT operation_id,username,target_id,status,actor_telegram_id,requested_at,cancelled_at "
        "FROM ssh_egress_intents WHERE operation_id=?", (operation_id,)
    ).fetchone()
    return dict(row) if row else None


def pending_intent_for_user(conn: sqlite3.Connection, username: str) -> dict | None:
    if not _USERNAME.fullmatch(username):
        raise EgressIntentError("INVALID_USERNAME")
    ensure_schema(conn)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT operation_id,username,target_id,status,actor_telegram_id,requested_at "
        "FROM ssh_egress_intents WHERE username=? AND status='PLANNED'", (username,)
    ).fetchone()
    return dict(row) if row else None


def _check_active_ssh_account(conn: sqlite3.Connection, username: str) -> None:
    row = conn.execute(
        "SELECT service_type,status FROM ssh_accounts WHERE username=?", (username,)
    ).fetchone()
    if not row or row[0] != "ssh" or row[1] != "🟢 فعال":
        raise EgressIntentError("ACTIVE_SSH_ACCOUNT_REQUIRED")


def _block_concurrent_failover(conn: sqlite3.Connection) -> None:
    existing = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='failover_operations'"
    ).fetchone()
    if existing and conn.execute(
        "SELECT 1 FROM failover_operations WHERE status='RUNNING' LIMIT 1"
    ).fetchone():
        raise EgressIntentError("FAILOVER_IN_PROGRESS")


def _admin_only(role: str, actor_telegram_id: int) -> None:
    if role != "admin" or isinstance(actor_telegram_id, bool) or not isinstance(actor_telegram_id, int) or actor_telegram_id <= 0:
        raise EgressIntentError("ADMIN_ONLY")


def plan_switch(
    conn: sqlite3.Connection, *, username: str, target_id: str,
    actor_telegram_id: int, role: str,
) -> dict:
    """Record review intent. No assignment or network mutation ever occurs."""
    _admin_only(role, actor_telegram_id)
    if not _USERNAME.fullmatch(username):
        raise EgressIntentError("INVALID_USERNAME")
    if not _TARGET_ID.fullmatch(target_id):
        raise EgressIntentError("INVALID_TARGET_ID")
    ensure_schema(conn)
    try:
        conn.execute("BEGIN IMMEDIATE")
        _block_concurrent_failover(conn)
        _check_active_ssh_account(conn, username)
        target = conn.execute(
            "SELECT 1 FROM ssh_egress_targets WHERE target_id=? AND status='DRAFT'",
            (target_id,),
        ).fetchone()
        if not target:
            raise EgressIntentError("TARGET_NOT_REGISTERED")
        pending = conn.execute(
            "SELECT 1 FROM ssh_egress_intents WHERE username=? AND status='PLANNED'",
            (username,),
        ).fetchone()
        if pending:
            raise EgressIntentError("PLAN_ALREADY_PENDING")
        operation_id = uuid.uuid4().hex[:20]
        now = _utc_now()
        conn.execute(
            "INSERT INTO ssh_egress_intents "
            "(operation_id,username,target_id,status,actor_telegram_id,requested_at) "
            "VALUES (?,?,?,'PLANNED',?,?)",
            (operation_id, username, target_id, actor_telegram_id, now),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return {
        "operation_id": operation_id,
        "username": username,
        "target_id": target_id,
        "status": "PLANNED",
        "route_changed": False,
    }


def cancel_plan(
    conn: sqlite3.Connection, *, operation_id: str, actor_telegram_id: int, role: str,
) -> bool:
    _admin_only(role, actor_telegram_id)
    if not _PLAN_ID.fullmatch(operation_id):
        raise EgressIntentError("INVALID_OPERATION_ID")
    ensure_schema(conn)
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT status FROM ssh_egress_intents WHERE operation_id=?",
            (operation_id,),
        ).fetchone()
        if row is None:
            raise EgressIntentError("PLAN_NOT_FOUND")
        if row[0] != "PLANNED":
            raise EgressIntentError("PLAN_NOT_PENDING")
        conn.execute(
            "UPDATE ssh_egress_intents SET status='CANCELLED',cancelled_at=? "
            "WHERE operation_id=? AND status='PLANNED'",
            (_utc_now(), operation_id),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="NVL SSH Egress: DRAFT target metadata only")
    parser.add_argument("--db", required=True)
    commands = parser.add_subparsers(dest="cmd", required=True)
    commands.add_parser("list")
    register = commands.add_parser("register-draft")
    register.add_argument("--target-id", required=True)
    register.add_argument("--edge-public-ip", required=True)
    register.add_argument("--namespace", required=True)
    register.add_argument("--internal-ip", required=True)
    register.add_argument("--local-port", required=True, type=int)
    register.add_argument("--confirm-no-route-change", action="store_true")
    args = parser.parse_args()
    if not os.path.isfile(args.db):
        parser.error("Existing NVL database is required: refusing to create a new DB")
    if args.cmd == "register-draft" and not args.confirm_no_route_change:
        parser.error("Use --confirm-no-route-change to register metadata only")
    with sqlite3.connect(args.db) as conn:
        if args.cmd == "register-draft":
            register_draft_target(
                conn, target_id=args.target_id, edge_public_ip=args.edge_public_ip,
                namespace=args.namespace, internal_ip=args.internal_ip, local_port=args.local_port,
            )
            print("TARGET_DRAFT_REGISTERED; NETWORK_UNCHANGED")
        else:
            print(json.dumps({"targets": list_targets(conn), "network_modified": False}, ensure_ascii=False))


if __name__ == "__main__":
    main()
