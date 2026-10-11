"""F1: fail-closed fence between legacy 6G/6H and protected UID mappings.

Use inside the SAME SQLite transaction as any legacy host or account write,
and recheck before DNS or remote provisioning (whose effects are not atomic
with SQLite). Existing installations without a mapping table are unaffected.
"""
from __future__ import annotations
import sqlite3

LEGACY_PROTECTED_BINDINGS_BLOCKED = "EGRESS_PROTECTED_BINDINGS_LEGACY_MUTATION_UNSAFE"


def has_protected_bindings(conn: sqlite3.Connection) -> bool:
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' "
        "AND name='edge_egress_uid_bindings'"
    ).fetchone()
    if not exists:
        return False
    # Never interpret an unknown/partially migrated table as absent: a
    # malformed schema raises and blocks the caller before network mutation.
    return conn.execute(
        "SELECT 1 FROM edge_egress_uid_bindings "
        "WHERE status='PROTECTED' LIMIT 1"
    ).fetchone() is not None


def assert_legacy_mutation_safe(conn: sqlite3.Connection) -> None:
    if has_protected_bindings(conn):
        raise RuntimeError(LEGACY_PROTECTED_BINDINGS_BLOCKED)


def any_protected_bindings(db_conn) -> bool:
    with db_conn() as conn:
        return has_protected_bindings(conn)
