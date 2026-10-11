"""D1-D1: transactional protected UID->Edge mapping CAS under EXISTING 6G.

No automatic migration/registration. Database schema is ONLY created when a
separate operator migration calls install_protected_mapping_schema(conn).
No bot handler imports or invokes this port in PR #80.

This CAS changes only edge_egress_uid_bindings, NEVER ssh_accounts.host,
host_pool, public DNS, Unix accounts, wg0, or host routing. A committed DB
mapping alone does not prove packets are leaving via that Edge; callers must
run the guarded 6G/6H saga with independently verified route evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable
import sqlite3

from edge_egress_handoff import HandoffSnapshot


class MappingUnsafe(ValueError):
    pass


MAPPING_SCHEMA = """
CREATE TABLE IF NOT EXISTS edge_egress_uid_bindings (
  username TEXT PRIMARY KEY,
  uid INTEGER NOT NULL UNIQUE CHECK(uid BETWEEN 1000 AND 59999),
  edge_id TEXT NOT NULL,
  edge_ipv4 TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status='PROTECTED'),
  generation INTEGER NOT NULL DEFAULT 1 CHECK(generation >= 1),
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_egress_uid_edge ON
  edge_egress_uid_bindings(edge_ipv4);
"""


def install_protected_mapping_schema(conn: sqlite3.Connection):
    """Explicit migration only; never called implicitly by a live operation."""
    conn.executescript(MAPPING_SCHEMA)


@dataclass
class Existing6GProtectedMappingPort:
    db_conn: Callable
    os_uid_for_username: Callable[[str], int]

    def _assert_lock(self, conn, operation_id, record: HandoffSnapshot):
        if type(operation_id) is not int or operation_id < 1:
            raise MappingUnsafe("INVALID_SHARED_OPERATION_ID")
        lock = conn.execute(
            "SELECT status,source_host,target_host FROM failover_operations "
            "WHERE id=?", (operation_id,)
        ).fetchone()
        if lock != ("RUNNING", record.source_host, record.target_host):
            raise MappingUnsafe("SHARED_6G_LOCK_NOT_CURRENT")
        mode = conn.execute(
            "SELECT value FROM settings WHERE key='edge_egress_protected_mode'"
        ).fetchone()
        if mode != ("1",):
            raise MappingUnsafe("PROTECTED_MODE_NOT_CONFIRMED_UNDER_LOCK")

    def _assert_snapshot(self, conn, record: HandoffSnapshot):
        record.validate()
        current = conn.execute(
            "SELECT value FROM settings WHERE key='dns_current_ip'"
        ).fetchone()
        if current != (record.current_dns_ipv4,):
            raise MappingUnsafe("PUBLIC_DNS_CHANGED")
        source = conn.execute(
            "SELECT active,is_default,service_port FROM host_pool WHERE host=?",
            (record.source_host,)
        ).fetchone()
        target = conn.execute(
            "SELECT active,is_default,is_standby,service_port "
            "FROM host_pool WHERE host=?", (record.target_host,)
        ).fetchone()
        if (not source or tuple(source) !=
                (1, 1, record.source_service_port)):
            raise MappingUnsafe("SOURCE_HOST_OWNERSHIP_CHANGED")
        if (not target or tuple(target) !=
                (1, 0, 1, record.target_service_port)):
            raise MappingUnsafe("TARGET_HOST_OWNERSHIP_CHANGED")
        db_accounts = tuple(conn.execute(
            "SELECT username,host FROM ssh_accounts "
            "WHERE service_type='ssh' AND status LIKE '%فعال%' "
            "AND status NOT LIKE '%غیر%' ORDER BY username"
        ).fetchall())
        requested = tuple(sorted((p.username for p in record.active_accounts)))
        if tuple(x[0] for x in db_accounts) != requested:
            raise MappingUnsafe("ACTIVE_SSH_ACCOUNT_SNAPSHOT_CHANGED")
        for username, host in db_accounts:
            if host not in (record.source_host, None, ""):
                raise MappingUnsafe("SSH_INGRESS_ACCOUNT_HOST_CHANGED")
        for account in record.active_accounts:
            if self.os_uid_for_username(account.username) != account.uid:
                raise MappingUnsafe("CORE_OS_UID_BINDING_CHANGED")

    def commit_mapping_cas_only(self, operation_id: int,
                                record: HandoffSnapshot) -> int:
        """Atomically switch all bindings from source Edge to target Edge.

        The dedicated target allocation must exist, be STAGED with a unique
        Edge IP and same Core public endpoint. A caller MUST first prove
        target Edge routing and DNS/IPv6 with the existing shared 6G lock.
        """
        with self.db_conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._assert_lock(conn, operation_id, record)
            self._assert_snapshot(conn, record)
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='edge_egress_uid_bindings'"
            ).fetchone()
            if not exists:
                raise MappingUnsafe("PROTECTED_MAPPING_MIGRATION_MISSING")
            edge = conn.execute(
                "SELECT edge_id,status,core_public_ipv4 FROM "
                "edge_egress_allocations WHERE edge_public_ipv4=?",
                (record.target_host,)
            ).fetchone()
            if not edge or edge[1:] != ("STAGED", record.core_public_ipv4):
                raise MappingUnsafe("TARGET_ALLOCATION_NOT_REVIEWED_STAGED")
            bindings = conn.execute(
                "SELECT username,uid,edge_ipv4,status,generation "
                "FROM edge_egress_uid_bindings ORDER BY username"
            ).fetchall()
            expected = sorted((p.username, p.uid) for p in record.active_accounts)
            if (len(bindings) != len(expected) or
                    [(b[0], b[1]) for b in bindings] != expected):
                raise MappingUnsafe("INCOMPLETE_OR_FOREIGN_UID_MAPPING")
            for username, uid, old_edge, status, gen in bindings:
                if (old_edge != record.source_host or status != "PROTECTED"
                        or type(gen) is not int or gen < 1):
                    raise MappingUnsafe("BINDING_SOURCE_OR_GENERATION_CHANGED")
            for username, uid, old_edge, status, generation in bindings:
                changed = conn.execute(
                    "UPDATE edge_egress_uid_bindings "
                    "SET edge_id=?,edge_ipv4=?,generation=generation+1,"
                    "updated_at=CURRENT_TIMESTAMP "
                    "WHERE username=? AND uid=? AND edge_ipv4=? "
                    "AND status='PROTECTED' AND generation=?",
                    (edge[0], record.target_host, username, uid, old_edge,
                     generation)
                ).rowcount
                if changed != 1:
                    raise MappingUnsafe("UID_MAPPING_COMPARE_AND_SWAP_LOST")
            self._assert_lock(conn, operation_id, record)
            self._assert_snapshot(conn, record)
            return len(bindings)
