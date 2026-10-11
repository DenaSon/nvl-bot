"""D1-C2B2: adapter to NVL's EXISTING 6G SQLite lock/journal.

Scoped to offline stage-only preparation. No SSH transport, no live WG/DNS,
no customer routing/host ownership writes. The adapter receives the current
bot's _db_acquire_failover_lock, _db_update_failover_operation and db_conn;
it neither invents another lock nor creates an inventory table implicitly.
Schema migration must happen independently, before this adapter is enabled.

The HostPort factory deliberately defaults to DENY; production bot does not
construct or call this adapter in D1-C2B2.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Callable, Optional

from edge_egress_inventory import (
    EdgeReservation, ensure_schema, reserve_allocation, mark_stage_only,
)
from edge_egress_prepare import LocalHostPort, PreparationUnsafe
from edge_egress_f3_readiness import stage_in_existing_6g_transaction
from ops.edge_egress_provision import EgressSpec


class NoLiveHostTransport:
    """Safe default until SSH host identity and staging are lab-verified."""
    async def read_only_preflight(self, spec):
        raise PreparationUnsafe("LIVE_HOST_TRANSPORT_NOT_INSTALLED")

    async def ensure_local_keypair(self, edge_id):
        raise PreparationUnsafe("LIVE_HOST_TRANSPORT_NOT_INSTALLED")

    async def stage_config_only(self, spec, *, peer_public_key):
        raise PreparationUnsafe("LIVE_HOST_TRANSPORT_NOT_INSTALLED")

    async def discard_staged_config_only(self, edge_id):
        raise PreparationUnsafe("LIVE_HOST_TRANSPORT_NOT_INSTALLED")


@dataclass
class Existing6GPreparationAdapter:
    """Stage-only bridge, consuming the LIVE bot's existing lock/journal APIs.

    The adapter stores operation ID only in this per-operation instance, never
    in module globals. Create a NEW instance per staged Edge operation.
    """
    db_conn: Callable
    acquire_fn: Callable
    update_fn: Callable
    host_factory: Optional[Callable[[str, str], LocalHostPort]] = None
    operation_id: Optional[int] = None
    source_host: Optional[str] = None
    target_host: Optional[str] = None
    original_account_snapshot: Optional[tuple] = None

    async def acquire_existing_6g_lock(self, source, target):
        if self.operation_id is not None:
            raise PreparationUnsafe("BRIDGE_INSTANCE_NOT_REUSABLE")
        operation_id, busy = await asyncio.to_thread(self.acquire_fn, source, target)
        if operation_id is not None:
            self.operation_id = operation_id
            self.source_host, self.target_host = source, target
        return operation_id, busy

    def _assert_lock_in_db(self, conn):
        if self.operation_id is None:
            raise PreparationUnsafe("SHARED_6G_LOCK_REQUIRED")
        row = conn.execute(
            "SELECT status, source_host, target_host FROM failover_operations "
            "WHERE id=?", (self.operation_id,),
        ).fetchone()
        if row != ("RUNNING", self.source_host, self.target_host):
            raise PreparationUnsafe("SHARED_6G_LOCK_LOST")

    async def journal_existing_6g(self, operation_id, status, phase, details):
        if operation_id != self.operation_id or status not in (
            "RUNNING", "FAILED", "SUCCEEDED"
        ):
            raise PreparationUnsafe("SHARED_6G_JOURNAL_REJECTED")
        if not isinstance(phase, str) or not phase.isupper():
            raise PreparationUnsafe("INVALID_JOURNAL_PHASE")
        safe_details = {}
        for key, value in details.items():
            if key in {"private_key", "password", "token", "secret"}:
                raise PreparationUnsafe("SECRET_IN_JOURNAL")
            if type(value) not in (str, int, bool, type(None)):
                raise PreparationUnsafe("UNSAFE_JOURNAL_VALUE")
            safe_details[key] = value
        detail = {
            "phase": phase,
            "kind": "EGRESS_STAGE_ONLY",
            **safe_details,
        }
        await asyncio.to_thread(
            self.update_fn, operation_id, status=status, detail=detail,
            finished=(status != "RUNNING"), require_running=True,
        )

    def _assert_source_and_target_in_db(self, conn, source, target):
        self._assert_lock_in_db(conn)
        if source != self.source_host or target != self.target_host:
            raise PreparationUnsafe("OPERATION_HOST_IDENTITY_CHANGED")
        source_row = conn.execute(
            "SELECT active, is_default, service_port FROM host_pool WHERE host=?",
            (source,),
        ).fetchone()
        target_row = conn.execute(
            "SELECT active, is_default, is_standby, service_port "
            "FROM host_pool WHERE host=?", (target,),
        ).fetchone()
        if not source_row or not target_row:
            raise PreparationUnsafe("EDGE_MISSING_FROM_HOST_POOL")
        if tuple(int(bool(x)) for x in source_row[:2]) != (1, 1):
            raise PreparationUnsafe("SOURCE_NOT_ACTIVE_DEFAULT")
        if tuple(int(bool(x)) for x in target_row[:3]) != (1, 0, 1):
            raise PreparationUnsafe("TARGET_NOT_ACTIVE_STANDBY")
        source_port, target_port = source_row[2], target_row[3]
        if not (isinstance(source_port, int) and source_port > 0
                and source_port == target_port and source_port <= 65535):
            raise PreparationUnsafe("SERVICE_PORT_MISMATCH")
        setting = conn.execute(
            "SELECT value FROM settings WHERE key='dns_current_ip'"
        ).fetchone()
        if not setting or setting[0] != source:
            raise PreparationUnsafe("DNS_NOT_AT_SOURCE_EDGE")
        other = conn.execute(
            "SELECT COUNT(*) FROM ssh_accounts WHERE service_type='ssh' "
            "AND status LIKE '%فعال%' AND status NOT LIKE '%غیر%' "
            "AND host IS NOT NULL AND host != '' AND host != ?",
            (source,),
        ).fetchone()
        if other and other[0]:
            raise PreparationUnsafe("GLOBAL_DOMAIN_MULTI_EDGE_CONFLICT")
        account_count = conn.execute(
            "SELECT COUNT(*) FROM ssh_accounts "
            "WHERE (host=? OR host IS NULL OR host='') AND service_type='ssh' "
            "AND status LIKE '%فعال%' AND status NOT LIKE '%غیر%'",
            (source,),
        ).fetchone()[0]
        if not account_count:
            raise PreparationUnsafe("EMPTY_SOURCE_ACCOUNT_SET")
        # Capture every active source username+assigned-host+status; staging
        # can take minutes, so concurrent account creation or removal must
        # invalidate the stale reservation before it is marked STAGED.
        rows = tuple(conn.execute(
            "SELECT username,host,status FROM ssh_accounts "
            "WHERE (host=? OR host IS NULL OR host='') AND service_type='ssh' "
            "AND status LIKE '%فعال%' AND status NOT LIKE '%غیر%' "
            "ORDER BY username", (source,),
        ).fetchall())
        if len(rows) != account_count:
            raise PreparationUnsafe("ACCOUNT_SET_CHANGED")
        if self.original_account_snapshot is None:
            self.original_account_snapshot = rows
        elif rows != self.original_account_snapshot:
            raise PreparationUnsafe("SOURCE_ACCOUNT_SNAPSHOT_CHANGED")

    def _sync_revalidate(self, source, target):
        with self.db_conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._assert_source_and_target_in_db(conn, source, target)

    async def assert_current_ownership_unchanged(self, source, target):
        await asyncio.to_thread(self._sync_revalidate, source, target)

    def _sync_reserve(self, spec, core_key, edge_key):
        with self.db_conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._assert_source_and_target_in_db(
                conn, self.source_host, spec.edge_public_ipv4
            )
            # No automatic schema creation during live operation.
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='edge_egress_allocations'"
            ).fetchone()
            if not exists:
                raise PreparationUnsafe("EDGE_ALLOCATION_SCHEMA_NOT_INSTALLED")
            return reserve_allocation(
                conn, spec, core_public_key=core_key,
                edge_public_key=edge_key,
            )

    async def reserve_under_6g_lock(self, spec, *, core_public_key, edge_public_key):
        return await asyncio.to_thread(
            self._sync_reserve, spec, core_public_key, edge_public_key,
        )

    def _sync_mark_staged(self, edge_id):
        with self.db_conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._assert_source_and_target_in_db(
                conn, self.source_host, self.target_host,
            )
            mark_stage_only(conn, edge_id)
            # Same BEGIN IMMEDIATE and 6G lease as the allocation write.
            stage_in_existing_6g_transaction(
                conn, self.operation_id, source=self.source_host,
                edge_id=edge_id, target=self.target_host,
            )

    async def stage_reservation_under_6g_lock(self, edge_id):
        await asyncio.to_thread(self._sync_mark_staged, edge_id)

    async def core(self, core_public_ip):
        # This host identity MUST be independently verified by the real host
        # transport. Reject unexpected Core host addresses before delegation.
        if not core_public_ip or core_public_ip in (self.source_host, self.target_host):
            raise PreparationUnsafe("INVALID_CORE_IDENTITY")
        if self.host_factory is None:
            return NoLiveHostTransport()
        return self.host_factory("core", core_public_ip)

    async def edge(self, edge_public_ip):
        if edge_public_ip != self.target_host:
            raise PreparationUnsafe("UNEXPECTED_EDGE_HOST")
        if self.host_factory is None:
            return NoLiveHostTransport()
        return self.host_factory("edge", edge_public_ip)
