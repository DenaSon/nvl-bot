"""J positive cutover adapter: existing 6G lease + SQLite CAS + host evidence.

This is the actual application-side coordinator adapter, not another engine.
It uses run_protected_handoff(..., guarded_failover=True) and ONLY the one
existing Phase 6G lock/journal. The host driver is required and defaults to
DENY. A production driver must pass operator-attested K acceptance before
this module is wired to the bot. No compatibility with legacy DNS->Core.

The adapter never guesses an SSH session is idle; no live driver means HOLD.
F2 PAM denies new logins when the persisted runtime row becomes FROZEN.
After this fence, old sessions must be proven absent BEFORE kernel repin.
Every host action is fail-closed and results are revalidated before DB/DNS.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import pwd
import sqlite3
from typing import Callable, Protocol

from edge_egress_handoff import (
    AccountOwner, HandoffSnapshot, HandoffUnsafe, TargetObservation,
    run_protected_handoff,
)
from edge_egress_f3_readiness import admission_eligible, read_readiness


class PositiveHandoffHold(HandoffUnsafe):
    pass


class HostActions(Protocol):
    """Mandatory audited K driver, not a second lifecycle controller.

    Implementations must use the existing F/G UID Kernel and F2 root-owned
    manifest/roster files. Each operation raises on uncertain host state.
    """
    async def ensure_target_transport(self, target: str) -> None: ...
    async def assert_target_peer(self, target: str) -> None: ...
    async def external_target_observation(self, target: str) -> TargetObservation: ...
    async def assert_real_ingress(self, target: str) -> None: ...
    async def assert_no_ssh_sessions(self, username: str, uid: int) -> None: ...
    async def freeze_uid(self, username: str, uid: int) -> None: ...
    async def assert_uid_frozen(self, username: str, uid: int) -> None: ...
    async def repin_frozen_uid(self, username: str, uid: int,
                               old_edge: str, new_edge: str) -> None: ...
    async def prove_uid_ipv4(self, username: str, uid: int,
                             target_ip: str) -> None: ...
    async def switch_dns_edge_to_edge(self, source: str, target: str) -> None: ...
    async def assert_dns_target(self, target: str) -> None: ...
    async def release_uid(self, username: str, uid: int) -> None: ...
    async def assert_uid_target(self, username: str, uid: int,
                                target_ip: str) -> None: ...


class NoLiveHostActions:
    """There is no implicit SSH, Cloudflare or WireGuard host transport."""
    def __getattr__(self, name):
        raise PositiveHandoffHold("K_LIVE_HOST_ACTIONS_NOT_INSTALLED")


@dataclass
class Existing6GProtectedHandoffAdapter:
    db_conn: Callable
    acquire_fn: Callable
    journal_fn: Callable
    core_ip: str
    host_actions: HostActions | None = None
    operation_id: int | None = None
    snapshot: HandoffSnapshot | None = None
    customer_fenced: bool = False
    identity_rebound: bool = False
    dns_switched: bool = False

    def _driver(self) -> HostActions:
        if self.host_actions is None:
            raise PositiveHandoffHold("K_LIVE_HOST_ACTIONS_NOT_INSTALLED")
        return self.host_actions

    def _locked(self, conn, *, source=None, target=None):
        if self.operation_id is None:
            raise PositiveHandoffHold("SHARED_6G_LOCK_REQUIRED")
        record = conn.execute(
            "SELECT status,source_host,target_host FROM failover_operations "
            "WHERE id=?", (self.operation_id,),
        ).fetchone()
        if not record or record[0] != "RUNNING":
            raise PositiveHandoffHold("SHARED_6G_LOCK_LOST")
        if source is not None and record[1] != source:
            raise PositiveHandoffHold("SHARED_SOURCE_CHANGED")
        if target is not None and record[2] != target:
            raise PositiveHandoffHold("SHARED_TARGET_CHANGED")
        if conn.execute(
            "SELECT 1 FROM failover_operations WHERE status='RUNNING' "
            "AND id!=? LIMIT 1", (self.operation_id,),
        ).fetchone():
            raise PositiveHandoffHold("SECOND_RUNNING_OPERATION")

    async def acquire_6g_lock(self, source, target):
        if self.operation_id is not None:
            raise PositiveHandoffHold("ADAPTER_REUSE_FORBIDDEN")
        operation_id, busy = await asyncio.to_thread(
            self.acquire_fn, source, target
        )
        if operation_id is not None:
            self.operation_id = operation_id
        return operation_id, busy

    async def update_6g_journal(self, operation_id, *, status, phase, details):
        if self.operation_id != operation_id:
            raise PositiveHandoffHold("JOURNAL_OPERATION_MISMATCH")
        if status not in {"RUNNING", "FAILED", "SUCCEEDED"}:
            raise PositiveHandoffHold("INVALID_JOURNAL_STATUS")
        # Never allow a driver to put a token, credential or raw error in DB.
        if not isinstance(details, dict) or any(
            type(v) not in (str, int, bool, type(None))
            or any(secret in k.lower() for secret in ("password", "token", "secret", "private"))
            for k, v in details.items()
        ):
            raise PositiveHandoffHold("UNSAFE_JOURNAL_DETAILS")
        safe = {"phase": phase, "kind": "PROTECTED_EGRESS_J", **details}
        await asyncio.to_thread(
            self.journal_fn, operation_id, status=status, detail=safe,
            finished=(status != "RUNNING"), require_running=True,
        )

    def _snapshot(self, source, target) -> HandoffSnapshot:
        with self.db_conn() as conn:
            self._locked(conn, source=source, target=target)
            if conn.execute(
                "SELECT value FROM settings WHERE key='edge_egress_protected_mode'"
            ).fetchone() != ("1",):
                raise PositiveHandoffHold("PROTECTED_MODE_REQUIRED")
            if conn.execute(
                "SELECT value FROM settings WHERE key='dns_current_ip'"
            ).fetchone() != (source,):
                raise PositiveHandoffHold("PUBLIC_DNS_SOURCE_CHANGED")
            s = conn.execute(
                "SELECT active,is_default,service_port FROM host_pool WHERE host=?",
                (source,),
            ).fetchone()
            t = conn.execute(
                "SELECT active,is_default,is_standby,service_port FROM host_pool "
                "WHERE host=?", (target,),
            ).fetchone()
            if not s or not t:
                raise PositiveHandoffHold("HOST_POOL_INCOMPLETE")
            source_port = int(s[2] or 0)
            target_port = int(t[3] or 0)
            accounts = conn.execute(
                "SELECT username,host FROM ssh_accounts "
                "WHERE service_type='ssh' AND status LIKE '%فعال%' "
                "AND status NOT LIKE '%غیر%' ORDER BY username"
            ).fetchall()
            if not accounts:
                raise PositiveHandoffHold("NO_ACTIVE_SSH_ACCOUNTS")
            if any(host not in (source, "", None) for _, host in accounts):
                raise PositiveHandoffHold("OTHER_EDGE_ACCOUNT_HOST_CONFLICT")
            runtime = conn.execute(
                "SELECT username,uid,edge_id,edge_ipv4,state "
                "FROM edge_egress_uid_runtime ORDER BY username"
            ).fetchall()
            binding = conn.execute(
                "SELECT username,uid,edge_id,edge_ipv4,status "
                "FROM edge_egress_uid_bindings ORDER BY username"
            ).fetchall()
            if len(runtime) != len(accounts) or len(binding) != len(accounts):
                raise PositiveHandoffHold("NOT_ALL_ACTIVE_SSH_UIDS_PROTECTED")
            for (username, _host), rr, bb in zip(accounts, runtime, binding):
                if (rr[0] != username or bb[0] != username
                        or rr[1:4] != bb[1:4] or rr[3] != source
                        or rr[4] != "PROTECTED" or bb[4] != "PROTECTED"
                        or pwd.getpwnam(username).pw_uid != rr[1]):
                    raise PositiveHandoffHold("UID_MAPPING_SOURCE_UNCERTAIN")
            identity = conn.execute(
                "SELECT edge_id,status,core_public_ipv4 FROM "
                "edge_egress_allocations WHERE edge_public_ipv4=?",
                (target,),
            ).fetchall()
            if len(identity) != 1 or identity[0][1:] != ("STAGED", self.core_ip):
                raise PositiveHandoffHold("TARGET_ALLOCATION_NOT_STAGED")
            ready = read_readiness(conn, identity[0][0])
            if not ready or ready.edge_ipv4 != target or not admission_eligible(ready):
                raise PositiveHandoffHold("TARGET_NOT_F4_READY")
            return HandoffSnapshot(
                source_host=source, target_host=target,
                core_public_ipv4=self.core_ip,
                current_dns_ipv4=source,
                active_accounts=tuple(AccountOwner(u, rr[1])
                                      for (u, _), rr in zip(accounts, runtime)),
                other_explicit_active_accounts=0,
                source_is_default=(s[0], s[1]) == (1, 1),
                target_is_active_standby=tuple(t[:3]) == (1, 0, 1),
                source_service_port=source_port,
                target_service_port=target_port,
                target_egress_identity_unique=True,
            )

    async def snapshot_under_lock(self, source, target):
        record = await asyncio.to_thread(self._snapshot, source, target)
        self.snapshot = record
        return record

    async def stage_target_shadow(self, record):
        await self._driver().ensure_target_transport(record.target_host)

    async def rekey_dedicated_peer(self, record):
        # No implicit rekey of the source/legacy wg0. Assert the dedicated
        # staged transport has the expected key rather than replacing it.
        await self._driver().assert_target_peer(record.target_host)

    async def observe_target(self, record):
        return await self._driver().external_target_observation(record.target_host)

    async def revalidate_before_cutover(self, record):
        if await asyncio.to_thread(
            self._snapshot, record.source_host, record.target_host
        ) != record:
            raise PositiveHandoffHold("SOURCE_SNAPSHOT_CHANGED")
        await self._driver().assert_real_ingress(record.target_host)

    async def block_new_logins(self, record):
        # Persist intent before any process/drain/kernel check: existing F2
        # PAM now rejects all affected UIDs even if a new SSH login races.
        def freeze_db():
            with self.db_conn() as conn:
                conn.execute("BEGIN IMMEDIATE")
                self._locked(conn, source=record.source_host,
                             target=record.target_host)
                for owner in record.active_accounts:
                    changed = conn.execute(
                        "UPDATE edge_egress_uid_runtime SET state='FROZEN',"
                        "generation=generation+1,last_operation_id=? "
                        "WHERE username=? AND uid=? AND edge_ipv4=? "
                        "AND state='PROTECTED'",
                        (self.operation_id, owner.username, owner.uid,
                         record.source_host),
                    ).rowcount
                    if changed != 1:
                        raise PositiveHandoffHold("ADMISSION_FENCE_CAS_LOST")
        await asyncio.to_thread(freeze_db)
        self.customer_fenced = True

    async def drain_source_sessions(self, record):
        if not self.customer_fenced:
            raise PositiveHandoffHold("ADMISSION_FENCE_NOT_DURABLE")
        for owner in record.active_accounts:
            await self._driver().assert_no_ssh_sessions(
                owner.username, owner.uid
            )

    async def arm_fail_closed(self, record):
        if not self.customer_fenced:
            raise PositiveHandoffHold("UID_ADMISSION_NOT_BLOCKED")
        for owner in record.active_accounts:
            await self._driver().freeze_uid(owner.username, owner.uid)
        for owner in record.active_accounts:
            await self._driver().assert_uid_frozen(owner.username, owner.uid)

    async def select_target_egress(self, record):
        for owner in record.active_accounts:
            await self._driver().assert_no_ssh_sessions(owner.username, owner.uid)
            await self._driver().assert_uid_frozen(owner.username, owner.uid)
            await self._driver().repin_frozen_uid(
                owner.username, owner.uid, record.source_host, record.target_host,
            )

    async def prove_selected_egress(self, record):
        # Driver's probe must keep SSH admission blocked and re-arm the UID
        # reject on either probe success or failure. No user session is open.
        for owner in record.active_accounts:
            await self._driver().prove_uid_ipv4(
                owner.username, owner.uid, record.target_host
            )
            await self._driver().assert_uid_frozen(owner.username, owner.uid)

    async def commit_source_accounts_cas(self, record):
        # Runtime and permanent mapping change together. Keep runtime
        # FROZEN; PAM admission remains DENY until verified Edge DNS cutover.
        def commit():
            with self.db_conn() as conn:
                conn.execute("BEGIN IMMEDIATE")
                self._locked(conn, source=record.source_host,
                             target=record.target_host)
                target = conn.execute(
                    "SELECT edge_id,route_table FROM edge_egress_allocations "
                    "WHERE edge_public_ipv4=? AND status='STAGED'",
                    (record.target_host,),
                ).fetchone()
                if target is None:
                    raise PositiveHandoffHold("TARGET_ALLOCATION_LOST")
                ready = read_readiness(conn, target[0])
                if not admission_eligible(ready):
                    raise PositiveHandoffHold("TARGET_READINESS_EXPIRED")
                for owner in record.active_accounts:
                    rr = conn.execute(
                        "SELECT edge_ipv4,state FROM edge_egress_uid_runtime "
                        "WHERE username=? AND uid=?",
                        (owner.username, owner.uid),
                    ).fetchone()
                    if rr != (record.source_host, "FROZEN"):
                        raise PositiveHandoffHold("RUNTIME_FROZEN_CAS_LOST")
                    changed = conn.execute(
                        "UPDATE edge_egress_uid_runtime SET edge_id=?,"
                        "edge_ipv4=?,route_table=?,generation=generation+1,"
                        "last_operation_id=? WHERE username=? AND uid=? "
                        "AND edge_ipv4=? AND state='FROZEN'",
                        (target[0], record.target_host, target[1],
                         self.operation_id, owner.username, owner.uid,
                         record.source_host),
                    ).rowcount
                    mapped = conn.execute(
                        "UPDATE edge_egress_uid_bindings SET edge_id=?,"
                        "edge_ipv4=?,generation=generation+1 "
                        "WHERE username=? AND uid=? AND edge_ipv4=? "
                        "AND status='PROTECTED'",
                        (target[0], record.target_host, owner.username,
                         owner.uid, record.source_host),
                    ).rowcount
                    if changed != 1 or mapped != 1:
                        raise PositiveHandoffHold("MAPPING_CAS_LOST")
                    host = conn.execute(
                        "UPDATE ssh_accounts SET host=? WHERE username=? "
                        "AND (host=? OR host IS NULL OR host='')",
                        (record.target_host, owner.username,
                         record.source_host),
                    ).rowcount
                    if host != 1:
                        raise PositiveHandoffHold("SSH_ACCOUNT_HOST_CAS_LOST")
        await asyncio.to_thread(commit)
        self.identity_rebound = True

    async def switch_dns_direct_to_target(self, record):
        if not self.identity_rebound:
            raise PositiveHandoffHold("MAPPING_NOT_REBOUND")
        if record.target_host == record.core_public_ipv4:
            raise PositiveHandoffHold("CORE_DNS_TARGET_FORBIDDEN")
        await self._driver().switch_dns_edge_to_edge(
            record.source_host, record.target_host
        )
        await self._driver().assert_dns_target(record.target_host)
        self.dns_switched = True
        def commit_default():
            with self.db_conn() as conn:
                conn.execute("BEGIN IMMEDIATE")
                self._locked(conn, source=record.source_host,
                             target=record.target_host)
                if conn.execute(
                    "SELECT value FROM settings WHERE key='dns_current_ip'"
                ).fetchone() != (record.source_host,):
                    raise PositiveHandoffHold("DNS_CAS_LOST")
                if conn.execute(
                    "UPDATE host_pool SET is_default=0 WHERE host=? "
                    "AND active=1 AND is_default=1",
                    (record.source_host,),
                ).rowcount != 1:
                    raise PositiveHandoffHold("SOURCE_DEFAULT_CAS_LOST")
                if conn.execute(
                    "UPDATE host_pool SET is_default=1,is_standby=0 "
                    "WHERE host=? AND active=1 AND is_default=0 AND is_standby=1",
                    (record.target_host,),
                ).rowcount != 1:
                    raise PositiveHandoffHold("TARGET_DEFAULT_CAS_LOST")
                if conn.execute(
                    "UPDATE settings SET value=? WHERE key='dns_current_ip' "
                    "AND value=?",
                    (record.target_host, record.source_host),
                ).rowcount != 1:
                    raise PositiveHandoffHold("DNS_SETTING_CAS_LOST")
        await asyncio.to_thread(commit_default)

    async def verify_final(self, record):
        if not self.dns_switched:
            raise PositiveHandoffHold("DNS_NOT_AT_TARGET")
        await self._driver().assert_dns_target(record.target_host)
        await self._driver().assert_real_ingress(record.target_host)
        for owner in record.active_accounts:
            await self._driver().assert_uid_target(
                owner.username, owner.uid, record.target_host
            )
        # Re-enable only with H root-owned manifest+roster already pinning
        # each protected login to the new ingress Edge.
        for owner in record.active_accounts:
            await self._driver().release_uid(owner.username, owner.uid)
        def activate():
            with self.db_conn() as conn:
                conn.execute("BEGIN IMMEDIATE")
                self._locked(conn, source=record.source_host,
                             target=record.target_host)
                for owner in record.active_accounts:
                    if conn.execute(
                        "UPDATE edge_egress_uid_runtime SET state='PROTECTED',"
                        "generation=generation+1,last_operation_id=? "
                        "WHERE username=? AND uid=? AND edge_ipv4=? "
                        "AND state='FROZEN'",
                        (self.operation_id, owner.username, owner.uid,
                         record.target_host),
                    ).rowcount != 1:
                        raise PositiveHandoffHold("FINAL_UID_CAS_LOST")
        await asyncio.to_thread(activate)

    async def freeze_customer_egress(self, record):
        # If the operation fails after its first host/DB mutation, never
        # roll back to old Core/main routing or release the shared 6G lease.
        for owner in record.active_accounts:
            await self._driver().freeze_uid(owner.username, owner.uid)
        def hold():
            with self.db_conn() as conn:
                conn.execute("BEGIN IMMEDIATE")
                self._locked(conn, source=record.source_host,
                             target=record.target_host)
                for owner in record.active_accounts:
                    conn.execute(
                        "UPDATE edge_egress_uid_runtime SET state='HOLD',"
                        "generation=generation+1,last_operation_id=? "
                        "WHERE username=? AND uid=? AND state IN "
                        "('FROZEN','PROTECTED','ROUTED_UNVERIFIED')",
                        (self.operation_id, owner.username, owner.uid),
                    )
        await asyncio.to_thread(hold)


async def execute_protected_switch(adapter: Existing6GProtectedHandoffAdapter,
                                   source_host: str, target_host: str):
    """Only callable behind K operator release; never from legacy 6H path."""
    if adapter.host_actions is None:
        raise PositiveHandoffHold("K_LIVE_HOST_ACTIONS_NOT_INSTALLED")
    return await run_protected_handoff(
        adapter, source_host, target_host, guarded_failover=True
    )
