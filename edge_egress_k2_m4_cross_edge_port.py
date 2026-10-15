"""K2 guarded cross-Edge UID port over the ORIGINAL P3/F2/6G engine.

One UID only; no shell, second lease, user mutation API, or global DNS/Edge
switch. Root factory must separately attest fresh physical F4 and PAM.
Never serves as an alternate privileged executor.
"""
from __future__ import annotations

from typing import Callable

from edge_egress_k2_m3_waves import (
    MigrationMember, build_wave_plan, m4_cross_edge_single_reviewed,
)
from edge_egress_k2_migration_inventory import (
    MigrationInventory, select_migration,
)
from edge_egress_p3_executor import (
    ExecutionScope, ExecutionTicket, assert_guarded_6g_intent,
    _scope_digest,
)
from edge_egress_p3_uid import GuardedProtectedUIDPort
from edge_egress_uid_runtime_store import K2CrossEdgeUIDRuntimeStore

M4_CROSS_EDGE_UID_PORT_ENABLED = False


class CrossEdgeUIDHold(ValueError):
    pass


class GuardedCrossEdgeUIDPort:
    """Recheck the *same* immutable M1 member before and after original P3."""

    def __init__(self, *, member: MigrationMember, scope: ExecutionScope,
                 ticket: ExecutionTicket, uid_port: GuardedProtectedUIDPort,
                 db_conn: Callable, live_inventory: Callable,
                 release_enabled: bool = False):
        store = getattr(uid_port, "store", None)
        if (type(uid_port) is not GuardedProtectedUIDPort
            or type(store) is not K2CrossEdgeUIDRuntimeStore
            or type(member) is not MigrationMember
            or type(scope) is not ExecutionScope
            or scope.action != "UID_ATTACH"
            or not isinstance(ticket, ExecutionTicket)
            or not callable(db_conn) or not callable(live_inventory)
            or uid_port.db_conn is not db_conn
            or uid_port.plan.scope != scope or uid_port.ticket != ticket
            or store.scope != scope or store.ticket != ticket
            or store.db_conn is not db_conn
            or store.ingress_edge_id != member.source_edge_id
            or member.username != scope.username or member.uid != scope.uid
            or not member.selectable or member.protected_edge_id
            or member.source_edge_id == member.target_edge_id
            or member.source_ipv4 == member.target_ipv4
            or member.source_ipv4 != scope.source_host
            or member.target_ipv4 != scope.target_host
            or member.target_edge_id != scope.edge_id
            or ticket.scope_digest != _scope_digest(scope)):
            raise CrossEdgeUIDHold("K2_EXACT_CROSS_EDGE_P3_UID_PORT_REQUIRED")
        self.member, self.scope, self.ticket = member, scope, ticket
        self.uid_port, self.db_conn = uid_port, db_conn
        self.live_inventory = live_inventory
        self.release_enabled = release_enabled is True
        self._started = False

    def _check(self, scope: ExecutionScope, *, committed: bool) -> None:
        if (not M4_CROSS_EDGE_UID_PORT_ENABLED
            or not self.release_enabled or scope != self.scope):
            raise CrossEdgeUIDHold("K2_CROSS_EDGE_P3_PORT_NOT_RELEASED")
        assert_guarded_6g_intent(self.db_conn, scope, self.ticket)
        member = self.member
        selection = select_migration(
            "SINGLE", (member.username,), member.target_edge_id
        )
        fresh = self.live_inventory(selection)
        if type(fresh) is not MigrationInventory:
            raise CrossEdgeUIDHold("K2_CROSS_EDGE_LIVE_INVENTORY_MISSING")
        plan = build_wave_plan(fresh, wave_size=1)
        chosen = plan.members[0] if len(plan.members) == 1 else None
        # A committed UID is expected to be PROTECTED, so M1 reports
        # TARGET_ALREADY_PROTECTED. Other changes remain fatal.
        if (not plan.selection.mode == "SINGLE"
            or any(x != "SHARED_6G_BUSY" for x in plan.global_blockers)
            or chosen is None or not fresh.target_f4_accepted
            or (chosen.blockers != ("TARGET_ALREADY_PROTECTED",)
                if committed else chosen.blockers != ())
            or chosen.username != member.username or chosen.uid != member.uid
            or chosen.source_edge_id != member.source_edge_id
            or chosen.source_ipv4 != member.source_ipv4
            or not chosen.source_proven or chosen.active_sessions != 0
            or chosen.historical_host != member.historical_host
            or chosen.target_edge_id != member.target_edge_id
            or chosen.target_ipv4 != member.target_ipv4
            or chosen.protected_edge_id != (
                member.target_edge_id if committed else ""
            )):
            raise CrossEdgeUIDHold("K2_CROSS_EDGE_SOURCE_OR_F4_DRIFT")
        assert_guarded_6g_intent(self.db_conn, scope, self.ticket)

    async def apply(self, scope: ExecutionScope) -> None:
        if self._started:
            raise CrossEdgeUIDHold("K2_CROSS_EDGE_ONE_SHOT")
        self._started = True
        self._check(scope, committed=False)
        await self.uid_port.apply(scope)

    async def verify(self, scope: ExecutionScope) -> bool:
        if not self._started:
            raise CrossEdgeUIDHold("K2_CROSS_EDGE_NOT_APPLIED")
        assert_guarded_6g_intent(self.db_conn, scope, self.ticket)
        if await self.uid_port.verify(scope) is not True:
            raise CrossEdgeUIDHold("K2_CROSS_EDGE_PACKET_PROOF_FAILED")
        self._check(scope, committed=True)
        return True

    async def freeze_or_hold(self, scope: ExecutionScope) -> None:
        if self._started and scope == self.scope:
            await self.uid_port.freeze_or_hold(scope)
