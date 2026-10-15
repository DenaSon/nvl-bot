"""M3 same-ingress Legacy→Protected P3 UID adapter without host rewrite.

A single SSH account may have historical `ssh_accounts.host` metadata from
a long-retired Edge while its *current, authenticated* ingress enters e9.
The earlier group Legacy enrollment helper cannot enroll that UID, because
it requires a homogeneous default-host cohort. This adapter substitutes
ONLY the fresh M1 *per-UID* attested source for that legacy cohort lookup.

P3 GuardedProtectedUIDPort + SameEdge6GUIDRuntimeStore still own every
kernel/DB/packet step, with original P3/6G nonce-bearing ticket. This
adapter NEVER authorizes a cross-Edge UID_ATTACH in legacy mode; the client
must first use the intended Edge ingress and be independently witnessed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable
from edge_egress_k2_migration_inventory import (
    MigrationInventory, MigrationSelection, select_migration,
)
from edge_egress_k2_m3_waves import MigrationMember
from edge_egress_p3_executor import (
    ExecutionScope, ExecutionTicket, assert_guarded_6g_intent,
    _scope_digest,
)
from edge_egress_p3_uid import GuardedProtectedUIDPort
from edge_egress_k2_source_enrollment import SameEdge6GUIDRuntimeStore

M3_VERIFIED_INGRESS_ADAPTER_ENABLED = False


class VerifiedIngressHold(ValueError):
    pass


@dataclass(frozen=True)
class VerifiedIngressContract:
    member: MigrationMember
    scope: ExecutionScope


class GuardedVerifiedIngressUIDPort:
    """One-use executor host port; release must be reviewed in M4/M5."""

    def __init__(
        self, *, contract: VerifiedIngressContract, ticket: ExecutionTicket,
        uid_port: GuardedProtectedUIDPort, db_conn: Callable,
        live_inventory: Callable[[MigrationSelection], MigrationInventory],
        release_enabled: bool = False,
    ):
        if (not isinstance(contract,VerifiedIngressContract)
            or not isinstance(ticket,ExecutionTicket)
            or not isinstance(uid_port,GuardedProtectedUIDPort)
            or not isinstance(uid_port.store,SameEdge6GUIDRuntimeStore)
            or not callable(db_conn) or not callable(live_inventory)
            or contract.scope.action!="UID_ENROLL_SOURCE"
            or contract.scope.source_host!=contract.scope.target_host
            or contract.member.source_ipv4!=contract.member.target_ipv4
            or not contract.member.source_proven
            or contract.member.source_edge_id!=contract.scope.edge_id
            or contract.member.active_sessions!=0
            or contract.member.uid!=contract.scope.uid
            or contract.member.username!=contract.scope.username
            or contract.member.target_edge_id!=contract.scope.edge_id
            or contract.member.protected_edge_id
            or uid_port.plan.scope!=contract.scope
            or uid_port.ticket!=ticket
            or uid_port.store.scope!=contract.scope
            or uid_port.store.ticket!=ticket
            or ticket.scope_digest!=_scope_digest(contract.scope)):
            raise VerifiedIngressHold("EXACT_SAME_EDGE_GUARDED_UID_PORT_REQUIRED")
        self.contract,self.ticket,self.uid_port=contract,ticket,uid_port
        self.db_conn,self.live_inventory=db_conn,live_inventory
        self.release_enabled=release_enabled is True
        self._started=False

    def _check(self, scope: ExecutionScope, *, committed: bool) -> None:
        if (not M3_VERIFIED_INGRESS_ADAPTER_ENABLED
            or not self.release_enabled
            or scope!=self.contract.scope):
            raise VerifiedIngressHold("INGRESS_ADAPTER_NOT_RELEASED")
        assert_guarded_6g_intent(self.db_conn,scope,self.ticket)
        m=self.contract.member
        if not m.selectable:
            raise VerifiedIngressHold("ORIGINAL_M1_MEMBER_BLOCKED")
        review=self.live_inventory(
            select_migration("SINGLE",(m.username,),m.target_edge_id))
        if (not isinstance(review,MigrationInventory)
            or review.selection.mode!="SINGLE"
            or review.selection.usernames!=(m.username,)
            or review.selection.target_edge_id!=m.target_edge_id
            or review.target_ipv4!=m.target_ipv4
            or not review.target_accepted
            or any(issue!="SHARED_6G_BUSY" for issue in review.global_issues)):
            raise VerifiedIngressHold("LIVE_M1_F4_OR_GLOBAL_GUARD_DRIFT")
        found=[a for a in review.accounts if a.selected]
        if len(found)!=1:
            raise VerifiedIngressHold("LIVE_M1_SELECTED_ACCOUNT_DRIFT")
        a=found[0]
        allowed=("TARGET_ALREADY_PROTECTED",) if committed else ()
        if (tuple(a.issues)!=allowed
            or a.username!=m.username or a.uid!=m.uid
            or a.historical_host!=m.historical_host
            or a.source_edge_id!=m.source_edge_id
            or a.source_ipv4!=m.source_ipv4
            or not a.source_proven or a.active_sessions!=0
            or a.protected_edge_id!=(
                m.target_edge_id if committed else "")):
            raise VerifiedIngressHold("LIVE_M1_UID_OR_SOURCE_CHANGED")
        assert_guarded_6g_intent(self.db_conn,scope,self.ticket)

    async def apply(self, scope: ExecutionScope) -> None:
        if self._started:
            raise VerifiedIngressHold("INGRESS_ADAPTER_ONE_SHOT")
        self._started=True
        self._check(scope,committed=False)
        await self.uid_port.apply(scope)

    async def verify(self, scope: ExecutionScope) -> bool:
        if not self._started:
            raise VerifiedIngressHold("INGRESS_ADAPTER_NOT_APPLIED")
        assert_guarded_6g_intent(self.db_conn,scope,self.ticket)
        if await self.uid_port.verify(scope) is not True:
            raise VerifiedIngressHold("PROTECTED_UID_PACKET_PROOF_MISSING")
        self._check(scope,committed=True)
        return True

    async def freeze_or_hold(self, scope: ExecutionScope) -> None:
        if self._started and scope==self.contract.scope:
            await self.uid_port.freeze_or_hold(scope)
