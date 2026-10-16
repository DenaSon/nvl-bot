"""K2 M4 protected root portal for existing Telegram admin workflow.

No privileged bot callback ever imports or invokes this default-OFF facade.
M5/M6 must supply an independently reviewed root service and physical F4
packet witnesses before connecting it to Telegram. No second 6G lease,
migration transaction DB, shell executor, global protected-mode switch or
fallback-to-Core operation is provided.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import time
from typing import Awaitable, Callable

from edge_egress_k2_migration_inventory import (
    MigrationInventory, MigrationSelection, select_migration,
)
from edge_egress_k2_m3_waves import (
    MigrationWavePlan, WaveApproval, WaveReport, MigrationWaveHold,
    build_wave_plan, m4_same_ingress_reviewed,
    m4_cross_edge_single_reviewed,
    m4_operational_reviewed,
    sign_wave_approval, verify_wave_approval,
    run_migration_wave,
)
from edge_egress_p3_executor import ExecutionScope, ExecutionTicket, ExecutionReceipt
from edge_egress_k2_m4_checkpoint import DurableWaveCheckpoint

M4_ROOT_PORTAL_ENABLED = False
# An unchanged Legacy global-mode cross-Edge operation may be prepared ONLY
# for one UID after F4, M42 and the original P3 host factory all accept it.
M4_CROSS_EDGE_SINGLE_ENABLED = False


class RootPortalHold(ValueError):
    pass


@dataclass(frozen=True)
class PreparedWave:
    plan: MigrationWavePlan
    approval: WaveApproval


class RootMigrationPortal:
    """Trusted worker boundary, not a Telegram-side service singleton.

    The worker owns all evidence and P3 factories; a Telegram handler must
    never supply fake proof callbacks, an HMAC secret or a privileged executor.
    """

    def __init__(
        self, *, root_secret: bytes,
        review: Callable[[MigrationSelection],MigrationInventory],
        admin_authorized: Callable[[int,int],bool],
        independent_physical_f4: Callable[[MigrationWavePlan],bool],
        current_protected_mode: Callable[[],str],
        issue_single_ticket: Callable[[ExecutionScope,int,int],ExecutionTicket],
        execute_single: Callable[
            [ExecutionScope,ExecutionTicket,int,int],Awaitable[ExecutionReceipt]],
        committed_6g: Callable[[ExecutionScope,ExecutionTicket,int],bool],
        checkpoint: DurableWaveCheckpoint | None = None,
        clock: Callable[[],int] = lambda:int(time.time()),
        geteuid: Callable[[],int] = os.geteuid,
        release_enabled: bool = False,
    ):
        self.secret=root_secret
        self.review=review
        self.admin_authorized=admin_authorized
        self.physical_f4=independent_physical_f4
        self.current_protected_mode=current_protected_mode
        self.issue_ticket=issue_single_ticket
        self.execute_single=execute_single
        self.committed_6g=committed_6g
        self.checkpoint=checkpoint
        self.clock=clock
        self.geteuid=geteuid
        self.release_enabled=release_enabled

    def _gate(self,actor_id:int,chat_id:int) -> None:
        if (not M4_ROOT_PORTAL_ENABLED or self.release_enabled is not True
            or self.geteuid()!=0
            or not isinstance(self.checkpoint,DurableWaveCheckpoint)
            or not isinstance(self.secret,bytes)
            or len(self.secret)<32 or type(actor_id) is not int
            or type(chat_id) is not int or actor_id<=0 or chat_id==0
            or not all(callable(fn) for fn in (
                self.review,self.admin_authorized,self.physical_f4,
                self.current_protected_mode,self.issue_ticket,
                self.execute_single,self.committed_6g,self.clock,
            ))):
            raise RootPortalHold("M4_ROOT_RELEASE_NOT_ATTESTED")
        if self.admin_authorized(actor_id,chat_id) is not True:
            raise RootPortalHold("M4_SUPERADMIN_NOT_ATTESTED")

    def prepare(self,selection: MigrationSelection, *,
                actor_id:int,chat_id:int) -> PreparedWave:
        self._gate(actor_id,chat_id)
        if not isinstance(selection,MigrationSelection):
            raise RootPortalHold("M4_SELECTION_NOT_ATTESTED")
        inventory=self.review(selection)
        if (not isinstance(inventory,MigrationInventory)
            or inventory.selection!=selection):
            raise RootPortalHold("M4_INVENTORY_SELECTION_DRIFT")
        plan=build_wave_plan(inventory)
        if (len(plan.members)>10 and not m4_operational_reviewed(plan)
            or plan.global_blockers or plan.blocked):
            raise RootPortalHold("M4_UNSAFE_OR_OVERSIZED_SELECTION")
        # Cross-Edge remains a separate, single-only reviewed release gate;
        # no PREPARED approval may authorize an implicit mixed Legacy batch.
        if not (m4_operational_reviewed(plan) or m4_same_ingress_reviewed(plan) or (
            M4_CROSS_EDGE_SINGLE_ENABLED
            and m4_cross_edge_single_reviewed(plan)
        )):
            raise RootPortalHold("M4_CROSS_EDGE_ATTACH_NOT_RELEASED")
        # P3 UID_ENROLL_SOURCE is explicitly constrained to the unchanged
        # Legacy global setting (0). Check *before* creating an approval;
        # never switch the shared protected mode on behalf of one UID.
        if self.current_protected_mode() != "0":
            raise RootPortalHold("M4_SAME_EDGE_REQUIRES_LEGACY_MODE")
        if self.physical_f4(plan) is not True:
            raise RootPortalHold("M4_PHYSICAL_F4_REQUIRED")
        now=self.clock()
        approval=sign_wave_approval(
            plan,actor_id=actor_id,chat_id=chat_id,
            expires_at=now+90,secret=self.secret,now=now,
            operator_authorized=True,
        )
        self.checkpoint.prepare(plan,approval)
        return PreparedWave(plan,approval)

    async def execute(self,prepared: PreparedWave, *,
                      actor_id:int,chat_id:int, stop_requested=None) -> WaveReport:
        self._gate(actor_id,chat_id)
        if not isinstance(prepared,PreparedWave):
            raise RootPortalHold("M4_EXACT_PREPARED_WAVE_REQUIRED")
        plan,approval=prepared.plan,prepared.approval
        now=self.clock()
        verify_wave_approval(
            plan,approval,actor_id=actor_id,chat_id=chat_id,
            secret=self.secret,now=now,
        )
        if (len(plan.members)>10 and not m4_operational_reviewed(plan)
            or plan.global_blockers or plan.blocked):
            raise RootPortalHold("M4_PLAN_CHANGED_OR_BLOCKED")
        if not (m4_operational_reviewed(plan) or m4_same_ingress_reviewed(plan) or (
            M4_CROSS_EDGE_SINGLE_ENABLED
            and m4_cross_edge_single_reviewed(plan)
        )):
            raise RootPortalHold("M4_CROSS_EDGE_ATTACH_NOT_RELEASED")
        refreshed=self.review(plan.selection)
        new_plan=build_wave_plan(refreshed)
        if new_plan.digest!=plan.digest:
            raise RootPortalHold("M4_SELECTED_WAVE_CHANGED")
        if self.current_protected_mode() != "0":
            raise RootPortalHold("M4_MODE_CHANGED_BEFORE_EXECUTE")
        if self.physical_f4(plan) is not True:
            raise RootPortalHold("M4_F4_EXPIRED_BEFORE_EXECUTE")
        # The root DB consumes exactly this actor/chat/plan approval BEFORE
        # any P3 host mutation. A crash leaves RUNNING permanently inspectable
        # as UNKNOWN_INFLIGHT; no automatic 6G unlock or batch replay.
        self.checkpoint.begin(plan,approval,actor_id=actor_id,chat_id=chat_id)
        try:
            report=await run_migration_wave(
                plan,approval,actor_id=actor_id,chat_id=chat_id,
                approval_secret=self.secret,
                fresh_inventory=self.review,
                issue_single_ticket=self.issue_ticket,
                execute_single=self.execute_single,
                committed_6g=self.committed_6g,
                current_protected_mode=self.current_protected_mode,
                on_verified=lambda username,uid,op:
                    self.checkpoint.record_verified(
                        plan,approval,username,uid,op),
                continuation_authorized=(lambda: self.checkpoint.running(plan,approval)),
                stop_requested=stop_requested,
                release_enabled=True,geteuid=self.geteuid,clock=self.clock,
            )
            self.checkpoint.finish(plan,approval,report)
            return report
        except BaseException:
            # CancelledError is BaseException; never resume next UID when
            # cancellation happens during awaited root operations. Preserve
            # the original exception if checkpoint writing itself fails.
            try:
                self.checkpoint.hold(plan,approval)
            except Exception:
                pass  # RUNNING remains a stronger fail-closed gate.
            raise
