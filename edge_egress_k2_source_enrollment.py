"""K2 Phase 2 — explicitly gated same-ingress/same-egress Legacy bootstrap.

The SSH account stays on Core. This composes the EXISTING P3-A journal and
P3-C deny-first UID lifecycle; it never changes public DNS/default host/6H.
No live host factory, PAM installer or Telegram execute handler is provided.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest
import json
from typing import Callable

from edge_egress_k2_legacy_enrollment import (
    LegacyEnrollmentAudit, inspect_legacy_enrollment,
)
from edge_egress_p3_executor import (
    ExecutionScope, ExecutionTicket, _scope_digest,
    assert_guarded_6g_intent, INTENT_PHASE,
)
from edge_egress_p3_uid import (
    NEW, GuardedProtectedUIDPort, ProtectedUIDPlan, review_protected_uid,
)
from edge_egress_uid_policy import UIDPolicyRequest
from edge_egress_uid_runtime_store import (
    Existing6GUIDRuntimeStore, RuntimeStoreUnsafe,
)


SOURCE_ENROLLMENT_RELEASED = False


class SourceEnrollmentHold(ValueError):
    pass


@dataclass(frozen=True)
class SourceEnrollmentPlan:
    audit: LegacyEnrollmentAudit
    uid_plan: ProtectedUIDPlan

    @property
    def scope(self) -> ExecutionScope:
        return self.uid_plan.scope


def plan_source_enrollment(db_conn: Callable, target_edge_id: str,
                           request: UIDPolicyRequest, *, dns_port: int,
                           roster_loader: Callable, guard_loader: Callable,
                           os_uid_for_username: Callable) -> SourceEnrollmentPlan:
    """Read-only: record an exact Legacy UID and complete preinstalled guard."""
    audit = inspect_legacy_enrollment(
        db_conn, target_edge_id, os_uid=os_uid_for_username,
    )
    if (not audit.inventory_clear or
            (request.username, request.uid) not in audit.legacy_users or
            request.spec.edge_id != audit.source_edge_id or
            request.spec.edge_public_ipv4 != audit.source_ip):
        raise SourceEnrollmentHold("LEGACY_SOURCE_IDENTITY_NOT_ACCEPTED")
    scope = ExecutionScope(
        "UID_ENROLL_SOURCE", audit.source_edge_id, audit.source_ip,
        audit.source_ip, username=request.username, uid=request.uid,
    )
    uid_plan = review_protected_uid(
        db_conn, scope, request, dns_port=dns_port, purpose=NEW,
        roster_loader=roster_loader, guard_loader=guard_loader,
        os_uid_for_username=os_uid_for_username,
    )
    return SourceEnrollmentPlan(audit, uid_plan)


class SameEdge6GUIDRuntimeStore(Existing6GUIDRuntimeStore):
    """P3-C store adapter: SAME Edge only under precise existing P3-A intent.

    The base store still rejects source==target. This adapter never permits
    that exception for other actions, other accounts, or non-current leases.
    """

    def __init__(self, db_conn: Callable, os_uid_for_username: Callable,
                 *, scope: ExecutionScope, ticket: ExecutionTicket,
                 shared_edge_enabled: bool = False):
        if (not isinstance(scope, ExecutionScope)
                or scope.action != "UID_ENROLL_SOURCE"
                or scope.source_host != scope.target_host
                or not isinstance(ticket, ExecutionTicket)
                or not compare_digest(ticket.scope_digest, _scope_digest(scope))
                or not shared_edge_enabled):
            raise SourceEnrollmentHold("EXPLICIT_SAME_EDGE_CONTRACT_REQUIRED")
        super().__init__(db_conn, os_uid_for_username, shared_edge_enabled=True)
        self.scope = scope
        self.ticket = ticket

    def _lock(self, conn, op_id: int, source: str, target: str) -> None:
        if (type(op_id) is not int or op_id <= 0
                or source != target or source != self.scope.source_host
                or self.scope.target_host != target):
            raise RuntimeStoreUnsafe("SAME_EDGE_SCOPE_CHANGED")
        rows = conn.execute(
            "SELECT id,source_host,target_host,detail_json "
            "FROM failover_operations WHERE status='RUNNING'"
        ).fetchall()
        if len(rows) != 1 or rows[0][:3] != (op_id, source, target):
            raise RuntimeStoreUnsafe("SAME_EDGE_SHARED_6G_LEASE_INVALID")
        try:
            detail = json.loads(rows[0][3])
        except (ValueError, TypeError) as exc:
            raise RuntimeStoreUnsafe("SAME_EDGE_INTENT_UNTRUSTED") from exc
        digest = sha256(self.ticket.nonce.encode("ascii")).hexdigest()
        if (not isinstance(detail, dict)
                or detail.get("kind") != "K2_P3A"
                or detail.get("phase") != INTENT_PHASE
                or detail.get("action") != "UID_ENROLL_SOURCE"
                or detail.get("edge_id") != self.scope.edge_id
                or not isinstance(detail.get("nonce_hash"), str)
                or not isinstance(detail.get("scope_digest"), str)
                or not compare_digest(detail["nonce_hash"], digest)
                or not compare_digest(detail["scope_digest"],
                                      _scope_digest(self.scope))):
            raise RuntimeStoreUnsafe("SAME_EDGE_INTENT_MISMATCH")


class GuardedSourceEnrollmentPort:
    """One-shot 6G host port; pre-mutating cohort snapshot must still match."""

    def __init__(self, *, db_conn: Callable, plan: SourceEnrollmentPlan,
                 ticket: ExecutionTicket, uid_port: GuardedProtectedUIDPort,
                 os_uid_for_username: Callable,
                 release_enabled: bool = False):
        if (not isinstance(plan, SourceEnrollmentPlan)
                or not isinstance(ticket, ExecutionTicket)
                or not isinstance(uid_port, GuardedProtectedUIDPort)
                or uid_port.plan != plan.uid_plan
                or uid_port.ticket != ticket
                or not isinstance(uid_port.store, SameEdge6GUIDRuntimeStore)
                or uid_port.store.scope != plan.scope
                or uid_port.store.ticket != ticket
                or not compare_digest(ticket.scope_digest,
                                      _scope_digest(plan.scope))):
            raise SourceEnrollmentHold("PINNED_UID_HOST_PORT_REQUIRED")
        self.db_conn, self.plan, self.ticket = db_conn, plan, ticket
        self.uid_port, self.os_uid = uid_port, os_uid_for_username
        self.release_enabled = release_enabled is True
        self._started = False

    def _intent(self, scope: ExecutionScope) -> int:
        if (scope != self.plan.scope or not self.release_enabled
                or not self.uid_port.release_enabled):
            raise SourceEnrollmentHold("SOURCE_ENROLLMENT_NOT_RELEASED")
        return assert_guarded_6g_intent(self.db_conn, scope, self.ticket)

    async def apply(self, scope: ExecutionScope) -> None:
        if self._started:
            raise SourceEnrollmentHold("ONE_SHOT_SOURCE_ENROLLMENT")
        self._started = True
        op = self._intent(scope)
        exact_lease = (
            op, _scope_digest(scope),
            sha256(self.ticket.nonce.encode("ascii")).hexdigest(),
        )
        current = inspect_legacy_enrollment(
            self.db_conn, self.plan.audit.target_edge_id,
            os_uid=self.os_uid, authorized_operation=exact_lease,
        )
        if (not current.inventory_clear
                or not compare_digest(current.fingerprint,
                                      self.plan.audit.fingerprint)
                or (scope.username, scope.uid) not in current.legacy_users):
            raise SourceEnrollmentHold("LEGACY_COHORT_DRIFT_UNDER_6G")
        self._intent(scope)
        await self.uid_port.apply(scope)

    async def verify(self, scope: ExecutionScope) -> bool:
        self._intent(scope)
        if not self._started or await self.uid_port.verify(scope) is not True:
            raise SourceEnrollmentHold("SOURCE_UID_EGRESS_NOT_PROVEN")
        self._intent(scope)
        with self.db_conn() as conn:
            row = conn.execute(
                "SELECT host,service_type,status FROM ssh_accounts "
                "WHERE username=?", (scope.username,),
            ).fetchone()
            mode = conn.execute(
                "SELECT value FROM settings "
                "WHERE key='edge_egress_protected_mode'",
            ).fetchone()
        if (row is None or row[0] != scope.source_host
                or row[1] != "ssh" or "فعال" not in str(row[2])
                or "غیر" in str(row[2]) or mode != ("0",)):
            raise SourceEnrollmentHold("LEGACY_HOST_OR_GLOBAL_MODE_CHANGED")
        return True

    async def freeze_or_hold(self, scope: ExecutionScope) -> None:
        if self._started and scope == self.plan.scope:
            await self.uid_port.freeze_or_hold(scope)
