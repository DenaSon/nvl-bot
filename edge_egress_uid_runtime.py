"""F2: journaled per-UID Egress orchestration on the EXISTING 6G lease.

Injected ports, default OFF. The controller does not import/modify the bot,
install PAM/systemd, create tunnels or change legacy SSH account ownership.
Any fault after a durable BLOCKED intent preserves the shared 6G lock and
fail-closed UID protection for operator reconciliation.

F2 is a code/integration milestone, NOT authority to cut over production
customers before the real SSH session-gate and reboot E2E tests.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol

from edge_egress_uid_policy import UIDPolicyRequest


HOLD_PHASE = "EGRESS_UID_RUNTIME_RECOVERY_REQUIRED"
PHASES = frozenset({
    "EGRESS_UID_RUNTIME_LOCKED",
    "EGRESS_UID_RUNTIME_SESSION_GATE",
    "EGRESS_UID_RUNTIME_BLOCK_INTENT",
    "EGRESS_UID_RUNTIME_ACCOUNT_IDLE",
    "EGRESS_UID_RUNTIME_ARM_GUARD",
    "EGRESS_UID_RUNTIME_START_EDGE",
    "EGRESS_UID_RUNTIME_ATTACH",
    "EGRESS_UID_RUNTIME_PROVE",
    "EGRESS_UID_RUNTIME_COMMIT_PROTECTED",
    "EGRESS_UID_RUNTIME_FREEZE",
    "EGRESS_UID_RUNTIME_FROZEN",
    "EGRESS_UID_RUNTIME_PROTECTED",
    HOLD_PHASE,
})


class RuntimeUnsafe(ValueError):
    pass


@dataclass(frozen=True)
class RuntimeOutcome:
    ok: bool
    reason: str
    operation_id: Optional[int] = None
    state: str = "DENIED"
    recovery_required: bool = False
    customer_ready: bool = False


class RuntimePorts(Protocol):
    """No second lock, no default shell transports.

    The app MUST provide the existing bot 6G lock/journal functions.
    An independent active PAM account hook must be verified before an
    intent is reserved; users already logged in must be drained/rejected.
    """
    async def acquire_6g(self, source: str, target: str): ...
    async def journal(self, operation_id: int, status: str,
                      phase: str, details: dict): ...
    async def check_session_gate(self, request: UIDPolicyRequest): ...
    async def reserve_blocked(self, operation_id: int, request: UIDPolicyRequest,
                              source: str, dns_port: int): ...
    async def assert_frozen_binding(self, operation_id: int, request: UIDPolicyRequest,
                                    source: str, dns_port: int): ...
    async def check_no_existing_sessions(self, request: UIDPolicyRequest): ...
    async def arm_boot_guard(self, request: UIDPolicyRequest, dns_port: int): ...
    async def start_edge(self, request: UIDPolicyRequest): ...
    async def attach_edge(self, request: UIDPolicyRequest): ...
    async def transition(self, operation_id: int, request: UIDPolicyRequest,
                         source: str, before: str, after: str): ...
    async def prove_ipv4(self, request: UIDPolicyRequest): ...
    async def prove_dns_ipv6(self, request: UIDPolicyRequest): ...
    async def commit_protected(self, operation_id: int, request: UIDPolicyRequest,
                               source: str): ...
    async def freeze_edge(self, request: UIDPolicyRequest): ...
    async def prove_frozen(self, request: UIDPolicyRequest): ...


async def attach_protected(
    ports: RuntimePorts, request: UIDPolicyRequest, *, source: str,
    dns_port: int, authorized: bool = False, resume_frozen: bool = False,
) -> RuntimeOutcome:
    """Atomic-intent/journaled attach. No Core fallback or canary restore."""
    request.validate()
    if not authorized:
        return RuntimeOutcome(False, "EXPLICIT_PROTECTED_AUTHORIZATION_REQUIRED")
    if source in (request.spec.core_public_ipv4, request.spec.edge_public_ipv4):
        return RuntimeOutcome(False, "INVALID_SOURCE_EDGE")
    operation_id, busy = await ports.acquire_6g(
        source, request.spec.edge_public_ipv4,
    )
    if operation_id is None:
        return RuntimeOutcome(False, "SHARED_6G_BUSY", busy)
    phase = "EGRESS_UID_RUNTIME_LOCKED"
    reserved = False
    mutation_possible = False
    protection_committed = False
    binding_state = "FROZEN" if resume_frozen else "BLOCKED"

    async def record(status, details=None):
        await ports.journal(operation_id, status, phase, details or {})

    try:
        await record("RUNNING", {"uid": request.uid,
                                 "username": request.username,
                                 "edge_id": request.spec.edge_id})
        # This MUST verify an already-installed active per-account PAM gate.
        # A new row then blocks all subsequent protected logins immediately.
        phase = "EGRESS_UID_RUNTIME_SESSION_GATE"
        await record("RUNNING")
        await ports.check_session_gate(request)

        phase = "EGRESS_UID_RUNTIME_BLOCK_INTENT"
        await record("RUNNING")
        if resume_frozen:
            await ports.assert_frozen_binding(operation_id, request, source, dns_port)
        else:
            await ports.reserve_blocked(operation_id, request, source, dns_port)
        reserved = True

        # Check AFTER persistent blocked intent, so fresh SSH auth is denied.
        phase = "EGRESS_UID_RUNTIME_ACCOUNT_IDLE"
        await record("RUNNING")
        await ports.check_no_existing_sessions(request)

        phase = "EGRESS_UID_RUNTIME_ARM_GUARD"
        await record("RUNNING")
        mutation_possible = True
        await ports.arm_boot_guard(request, dns_port)

        phase = "EGRESS_UID_RUNTIME_START_EDGE"
        await record("RUNNING")
        await ports.start_edge(request)

        phase = "EGRESS_UID_RUNTIME_ATTACH"
        await record("RUNNING")
        await ports.attach_edge(request)
        await ports.transition(operation_id, request, source,
                               binding_state, "ROUTED_UNVERIFIED")
        binding_state = "ROUTED_UNVERIFIED"

        phase = "EGRESS_UID_RUNTIME_PROVE"
        await record("RUNNING")
        observed = await ports.prove_ipv4(request)
        if observed != request.spec.edge_public_ipv4:
            raise RuntimeUnsafe("WRONG_PUBLIC_EGRESS_IP")
        await ports.prove_dns_ipv6(request)

        phase = "EGRESS_UID_RUNTIME_COMMIT_PROTECTED"
        await record("RUNNING")
        await ports.commit_protected(operation_id, request, source)
        binding_state = "PROTECTED"
        protection_committed = True

        phase = "EGRESS_UID_RUNTIME_PROTECTED"
        await record("SUCCEEDED", {"observed_edge_ipv4": observed})
        # This success means conditional controlled-runtime proof only.
        # Customer readiness still needs real PAM/boot/SSH E2E acceptance.
        return RuntimeOutcome(True, "RUNTIME_PROOF_COMMITTED", operation_id,
                              state="PROTECTED", customer_ready=False)
    except Exception:
        if reserved or mutation_possible:
            # Do not tear down UID selectors/terminal blackhole. Unknown
            # kernel state or a failed journal is an operator recovery hold.
            frozen = False
            try:
                await ports.freeze_edge(request)
                await ports.prove_frozen(request)
                frozen = True
            except Exception:
                pass
            try:
                if reserved:
                    # FROZEN/HOLD intent remains; never delete protected
                    # mapping nor allow a normal Core fallback.
                    prior = binding_state
                    try:
                        await ports.transition(operation_id, request, source,
                                               prior, "HOLD")
                    except Exception:
                        pass
                phase = HOLD_PHASE
                await record("RUNNING", {"frozen": frozen})
            except Exception:
                pass
            return RuntimeOutcome(False, "OPERATOR_RECOVERY_REQUIRED",
                                  operation_id, state="HOLD",
                                  recovery_required=True)
        try:
            phase = "EGRESS_UID_RUNTIME_LOCKED"
            await record("FAILED", {"reason": "PRE_RESERVATION_FAILURE"})
        except Exception:
            return RuntimeOutcome(False, "JOURNAL_UNCERTAIN", operation_id,
                                  state="HOLD", recovery_required=True)
        return RuntimeOutcome(False, "PRE_RESERVATION_FAILED", operation_id)


async def freeze_protected(
    ports: RuntimePorts, request: UIDPolicyRequest, *, source: str,
    authorized: bool = False,
) -> RuntimeOutcome:
    """Explicit per-user freeze, no removal of UID rule/blackhole or mapping.

    For multiple users on the SAME Edge route-table, freezing the Edge default
    deliberately affects *all* users sharing the Edge. F2 never claims that
    this is a single-user kernel route action.
    """
    request.validate()
    if not authorized:
        return RuntimeOutcome(False, "EXPLICIT_FREEZE_AUTHORIZATION_REQUIRED")
    op, busy = await ports.acquire_6g(source, request.spec.edge_public_ipv4)
    if op is None:
        return RuntimeOutcome(False, "SHARED_6G_BUSY", busy)
    try:
        await ports.journal(op, "RUNNING", "EGRESS_UID_RUNTIME_FREEZE",
                            {"edge_id": request.spec.edge_id})
        await ports.freeze_edge(request)
        await ports.prove_frozen(request)
        await ports.transition(op, request, source, "PROTECTED", "FROZEN")
        await ports.journal(op, "SUCCEEDED", "EGRESS_UID_RUNTIME_FROZEN",
                            {"edge_id": request.spec.edge_id})
        return RuntimeOutcome(True, "FROZEN_FAIL_CLOSED", op, state="FROZEN")
    except Exception:
        try:
            await ports.transition(op, request, source, "PROTECTED", "HOLD")
        except Exception:
            pass
        try:
            await ports.journal(op, "RUNNING", HOLD_PHASE, {})
        except Exception:
            pass
        return RuntimeOutcome(False, "OPERATOR_RECOVERY_REQUIRED", op,
                              state="HOLD", recovery_required=True)
