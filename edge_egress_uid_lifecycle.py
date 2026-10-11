"""D1-C3B: 6G-locked UID-guard lifecycle orchestration (INJECTED PORTS).

No bot registration, live command transport, customer activation, DNS changes,
or systemd mutations. This saga is an opt-in kernel-canary coordinator; a
production adapter must establish boot-time protection and live DNS/IPv6 proof
*before* it may let a protected account send Internet traffic.

Failure after possibly touching kernel state NEVER unlocks Phase 6G. The
shared journal is left RUNNING in EGRESS_UID_RECOVERY_REQUIRED. A successful
canary is fully stopped and restored by the injected host port while under
the lock. If restoration is uncertain, we leave the shared lock HELD.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Optional

from edge_egress_uid_policy import UIDPolicyRequest


HOLD_PHASE = "EGRESS_UID_RECOVERY_REQUIRED"
MUTATING_PHASES = frozenset({
    "EGRESS_UID_ARM_GUARD",
    "EGRESS_UID_START_SHADOW",
    "EGRESS_UID_ATTACH_ROUTE",
    "EGRESS_UID_PROVE_IPV4",
    "EGRESS_UID_PROVE_IPV6_DNS",
    "EGRESS_UID_STOP_SHADOW",
    "EGRESS_UID_RESTORE_CANARY",
    HOLD_PHASE,
})


class UIDCanaryUnsafe(ValueError):
    pass


@dataclass(frozen=True)
class UIDCanaryResult:
    ok: bool
    reason: str
    operation_id: Optional[int]
    recovery_required: bool = False
    state: str = "DENIED"
    customer_ready: bool = False


class UIDCanaryPorts(Protocol):
    """An opt-in adapter using the SAME persisted Phase 6G operation lock.

    Ports must bind precisely one username+UID+Edge and compare the live
    account ownership under 6G lock at each transition. No alternative lock
    or ephemeral in-memory transaction is acceptable.

    arm_guard: before UID rule installation, ensure terminal blackhole,
    IPv6 protection and DNS guard. On errors this MAY have partially mutated.

    freeze_uid: remove Edge next-hop WITHOUT deleting UID rule, terminal
    blackhole, IPv6 or DNS guards. Must work even if attach raised.

    restore_disposable_canary: may remove guards ONLY after the Edge shadow
    has stopped and the canary is independently verified as unprotected
    before entering the operation; never use for a protected customer.
    """
    async def acquire_6g_lock(self, source: str, target: str) -> tuple[Optional[int], Optional[int]]: ...
    async def journal_6g(self, operation_id: int, status: str, phase: str,
                         details: dict) -> None: ...
    async def assert_ownership_and_uid(self, request: UIDPolicyRequest,
                                       source: str) -> None: ...
    async def assert_disposable_lab_ready(self, request: UIDPolicyRequest) -> None: ...
    async def arm_guard(self, request: UIDPolicyRequest) -> None: ...
    async def start_shadow(self, request: UIDPolicyRequest) -> None: ...
    async def attach_edge(self, request: UIDPolicyRequest) -> None: ...
    async def prove_public_edge_ip(self, request: UIDPolicyRequest) -> str: ...
    async def prove_ipv6_dns_blocked(self, request: UIDPolicyRequest) -> None: ...
    async def freeze_uid(self, request: UIDPolicyRequest) -> None: ...
    async def stop_shadow(self, request: UIDPolicyRequest) -> None: ...
    async def restore_disposable_canary(self, request: UIDPolicyRequest) -> None: ...


async def run_disposable_uid_canary(
    ports: UIDCanaryPorts,
    request: UIDPolicyRequest,
    *,
    source_edge: str,
    explicitly_authorized: bool = False,
) -> UIDCanaryResult:
    """Short-lived test only: all phase writes precede kernel operations.

    Success means the canary proved Edge IP and the injected port restored
    its original unprotected state. NEVER signals protected customer READY.
    """
    request.validate()
    if not explicitly_authorized:
        return UIDCanaryResult(False, "EXPLICIT_LAB_AUTHORIZATION_REQUIRED", None)
    spec = request.spec
    if source_edge in (spec.edge_public_ipv4, spec.core_public_ipv4):
        return UIDCanaryResult(False, "INVALID_SOURCE_EDGE", None)
    operation_id, busy = await ports.acquire_6g_lock(
        source_edge, spec.edge_public_ipv4
    )
    if operation_id is None:
        return UIDCanaryResult(False, "SHARED_6G_BUSY", busy)

    touched = False
    guard_armed = False
    shadow_attempted = False
    phase = "EGRESS_UID_LOCKED"

    async def record(status: str, phase: str, details: dict) -> None:
        await ports.journal_6g(operation_id, status, phase, details)

    try:
        await record("RUNNING", phase, {
            "kind": "EGRESS_UID_CANARY",
            "edge_id": spec.edge_id, "username": request.username,
            "uid": request.uid,
        })
        phase = "EGRESS_UID_VALIDATE"
        await record("RUNNING", phase, {})
        await ports.assert_ownership_and_uid(request, source_edge)
        await ports.assert_disposable_lab_ready(request)

        # Mark mutation possible BEFORE invoking the arm implementation.
        phase = "EGRESS_UID_ARM_GUARD"
        await record("RUNNING", phase, {})
        touched = True
        await ports.arm_guard(request)
        guard_armed = True

        phase = "EGRESS_UID_START_SHADOW"
        await record("RUNNING", phase, {})
        shadow_attempted = True
        await ports.start_shadow(request)

        phase = "EGRESS_UID_ATTACH_ROUTE"
        await record("RUNNING", phase, {})
        await ports.assert_ownership_and_uid(request, source_edge)
        await ports.attach_edge(request)

        phase = "EGRESS_UID_PROVE_IPV4"
        await record("RUNNING", phase, {})
        observed = await ports.prove_public_edge_ip(request)
        if observed != spec.edge_public_ipv4:
            raise UIDCanaryUnsafe("EDGE_PUBLIC_IP_NOT_PROVEN")

        phase = "EGRESS_UID_PROVE_IPV6_DNS"
        await record("RUNNING", phase, {})
        await ports.prove_ipv6_dns_blocked(request)

        # Detach then stop; keep guard active until BOTH have succeeded.
        phase = "EGRESS_UID_STOP_SHADOW"
        await record("RUNNING", phase, {})
        await ports.freeze_uid(request)
        await ports.stop_shadow(request)
        shadow_attempted = False

        phase = "EGRESS_UID_RESTORE_CANARY"
        await record("RUNNING", phase, {})
        await ports.restore_disposable_canary(request)
        touched = False
        guard_armed = False

        # The transaction finished, but did not create a protected customer.
        await record("SUCCEEDED", "EGRESS_UID_CANARY_RESTORED", {
            "observed_edge_ip": observed, "customer_ready": False
        })
        return UIDCanaryResult(True, "DISPOSABLE_CANARY_RESTORED",
                               operation_id, state="RESTORED")
    except Exception as exc:
        # Never unlock if kernel mutation might have happened.
        if touched:
            frozen = False
            shadow_stopped = not shadow_attempted
            try:
                await ports.freeze_uid(request)
                frozen = True
            except Exception:
                pass
            if shadow_attempted:
                try:
                    await ports.stop_shadow(request)
                    shadow_stopped = True
                except Exception:
                    pass
            try:
                await record("RUNNING", HOLD_PHASE, {
                    "failed_phase": phase, "frozen": frozen,
                    "shadow_stopped": shadow_stopped,
                    "guard_maybe_partial": not guard_armed,
                })
            except Exception:
                pass
            return UIDCanaryResult(False, "RECOVERY_REQUIRED",
                                   operation_id, True, "GUARDED_HOLD")

        try:
            await record("FAILED", phase, {
                "reason": str(exc)[:100] if isinstance(exc, UIDCanaryUnsafe)
                else "PRE_MUTATION_FAILED",
            })
        except Exception:
            return UIDCanaryResult(False, "JOURNAL_UNCERTAIN",
                                   operation_id, True, "RECOVERY_REQUIRED")
        return UIDCanaryResult(False, "PRE_MUTATION_FAILED",
                               operation_id, state="NOT_MUTATED")
