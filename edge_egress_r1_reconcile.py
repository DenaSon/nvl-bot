"""R1 read-only reconciliation: observe startup/transport; never attach a UID.

No systemd, SSH, WireGuard, iptables or database writes. This check does not
release the existing 6G lease, nor does it replace F2 BootGuard/PAM or the
post-reboot disposable acceptance required by issue #88.
"""
from __future__ import annotations

from dataclasses import dataclass

from edge_egress_r1_transport import R1Observation, decide


@dataclass(frozen=True)
class R1RecoveryInputs:
    transport: R1Observation
    # These are verified snapshots supplied by callers reading their
    # EXISTING 6G journal and existing protected UID tables. Unknown is None.
    shared_6g_running: bool | None
    protected_binding_count: int | None
    protected_uid_guards_attested: bool | None
    protected_ssh_gate_attested: bool | None
    outstanding_recovery_marker: bool | None


@dataclass(frozen=True)
class R1RecoveryResult:
    state: str
    reason: str
    network_mutation_allowed: bool = False
    uid_attach_allowed: bool = False
    customer_ready: bool = False


def assess_r1_recovery(inputs: R1RecoveryInputs) -> R1RecoveryResult:
    """Always deny any automatic actions, including after a healthy boot."""
    t = decide(inputs.transport)
    if t.state == "HOLD":
        return R1RecoveryResult("HOLD", "TRANSPORT_" + t.reason)
    checks = (inputs.shared_6g_running, inputs.protected_binding_count,
              inputs.protected_uid_guards_attested,
              inputs.protected_ssh_gate_attested,
              inputs.outstanding_recovery_marker)
    if (any(v is None for v in checks) or
        type(inputs.shared_6g_running) is not bool or
        type(inputs.protected_binding_count) is not int or
        inputs.protected_binding_count < 0 or
        type(inputs.protected_uid_guards_attested) is not bool or
        type(inputs.protected_ssh_gate_attested) is not bool or
        type(inputs.outstanding_recovery_marker) is not bool):
        return R1RecoveryResult("HOLD", "JOURNAL_OR_UID_GUARD_EVIDENCE_UNKNOWN")
    if inputs.shared_6g_running:
        return R1RecoveryResult("HOLD", "SHARED_6G_RECOVERY_LEASE_ACTIVE")
    if inputs.outstanding_recovery_marker:
        return R1RecoveryResult("HOLD", "EXISTING_RECOVERY_MARKER")
    if inputs.protected_binding_count and (
        not inputs.protected_uid_guards_attested or
        not inputs.protected_ssh_gate_attested
    ):
        return R1RecoveryResult("HOLD", "PROTECTED_UID_ADMISSION_NOT_ATTESTED")
    if inputs.protected_binding_count:
        # Even with guards and gate, only F2 + signed acceptance may lift a
        # protected UID from frozen state after actual network proof.
        return R1RecoveryResult("HOLD", "PROTECTED_UID_NEEDS_INDEPENDENT_F2_RECONCILE")
    if t.state == "MANAGED_RUNNING":
        return R1RecoveryResult("TRANSPORT_ONLY",
                                "UID_PROTECTION_NOT_ACTIVATED")
    if t.state == "STAGED_OFFLINE":
        return R1RecoveryResult("STAGED_OFFLINE",
                                "MANUAL_DISPOSABLE_6G_REVIEW_REQUIRED")
    return R1RecoveryResult("HOLD", "UNRECOGNIZED_TRANSPORT_STATE")
