"""D1-C1 compatibility gates for existing NVL Edge lifecycle.

Legacy Phase 6G/6H changes DNS to Core, rebuilds accounts on Standby and
changes ownership. It MUST NOT silently switch protected Core-terminated SSH
customers to that mechanism. Conversely the new egress provisioner is still
stage-only and must not advertise a newly provisioned Relay as protected-ready.

This module is deliberately side-effect-free and has no success path for
protected-mode legacy switches. The mode is OFF by default until a separately
reviewed atomic Core/Edge relay handoff engine is implemented and proven.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


PROTECTED_SETTING_KEY = "edge_egress_protected_mode"
PROTECTED_SETTING_DEFAULT = "0"

LEGACY_FAILOVER_UNSAFE = "EGRESS_PROTECTED_LEGACY_CORE_FALLBACK_UNSAFE"
EDGE_PROVISION_UNSAFE = "EGRESS_PROTECTED_EDGE_ACTIVATION_NOT_READY"
UNKNOWN_MODE = "EGRESS_PROTECTED_MODE_INVALID"


@dataclass(frozen=True)
class LifecycleGate:
    allowed: bool
    reason: str
    protected_mode: bool


def _mode(value: Optional[str]) -> str:
    # '0' is the only accepted opt-out. Invalid/unknown configuration must
    # block customer-affecting changes rather than silently fall back to Core.
    if value is None:
        return PROTECTED_SETTING_DEFAULT
    if value == "0":
        return "0"
    if value == "1":
        return "1"
    return "invalid"


def legacy_failover_gate(protected_setting: Optional[str]) -> LifecycleGate:
    """Enforce the contract BEFORE any Phase 6G fallback DNS or account rebuild.

    The function is used for manual UI preflight and for the mandatory
    lock-protected re-check shared with Phase 6H automatic failover.
    """
    state = _mode(protected_setting)
    if state == "0":
        return LifecycleGate(True, "LEGACY_UNPROTECTED_MODE", False)
    if state == "invalid":
        return LifecycleGate(False, UNKNOWN_MODE, True)
    return LifecycleGate(False, LEGACY_FAILOVER_UNSAFE, True)


def legacy_new_edge_gate(protected_setting: Optional[str]) -> LifecycleGate:
    """Existing onboarding installs ingress-only Edge and marks it active.

    Until bot-driven egress provisioning, peer rekey, external-IP verification
    and crash-safe handoff exist, deny that lifecycle in protected mode.
    """
    state = _mode(protected_setting)
    if state == "0":
        return LifecycleGate(True, "LEGACY_UNPROTECTED_MODE", False)
    if state == "invalid":
        return LifecycleGate(False, UNKNOWN_MODE, True)
    return LifecycleGate(False, EDGE_PROVISION_UNSAFE, True)
