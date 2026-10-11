"""D1-D1: failover UID evidence contract shared by manual 6G and auto 6H.

Evidence objects are supplied by independently reviewed live probes, NOT by
database flags or staged WireGuard metadata. Pure safety policy, no live host
adapter, no bot registration, no shell, no DNS/DB side effects. Nothing here
can turn a STAGED Edge into protected customer READY on its own.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, ip_address

from edge_egress_handoff import HandoffSnapshot, HandoffUnsafe

EVIDENCE_MAX_AGE = timedelta(seconds=30)
VALID_TRIGGERS = frozenset({"manual_6g", "automatic_6h"})


class GuardProofError(HandoffUnsafe):
    pass


@dataclass(frozen=True)
class UIDGuardProof:
    """An observed, non-config-derived route+DNS+IPv6 proof for one Core UID.

    A live adapter MUST establish these from OS ownership, real route and
    firewall state, DNS packet checks and a measured public egress response.
    """
    username: str
    uid: int
    selected_edge_ip: str
    observed_public_ip: str
    observed_at: datetime
    boot_guard_installed: bool
    full_ipv4_uid_rule: bool
    terminal_blackhole: bool
    ipv6_packet_blocked: bool
    dns_exits_only_via_edge: bool
    ssh_identity_on_core: bool
    no_core_fallback: bool


@dataclass(frozen=True)
class ProtectedFailoverProof:
    operation_id: int
    trigger: str
    source_edge_ip: str
    target_edge_ip: str
    core_public_ipv4: str
    users: tuple[UIDGuardProof, ...]
    boot_gate_verified_on_disposable_vps: bool
    existing_6g_lock_running: bool
    observed_at: datetime


def assert_protected_failover_proof(
    snapshot: HandoffSnapshot,
    proof: ProtectedFailoverProof,
    *,
    operation_id: int,
    trigger: str,
    selected_edge_ip: str,
    now: datetime | None = None,
) -> None:
    """Fail if any selected UID can bypass Edge or if evidence is incomplete.

    Every account present in the immutable source snapshot must have an exact
    proof. The same set is rechecked after route selection and after DNS.
    """
    snapshot.validate()
    if type(proof.operation_id) is not int or proof.operation_id != operation_id:
        raise GuardProofError("PROOF_NOT_BOUND_TO_SHARED_6G_LOCK")
    if trigger not in VALID_TRIGGERS or proof.trigger != trigger:
        raise GuardProofError("FAILOVER_TRIGGER_MISMATCH")
    if proof.existing_6g_lock_running is not True:
        raise GuardProofError("SHARED_6G_LOCK_NOT_RUNNING")
    if proof.boot_gate_verified_on_disposable_vps is not True:
        raise GuardProofError("VM_BOOT_GUARD_NOT_VERIFIED")
    if (proof.source_edge_ip != snapshot.source_host or
            proof.target_edge_ip != snapshot.target_host or
            proof.core_public_ipv4 != snapshot.core_public_ipv4):
        raise GuardProofError("FAILOVER_IDENTITY_CHANGED")
    if selected_edge_ip not in {snapshot.source_host, snapshot.target_host}:
        raise GuardProofError("UNREVIEWED_EGRESS_SELECTION")
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None or proof.observed_at.tzinfo is None:
        raise GuardProofError("PROOF_CLOCK_UNTRUSTED")
    age = current - proof.observed_at
    if not timedelta(seconds=-5) <= age <= EVIDENCE_MAX_AGE:
        raise GuardProofError("GLOBAL_PROOF_STALE")
    identities = {(account.username, account.uid) for account in snapshot.active_accounts}
    if (len(proof.users) != len(identities) or
            {(p.username, p.uid) for p in proof.users} != identities):
        raise GuardProofError("PROTECTED_UID_COVERAGE_INCOMPLETE")
    for user in proof.users:
        if type(user.uid) is not int or user.uid < 1000 or user.uid >= 60000:
            raise GuardProofError("UNSAFE_PROTECTED_UID")
        try:
            selected = ip_address(user.selected_edge_ip)
            observed = ip_address(user.observed_public_ip)
        except ValueError as exc:
            raise GuardProofError("INVALID_LIVE_IP_PROOF") from exc
        if not all((isinstance(selected, IPv4Address),
                    isinstance(observed, IPv4Address),
                    selected.is_global, observed.is_global)):
            raise GuardProofError("NONPUBLIC_LIVE_IP_PROOF")
        if selected != ip_address(selected_edge_ip) or observed != selected:
            raise GuardProofError("UID_PUBLIC_IP_NOT_SELECTED_EDGE")
        if user.observed_at.tzinfo is None:
            raise GuardProofError("UID_PROOF_CLOCK_UNTRUSTED")
        elapsed = current - user.observed_at
        if not timedelta(seconds=-5) <= elapsed <= EVIDENCE_MAX_AGE:
            raise GuardProofError("UID_PROOF_STALE")
        checks = {
            "BOOT_GUARD_NOT_INSTALLED": user.boot_guard_installed,
            "PARTIAL_UID_ROUTING": user.full_ipv4_uid_rule,
            "BLACKHOLE_MISSING": user.terminal_blackhole,
            "IPV6_BYPASS_UNVERIFIED": user.ipv6_packet_blocked,
            "DNS_CORE_BYPASS_UNVERIFIED": user.dns_exits_only_via_edge,
            "SSH_MOVED_OFF_CORE": user.ssh_identity_on_core,
            "CORE_FALLBACK_UNSAFE": user.no_core_fallback,
        }
        for error, passed in checks.items():
            if passed is not True:
                raise GuardProofError(error)
