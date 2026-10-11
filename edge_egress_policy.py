"""Pure safety policy for a future NVL bot-managed Edge egress lifecycle.

No database reads/writes, shell calls, DNS changes, or system/network mutation.
This module is NOT yet wired into Phase 6G/6H.
"""
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, ip_address
from typing import Optional


@dataclass(frozen=True)
class EgressReadiness:
    """Fresh, independently verified observations about a relay-mode Edge.

    observed_egress_ipv4 must come from a live end-to-end Core -> Egress -> Edge
    TCP probe, never from a static config, the host_pool row, or a WG handshake.
    """
    edge_host: str
    public_ipv4: str
    observed_egress_ipv4: Optional[str]
    ingress_service_ok: bool
    management_ssh_ok: bool
    ingress_wireguard_ok: bool
    egress_wireguard_ok: bool
    egress_nat_ok: bool
    fail_closed_policy_ok: bool
    ipv6_leak_protected: bool
    fresh: bool
    mode: str = "relay"


@dataclass(frozen=True)
class ReadinessDecision:
    ready: bool
    reason: str


REASON_READY = "READY"
REASON_SOURCE_EQUALS_TARGET = "SOURCE_EQUALS_TARGET"
REASON_TARGET_IS_CORE = "TARGET_IS_CORE"
REASON_GLOBAL_DOMAIN_CONFLICT = "GLOBAL_DOMAIN_MULTI_EDGE_CONFLICT"
REASON_CORE_FALLBACK_UNSAFE = "LEGACY_DNS_CORE_FALLBACK_UNSAFE"
REASON_TARGET_NOT_READY = "TARGET_EGRESS_NOT_READY"


def evaluate_egress_readiness(data: EgressReadiness) -> ReadinessDecision:
    """Deny readiness if *any* live proof is missing or inconsistent."""
    try:
        public_ip = ip_address(data.public_ipv4)
        host_ip = ip_address(data.edge_host)
    except ValueError:
        return ReadinessDecision(False, "INVALID_EDGE_IP")
    if not isinstance(public_ip, IPv4Address) or not isinstance(host_ip, IPv4Address):
        return ReadinessDecision(False, "INVALID_EDGE_IP")
    if not public_ip.is_global:
        return ReadinessDecision(False, "NOT_PUBLIC_EDGE_IP")
    if host_ip != public_ip:
        return ReadinessDecision(False, "HOST_PUBLIC_IP_MISMATCH")
    if data.mode != "relay":
        return ReadinessDecision(False, "UNSUPPORTED_EDGE_MODE")
    if not data.fresh:
        return ReadinessDecision(False, "STALE_EDGE_EVIDENCE")
    gates = (
        ("INGRESS_SERVICE_DOWN", data.ingress_service_ok),
        ("ADMIN_SSH_DOWN", data.management_ssh_ok),
        ("INGRESS_WG_DOWN", data.ingress_wireguard_ok),
        ("EGRESS_WG_DOWN", data.egress_wireguard_ok),
        ("EGRESS_NAT_NOT_VERIFIED", data.egress_nat_ok),
        ("FAIL_CLOSED_NOT_VERIFIED", data.fail_closed_policy_ok),
        ("IPV6_LEAK_NOT_PROTECTED", data.ipv6_leak_protected),
    )
    for reason, passed in gates:
        if passed is not True:
            return ReadinessDecision(False, reason)
    if not data.observed_egress_ipv4:
        return ReadinessDecision(False, "MISSING_EGRESS_IP_PROOF")
    try:
        observed = ip_address(data.observed_egress_ipv4)
    except ValueError:
        return ReadinessDecision(False, "INVALID_EGRESS_IP_PROOF")
    if observed != public_ip:
        return ReadinessDecision(False, "EGRESS_IP_MISMATCH")
    return ReadinessDecision(True, REASON_READY)


def evaluate_protected_handoff(
    *,
    source_edge: str,
    target: EgressReadiness,
    core_public_ipv4: str,
    legacy_dns_core_fallback_enabled: bool,
    global_domain_multi_edge_conflict: bool,
) -> ReadinessDecision:
    """Additional future Phase 6G gate; does not replace existing safety checks.

    Caller MUST retain 6G lock, live revalidation, DB ownership CAS, port
    invariants, DNS checks and rollback journal. Passing this pure gate grants
    no authorization to mutate DB, host networking or public DNS.
    """
    try:
        if ip_address(source_edge) == ip_address(target.edge_host):
            return ReadinessDecision(False, REASON_SOURCE_EQUALS_TARGET)
        if ip_address(core_public_ipv4) == ip_address(target.edge_host):
            return ReadinessDecision(False, REASON_TARGET_IS_CORE)
    except ValueError:
        return ReadinessDecision(False, "INVALID_HANDOFF_IP")
    if global_domain_multi_edge_conflict:
        return ReadinessDecision(False, REASON_GLOBAL_DOMAIN_CONFLICT)
    # Existing Phase 6G routes DNS to Core during failover. That behavior is
    # incompatible with strict protected/no-Core-public-endpoint mode.
    if legacy_dns_core_fallback_enabled:
        return ReadinessDecision(False, REASON_CORE_FALLBACK_UNSAFE)
    result = evaluate_egress_readiness(target)
    if not result.ready:
        return ReadinessDecision(False, f"{REASON_TARGET_NOT_READY}:{result.reason}")
    return ReadinessDecision(True, REASON_READY)
