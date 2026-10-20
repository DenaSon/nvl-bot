"""Fail-closed, side-effect-free DNS routing plan for retiring a managed host.

Operator-approved Core migration intentionally uses separate control paths.
"""
from dataclasses import dataclass
from typing import Iterable, Optional


@dataclass(frozen=True)
class RelayCandidate:
    host: str
    is_default: bool
    verified_healthy: bool
    is_standby: bool = False


@dataclass(frozen=True)
class DNSDecision:
    action: str  # UNCHANGED, SWITCH, BLOCKED
    target: Optional[str]
    reason: str


def plan_host_retirement_dns(
    disabled_host: str,
    live_dns_ip: Optional[str],
    core_ip: Optional[str],
    remaining: Iterable[RelayCandidate],
) -> DNSDecision:
    """Do not mutate public DNS on an unrelated host failure or select Core."""
    if not disabled_host or not live_dns_ip or not core_ip:
        return DNSDecision("BLOCKED", None, "ROUTE_IDENTITY_UNVERIFIED")
    if live_dns_ip != disabled_host:
        return DNSDecision("UNCHANGED", None, "UNRELATED_HOST")
    if disabled_host == core_ip:
        return DNSDecision("BLOCKED", None, "CORE_ROUTING_REQUIRES_EXPLICIT_ACTION")
    eligible = [
        candidate for candidate in remaining
        if candidate.host
        and candidate.host != disabled_host
        and candidate.host != core_ip
        and candidate.verified_healthy
        and not candidate.is_standby
    ]
    eligible.sort(key=lambda candidate: (not candidate.is_default, candidate.host))
    if not eligible:
        return DNSDecision("BLOCKED", None, "NO_VERIFIED_RELAY")
    return DNSDecision("SWITCH", eligible[0].host, "ROUTED_HOST_RETIRED")
