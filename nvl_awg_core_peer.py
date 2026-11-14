"""NVL-AWG-02: plan safe Core AWG peer additions (no live mutation).

Adding a new Edge MUST NOT restart awg0, wg0, SSH or the NVL bot.
The future commit worker must acquire the shared installer lease and only
apply a fresh, CAS-verified plan with awg set (never wg syncconf).
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import ipaddress

from nvl_awg_new_edge import (
    AWGPlanHold, AWGCoreProfile, allocated_edge_ip, expected_peer_block,
    ipv4, public_key, port,
)


@dataclass(frozen=True)
class AWGCorePeerPlan:
    before_sha256: str
    after_conf: str = field(repr=False)  # contains Core secrets; never log
    edge_tunnel_ip: str
    edge_public_key: str
    edge_host: str
    edge_udp_port: int
    apply_argv: tuple[str, ...]


def plan_core_peer(
    core_conf: str, live_allowed_ips: str, *,
    edge_host: str, edge_udp_port: int, edge_public_key: str,
    registered_ips: tuple[str, ...] = (),
) -> AWGCorePeerPlan:
    """Pure planning. Refuse overlapping peer identities, subnets and markers."""
    core = AWGCoreProfile.parse(core_conf)
    host = ipv4(edge_host, global_address=True)
    key = public_key(edge_public_key)
    port(edge_udp_port)
    raw = core_conf
    if raw.count("[Interface]") != 1:
        raise AWGPlanHold("CORE_AWG_CONFIG_INVALID")
    # Existing registered/public peer addresses and live kernel state are
    # both authoritative. A configured peer missing from the runtime is not
    # cause to reuse its address.
    lines = [line.strip() for line in raw.splitlines()]
    for line in lines:
        if line.startswith("PublicKey"):
            if line.split("=", 1)[-1].strip() == key:
                raise AWGPlanHold("EDGE_PEER_ALREADY_CONFIGURED")
    for row in live_allowed_ips.splitlines():
        fields = row.split()
        if len(fields) != 2:
            raise AWGPlanHold("CORE_LIVE_ALLOWED_IPS_UNVERIFIED")
        if fields[0] == key:
            raise AWGPlanHold("EDGE_PEER_ALREADY_LIVE")
    if "# edge-" + host.replace(".", "-") in lines:
        raise AWGPlanHold("EDGE_HOST_MARKER_EXISTS")
    address = allocated_edge_ip(
        raw, core_tunnel_ip=core.core_tunnel_ip,
        registered_ips=registered_ips, live_allowed_ips=live_allowed_ips,
    )
    updated = raw.rstrip("\n") + "\n" + expected_peer_block(
        host=host, peer_key=key, tunnel_ip=address,
        edge_port=edge_udp_port,
    )
    # Core must be able to contact the new Edge before it has learned endpoint.
    command = (
        "awg", "set", "awg0", "peer", key,
        "allowed-ips", address + "/32",
        "endpoint", host + ":" + str(edge_udp_port),
        "persistent-keepalive", "25",
    )
    return AWGCorePeerPlan(
        before_sha256=hashlib.sha256(raw.encode()).hexdigest(),
        after_conf=updated, edge_tunnel_ip=address,
        edge_public_key=key, edge_host=host,
        edge_udp_port=edge_udp_port, apply_argv=command,
    )


def verify_core_peer_plan(plan: AWGCorePeerPlan, *,
                          current_conf: str,
                          current_live_allowed: str) -> None:
    """Recheck under a lock before any executor writes the root-owned Core config."""
    if hashlib.sha256(current_conf.encode()).hexdigest() != plan.before_sha256:
        raise AWGPlanHold("CORE_AWG_CONFIG_CHANGED")
    expected = plan_core_peer(
        current_conf, current_live_allowed,
        edge_host=plan.edge_host, edge_udp_port=plan.edge_udp_port,
        edge_public_key=plan.edge_public_key,
    )
    if (expected.edge_tunnel_ip != plan.edge_tunnel_ip or
            expected.after_conf != plan.after_conf or
            expected.apply_argv != plan.apply_argv):
        raise AWGPlanHold("CORE_AWG_PEER_PLAN_CHANGED")
