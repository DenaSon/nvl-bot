"""Stage 3A: render a deliberately disabled, localhost-only SSH Egress pilot.

No database, iptables, routing, systemd or production SSH mutation is performed.
Generated files are proposals for a reviewed, explicit deployment only.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath


_SAFE_NAME = re.compile(r"[a-z][a-z0-9_-]{0,62}\Z", re.ASCII)
_SAFE_USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z", re.ASCII)


@dataclass(frozen=True)
class PilotSpec:
    username: str
    namespace: str
    wg_interface: str
    internal_ip: str
    expected_edge_ip: str
    core_ip: str
    ssh_port: int = 22284
    host_key: str = "/var/lib/nvl-egress-stg1-sshd/host_ed25519"
    proxy_binary: str = "/usr/lib/systemd/systemd-socket-proxyd"

    def __post_init__(self) -> None:
        if not _SAFE_USER.fullmatch(self.username) or self.username == "root":
            raise ValueError("unsafe or privileged pilot username")
        for value in (self.namespace, self.wg_interface):
            if not _SAFE_NAME.fullmatch(value):
                raise ValueError("unsafe namespace/interface name")
        inner = ipaddress.ip_address(self.internal_ip)
        edge = ipaddress.ip_address(self.expected_edge_ip)
        core = ipaddress.ip_address(self.core_ip)
        if any(a.version != 4 for a in (inner, edge, core)):
            raise ValueError("Stage 3A only supports IPv4")
        if not inner.is_private or inner.is_loopback:
            raise ValueError("internal address must be private IPv4")
        if not edge.is_global or not core.is_global:
            raise ValueError("Core and Edge must be global IPv4 addresses")
        if edge == core or edge == inner or core == inner:
            raise ValueError("Core, Edge, and namespace addresses must differ")
        if not 1024 <= self.ssh_port <= 65535:
            raise ValueError("pilot port must be unprivileged")
        for path in (self.host_key, self.proxy_binary):
            p = PurePosixPath(path)
            if not p.is_absolute() or ".." in p.parts or any(ch.isspace() for ch in path):
                raise ValueError("unsafe absolute filesystem path")


@dataclass(frozen=True)
class RouteEvidence:
    """Read-only observations supplied by the deployment preflight.

    This is a guard, not proof that remote connectivity or NAT will work.
    """
    ipv4_default_routes: str
    ipv6_default_routes: str
    wg_interfaces: str
    observed_egress_ip: str


def route_blockers(spec: PilotSpec, evidence: RouteEvidence) -> list[str]:
    """Fail closed on ambiguity, non-WG default routes, or wrong Egress IP."""
    errors: list[str] = []
    lines = [s.split() for s in evidence.ipv4_default_routes.splitlines() if s.strip()]
    if len(lines) != 1 or lines[0][:3] != ["default", "dev", spec.wg_interface]:
        errors.append("IPV4_DEFAULT_NOT_EXCLUSIVELY_WIREGUARD")
    elif "via" in lines[0] or "nexthop" in lines[0]:
        errors.append("IPV4_DEFAULT_HAS_UNEXPECTED_GATEWAY")
    if evidence.ipv6_default_routes.strip():
        errors.append("UNREVIEWED_IPV6_DEFAULT_ROUTE")
    if spec.wg_interface not in evidence.wg_interfaces.split():
        errors.append("WIREGUARD_INTERFACE_MISSING")
    if evidence.observed_egress_ip.strip() != spec.expected_edge_ip:
        errors.append("EGRESS_IP_MISMATCH")
    return errors


def render_manifests(spec: PilotSpec) -> dict[str, str]:
    """Generate files without writing or enabling them.

    The socket is intentionally bound to loopback; public ingress is deferred.
    """
    config_path = "/etc/nvl/egress-pilot/sshd_config"
    sshd = f"""# Generated Stage 3A pilot; isolated from /etc/ssh/sshd_config
AddressFamily inet
ListenAddress {spec.internal_ip}
Port {spec.ssh_port}
HostKey {spec.host_key}
PidFile /run/nvl-egress-pilot-sshd.pid
AllowUsers {spec.username}
PermitRootLogin no
UsePAM yes
AuthenticationMethods password
PubkeyAuthentication no
PasswordAuthentication yes
PermitEmptyPasswords no
KbdInteractiveAuthentication no
MaxAuthTries 3
LoginGraceTime 15
MaxStartups 10:30:30
PermitTTY no
MaxSessions 0
AllowTcpForwarding local
PermitOpen any
GatewayPorts no
X11Forwarding no
AllowAgentForwarding no
AllowStreamLocalForwarding no
PermitTunnel no
PermitUserRC no
PermitUserEnvironment no
LogLevel VERBOSE
"""
    daemon = f"""[Unit]
Description=NVL Stage 3A isolated SSH Egress pilot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=/usr/sbin/sshd -t -f {config_path}
ExecStart=/usr/sbin/ip netns exec {spec.namespace} /usr/sbin/sshd -D -e -f {config_path}
Restart=on-failure
RestartSec=5

# Not enabled; explicit start required.
"""
    socket = f"""[Unit]
Description=NVL Stage 3A local-only pilot ingress

[Socket]
ListenStream=127.0.0.1:{spec.ssh_port}
Accept=no
Service=nvl-egress-pilot-proxy.service

# Not enabled; explicit start required.
"""
    proxy = f"""[Unit]
Description=NVL Stage 3A loopback-to-namespace SSH proxy
Requires=nvl-egress-pilot-sshd.service
After=nvl-egress-pilot-sshd.service

[Service]
Type=simple
ExecStart={spec.proxy_binary} {spec.internal_ip}:{spec.ssh_port}
DynamicUser=yes
NoNewPrivileges=yes
PrivateTmp=yes

# Socket-activated service only.
"""
    return {
        config_path: sshd,
        "/etc/systemd/system/nvl-egress-pilot-sshd.service": daemon,
        "/etc/systemd/system/nvl-egress-pilot-proxy.socket": socket,
        "/etc/systemd/system/nvl-egress-pilot-proxy.service": proxy,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Print, but never install, Stage 3A pilot manifests")
    parser.add_argument("--username", required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--wg-interface", required=True)
    parser.add_argument("--internal-ip", required=True)
    parser.add_argument("--expected-edge-ip", required=True)
    parser.add_argument("--core-ip", required=True)
    parser.add_argument("--ssh-port", type=int, default=22284)
    args = parser.parse_args()
    spec = PilotSpec(**vars(args))
    print(json.dumps({"deployment": "NOT_APPLIED", "public_listener": False,
                      "observed_egress_verified": False,
                      "files": render_manifests(spec)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
