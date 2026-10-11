#!/usr/bin/env python3
"""D1-B2: stage-only, per-Edge WireGuard egress provisioner.

No command in this CLI changes routes, iptables, netns, interfaces, DNS, SQLite
or systemd runtime. It generates root-only files for review. The generated
up/down scripts are NOT executed here; they remain an explicit future gate.
"""
from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

IDENTIFIER = re.compile(r"^[a-z][a-z0-9]{0,6}$")
DEVICE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$")
INGRESS_NET = ipaddress.ip_network("10.77.0.0/24")
POC_NETS = (ipaddress.ip_network("10.78.98.0/30"),
            ipaddress.ip_network("10.78.99.0/30"))
IFACE_PREFIX = "wg-nvl-"


class ProvisionError(ValueError):
    pass


@dataclass(frozen=True)
class EgressSpec:
    edge_id: str
    edge_public_ipv4: str
    core_public_ipv4: str
    tunnel_network: str
    veth_network: str
    edge_uplink: str
    edge_listen_port: int = 51832
    route_table: int = 1780
    mode: str = "relay"

    @classmethod
    def from_json(cls, raw: dict) -> "EgressSpec":
        if not isinstance(raw, dict):
            raise ProvisionError("spec must be a JSON object")
        required = set(cls.__dataclass_fields__)
        unknown = set(raw) - required
        if unknown:
            raise ProvisionError(f"unknown spec keys: {sorted(unknown)}")
        try:
            spec = cls(**raw)
        except TypeError as exc:
            raise ProvisionError(str(exc)) from exc
        spec.validate()
        return spec

    def validate(self) -> None:
        if not isinstance(self.edge_id, str) or not IDENTIFIER.fullmatch(self.edge_id):
            raise ProvisionError("edge_id must be 1-7 lowercase ASCII letters/digits starting with a letter")
        if self.mode != "relay":
            raise ProvisionError("Only Core-terminated SSH / relay mode is supported")
        if not isinstance(self.edge_uplink, str) or not DEVICE.fullmatch(self.edge_uplink):
            raise ProvisionError("invalid edge_uplink device name")
        if type(self.edge_listen_port) is not int or not (1024 <= self.edge_listen_port <= 65535):
            raise ProvisionError("edge_listen_port must be a non-privileged UDP port")
        if type(self.route_table) is not int or not (1000 <= self.route_table <= 32765):
            raise ProvisionError("route_table out of allowed range")
        if self.route_table in {7700}:  # intentionally avoid future policy collisions
            raise ProvisionError("reserved route_table")
        for attr in ("edge_public_ipv4", "core_public_ipv4"):
            try:
                ip = ipaddress.IPv4Address(getattr(self, attr))
            except (ipaddress.AddressValueError, TypeError) as exc:
                raise ProvisionError(f"invalid {attr}") from exc
            if not ip.is_global:
                raise ProvisionError(f"{attr} must be a public IPv4")
        if self.edge_public_ipv4 == self.core_public_ipv4:
            raise ProvisionError("Core and Edge public IP must differ")
        tn = self.tunnel
        vn = self.veth
        if tn.prefixlen != 30 or vn.prefixlen != 30:
            raise ProvisionError("both tunnel_network and veth_network must be /30")
        if tn.overlaps(vn) or any(
            n.overlaps(protected) for n in (tn, vn) for protected in (INGRESS_NET, *POC_NETS)
        ):
            raise ProvisionError("networks collide with each other, ingress wg0 or POC networks")

    @property
    def tunnel(self):
        return self._network(self.tunnel_network)

    @property
    def veth(self):
        return self._network(self.veth_network)

    @staticmethod
    def _network(value):
        try:
            result = ipaddress.ip_network(value, strict=True)
        except (ValueError, TypeError) as exc:
            raise ProvisionError(f"invalid canonical network {value!r}") from exc
        if not isinstance(result, ipaddress.IPv4Network):
            raise ProvisionError("IPv4-only provisioning")
        return result

    @property
    def iface(self):
        return IFACE_PREFIX + self.edge_id

    @property
    def namespace(self):
        return "nvl-egress-" + self.edge_id

    @property
    def veth_root(self):
        return "vnh-" + self.edge_id

    @property
    def veth_ns(self):
        return "vnn-" + self.edge_id

    @property
    def edge_tunnel_ip(self):
        return str(self.tunnel.network_address + 1)

    @property
    def core_tunnel_ip(self):
        return str(self.tunnel.network_address + 2)

    @property
    def root_veth_ip(self):
        return str(self.veth.network_address + 1)

    @property
    def ns_veth_ip(self):
        return str(self.veth.network_address + 2)


def validated_key(value: str, label: str) -> str:
    if not isinstance(value, str):
        raise ProvisionError(f"{label}: not a string")
    try:
        decoded = base64.b64decode(value.strip(), validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ProvisionError(f"{label}: invalid WireGuard key") from exc
    if len(decoded) != 32 or len(value.strip()) != 44:
        raise ProvisionError(f"{label}: WireGuard key must decode to 32 bytes")
    return value.strip()


def load_spec(path: Path) -> EgressSpec:
    return EgressSpec.from_json(json.loads(path.read_text(encoding="utf-8")))


def plan(spec: EgressSpec, role: str) -> dict:
    spec.validate()
    return {
        "mode": "STAGE_ONLY_NO_NETWORK_MUTATION",
        "role": role,
        "edge_id": spec.edge_id,
        "ifname": spec.iface,
        "namespace": spec.namespace if role == "core" else None,
        "edge_public_ipv4": spec.edge_public_ipv4,
        "core_public_ipv4": spec.core_public_ipv4,
        "wg_tunnel": spec.tunnel_network,
        "veth_network": spec.veth_network if role == "core" else None,
        "edge_udp_port": spec.edge_listen_port,
        "uplink": spec.edge_uplink if role == "edge" else None,
        "future_route_table_not_installed": spec.route_table,
        "user_routes_changed": False,
        "wg0_changed": False,
    }


def _run_read_only(*cmd):
    p = subprocess.run(cmd, check=True, text=True, capture_output=True, timeout=8)
    return p.stdout


def preflight(spec: EgressSpec, role: str) -> dict:
    """Read-only conflict screen; not sufficient to approve activation."""
    conflicts = []
    needed = ("ip", "wg", "iptables", "sysctl", "ss")
    for name in needed:
        if shutil.which(name) is None:
            conflicts.append("MISSING_TOOL:" + name)
    if conflicts:
        return {"ok": False, "issues": conflicts, "role": role}

    ifaces = (spec.iface, spec.veth_root) if role == "core" else (spec.iface,)
    for iface in ifaces:
        found = subprocess.run(
            ["ip", "link", "show", "dev", iface], capture_output=True, timeout=8
        )
        if found.returncode == 0:
            conflicts.append(f"INTERFACE_EXISTS:{iface}")

    if role == "core":
        existing = _run_read_only("ip", "netns", "list")
        if any(line.split()[0] == spec.namespace for line in existing.splitlines() if line.strip()):
            conflicts.append("NAMESPACE_EXISTS")
        routes = json.loads(_run_read_only("ip", "-j", "-4", "route", "show", "table", "all"))
        for r in routes:
            dst = r.get("dst")
            if not dst or dst == "default":
                continue
            try:
                existing_net = ipaddress.ip_network(dst, strict=False)
            except ValueError:
                continue
            if existing_net.overlaps(spec.tunnel) or existing_net.overlaps(spec.veth):
                conflicts.append(f"ROUTE_SUBNET_COLLISION:{dst}")
        # Use the already retrieved all-tables dump: querying a nonexistent
        # table directly often returns a nonzero error on modern iproute2.
        if any(str(r.get("table", "main")) == str(spec.route_table) for r in routes):
            conflicts.append("ROUTE_TABLE_OCCUPIED")
    else:
        if _run_read_only("sysctl", "-n", "net.ipv4.ip_forward").strip() != "1":
            conflicts.append("EDGE_IP_FORWARD_DISABLED")
        sockets = _run_read_only("ss", "-H", "-lun")
        if re.search(rf":{spec.edge_listen_port}(?=\s|$)", sockets):
            conflicts.append("UDP_PORT_BUSY")
        route = _run_read_only("ip", "-o", "-4", "route", "get", "1.1.1.1")
        if not re.search(r"\bdev " + re.escape(spec.edge_uplink) + r"\b", route):
            conflicts.append("UNEXPECTED_EDGE_UPLINK")
    return {"ok": not conflicts, "issues": sorted(set(conflicts)), "role": role}


def wireguard_config(spec: EgressSpec, role: str, private: str, peer: str) -> str:
    validated_key(private, "private")
    validated_key(peer, "peer_public")
    if role == "core":
        # AllowedIPs=0/0 is confined to the NEW interface moved into a netns.
        return (
            f"[Interface]\nPrivateKey = {private}\n\n"
            f"[Peer]\nPublicKey = {peer}\nAllowedIPs = 0.0.0.0/0\n"
            f"Endpoint = {spec.edge_public_ipv4}:{spec.edge_listen_port}\n"
            "PersistentKeepalive = 25\n"
        )
    return (
        f"[Interface]\nPrivateKey = {private}\nListenPort = {spec.edge_listen_port}\n\n"
        f"[Peer]\nPublicKey = {peer}\nAllowedIPs = {spec.core_tunnel_ip}/32\n"
    )


def _common_prefix(spec: EgressSpec, stage: Path):
    q = shlex.quote
    return (
        "#!/usr/bin/env bash\nset -Eeuo pipefail\n"
        "umask 077\n"
        f"IFACE={q(spec.iface)}\n"
        f"WGCONF={q(str(stage / 'wg.conf'))}\n"
        f"TAG={q('nvl-egress-' + spec.edge_id)}\n"
    )


def edge_up_script(spec: EgressSpec, stage: Path) -> str:
    return _common_prefix(spec, stage) + f"""UPLINK={shlex.quote(spec.edge_uplink)}
CORE_WG={spec.core_tunnel_ip}
EDGE_WG={spec.edge_tunnel_ip}
PORT={spec.edge_listen_port}

if ip link show dev "$IFACE" >/dev/null 2>&1; then
  echo "STOP: interface collision" >&2; exit 1
fi
test "$(sysctl -n net.ipv4.ip_forward)" = 1 || {{ echo "STOP: Edge forwarding disabled" >&2; exit 1; }}
ip -o -4 route get 1.1.1.1 | grep -Eq " dev $UPLINK( |$)" || {{
  echo "STOP: unexpected Edge uplink" >&2; exit 1;
}}
if ss -H -lun | grep -Eq ":$PORT([[:space:]]|$)"; then
  echo "STOP: WireGuard UDP port occupied" >&2; exit 1
fi
cleanup() {{
  iptables -w -t nat -D POSTROUTING -s "$CORE_WG/32" -o "$UPLINK" -m comment --comment "$TAG" -j MASQUERADE 2>/dev/null || true
  iptables -w -D FORWARD -i "$IFACE" -o "$UPLINK" -s "$CORE_WG/32" -m comment --comment "$TAG" -j ACCEPT 2>/dev/null || true
  iptables -w -D FORWARD -i "$UPLINK" -o "$IFACE" -d "$CORE_WG/32" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "$TAG" -j ACCEPT 2>/dev/null || true
  iptables -w -D INPUT -i "$UPLINK" -p udp --dport "$PORT" -m comment --comment "$TAG" -j ACCEPT 2>/dev/null || true
  ip link del "$IFACE" 2>/dev/null || true
}}
trap cleanup ERR
ip link add dev "$IFACE" type wireguard
wg setconf "$IFACE" "$WGCONF"
ip -4 addr add "$EDGE_WG/30" dev "$IFACE"
ip link set dev "$IFACE" up
iptables -w -A INPUT -i "$UPLINK" -p udp --dport "$PORT" -m comment --comment "$TAG" -j ACCEPT
iptables -w -A FORWARD -i "$IFACE" -o "$UPLINK" -s "$CORE_WG/32" -m comment --comment "$TAG" -j ACCEPT
iptables -w -A FORWARD -i "$UPLINK" -o "$IFACE" -d "$CORE_WG/32" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "$TAG" -j ACCEPT
iptables -w -t nat -A POSTROUTING -s "$CORE_WG/32" -o "$UPLINK" -m comment --comment "$TAG" -j MASQUERADE
trap - ERR
echo "EDGE SHADOW EGRESS UP (no user route changed)"
"""


def edge_down_script(spec: EgressSpec, stage: Path) -> str:
    return _common_prefix(spec, stage) + f"""UPLINK={shlex.quote(spec.edge_uplink)}
CORE_WG={spec.core_tunnel_ip}
PORT={spec.edge_listen_port}
iptables -w -t nat -D POSTROUTING -s "$CORE_WG/32" -o "$UPLINK" -m comment --comment "$TAG" -j MASQUERADE 2>/dev/null || true
iptables -w -D FORWARD -i "$IFACE" -o "$UPLINK" -s "$CORE_WG/32" -m comment --comment "$TAG" -j ACCEPT 2>/dev/null || true
iptables -w -D FORWARD -i "$UPLINK" -o "$IFACE" -d "$CORE_WG/32" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "$TAG" -j ACCEPT 2>/dev/null || true
iptables -w -D INPUT -i "$UPLINK" -p udp --dport "$PORT" -m comment --comment "$TAG" -j ACCEPT 2>/dev/null || true
ip link del "$IFACE" 2>/dev/null || true
"""


def core_up_script(spec: EgressSpec, stage: Path) -> str:
    return _common_prefix(spec, stage) + f"""NS={shlex.quote(spec.namespace)}
VH={shlex.quote(spec.veth_root)}
VN={shlex.quote(spec.veth_ns)}
CORE_WG={spec.core_tunnel_ip}
HOST_VETH={spec.root_veth_ip}
NS_VETH={spec.ns_veth_ip}

for d in "$IFACE" "$VH"; do
  if ip link show dev "$d" >/dev/null 2>&1; then
    echo "STOP: interface collision $d" >&2; exit 1
  fi
done
if ip netns list | grep -Eq "^$NS( |$)"; then
  echo "STOP: namespace collision" >&2; exit 1
fi
cleanup() {{
  ip link del "$VH" 2>/dev/null || true
  ip netns del "$NS" 2>/dev/null || true
  ip link del "$IFACE" 2>/dev/null || true
}}
trap cleanup ERR
ip netns add "$NS"
ip link add dev "$IFACE" type wireguard
# Create WG in root namespace to keep its UDP socket on Core's existing uplink.
wg setconf "$IFACE" "$WGCONF"
ip link set "$IFACE" netns "$NS"
ip netns exec "$NS" ip -4 addr add "$CORE_WG/30" dev "$IFACE"
ip netns exec "$NS" ip link set dev "$IFACE" up
ip netns exec "$NS" ip route add default dev "$IFACE"

ip link add "$VH" type veth peer name "$VN"
ip link set "$VN" netns "$NS"
ip -4 addr add "$HOST_VETH/30" dev "$VH"
ip link set "$VH" up
ip netns exec "$NS" ip -4 addr add "$NS_VETH/30" dev "$VN"
ip netns exec "$NS" ip link set "$VN" up
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" sysctl -q -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec "$NS" iptables -w -A FORWARD -i "$VN" -o "$IFACE" -j ACCEPT
ip netns exec "$NS" iptables -w -A FORWARD -i "$IFACE" -o "$VN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# Packets from the Core-side veth use the HOST's 10.x address as source.
# Match that source, not the namespace-side veth IP.
ip netns exec "$NS" iptables -w -t nat -A POSTROUTING -s "{spec.root_veth_ip}/32" -o "$IFACE" -j MASQUERADE
trap - ERR
echo "CORE SHADOW EGRESS UP (no UID rule, no host default route)"
"""


def core_down_script(spec: EgressSpec, stage: Path) -> str:
    return _common_prefix(spec, stage) + f"""NS={shlex.quote(spec.namespace)}
VH={shlex.quote(spec.veth_root)}
ip link del "$VH" 2>/dev/null || true
ip netns del "$NS" 2>/dev/null || true
ip link del "$IFACE" 2>/dev/null || true
"""


def service_unit(spec: EgressSpec, role: str, stage: Path) -> str:
    return (
        "[Unit]\n"
        f"Description=NVL shadow Egress {spec.edge_id} ({role})\n"
        "Wants=network-online.target\nAfter=network-online.target\n"
        "ConditionPathExists=" + str(stage / "wg.conf") + "\n\n"
        "[Service]\nType=oneshot\nRemainAfterExit=yes\n"
        "ExecStart=/bin/bash " + str(stage / "up.sh") + "\n"
        "ExecStop=/bin/bash " + str(stage / "down.sh") + "\n"
        "TimeoutStartSec=35\nTimeoutStopSec=20\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )


def stage_files(spec: EgressSpec, role: str, dst: Path, private: str, peer: str, *, owner_token: str | None = None) -> None:
    if role not in ("core", "edge"):
        raise ProvisionError("invalid role")
    if not dst.is_absolute() or ".." in dst.parts:
        raise ProvisionError("stage directory must be canonical absolute path")
    if dst.exists() or dst.is_symlink():
        raise ProvisionError("refusing to overwrite existing stage directory")
    if not dst.parent.is_dir() or dst.parent.is_symlink():
        raise ProvisionError("stage parent must already exist and not be a symlink")
    if dst.parent.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ProvisionError("stage parent must not be writable by other users")
    spec.validate()
    # Creation is transactional: no half-staged files at target path.
    temp = Path(tempfile.mkdtemp(prefix=".nvl-egress-", dir=dst.parent))
    try:
        content = {
            "wg.conf": (wireguard_config(spec, role, private, peer), 0o600),
            "up.sh": ((core_up_script if role == "core" else edge_up_script)(spec, dst), 0o700),
            "down.sh": ((core_down_script if role == "core" else edge_down_script)(spec, dst), 0o700),
            f"nvl-egress-{spec.edge_id}.service": (service_unit(spec, role, dst), 0o600),
            "manifest.json": (json.dumps({
                "config": asdict(spec), "role": role,
                "stage_only": True, "user_routes_installed": False,\n                "owner_token": owner_token,
                "core_public_ipv4": spec.core_public_ipv4,
                "edge_public_ipv4": spec.edge_public_ipv4,
            }, indent=2) + "\n", 0o600),
        }
        for name, (text, mode) in content.items():
            p = temp / name
            with p.open("x", encoding="utf-8") as fh:
                fh.write(text)
            p.chmod(mode)
        os.rename(temp, dst)
    finally:
        if temp.exists():
            shutil.rmtree(temp)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "preflight", "stage"))
    parser.add_argument("--role", required=True, choices=("core", "edge"))
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--stage-dir", type=Path)
    parser.add_argument("--private-key-file", type=Path)
    parser.add_argument("--peer-public-key")
    args = parser.parse_args(argv)
    try:
        spec = load_spec(args.spec)
        if args.command == "plan":
            print(json.dumps(plan(spec, args.role), indent=2))
        elif args.command == "preflight":
            result = preflight(spec, args.role)
            print(json.dumps(result, indent=2))
            return 0 if result["ok"] else 3
        else:
            if not args.stage_dir or not args.private_key_file or not args.peer_public_key:
                raise ProvisionError("stage requires --stage-dir --private-key-file --peer-public-key")
            if args.private_key_file.is_symlink():
                raise ProvisionError("private key file must not be a symlink")
            if args.private_key_file.stat().st_mode & 0o077:
                raise ProvisionError("private key file must be owner-only")
            private = validated_key(args.private_key_file.read_text().strip(), "private")
            peer = validated_key(args.peer_public_key, "peer_public")
            stage_files(spec, args.role, args.stage_dir, private, peer)
            print(f"STAGED_ONLY={args.stage_dir}")
            print("NO NETWORK/SYSTEMD/DATABASE/DNS CHANGES. DO NOT ENABLE UNIT YET.")
    except (ProvisionError, OSError, json.JSONDecodeError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
