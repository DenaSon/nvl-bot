"""NVL AWG 3.1 new-Edge configuration planner (pure / no network effects).

All Core profile parameters are read from *the running Core interface's
managed config*. The HeaderProtectionKey is a secret: only render into a
0600 SFTP-staged file on the new Edge; never print it or write to SQLite.
No fixed public Edge address is accepted or embedded here.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import ipaddress
import re


class AWGPlanHold(ValueError):
    pass


KEY_RE = re.compile(r"[A-Za-z0-9+/]{43}=\Z")
PROFILE_REQUIRED = (
    "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4",
    "H1", "H2", "H3", "H4", "HeaderProtectionKey",
)
PROFILE_OPTIONAL = (
    "ContentPaddingAddition", "RandomTrailers", "DisableCookies",
    "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime",
    "KeepaliveTimeout", "MaxHandshakeAttempts",
)
ALLOWED_PROFILE = frozenset(PROFILE_REQUIRED + PROFILE_OPTIONAL)


def public_key(value: str) -> str:
    if not isinstance(value, str) or not KEY_RE.fullmatch(value):
        raise AWGPlanHold("AWG_KEY_INVALID")
    try:
        if len(base64.b64decode(value, validate=True)) != 32:
            raise AWGPlanHold("AWG_KEY_INVALID")
    except (ValueError, base64.binascii.Error) as exc:
        raise AWGPlanHold("AWG_KEY_INVALID") from exc
    return value


def ipv4(value: str, *, global_address: bool = False) -> str:
    try:
        addr = ipaddress.IPv4Address(value)
    except (ValueError, ipaddress.AddressValueError, TypeError) as exc:
        raise AWGPlanHold("AWG_IPV4_INVALID") from exc
    if global_address and not addr.is_global:
        raise AWGPlanHold("AWG_PUBLIC_IP_REQUIRED")
    return str(addr)


def port(value: int) -> int:
    if type(value) is not int or not 1 <= value <= 65535:
        raise AWGPlanHold("AWG_PORT_INVALID")
    return value


@dataclass(frozen=True)
class AWGCoreProfile:
    core_tunnel_ip: str
    core_listen_port: int
    mtu: int
    values: tuple[tuple[str, str], ...]

    @classmethod
    def parse(cls, conf: str) -> "AWGCoreProfile":
        if not isinstance(conf, str) or len(conf) > 131072:
            raise AWGPlanHold("AWG_CONFIG_INVALID")
        sections: list[tuple[str, dict[str, str]]] = []
        current = None
        for source in conf.splitlines():
            line = source.strip()
            if not line or line.startswith(("#", ";")):
                continue
            if line in ("[Interface]", "[Peer]"):
                current = {}
                sections.append((line, current))
                continue
            if current is None or "=" not in line:
                raise AWGPlanHold("AWG_CONFIG_INVALID")
            name, value = (v.strip() for v in line.split("=", 1))
            if not name or not value or name in current or "\x00" in value:
                raise AWGPlanHold("AWG_CONFIG_DUPLICATE_OR_INVALID")
            current[name] = value
        if not sections or sections[0][0] != "[Interface]" or sum(
            1 for name, _ in sections if name == "[Interface]"
        ) != 1:
            raise AWGPlanHold("AWG_CONFIG_INTERFACE_INVALID")
        opts = sections[0][1]
        for req in PROFILE_REQUIRED:
            if req not in opts:
                raise AWGPlanHold("AWG_PROFILE_REQUIRED_MISSING")
        header = public_key(opts["HeaderProtectionKey"])
        if not header:
            raise AWGPlanHold("AWG_HPK_INVALID")
        for index in range(1, 5):
            try:
                s = int(opts[f"S{index}"])
            except ValueError as exc:
                raise AWGPlanHold("AWG_PADDING_INVALID") from exc
            if not 12 <= s <= 512 or opts[f"H{index}"] != str(index):
                raise AWGPlanHold("AWG_PADDING_OR_HEADER_UNSUPPORTED")
        try:
            jc = int(opts["Jc"])
            jmin, jmax = int(opts["Jmin"]), int(opts["Jmax"])
            mtu = int(opts["MTU"])
            listener = int(opts["ListenPort"])
        except (ValueError, KeyError) as exc:
            raise AWGPlanHold("AWG_INTERFACE_INCOMPLETE") from exc
        if not (0 <= jc <= 50 and 0 <= jmin <= jmax <= 65535
                and 1120 <= mtu <= 1420):
            raise AWGPlanHold("AWG_PROFILE_OUT_OF_RANGE")
        port(listener)
        address = opts.get("Address", "").split(",", 1)[0].strip()
        if not address.endswith("/32"):
            raise AWGPlanHold("AWG_CORE_ADDRESS_UNSUPPORTED")
        core = ipv4(address[:-3])
        return cls(
            core_tunnel_ip=core,
            core_listen_port=listener,
            mtu=mtu,
            values=tuple((key, opts[key]) for key in
                         PROFILE_REQUIRED + PROFILE_OPTIONAL if key in opts),
        )


def allocated_edge_ip(
    core_conf: str, *, core_tunnel_ip: str,
    pool: str | None = None, registered_ips: tuple[str, ...] = (),
    live_allowed_ips: str = "",
) -> str:
    """Never reuse Core /32 or any config, runtime or registered address."""
    network = ipaddress.IPv4Network(\n        pool or str(ipaddress.IPv4Network(core_tunnel_ip + "/24", strict=False)),\n        strict=True,\n    )
    core = ipaddress.IPv4Address(ipv4(core_tunnel_ip))
    if core not in network:
        raise AWGPlanHold("AWG_CORE_OUTSIDE_POOL")
    used = {core}
    for raw in registered_ips:
        addr = ipaddress.IPv4Address(ipv4(raw))
        used.add(addr)
    for line in core_conf.splitlines():
        match = re.match(r"\s*AllowedIPs\s*=\s*(.+)", line)
        if not match:
            continue
        for token in match.group(1).split(","):
            try:
                peer_net = ipaddress.ip_network(token.strip(), strict=True)
            except ValueError as exc:
                raise AWGPlanHold("AWG_CONFIG_ALLOWED_IPS_INVALID") from exc
            if isinstance(peer_net, ipaddress.IPv4Network):
                used.update(a for a in network.hosts() if a in peer_net)
    for row in live_allowed_ips.splitlines():
        parts = row.split()
        if len(parts) != 2:
            raise AWGPlanHold("AWG_LIVE_ALLOWED_IPS_INVALID")
        public_key(parts[0])
        for raw in parts[1].split(","):
            try:
                net = ipaddress.ip_network(raw, strict=True)
            except ValueError as exc:
                raise AWGPlanHold("AWG_LIVE_ALLOWED_IPS_INVALID") from exc
            if isinstance(net, ipaddress.IPv4Network):
                used.update(a for a in network.hosts() if a in net)
    for address in network.hosts():
        if address not in used:
            return str(address)
    raise AWGPlanHold("AWG_ADDRESS_POOL_EXHAUSTED")


def render_new_edge_conf(
    profile: AWGCoreProfile, *,
    edge_private_key: str, core_public_key: str,
    core_public_ip: str, edge_tunnel_ip: str, edge_port: int,
) -> str:
    public_key(edge_private_key)  # same Base64 key format, secret value
    pubkey = public_key(core_public_key)
    endpoint = ipv4(core_public_ip, global_address=True)
    edge = ipv4(edge_tunnel_ip)
    if edge == profile.core_tunnel_ip:
        raise AWGPlanHold("AWG_ADDRESS_COLLISION")
    port(edge_port)
    core = profile.core_tunnel_ip
    fields = "\n".join(f"{k} = {v}" for k, v in profile.values)
    return (
        "[Interface]\n"
        f"Address = {edge}/32\n"
        f"ListenPort = {edge_port}\n"
        f"MTU = {profile.mtu}\n"
        f"PrivateKey = {edge_private_key}\n"
        f"{fields}\n\n"
        "[Peer]\n"
        f"PublicKey = {pubkey}\n"
        f"Endpoint = {endpoint}:{profile.core_listen_port}\n"
        f"AllowedIPs = {core}/32\n"
        "PersistentKeepalive = 25\n"
    )


def expected_peer_block(*, host: str, peer_key: str, tunnel_ip: str, edge_port: int) -> str:
    ip = ipv4(host, global_address=True)
    public_key(peer_key)
    tunnel = ipv4(tunnel_ip)
    port(edge_port)
    return (
        f"\n[Peer]\n# edge-{ip.replace('.', '-')}\n"
        f"PublicKey = {peer_key}\n"
        f"AllowedIPs = {tunnel}/32\n"
        f"Endpoint = {ip}:{edge_port}\n"
        "PersistentKeepalive = 25\n"
    )
