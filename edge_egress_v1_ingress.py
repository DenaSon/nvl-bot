"""H: resolve *actual* SSH ingress Edge for a protected Core SSH session.

SSH arrives at the Core over the existing wg0 (e.g. 10.77.0.8 from Miami).
Only PAM_RHOST from sshd's PAM account phase is considered the SSH transport
peer; never dns_current_ip, host_pool.is_default, ssh_accounts.host or
client-supplied SSH environment. A root-only Edge->wg0 source+public-key
registry is crossed with live wg0 AllowedIPs and existing protected UID
runtime identity. Unknown, conflicting or unverifiable ingress => DENY.

V1 explicitly pins *one UID to one Edge*. An SSH connection from another
Edge is refused; changing default DNS/relay does not rewrite running sessions.
Session migration/drain belongs to J. No PAM installer or network mutation.
"""
from __future__ import annotations

from dataclasses import dataclass
import base64
import binascii
import ipaddress
import json
from pathlib import Path
import re
import subprocess

from edge_egress_v1_admission import _trusted_bytes, _trusted_directory
from edge_egress_uid_runtime_store import RuntimeBinding

REGISTRY = Path("/etc/nvl-egress/v1-ingress-peers.json")
NET = ipaddress.IPv4Network("10.77.0.0/24")
EDGE_ID = re.compile(r"^[a-z][a-z0-9_-]{1,23}$")


class IngressHold(ValueError):
    pass


@dataclass(frozen=True)
class IngressPeer:
    edge_id: str
    edge_ipv4: str
    ingress_ipv4: str
    wg_public_key: str


def _ip(value: object) -> ipaddress.IPv4Address:
    if not isinstance(value, str):
        raise IngressHold("INVALID_IPV4")
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as exc:
        raise IngressHold("INVALID_IPV4") from exc
    if not isinstance(parsed, ipaddress.IPv4Address) or str(parsed) != value:
        raise IngressHold("NOT_CANONICAL_IPV4")
    return parsed


def _key(value: object) -> str:
    if not isinstance(value, str) or len(value) != 44:
        raise IngressHold("INVALID_WG_KEY")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise IngressHold("INVALID_WG_KEY") from exc
    if len(raw) != 32 or base64.b64encode(raw).decode() != value:
        raise IngressHold("INVALID_WG_KEY")
    return value


def parse_registry(data: bytes) -> tuple[IngressPeer, ...]:
    if not isinstance(data, bytes) or len(data) > 65536:
        raise IngressHold("INVALID_REGISTRY_DATA")
    try:
        obj = json.loads(data)
    except (ValueError, UnicodeError) as exc:
        raise IngressHold("INVALID_REGISTRY_JSON") from exc
    if not isinstance(obj, dict) or set(obj) != {"version", "peers"}:
        raise IngressHold("INVALID_REGISTRY_SCHEMA")
    if type(obj["version"]) is not int or obj["version"] != 1:
        raise IngressHold("UNSUPPORTED_REGISTRY_VERSION")
    peers = obj["peers"]
    if not isinstance(peers, list) or len(peers) > 254:
        raise IngressHold("INVALID_REGISTRY_PEERS")
    seen_edge, seen_ip, seen_src, seen_keys = set(), set(), set(), set()
    result = []
    for item in peers:
        if not isinstance(item, dict) or set(item) != {
            "edge_id", "edge_ipv4", "ingress_ipv4", "wg_public_key"
        }:
            raise IngressHold("INVALID_PEER_ENTRY")
        edge = item["edge_id"]
        if not isinstance(edge, str) or not EDGE_ID.fullmatch(edge):
            raise IngressHold("INVALID_EDGE_ID")
        ip, src = _ip(item["edge_ipv4"]), _ip(item["ingress_ipv4"])
        key = _key(item["wg_public_key"])
        if (src not in NET or src in (NET.network_address, NET.broadcast_address)
                or src == ipaddress.IPv4Address("10.77.0.1")):
            raise IngressHold("INVALID_INGRESS_SOURCE")
        if (edge in seen_edge or str(ip) in seen_ip or str(src) in seen_src
                or key in seen_keys):
            raise IngressHold("DUPLICATE_INGRESS_IDENTITY")
        seen_edge.add(edge)
        seen_ip.add(str(ip))
        seen_src.add(str(src))
        seen_keys.add(key)
        result.append(IngressPeer(edge, str(ip), str(src), key))
    return tuple(result)


def load_registry(path: Path = REGISTRY) -> tuple[IngressPeer, ...]:
    """Fixed root-owned file for PAM; no SSH or user-controlled path."""
    if path != REGISTRY:
        raise IngressHold("REGISTRY_PATH_NOT_FIXED")
    try:
        _trusted_directory(path.parent)
        content = _trusted_bytes(path, 65536)
        return parse_registry(content)
    except (OSError, ValueError) as exc:
        raise IngressHold("REGISTRY_UNAVAILABLE_OR_UNTRUSTED") from exc


def _networks(raw: str) -> dict[str, tuple[ipaddress._BaseNetwork, ...]]:
    """Parse exactly the output of: wg show wg0 allowed-ips.

    Fail on ambiguous/duplicate lines. No 'all traffic' wildcard may prove a
    peer owns an ingress address; only its own exact /32 can do that.
    """
    if not isinstance(raw, str) or len(raw) > 131072:
        raise IngressHold("WG_PEER_INVENTORY_INVALID")
    result = {}
    for line in raw.splitlines():
        tokens = line.split(None, 1)
        if len(tokens) != 2 or tokens[0] in result:
            raise IngressHold("WG_PEER_INVENTORY_AMBIGUOUS")
        key = _key(tokens[0])
        networks = []
        for item in tokens[1].split(","):
            try:
                net = ipaddress.ip_network(item.strip(), strict=True)
            except ValueError as exc:
                raise IngressHold("WG_ALLOWED_IP_INVALID") from exc
            networks.append(net)
        if not networks:
            raise IngressHold("WG_ALLOWED_IP_EMPTY")
        result[key] = tuple(networks)
    if not result:
        raise IngressHold("WG_PEER_INVENTORY_EMPTY")
    return result


def verify_ingress(row: RuntimeBinding, rhost: str,
                   peers: tuple[IngressPeer, ...],
                   wg_allowed_ips: str) -> bool:
    """Proof for one already-PROTECTED UID's *new SSH login*.

    No fallback to whichever relay is currently default.
    """
    if not isinstance(row, RuntimeBinding):
        return False
    try:
        source = _ip(rhost)
        if source not in NET:
            return False
        matching = [peer for peer in peers if peer.ingress_ipv4 == str(source)]
        if len(matching) != 1:
            return False
        peer = matching[0]
        if (peer.edge_id != row.edge_id or peer.edge_ipv4 != row.edge_ipv4):
            return False
        allowed = _networks(wg_allowed_ips)
        expected = ipaddress.ip_network(str(source) + "/32")
        if expected not in allowed.get(peer.wg_public_key, ()):
            return False
        # No OTHER key may be able to inject that wg0 source address.
        if any(source in network for key, networks in allowed.items()
               if key != peer.wg_public_key for network in networks):
            return False
        return True
    except (IngressHold, ValueError):
        return False


def probe_ingress(row: RuntimeBinding, rhost: str) -> bool:
    """Minimal current wg0 peer validation for PAM; read-only."""
    try:
        peers = load_registry()
        peer_result = subprocess.run(
            ["wg", "show", "wg0", "allowed-ips"],
            text=True, capture_output=True, timeout=3, check=False,
        )
        if peer_result.returncode:
            return False
        return verify_ingress(row, rhost, peers, peer_result.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return False


def render_registry(entries: list[IngressPeer]) -> str:
    """Pure renderer for I onboarding, not a provisioning/install action."""
    if not isinstance(entries, list):
        raise IngressHold("INVALID_PEERS_INPUT")
    obj = {"version": 1, "peers": [
        dict(edge_id=p.edge_id, edge_ipv4=p.edge_ipv4,
             ingress_ipv4=p.ingress_ipv4, wg_public_key=p.wg_public_key)
        for p in entries
    ]}
    text = json.dumps(obj, indent=2, sort_keys=True) + "\n"
    parse_registry(text.encode())
    return text
