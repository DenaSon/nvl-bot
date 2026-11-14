"""Read-only, dual-backend NVL ingress tunnel registry and health probes.

Legacy Edge hosts have no registry entry and must continue through the existing
wg0 inspection path. A present but invalid/unverified entry is a hard HOLD,
never an invitation to fall back to legacy or change routes.
No SSH, NAT, DNS, users, keys or network state are modified by this module.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime
import ipaddress
import re
import sqlite3
import subprocess
import time


class TunnelHold(ValueError):
    """A registered binding is ambiguous or cannot be trusted."""


# DDL is explicit and opt-in. Reading the registry NEVER migrates Production DB.
SCHEMA = """
CREATE TABLE IF NOT EXISTS edge_tunnel_bindings (
    host TEXT PRIMARY KEY,
    backend TEXT NOT NULL CHECK (backend IN ('wireguard', 'amneziawg')),
    interface TEXT NOT NULL,
    core_tunnel_ip TEXT NOT NULL,
    edge_tunnel_ip TEXT NOT NULL,
    peer_public_key TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('VERIFIED', 'HOLD')),
    verified_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_edge_tunnel_source
    ON edge_tunnel_bindings(backend, edge_tunnel_ip);
"""
_KEY_RE = re.compile(r"[A-Za-z0-9+/]{43}=\Z")
_INTERFACE_RE = re.compile(r"(wg|awg)[0-9]+\Z")
_LEGACY_SHARED_NETWORK = ipaddress.IPv4Network("10.77.0.0/24")


def _ipv4(raw: str) -> ipaddress.IPv4Address:
    try:
        return ipaddress.IPv4Address(raw)
    except (ValueError, TypeError, ipaddress.AddressValueError) as exc:
        raise TunnelHold("INVALID_TUNNEL_IPV4") from exc


def _key(raw: str) -> str:
    if not isinstance(raw, str) or not _KEY_RE.fullmatch(raw):
        raise TunnelHold("INVALID_TUNNEL_PUBLIC_KEY")
    try:
        if len(base64.b64decode(raw, validate=True)) != 32:
            raise ValueError("not a Curve25519 public key")
    except (ValueError, base64.binascii.Error) as exc:
        raise TunnelHold("INVALID_TUNNEL_PUBLIC_KEY") from exc
    return raw


@dataclass(frozen=True)
class TunnelBinding:
    host: str
    backend: str
    interface: str
    core_tunnel_ip: str
    edge_tunnel_ip: str
    peer_public_key: str
    verified_at: int

    @classmethod
    def from_row(cls, row: tuple) -> "TunnelBinding":
        if len(row) != 8:
            raise TunnelHold("TUNNEL_BINDING_SHAPE_INVALID")
        host, backend, interface, core_ip, edge_ip, peer_key, state, at = row
        _ipv4(host)
        core, edge = _ipv4(core_ip), _ipv4(edge_ip)
        if core == edge:
            raise TunnelHold("TUNNEL_ADDRESS_COLLISION")
        if backend not in ("wireguard", "amneziawg"):
            raise TunnelHold("TUNNEL_BACKEND_UNSUPPORTED")
        if not isinstance(interface, str) or not _INTERFACE_RE.fullmatch(interface):
            raise TunnelHold("TUNNEL_INTERFACE_INVALID")
        expected = "awg" if backend == "amneziawg" else "wg"
        if not interface.startswith(expected):
            raise TunnelHold("TUNNEL_BACKEND_INTERFACE_MISMATCH")
        _key(peer_key)
        if state != "VERIFIED":
            raise TunnelHold("TUNNEL_BINDING_NOT_VERIFIED")
        if not isinstance(at, int) or at <= 0:
            raise TunnelHold("TUNNEL_VERIFICATION_MISSING")
        return cls(host, backend, interface, str(core), str(edge), peer_key, at)


def _exists(db: sqlite3.Connection) -> bool:
    return db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' "
        "AND name='edge_tunnel_bindings'"
    ).fetchone() is not None


def lookup_binding(db: sqlite3.Connection, host: str) -> TunnelBinding | None:
    """Absent registry/host = legacy wg0; malformed present record = HOLD."""
    _ipv4(host)
    if not _exists(db):
        return None
    row = db.execute(
        "SELECT host,backend,interface,core_tunnel_ip,edge_tunnel_ip,"
        "peer_public_key,state,verified_at FROM edge_tunnel_bindings "
        "WHERE host=?", (host,),
    ).fetchone()
    return TunnelBinding.from_row(row) if row else None


def verified_shared_edge_sources(db: sqlite3.Connection) -> frozenset[str]:
    """Exact registered AWG SNAT /32s; excludes unverified/historical records."""
    if not _exists(db):
        return frozenset()
    sources: set[str] = set()
    for row in db.execute(
        "SELECT host,backend,interface,core_tunnel_ip,edge_tunnel_ip,"
        "peer_public_key,state,verified_at FROM edge_tunnel_bindings "
        "WHERE backend='amneziawg' AND state='VERIFIED'"
    ):
        binding = TunnelBinding.from_row(row)
        if binding.edge_tunnel_ip in sources:
            raise TunnelHold("TUNNEL_SHARED_SOURCE_COLLISION")
        sources.add(binding.edge_tunnel_ip)
    return frozenset(sources)


def is_shared_ingress_source(ip: str, awg_sources: frozenset[str]) -> bool:
    """Keep existing WG subnet handling, add ONLY verified AWG source IPs."""
    try:
        address = _ipv4(ip)
    except TunnelHold:
        return False
    return address in _LEGACY_SHARED_NETWORK or str(address) in awg_sources


def _observed(result: object) -> str:
    if getattr(result, "returncode", 1) != 0:
        raise TunnelHold("TUNNEL_COMMAND_FAILED")
    out = getattr(result, "stdout", None)
    if not isinstance(out, str) or len(out) > 131072:
        raise TunnelHold("TUNNEL_OUTPUT_UNVERIFIED")
    return out


def _allowed_peer(raw: str, binding: TunnelBinding) -> bool:
    expected = ipaddress.ip_network(binding.edge_tunnel_ip + "/32")
    matching = 0
    for line in raw.splitlines():
        parts = line.split(None, 1)
        if len(parts) != 2:
            raise TunnelHold("TUNNEL_ALLOWED_IPS_MALFORMED")
        key, cidrs = parts
        _key(key)
        for text in cidrs.split(","):
            try:
                net = ipaddress.ip_network(text.strip(), strict=True)
            except ValueError as exc:
                raise TunnelHold("TUNNEL_ALLOWED_IPS_INVALID") from exc
            if ipaddress.IPv4Address(binding.edge_tunnel_ip) in net:
                if key != binding.peer_public_key or net != expected:
                    raise TunnelHold("TUNNEL_PEER_OWNERSHIP_AMBIGUOUS")
                matching += 1
    return matching == 1


def _run(runner, cmd: list[str], timeout: int):
    return runner(cmd, capture_output=True, text=True, timeout=timeout)


def probe_binding(
    binding: TunnelBinding, *, runner=subprocess.run,
    clock=time.time, timeout: int = 3, max_handshake_age: int = 180,
) -> dict:
    """Read-only AWG peer ownership, handshake and Core->Edge path evidence.

    Caller retains old observability field names for DB/API compatibility.
    No AWG-specific probes ever run for unregistered legacy hosts.
    """
    result = dict(
        wg_peer_ok=None, wg_last_handshake_at=None,
        wg_reason="TUNNEL_UNVERIFIED",
        core_path_ok=None, core_path_reason="TUNNEL_UNVERIFIED",
        tunnel_backend=binding.backend,
    )
    tool = "awg" if binding.backend == "amneziawg" else "wg"
    try:
        allowed = _observed(_run(
            runner, [tool, "show", binding.interface, "allowed-ips"], timeout,
        ))
        if not _allowed_peer(allowed, binding):
            result.update(wg_peer_ok=False, core_path_ok=False,
                          wg_reason="TUNNEL_PEER_MISSING",
                          core_path_reason="TUNNEL_PEER_MISSING")
            return result
    except (TunnelHold, OSError, subprocess.TimeoutExpired) as exc:
        result["wg_reason"] = (
            str(exc) if isinstance(exc, TunnelHold) else "TUNNEL_PEER_PROBE_ERROR"
        )
        return result

    try:
        ping = _run(
            runner, ["ping", "-I", binding.interface, "-c", "1", "-W",
                     str(timeout), binding.edge_tunnel_ip], timeout + 2,
        )
        path_ok = getattr(ping, "returncode", 1) == 0
        result["core_path_ok"] = path_ok
        result["core_path_reason"] = (
            "OK" if path_ok else "CORE_TUNNEL_PING_FAILED"
        )
    except (OSError, subprocess.TimeoutExpired):
        result["core_path_reason"] = "CORE_TUNNEL_PROBE_ERROR"

    try:
        raw = _observed(_run(
            runner, [tool, "show", binding.interface, "latest-handshakes"],
            timeout,
        ))
        entries = {}
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) != 2 or parts[0] in entries:
                raise TunnelHold("TUNNEL_HANDSHAKE_INVALID")
            _key(parts[0])
            entries[parts[0]] = int(parts[1])
        ts = entries.get(binding.peer_public_key, 0)
        if ts > 0:
            result["wg_last_handshake_at"] = datetime.fromtimestamp(
                ts,
            ).strftime("%Y-%m-%d %H:%M:%S")
        fresh = bool(ts > 0 and 0 <= int(clock()) - ts <= max_handshake_age)
    except (ValueError, TunnelHold, OSError, subprocess.TimeoutExpired, OverflowError):
        fresh = False

    result["wg_peer_ok"] = fresh or result["core_path_ok"] is True
    result["wg_reason"] = (
        "OK" if fresh else
        "TUNNEL_PATH_PROVEN" if result["core_path_ok"] is True else
        "TUNNEL_HANDSHAKE_STALE_OR_MISSING"
    )
    return result
