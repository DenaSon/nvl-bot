"""V120-A: read-only Marzban infrastructure asset discovery.

This module deliberately does *not* probe, alert, fail over, mutate Marzban, or
change DNS. It builds an authoritative inventory snapshot from the configured
Marzban Main URL plus the read-only Nodes / Hosts / Inbounds APIs, resolves
addresses, and persists only inventory metadata.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence
from urllib.parse import urlsplit


V120A_VERSION = "V120A.0-2026-10-03-marzban-asset-discovery"

ASSET_MAIN = "MARZBAN_MAIN"
ASSET_NODE = "MARZBAN_NODE"
ASSET_PUBLIC_HOST = "MARZBAN_PUBLIC_HOST"

Resolver = Callable[[str], Iterable[str]]


class AssetDiscoveryError(RuntimeError):
    """An authoritative discovery snapshot could not be completed safely."""


@dataclass(frozen=True)
class MarzbanAsset:
    asset_key: str
    asset_type: str
    source_id: str
    name: str
    address: str
    port: Optional[int]
    resolved_ips: tuple[str, ...]
    metadata: Mapping[str, Any]


@dataclass(frozen=True)
class DiscoverySnapshot:
    assets: tuple[MarzbanAsset, ...]
    observed_at: str


@dataclass(frozen=True)
class InventoryDiff:
    added: tuple[str, ...]
    changed: tuple[str, ...]
    removed: tuple[str, ...]


@dataclass(frozen=True)
class AssetEndpoint:
    host: str
    port: int
    asset_keys: tuple[str, ...]


def utc_now_text() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clean_text(value: Any) -> str:
    return str(value or "").strip()


def _normalize_port(value: Any, default: Optional[int] = None) -> Optional[int]:
    if value is None or _clean_text(value).lower() in {"", "none", "null", "-"}:
        return default
    try:
        port = int(value)
    except (TypeError, ValueError):
        return default
    return port if 1 <= port <= 65535 else default


def resolve_address(address: str) -> tuple[str, ...]:
    """Resolve one literal IP/hostname into a stable unique IP tuple."""
    address = _clean_text(address)
    if not address:
        return ()

    raw_ip = address[1:-1] if address.startswith("[") and address.endswith("]") else address
    try:
        return (str(ipaddress.ip_address(raw_ip)),)
    except ValueError:
        pass

    infos = socket.getaddrinfo(address, None, type=socket.SOCK_STREAM)
    values = {
        str(ipaddress.ip_address(info[4][0]))
        for info in infos
        if info and len(info) > 4 and info[4]
    }
    return tuple(sorted(values))


def _resolved(address: str, resolver: Resolver) -> tuple[tuple[str, ...], Optional[str]]:
    try:
        values = tuple(
            sorted({_clean_text(ip) for ip in resolver(address) if _clean_text(ip)})
        )
        return values, None
    except Exception as exc:
        return (), f"{type(exc).__name__}: {exc}"


def _make_asset(
    *,
    asset_type: str,
    source_id: str,
    name: str,
    address: str,
    port: Optional[int],
    metadata: Optional[Mapping[str, Any]],
    resolver: Resolver,
) -> MarzbanAsset:
    address = _clean_text(address)
    if not address:
        raise AssetDiscoveryError(f"{asset_type}:{source_id} has no address")

    resolved_ips, resolution_error = _resolved(address, resolver)
    safe_metadata = dict(metadata or {})
    if resolution_error:
        safe_metadata["resolution_error"] = resolution_error

    return MarzbanAsset(
        asset_key=f"{asset_type}:{source_id}",
        asset_type=asset_type,
        source_id=str(source_id),
        name=_clean_text(name) or str(source_id),
        address=address,
        port=_normalize_port(port),
        resolved_ips=resolved_ips,
        metadata=safe_metadata,
    )


def _main_asset(marzban_url: str, resolver: Resolver) -> MarzbanAsset:
    raw = _clean_text(marzban_url)
    if not raw:
        raise AssetDiscoveryError("Marzban Main URL is empty")

    parsed = urlsplit(raw if "://" in raw else f"https://{raw}")
    if not parsed.hostname:
        raise AssetDiscoveryError("Marzban Main URL has no hostname")

    default_port = 443 if parsed.scheme.lower() == "https" else 80
    try:
        port = parsed.port or default_port
    except ValueError as exc:
        raise AssetDiscoveryError(f"Marzban Main URL has invalid port: {exc}") from exc

    return _make_asset(
        asset_type=ASSET_MAIN,
        source_id="main",
        name="Marzban Main",
        address=parsed.hostname,
        port=port,
        metadata={"scheme": parsed.scheme.lower() or "https"},
        resolver=resolver,
    )


def _node_rows(payload: Any) -> Sequence[Mapping[str, Any]]:
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict) and isinstance(payload.get("nodes"), list):
        rows = payload["nodes"]
    else:
        raise AssetDiscoveryError("Invalid /api/nodes payload")

    if any(not isinstance(row, dict) for row in rows):
        raise AssetDiscoveryError("Invalid node entry in /api/nodes payload")
    return rows


def _inbound_port_map(payload: Any) -> dict[str, int]:
    if not isinstance(payload, dict):
        raise AssetDiscoveryError("Invalid /api/inbounds payload")

    result: dict[str, int] = {}
    for _protocol, rows in payload.items():
        if not isinstance(rows, list):
            raise AssetDiscoveryError("Invalid inbound group in /api/inbounds payload")
        for row in rows:
            if not isinstance(row, dict):
                raise AssetDiscoveryError("Invalid inbound entry in /api/inbounds payload")
            tag = _clean_text(row.get("tag"))
            port = _normalize_port(row.get("port"))
            if tag and port is not None:
                result[tag] = port
    return result


def _node_assets(payload: Any, resolver: Resolver) -> list[MarzbanAsset]:
    assets: list[MarzbanAsset] = []
    seen_ids: set[int] = set()

    for row in _node_rows(payload):
        try:
            node_id = int(row.get("id"))
        except (TypeError, ValueError):
            raise AssetDiscoveryError("Node entry has invalid id")
        if node_id <= 0 or node_id in seen_ids:
            raise AssetDiscoveryError(f"Duplicate/invalid Marzban node id: {node_id}")
        seen_ids.add(node_id)

        assets.append(
            _make_asset(
                asset_type=ASSET_NODE,
                source_id=str(node_id),
                name=_clean_text(row.get("name")) or f"Node {node_id}",
                address=_clean_text(row.get("address")),
                port=_normalize_port(row.get("port"), 62050),
                metadata={
                    "node_id": node_id,
                    "status": _clean_text(row.get("status")),
                    "api_port": _normalize_port(row.get("api_port"), 62051),
                    "usage_coefficient": row.get("usage_coefficient"),
                    "xray_version": row.get("xray_version"),
                },
                resolver=resolver,
            )
        )
    return assets


def _public_host_assets(
    hosts_payload: Any,
    inbound_ports: Mapping[str, int],
    resolver: Resolver,
) -> list[MarzbanAsset]:
    if not isinstance(hosts_payload, dict):
        raise AssetDiscoveryError("Invalid /api/hosts payload")

    assets: list[MarzbanAsset] = []
    for inbound_tag in sorted(hosts_payload):
        rows = hosts_payload[inbound_tag]
        if not isinstance(rows, list):
            raise AssetDiscoveryError("Invalid host group in /api/hosts payload")

        for index, row in enumerate(rows):
            if not isinstance(row, dict):
                raise AssetDiscoveryError("Invalid host entry in /api/hosts payload")
            address = _clean_text(row.get("address"))
            if not address:
                raise AssetDiscoveryError(
                    f"Public Host {inbound_tag}[{index}] has no address"
                )
            explicit_port = _normalize_port(row.get("port"))
            effective_port = explicit_port or inbound_ports.get(inbound_tag)
            assets.append(
                _make_asset(
                    asset_type=ASSET_PUBLIC_HOST,
                    source_id=f"{inbound_tag}:{index}",
                    name=_clean_text(row.get("remark"))
                    or f"{inbound_tag} #{index + 1}",
                    address=address,
                    port=effective_port,
                    metadata={
                        "inbound_tag": inbound_tag,
                        "host_index": index,
                        "port_source": "host"
                        if explicit_port
                        else ("inbound" if effective_port else "unknown"),
                        "is_disabled": row.get("is_disabled"),
                        "sni": row.get("sni"),
                        "host": row.get("host"),
                        "security": row.get("security"),
                    },
                    resolver=resolver,
                )
            )
    return assets


def discover_assets(
    marzban_url: str,
    nodes_payload: Any,
    hosts_payload: Any,
    inbounds_payload: Any,
    *,
    resolver: Resolver = resolve_address,
    observed_at: Optional[str] = None,
) -> DiscoverySnapshot:
    """Build a complete logical inventory snapshot from authoritative read APIs."""
    inbound_ports = _inbound_port_map(inbounds_payload)
    assets = [
        _main_asset(marzban_url, resolver),
        *_node_assets(nodes_payload, resolver),
        *_public_host_assets(hosts_payload, inbound_ports, resolver),
    ]

    keys = [asset.asset_key for asset in assets]
    if len(keys) != len(set(keys)):
        raise AssetDiscoveryError("Discovery produced duplicate asset keys")

    assets.sort(key=lambda item: (item.asset_type, item.asset_key))
    return DiscoverySnapshot(
        assets=tuple(assets),
        observed_at=observed_at or utc_now_text(),
    )


async def discover_from_service(
    service: Any,
    *,
    resolver: Resolver = resolve_address,
) -> DiscoverySnapshot:
    """Read Main/Nodes/Hosts/Inbounds only; any partial API snapshot fails closed."""
    if service is None:
        raise AssetDiscoveryError("Marzban service is unavailable")
    if hasattr(service, "configured") and not service.configured:
        raise AssetDiscoveryError("Marzban service is not configured")

    async def fetch(label: str, method_name: str):
        method = getattr(service, method_name, None)
        if method is None:
            raise AssetDiscoveryError(f"Marzban service lacks {method_name}()")
        ok, payload = await method()
        if not ok:
            raise AssetDiscoveryError(f"{label} discovery failed: {payload}")
        return payload

    nodes_payload = await fetch("nodes", "get_nodes")
    hosts_payload = await fetch("hosts", "get_hosts")
    inbounds_payload = await fetch("inbounds", "get_inbounds")

    return await asyncio.to_thread(
        discover_assets,
        service.url,
        nodes_payload,
        hosts_payload,
        inbounds_payload,
        resolver=resolver,
    )


def install_schema(conn) -> None:
    conn.execute(
        """CREATE TABLE IF NOT EXISTS marzban_assets (
            asset_key TEXT PRIMARY KEY,
            asset_type TEXT NOT NULL,
            source_id TEXT NOT NULL,
            name TEXT NOT NULL,
            address TEXT NOT NULL,
            port INTEGER DEFAULT NULL,
            resolved_ips_json TEXT NOT NULL DEFAULT '[]',
            metadata_json TEXT NOT NULL DEFAULT '{}',
            active INTEGER NOT NULL DEFAULT 1,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            retired_at TEXT DEFAULT NULL
        )"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_marzban_assets_active_type "
        "ON marzban_assets(active, asset_type)"
    )


def _json(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


def sync_inventory(
    conn,
    assets: Sequence[MarzbanAsset],
    *,
    observed_at: Optional[str] = None,
) -> InventoryDiff:
    """Persist one complete snapshot and return added/changed/removed logical keys."""
    install_schema(conn)
    seen_at = observed_at or utc_now_text()

    incoming: dict[str, MarzbanAsset] = {}
    for asset in assets:
        if asset.asset_key in incoming:
            raise AssetDiscoveryError(f"Duplicate asset key: {asset.asset_key}")
        incoming[asset.asset_key] = asset

    rows = conn.execute(
        """SELECT asset_key, asset_type, source_id, name, address, port,
                  resolved_ips_json, metadata_json, active
           FROM marzban_assets"""
    ).fetchall()
    current = {row[0]: row for row in rows}

    added: list[str] = []
    changed: list[str] = []

    for key in sorted(incoming):
        asset = incoming[key]
        resolved_json = _json(list(asset.resolved_ips))
        metadata_json = _json(dict(asset.metadata))
        row = current.get(key)

        if row is None:
            conn.execute(
                """INSERT INTO marzban_assets (
                       asset_key, asset_type, source_id, name, address, port,
                       resolved_ips_json, metadata_json, active,
                       first_seen_at, last_seen_at, retired_at
                   ) VALUES (?,?,?,?,?,?,?,?,1,?,?,NULL)""",
                (
                    asset.asset_key,
                    asset.asset_type,
                    asset.source_id,
                    asset.name,
                    asset.address,
                    asset.port,
                    resolved_json,
                    metadata_json,
                    seen_at,
                    seen_at,
                ),
            )
            added.append(key)
            continue

        old_signature = (
            row[1],
            row[2],
            row[3],
            row[4],
            row[5],
            row[6],
            row[7],
        )
        new_signature = (
            asset.asset_type,
            asset.source_id,
            asset.name,
            asset.address,
            asset.port,
            resolved_json,
            metadata_json,
        )
        was_active = bool(row[8])
        is_changed = old_signature != new_signature

        conn.execute(
            """UPDATE marzban_assets
               SET asset_type=?, source_id=?, name=?, address=?, port=?,
                   resolved_ips_json=?, metadata_json=?, active=1,
                   last_seen_at=?, retired_at=NULL
               WHERE asset_key=?""",
            (
                asset.asset_type,
                asset.source_id,
                asset.name,
                asset.address,
                asset.port,
                resolved_json,
                metadata_json,
                seen_at,
                key,
            ),
        )

        if not was_active:
            added.append(key)
        elif is_changed:
            changed.append(key)

    removed: list[str] = []
    for key, row in current.items():
        if bool(row[8]) and key not in incoming:
            conn.execute(
                """UPDATE marzban_assets
                   SET active=0, retired_at=?
                   WHERE asset_key=?""",
                (seen_at, key),
            )
            removed.append(key)

    return InventoryDiff(
        added=tuple(sorted(added)),
        changed=tuple(sorted(changed)),
        removed=tuple(sorted(removed)),
    )


def list_active_assets(conn) -> tuple[MarzbanAsset, ...]:
    install_schema(conn)
    rows = conn.execute(
        """SELECT asset_key, asset_type, source_id, name, address, port,
                  resolved_ips_json, metadata_json
           FROM marzban_assets
           WHERE active=1
           ORDER BY asset_type, asset_key"""
    ).fetchall()
    result = []
    for row in rows:
        result.append(
            MarzbanAsset(
                asset_key=row[0],
                asset_type=row[1],
                source_id=row[2],
                name=row[3],
                address=row[4],
                port=row[5],
                resolved_ips=tuple(json.loads(row[6] or "[]")),
                metadata=json.loads(row[7] or "{}"),
            )
        )
    return tuple(result)


def deduplicated_endpoints(
    assets: Sequence[MarzbanAsset],
) -> tuple[AssetEndpoint, ...]:
    """Collapse logical assets onto unique host:port candidates for future V120-B."""
    grouped: dict[tuple[str, int], set[str]] = {}
    for asset in assets:
        if asset.port is None:
            continue
        targets = asset.resolved_ips or (asset.address,)
        for host in targets:
            grouped.setdefault((host, asset.port), set()).add(asset.asset_key)

    return tuple(
        AssetEndpoint(host=host, port=port, asset_keys=tuple(sorted(keys)))
        for (host, port), keys in sorted(grouped.items())
    )
