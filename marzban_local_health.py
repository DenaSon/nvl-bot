"""V120-B local-only health monitoring for discovered Marzban assets.

This layer is read-only. It records local reachability and Marzban-reported
health for Main, Nodes, and Public Hosts. Regional filtering, notifications,
routing changes, DNS changes, and Marzban mutations are outside this phase.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Mapping, Optional, Sequence

import marzban_asset_discovery as discovery


V120B_VERSION = "V120B.0-2026-10-03-marzban-local-health"

STATE_LOCAL_HEALTHY = "LOCAL_HEALTHY"
STATE_DNS_ERROR = "DNS_ERROR"
STATE_SERVICE_DOWN = "SERVICE_DOWN"
STATE_API_DOWN = "API_DOWN"
STATE_NODE_DISCONNECTED = "NODE_DISCONNECTED"
STATE_CONTROL_DOWN = "CONTROL_DOWN"
STATE_DISABLED = "DISABLED"
STATE_UNKNOWN = "UNKNOWN"

REASON_OK = "OK"
REASON_DNS_UNRESOLVED = "DNS_UNRESOLVED"
REASON_PORT_UNKNOWN = "PORT_UNKNOWN"
REASON_TCP_UNREACHABLE = "TCP_UNREACHABLE"
REASON_MAIN_API_UNAVAILABLE = "MAIN_API_UNAVAILABLE"
REASON_NODE_STATUS_NOT_CONNECTED = "NODE_STATUS_NOT_CONNECTED"
REASON_NODE_CONTROL_UNREACHABLE = "NODE_CONTROL_UNREACHABLE"
REASON_NODE_API_UNREACHABLE = "NODE_API_UNREACHABLE"
REASON_PUBLIC_HOST_DISABLED = "PUBLIC_HOST_DISABLED"
REASON_NODE_DISABLED = "NODE_DISABLED"

ProbeFunc = Callable[[str, int, float], Awaitable["TcpProbe"]]


@dataclass(frozen=True)
class TcpProbe:
    host: str
    port: int
    ok: bool
    latency_ms: Optional[float]
    error: Optional[str]


@dataclass(frozen=True)
class AssetHealth:
    asset_key: str
    asset_type: str
    health_state: str
    health_reason: str
    healthy: Optional[bool]
    checked_at: str
    latency_ms: Optional[float]
    evidence: Mapping[str, Any]


def _error_text(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}".strip()[:500]


async def tcp_probe(host: str, port: int, timeout: float) -> TcpProbe:
    started = time.perf_counter()
    writer = None
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, int(port)),
            timeout=max(0.1, float(timeout)),
        )
        latency = (time.perf_counter() - started) * 1000.0
        return TcpProbe(host, int(port), True, round(latency, 2), None)
    except Exception as exc:
        return TcpProbe(host, int(port), False, None, _error_text(exc))
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


def _targets(asset: discovery.MarzbanAsset) -> tuple[str, ...]:
    return tuple(asset.resolved_ips)


def _node_api_port(asset: discovery.MarzbanAsset) -> Optional[int]:
    try:
        port = int(asset.metadata.get("api_port"))
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _endpoint_keys(
    assets: Sequence[discovery.MarzbanAsset],
) -> tuple[tuple[str, int], ...]:
    keys: set[tuple[str, int]] = set()
    for asset in assets:
        if (
            asset.asset_type == discovery.ASSET_PUBLIC_HOST
            and asset.metadata.get("is_disabled") is True
        ):
            continue
        if (
            asset.asset_type == discovery.ASSET_NODE
            and str(asset.metadata.get("status") or "").strip().lower() == "disabled"
        ):
            continue
        if asset.port is not None:
            for host in _targets(asset):
                keys.add((host, int(asset.port)))
        if asset.asset_type == discovery.ASSET_NODE:
            api_port = _node_api_port(asset)
            if api_port is not None:
                for host in _targets(asset):
                    keys.add((host, api_port))
    return tuple(sorted(keys))


async def _probe_all(
    assets: Sequence[discovery.MarzbanAsset],
    *,
    probe_func: ProbeFunc,
    timeout: float,
    concurrency: int,
) -> dict[tuple[str, int], TcpProbe]:
    semaphore = asyncio.Semaphore(max(1, int(concurrency)))

    async def one(host: str, port: int):
        async with semaphore:
            return (host, port), await probe_func(host, port, timeout)

    pairs = await asyncio.gather(
        *(one(host, port) for host, port in _endpoint_keys(assets))
    )
    return dict(pairs)


def _port_evidence(
    asset: discovery.MarzbanAsset,
    port: Optional[int],
    probes: Mapping[tuple[str, int], TcpProbe],
) -> dict[str, Any]:
    if port is None:
        return {"port": None, "ok": None, "latency_ms": None, "attempts": []}

    attempts = []
    successes = []
    for host in _targets(asset):
        probe = probes.get((host, int(port)))
        if probe is None:
            continue
        attempts.append(
            {
                "host": host,
                "port": int(port),
                "ok": probe.ok,
                "latency_ms": probe.latency_ms,
                "error": probe.error,
            }
        )
        if probe.ok:
            successes.append(probe)

    best = min(
        successes,
        key=lambda p: p.latency_ms if p.latency_ms is not None else float("inf"),
        default=None,
    )
    return {
        "port": int(port),
        "ok": bool(successes) if attempts else None,
        "latency_ms": best.latency_ms if best else None,
        "attempts": attempts,
    }


async def _main_api_check(service: Any) -> tuple[Optional[bool], Optional[str]]:
    if service is None or not getattr(service, "configured", False):
        return None, "Marzban service is not configured"
    try:
        ok, payload = await service.get_system_stats()
    except Exception as exc:
        return False, _error_text(exc)
    return (True, None) if ok else (False, str(payload)[:500])


async def _live_node_statuses(
    service: Any,
) -> tuple[dict[int, str], Optional[str]]:
    if service is None or not getattr(service, "configured", False):
        return {}, "Marzban service is not configured"
    try:
        ok, payload = await service.get_nodes()
    except Exception as exc:
        return {}, _error_text(exc)
    if not ok:
        return {}, str(payload)[:500]
    if not isinstance(payload, list):
        return {}, "Invalid /api/nodes payload"

    statuses = {}
    for row in payload:
        if not isinstance(row, dict):
            continue
        try:
            node_id = int(row.get("id"))
        except (TypeError, ValueError):
            continue
        statuses[node_id] = str(row.get("status") or "").strip().lower()
    return statuses, None


def _disabled_result(
    asset: discovery.MarzbanAsset,
    checked_at: str,
    reason: str,
) -> AssetHealth:
    return AssetHealth(
        asset.asset_key,
        asset.asset_type,
        STATE_DISABLED,
        reason,
        None,
        checked_at,
        None,
        {
            "address": asset.address,
            "resolved_ips": list(asset.resolved_ips),
            "disabled": True,
        },
    )


def _classify(
    asset: discovery.MarzbanAsset,
    *,
    checked_at: str,
    primary: Mapping[str, Any],
    node_api: Optional[Mapping[str, Any]],
    main_api_ok: Optional[bool],
    main_api_error: Optional[str],
    node_status: Optional[str],
    node_status_source: Optional[str],
    node_status_refresh_error: Optional[str],
) -> AssetHealth:
    if (
        asset.asset_type == discovery.ASSET_PUBLIC_HOST
        and asset.metadata.get("is_disabled") is True
    ):
        return _disabled_result(asset, checked_at, REASON_PUBLIC_HOST_DISABLED)

    normalized_node_status = str(node_status or "").strip().lower()
    if asset.asset_type == discovery.ASSET_NODE and normalized_node_status == "disabled":
        return _disabled_result(asset, checked_at, REASON_NODE_DISABLED)

    evidence: dict[str, Any] = {
        "address": asset.address,
        "resolved_ips": list(asset.resolved_ips),
        "primary": dict(primary),
    }

    if not asset.resolved_ips:
        evidence["resolution_error"] = asset.metadata.get("resolution_error")
        return AssetHealth(
            asset.asset_key,
            asset.asset_type,
            STATE_DNS_ERROR,
            REASON_DNS_UNRESOLVED,
            False,
            checked_at,
            None,
            evidence,
        )

    if asset.asset_type == discovery.ASSET_MAIN:
        evidence["api_ok"] = main_api_ok
        evidence["api_error"] = main_api_error
        if asset.port is None:
            return AssetHealth(
                asset.asset_key, asset.asset_type, STATE_UNKNOWN,
                REASON_PORT_UNKNOWN, None, checked_at, None, evidence
            )
        if primary.get("ok") is not True:
            return AssetHealth(
                asset.asset_key, asset.asset_type, STATE_SERVICE_DOWN,
                REASON_TCP_UNREACHABLE, False, checked_at, None, evidence
            )
        if main_api_ok is not True:
            return AssetHealth(
                asset.asset_key, asset.asset_type, STATE_API_DOWN,
                REASON_MAIN_API_UNAVAILABLE,
                False if main_api_ok is False else None,
                checked_at, primary.get("latency_ms"), evidence
            )
        return AssetHealth(
            asset.asset_key, asset.asset_type, STATE_LOCAL_HEALTHY,
            REASON_OK, True, checked_at, primary.get("latency_ms"), evidence
        )

    if asset.asset_type == discovery.ASSET_NODE:
        evidence["node_status"] = normalized_node_status
        evidence["node_status_source"] = node_status_source
        evidence["node_status_refresh_error"] = node_status_refresh_error
        evidence["node_api"] = dict(node_api or {})
        if normalized_node_status and normalized_node_status != "connected":
            return AssetHealth(
                asset.asset_key, asset.asset_type, STATE_NODE_DISCONNECTED,
                REASON_NODE_STATUS_NOT_CONNECTED, False, checked_at, None, evidence
            )
        if asset.port is None or primary.get("ok") is not True:
            return AssetHealth(
                asset.asset_key, asset.asset_type, STATE_CONTROL_DOWN,
                REASON_NODE_CONTROL_UNREACHABLE, False, checked_at, None, evidence
            )
        if node_api is not None and node_api.get("ok") is not True:
            return AssetHealth(
                asset.asset_key, asset.asset_type, STATE_CONTROL_DOWN,
                REASON_NODE_API_UNREACHABLE, False, checked_at,
                primary.get("latency_ms"), evidence
            )
        return AssetHealth(
            asset.asset_key, asset.asset_type, STATE_LOCAL_HEALTHY,
            REASON_OK, True, checked_at, primary.get("latency_ms"), evidence
        )

    if asset.asset_type == discovery.ASSET_PUBLIC_HOST:
        if asset.port is None:
            return AssetHealth(
                asset.asset_key, asset.asset_type, STATE_UNKNOWN,
                REASON_PORT_UNKNOWN, None, checked_at, None, evidence
            )
        if primary.get("ok") is not True:
            return AssetHealth(
                asset.asset_key, asset.asset_type, STATE_SERVICE_DOWN,
                REASON_TCP_UNREACHABLE, False, checked_at, None, evidence
            )
        return AssetHealth(
            asset.asset_key, asset.asset_type, STATE_LOCAL_HEALTHY,
            REASON_OK, True, checked_at, primary.get("latency_ms"), evidence
        )

    return AssetHealth(
        asset.asset_key, asset.asset_type, STATE_UNKNOWN,
        "UNSUPPORTED_ASSET_TYPE", None, checked_at, None, evidence
    )


async def collect_local_health(
    assets: Sequence[discovery.MarzbanAsset],
    service: Any,
    *,
    probe_func: ProbeFunc = tcp_probe,
    timeout: float = 5.0,
    concurrency: int = 10,
    checked_at: Optional[str] = None,
) -> tuple[AssetHealth, ...]:
    timestamp = checked_at or discovery.utc_now_text()
    assets = tuple(assets)
    if not assets:
        return ()

    probes = await _probe_all(
        assets,
        probe_func=probe_func,
        timeout=timeout,
        concurrency=concurrency,
    )

    main_reachable = False
    for item in assets:
        if item.asset_type != discovery.ASSET_MAIN:
            continue
        if _port_evidence(item, item.port, probes).get("ok") is True:
            main_reachable = True
            break

    if main_reachable:
        (main_api_ok, main_api_error), (
            live_statuses,
            node_status_refresh_error,
        ) = await asyncio.gather(
            _main_api_check(service),
            _live_node_statuses(service),
        )
    else:
        main_api_ok = False
        main_api_error = "Main TCP is not reachable"
        live_statuses = {}
        node_status_refresh_error = "Main TCP is not reachable"

    results = []
    for item in assets:
        primary = _port_evidence(item, item.port, probes)
        node_api = None
        node_status = None
        node_status_source = None

        if item.asset_type == discovery.ASSET_NODE:
            node_api = _port_evidence(item, _node_api_port(item), probes)
            try:
                node_id = int(item.metadata.get("node_id") or item.source_id)
            except (TypeError, ValueError):
                node_id = -1
            if node_id in live_statuses:
                node_status = live_statuses[node_id]
                node_status_source = "live_api"
            else:
                node_status = str(item.metadata.get("status") or "").strip().lower()
                node_status_source = "inventory"

        results.append(
            _classify(
                item,
                checked_at=timestamp,
                primary=primary,
                node_api=node_api,
                main_api_ok=main_api_ok,
                main_api_error=main_api_error,
                node_status=node_status,
                node_status_source=node_status_source,
                node_status_refresh_error=node_status_refresh_error,
            )
        )
    return tuple(results)


def install_schema(conn) -> None:
    conn.execute(
        """CREATE TABLE IF NOT EXISTS marzban_asset_health (
            asset_key TEXT PRIMARY KEY,
            asset_type TEXT NOT NULL,
            health_state TEXT NOT NULL,
            health_reason TEXT NOT NULL,
            healthy INTEGER DEFAULT NULL,
            checked_at TEXT NOT NULL,
            state_since TEXT NOT NULL,
            last_success_at TEXT DEFAULT NULL,
            last_failure_at TEXT DEFAULT NULL,
            latency_ms REAL DEFAULT NULL,
            evidence_json TEXT NOT NULL DEFAULT '{}'
        )"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_marzban_asset_health_state "
        "ON marzban_asset_health(health_state, checked_at)"
    )


def persist_health_snapshot(
    conn,
    results: Sequence[AssetHealth],
) -> None:
    install_schema(conn)
    for result in results:
        row = conn.execute(
            """SELECT health_state, state_since, last_success_at, last_failure_at
               FROM marzban_asset_health WHERE asset_key=?""",
            (result.asset_key,),
        ).fetchone()

        state_since = (
            row[1]
            if row and row[0] == result.health_state
            else result.checked_at
        )
        last_success = row[2] if row else None
        last_failure = row[3] if row else None
        if result.healthy is True:
            last_success = result.checked_at
        elif result.healthy is False:
            last_failure = result.checked_at

        conn.execute(
            """INSERT INTO marzban_asset_health (
                   asset_key, asset_type, health_state, health_reason, healthy,
                   checked_at, state_since, last_success_at, last_failure_at,
                   latency_ms, evidence_json
               ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(asset_key) DO UPDATE SET
                   asset_type=excluded.asset_type,
                   health_state=excluded.health_state,
                   health_reason=excluded.health_reason,
                   healthy=excluded.healthy,
                   checked_at=excluded.checked_at,
                   state_since=excluded.state_since,
                   last_success_at=excluded.last_success_at,
                   last_failure_at=excluded.last_failure_at,
                   latency_ms=excluded.latency_ms,
                   evidence_json=excluded.evidence_json""",
            (
                result.asset_key,
                result.asset_type,
                result.health_state,
                result.health_reason,
                None if result.healthy is None else int(result.healthy),
                result.checked_at,
                state_since,
                last_success,
                last_failure,
                result.latency_ms,
                json.dumps(
                    dict(result.evidence),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            ),
        )


def list_health(conn) -> dict[str, dict[str, Any]]:
    install_schema(conn)
    rows = conn.execute(
        """SELECT asset_key, asset_type, health_state, health_reason, healthy,
                  checked_at, state_since, last_success_at, last_failure_at,
                  latency_ms, evidence_json
           FROM marzban_asset_health ORDER BY asset_key"""
    ).fetchall()
    return {
        row[0]: {
            "asset_type": row[1],
            "health_state": row[2],
            "health_reason": row[3],
            "healthy": None if row[4] is None else bool(row[4]),
            "checked_at": row[5],
            "state_since": row[6],
            "last_success_at": row[7],
            "last_failure_at": row[8],
            "latency_ms": row[9],
            "evidence": json.loads(row[10] or "{}"),
        }
        for row in rows
    }
