"""V120-C regional filtering integration for Marzban infrastructure.

This module combines V120-A inventory + V120-B local health with provider-neutral
regional evidence. It is monitoring-only: no Telegram notifications, DNS changes,
Marzban mutations, routing changes, or failover actions.

Important semantic rule:
- Marzban Main is probed on its real public service port.
- Public Hosts are probed on customer-facing ports.
- Marzban Node control ports (62050/62051) are NEVER used as regional filtering
  targets because they may be intentionally restricted to the Main server. Node
  filtering state is derived from Public Hosts that resolve to the same node IP.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Optional, Sequence

import marzban_asset_discovery as discovery
from filtering_runtime import (
    PROVIDER_STATUS_ERROR,
    PROVIDER_STATUS_LIMITED,
    PROVIDER_STATUS_NEVER,
    PROVIDER_STATUS_OK,
    provider_backoff_until,
)
from regional_filtering import (
    REGIONAL_STATE_CLEAR,
    REGIONAL_STATE_LIKELY,
    REGIONAL_STATE_POSSIBLE,
    REGIONAL_STATE_UNKNOWN,
)


V120C_VERSION = "V120C.0-2026-10-03-marzban-regional-filtering"

REASON_DIRECT_ENDPOINTS = "DIRECT_ENDPOINTS"
REASON_DERIVED_PUBLIC_HOSTS = "DERIVED_FROM_PUBLIC_HOSTS"
REASON_LOCAL_EVIDENCE_MISSING = "LOCAL_EVIDENCE_MISSING"
REASON_LOCAL_NOT_HEALTHY = "LOCAL_NOT_HEALTHY"
REASON_NO_REGIONAL_TARGET = "NO_REGIONAL_TARGET"
REASON_NO_PUBLIC_HOST_MAPPING = "NO_PUBLIC_HOST_MAPPING"
REASON_ENDPOINT_EVIDENCE_STALE = "ENDPOINT_EVIDENCE_STALE"
REASON_PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
REASON_DISABLED = "DISABLED"


@dataclass(frozen=True)
class RegionalTarget:
    target_key: str
    host: str
    port: int
    asset_keys: tuple[str, ...]


@dataclass(frozen=True)
class AssetRegionalState:
    asset_key: str
    asset_type: str
    filter_state: str
    filter_reason: str
    checked_at: str
    evidence: Mapping[str, Any]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_text(value: Optional[datetime] = None) -> str:
    value = value or utc_now()
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_ts(value: Any) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            return datetime.fromisoformat(text[:-1] + "+00:00")
        parsed = datetime.fromisoformat(text)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def _target_key(host: str, port: int) -> str:
    return f"{host}|{int(port)}"


def _local_is_healthy(health_map: Mapping[str, Mapping[str, Any]], key: str) -> bool:
    row = health_map.get(key) or {}
    return row.get("healthy") is True


def build_probe_targets(
    assets: Sequence[discovery.MarzbanAsset],
    health_map: Mapping[str, Mapping[str, Any]],
) -> tuple[RegionalTarget, ...]:
    """Build regional targets from Main + user-facing Public Hosts only."""
    grouped: dict[tuple[str, int], set[str]] = {}

    for asset in assets:
        if asset.asset_type not in {
            discovery.ASSET_MAIN,
            discovery.ASSET_PUBLIC_HOST,
        }:
            continue
        if asset.asset_type == discovery.ASSET_PUBLIC_HOST and asset.metadata.get(
            "is_disabled"
        ) is True:
            continue
        if not _local_is_healthy(health_map, asset.asset_key):
            continue
        if asset.port is None:
            continue
        for host in asset.resolved_ips:
            grouped.setdefault((host, int(asset.port)), set()).add(asset.asset_key)

    return tuple(
        RegionalTarget(
            target_key=_target_key(host, port),
            host=host,
            port=port,
            asset_keys=tuple(sorted(keys)),
        )
        for (host, port), keys in sorted(grouped.items())
    )


def select_rotating_targets(
    targets: Sequence[RegionalTarget],
    cursor: int,
    limit: int,
) -> tuple[tuple[RegionalTarget, ...], int]:
    targets = tuple(targets)
    if not targets or limit <= 0:
        return (), 0
    count = min(len(targets), max(1, int(limit)))
    start = int(cursor or 0) % len(targets)
    selected = tuple(targets[(start + offset) % len(targets)] for offset in range(count))
    return selected, (start + count) % len(targets)


def install_schema(conn) -> None:
    conn.execute(
        """CREATE TABLE IF NOT EXISTS marzban_regional_endpoints (
            target_key TEXT PRIMARY KEY,
            target_host TEXT NOT NULL,
            target_port INTEGER NOT NULL,
            asset_keys_json TEXT NOT NULL DEFAULT '[]',
            filter_state TEXT NOT NULL DEFAULT 'UNKNOWN',
            filter_reason TEXT DEFAULT NULL,
            provider TEXT DEFAULT NULL,
            provider_status TEXT NOT NULL DEFAULT 'NEVER',
            provider_error TEXT DEFAULT NULL,
            request_id TEXT DEFAULT NULL,
            permanent_link TEXT DEFAULT NULL,
            total_nodes INTEGER DEFAULT 0,
            completed_nodes INTEGER DEFAULT 0,
            successful_nodes INTEGER DEFAULT 0,
            failed_nodes INTEGER DEFAULT 0,
            pending_nodes INTEGER DEFAULT 0,
            success_ratio REAL DEFAULT NULL,
            failed_asns_json TEXT NOT NULL DEFAULT '[]',
            failed_cities_json TEXT NOT NULL DEFAULT '[]',
            evidence_checked_at TEXT DEFAULT NULL,
            last_attempt_at TEXT DEFAULT NULL,
            updated_at TEXT NOT NULL
        )"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_marzban_regional_endpoints_state "
        "ON marzban_regional_endpoints(filter_state, evidence_checked_at)"
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS marzban_asset_regional (
            asset_key TEXT PRIMARY KEY,
            asset_type TEXT NOT NULL,
            filter_state TEXT NOT NULL,
            filter_reason TEXT NOT NULL,
            checked_at TEXT NOT NULL,
            state_since TEXT NOT NULL,
            evidence_json TEXT NOT NULL DEFAULT '{}'
        )"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_marzban_asset_regional_state "
        "ON marzban_asset_regional(filter_state, checked_at)"
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS marzban_regional_runtime (
            id INTEGER PRIMARY KEY CHECK (id=1),
            provider_status TEXT NOT NULL DEFAULT 'NEVER',
            provider_error TEXT DEFAULT NULL,
            backoff_until TEXT DEFAULT NULL,
            consecutive_limits INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL
        )"""
    )
    conn.execute(
        """INSERT OR IGNORE INTO marzban_regional_runtime (
               id, provider_status, provider_error, backoff_until,
               consecutive_limits, updated_at
           ) VALUES (1, 'NEVER', NULL, NULL, 0, ?)""",
        (utc_text(),),
    )


def sync_target_catalog(
    conn,
    targets: Sequence[RegionalTarget],
    *,
    observed_at: Optional[str] = None,
) -> None:
    install_schema(conn)
    stamp = observed_at or utc_text()
    for target in targets:
        conn.execute(
            """INSERT INTO marzban_regional_endpoints (
                   target_key, target_host, target_port, asset_keys_json,
                   filter_state, provider_status, updated_at
               ) VALUES (?, ?, ?, ?, 'UNKNOWN', 'NEVER', ?)
               ON CONFLICT(target_key) DO UPDATE SET
                   target_host=excluded.target_host,
                   target_port=excluded.target_port,
                   asset_keys_json=excluded.asset_keys_json,
                   updated_at=excluded.updated_at""",
            (
                target.target_key,
                target.host,
                target.port,
                json.dumps(list(target.asset_keys), separators=(",", ":")),
                stamp,
            ),
        )


def persist_probe_success(
    conn,
    target: RegionalTarget,
    probe: Any,
    decision: Any,
    *,
    checked_at: Optional[str] = None,
) -> None:
    install_schema(conn)
    stamp = checked_at or utc_text()
    summary = decision.summary
    conn.execute(
        """INSERT INTO marzban_regional_endpoints (
               target_key, target_host, target_port, asset_keys_json,
               filter_state, filter_reason, provider, provider_status,
               provider_error, request_id, permanent_link,
               total_nodes, completed_nodes, successful_nodes, failed_nodes,
               pending_nodes, success_ratio, failed_asns_json,
               failed_cities_json, evidence_checked_at, last_attempt_at, updated_at
           ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(target_key) DO UPDATE SET
               target_host=excluded.target_host,
               target_port=excluded.target_port,
               asset_keys_json=excluded.asset_keys_json,
               filter_state=excluded.filter_state,
               filter_reason=excluded.filter_reason,
               provider=excluded.provider,
               provider_status=excluded.provider_status,
               provider_error=NULL,
               request_id=excluded.request_id,
               permanent_link=excluded.permanent_link,
               total_nodes=excluded.total_nodes,
               completed_nodes=excluded.completed_nodes,
               successful_nodes=excluded.successful_nodes,
               failed_nodes=excluded.failed_nodes,
               pending_nodes=excluded.pending_nodes,
               success_ratio=excluded.success_ratio,
               failed_asns_json=excluded.failed_asns_json,
               failed_cities_json=excluded.failed_cities_json,
               evidence_checked_at=excluded.evidence_checked_at,
               last_attempt_at=excluded.last_attempt_at,
               updated_at=excluded.updated_at""",
        (
            target.target_key,
            target.host,
            target.port,
            json.dumps(list(target.asset_keys), separators=(",", ":")),
            decision.state,
            decision.reason,
            str(getattr(probe, "provider", "") or ""),
            PROVIDER_STATUS_OK,
            None,
            str(getattr(probe, "request_id", "") or ""),
            getattr(probe, "permanent_link", None),
            summary.total_nodes,
            summary.completed_nodes,
            summary.successful_nodes,
            summary.failed_nodes,
            summary.pending_nodes,
            summary.success_ratio,
            json.dumps(list(summary.failed_asns), separators=(",", ":")),
            json.dumps(list(summary.failed_cities), separators=(",", ":")),
            stamp,
            stamp,
            stamp,
        ),
    )


def persist_probe_attempt_error(
    conn,
    target: RegionalTarget,
    provider_status: str,
    error: str,
    *,
    attempted_at: Optional[str] = None,
) -> None:
    """Record an attempt error without destroying last trustworthy evidence."""
    install_schema(conn)
    stamp = attempted_at or utc_text()
    conn.execute(
        """INSERT INTO marzban_regional_endpoints (
               target_key, target_host, target_port, asset_keys_json,
               filter_state, filter_reason, provider_status, provider_error,
               last_attempt_at, updated_at
           ) VALUES (?,?,?,?,'UNKNOWN',?,?,?, ?,?)
           ON CONFLICT(target_key) DO UPDATE SET
               target_host=excluded.target_host,
               target_port=excluded.target_port,
               asset_keys_json=excluded.asset_keys_json,
               provider_status=excluded.provider_status,
               provider_error=excluded.provider_error,
               last_attempt_at=excluded.last_attempt_at,
               updated_at=excluded.updated_at""",
        (
            target.target_key,
            target.host,
            target.port,
            json.dumps(list(target.asset_keys), separators=(",", ":")),
            REASON_PROVIDER_UNAVAILABLE,
            provider_status,
            str(error or "")[:500],
            stamp,
            stamp,
        ),
    )


def load_endpoint_states(
    conn,
    targets: Sequence[RegionalTarget],
    *,
    now: Optional[datetime] = None,
    max_age_seconds: int = 900,
) -> dict[str, dict[str, Any]]:
    install_schema(conn)
    now = now or utc_now()
    result = {}
    for target in targets:
        row = conn.execute(
            """SELECT filter_state, filter_reason, provider, provider_status,
                      provider_error, request_id, permanent_link,
                      total_nodes, completed_nodes, successful_nodes, failed_nodes,
                      pending_nodes, success_ratio, failed_asns_json,
                      failed_cities_json, evidence_checked_at, last_attempt_at
               FROM marzban_regional_endpoints WHERE target_key=?""",
            (target.target_key,),
        ).fetchone()
        if not row:
            result[target.target_key] = {
                "filter_state": REGIONAL_STATE_UNKNOWN,
                "filter_reason": REASON_ENDPOINT_EVIDENCE_STALE,
                "fresh": False,
            }
            continue

        evidence_at = _parse_ts(row[15])
        age = float("inf")
        if evidence_at is not None:
            age = max(0.0, (now - evidence_at).total_seconds())
        fresh = age <= max(1, int(max_age_seconds))
        result[target.target_key] = {
            "filter_state": row[0] if fresh else REGIONAL_STATE_UNKNOWN,
            "filter_reason": row[1] if fresh else REASON_ENDPOINT_EVIDENCE_STALE,
            "provider": row[2],
            "provider_status": row[3],
            "provider_error": row[4],
            "request_id": row[5],
            "permanent_link": row[6],
            "total_nodes": row[7],
            "completed_nodes": row[8],
            "successful_nodes": row[9],
            "failed_nodes": row[10],
            "pending_nodes": row[11],
            "success_ratio": row[12],
            "failed_asns": json.loads(row[13] or "[]"),
            "failed_cities": json.loads(row[14] or "[]"),
            "evidence_checked_at": row[15],
            "last_attempt_at": row[16],
            "age_seconds": None if age == float("inf") else age,
            "fresh": fresh,
        }
    return result


def _aggregate_states(states: Sequence[str]) -> str:
    states = tuple(str(s or REGIONAL_STATE_UNKNOWN).upper() for s in states)
    if not states:
        return REGIONAL_STATE_UNKNOWN
    if REGIONAL_STATE_POSSIBLE in states:
        return REGIONAL_STATE_POSSIBLE
    if REGIONAL_STATE_LIKELY in states:
        if all(state == REGIONAL_STATE_LIKELY for state in states):
            return REGIONAL_STATE_LIKELY
        return REGIONAL_STATE_POSSIBLE
    if REGIONAL_STATE_CLEAR in states:
        return REGIONAL_STATE_CLEAR
    return REGIONAL_STATE_UNKNOWN


def _asset_target_keys(
    targets: Sequence[RegionalTarget],
) -> dict[str, tuple[str, ...]]:
    mapping: dict[str, list[str]] = {}
    for target in targets:
        for asset_key in target.asset_keys:
            mapping.setdefault(asset_key, []).append(target.target_key)
    return {key: tuple(sorted(values)) for key, values in mapping.items()}


def _public_hosts_for_node(
    node: discovery.MarzbanAsset,
    assets: Sequence[discovery.MarzbanAsset],
) -> tuple[str, ...]:
    node_ips = set(node.resolved_ips)
    if not node_ips:
        return ()
    keys = []
    for asset in assets:
        if asset.asset_type != discovery.ASSET_PUBLIC_HOST:
            continue
        if asset.metadata.get("is_disabled") is True:
            continue
        if node_ips.intersection(asset.resolved_ips):
            keys.append(asset.asset_key)
    return tuple(sorted(set(keys)))


def derive_asset_states(
    assets: Sequence[discovery.MarzbanAsset],
    health_map: Mapping[str, Mapping[str, Any]],
    targets: Sequence[RegionalTarget],
    endpoint_states: Mapping[str, Mapping[str, Any]],
    *,
    checked_at: Optional[str] = None,
) -> tuple[AssetRegionalState, ...]:
    stamp = checked_at or utc_text()
    target_map = _asset_target_keys(targets)
    direct_states: dict[str, AssetRegionalState] = {}
    results: list[AssetRegionalState] = []

    for asset in assets:
        if asset.asset_type == discovery.ASSET_NODE:
            continue
        local = health_map.get(asset.asset_key)
        if asset.asset_type == discovery.ASSET_PUBLIC_HOST and asset.metadata.get(
            "is_disabled"
        ) is True:
            state = AssetRegionalState(
                asset.asset_key,
                asset.asset_type,
                REGIONAL_STATE_UNKNOWN,
                REASON_DISABLED,
                stamp,
                {"local_health": local or {}, "target_keys": []},
            )
            direct_states[asset.asset_key] = state
            results.append(state)
            continue
        if not local:
            state = AssetRegionalState(
                asset.asset_key,
                asset.asset_type,
                REGIONAL_STATE_UNKNOWN,
                REASON_LOCAL_EVIDENCE_MISSING,
                stamp,
                {"local_health": {}, "target_keys": []},
            )
            direct_states[asset.asset_key] = state
            results.append(state)
            continue
        if local.get("healthy") is not True:
            state = AssetRegionalState(
                asset.asset_key,
                asset.asset_type,
                REGIONAL_STATE_UNKNOWN,
                REASON_LOCAL_NOT_HEALTHY,
                stamp,
                {
                    "local_health": local,
                    "target_keys": [],
                },
            )
            direct_states[asset.asset_key] = state
            results.append(state)
            continue

        keys = target_map.get(asset.asset_key, ())
        if not keys:
            state = AssetRegionalState(
                asset.asset_key,
                asset.asset_type,
                REGIONAL_STATE_UNKNOWN,
                REASON_NO_REGIONAL_TARGET,
                stamp,
                {"local_health": local, "target_keys": []},
            )
            direct_states[asset.asset_key] = state
            results.append(state)
            continue

        endpoint_rows = [dict(endpoint_states.get(key) or {}) for key in keys]
        aggregate = _aggregate_states(
            [row.get("filter_state", REGIONAL_STATE_UNKNOWN) for row in endpoint_rows]
        )
        state = AssetRegionalState(
            asset.asset_key,
            asset.asset_type,
            aggregate,
            REASON_DIRECT_ENDPOINTS,
            stamp,
            {
                "local_health": local,
                "target_keys": list(keys),
                "endpoints": {
                    key: dict(endpoint_states.get(key) or {})
                    for key in keys
                },
            },
        )
        direct_states[asset.asset_key] = state
        results.append(state)

    for node in (a for a in assets if a.asset_type == discovery.ASSET_NODE):
        local = health_map.get(node.asset_key)
        if str((local or {}).get("health_state") or "").upper() == "DISABLED":
            results.append(
                AssetRegionalState(
                    node.asset_key,
                    node.asset_type,
                    REGIONAL_STATE_UNKNOWN,
                    REASON_DISABLED,
                    stamp,
                    {"local_health": local or {}, "public_host_assets": []},
                )
            )
            continue
        if not local:
            results.append(
                AssetRegionalState(
                    node.asset_key,
                    node.asset_type,
                    REGIONAL_STATE_UNKNOWN,
                    REASON_LOCAL_EVIDENCE_MISSING,
                    stamp,
                    {"local_health": {}, "public_host_assets": []},
                )
            )
            continue
        if local.get("healthy") is not True:
            results.append(
                AssetRegionalState(
                    node.asset_key,
                    node.asset_type,
                    REGIONAL_STATE_UNKNOWN,
                    REASON_LOCAL_NOT_HEALTHY,
                    stamp,
                    {"local_health": local, "public_host_assets": []},
                )
            )
            continue

        source_keys = _public_hosts_for_node(node, assets)
        source_states = [
            direct_states[key]
            for key in source_keys
            if key in direct_states
        ]
        if not source_states:
            results.append(
                AssetRegionalState(
                    node.asset_key,
                    node.asset_type,
                    REGIONAL_STATE_UNKNOWN,
                    REASON_NO_PUBLIC_HOST_MAPPING,
                    stamp,
                    {
                        "local_health": local,
                        "public_host_assets": list(source_keys),
                    },
                )
            )
            continue

        results.append(
            AssetRegionalState(
                node.asset_key,
                node.asset_type,
                _aggregate_states([state.filter_state for state in source_states]),
                REASON_DERIVED_PUBLIC_HOSTS,
                stamp,
                {
                    "local_health": local,
                    "public_host_assets": [
                        {
                            "asset_key": state.asset_key,
                            "filter_state": state.filter_state,
                            "filter_reason": state.filter_reason,
                        }
                        for state in source_states
                    ],
                },
            )
        )

    return tuple(sorted(results, key=lambda item: item.asset_key))


def persist_asset_states(
    conn,
    states: Sequence[AssetRegionalState],
) -> None:
    install_schema(conn)
    for state in states:
        row = conn.execute(
            "SELECT filter_state, state_since FROM marzban_asset_regional WHERE asset_key=?",
            (state.asset_key,),
        ).fetchone()
        state_since = (
            row[1]
            if row and row[0] == state.filter_state
            else state.checked_at
        )
        conn.execute(
            """INSERT INTO marzban_asset_regional (
                   asset_key, asset_type, filter_state, filter_reason,
                   checked_at, state_since, evidence_json
               ) VALUES (?,?,?,?,?,?,?)
               ON CONFLICT(asset_key) DO UPDATE SET
                   asset_type=excluded.asset_type,
                   filter_state=excluded.filter_state,
                   filter_reason=excluded.filter_reason,
                   checked_at=excluded.checked_at,
                   state_since=excluded.state_since,
                   evidence_json=excluded.evidence_json""",
            (
                state.asset_key,
                state.asset_type,
                state.filter_state,
                state.filter_reason,
                state.checked_at,
                state_since,
                json.dumps(
                    dict(state.evidence),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            ),
        )


def list_asset_states(conn) -> dict[str, dict[str, Any]]:
    install_schema(conn)
    rows = conn.execute(
        """SELECT asset_key, asset_type, filter_state, filter_reason,
                  checked_at, state_since, evidence_json
           FROM marzban_asset_regional ORDER BY asset_key"""
    ).fetchall()
    return {
        row[0]: {
            "asset_type": row[1],
            "filter_state": row[2],
            "filter_reason": row[3],
            "checked_at": row[4],
            "state_since": row[5],
            "evidence": json.loads(row[6] or "{}"),
        }
        for row in rows
    }


def get_runtime(conn) -> dict[str, Any]:
    install_schema(conn)
    row = conn.execute(
        """SELECT provider_status, provider_error, backoff_until,
                  consecutive_limits, updated_at
           FROM marzban_regional_runtime WHERE id=1"""
    ).fetchone()
    return {
        "provider_status": row[0] if row else PROVIDER_STATUS_NEVER,
        "provider_error": row[1] if row else None,
        "backoff_until": row[2] if row else None,
        "consecutive_limits": int(row[3] or 0) if row else 0,
        "updated_at": row[4] if row else None,
    }


def backoff_remaining_seconds(
    conn,
    *,
    now: Optional[datetime] = None,
) -> int:
    runtime = get_runtime(conn)
    until = _parse_ts(runtime.get("backoff_until"))
    now = now or utc_now()
    if until is None:
        return 0
    return max(0, int((until - now).total_seconds()))


def record_provider_ok(conn, *, now: Optional[datetime] = None) -> None:
    install_schema(conn)
    stamp = utc_text(now)
    conn.execute(
        """UPDATE marzban_regional_runtime
           SET provider_status=?, provider_error=NULL, backoff_until=NULL,
               consecutive_limits=0, updated_at=?
           WHERE id=1""",
        (PROVIDER_STATUS_OK, stamp),
    )


def record_provider_limited(
    conn,
    error: str,
    *,
    now: Optional[datetime] = None,
    base_seconds: int = 300,
    max_seconds: int = 3600,
) -> int:
    install_schema(conn)
    now = now or utc_now()
    runtime = get_runtime(conn)
    count = int(runtime.get("consecutive_limits") or 0) + 1
    until = provider_backoff_until(
        now,
        count,
        base_seconds=base_seconds,
        max_seconds=max_seconds,
    )
    conn.execute(
        """UPDATE marzban_regional_runtime
           SET provider_status=?, provider_error=?, backoff_until=?,
               consecutive_limits=?, updated_at=?
           WHERE id=1""",
        (
            PROVIDER_STATUS_LIMITED,
            str(error or "")[:500],
            utc_text(until),
            count,
            utc_text(now),
        ),
    )
    return max(0, int((until - now).total_seconds()))


def record_provider_error(
    conn,
    error: str,
    *,
    now: Optional[datetime] = None,
    backoff_seconds: int = 300,
) -> int:
    install_schema(conn)
    now = now or utc_now()
    until = now + timedelta(seconds=max(1, int(backoff_seconds)))
    runtime = get_runtime(conn)
    conn.execute(
        """UPDATE marzban_regional_runtime
           SET provider_status=?, provider_error=?, backoff_until=?,
               consecutive_limits=?, updated_at=?
           WHERE id=1""",
        (
            PROVIDER_STATUS_ERROR,
            str(error or "")[:500],
            utc_text(until),
            int(runtime.get("consecutive_limits") or 0),
            utc_text(now),
        ),
    )
    return max(0, int((until - now).total_seconds()))
