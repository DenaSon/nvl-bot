"""V119-C pure warm-standby readiness helpers.

This module is side-effect free. Runtime code owns probing/persistence; these helpers
only decide whether a Standby has complete and fresh evidence for automatic failover.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Mapping, Sequence


READINESS_READY = "READY"
READINESS_NO_STANDBY = "NO_STANDBY"
READINESS_NO_READY = "NO_READY"

_LOCAL_TIMESTAMP_KEYS = (
    "service_last_check",
    "admin_last_check",
    "wg_last_check",
    "core_path_last_check",
    "external_service_last_check",
)


def _parse_timestamp(value):
    raw = str(value or "").strip()
    if not raw:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(raw[:19], fmt)
        except ValueError:
            pass
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def evidence_age_seconds(value, now: datetime) -> float:
    dt = _parse_timestamp(value)
    if dt is None:
        return float("inf")
    return max(0.0, (now - dt).total_seconds())


@dataclass(frozen=True)
class StandbyReadiness:
    ready: bool
    failures: tuple[str, ...]
    local_fresh: bool
    regional_fresh: bool
    regional_clear: bool


def evaluate_standby_readiness(
    health: Mapping,
    *,
    now: datetime,
    local_max_age_seconds: int,
    regional_max_age_seconds: int,
) -> StandbyReadiness:
    health = health or {}
    failures = []

    if "active" in health and health.get("active") is not True:
        failures.append("INACTIVE")

    required_true = (
        ("service_ok", "SERVICE_NOT_OK"),
        ("admin_ok", "ADMIN_NOT_OK"),
        ("wg_peer_ok", "WG_NOT_OK"),
        ("core_path_ok", "CORE_PATH_NOT_OK"),
        ("external_service_ok", "EXTERNAL_NOT_OK"),
    )
    for key, code in required_true:
        if health.get(key) is not True:
            failures.append(code)

    local_limit = max(1, int(local_max_age_seconds or 1))
    stale_local = [
        key for key in _LOCAL_TIMESTAMP_KEYS
        if evidence_age_seconds(health.get(key), now) > local_limit
    ]
    local_fresh = not stale_local
    if stale_local:
        failures.append("LOCAL_EVIDENCE_STALE:" + ",".join(stale_local))

    regional_state = str(health.get("filter_state") or "").upper()
    regional_clear = regional_state == "CLEAR"
    if not regional_clear:
        failures.append("FILTER_NOT_CLEAR")

    regional_limit = max(1, int(regional_max_age_seconds or 1))
    regional_age = evidence_age_seconds(
        health.get("regional_service_last_check"),
        now,
    )
    regional_fresh = regional_age <= regional_limit
    if not regional_fresh:
        failures.append("REGIONAL_EVIDENCE_STALE")

    return StandbyReadiness(
        ready=not failures,
        failures=tuple(failures),
        local_fresh=local_fresh,
        regional_fresh=regional_fresh,
        regional_clear=regional_clear,
    )


def rank_ready_standbys(
    standby_hosts: Sequence[str],
    health_map: Mapping[str, Mapping],
    *,
    now: datetime,
    local_max_age_seconds: int,
    regional_max_age_seconds: int,
) -> tuple[str, ...]:
    ready = []
    for host in standby_hosts:
        health = health_map.get(host) or {}
        verdict = evaluate_standby_readiness(
            health,
            now=now,
            local_max_age_seconds=local_max_age_seconds,
            regional_max_age_seconds=regional_max_age_seconds,
        )
        if not verdict.ready:
            continue
        latency = health.get("avg_latency_ms")
        try:
            latency_key = float(latency)
        except (TypeError, ValueError):
            latency_key = float("inf")
        ready.append((latency_key, str(host)))
    ready.sort(key=lambda item: (item[0], item[1]))
    return tuple(host for _latency, host in ready)


def readiness_diagnostics(
    standby_hosts: Sequence[str],
    health_map: Mapping[str, Mapping],
    *,
    now: datetime,
    local_max_age_seconds: int,
    regional_max_age_seconds: int,
) -> dict[str, tuple[str, ...]]:
    result = {}
    for host in standby_hosts:
        verdict = evaluate_standby_readiness(
            health_map.get(host) or {},
            now=now,
            local_max_age_seconds=local_max_age_seconds,
            regional_max_age_seconds=regional_max_age_seconds,
        )
        if not verdict.ready:
            result[str(host)] = verdict.failures
    return result
