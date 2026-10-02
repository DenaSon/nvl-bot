"""Pure Phase 6H automatic-failover policy helpers.

This module is side-effect free. It decides whether an automatic failover attempt is
eligible and whether a Standby is sufficiently healthy to be considered. All DNS,
DB, SSH, rebuild, and rollback work remains in the Phase 6G failover engine.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional, Sequence


AUTO_FAILOVER_REASON_READY = "READY"
AUTO_FAILOVER_REASON_DISABLED = "AUTO_DISABLED"
AUTO_FAILOVER_REASON_SOURCE_NOT_DEFAULT = "SOURCE_NOT_DEFAULT"
AUTO_FAILOVER_REASON_SOURCE_IS_STANDBY = "SOURCE_IS_STANDBY"
AUTO_FAILOVER_REASON_FILTER_NOT_LIKELY = "FILTER_NOT_LIKELY"
AUTO_FAILOVER_REASON_CONFIDENCE_NOT_HIGH = "CONFIDENCE_NOT_HIGH"
AUTO_FAILOVER_REASON_DIAGNOSTIC_NOT_FILTER = "DIAGNOSTIC_NOT_FILTER"
AUTO_FAILOVER_REASON_FAILURE_STREAK_LOW = "FAILURE_STREAK_LOW"
AUTO_FAILOVER_REASON_PROVIDER_NOT_OK = "PROVIDER_NOT_OK"
AUTO_FAILOVER_REASON_SWITCH_COOLDOWN = "SWITCH_COOLDOWN_ACTIVE"
AUTO_FAILOVER_REASON_ATTEMPT_COOLDOWN = "ATTEMPT_COOLDOWN_ACTIVE"
AUTO_FAILOVER_REASON_NO_STANDBY = "NO_SAFE_STANDBY"


@dataclass(frozen=True)
class AutoFailoverDecision:
    eligible: bool
    reason: str


def evaluate_auto_failover(
    *,
    enabled: bool,
    source_is_default: bool,
    source_is_standby: bool,
    filter_state: str,
    filter_confidence: str,
    diagnostic_reason: str,
    failure_streak: int,
    confirm_threshold: int,
    provider_status: str,
    seconds_since_last_switch: int,
    switch_cooldown_seconds: int,
    seconds_since_last_attempt: int,
    attempt_cooldown_seconds: int,
    safe_standby_count: int,
) -> AutoFailoverDecision:
    """Fail-closed Phase 6H policy.

    Only high-confidence, repeatedly confirmed regional filtering on the current
    default Edge can trigger an automatic failover. Coarse traffic-anomaly signals
    are intentionally absent from this policy.
    """
    if not enabled:
        return AutoFailoverDecision(False, AUTO_FAILOVER_REASON_DISABLED)
    if not source_is_default:
        return AutoFailoverDecision(False, AUTO_FAILOVER_REASON_SOURCE_NOT_DEFAULT)
    if source_is_standby:
        return AutoFailoverDecision(False, AUTO_FAILOVER_REASON_SOURCE_IS_STANDBY)
    if str(filter_state or "").upper() != "LIKELY":
        return AutoFailoverDecision(False, AUTO_FAILOVER_REASON_FILTER_NOT_LIKELY)
    if str(filter_confidence or "").upper() != "HIGH":
        return AutoFailoverDecision(False, AUTO_FAILOVER_REASON_CONFIDENCE_NOT_HIGH)
    if str(diagnostic_reason or "").upper() != "FILTER_SUSPECTED":
        return AutoFailoverDecision(False, AUTO_FAILOVER_REASON_DIAGNOSTIC_NOT_FILTER)
    if int(failure_streak or 0) < max(1, int(confirm_threshold or 1)):
        return AutoFailoverDecision(False, AUTO_FAILOVER_REASON_FAILURE_STREAK_LOW)
    if str(provider_status or "").upper() != "OK":
        return AutoFailoverDecision(False, AUTO_FAILOVER_REASON_PROVIDER_NOT_OK)
    try:
        switch_age = float(seconds_since_last_switch)
    except (TypeError, ValueError):
        switch_age = 0.0
    try:
        attempt_age = float(seconds_since_last_attempt)
    except (TypeError, ValueError):
        attempt_age = 0.0
    if switch_age < max(0, int(switch_cooldown_seconds or 0)):
        return AutoFailoverDecision(False, AUTO_FAILOVER_REASON_SWITCH_COOLDOWN)
    if attempt_age < max(0, int(attempt_cooldown_seconds or 0)):
        return AutoFailoverDecision(False, AUTO_FAILOVER_REASON_ATTEMPT_COOLDOWN)
    if int(safe_standby_count or 0) <= 0:
        return AutoFailoverDecision(False, AUTO_FAILOVER_REASON_NO_STANDBY)
    return AutoFailoverDecision(True, AUTO_FAILOVER_REASON_READY)


def is_safe_standby_evidence(health: Mapping) -> bool:
    """Require strong persisted evidence before a Standby can be auto-selected.

    Phase 6G will still perform fresh network/preflight checks immediately before
    mutation. This is only the stricter Phase 6H candidate gate.
    """
    if not health:
        return False
    if str(health.get("filter_state") or "").upper() != "CLEAR":
        return False
    required_true = (
        "service_ok",
        "admin_ok",
        "wg_peer_ok",
        "core_path_ok",
        "external_service_ok",
    )
    return all(health.get(key) is True for key in required_true)


def rank_safe_standbys(
    standby_hosts: Sequence[str],
    health_map: Mapping[str, Mapping],
) -> tuple[str, ...]:
    """Return deterministic safe candidates, preferring lower recorded latency."""

    safe = []
    for host in standby_hosts:
        health = health_map.get(host) or {}
        if not is_safe_standby_evidence(health):
            continue
        latency = health.get("avg_latency_ms")
        try:
            latency_key = float(latency)
        except (TypeError, ValueError):
            latency_key = float("inf")
        safe.append((latency_key, str(host)))

    safe.sort(key=lambda item: (item[0], item[1]))
    return tuple(host for _latency, host in safe)
