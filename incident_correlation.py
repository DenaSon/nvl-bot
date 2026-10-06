"""Pure incident correlation policy for NVL Radar V4.

This module combines already-computed differential filtering evidence with the
latest external Radar context. It performs no I/O and cannot mutate filtering,
DNS, accounts, Standby state, or failover operations.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping, Optional


CORRELATION_TARGET_SPECIFIC_FILTERING = "TARGET_SPECIFIC_FILTERING"
CORRELATION_WIDESPREAD_NETWORK_OUTAGE = "WIDESPREAD_NETWORK_OUTAGE"
CORRELATION_SHARED_NETWORK_FAILURE = "SHARED_NETWORK_FAILURE"
CORRELATION_INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"

CORRELATION_REASON_FRESH_RADAR_OUTAGE = "FRESH_RADAR_OUTAGE"
CORRELATION_REASON_DIFFERENTIAL_TARGET_SPECIFIC = "DIFFERENTIAL_TARGET_SPECIFIC"
CORRELATION_REASON_DIFFERENTIAL_SHARED = "DIFFERENTIAL_SHARED_FAILURE"
CORRELATION_REASON_NOT_ENOUGH_EVIDENCE = "NOT_ENOUGH_EVIDENCE"

DIFF_TARGET_SPECIFIC = "TARGET_SPECIFIC_REGIONAL_FAILURE"
DIFF_SHARED_FAILURE = "SHARED_REGIONAL_FAILURE"


@dataclass(frozen=True)
class IncidentCorrelationDecision:
    classification: str
    reason: str
    confidence: str
    failover_inhibited: bool
    radar_state: str
    radar_fresh: bool
    radar_age_seconds: Optional[float]
    differential_verdict: str
    differential_confirmed: bool

    def to_dict(self) -> dict:
        return {
            "classification": self.classification,
            "reason": self.reason,
            "confidence": self.confidence,
            "failover_inhibited": self.failover_inhibited,
            "radar_state": self.radar_state,
            "radar_fresh": self.radar_fresh,
            "radar_age_seconds": self.radar_age_seconds,
            "differential_verdict": self.differential_verdict,
            "differential_confirmed": self.differential_confirmed,
        }


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_timestamp(value) -> Optional[datetime]:
    raw = str(value or "").strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _age_seconds(value, *, now: datetime) -> Optional[float]:
    parsed = _parse_timestamp(value)
    if parsed is None:
        return None
    age = (now - parsed).total_seconds()
    if age < 0:
        return None
    return age


def evaluate_incident_correlation(
    *,
    differential_confirmed: bool,
    differential_verdict: str,
    radar_snapshot: Optional[Mapping],
    radar_max_age_seconds: int = 1200,
    now: Optional[datetime] = None,
) -> IncidentCorrelationDecision:
    """Correlate target-specific evidence with fresh external network context.

    V4 intentionally gives Radar only a negative safety role:
    a fresh explicit OUTAGE may inhibit automatic failover. NORMAL/DEGRADED Radar
    context never creates or strengthens a filtering verdict and stale/missing
    Radar data never blocks an otherwise-valid automatic failover.
    """

    current = now or _utc_now()
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    current = current.astimezone(timezone.utc)

    snapshot = dict(radar_snapshot or {})
    radar_state = str(snapshot.get("state") or "UNKNOWN").upper()
    radar_age = _age_seconds(snapshot.get("observed_at"), now=current)
    max_age = max(1, int(radar_max_age_seconds or 1))
    radar_fresh = radar_age is not None and radar_age <= max_age

    verdict = str(differential_verdict or "").upper()
    confirmed = bool(differential_confirmed)

    # Strong explicit external outage context wins only as an AUTO safety gate.
    # It does not rewrite the regional filtering verdict itself.
    if radar_fresh and radar_state == "OUTAGE":
        return IncidentCorrelationDecision(
            classification=CORRELATION_WIDESPREAD_NETWORK_OUTAGE,
            reason=CORRELATION_REASON_FRESH_RADAR_OUTAGE,
            confidence="HIGH",
            failover_inhibited=True,
            radar_state=radar_state,
            radar_fresh=True,
            radar_age_seconds=radar_age,
            differential_verdict=verdict,
            differential_confirmed=confirmed,
        )

    if verdict == DIFF_SHARED_FAILURE:
        return IncidentCorrelationDecision(
            classification=CORRELATION_SHARED_NETWORK_FAILURE,
            reason=CORRELATION_REASON_DIFFERENTIAL_SHARED,
            confidence="HIGH",
            failover_inhibited=True,
            radar_state=radar_state,
            radar_fresh=radar_fresh,
            radar_age_seconds=radar_age,
            differential_verdict=verdict,
            differential_confirmed=confirmed,
        )

    if confirmed and verdict == DIFF_TARGET_SPECIFIC:
        return IncidentCorrelationDecision(
            classification=CORRELATION_TARGET_SPECIFIC_FILTERING,
            reason=CORRELATION_REASON_DIFFERENTIAL_TARGET_SPECIFIC,
            confidence="HIGH",
            failover_inhibited=False,
            radar_state=radar_state,
            radar_fresh=radar_fresh,
            radar_age_seconds=radar_age,
            differential_verdict=verdict,
            differential_confirmed=True,
        )

    return IncidentCorrelationDecision(
        classification=CORRELATION_INSUFFICIENT_EVIDENCE,
        reason=CORRELATION_REASON_NOT_ENOUGH_EVIDENCE,
        confidence="LOW",
        failover_inhibited=False,
        radar_state=radar_state,
        radar_fresh=radar_fresh,
        radar_age_seconds=radar_age,
        differential_verdict=verdict,
        differential_confirmed=confirmed,
    )
