"""Phase 6F runtime policy primitives.

Pure helpers used by the Telegram bot runtime for:
- provider backoff;
- state-transition notification policy;
- stable state labels.

This module intentionally performs no I/O and no operational failover actions.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from regional_filtering import (
    REGIONAL_STATE_CLEAR,
    REGIONAL_STATE_LIKELY,
    REGIONAL_STATE_POSSIBLE,
    REGIONAL_STATE_UNKNOWN,
)


PROVIDER_STATUS_NEVER = "NEVER"
PROVIDER_STATUS_OK = "OK"
PROVIDER_STATUS_LIMITED = "LIMITED"
PROVIDER_STATUS_ERROR = "ERROR"


def provider_error_alert_due(
    consecutive_errors: int,
    *,
    seconds_since_last_alert: Optional[float] = None,
    threshold: int = 3,
    repeat_seconds: int = 1800,
) -> bool:
    """Return whether a provider-error notification should be emitted.

    Provider health is intentionally separate from Edge filtering state. A transient
    transport/API failure is logged immediately, but Telegram notifications require
    a consecutive-error threshold and are rate-limited while the outage persists.
    """
    errors = max(0, int(consecutive_errors or 0))
    threshold = max(1, int(threshold))
    if errors < threshold:
        return False
    if seconds_since_last_alert is None:
        return True
    try:
        age = float(seconds_since_last_alert)
    except (TypeError, ValueError):
        return True
    return age >= max(1, int(repeat_seconds))


def provider_recovery_ready(
    previous_status: Optional[str],
    consecutive_successes: int,
    *,
    threshold: int = 2,
) -> bool:
    """Require stable evidence before declaring a degraded provider recovered."""
    previous = str(previous_status or PROVIDER_STATUS_NEVER).upper()
    if previous not in {PROVIDER_STATUS_ERROR, PROVIDER_STATUS_LIMITED}:
        return True
    return max(0, int(consecutive_successes or 0)) >= max(1, int(threshold))

TRANSITION_NONE = "NONE"
TRANSITION_WARNING = "WARNING"
TRANSITION_CRITICAL = "CRITICAL"
TRANSITION_RECOVERED = "RECOVERED"
TRANSITION_DEGRADED = "DEGRADED"


@dataclass(frozen=True)
class FilterTransition:
    kind: str
    previous_state: str
    current_state: str

    @property
    def notify(self) -> bool:
        return self.kind != TRANSITION_NONE


def normalize_filter_state(value) -> str:
    value = str(value or "").upper()
    if value in {
        REGIONAL_STATE_UNKNOWN,
        REGIONAL_STATE_CLEAR,
        REGIONAL_STATE_POSSIBLE,
        REGIONAL_STATE_LIKELY,
    }:
        return value
    return REGIONAL_STATE_UNKNOWN


def classify_filter_transition(
    previous_state: Optional[str],
    current_state: Optional[str],
    *,
    notify_initial: bool = False,
) -> FilterTransition:
    """Return a transition category suitable for admin notifications.

    Initial DB population is quiet by default to avoid a burst of messages after
    deploy. Subsequent meaningful transitions are notified.
    """
    previous_missing = previous_state is None or str(previous_state).strip() == ""
    previous = normalize_filter_state(previous_state)
    current = normalize_filter_state(current_state)

    if previous_missing and not notify_initial:
        return FilterTransition(TRANSITION_NONE, previous, current)

    if previous == current:
        return FilterTransition(TRANSITION_NONE, previous, current)

    if current == REGIONAL_STATE_LIKELY:
        return FilterTransition(TRANSITION_CRITICAL, previous, current)

    if current == REGIONAL_STATE_POSSIBLE:
        if previous == REGIONAL_STATE_LIKELY:
            # Still unhealthy, but severity has dropped. Do not call it recovered
            # until a qualified CLEAR transition is observed.
            return FilterTransition(TRANSITION_WARNING, previous, current)
        return FilterTransition(TRANSITION_WARNING, previous, current)

    if current == REGIONAL_STATE_CLEAR:
        if previous in {REGIONAL_STATE_POSSIBLE, REGIONAL_STATE_LIKELY}:
            return FilterTransition(TRANSITION_RECOVERED, previous, current)
        return FilterTransition(TRANSITION_NONE, previous, current)

    if current == REGIONAL_STATE_UNKNOWN:
        if previous in {REGIONAL_STATE_POSSIBLE, REGIONAL_STATE_LIKELY}:
            return FilterTransition(TRANSITION_DEGRADED, previous, current)
        return FilterTransition(TRANSITION_NONE, previous, current)

    return FilterTransition(TRANSITION_NONE, previous, current)


def provider_backoff_seconds(
    consecutive_limits: int,
    *,
    base_seconds: int = 300,
    max_seconds: int = 3600,
) -> int:
    """Exponential backoff for Check-Host limit exhaustion.

    count=1 -> base, count=2 -> base*2, then doubles up to max_seconds.
    """
    count = max(1, int(consecutive_limits or 1))
    base = max(1, int(base_seconds))
    cap = max(base, int(max_seconds))
    return min(cap, base * (2 ** (count - 1)))


def provider_backoff_until(
    now: datetime,
    consecutive_limits: int,
    *,
    base_seconds: int = 300,
    max_seconds: int = 3600,
) -> datetime:
    return now + timedelta(
        seconds=provider_backoff_seconds(
            consecutive_limits,
            base_seconds=base_seconds,
            max_seconds=max_seconds,
        )
    )
