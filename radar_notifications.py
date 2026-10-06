"""Low-noise notification policy for NVL Cloudflare Radar context.

Pure policy only: no Telegram, SQLite, network, DNS, filtering, or failover I/O.
"""

from __future__ import annotations

from dataclasses import dataclass

from radar_context import (
    NETWORK_STATE_DEGRADED,
    NETWORK_STATE_NORMAL,
    NETWORK_STATE_OUTAGE,
    NETWORK_STATE_UNKNOWN,
)


NOTIFY_NONE = "NONE"
NOTIFY_DEGRADED = "DEGRADED"
NOTIFY_OUTAGE = "OUTAGE"
NOTIFY_RECOVERED = "RECOVERED"


@dataclass(frozen=True)
class RadarNotificationDecision:
    kind: str
    notify: bool
    previous_effective_state: str
    effective_state: str
    observed_state: str
    degraded_streak: int
    normal_streak: int


def _state(value: str) -> str:
    normalized = str(value or "").upper()
    if normalized in {
        NETWORK_STATE_NORMAL,
        NETWORK_STATE_DEGRADED,
        NETWORK_STATE_OUTAGE,
        NETWORK_STATE_UNKNOWN,
    }:
        return normalized
    return NETWORK_STATE_UNKNOWN


def evaluate_radar_notification(
    *,
    previous_effective_state: str,
    observed_state: str,
    degraded_streak: int = 0,
    normal_streak: int = 0,
    degraded_confirm_rounds: int = 2,
    recovery_confirm_rounds: int = 2,
) -> RadarNotificationDecision:
    """Return one transition decision without creating notification spam.

    Policy:
    - OUTAGE is strong explicit Cloudflare evidence and notifies immediately.
    - DEGRADED requires consecutive confirmation.
    - Recovery requires consecutive NORMAL evidence.
    - UNKNOWN never notifies and breaks confirmation streaks.
    - Once OUTAGE has been notified, a downgrade to DEGRADED stays effectively
      unhealthy until NORMAL recovery, preventing outage/degraded flapping spam.
    """

    previous = _state(previous_effective_state)
    observed = _state(observed_state)
    degraded_streak = max(0, int(degraded_streak or 0))
    normal_streak = max(0, int(normal_streak or 0))
    degraded_confirm_rounds = max(1, int(degraded_confirm_rounds or 1))
    recovery_confirm_rounds = max(1, int(recovery_confirm_rounds or 1))

    if observed == NETWORK_STATE_OUTAGE:
        should_notify = previous != NETWORK_STATE_OUTAGE
        return RadarNotificationDecision(
            kind=NOTIFY_OUTAGE if should_notify else NOTIFY_NONE,
            notify=should_notify,
            previous_effective_state=previous,
            effective_state=NETWORK_STATE_OUTAGE,
            observed_state=observed,
            degraded_streak=0,
            normal_streak=0,
        )

    if observed == NETWORK_STATE_DEGRADED:
        if previous == NETWORK_STATE_OUTAGE:
            return RadarNotificationDecision(
                kind=NOTIFY_NONE,
                notify=False,
                previous_effective_state=previous,
                effective_state=NETWORK_STATE_OUTAGE,
                observed_state=observed,
                degraded_streak=0,
                normal_streak=0,
            )

        next_degraded = degraded_streak + 1
        if previous == NETWORK_STATE_DEGRADED:
            return RadarNotificationDecision(
                kind=NOTIFY_NONE,
                notify=False,
                previous_effective_state=previous,
                effective_state=NETWORK_STATE_DEGRADED,
                observed_state=observed,
                degraded_streak=min(next_degraded, degraded_confirm_rounds),
                normal_streak=0,
            )

        if next_degraded >= degraded_confirm_rounds:
            return RadarNotificationDecision(
                kind=NOTIFY_DEGRADED,
                notify=True,
                previous_effective_state=previous,
                effective_state=NETWORK_STATE_DEGRADED,
                observed_state=observed,
                degraded_streak=degraded_confirm_rounds,
                normal_streak=0,
            )

        return RadarNotificationDecision(
            kind=NOTIFY_NONE,
            notify=False,
            previous_effective_state=previous,
            effective_state=previous,
            observed_state=observed,
            degraded_streak=next_degraded,
            normal_streak=0,
        )

    if observed == NETWORK_STATE_NORMAL:
        if previous in {NETWORK_STATE_OUTAGE, NETWORK_STATE_DEGRADED}:
            next_normal = normal_streak + 1
            if next_normal >= recovery_confirm_rounds:
                return RadarNotificationDecision(
                    kind=NOTIFY_RECOVERED,
                    notify=True,
                    previous_effective_state=previous,
                    effective_state=NETWORK_STATE_NORMAL,
                    observed_state=observed,
                    degraded_streak=0,
                    normal_streak=recovery_confirm_rounds,
                )
            return RadarNotificationDecision(
                kind=NOTIFY_NONE,
                notify=False,
                previous_effective_state=previous,
                effective_state=previous,
                observed_state=observed,
                degraded_streak=0,
                normal_streak=next_normal,
            )

        return RadarNotificationDecision(
            kind=NOTIFY_NONE,
            notify=False,
            previous_effective_state=previous,
            effective_state=NETWORK_STATE_NORMAL,
            observed_state=observed,
            degraded_streak=0,
            normal_streak=0,
        )

    return RadarNotificationDecision(
        kind=NOTIFY_NONE,
        notify=False,
        previous_effective_state=previous,
        effective_state=previous,
        observed_state=NETWORK_STATE_UNKNOWN,
        degraded_streak=0,
        normal_streak=0,
    )
