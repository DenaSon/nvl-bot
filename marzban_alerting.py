"""Low-noise, group-only Telegram delivery policy for Marzban filtering events.

This module changes only notification eligibility; regional probing, classification,
history, and Marzban/Xray operations remain untouched. A POSSIBLE alert needs
three DISTINCT fresh Check-Host evidence revisions, not three scheduler ticks.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Optional, Sequence

import marzban_asset_discovery as discovery
import marzban_observability as obs
import marzban_regional_filtering as regional
from regional_filtering import REGIONAL_STATE_CLEAR, REGIONAL_STATE_LIKELY, REGIONAL_STATE_POSSIBLE


def install_schema(conn) -> None:
    conn.execute(
        """CREATE TABLE IF NOT EXISTS marzban_alert_confirmations (
            asset_key TEXT PRIMARY KEY,
            evidence_signature TEXT NOT NULL,
            evidence_at TEXT NOT NULL,
            consecutive_count INTEGER NOT NULL
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS marzban_alert_suppressed (
            event_id INTEGER PRIMARY KEY,
            reason TEXT NOT NULL,
            suppressed_at TEXT NOT NULL
        )"""
    )


def _stamp(value: Optional[str]) -> Optional[datetime]:
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _fresh_signature(state: regional.AssetRegionalState) -> Optional[str]:
    """Use only fresh, individually timestamped provider evidence.

    A cached result reused during subsequent five-minute scheduler cycles
    never counts as a second independent observation.
    """
    endpoints = state.evidence.get("endpoints") if isinstance(state.evidence, dict) else None
    if not isinstance(endpoints, dict):
        return None
    relevant = []
    for key, row in sorted(endpoints.items()):
        if not isinstance(row, dict) or row.get("fresh") is not True:
            continue
        if str(row.get("filter_state") or "").upper() not in (
            REGIONAL_STATE_POSSIBLE, REGIONAL_STATE_LIKELY,
        ):
            continue
        checked = str(row.get("evidence_checked_at") or "").strip()
        if _stamp(checked) is None:
            continue
        relevant.append((str(key), str(row.get("filter_state")), checked))
    return json.dumps(relevant, separators=(",", ":"), sort_keys=True) if relevant else None


def observe_regional_scan(conn, states: Sequence[regional.AssetRegionalState]) -> None:
    """Maintain confirmation counters without modifying the monitoring verdicts."""
    install_schema(conn)
    for state in states:
        # Node verdicts are derived from public hosts, not independent witnesses.
        if state.asset_type == discovery.ASSET_NODE:
            continue
        if state.filter_state != REGIONAL_STATE_POSSIBLE:
            conn.execute(
                "DELETE FROM marzban_alert_confirmations WHERE asset_key=?",
                (state.asset_key,),
            )
            continue
        signature = _fresh_signature(state)
        if not signature:
            # An evidence gap breaks consecutiveness; it must not confirm a warning.
            conn.execute(
                "DELETE FROM marzban_alert_confirmations WHERE asset_key=?",
                (state.asset_key,),
            )
            continue
        prior = conn.execute(
            "SELECT evidence_signature, consecutive_count FROM marzban_alert_confirmations WHERE asset_key=?",
            (state.asset_key,),
        ).fetchone()
        if prior and prior[0] == signature:
            continue
        count = min(1000, int(prior[1]) + 1) if prior else 1
        conn.execute(
            """INSERT INTO marzban_alert_confirmations (
                   asset_key, evidence_signature, evidence_at, consecutive_count
               ) VALUES (?,?,?,?)
               ON CONFLICT(asset_key) DO UPDATE SET
                   evidence_signature=excluded.evidence_signature,
                   evidence_at=excluded.evidence_at,
                   consecutive_count=excluded.consecutive_count""",
            (state.asset_key, signature, state.checked_at, count),
        )


def _has_notified_warning(conn, recovery: obs.MonitorEvent) -> bool:
    # Require the warning from THIS incident to have been delivered. An older
    # warning must not turn a new, unannounced transient into recovery spam.
    row = conn.execute(
        """SELECT notified_at FROM marzban_monitor_events
           WHERE asset_key=? AND transition_kind='WARNING' AND event_id<?
           ORDER BY event_id DESC LIMIT 1""",
        (recovery.asset_key, recovery.event_id),
    ).fetchone()
    return bool(row and row[0])


def _within_cooldown(conn, event: obs.MonitorEvent, cutoff: datetime) -> bool:
    """Silence repeated same-severity flaps, but never suppress a new incident
    after a confirmed, delivered recovery.
    """
    row = conn.execute(
        """SELECT notified_at FROM marzban_monitor_events
           WHERE asset_key=? AND transition_kind=?
             AND notified_at IS NOT NULL
           ORDER BY event_id DESC LIMIT 1""",
        (event.asset_key, event.transition_kind),
    ).fetchone()
    last = _stamp(row[0]) if row else None
    if not last or last < cutoff:
        return False
    recovered = conn.execute(
        """SELECT notified_at FROM marzban_monitor_events
           WHERE asset_key=? AND transition_kind='RECOVERED'
             AND notified_at IS NOT NULL
           ORDER BY event_id DESC LIMIT 1""",
        (event.asset_key,),
    ).fetchone()
    recovered_at = _stamp(recovered[0]) if recovered else None
    return recovered_at is None or recovered_at <= last


def prepare_delivery(
    conn,
    *,
    confirm_scans: int = 3,
    cooldown_minutes: int = 60,
    now: Optional[datetime] = None,
    outbox_limit: int = 500,
    message_limit: int = 12,
) -> tuple[tuple[obs.MonitorEvent, ...], tuple[tuple[int, str], ...]]:
    """Return eligible events and explicit suppression decisions.

    Deferred POSSIBLE events remain pending. Suppressed events have an audit
    record in marzban_alert_suppressed, not a misleading notified_at timestamp.
    """
    install_schema(conn)
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=max(1, int(cooldown_minutes)))
    sent = []
    suppressed = []
    # Exclude already suppressed rows BEFORE LIMIT, avoiding outbox starvation.
    rows = conn.execute(
        """SELECT event_id, asset_key, asset_type, asset_name, address,
                  previous_state, current_state, transition_kind,
                  filter_reason, created_at, evidence_json
           FROM marzban_monitor_events e
           WHERE notified_at IS NULL AND transition_kind != 'DEGRADED'
             AND COALESCE(previous_state, '') != 'UNKNOWN'
             AND NOT EXISTS (
                 SELECT 1 FROM marzban_alert_suppressed s WHERE s.event_id=e.event_id
             )
           ORDER BY CASE WHEN transition_kind='CRITICAL' THEN 0 ELSE 1 END,
                    event_id LIMIT ?""",
        (max(1, int(outbox_limit)),),
    ).fetchall()
    events = tuple(obs._row_to_event(row) for row in rows)
    for event in events:
        if conn.execute(
            "SELECT 1 FROM marzban_alert_suppressed WHERE event_id=?",
            (event.event_id,),
        ).fetchone():
            continue
        # Derived NODE alerts duplicate their source PUBLIC HOST monitoring.
        if (event.asset_type == discovery.ASSET_NODE
                and event.filter_reason == regional.REASON_DERIVED_PUBLIC_HOSTS):
            suppressed.append((event.event_id, "DERIVED_NODE_DUPLICATE"))
            continue

        current = conn.execute(
            "SELECT last_actionable_state FROM marzban_monitor_state WHERE asset_key=?",
            (event.asset_key,),
        ).fetchone()
        current_state = str(current[0]) if current else None

        if event.transition_kind == obs.TRANSITION_WARNING:
            if current_state != REGIONAL_STATE_POSSIBLE:
                suppressed.append((event.event_id, "STALE_POSSIBLE"))
                continue
            streak = conn.execute(
                "SELECT consecutive_count FROM marzban_alert_confirmations WHERE asset_key=?",
                (event.asset_key,),
            ).fetchone()
            if not streak or int(streak[0]) < max(1, int(confirm_scans)):
                continue  # pending, NOT delivered or discarded
            if _within_cooldown(conn, event, cutoff):
                suppressed.append((event.event_id, "WARNING_COOLDOWN"))
                continue

        elif event.transition_kind == obs.TRANSITION_RECOVERED:
            if current_state != REGIONAL_STATE_CLEAR:
                suppressed.append((event.event_id, "STALE_RECOVERY"))
                continue
            if (event.previous_state != REGIONAL_STATE_LIKELY
                    and not _has_notified_warning(conn, event)):
                suppressed.append((event.event_id, "UNANNOUNCED_WARNING_RECOVERY"))
                continue

        elif event.transition_kind == obs.TRANSITION_CRITICAL:
            if _within_cooldown(conn, event, cutoff):
                suppressed.append((event.event_id, "CRITICAL_COOLDOWN"))
                continue
        else:
            suppressed.append((event.event_id, "NOT_ACTIONABLE"))
            continue

        if len(sent) < max(1, min(12, int(message_limit))):
            sent.append(event)
    return tuple(sent), tuple(suppressed)


def mark_suppressed(conn, reasons: Sequence[tuple[int, str]]) -> None:
    install_schema(conn)
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    conn.executemany(
        """INSERT OR IGNORE INTO marzban_alert_suppressed
           (event_id, reason, suppressed_at) VALUES (?,?,?)""",
        [(int(event_id), str(reason), now) for event_id, reason in reasons],
    )
