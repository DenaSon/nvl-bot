"""V120-D transition alerts and operator observability for Marzban monitoring.

Inventory stays complete for audit/debugging, while the operator monitor only
shows actionable assets. UNKNOWN means evidence is unavailable/stale and is not
treated as a filtering transition.
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence

import marzban_asset_discovery as discovery
import marzban_local_health as local_health
import marzban_regional_filtering as regional
from regional_filtering import (
    REGIONAL_STATE_CLEAR,
    REGIONAL_STATE_LIKELY,
    REGIONAL_STATE_POSSIBLE,
    REGIONAL_STATE_UNKNOWN,
)


V120D_VERSION = "V120D.2-2026-10-04-clean-monitoring-data"

TRANSITION_NONE = "NONE"
TRANSITION_WARNING = "WARNING"
TRANSITION_CRITICAL = "CRITICAL"
TRANSITION_RECOVERED = "RECOVERED"
# Kept only so legacy DB rows remain readable. V120D.2 no longer creates it.
TRANSITION_DEGRADED = "DEGRADED"

ACTIONABLE_STATES = frozenset(
    {
        REGIONAL_STATE_CLEAR,
        REGIONAL_STATE_POSSIBLE,
        REGIONAL_STATE_LIKELY,
    }
)


@dataclass(frozen=True)
class Transition:
    kind: str
    previous_state: Optional[str]
    current_state: str

    @property
    def notify(self) -> bool:
        return self.kind != TRANSITION_NONE


@dataclass(frozen=True)
class MonitorEvent:
    event_id: int
    asset_key: str
    asset_type: str
    asset_name: str
    address: str
    previous_state: Optional[str]
    current_state: str
    transition_kind: str
    filter_reason: str
    created_at: str
    evidence: Mapping[str, Any]


def classify_transition(
    previous_state: Optional[str],
    current_state: Optional[str],
) -> Transition:
    current = str(current_state or REGIONAL_STATE_UNKNOWN).strip().upper()
    previous_raw = str(previous_state or "").strip().upper()

    # UNKNOWN is evidence coverage, not a filtering verdict.
    if current == REGIONAL_STATE_UNKNOWN:
        previous = previous_raw or None
        return Transition(TRANSITION_NONE, previous, current)

    previous = (
        None
        if not previous_raw or previous_raw == REGIONAL_STATE_UNKNOWN
        else previous_raw
    )

    if previous == current:
        return Transition(TRANSITION_NONE, previous, current)

    if previous is None:
        if current == REGIONAL_STATE_LIKELY:
            return Transition(TRANSITION_CRITICAL, None, current)
        if current == REGIONAL_STATE_POSSIBLE:
            return Transition(TRANSITION_WARNING, None, current)
        return Transition(TRANSITION_NONE, None, current)

    if current == REGIONAL_STATE_LIKELY:
        return Transition(TRANSITION_CRITICAL, previous, current)

    if current == REGIONAL_STATE_POSSIBLE:
        return Transition(TRANSITION_WARNING, previous, current)

    if (
        current == REGIONAL_STATE_CLEAR
        and previous in {REGIONAL_STATE_POSSIBLE, REGIONAL_STATE_LIKELY}
    ):
        return Transition(TRANSITION_RECOVERED, previous, current)

    return Transition(TRANSITION_NONE, previous, current)


def install_schema(conn) -> None:
    conn.execute(
        """CREATE TABLE IF NOT EXISTS marzban_monitor_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_key TEXT NOT NULL,
            asset_type TEXT NOT NULL,
            asset_name TEXT NOT NULL,
            address TEXT NOT NULL,
            previous_state TEXT DEFAULT NULL,
            current_state TEXT NOT NULL,
            transition_kind TEXT NOT NULL,
            filter_reason TEXT NOT NULL,
            created_at TEXT NOT NULL,
            evidence_json TEXT NOT NULL DEFAULT '{}',
            notified_at TEXT DEFAULT NULL
        )"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_marzban_monitor_events_asset_time "
        "ON marzban_monitor_events(asset_key, created_at DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_marzban_monitor_events_pending "
        "ON marzban_monitor_events(notified_at, event_id)"
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS marzban_monitor_state (
            asset_key TEXT PRIMARY KEY,
            last_actionable_state TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )"""
    )

    # Upgrade path: recover the last meaningful verdict from existing event history
    # before considering current regional rows (which may currently be UNKNOWN/stale).
    conn.execute(
        """INSERT OR IGNORE INTO marzban_monitor_state (
               asset_key, last_actionable_state, updated_at
           )
           SELECT e.asset_key, e.current_state, e.created_at
           FROM marzban_monitor_events e
           JOIN (
               SELECT asset_key, MAX(event_id) AS max_event_id
               FROM marzban_monitor_events
               WHERE current_state IN ('CLEAR','POSSIBLE','LIKELY')
                 AND transition_kind != 'DEGRADED'
               GROUP BY asset_key
           ) latest ON latest.max_event_id=e.event_id"""
    )
    regional.install_schema(conn)
    conn.execute(
        """INSERT OR IGNORE INTO marzban_monitor_state (
               asset_key, last_actionable_state, updated_at
           )
           SELECT asset_key, filter_state, checked_at
           FROM marzban_asset_regional
           WHERE filter_state IN ('CLEAR','POSSIBLE','LIKELY')"""
    )


def _existing_states(conn) -> dict[str, str]:
    install_schema(conn)
    rows = conn.execute(
        "SELECT asset_key, last_actionable_state FROM marzban_monitor_state"
    ).fetchall()
    result = {row[0]: str(row[1]) for row in rows}

    # Supports tests/upgrade races where regional state was written after schema init.
    for key, value in conn.execute(
        """SELECT asset_key, filter_state
           FROM marzban_asset_regional
           WHERE filter_state IN ('CLEAR','POSSIBLE','LIKELY')"""
    ).fetchall():
        result.setdefault(key, str(value))
    return result


def _set_actionable_state(conn, asset_key: str, state: str, stamp: str) -> None:
    conn.execute(
        """INSERT INTO marzban_monitor_state (
               asset_key, last_actionable_state, updated_at
           ) VALUES (?,?,?)
           ON CONFLICT(asset_key) DO UPDATE SET
               last_actionable_state=excluded.last_actionable_state,
               updated_at=excluded.updated_at""",
        (asset_key, state, stamp),
    )


def _is_monitorable_asset(
    asset: discovery.MarzbanAsset,
    health_map: Mapping[str, Mapping[str, Any]],
) -> bool:
    if (
        asset.asset_type == discovery.ASSET_PUBLIC_HOST
        and asset.metadata.get("is_disabled") is True
    ):
        return False
    local = health_map.get(asset.asset_key) or {}
    if (
        asset.asset_type == discovery.ASSET_NODE
        and str(local.get("health_state") or "").upper() == local_health.STATE_DISABLED
    ):
        return False
    return True


def record_state_transitions(
    conn,
    assets: Sequence[discovery.MarzbanAsset],
    new_states: Sequence[regional.AssetRegionalState],
    health_map: Mapping[str, Mapping[str, Any]],
) -> tuple[MonitorEvent, ...]:
    """Record only actionable filtering transitions.

    UNKNOWN does not overwrite the last actionable baseline. This prevents
    LIKELY -> UNKNOWN(stale/provider gap) -> LIKELY from creating false recovery
    or duplicate critical events.
    """
    install_schema(conn)
    previous = _existing_states(conn)
    asset_map = {item.asset_key: item for item in assets}
    created: list[MonitorEvent] = []

    for state in new_states:
        asset = asset_map.get(state.asset_key)
        if asset is not None and not _is_monitorable_asset(asset, health_map):
            continue

        current = str(state.filter_state or REGIONAL_STATE_UNKNOWN).upper()
        if current not in ACTIONABLE_STATES:
            continue

        transition = classify_transition(previous.get(state.asset_key), current)
        _set_actionable_state(conn, state.asset_key, current, state.checked_at)
        previous[state.asset_key] = current

        if not transition.notify:
            continue

        name = asset.name if asset else state.asset_key
        address = asset.address if asset else ""
        evidence = {
            "regional": dict(state.evidence),
            "local_health": dict(health_map.get(state.asset_key) or {}),
        }
        cursor = conn.execute(
            """INSERT INTO marzban_monitor_events (
                   asset_key, asset_type, asset_name, address,
                   previous_state, current_state, transition_kind,
                   filter_reason, created_at, evidence_json, notified_at
               ) VALUES (?,?,?,?,?,?,?,?,?,?,NULL)""",
            (
                state.asset_key,
                state.asset_type,
                name,
                address,
                transition.previous_state,
                current,
                transition.kind,
                state.filter_reason,
                state.checked_at,
                json.dumps(
                    evidence,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            ),
        )
        created.append(
            MonitorEvent(
                event_id=int(cursor.lastrowid),
                asset_key=state.asset_key,
                asset_type=state.asset_type,
                asset_name=name,
                address=address,
                previous_state=transition.previous_state,
                current_state=current,
                transition_kind=transition.kind,
                filter_reason=state.filter_reason,
                created_at=state.checked_at,
                evidence=evidence,
            )
        )
    return tuple(created)


def _row_to_event(row) -> MonitorEvent:
    return MonitorEvent(
        event_id=int(row[0]),
        asset_key=row[1],
        asset_type=row[2],
        asset_name=row[3],
        address=row[4],
        previous_state=row[5],
        current_state=row[6],
        transition_kind=row[7],
        filter_reason=row[8],
        created_at=row[9],
        evidence=json.loads(row[10] or "{}"),
    )


def pending_notifications(conn, limit: int = 20) -> tuple[MonitorEvent, ...]:
    install_schema(conn)
    rows = conn.execute(
        """SELECT event_id, asset_key, asset_type, asset_name, address,
                  previous_state, current_state, transition_kind,
                  filter_reason, created_at, evidence_json
           FROM marzban_monitor_events
           WHERE notified_at IS NULL
             AND transition_kind != 'DEGRADED'
             AND COALESCE(previous_state, '') != 'UNKNOWN'
           ORDER BY event_id
           LIMIT ?""",
        (max(1, int(limit)),),
    ).fetchall()
    return tuple(_row_to_event(row) for row in rows)


def mark_notified(
    conn,
    event_ids: Sequence[int],
    *,
    notified_at: Optional[str] = None,
) -> None:
    install_schema(conn)
    ids = tuple(sorted({int(value) for value in event_ids if int(value) > 0}))
    if not ids:
        return
    stamp = notified_at or regional.utc_text()
    placeholders = ",".join("?" for _ in ids)
    conn.execute(
        f"UPDATE marzban_monitor_events SET notified_at=? "
        f"WHERE event_id IN ({placeholders})",
        (stamp, *ids),
    )


def recent_events(conn, limit: int = 10) -> tuple[MonitorEvent, ...]:
    """Return meaningful legacy/current events, hiding old UNKNOWN churn."""
    install_schema(conn)
    rows = conn.execute(
        """SELECT event_id, asset_key, asset_type, asset_name, address,
                  previous_state, current_state, transition_kind,
                  filter_reason, created_at, evidence_json
           FROM marzban_monitor_events
           WHERE transition_kind != 'DEGRADED'
             AND COALESCE(previous_state, '') != 'UNKNOWN'
           ORDER BY event_id DESC
           LIMIT ?""",
        (max(1, int(limit)),),
    ).fetchall()
    return tuple(_row_to_event(row) for row in rows)


def _state_icon(state: str) -> str:
    return {
        REGIONAL_STATE_CLEAR: "🟢",
        REGIONAL_STATE_POSSIBLE: "🟡",
        REGIONAL_STATE_LIKELY: "🔴",
        REGIONAL_STATE_UNKNOWN: "⚪️",
    }.get(str(state or "").upper(), "⚪️")


def _transition_icon(kind: str) -> str:
    return {
        TRANSITION_WARNING: "🟡",
        TRANSITION_CRITICAL: "🔴",
        TRANSITION_RECOVERED: "🟢",
        TRANSITION_DEGRADED: "⚪️",
    }.get(kind, "ℹ️")


def _type_label(asset_type: str) -> str:
    return {
        discovery.ASSET_MAIN: "MAIN",
        discovery.ASSET_NODE: "NODE",
        discovery.ASSET_PUBLIC_HOST: "PUBLIC HOST",
    }.get(asset_type, asset_type)


def render_alert_digest(events: Sequence[MonitorEvent]) -> str:
    events = tuple(events)
    if not events:
        return ""

    title = "🚨 <b>Marzban Infrastructure Alert</b>"
    if all(event.transition_kind == TRANSITION_RECOVERED for event in events):
        title = "✅ <b>Marzban Infrastructure Recovery</b>"

    lines = [title, ""]
    for event in events[:12]:
        previous = event.previous_state or "—"
        lines.extend(
            [
                f"{_transition_icon(event.transition_kind)} "
                f"<b>{html.escape(_type_label(event.asset_type))}</b> — "
                f"{html.escape(event.asset_name)}",
                f"<code>{html.escape(event.address or '-')}</code>",
                f"{html.escape(previous)} → <b>{html.escape(event.current_state)}</b>",
                f"Reason: <code>{html.escape(event.filter_reason)}</code>",
                "",
            ]
        )
    if len(events) > 12:
        lines.append(f"… و {len(events) - 12} تغییر دیگر")
    lines.append("ℹ️ فقط هشدار/مانیتور؛ هیچ اقدام خودکاری انجام نشده است.")
    return "\n".join(lines)[:3900]


def render_status_report(conn, *, max_assets: int = 30, event_limit: int = 8) -> str:
    inventory = discovery.list_active_assets(conn)
    health = local_health.list_health(conn)
    regional_states = regional.list_asset_states(conn)
    provider = regional.get_runtime(conn)

    assets = tuple(
        item for item in inventory if _is_monitorable_asset(item, health)
    )
    ignored_count = len(inventory) - len(assets)
    visible_keys = {item.asset_key for item in assets}
    history = tuple(
        event
        for event in recent_events(conn, max(event_limit * 4, event_limit))
        if event.asset_key in visible_keys
    )[:event_limit]

    lines = [
        "🛰️ <b>Marzban Infrastructure Monitor</b>",
        "",
        f"Provider: <code>{html.escape(str(provider.get('provider_status') or 'NEVER'))}</code>",
        f"Monitored: <b>{len(assets)}</b> · Inventory: <b>{len(inventory)}</b>",
    ]
    if ignored_count:
        lines.append(f"Ignored disabled: <b>{ignored_count}</b>")
    lines.append("")

    if not assets:
        lines.append("هیچ Asset قابل مانیتوری فعالی وجود ندارد.")
    else:
        for item in assets[:max_assets]:
            local = health.get(item.asset_key) or {}
            reg = regional_states.get(item.asset_key) or {}
            reg_state = str(reg.get("filter_state") or REGIONAL_STATE_UNKNOWN)
            reg_reason = str(reg.get("filter_reason") or "")
            local_state = str(local.get("health_state") or "NO_DATA")

            regional_na = (
                item.asset_type == discovery.ASSET_NODE
                and reg_reason == regional.REASON_NO_PUBLIC_HOST_MAPPING
            )
            icon = (
                "🟢"
                if regional_na and local_state == local_health.STATE_LOCAL_HEALTHY
                else _state_icon(reg_state)
            )

            lines.append(
                f"{icon} <b>{html.escape(_type_label(item.asset_type))}</b> "
                f"{html.escape(item.name)}"
            )
            endpoint = item.address
            if item.port:
                endpoint += f":{item.port}"
            lines.append(f"   <code>{html.escape(endpoint)}</code>")

            if regional_na:
                lines.append(
                    f"   Local: <code>{html.escape(local_state)}</code> | "
                    "Regional: <b>N/A</b> <i>(no active Public Host)</i>"
                )
            else:
                lines.append(
                    f"   Local: <code>{html.escape(local_state)}</code> | "
                    f"Regional: <b>{html.escape(reg_state)}</b>"
                )

        if len(assets) > max_assets:
            lines.append(f"… {len(assets) - max_assets} Asset دیگر")

    lines.extend(["", "🕘 <b>Recent transitions</b>"])
    if not history:
        lines.append("هنوز Transition معناداری ثبت نشده است.")
    else:
        for event in history:
            previous = event.previous_state or "—"
            lines.append(
                f"{_transition_icon(event.transition_kind)} "
                f"{html.escape(event.asset_name)}: "
                f"{html.escape(previous)} → <b>{html.escape(event.current_state)}</b>"
            )
            lines.append(f"   <code>{html.escape(event.created_at)}</code>")

    return "\n".join(lines)[:3900]
