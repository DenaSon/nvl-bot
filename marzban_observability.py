"""V120-D transition alerts and operator observability for Marzban monitoring.

Inventory stays complete for audit/debugging, while the operator monitor only
shows actionable assets. UNKNOWN means evidence is unavailable/stale and is not
treated as a filtering transition.
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass
from datetime import datetime, timezone
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


V120D_VERSION = "V122A.0-2026-10-06-monitoring-ui"

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


def _parse_stamp(value: Any) -> Optional[datetime]:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        if raw.endswith("Z"):
            return datetime.fromisoformat(raw[:-1] + "+00:00")
        parsed = datetime.fromisoformat(raw)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def _age_label(value: Any, *, now: Optional[datetime] = None) -> str:
    stamp = _parse_stamp(value)
    if stamp is None:
        return "ثبت نشده"
    now = now or datetime.now(timezone.utc)
    age = max(0, int((now - stamp.astimezone(timezone.utc)).total_seconds()))
    if age < 60:
        return "کمتر از ۱ دقیقه پیش"
    minutes = age // 60
    if minutes < 60:
        return f"{minutes} دقیقه پیش"
    hours = minutes // 60
    if hours < 24:
        return f"{hours} ساعت پیش"
    return f"{hours // 24} روز پیش"


def _latency_label(value: Any) -> str:
    try:
        latency = float(value)
    except (TypeError, ValueError):
        return "—"
    if latency < 0:
        return "—"
    return f"{latency:.0f} ms"


def _local_view(row: Mapping[str, Any]) -> tuple[str, str]:
    state = str(row.get("health_state") or local_health.STATE_UNKNOWN).upper()
    labels = {
        local_health.STATE_LOCAL_HEALTHY: ("🟢", "سالم"),
        local_health.STATE_DNS_ERROR: ("🔴", "خطای DNS"),
        local_health.STATE_SERVICE_DOWN: ("🔴", "سرویس در دسترس نیست"),
        local_health.STATE_API_DOWN: ("🔴", "API در دسترس نیست"),
        local_health.STATE_NODE_DISCONNECTED: ("🔴", "Node قطع است"),
        local_health.STATE_CONTROL_DOWN: ("🔴", "کنترل Node در دسترس نیست"),
        local_health.STATE_DISABLED: ("⚫️", "غیرفعال"),
        local_health.STATE_UNKNOWN: ("⚪️", "در انتظار داده"),
    }
    return labels.get(state, ("⚪️", state.replace("_", " ").title()))


def _regional_view(
    row: Mapping[str, Any],
    *,
    asset_type: Optional[str] = None,
) -> tuple[str, str]:
    state = str(row.get("filter_state") or REGIONAL_STATE_UNKNOWN).upper()
    reason = str(row.get("filter_reason") or "").upper()

    if asset_type == discovery.ASSET_NODE and reason == regional.REASON_NO_PUBLIC_HOST_MAPPING:
        return "➖", "N/A"

    if state == REGIONAL_STATE_CLEAR:
        return "🟢", "سالم"
    if state == REGIONAL_STATE_POSSIBLE:
        return "🟡", "مشکوک"
    if state == REGIONAL_STATE_LIKELY:
        return "🔴", "اختلال محتمل"

    reason_labels = {
        regional.REASON_ENDPOINT_EVIDENCE_STALE: ("⚪️", "داده قدیمی"),
        regional.REASON_PROVIDER_UNAVAILABLE: ("⚠️", "Probe در دسترس نیست"),
        regional.REASON_LOCAL_EVIDENCE_MISSING: ("⏳", "در انتظار Local Check"),
        regional.REASON_LOCAL_NOT_HEALTHY: ("⚠️", "Local مشکل دارد"),
        regional.REASON_NO_REGIONAL_TARGET: ("⏳", "در انتظار تست منطقه‌ای"),
        regional.REASON_NO_PUBLIC_HOST_MAPPING: ("➖", "N/A"),
        regional.REASON_DISABLED: ("⚫️", "غیرفعال"),
    }
    return reason_labels.get(reason, ("⚪️", "در انتظار داده"))


def _short_inbound_tag(value: Any) -> str:
    tag = str(value or "").strip()
    aliases = {
        "VLESS TCP REALITY": "VLESS Reality",
        "VLESS TCP REALITY DIRECT": "VLESS Reality Direct",
        "VLESS TCP HTTP": "VLESS TCP",
        "SS2022-TUNNEL": "SS2022 Tunnel",
    }
    return aliases.get(tag, tag or "Public Host")


def _clean_host_remark(value: Any) -> Optional[str]:
    remark = str(value or "").strip()
    if not remark:
        return None
    if any(token in remark for token in ("{USERNAME}", "{PROTOCOL}", "{TRANSPORT}")):
        return None
    return remark


def _endpoint_text(asset: discovery.MarzbanAsset) -> str:
    endpoint = asset.address
    if asset.port:
        endpoint += f":{asset.port}"
    return endpoint


def _monitor_snapshot(conn):
    inventory = discovery.list_active_assets(conn)
    health = local_health.list_health(conn)
    regional_states = regional.list_asset_states(conn)
    provider = regional.get_runtime(conn)
    assets = tuple(
        item for item in inventory if _is_monitorable_asset(item, health)
    )
    return inventory, assets, health, regional_states, provider


def _oldest_check_label(
    rows: Sequence[Mapping[str, Any]],
    field: str,
) -> str:
    stamps = []
    for row in rows:
        stamp = _parse_stamp(row.get(field))
        if stamp is not None:
            stamps.append(stamp)
    if not stamps:
        return "ثبت نشده"
    return _age_label(min(stamps))


def _node_connected(
    node: discovery.MarzbanAsset,
    local: Mapping[str, Any],
) -> bool:
    evidence = local.get("evidence") or {}
    status = str(
        evidence.get("node_status")
        or node.metadata.get("status")
        or ""
    ).strip().lower()
    return status == "connected" and local.get("healthy") is True


def _overall_monitor_state(
    mains: Sequence[discovery.MarzbanAsset],
    nodes: Sequence[discovery.MarzbanAsset],
    hosts: Sequence[discovery.MarzbanAsset],
    health: Mapping[str, Mapping[str, Any]],
    regional_states: Mapping[str, Mapping[str, Any]],
    provider: Mapping[str, Any],
) -> tuple[str, str]:
    monitored = tuple(mains) + tuple(nodes) + tuple(hosts)
    local_rows = [health.get(item.asset_key) or {} for item in monitored]
    if any(row.get("healthy") is False for row in local_rows):
        return "🔴", "نیازمند بررسی"

    regional_rows = [
        regional_states.get(item.asset_key) or {}
        for item in tuple(mains) + tuple(hosts)
    ]
    states = {
        str(row.get("filter_state") or REGIONAL_STATE_UNKNOWN).upper()
        for row in regional_rows
    }
    if REGIONAL_STATE_LIKELY in states:
        return "🔴", "اختلال منطقه‌ای محتمل"
    if REGIONAL_STATE_POSSIBLE in states:
        return "🟡", "نیازمند بررسی"

    provider_status = str(provider.get("provider_status") or "NEVER").upper()
    if provider_status in {"ERROR", "LIMITED"}:
        return "🟡", "پایش منطقه‌ای محدود"

    if (
        any(not row for row in local_rows)
        or any(
            str(row.get("filter_state") or REGIONAL_STATE_UNKNOWN).upper()
            == REGIONAL_STATE_UNKNOWN
            for row in regional_rows
        )
    ):
        return "🟡", "پایش ناقص"

    return "🟢", "سالم"


def render_dashboard_report(conn) -> str:
    _inventory, assets, health, regional_states, provider = _monitor_snapshot(conn)
    mains = tuple(a for a in assets if a.asset_type == discovery.ASSET_MAIN)
    nodes = tuple(a for a in assets if a.asset_type == discovery.ASSET_NODE)
    hosts = tuple(a for a in assets if a.asset_type == discovery.ASSET_PUBLIC_HOST)

    overall_icon, overall_label = _overall_monitor_state(
        mains, nodes, hosts, health, regional_states, provider
    )

    lines = [
        "🛰️ <b>Marzban Monitor</b>",
        "━━━━━━━━━━━━━━",
        f"{overall_icon} وضعیت کلی: <b>{html.escape(overall_label)}</b>",
        "",
    ]

    if mains:
        main = mains[0]
        local = health.get(main.asset_key) or {}
        reg = regional_states.get(main.asset_key) or {}
        li, ll = _local_view(local)
        ri, rl = _regional_view(reg, asset_type=main.asset_type)
        lines.extend([
            "🌐 <b>Main</b>",
            f"{li} {html.escape(ll)} · <code>{html.escape(_latency_label(local.get('latency_ms')))}</code>",
            f"<code>{html.escape(_endpoint_text(main))}</code>",
            f"Regional: {ri} <b>{html.escape(rl)}</b>",
            "",
        ])
    else:
        lines.extend(["🌐 <b>Main</b>", "⚪️ هنوز در Inventory ثبت نشده است.", ""])

    connected_nodes = sum(
        1 for item in nodes if _node_connected(item, health.get(item.asset_key) or {})
    )
    healthy_hosts = sum(
        1 for item in hosts if (health.get(item.asset_key) or {}).get("healthy") is True
    )
    lines.extend([
        "🖥 <b>Nodes</b>",
        f"{'🟢' if nodes and connected_nodes == len(nodes) else '🟡' if nodes else '⚪️'} "
        f"<b>{connected_nodes}/{len(nodes)}</b> متصل و سالم",
        "",
        "🔗 <b>Public Hosts</b>",
        f"{'🟢' if hosts and healthy_hosts == len(hosts) else '🟡' if hosts else '⚪️'} "
        f"<b>{healthy_hosts}/{len(hosts)}</b> سالم",
        "",
    ])

    counts = {
        REGIONAL_STATE_CLEAR: 0,
        REGIONAL_STATE_POSSIBLE: 0,
        REGIONAL_STATE_LIKELY: 0,
        REGIONAL_STATE_UNKNOWN: 0,
    }
    for item in hosts:
        row = regional_states.get(item.asset_key) or {}
        state = str(row.get("filter_state") or REGIONAL_STATE_UNKNOWN).upper()
        counts[state if state in counts else REGIONAL_STATE_UNKNOWN] += 1

    lines.extend([
        "🌍 <b>Regional · Public Hosts</b>",
        f"🟢 {counts[REGIONAL_STATE_CLEAR]} سالم · "
        f"🟡 {counts[REGIONAL_STATE_POSSIBLE]} مشکوک · "
        f"🔴 {counts[REGIONAL_STATE_LIKELY]} محتمل · "
        f"⚪️ {counts[REGIONAL_STATE_UNKNOWN]} بدون نتیجه",
    ])

    provider_status = str(provider.get("provider_status") or "NEVER").upper()
    provider_icon = "🟢" if provider_status == "OK" else "🟡" if provider_status in {"LIMITED", "ERROR"} else "⚪️"
    lines.extend([
        f"{provider_icon} Probe provider: <code>{html.escape(provider_status)}</code>",
        "",
    ])

    local_rows = [health.get(item.asset_key) or {} for item in assets]
    regional_rows = [
        regional_states.get(item.asset_key) or {}
        for item in tuple(mains) + tuple(hosts)
    ]
    lines.extend([
        f"🕒 Local data: <b>{html.escape(_oldest_check_label(local_rows, 'checked_at'))}</b>",
        f"🕒 Regional data: <b>{html.escape(_oldest_check_label(regional_rows, 'checked_at'))}</b>",
    ])
    return "\n".join(lines)[:3900]


def render_nodes_report(conn) -> str:
    _inventory, assets, health, regional_states, _provider = _monitor_snapshot(conn)
    nodes = tuple(a for a in assets if a.asset_type == discovery.ASSET_NODE)
    lines = ["🖥 <b>Marzban Nodes</b>", "━━━━━━━━━━━━━━", ""]

    if not nodes:
        lines.append("هیچ Node فعالی ثبت نشده است.")
        return "\n".join(lines)

    for item in nodes:
        local = health.get(item.asset_key) or {}
        reg = regional_states.get(item.asset_key) or {}
        li, ll = _local_view(local)
        ri, rl = _regional_view(reg, asset_type=item.asset_type)
        evidence = local.get("evidence") or {}
        node_status = str(
            evidence.get("node_status") or item.metadata.get("status") or "unknown"
        ).strip().lower()
        status_label = {
            "connected": "Connected",
            "connecting": "Connecting",
            "disabled": "Disabled",
            "error": "Error",
        }.get(node_status, node_status or "Unknown")
        api_port = item.metadata.get("api_port")
        node_api = evidence.get("node_api") or {}
        api_icon = (
            "🟢" if node_api.get("ok") is True
            else "🔴" if node_api.get("ok") is False
            else "⚪️"
        )

        lines.extend([
            f"{li} <b>{html.escape(item.name)}</b>",
            f"<code>{html.escape(_endpoint_text(item))}</code>",
            f"Marzban: <b>{html.escape(status_label)}</b> · Local: {html.escape(ll)} · "
            f"<code>{html.escape(_latency_label(local.get('latency_ms')))}</code>",
        ])
        if api_port:
            lines.append(
                f"Xray API <code>:{int(api_port)}</code> {api_icon} "
                f"<code>{html.escape(_latency_label(node_api.get('latency_ms')))}</code>"
            )
        xray_version = str(item.metadata.get("xray_version") or "").strip()
        if xray_version:
            lines.append(f"Xray: <code>{html.escape(xray_version)}</code>")
        lines.extend([
            f"Regional: {ri} <b>{html.escape(rl)}</b>",
            f"Checked: <b>{html.escape(_age_label(local.get('checked_at')))}</b>",
            "",
        ])

    return "\n".join(lines)[:3900]


def _node_for_host(
    host: discovery.MarzbanAsset,
    nodes: Sequence[discovery.MarzbanAsset],
) -> Optional[discovery.MarzbanAsset]:
    host_ips = set(host.resolved_ips)
    for node in nodes:
        if host.address == node.address:
            return node
        if host_ips and host_ips.intersection(node.resolved_ips):
            return node
    return None


def render_hosts_report(conn) -> str:
    _inventory, assets, health, regional_states, _provider = _monitor_snapshot(conn)
    nodes = tuple(a for a in assets if a.asset_type == discovery.ASSET_NODE)
    hosts = tuple(a for a in assets if a.asset_type == discovery.ASSET_PUBLIC_HOST)
    lines = ["🌐 <b>Public Hosts</b>", "━━━━━━━━━━━━━━", ""]

    if not hosts:
        lines.append("هیچ Public Host فعالی ثبت نشده است.")
        return "\n".join(lines)

    groups: dict[str, list[discovery.MarzbanAsset]] = {}
    for item in hosts:
        groups.setdefault(item.address, []).append(item)

    for address in sorted(groups):
        group = sorted(
            groups[address],
            key=lambda item: (
                str(item.metadata.get("inbound_tag") or ""),
                int(item.port or 0),
            ),
        )
        node = _node_for_host(group[0], nodes)
        if node is not None:
            title = node.name
            prefix = "🖥"
        else:
            title = next(
                (
                    remark
                    for remark in (_clean_host_remark(item.name) for item in group)
                    if remark
                ),
                "Standalone",
            )
            prefix = "🌐"

        lines.extend([
            f"{prefix} <b>{html.escape(title)}</b>",
            f"<code>{html.escape(address)}</code>",
        ])

        for item in group:
            local = health.get(item.asset_key) or {}
            reg = regional_states.get(item.asset_key) or {}
            li, ll = _local_view(local)
            ri, rl = _regional_view(reg, asset_type=item.asset_type)
            tag = _short_inbound_tag(item.metadata.get("inbound_tag"))
            port = f":{item.port}" if item.port else ":?"
            lines.append(
                f"{li} <b>{html.escape(tag)}</b> · <code>{html.escape(port)}</code> · "
                f"<code>{html.escape(_latency_label(local.get('latency_ms')))}</code>"
            )
            lines.append(
                f"   Regional: {ri} {html.escape(rl)} · "
                f"{html.escape(_age_label(reg.get('checked_at')))}"
            )
        lines.append("")

    return "\n".join(lines)[:3900]


def _regional_metrics(row: Mapping[str, Any]) -> dict[str, Any]:
    evidence = row.get("evidence") or {}
    endpoints = evidence.get("endpoints") or {}
    if not isinstance(endpoints, dict):
        return {}

    endpoint_rows = [value for value in endpoints.values() if isinstance(value, dict)]
    if not endpoint_rows:
        return {}

    completed = sum(int(value.get("completed_nodes") or 0) for value in endpoint_rows)
    successful = sum(int(value.get("successful_nodes") or 0) for value in endpoint_rows)
    failed = sum(int(value.get("failed_nodes") or 0) for value in endpoint_rows)
    pending = sum(int(value.get("pending_nodes") or 0) for value in endpoint_rows)
    ratio = (successful / completed) if completed > 0 else None
    failed_asns = sorted({
        str(item)
        for value in endpoint_rows
        for item in (value.get("failed_asns") or [])
        if str(item).strip()
    })
    failed_cities = sorted({
        str(item)
        for value in endpoint_rows
        for item in (value.get("failed_cities") or [])
        if str(item).strip()
    })
    checked = [
        value.get("evidence_checked_at")
        for value in endpoint_rows
        if value.get("evidence_checked_at")
    ]
    providers = sorted({
        str(value.get("provider") or "").strip()
        for value in endpoint_rows
        if str(value.get("provider") or "").strip()
    })
    return {
        "completed": completed,
        "successful": successful,
        "failed": failed,
        "pending": pending,
        "ratio": ratio,
        "failed_asns": failed_asns,
        "failed_cities": failed_cities,
        "checked_at": min(checked) if checked else row.get("checked_at"),
        "providers": providers,
    }


def render_regional_report(conn) -> str:
    _inventory, assets, _health, regional_states, provider = _monitor_snapshot(conn)
    targets = tuple(
        item for item in assets
        if item.asset_type in {discovery.ASSET_MAIN, discovery.ASSET_PUBLIC_HOST}
    )
    provider_status = str(provider.get("provider_status") or "NEVER").upper()
    lines = [
        "🌍 <b>Regional Monitoring</b>",
        "━━━━━━━━━━━━━━",
        f"Provider: <code>{html.escape(provider_status)}</code> · "
        f"{html.escape(_age_label(provider.get('updated_at')))}",
    ]
    if provider.get("provider_error"):
        lines.append(f"⚠️ <code>{html.escape(str(provider.get('provider_error'))[:180])}</code>")
    if provider.get("backoff_until"):
        lines.append(f"Backoff until: <code>{html.escape(str(provider.get('backoff_until')))}</code>")
    lines.append("")

    if not targets:
        lines.append("هیچ Endpoint منطقه‌ای فعالی وجود ندارد.")
        return "\n".join(lines)

    for item in targets:
        row = regional_states.get(item.asset_key) or {}
        ri, rl = _regional_view(row, asset_type=item.asset_type)
        if item.asset_type == discovery.ASSET_MAIN:
            label = "Main"
        else:
            label = _short_inbound_tag(item.metadata.get("inbound_tag"))

        lines.extend([
            f"{ri} <b>{html.escape(label)}</b>",
            f"<code>{html.escape(_endpoint_text(item))}</code>",
            f"Status: <b>{html.escape(rl)}</b> · "
            f"Checked: {html.escape(_age_label(row.get('checked_at')))}",
        ])

        metrics = _regional_metrics(row)
        if metrics:
            ratio = metrics.get("ratio")
            ratio_text = f"{ratio * 100:.0f}%" if ratio is not None else "—"
            lines.append(
                f"Reachability: <b>{html.escape(ratio_text)}</b> · "
                f"OK {metrics['successful']} · Fail {metrics['failed']} · Pending {metrics['pending']}"
            )
            if metrics["providers"]:
                lines.append(
                    "Probe: <code>"
                    + html.escape(", ".join(metrics["providers"]))
                    + "</code>"
                )
            if metrics["failed_asns"]:
                lines.append(
                    "Failed ASN: <code>"
                    + html.escape(", ".join(metrics["failed_asns"][:6]))
                    + "</code>"
                )
            if metrics["failed_cities"]:
                lines.append(
                    "Failed cities: <code>"
                    + html.escape(", ".join(metrics["failed_cities"][:6]))
                    + "</code>"
                )
        lines.append("")

    return "\n".join(lines)[:3900]


def render_events_report(conn, *, event_limit: int = 12) -> str:
    _inventory, assets, _health, _regional_states, _provider = _monitor_snapshot(conn)
    asset_map = {item.asset_key: item for item in assets}
    events = recent_events(conn, event_limit)
    lines = ["🕘 <b>Marzban Events</b>", "━━━━━━━━━━━━━━", ""]

    if not events:
        lines.append("هنوز Transition معناداری ثبت نشده است.")
        return "\n".join(lines)

    for event in events:
        asset = asset_map.get(event.asset_key)
        if asset is not None:
            if asset.asset_type == discovery.ASSET_PUBLIC_HOST:
                label = _short_inbound_tag(asset.metadata.get("inbound_tag"))
            elif asset.asset_type == discovery.ASSET_MAIN:
                label = "Main"
            else:
                label = asset.name
        else:
            label = _clean_host_remark(event.asset_name) or event.address or _type_label(event.asset_type)

        previous_icon, previous_label = _regional_view(
            {"filter_state": event.previous_state or REGIONAL_STATE_UNKNOWN}
        )
        current_icon, current_label = _regional_view(
            {"filter_state": event.current_state}
        )
        lines.extend([
            f"{_transition_icon(event.transition_kind)} <b>{html.escape(label)}</b>",
            f"{previous_icon} {html.escape(previous_label)} → "
            f"{current_icon} <b>{html.escape(current_label)}</b>",
            f"<code>{html.escape(event.address or '-')}</code> · "
            f"{html.escape(_age_label(event.created_at))}",
            "",
        ])

    return "\n".join(lines)[:3900]


def render_status_report(conn, *, max_assets: int = 30, event_limit: int = 8) -> str:
    """Backward-compatible entry point; V122A uses the compact dashboard."""
    return render_dashboard_report(conn)
