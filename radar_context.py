"""Pure Cloudflare Radar network-context classification for NVL.

This module converts already-normalized Radar evidence into one conservative
country/ASN context state. It performs no network I/O, SQLite writes, Telegram
notifications, DNS changes, filtering mutations, or failover actions.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Mapping, Optional

from cloudflare_radar import RadarOutage, RadarTimeSeries, RadarTrafficAnomaly


NETWORK_STATE_UNKNOWN = "UNKNOWN"
NETWORK_STATE_NORMAL = "NORMAL"
NETWORK_STATE_DEGRADED = "DEGRADED"
NETWORK_STATE_OUTAGE = "OUTAGE"

NETWORK_REASON_PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
NETWORK_REASON_INCOMPLETE_PRIMARY_EVIDENCE = "INCOMPLETE_PRIMARY_EVIDENCE"
NETWORK_REASON_NO_ACTIVE_INCIDENT = "NO_ACTIVE_INCIDENT"
NETWORK_REASON_VERIFIED_TRAFFIC_ANOMALY = "VERIFIED_TRAFFIC_ANOMALY"
NETWORK_REASON_ACTIVE_OUTAGE_ANNOTATION = "ACTIVE_OUTAGE_ANNOTATION"

SOURCE_OK = "OK"


@dataclass(frozen=True)
class RadarMetricPoint:
    metric: str
    value: Optional[float]
    previous_value: Optional[float]
    delta_pct: Optional[float]
    unit: Optional[str]
    series_name: Optional[str]
    confidence_level: Optional[int]
    last_updated: Optional[str]


@dataclass(frozen=True)
class NetworkContextDecision:
    provider: str
    scope_type: str
    scope_value: str
    state: str
    reason: str
    provider_status: str
    provider_error: Optional[str]
    anomaly_count: int
    active_anomaly_count: int
    outage_count: int
    active_outage_count: int
    traffic: RadarMetricPoint
    latency: RadarMetricPoint
    dns: RadarMetricPoint
    bandwidth: RadarMetricPoint
    source_statuses: tuple[tuple[str, str], ...]
    observed_at: str

    @property
    def confidence_level(self) -> Optional[int]:
        values = [
            item.confidence_level
            for item in (self.traffic, self.latency, self.dns, self.bandwidth)
            if item.confidence_level is not None
        ]
        return min(values) if values else None

    def source_status_dict(self) -> dict[str, str]:
        return dict(self.source_statuses)

    def to_dict(self) -> dict:
        def metric_dict(item: RadarMetricPoint) -> dict:
            return {
                "metric": item.metric,
                "value": item.value,
                "previous_value": item.previous_value,
                "delta_pct": item.delta_pct,
                "unit": item.unit,
                "series_name": item.series_name,
                "confidence_level": item.confidence_level,
                "last_updated": item.last_updated,
            }

        return {
            "provider": self.provider,
            "scope_type": self.scope_type,
            "scope_value": self.scope_value,
            "state": self.state,
            "reason": self.reason,
            "provider_status": self.provider_status,
            "provider_error": self.provider_error,
            "anomaly_count": self.anomaly_count,
            "active_anomaly_count": self.active_anomaly_count,
            "outage_count": self.outage_count,
            "active_outage_count": self.active_outage_count,
            "traffic": metric_dict(self.traffic),
            "latency": metric_dict(self.latency),
            "dns": metric_dict(self.dns),
            "bandwidth": metric_dict(self.bandwidth),
            "confidence_level": self.confidence_level,
            "source_statuses": self.source_status_dict(),
            "observed_at": self.observed_at,
        }


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_timestamp(value: Optional[str]) -> Optional[datetime]:
    raw = str(value or "").strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        value_dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if value_dt.tzinfo is None:
        value_dt = value_dt.replace(tzinfo=timezone.utc)
    return value_dt.astimezone(timezone.utc)


def _event_is_active(
    start_date: Optional[str],
    end_date: Optional[str],
    *,
    now: datetime,
) -> bool:
    start = _parse_timestamp(start_date)
    if start is not None and start > now:
        return False
    end = _parse_timestamp(end_date)
    if end is not None and end < now:
        return False
    return True


def _unit_for_series(series: RadarTimeSeries, series_name: Optional[str]) -> Optional[str]:
    units = dict(series.meta.units)
    if series_name and series_name in units:
        return units[series_name] or None
    if "*" in units:
        return units["*"] or None
    if len(units) == 1:
        return next(iter(units.values())) or None
    return None


def _last_two_numeric(values: Iterable[Optional[float]]) -> tuple[Optional[float], Optional[float]]:
    usable = [float(value) for value in values if value is not None]
    if not usable:
        return None, None
    if len(usable) == 1:
        return usable[-1], None
    return usable[-1], usable[-2]


def _metric_point(
    metric: str,
    series: Optional[RadarTimeSeries],
) -> RadarMetricPoint:
    if series is None:
        return RadarMetricPoint(
            metric=metric,
            value=None,
            previous_value=None,
            delta_pct=None,
            unit=None,
            series_name=None,
            confidence_level=None,
            last_updated=None,
        )

    available = series.series_dict()
    selected_name = None
    for preferred in ("p50", "values"):
        if preferred in available:
            selected_name = preferred
            break
    if selected_name is None and available:
        selected_name = sorted(available)[0]

    value = previous = delta_pct = None
    if selected_name is not None:
        value, previous = _last_two_numeric(available[selected_name])
        if value is not None and previous not in (None, 0):
            delta_pct = ((value - previous) / abs(previous)) * 100.0

    return RadarMetricPoint(
        metric=metric,
        value=value,
        previous_value=previous,
        delta_pct=delta_pct,
        unit=_unit_for_series(series, selected_name),
        series_name=selected_name,
        confidence_level=series.meta.confidence_level,
        last_updated=series.meta.last_updated,
    )


def derive_network_context(
    *,
    provider_status: str,
    provider_error: Optional[str],
    source_statuses: Mapping[str, str],
    anomalies: Iterable[RadarTrafficAnomaly] = (),
    outages: Iterable[RadarOutage] = (),
    netflows: Optional[RadarTimeSeries] = None,
    latency: Optional[RadarTimeSeries] = None,
    dns: Optional[RadarTimeSeries] = None,
    bandwidth: Optional[RadarTimeSeries] = None,
    scope_type: str = "COUNTRY",
    scope_value: str = "IR",
    provider: str = "cloudflare-radar",
    now: Optional[datetime] = None,
) -> NetworkContextDecision:
    """Derive a conservative network context from Radar evidence.

    Only Cloudflare's explicit outage annotations and VERIFIED traffic anomalies
    affect the state in V2. NetFlows/IQI are persisted as context metrics but do
    not independently declare degradation/outage until production thresholds are
    calibrated in a later phase.
    """

    current = now or _utc_now()
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    current = current.astimezone(timezone.utc)

    anomaly_rows = tuple(anomalies or ())
    outage_rows = tuple(outages or ())

    active_anomalies = tuple(
        item
        for item in anomaly_rows
        if str(item.status or "").upper() == "VERIFIED"
        and _event_is_active(item.start_date, item.end_date, now=current)
    )
    active_outages = tuple(
        item
        for item in outage_rows
        if str(item.event_type or "").upper() == "OUTAGE"
        and _event_is_active(item.start_date, item.end_date, now=current)
    )

    statuses = {
        str(key): str(value or "")
        for key, value in dict(source_statuses or {}).items()
    }
    anomaly_source_ok = statuses.get("traffic_anomalies") == SOURCE_OK
    outage_source_ok = statuses.get("outages") == SOURCE_OK

    if active_outages:
        state = NETWORK_STATE_OUTAGE
        reason = NETWORK_REASON_ACTIVE_OUTAGE_ANNOTATION
    elif active_anomalies:
        state = NETWORK_STATE_DEGRADED
        reason = NETWORK_REASON_VERIFIED_TRAFFIC_ANOMALY
    elif anomaly_source_ok and outage_source_ok:
        state = NETWORK_STATE_NORMAL
        reason = NETWORK_REASON_NO_ACTIVE_INCIDENT
    elif not anomaly_source_ok and not outage_source_ok:
        state = NETWORK_STATE_UNKNOWN
        reason = NETWORK_REASON_PROVIDER_UNAVAILABLE
    else:
        state = NETWORK_STATE_UNKNOWN
        reason = NETWORK_REASON_INCOMPLETE_PRIMARY_EVIDENCE

    return NetworkContextDecision(
        provider=provider,
        scope_type=str(scope_type or "COUNTRY").upper(),
        scope_value=str(scope_value or "IR").upper(),
        state=state,
        reason=reason,
        provider_status=str(provider_status or "UNKNOWN").upper(),
        provider_error=str(provider_error)[:500] if provider_error else None,
        anomaly_count=len(anomaly_rows),
        active_anomaly_count=len(active_anomalies),
        outage_count=len(outage_rows),
        active_outage_count=len(active_outages),
        traffic=_metric_point("NETFLOWS", netflows),
        latency=_metric_point("LATENCY", latency),
        dns=_metric_point("DNS", dns),
        bandwidth=_metric_point("BANDWIDTH", bandwidth),
        source_statuses=tuple(sorted(statuses.items())),
        observed_at=current.isoformat().replace("+00:00", "Z"),
    )
