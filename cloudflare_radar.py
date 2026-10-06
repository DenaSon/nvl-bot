"""Read-only Cloudflare Radar API client for NVL.

Radar V1 is intentionally isolated from the filtering classifier, persistence,
Telegram UI, and failover paths. It only retrieves and normalizes external
Internet-health evidence.

No API token is logged or included in returned models.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, Optional, Tuple


API_BASE = "https://api.cloudflare.com/client/v4"
RADAR_USER_AGENT = "NVL-Radar/1.0 (+read-only-monitoring)"

DEFAULT_LOCATION = "IR"
DEFAULT_DATE_RANGE = "1d"
DEFAULT_AGG_INTERVAL = "15m"

_ALLOWED_AGG_INTERVALS = {"15m", "1h", "1d", "1w"}
_ALLOWED_IQI_METRICS = {"BANDWIDTH", "DNS", "LATENCY"}
_ALLOWED_ANOMALY_STATUS = {"VERIFIED", "UNVERIFIED"}
_ALLOWED_ANOMALY_TYPES = {"LOCATION", "AS", "ORIGIN"}
_ALLOWED_OUTAGE_TYPES = {"NATIONWIDE", "REGIONAL", "NETWORK", "PLATFORM"}
_ALLOWED_OUTAGE_CAUSES = {
    "BLOCKING", "CABLE_CUT", "CYBERATTACK", "DNS", "FIRE",
    "GOVERNMENT_DIRECTED", "MAINTENANCE", "MECHANICAL", "MILITARY_ACTION",
    "MISCONFIGURATION", "NATURAL_DISASTER", "NETWORK_PROBLEM",
    "POWER_OUTAGE", "SOFTWARE", "TECHNICAL_PROBLEM", "UNKNOWN", "WEATHER",
}
_DATE_RANGE_RE = re.compile(r"^[1-9]\d*(?:d|w)(?:control)?$", re.IGNORECASE)


class CloudflareRadarError(RuntimeError):
    """Base error for bounded Radar provider/configuration failures."""


class CloudflareRadarAuthError(CloudflareRadarError):
    """Authentication/authorization failure. Never retried by the client."""


class CloudflareRadarRateLimited(CloudflareRadarError):
    """Cloudflare rejected the request because of a rate limit."""

    def __init__(self, message: str, *, retry_after: Optional[float] = None):
        super().__init__(message)
        self.retry_after = retry_after


class CloudflareRadarTransientError(CloudflareRadarError):
    """Transient network/provider failure eligible for bounded retries."""


@dataclass(frozen=True)
class RadarMeta:
    agg_interval: Optional[str]
    confidence_level: Optional[int]
    last_updated: Optional[str]
    normalization: Optional[str]
    units: Tuple[Tuple[str, str], ...]
    date_ranges: Tuple[Tuple[Optional[str], Optional[str]], ...]


@dataclass(frozen=True)
class RadarTimeSeries:
    """Normalized provider time series."""

    metric: str
    scope: str
    timestamps: Tuple[str, ...]
    series: Tuple[Tuple[str, Tuple[Optional[float], ...]], ...]
    meta: RadarMeta

    def series_dict(self) -> Dict[str, Tuple[Optional[float], ...]]:
        return dict(self.series)


@dataclass(frozen=True)
class RadarTrafficAnomaly:
    uuid: str
    status: str
    anomaly_type: str
    start_date: str
    end_date: Optional[str]
    location_code: Optional[str]
    location_name: Optional[str]
    asn: Optional[str]
    asn_name: Optional[str]
    visible_in_data_sources: Tuple[str, ...]


@dataclass(frozen=True)
class RadarOutage:
    annotation_id: str
    event_type: str
    description: str
    data_source: str
    scope: str
    start_date: str
    end_date: Optional[str]
    outage_cause: Optional[str]
    outage_type: Optional[str]
    locations: Tuple[str, ...]
    asns: Tuple[str, ...]
    tags: Tuple[str, ...]


Transport = Callable[
    [str, str, Dict[str, str], Optional[bytes], float],
    Dict[str, Any],
]


def _bounded_provider_detail(raw: bytes) -> str:
    try:
        payload = json.loads(raw.decode("utf-8", errors="replace"))
        errors = payload.get("errors") if isinstance(payload, dict) else None
        if errors:
            return json.dumps(errors, ensure_ascii=False, default=str)[:500]
    except Exception:
        pass
    text = raw.decode("utf-8", errors="replace").strip()
    return text[:500] if text else "provider error"


def _retry_after_seconds(headers: Any) -> Optional[float]:
    try:
        raw = headers.get("Retry-After")
    except Exception:
        return None
    if raw is None:
        return None
    try:
        return max(0.0, float(str(raw).strip()))
    except (TypeError, ValueError):
        return None


def _urllib_transport(
    method: str,
    url: str,
    headers: Dict[str, str],
    body: Optional[bytes],
    timeout: float,
) -> Dict[str, Any]:
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read()
        except Exception:
            raw = b""
        detail = _bounded_provider_detail(raw)
        message = f"Cloudflare Radar HTTP {exc.code}: {detail}"
        if exc.code in {401, 403}:
            raise CloudflareRadarAuthError(message) from exc
        if exc.code == 429:
            raise CloudflareRadarRateLimited(
                message,
                retry_after=_retry_after_seconds(exc.headers),
            ) from exc
        if 500 <= int(exc.code) <= 599:
            raise CloudflareRadarTransientError(message) from exc
        raise CloudflareRadarError(message) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise CloudflareRadarTransientError(
            f"Cloudflare Radar network error: {type(exc).__name__}"
        ) from exc

    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise CloudflareRadarError("Cloudflare Radar returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise CloudflareRadarError("Cloudflare Radar returned an invalid payload")
    return payload


def _normalize_location(value: Any) -> str:
    location = str(value or "").strip().upper()
    if len(location) != 2 or not location.isalpha():
        raise CloudflareRadarError("Radar location must be an alpha-2 code")
    return location


def _normalize_asn(value: Any) -> Optional[int]:
    if value is None or str(value).strip() == "":
        return None
    raw = str(value).strip().upper()
    if raw.startswith("AS"):
        raw = raw[2:]
    try:
        asn = int(raw)
    except (TypeError, ValueError) as exc:
        raise CloudflareRadarError("Radar ASN must be a positive integer") from exc
    if asn <= 0:
        raise CloudflareRadarError("Radar ASN must be a positive integer")
    return asn


def _normalize_date_range(value: Any) -> str:
    date_range = str(value or "").strip().lower()
    if not _DATE_RANGE_RE.fullmatch(date_range):
        raise CloudflareRadarError(
            "Radar date_range must look like 1d, 7d, 1w, or 7dcontrol"
        )
    return date_range


def _normalize_agg_interval(value: Any) -> str:
    interval = str(value or "").strip().lower()
    if interval not in _ALLOWED_AGG_INTERVALS:
        raise CloudflareRadarError(
            f"Radar agg_interval must be one of {sorted(_ALLOWED_AGG_INTERVALS)}"
        )
    return interval


def _normalize_limit(value: Any) -> int:
    try:
        limit = int(value)
    except (TypeError, ValueError) as exc:
        raise CloudflareRadarError("Radar limit must be a positive integer") from exc
    if limit <= 0:
        raise CloudflareRadarError("Radar limit must be a positive integer")
    return min(limit, 1000)


def _normalize_optional_enum(value: Any, allowed: set[str], label: str) -> Optional[str]:
    if value is None or str(value).strip() == "":
        return None
    normalized = str(value).strip().upper()
    if normalized not in allowed:
        raise CloudflareRadarError(f"{label} must be one of {sorted(allowed)}")
    return normalized


def _optional_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _float_or_none(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _int_or_none(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _tuple_text(values: Any) -> Tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        return ()
    return tuple(
        str(item) for item in values
        if item is not None and str(item).strip()
    )


def _result_object(payload: Mapping[str, Any], endpoint: str) -> Dict[str, Any]:
    if payload.get("success") is not True:
        errors = payload.get("errors")
        detail = (
            json.dumps(errors, ensure_ascii=False, default=str)[:500]
            if errors
            else "unknown API failure"
        )
        raise CloudflareRadarError(
            f"Cloudflare Radar API failed at {endpoint}: {detail}"
        )
    result = payload.get("result")
    if not isinstance(result, dict):
        raise CloudflareRadarError(
            f"Cloudflare Radar returned invalid result for {endpoint}"
        )
    return result


def _parse_meta(raw: Any) -> RadarMeta:
    meta = raw if isinstance(raw, dict) else {}
    confidence = (
        meta.get("confidenceInfo")
        if isinstance(meta.get("confidenceInfo"), dict)
        else {}
    )
    units = []
    for item in meta.get("units") or ():
        if isinstance(item, dict):
            units.append(
                (str(item.get("name") or ""), str(item.get("value") or ""))
            )
    date_ranges = []
    for item in meta.get("dateRange") or ():
        if isinstance(item, dict):
            date_ranges.append(
                (
                    _optional_text(item.get("startTime")),
                    _optional_text(item.get("endTime")),
                )
            )
    return RadarMeta(
        agg_interval=_optional_text(meta.get("aggInterval")),
        confidence_level=_int_or_none(confidence.get("level")),
        last_updated=_optional_text(meta.get("lastUpdated")),
        normalization=_optional_text(meta.get("normalization")),
        units=tuple(units),
        date_ranges=tuple(date_ranges),
    )


def _parse_timeseries(
    result: Dict[str, Any],
    *,
    metric: str,
    scope: str,
) -> RadarTimeSeries:
    raw_series = result.get("serie_0")
    if not isinstance(raw_series, dict):
        raise CloudflareRadarError(
            f"Cloudflare Radar {metric} response has no serie_0"
        )

    raw_timestamps = raw_series.get("timestamps")
    if not isinstance(raw_timestamps, list):
        raise CloudflareRadarError(
            f"Cloudflare Radar {metric} response has invalid timestamps"
        )
    timestamps = tuple(str(item) for item in raw_timestamps)

    normalized_series = []
    for name, values in raw_series.items():
        if name == "timestamps" or not isinstance(values, list):
            continue
        normalized_values = tuple(_float_or_none(value) for value in values)
        if len(normalized_values) != len(timestamps):
            raise CloudflareRadarError(
                f"Cloudflare Radar {metric} series length mismatch for {name}"
            )
        normalized_series.append((str(name), normalized_values))

    return RadarTimeSeries(
        metric=metric,
        scope=scope,
        timestamps=timestamps,
        series=tuple(sorted(normalized_series, key=lambda item: item[0])),
        meta=_parse_meta(result.get("meta")),
    )


class CloudflareRadarClient:
    """Minimal read-only Cloudflare Radar client with bounded retries."""

    def __init__(
        self,
        api_token: str,
        *,
        timeout: float = 8.0,
        retries: int = 2,
        backoff_base: float = 0.5,
        backoff_max: float = 8.0,
        transport: Optional[Transport] = None,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        token = str(api_token or "").strip()
        if not token:
            raise CloudflareRadarError(
                "Cloudflare Radar API token is not configured"
            )
        self._token = token
        self.timeout = max(0.1, float(timeout))
        self.retries = min(5, max(0, int(retries)))
        self.backoff_base = max(0.0, float(backoff_base))
        self.backoff_max = max(self.backoff_base, float(backoff_max))
        self._transport = transport or _urllib_transport
        self._sleeper = sleeper

    @classmethod
    def from_env(cls, **overrides: Any) -> "CloudflareRadarClient":
        token = str(
            os.getenv("NVL_CLOUDFLARE_RADAR_API_TOKEN") or ""
        ).strip()
        config = {
            "timeout": _env_float("NVL_CLOUDFLARE_RADAR_TIMEOUT", 8.0),
            "retries": _env_int("NVL_CLOUDFLARE_RADAR_RETRIES", 2),
            "backoff_base": _env_float(
                "NVL_CLOUDFLARE_RADAR_BACKOFF_BASE", 0.5
            ),
            "backoff_max": _env_float(
                "NVL_CLOUDFLARE_RADAR_BACKOFF_MAX", 8.0
            ),
        }
        config.update(overrides)
        return cls(token, **config)

    @property
    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
            "User-Agent": RADAR_USER_AGENT,
        }

    def _delay_for(
        self,
        attempt: int,
        exc: CloudflareRadarError,
    ) -> float:
        if (
            isinstance(exc, CloudflareRadarRateLimited)
            and exc.retry_after is not None
        ):
            return min(
                self.backoff_max,
                max(0.0, float(exc.retry_after)),
            )
        return min(
            self.backoff_max,
            self.backoff_base * (2 ** attempt),
        )

    def _request(
        self,
        path: str,
        *,
        query: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        url = API_BASE + path
        if query:
            pairs = []
            for key, value in query.items():
                if value is None:
                    continue
                if isinstance(value, (list, tuple)):
                    for item in value:
                        pairs.append((key, item))
                else:
                    pairs.append((key, value))
            if pairs:
                url += "?" + urllib.parse.urlencode(pairs)

        for attempt in range(self.retries + 1):
            try:
                payload = self._transport(
                    "GET",
                    url,
                    self._headers,
                    None,
                    self.timeout,
                )
                if not isinstance(payload, dict):
                    raise CloudflareRadarError(
                        "Cloudflare Radar transport returned invalid payload"
                    )
                return payload
            except (
                CloudflareRadarRateLimited,
                CloudflareRadarTransientError,
            ) as exc:
                if attempt >= self.retries:
                    raise
                delay = self._delay_for(attempt, exc)
                if delay > 0:
                    self._sleeper(delay)

        raise CloudflareRadarError(
            "Cloudflare Radar request failed unexpectedly"
        )

    @staticmethod
    def _scope(
        location: Optional[str],
        asn: Optional[int],
    ) -> str:
        if asn is not None:
            return f"ASN:{asn}"
        return f"LOCATION:{location or DEFAULT_LOCATION}"

    def get_traffic_anomalies(
        self,
        *,
        location: str = DEFAULT_LOCATION,
        asn: Any = None,
        date_range: str = DEFAULT_DATE_RANGE,
        status: Optional[str] = "VERIFIED",
        anomaly_type: Optional[str] = None,
        limit: int = 50,
    ) -> Tuple[RadarTrafficAnomaly, ...]:
        normalized_asn = _normalize_asn(asn)
        normalized_location = (
            _normalize_location(location)
            if normalized_asn is None
            else None
        )
        normalized_status = _normalize_optional_enum(
            status,
            _ALLOWED_ANOMALY_STATUS,
            "Radar anomaly status",
        )
        normalized_type = _normalize_optional_enum(
            anomaly_type,
            _ALLOWED_ANOMALY_TYPES,
            "Radar anomaly type",
        )
        payload = self._request(
            "/radar/traffic_anomalies",
            query={
                "location": normalized_location,
                "asn": normalized_asn,
                "dateRange": _normalize_date_range(date_range),
                "status": normalized_status,
                "type": normalized_type,
                "limit": _normalize_limit(limit),
                "format": "JSON",
            },
        )
        result = _result_object(payload, "traffic_anomalies")
        rows = result.get("trafficAnomalies")
        if not isinstance(rows, list):
            raise CloudflareRadarError(
                "Cloudflare Radar returned invalid trafficAnomalies"
            )

        normalized = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            location_details = (
                row.get("locationDetails")
                if isinstance(row.get("locationDetails"), dict)
                else {}
            )
            asn_details = (
                row.get("asnDetails")
                if isinstance(row.get("asnDetails"), dict)
                else {}
            )
            normalized.append(
                RadarTrafficAnomaly(
                    uuid=str(row.get("uuid") or ""),
                    status=str(row.get("status") or ""),
                    anomaly_type=str(row.get("type") or ""),
                    start_date=str(row.get("startDate") or ""),
                    end_date=_optional_text(row.get("endDate")),
                    location_code=_optional_text(
                        location_details.get("code")
                    ),
                    location_name=_optional_text(
                        location_details.get("name")
                    ),
                    asn=_optional_text(asn_details.get("asn")),
                    asn_name=_optional_text(asn_details.get("name")),
                    visible_in_data_sources=_tuple_text(
                        row.get("visibleInDataSources")
                    ),
                )
            )
        return tuple(normalized)

    def get_netflows(
        self,
        *,
        location: str = DEFAULT_LOCATION,
        asn: Any = None,
        date_range: str = DEFAULT_DATE_RANGE,
        agg_interval: str = DEFAULT_AGG_INTERVAL,
        product: str = "ALL",
        normalization: Optional[str] = None,
    ) -> RadarTimeSeries:
        normalized_asn = _normalize_asn(asn)
        normalized_location = (
            _normalize_location(location)
            if normalized_asn is None
            else None
        )
        normalized_product = str(product or "").strip().upper()
        if normalized_product not in {"ALL", "HTTP"}:
            raise CloudflareRadarError(
                "Radar NetFlows product must be ALL or HTTP"
            )
        normalized_normalization = None
        if normalization is not None and str(normalization).strip():
            normalized_normalization = str(
                normalization
            ).strip().upper()
            if normalized_normalization not in {
                "PERCENTAGE_CHANGE",
                "MIN0_MAX",
            }:
                raise CloudflareRadarError(
                    "Radar NetFlows normalization must be "
                    "PERCENTAGE_CHANGE or MIN0_MAX"
                )

        payload = self._request(
            "/radar/netflows/timeseries",
            query={
                "location": normalized_location,
                "asn": normalized_asn,
                "dateRange": _normalize_date_range(date_range),
                "aggInterval": _normalize_agg_interval(
                    agg_interval
                ),
                "product": normalized_product,
                "normalization": normalized_normalization,
                "format": "JSON",
            },
        )
        result = _result_object(
            payload,
            "netflows/timeseries",
        )
        return _parse_timeseries(
            result,
            metric="NETFLOWS",
            scope=self._scope(
                normalized_location,
                normalized_asn,
            ),
        )

    def get_iqi(
        self,
        metric: str,
        *,
        location: str = DEFAULT_LOCATION,
        asn: Any = None,
        date_range: str = DEFAULT_DATE_RANGE,
        agg_interval: str = DEFAULT_AGG_INTERVAL,
        interpolation: bool = False,
    ) -> RadarTimeSeries:
        normalized_metric = str(metric or "").strip().upper()
        if normalized_metric not in _ALLOWED_IQI_METRICS:
            raise CloudflareRadarError(
                f"Radar IQI metric must be one of "
                f"{sorted(_ALLOWED_IQI_METRICS)}"
            )
        normalized_asn = _normalize_asn(asn)
        normalized_location = (
            _normalize_location(location)
            if normalized_asn is None
            else None
        )
        payload = self._request(
            "/radar/quality/iqi/timeseries_groups",
            query={
                "metric": normalized_metric,
                "location": normalized_location,
                "asn": normalized_asn,
                "dateRange": _normalize_date_range(date_range),
                "aggInterval": _normalize_agg_interval(
                    agg_interval
                ),
                "interpolation": (
                    "true" if interpolation else "false"
                ),
                "format": "JSON",
            },
        )
        result = _result_object(
            payload,
            "quality/iqi/timeseries_groups",
        )
        return _parse_timeseries(
            result,
            metric=normalized_metric,
            scope=self._scope(
                normalized_location,
                normalized_asn,
            ),
        )

    def get_internet_quality(
        self,
        *,
        location: str = DEFAULT_LOCATION,
        asn: Any = None,
        date_range: str = DEFAULT_DATE_RANGE,
        agg_interval: str = DEFAULT_AGG_INTERVAL,
    ) -> Tuple[RadarTimeSeries, ...]:
        return tuple(
            self.get_iqi(
                metric,
                location=location,
                asn=asn,
                date_range=date_range,
                agg_interval=agg_interval,
            )
            for metric in (
                "LATENCY",
                "DNS",
                "BANDWIDTH",
            )
        )

    def get_outages(
        self,
        *,
        location: str = DEFAULT_LOCATION,
        asn: Any = None,
        date_range: str = "7d",
        outage_cause: Optional[str] = None,
        outage_type: Optional[str] = None,
        limit: int = 50,
    ) -> Tuple[RadarOutage, ...]:
        normalized_asn = _normalize_asn(asn)
        normalized_location = (
            _normalize_location(location)
            if normalized_asn is None
            else None
        )
        normalized_cause = _normalize_optional_enum(
            outage_cause,
            _ALLOWED_OUTAGE_CAUSES,
            "Radar outage cause",
        )
        normalized_type = _normalize_optional_enum(
            outage_type,
            _ALLOWED_OUTAGE_TYPES,
            "Radar outage type",
        )
        payload = self._request(
            "/radar/annotations/outages",
            query={
                "location": normalized_location,
                "asn": normalized_asn,
                "dateRange": _normalize_date_range(date_range),
                "outageCause": normalized_cause,
                "outageType": normalized_type,
                "limit": _normalize_limit(limit),
                "format": "JSON",
            },
        )
        result = _result_object(
            payload,
            "annotations/outages",
        )
        rows = result.get("annotations")
        if not isinstance(rows, list):
            raise CloudflareRadarError(
                "Cloudflare Radar returned invalid outage annotations"
            )

        normalized = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            outage = (
                row.get("outage")
                if isinstance(row.get("outage"), dict)
                else {}
            )
            normalized.append(
                RadarOutage(
                    annotation_id=str(row.get("id") or ""),
                    event_type=str(
                        row.get("eventType") or ""
                    ),
                    description=str(
                        row.get("description") or ""
                    ),
                    data_source=str(
                        row.get("dataSource") or ""
                    ),
                    scope=str(row.get("scope") or ""),
                    start_date=str(
                        row.get("startDate") or ""
                    ),
                    end_date=_optional_text(
                        row.get("endDate")
                    ),
                    outage_cause=_optional_text(
                        outage.get("outageCause")
                    ),
                    outage_type=_optional_text(
                        outage.get("outageType")
                    ),
                    locations=_tuple_text(
                        row.get("locations")
                    ),
                    asns=_tuple_text(row.get("asns")),
                    tags=_tuple_text(row.get("tags")),
                )
            )
        return tuple(normalized)


def _env_float(
    name: str,
    default: float,
) -> float:
    raw = str(os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise CloudflareRadarError(
            f"{name} must be numeric"
        ) from exc


def _env_int(
    name: str,
    default: int,
) -> int:
    raw = str(os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise CloudflareRadarError(
            f"{name} must be an integer"
        ) from exc
