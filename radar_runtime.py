"""Cloudflare Radar V2 runtime, cache and persistence for NVL.

This module polls Radar as external Internet context only. It does not mutate
Edge filtering state, DNS, accounts, Standby membership, or failover policy and
does not send Telegram notifications.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

from cloudflare_radar import (
    CloudflareRadarAuthError,
    CloudflareRadarClient,
    CloudflareRadarError,
    CloudflareRadarRateLimited,
)
from radar_context import NetworkContextDecision, derive_network_context


log = logging.getLogger(__name__)

RADAR_PROVIDER = "cloudflare-radar"

PROVIDER_STATUS_NEVER = "NEVER"
PROVIDER_STATUS_OK = "OK"
PROVIDER_STATUS_PARTIAL = "PARTIAL"
PROVIDER_STATUS_RATE_LIMITED = "RATE_LIMITED"
PROVIDER_STATUS_AUTH_ERROR = "AUTH_ERROR"
PROVIDER_STATUS_CONFIG_ERROR = "CONFIG_ERROR"
PROVIDER_STATUS_ERROR = "ERROR"

SOURCE_STATUS_OK = "OK"
SOURCE_STATUS_RATE_LIMITED = "RATE_LIMITED"
SOURCE_STATUS_AUTH_ERROR = "AUTH_ERROR"
SOURCE_STATUS_CONFIG_ERROR = "CONFIG_ERROR"
SOURCE_STATUS_ERROR = "ERROR"
SOURCE_STATUS_SKIPPED = "SKIPPED"

DEFAULT_INTERVAL_SECONDS = 600
DEFAULT_INITIAL_DELAY_SECONDS = 45
DEFAULT_RETENTION_DAYS = 14

_SOURCE_NAMES = (
    "traffic_anomalies",
    "outages",
    "netflows",
    "latency",
    "dns",
    "bandwidth",
)


def _env_int(
    name: str,
    default: int,
    *,
    minimum: int = 0,
    maximum: Optional[int] = None,
) -> int:
    try:
        value = int(str(os.getenv(name, default)).strip())
    except (TypeError, ValueError):
        value = int(default)
    value = max(minimum, value)
    if maximum is not None:
        value = min(value, maximum)
    return value


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _sqlite_now() -> str:
    return _now_utc().strftime("%Y-%m-%d %H:%M:%S")


def _bounded_error(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"[:500]


def _provider_status(
    statuses: dict[str, str],
) -> str:
    values = tuple(statuses.values())
    if values and all(value == SOURCE_STATUS_OK for value in values):
        return PROVIDER_STATUS_OK
    if any(value == SOURCE_STATUS_OK for value in values):
        return PROVIDER_STATUS_PARTIAL
    if any(value == SOURCE_STATUS_AUTH_ERROR for value in values):
        return PROVIDER_STATUS_AUTH_ERROR
    if any(value == SOURCE_STATUS_CONFIG_ERROR for value in values):
        return PROVIDER_STATUS_CONFIG_ERROR
    if any(value == SOURCE_STATUS_RATE_LIMITED for value in values):
        return PROVIDER_STATUS_RATE_LIMITED
    return PROVIDER_STATUS_ERROR


def _provider_error(
    errors: dict[str, str],
) -> Optional[str]:
    if not errors:
        return None
    text = "; ".join(
        f"{name}={errors[name]}"
        for name in sorted(errors)
        if errors.get(name)
    )
    return text[:500] or None


def collect_radar_context(
    *,
    client: Optional[CloudflareRadarClient] = None,
    location: str = "IR",
    now: Optional[datetime] = None,
) -> NetworkContextDecision:
    """Collect one bounded Radar snapshot.

    Each endpoint is isolated so a non-primary metric failure does not discard
    valid outage/anomaly evidence. Authentication/rate-limit failures short-circuit
    remaining provider calls to avoid hammering a provider that has already refused
    the request.
    """

    location = str(location or "IR").strip().upper()
    statuses: dict[str, str] = {}
    errors: dict[str, str] = {}
    values: dict[str, Any] = {}

    if client is None:
        try:
            client = CloudflareRadarClient.from_env()
        except CloudflareRadarError as exc:
            for name in _SOURCE_NAMES:
                statuses[name] = SOURCE_STATUS_CONFIG_ERROR
            errors["configuration"] = _bounded_error(exc)
            return derive_network_context(
                provider_status=PROVIDER_STATUS_CONFIG_ERROR,
                provider_error=_provider_error(errors),
                source_statuses=statuses,
                scope_type="COUNTRY",
                scope_value=location,
                provider=RADAR_PROVIDER,
                now=now,
            )

    calls: tuple[tuple[str, Callable[[], Any]], ...] = (
        (
            "traffic_anomalies",
            lambda: client.get_traffic_anomalies(
                location=location,
                date_range="1d",
                status="VERIFIED",
            ),
        ),
        (
            "outages",
            lambda: client.get_outages(
                location=location,
                date_range="7d",
            ),
        ),
        (
            "netflows",
            lambda: client.get_netflows(
                location=location,
                date_range="1d",
                agg_interval="15m",
            ),
        ),
        (
            "latency",
            lambda: client.get_iqi(
                "LATENCY",
                location=location,
                date_range="1d",
                agg_interval="15m",
            ),
        ),
        (
            "dns",
            lambda: client.get_iqi(
                "DNS",
                location=location,
                date_range="1d",
                agg_interval="15m",
            ),
        ),
        (
            "bandwidth",
            lambda: client.get_iqi(
                "BANDWIDTH",
                location=location,
                date_range="1d",
                agg_interval="15m",
            ),
        ),
    )

    stop_status: Optional[str] = None
    for name, call in calls:
        if stop_status is not None:
            statuses[name] = SOURCE_STATUS_SKIPPED
            continue
        try:
            values[name] = call()
            statuses[name] = SOURCE_STATUS_OK
        except CloudflareRadarAuthError as exc:
            statuses[name] = SOURCE_STATUS_AUTH_ERROR
            errors[name] = _bounded_error(exc)
            stop_status = SOURCE_STATUS_AUTH_ERROR
        except CloudflareRadarRateLimited as exc:
            statuses[name] = SOURCE_STATUS_RATE_LIMITED
            errors[name] = _bounded_error(exc)
            stop_status = SOURCE_STATUS_RATE_LIMITED
        except CloudflareRadarError as exc:
            statuses[name] = SOURCE_STATUS_ERROR
            errors[name] = _bounded_error(exc)

    provider_status = _provider_status(statuses)
    provider_error = _provider_error(errors)

    return derive_network_context(
        provider_status=provider_status,
        provider_error=provider_error,
        source_statuses=statuses,
        anomalies=values.get("traffic_anomalies") or (),
        outages=values.get("outages") or (),
        netflows=values.get("netflows"),
        latency=values.get("latency"),
        dns=values.get("dns"),
        bandwidth=values.get("bandwidth"),
        scope_type="COUNTRY",
        scope_value=location,
        provider=RADAR_PROVIDER,
        now=now,
    )


@contextlib.contextmanager
def _db_conn(db_path: str):
    conn = sqlite3.connect(str(db_path), timeout=10)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=10000")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def ensure_radar_schema(db_path: str) -> None:
    with _db_conn(db_path) as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS settings "
            "(key TEXT PRIMARY KEY, value TEXT)"
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS network_context_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider TEXT NOT NULL,
                scope_type TEXT NOT NULL,
                scope_value TEXT NOT NULL,
                state TEXT NOT NULL,
                reason TEXT NOT NULL,
                provider_status TEXT NOT NULL,
                provider_error TEXT DEFAULT NULL,
                anomaly_count INTEGER NOT NULL DEFAULT 0,
                active_anomaly_count INTEGER NOT NULL DEFAULT 0,
                outage_count INTEGER NOT NULL DEFAULT 0,
                active_outage_count INTEGER NOT NULL DEFAULT 0,
                traffic_value REAL DEFAULT NULL,
                traffic_delta_pct REAL DEFAULT NULL,
                traffic_unit TEXT DEFAULT NULL,
                latency_value REAL DEFAULT NULL,
                latency_unit TEXT DEFAULT NULL,
                dns_value REAL DEFAULT NULL,
                dns_unit TEXT DEFAULT NULL,
                bandwidth_value REAL DEFAULT NULL,
                bandwidth_unit TEXT DEFAULT NULL,
                confidence_level INTEGER DEFAULT NULL,
                detail_json TEXT DEFAULT NULL,
                observed_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            )"""
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_network_context_scope_observed "
            "ON network_context_snapshots("
            "provider, scope_type, scope_value, observed_at)"
        )


def _set_setting(
    conn: sqlite3.Connection,
    key: str,
    value: Any,
) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)",
        (str(key), "" if value is None else str(value)),
    )


def _get_setting(
    conn: sqlite3.Connection,
    key: str,
    default: str = "",
) -> str:
    row = conn.execute(
        "SELECT value FROM settings WHERE key=?",
        (str(key),),
    ).fetchone()
    return str(row[0]) if row else str(default)


def _safe_int(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def persist_radar_snapshot(
    db_path: str,
    snapshot: NetworkContextDecision,
    *,
    retention_days: int = DEFAULT_RETENTION_DAYS,
) -> int:
    ensure_radar_schema(db_path)
    now = _sqlite_now()
    details = snapshot.to_dict()

    with _db_conn(db_path) as conn:
        cursor = conn.execute(
            """INSERT INTO network_context_snapshots (
                provider, scope_type, scope_value, state, reason,
                provider_status, provider_error,
                anomaly_count, active_anomaly_count,
                outage_count, active_outage_count,
                traffic_value, traffic_delta_pct, traffic_unit,
                latency_value, latency_unit,
                dns_value, dns_unit,
                bandwidth_value, bandwidth_unit,
                confidence_level, detail_json, observed_at, created_at
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )""",
            (
                snapshot.provider,
                snapshot.scope_type,
                snapshot.scope_value,
                snapshot.state,
                snapshot.reason,
                snapshot.provider_status,
                snapshot.provider_error,
                snapshot.anomaly_count,
                snapshot.active_anomaly_count,
                snapshot.outage_count,
                snapshot.active_outage_count,
                snapshot.traffic.value,
                snapshot.traffic.delta_pct,
                snapshot.traffic.unit,
                snapshot.latency.value,
                snapshot.latency.unit,
                snapshot.dns.value,
                snapshot.dns.unit,
                snapshot.bandwidth.value,
                snapshot.bandwidth.unit,
                snapshot.confidence_level,
                json.dumps(
                    details,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    default=str,
                ),
                snapshot.observed_at,
                now,
            ),
        )

        previous_status = _get_setting(
            conn,
            "radar_provider_status",
            PROVIDER_STATUS_NEVER,
        )
        success_streak = _safe_int(
            _get_setting(conn, "radar_provider_success_streak", "0")
        )
        error_streak = _safe_int(
            _get_setting(conn, "radar_provider_error_streak", "0")
        )

        if snapshot.provider_status == PROVIDER_STATUS_OK:
            success_streak += 1
            error_streak = 0
            _set_setting(conn, "radar_provider_last_success_at", now)
        else:
            error_streak += 1
            success_streak = 0

        _set_setting(conn, "radar_provider_previous_status", previous_status)
        _set_setting(conn, "radar_provider_status", snapshot.provider_status)
        _set_setting(
            conn,
            "radar_provider_last_error",
            snapshot.provider_error or "",
        )
        _set_setting(conn, "radar_provider_last_check_at", now)
        _set_setting(conn, "radar_provider_success_streak", success_streak)
        _set_setting(conn, "radar_provider_error_streak", error_streak)
        _set_setting(conn, "radar_context_state", snapshot.state)
        _set_setting(conn, "radar_context_reason", snapshot.reason)
        _set_setting(conn, "radar_context_observed_at", snapshot.observed_at)

        keep_days = max(1, int(retention_days))
        cutoff = (
            _now_utc() - timedelta(days=keep_days)
        ).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "DELETE FROM network_context_snapshots "
            "WHERE created_at < ?",
            (cutoff,),
        )
        return int(cursor.lastrowid)


def load_latest_radar_snapshot(
    db_path: str,
    *,
    scope_type: str = "COUNTRY",
    scope_value: str = "IR",
) -> Optional[dict]:
    ensure_radar_schema(db_path)
    with _db_conn(db_path) as conn:
        row = conn.execute(
            "SELECT detail_json FROM network_context_snapshots "
            "WHERE provider=? AND scope_type=? AND scope_value=? "
            "ORDER BY id DESC LIMIT 1",
            (
                RADAR_PROVIDER,
                str(scope_type or "COUNTRY").upper(),
                str(scope_value or "IR").upper(),
            ),
        ).fetchone()
    if not row or not row[0]:
        return None
    try:
        data = json.loads(row[0])
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def get_radar_provider_runtime(db_path: str) -> dict:
    ensure_radar_schema(db_path)
    with _db_conn(db_path) as conn:
        return {
            "status": _get_setting(
                conn,
                "radar_provider_status",
                PROVIDER_STATUS_NEVER,
            ),
            "previous_status": _get_setting(
                conn,
                "radar_provider_previous_status",
                PROVIDER_STATUS_NEVER,
            ),
            "last_error": _get_setting(
                conn,
                "radar_provider_last_error",
                "",
            ),
            "last_check_at": _get_setting(
                conn,
                "radar_provider_last_check_at",
                "",
            ),
            "last_success_at": _get_setting(
                conn,
                "radar_provider_last_success_at",
                "",
            ),
            "success_streak": _safe_int(
                _get_setting(
                    conn,
                    "radar_provider_success_streak",
                    "0",
                )
            ),
            "error_streak": _safe_int(
                _get_setting(
                    conn,
                    "radar_provider_error_streak",
                    "0",
                )
            ),
            "context_state": _get_setting(
                conn,
                "radar_context_state",
                "UNKNOWN",
            ),
            "context_reason": _get_setting(
                conn,
                "radar_context_reason",
                "PROVIDER_UNAVAILABLE",
            ),
            "context_observed_at": _get_setting(
                conn,
                "radar_context_observed_at",
                "",
            ),
        }


class RadarMonitor:
    """Async scheduler wrapper around the synchronous Radar V2 collector."""

    def __init__(
        self,
        db_path: str,
        *,
        location: Optional[str] = None,
        interval_seconds: Optional[int] = None,
        initial_delay_seconds: Optional[int] = None,
        retention_days: Optional[int] = None,
        client: Optional[CloudflareRadarClient] = None,
    ) -> None:
        self.db_path = str(db_path)
        self.location = str(
            location
            or os.getenv("NVL_RADAR_LOCATION", "IR")
            or "IR"
        ).strip().upper()
        self.interval_seconds = (
            max(60, int(interval_seconds))
            if interval_seconds is not None
            else _env_int(
                "NVL_RADAR_INTERVAL",
                DEFAULT_INTERVAL_SECONDS,
                minimum=60,
            )
        )
        self.initial_delay_seconds = (
            max(0, int(initial_delay_seconds))
            if initial_delay_seconds is not None
            else _env_int(
                "NVL_RADAR_INITIAL_DELAY",
                DEFAULT_INITIAL_DELAY_SECONDS,
                minimum=0,
            )
        )
        self.retention_days = (
            max(1, int(retention_days))
            if retention_days is not None
            else _env_int(
                "NVL_RADAR_RETENTION_DAYS",
                DEFAULT_RETENTION_DAYS,
                minimum=1,
                maximum=365,
            )
        )
        self.client = client

    def ensure_schema(self) -> None:
        ensure_radar_schema(self.db_path)

    def collect_once(self) -> NetworkContextDecision:
        return collect_radar_context(
            client=self.client,
            location=self.location,
        )

    def persist(self, snapshot: NetworkContextDecision) -> int:
        return persist_radar_snapshot(
            self.db_path,
            snapshot,
            retention_days=self.retention_days,
        )

    async def tick(self, app) -> NetworkContextDecision:
        snapshot = await asyncio.to_thread(self.collect_once)
        await asyncio.to_thread(self.persist, snapshot)

        app.bot_data["radar_network_context"] = snapshot.to_dict()
        app.bot_data["radar_provider_health"] = await asyncio.to_thread(
            get_radar_provider_runtime,
            self.db_path,
        )

        log.info(
            "Radar V2 context state=%s reason=%s provider=%s "
            "anomalies=%s active_anomalies=%s outages=%s active_outages=%s",
            snapshot.state,
            snapshot.reason,
            snapshot.provider_status,
            snapshot.anomaly_count,
            snapshot.active_anomaly_count,
            snapshot.outage_count,
            snapshot.active_outage_count,
        )
        return snapshot

    async def loop(self, app) -> None:
        self.ensure_schema()
        previous = await asyncio.to_thread(
            load_latest_radar_snapshot,
            self.db_path,
            scope_type="COUNTRY",
            scope_value=self.location,
        )
        if previous:
            app.bot_data["radar_network_context"] = previous
        app.bot_data["radar_provider_health"] = await asyncio.to_thread(
            get_radar_provider_runtime,
            self.db_path,
        )

        if self.initial_delay_seconds > 0:
            await asyncio.sleep(self.initial_delay_seconds)

        log.info(
            "Radar V2 monitor started location=%s interval=%ss retention=%sd",
            self.location,
            self.interval_seconds,
            self.retention_days,
        )
        while True:
            try:
                await self.tick(app)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception(
                    "Radar V2 monitor failed; next scheduled round will continue."
                )
            await asyncio.sleep(self.interval_seconds)
