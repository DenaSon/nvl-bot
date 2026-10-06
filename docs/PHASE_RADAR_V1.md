# Radar V1 — Cloudflare Radar Core

Status: implementation branch feature/radar-v1-core

## Goal

Radar V1 adds a read-only Cloudflare Radar integration without changing the existing
regional filtering classifier, persistence, Telegram UI, notifications, or failover
policy.

The module is external-context only. It cannot mark an Edge filtered, change DNS,
move accounts, activate Standby, or trigger failover.

## Module

cloudflare_radar.py

Supported read-only calls:

- get_traffic_anomalies() -> /radar/traffic_anomalies
- get_netflows() -> /radar/netflows/timeseries
- get_iqi() -> /radar/quality/iqi/timeseries_groups
- get_internet_quality() -> LATENCY + DNS + BANDWIDTH IQI calls
- get_outages() -> /radar/annotations/outages

Defaults target Iran (IR) and short monitoring windows. ASN scope is also supported
for later correlation work.

## Normalized models

Radar V1 exposes provider-neutral immutable models:

- RadarTrafficAnomaly
- RadarTimeSeries
- RadarMeta
- RadarOutage

No NORMAL / DEGRADED / OUTAGE classification is performed in V1. That belongs to
the later network-context phase so provider retrieval remains separate from policy.

## Failure handling

The client is fail-closed:

- missing token -> configuration error;
- 401/403 -> authorization error, no retry;
- 429 -> bounded retry, honoring numeric Retry-After when present;
- network errors and 5xx -> bounded exponential retry;
- malformed JSON/result shapes -> provider error;
- secrets are never returned in normalized models.

Defaults:

- timeout: 8 seconds
- retries: 2
- backoff base: 0.5 seconds
- backoff max: 8 seconds

## Environment

NVL_CLOUDFLARE_RADAR_API_TOKEN=
NVL_CLOUDFLARE_RADAR_TIMEOUT=8
NVL_CLOUDFLARE_RADAR_RETRIES=2
NVL_CLOUDFLARE_RADAR_BACKOFF_BASE=0.5
NVL_CLOUDFLARE_RADAR_BACKOFF_MAX=8

The Radar token is intentionally separate from NVL_CLOUDFLARE_API_TOKEN, which is
used by the DNS automation path.

## Safety boundary

Radar V1 must not:

- write SQLite;
- change host_pool;
- modify filter_state;
- send Telegram notifications;
- schedule polling;
- alter Cloudflare DNS;
- influence differential filtering;
- trigger manual or automatic failover.

## Tests

tests/test_cloudflare_radar.py covers token validation, query defaults, NetFlows,
dynamic IQI percentile parsing, timestamp-only IQI responses, outage parsing, ASN
scope, validation-before-I/O, retry behavior, auth failures, malformed provider
responses, and the no-side-effect boundary.

Local V1 checks:

    python -m py_compile cloudflare_radar.py
    python -m unittest tests.test_cloudflare_radar -v

Full repository suite remains the merge gate:

    python -m unittest discover -s tests -v

## Next phase

Radar V2 will add runtime scheduling, cache/persistence, provider health, and
network-context snapshots. V1 remains a passive API adapter.
