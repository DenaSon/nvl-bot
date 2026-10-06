# Radar V2 — Runtime, Persistence and Network Context

Status: implementation branch feature/radar-v2-runtime

## Goal

Radar V2 turns the V1 read-only Cloudflare Radar client into a continuously updated
external Internet-context source for NVL.

This phase remains monitor-only. It does not change Edge filtering verdicts, send
Telegram notifications, modify Cloudflare DNS, move accounts, activate Standby, or
influence manual/automatic failover.

## Architecture

    Cloudflare Radar
        |
        +-- Traffic Anomalies
        +-- Outage Annotations
        +-- NetFlows
        +-- IQI: Latency / DNS / Bandwidth
        |
        v
    radar_runtime.py
        |
        v
    radar_context.py
        |
        +-- NORMAL
        +-- DEGRADED
        +-- OUTAGE
        +-- UNKNOWN
        |
        +--> app.bot_data cache
        |
        +--> network_context_snapshots (SQLite)
        |
        +--> provider runtime settings

## Conservative classification policy

V2 deliberately avoids inventing thresholds.

- active non-instantaneous Cloudflare outage annotation -> OUTAGE
- active VERIFIED Traffic Anomaly -> DEGRADED
- both primary sources healthy with no active event -> NORMAL
- missing/incomplete primary evidence -> UNKNOWN

NetFlows and IQI values are stored as context metrics only. They do not independently
produce DEGRADED/OUTAGE in V2. Threshold-based interpretation is deferred until real
production data can be observed and calibrated.

Instantaneous outage annotations are retained in history but do not remain active merely
because endDate is empty.

## Runtime

Default schedule:

- initial delay: 45 seconds
- interval: 600 seconds
- location: IR
- snapshot retention: 14 days

Environment overrides:

    NVL_RADAR_LOCATION=IR
    NVL_RADAR_INTERVAL=600
    NVL_RADAR_INITIAL_DELAY=45
    NVL_RADAR_RETENTION_DAYS=14

The V1 client timeout/retry settings continue to apply.

The monitor runs through asyncio.to_thread so urllib and SQLite work do not block the
Telegram event loop.

## Persistence

Radar data is intentionally not stored in host_pool because country/ASN Internet context
is not an Edge property.

New table:

    network_context_snapshots

It stores one normalized snapshot per collection round, including:

- state/reason
- provider status/error
- anomaly/outage counts
- latest NetFlows/IQI metric values
- short-term metric delta where available
- confidence level
- normalized detail JSON
- observed/created timestamps

Provider current state is stored under dedicated settings keys:

- radar_provider_status
- radar_provider_previous_status
- radar_provider_last_error
- radar_provider_last_check_at
- radar_provider_last_success_at
- radar_provider_success_streak
- radar_provider_error_streak
- radar_context_state
- radar_context_reason
- radar_context_observed_at

## Provider health

Provider health is independent of network state:

- OK
- PARTIAL
- RATE_LIMITED
- AUTH_ERROR
- CONFIG_ERROR
- ERROR

A provider problem cannot be interpreted as an Iran Internet outage.

## Cache

The latest snapshot is also copied into:

    app.bot_data["radar_network_context"]
    app.bot_data["radar_provider_health"]

bot_data persistence remains disabled, so SQLite is the durable source of truth.

## Safety boundary

Radar V2 must not call or reference:

- host/default mutation functions
- account migration
- Cloudflare DNS mutation
- Standby activation
- Core/Edge promotion or demotion
- admin notification functions
- failover execution

The bot lifecycle integration only starts and cleanly cancels the Radar monitor task.

## Tests

V2 coverage includes:

- outage/anomaly state classification
- ended and instantaneous event handling
- incomplete primary evidence
- NetFlows/IQI metrics remaining context-only
- full provider collection
- rate-limit short-circuiting
- SQLite snapshot round-trip
- provider success/error streaks
- bot_data cache
- bot startup/shutdown task wiring
- static no-operational-side-effect guard

Full repository CI remains the merge gate.

## Next phase

Radar V3 adds Telegram Monitoring UI and a low-noise transition notification policy.
No failover correlation is introduced until Radar V4.
