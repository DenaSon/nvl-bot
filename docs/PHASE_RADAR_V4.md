# Radar V4 — Incident Correlation and Auto-Failover Safety Gate

Status: implementation branch `feature/radar-v4-correlation-gate`

## Goal

Radar V4 correlates Cloudflare Radar Internet context with NVL's existing differential
regional filtering evidence.

Radar remains negative-only external context: it may stop an automatic failover when
there is strong fresh evidence of a widespread Internet outage, but it cannot create,
upgrade, or confirm an Edge filtering verdict.

## Correlation states

`incident_correlation.py` returns one of:

- `TARGET_SPECIFIC_FILTERING`
- `WIDESPREAD_NETWORK_OUTAGE`
- `SHARED_NETWORK_FAILURE`
- `INSUFFICIENT_EVIDENCE`

### Target-specific filtering

A current differential result that is confirmed and has verdict
`TARGET_SPECIFIC_REGIONAL_FAILURE` remains target-specific unless a fresh explicit
Radar OUTAGE is active.

### Widespread outage

A fresh Radar snapshot with state `OUTAGE` becomes
`WIDESPREAD_NETWORK_OUTAGE`.

This classification has `failover_inhibited=True` for automatic failover only.

### Shared regional failure

A differential `SHARED_REGIONAL_FAILURE` is classified separately. Phase 6H already
blocks this because differential confirmation is absent; Radar does not replace that gate.

## Freshness

Default maximum Radar age for AUTO safety decisions:

`NVL_RADAR_FAILOVER_CONTEXT_MAX_AGE=1200`

A missing, malformed, future-dated, or stale Radar snapshot never blocks an otherwise
valid automatic failover.

Radar `DEGRADED` and `NORMAL` also never block automatic failover.

## Phase 6H integration

The existing Phase 6H path remains authoritative:

1. confirm source/default/filtering prerequisites;
2. load the latest matching differential evidence;
3. load latest Radar country context;
4. derive incident correlation;
5. if fresh widespread outage exists, block AUTO;
6. otherwise continue existing differential/provider/cooldown/Standby gates;
7. eligible operations still execute through the unchanged Phase 6G safe engine.

No new DNS/migration execution path is introduced.

## Manual failover

Manual failover is deliberately unchanged.

Radar V4 does not appear inside `_safe_manual_failover`, and the operator can still
perform a manual safe failover if they intentionally decide it is appropriate.

## Notification behavior

Radar V3 already sends one transition-based OUTAGE notification.

When V4 blocks AUTO because of the same outage:

- the incident block is persisted;
- the correlation reason/details are logged;
- no second generic "automatic failover blocked" Telegram message is sent.

The Radar OUTAGE notification now explicitly states that the automatic safety gate is
temporarily active and that manual failover/filtering diagnosis remain independent.

## Monitoring UI

The existing Filtering Monitor shows one extra Radar Safety Gate line:

- red/blocked when a fresh widespread Radar outage is active;
- green when there is a Radar snapshot but no fresh widespread outage;
- unknown when Radar has no snapshot yet.

## Safety boundary

Radar V4 must not:

- mutate `filter_state`;
- turn NORMAL/DEGRADED Radar data into filtering confirmation;
- bypass differential confirmation;
- trigger automatic failover;
- alter the manual failover engine;
- change DNS/accounts/Standby state itself;
- keep blocking AUTO from stale Radar context.

## Tests

Coverage includes:

- fresh OUTAGE inhibits AUTO even with target-specific differential evidence;
- stale OUTAGE does not inhibit;
- DEGRADED does not inhibit;
- missing Radar does not inhibit;
- NORMAL Radar does not create filtering evidence;
- shared differential failure classification;
- widespread-outage reason precedence over secondary auto-block reasons;
- manual failover remains Radar-independent;
- duplicate outage/block notification suppression;
- monitor Safety Gate wiring.

Full repository GitHub Actions remains the merge gate.
