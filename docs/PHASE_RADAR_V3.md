# Radar V3 — Monitoring UI and Low-Noise Notifications

Status: implementation branch `feature/radar-v3-ui-notifications`

## Goal

Radar V3 exposes the existing Cloudflare Radar network context inside the current
Filtering Monitor and adds a deliberately conservative Telegram notification policy.

This phase still does not influence filtering classification, DNS, account placement,
Standby activation, or automatic/manual failover.

## UI

Radar is shown inside the existing:

`🛡 فیلترینگ و دسترسی`

The main Filtering Monitor receives a compact Iran Internet card with:

- network state: NORMAL / DEGRADED / OUTAGE / UNKNOWN;
- Cloudflare Radar provider health;
- latest Traffic value/change;
- Latency;
- DNS;
- Bandwidth;
- last observation time.

A dedicated `🌐 جزئیات اینترنت ایران` action shows:

- current state/reason;
- provider status;
- anomaly/outage counts;
- source-by-source health;
- metric values;
- recent context history;
- last Radar provider error.

Radar does not receive a separate top-level monitoring area.

## Notification policy

Notifications are state-transition driven and intentionally sparse.

### OUTAGE

An active Cloudflare outage annotation is already strong provider evidence, so entry
into OUTAGE notifies immediately.

Repeated OUTAGE snapshots do not notify again.

### DEGRADED

DEGRADED requires two consecutive snapshots by default:

`NVL_RADAR_DEGRADED_CONFIRM_ROUNDS=2`

The first DEGRADED snapshot is silent. The second consecutive DEGRADED snapshot emits
one notification. Further DEGRADED snapshots are silent.

NetFlows, latency, DNS or bandwidth changes by themselves never send a notification.

### Recovery

Recovery from DEGRADED/OUTAGE requires two consecutive NORMAL snapshots by default:

`NVL_RADAR_RECOVERY_CONFIRM_ROUNDS=2`

Only then is one recovery notification emitted.

### UNKNOWN and provider errors

UNKNOWN, authentication failures, rate limits, configuration errors and provider
transport errors do not send Telegram notifications.

They remain visible in logs and the Radar UI.

### Anti-flap rule

After a notified OUTAGE, a move to DEGRADED does not send a second warning and does not
declare recovery. The effective incident remains OUTAGE until confirmed NORMAL recovery.

## Persistence

Notification state is stored in existing settings keys:

- `radar_notify_effective_state`
- `radar_notify_degraded_streak`
- `radar_notify_normal_streak`
- `radar_notify_last_kind`
- `radar_notify_last_sent_at`

This makes the anti-spam state survive bot restarts.

## Runtime integration

`RadarMonitor` accepts an optional `on_snapshot` callback.

The runtime order is:

1. collect Radar evidence;
2. persist normalized snapshot;
3. refresh provider/cache state;
4. invoke the V3 notification callback;
5. return to the normal 10-minute polling schedule.

The callback is invoked only after persistence succeeds.

## Safety boundary

Radar V3 must not:

- change Edge filter state;
- add Radar as a vote to regional filtering;
- alter differential filtering;
- change Cloudflare DNS;
- move accounts;
- activate/deactivate Standby;
- call manual or automatic failover;
- notify on provider errors;
- notify on raw metric movement alone.

## Tests

V3 includes coverage for:

- immediate one-shot OUTAGE notification;
- two-round DEGRADED confirmation;
- persistent DEGRADED silence;
- OUTAGE -> DEGRADED anti-flap behavior;
- two-round recovery confirmation;
- UNKNOWN silence/streak reset;
- compact/detail UI rendering;
- HTML escaping;
- snapshot callback ordering;
- bot UI/callback wiring;
- static no-failover boundary.

Full repository GitHub Actions remains the merge gate.

## Next phase

Radar V4 may correlate Radar context with Check-Host regional evidence and differential
filtering. Any failover inhibition based on widespread outage belongs to V4 and is not
part of V3.
