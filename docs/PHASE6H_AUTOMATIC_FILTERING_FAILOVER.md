# Phase 6H — Automatic Filtering Failover

Phase 6H connects the regional filtering evidence pipeline to the rollback-aware
Phase 6G failover engine. It does **not** create a second migration/DNS path.

## Safety model

Automatic failover is opt-in and defaults to OFF.

An automatic attempt is eligible only when all of the following are true:

- the admin explicitly enabled `auto_failover_mode`;
- the source is the current default Edge and is not a Standby;
- the source filtering state is `LIKELY`;
- filtering confidence is `HIGH`;
- the diagnostic reason is `FILTER_SUSPECTED`;
- the regional failure streak reached the configured confirmation threshold;
- the regional provider round completed successfully;
- the global post-switch cooldown has expired;
- the automatic-attempt cooldown has expired;
- at least one active Standby has strict healthy persisted evidence.

The legacy traffic-anomaly signal based on global online-user percentage remains
notification-only and cannot trigger failover.

## Standby selection

Phase 6H accepts a Standby candidate only when its persisted evidence says:

- `filter_state=CLEAR`;
- customer Service is healthy;
- Admin SSH is healthy;
- WireGuard peer is healthy;
- Core path is healthy;
- Core-to-Edge external service probe is healthy.

Safe candidates are deterministic and prefer lower recorded latency. The selected
candidate is still subjected to the complete fresh Phase 6G preflight immediately
before any customer-state mutation.

## Shared execution engine

Automatic operations call the same Phase 6G engine with `mode=AUTO`.

The engine still provides:

1. one persisted failover lock;
2. source/target/Core validation;
3. temporary DNS fallback to Core;
4. exact account rebuild on Standby;
5. post-rebuild target verification;
6. atomic source-set revalidation + DB/default ownership move;
7. atomic consumption of the Target Standby role;
8. final DNS handoff;
9. Core-first recovery and DB rollback when final DNS fails;
10. fail-closed Target ownership retention when route recovery is uncertain.

No automatic path bypasses these gates.

## Cooldowns

Two independent cooldowns are used:

- `NVL_AUTO_FAILOVER_SWITCH_COOLDOWN_SECONDS` — default 1800 seconds;
- `NVL_AUTO_FAILOVER_ATTEMPT_COOLDOWN_SECONDS` — default 900 seconds.

The attempt timestamp is persisted before network/preflight work starts so a
repeated safe failure cannot hammer DNS/SSH on every regional-monitor round.

## Admin UI

A direct entry is available from:

`Settings -> Filtering Status`

The Filtering Monitor shows whether Automatic Failover is ON or OFF.

Enabling Automatic Failover requires an explicit confirmation screen. Disabling it
is immediate and does not disable monitoring.

## Production rollout

Recommended rollout:

1. deploy with Automatic Failover OFF;
2. verify Phase 6H monitor UI and current Edge/Standby evidence;
3. run isolated automatic-policy and failure-injection drills;
4. enable Automatic Failover only after a known-good Standby is present;
5. observe the first real automatic operation and its persisted
   `failover_operations.mode=AUTO` journal.
