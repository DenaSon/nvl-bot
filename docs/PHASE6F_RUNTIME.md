# Phase 6F — Regional Filtering Runtime Monitor

Status: implementation branch `feature/phase6f-filtering-runtime`

## Goal

Phase 6F activates the Phase 6D/6E filtering evidence pipeline inside the running
NVL bot while keeping the system strictly **MONITOR ONLY**.

The Core is the control plane. It schedules checks and stores evidence, but the
regional TCP probes target the customer-facing `service_port` of **Edge** servers.

Phase 6F does not perform DNS switching, account migration, Standby activation,
or failover.

## Runtime pipeline

```text
Core bot scheduler
       |
       v
Check-Host Iran nodes
       |
       v
Edge IP : service_port
       |
       v
Phase 6D normalized node evidence
       |
       v
Phase 6E spatial classifier
UNKNOWN / CLEAR / POSSIBLE / LIKELY
       |
       v
Phase 6C/6E temporal + local-path controls
       |
       v
persist final filter_state
       |
       +--> transition notifications
       |
       +--> Filtering Monitor UI
```

The current Core is always excluded from Edge regional probing.

## Default schedule

Defaults are code fallbacks; Phase 6F does not require an ENV migration.

- initial delay: 30 seconds
- scheduled interval: 600 seconds
- max Iran nodes: 8
- gap between Edge requests: 15 seconds

Optional ENV overrides:

- `NVL_REGIONAL_PROBE_INTERVAL`
- `NVL_REGIONAL_PROBE_INITIAL_DELAY`
- `NVL_REGIONAL_PROBE_EDGE_GAP`
- `NVL_REGIONAL_PROBE_MAX_NODES`
- `NVL_REGIONAL_PROVIDER_BACKOFF_BASE`
- `NVL_REGIONAL_PROVIDER_BACKOFF_MAX`

## Check-Host rate limiting

`limit_exceeded` is provider availability evidence, **not** Edge failure evidence.

Global backoff is exponential:

```text
1st limit -> 5 min
2nd       -> 10 min
3rd       -> 20 min
4th       -> 40 min
5th+      -> 60 min cap
```

The limit streak resets only after a **whole scheduled Edge round** succeeds
without provider errors/limits. A successful first Edge cannot erase a repeated
limit encountered on a later Edge.

During provider backoff:

- no new Check-Host request is sent;
- the previous filtering state is preserved;
- no fake regional failure is recorded;
- the admin UI shows provider/backoff state.

## External control

For every Edge regional round, Phase 6F also performs a direct TCP check from the
Core to the same Edge `service_port`.

This is stored as `external_service` with source `core-direct-tcp`.

It helps distinguish:

```text
Core -> Edge        UP
Iran -> Edge        FAIL
WG/Core path        UP
=> regional filtering evidence

Core -> Edge        FAIL
Iran -> Edge        FAIL
=> filtering cannot be isolated
```

## Temporal confirmation

Only consecutive **LIKELY** regional rounds build the filtering confirmation
streak.

- CLEAR: increments recovery streak; resets LIKELY streak
- LIKELY: increments strong failure streak; resets recovery streak
- POSSIBLE: resets both streaks
- UNKNOWN: resets both streaks

Therefore several POSSIBLE rounds cannot pre-fill a future LIKELY confirmation.

The final high-confidence LIKELY state still requires the Phase 6C/6E controls,
including healthy local paths and external reachability.

## Persistence

Phase 6F adds the following `host_pool` columns:

- `filter_state`
- `regional_filter_state`
- `regional_filter_reason`
- `regional_total_nodes`
- `regional_completed_nodes`
- `regional_successful_nodes`
- `regional_failed_nodes`
- `regional_pending_nodes`
- `regional_success_ratio`
- `regional_failed_asns`
- `regional_failed_cities`
- `regional_last_request_id`
- `regional_provider_status`
- `regional_provider_error`
- `regional_state_updated_at`

Raw normalized Check-Host node results are written to `host_probe_results` as
`regional_node` records. One aggregated `regional_service` row is also written
for each round.

## Transition notifications

Regional state transitions are always persisted for incident history and remain
visible in the monitoring UI, but Telegram admin notifications are intentionally
**critical-only**.

Telegram alerts are emitted only when entering one of these incident states:

- `FILTER_CONFIRMED`: high-confidence regional filtering is confirmed;
- `FAILOVER_BLOCKED`: confirmed filtering exists but automatic recovery cannot proceed safely;
- `FAILOVER_FAILED`: an automatic failover attempt failed.

These states remain silent in Telegram while still being recorded:

- `SUSPECTED`;
- `CONFIRMING`;
- `EVIDENCE_DEGRADED`;
- `RECOVERED`;
- `FAILOVER_STARTED`;
- `FAILOVER_SUCCEEDED`.

A reason-only change while already inside the same critical state does not emit
another alert. Initial healthy state population is also quiet.

## Management UI

Under the existing IP/host-pool management panel:

```text
🛡 فیلترینگ و دسترسی
```

The Filtering Monitor shows:

- final state per Edge;
- provider status/backoff;
- completed/failed regional nodes;
- confidence and diagnostic reason;
- Service/Admin/WireGuard/Core-path/External evidence;
- regional classifier reason;
- failed ASNs and cities;
- confirmation/recovery streaks;
- Check-Host request id;
- timestamps;
- recent raw node probes.

Available Phase 6F admin actions:

- recheck one Edge now;
- inspect raw recent node evidence;
- inspect persisted filtering details.

All remain diagnostic-only.

## Legacy V89 detector

The previous global online-percentage detector is downgraded to:

```text
Traffic Anomaly Signal
```

It can send a coarse anomaly warning, but it cannot:

- change the default host;
- change Cloudflare DNS;
- move accounts;
- activate Standby;
- trigger failover.

At bot startup, legacy `auto_failover_mode` is forced to `0` in Phase 6F.

Old Telegram callbacks for legacy auto failover / standby activation are guarded
and perform no action.

## Safety boundary

The Phase 6F regional runtime must not invoke:

- `_db_set_default_host`
- `_db_set_all_accounts_host`
- `_update_cloudflare_dns`
- `_cf_switch_public_domain`
- `_activate_standby_for_filtered_edge`
- `_db_set_host_active`
- Core/Edge promotion or demotion

Safe Manual Failover is Phase 6G. Automatic Failover is Phase 6H.

## Staging validation

Create a detached worktree for the Phase 6F branch, then:

```bash
/root/venv/bin/python3 -m py_compile \
  bot_final_v49-2.py \
  edge_observability.py \
  checkhost_probe.py \
  regional_filtering.py \
  filtering_runtime.py

/root/venv/bin/python3 -m unittest \
  tests.test_phase6c_regressions \
  tests.test_phase6d_checkhost \
  tests.test_phase6e_filtering \
  tests.test_phase6f_runtime \
  -v

/root/venv/bin/python3 -m unittest discover \
  -s tests \
  -p 'test_*.py' \
  -v
```

The staging test must pass before any production cutover.

## Production validation after merge/deploy

After the standard backup/cutover/restart workflow:

1. verify `nvlbot` is active and has no restart loop;
2. verify release marker:
   `V116.0-2026-10-03-phase6f-filtering-runtime`;
3. verify the Phase 6F monitor starts;
4. verify `auto_failover_mode=0`;
5. verify Core remains `CORE_LOCAL`;
6. inspect `host_pool.filter_state` and regional evidence for each Edge;
7. open the Telegram Filtering Monitor;
8. confirm that no DNS/account/Standby mutation occurred from regional monitoring.

Phase 6F is only complete after this production smoke validation succeeds.
