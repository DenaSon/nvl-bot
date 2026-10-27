# LEGACY IP ROUTE FREEZE — 2026-10-27

## Decision and observed Production baseline

This patch is **source only** until the operator deploys it to Core.
Owner read-only evidence at 2026-10-27:

- 489 active SSH users all pinned to `144.172.68.167`.
- `dns_current_ip=144.172.68.167`, `settings.hosts=144.172.68.167`.
- Four active inventory rows: default `144.172.68.167`, other Edges
  `144.172.68.157`, `144.172.68.62`, plus Core `91.107.170.239`.
- `phase6h_auto_failover_enabled=0`, `auto_failover_mode=0`.
- IP pressure streak 0 / no elapsed pressure; `nvl-edge-sync.timer` disabled.

## Scope

1. Retain automatic CPU/RAM and Edge health monitoring, persistence, and alerts;
   retire automatic 3-hour full account rebalancing and automatic host disable
   or DNS changes from `_host_health_tick`.
2. Only a single active, non-Standby, non-Core default Relay with matching
   `dns_current_ip` may be written into `settings.hosts`. Inventory membership
   is **not** the list of customer routes. A mismatch blocks publishing.
3. Legacy direct host-override setters refuse nondefault destinations. This
   prevents one-click old Telegram controls and future accidental callers
   from scattering SSH account metadata across all active inventory entries.
4. Old Round-Robin and pressure-based immediate migrate callbacks remain
   present but explicitly refuse mutation; legacy default selection/retirement
   refuses changing the current global route outside the journaled cutover.
5. CZ-04B/CZ-07 guarded operations and original 6G/6H transaction engine
   are deliberately **not modified**. Phase 6H is still a separate opt-in
   capability and remains OFF in the observed Production configuration.
6. In legacy IP Service UI, the old filtering traffic anomaly is described
   as alert-only, matching the existing runtime semantics.

## Pressure escalation

- Retain the 300-second check, threshold, and two-consecutive-check debounce.
- First sustained threshold crossing sends the initial warning.
- After the historical 3-hour deadline, send **one additional alert**, persist
  `ip_pressure_escalated_at` (a notification timestamp, not a route-change
  flag), and never change users, DNS, or host eligibility.
- When pressure clears, reset the incident counters; a new episode may alert
  again.

## Deliberate compatibility holds

- The legacy `hpdef_` handler cannot atomically change the default plus DNS
  plus customer ownership. It now instructs the admin to use CZ-04B.
- The legacy `hpblk_`/`hpdelyes_` handlers refuse the current default. An
  unselected nondefault host may still be manually managed with existing
  verification and lock guards.
- Bulk/single metadata host reassignment can only target the verified current
  default. Multi-relay movement must use CZ-04B/CZ-07 or the protected
  migration engine, not metadata-only legacy callbacks.

## Verification and deployment boundary

Regression unit tests: `tests/test_legacy_route_mutation_freeze.py` and
the updated `tests/test_hf01_dns_route_guard.py`. Run full GitHub CI.
No live DNS mutations, WireGuard alterations, database migration, Core
restart, customer move or Production deployment occur in this change.

After operator deploy, run read-only DB checks for active SSH counts per host,
`settings.hosts`, `dns_current_ip`, `host_pool` default, 6H OFF, and
journal lines for pressure and health. A GitHub merge by itself is not a
production acceptance.
