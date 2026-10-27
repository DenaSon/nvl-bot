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

## Scope — compatible with the 2026-10-27 follow-up patch

1. Automatic CPU/RAM pressure and Edge health tasks are **monitor/alert only**:
   no background account reassignment, default change, DNS update, or host retirement.
2. Admin-initiated **Legacy** paths are preserved as fallback while CZ-04B/CZ-07
   is not operationally reliable: manual Edge provision, activation, choosing a
   default (`hpdef_`), and the second-stage manual customer transfer
   (`hpdef_migrate_` / `hpdefmig_yes_`).
3. `_db_rebuild_hosts_from_pool` is kept for explicit manual operations: it
   rebuilds the legacy host picker from active `host_pool`, default first.
   This may include the Core fallback and additional active Edges, as it did
   prior to PR #208. It does NOT allocate customers or change DNS.
4. Legacy account setters keep the existing 6G running-operation lock and
   protected Egress/bindings guard. They may set manually chosen nondefault
   hosts; automatic callers have been retired.
5. **New Legacy customers still use only the verified active, non-Standby,
   non-Core default** via `_default_customer_relay_checked`. This rule is
   independent of additional inventory entries in `settings.hosts`.
6. The old Round-Robin confirm callback and CPU-pressure automatic transfer
   remain disabled; no automatic routing is restored.
7. CZ-04A/CZ-04B/CZ-07 and original 6G/6H paths remain unchanged. The Phase
   6H opt-in flag was OFF in the Production snapshot; it is NOT changed by
   this patch.

**Important historic behavior:** The Legacy default-selection button is
two-stage. It updates the database default before the separate transfer+DNS
confirmation. During that gap, the new-customer routing guard intentionally
refuses to issue new accounts (`DEFAULT_CUSTOMER_RELAY_ROUTE_MISMATCH`) rather
than silently selling an account on the wrong Relay. The manual cutover is
not atomic and must be operator-controlled and verified carefully; do not
treat it as equivalent to the journaled CZ-04B/CZ-07 flow.

## Pressure escalation

- Retain the 300-second check, threshold, and two-consecutive-check debounce.
- First sustained threshold crossing sends the initial warning.
- After the historical 3-hour deadline, send **one additional alert**, persist
  `ip_pressure_escalated_at` (a notification timestamp, not a route-change
  flag), and never change users, DNS, or host eligibility.
- When pressure clears, reset the incident counters; a new episode may alert
  again.

## Retained safety restrictions

- Default-host disable/delete from the old host-pool UI still requires a
  safe cutover first; deleting the active Relay or its WireGuard peer is not
  a rescue operation.
- Protected Egress mode, protected UID bindings, and the shared Phase 6G
  running-operation lease continue to block conflicting Legacy mutations.
- A manually chosen Core/Standby fallback may appear in historical inventory.
  This is **not** automatic eligibility for new customer subscriptions.
- For new live migrations, verify real client connectivity, preserve backups
  and inspect both Cloudflare live DNS and database default before/after.

## Verification and deployment boundary

Regression unit tests: `tests/test_legacy_route_mutation_freeze.py` and
the updated `tests/test_hf01_dns_route_guard.py`. Run full GitHub CI.
No live DNS mutations, WireGuard alterations, database migration, Core
restart, customer move or Production deployment occur in this change.

After operator deploy, run read-only DB checks for active SSH counts per host,
`settings.hosts`, `dns_current_ip`, `host_pool` default, 6H OFF, and
journal lines for pressure and health. A GitHub merge by itself is not a
production acceptance.
