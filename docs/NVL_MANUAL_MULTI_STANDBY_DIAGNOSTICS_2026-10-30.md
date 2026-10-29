# Manual Edge: Multi-Standby + Action Diagnostics (2026-10-30)

**Scope:** Telegram administrator, Legacy WireGuard/SSH Edge onboarding. Source-only patch; merge does not deploy or migrate production.

## Lifecycle and concurrency

- Each manual Edge has an independent `manual_edge_operations.id`, owner (`actor, chat`), pinned SSH identity and unique IP. A separate operation may be created while earlier operations are `EDGE_READY`, `STANDBY`, `ROUTING`, `MIGRATING`, `HOLD` or `ACTIVE`.
- Only one **unfinished admin intake** (`DRAFT`, `IDENTITY_PENDING`, `HOSTKEY_PENDING`, `READY_INSTALL`) or **currently INSTALLING** operation per admin remains exclusive. Keep the existing shared WireGuard installation lease, per-IP host identity index and actual 6G/DNS/migration safety checks.
- Existing `manual_edge_live_owner` index is upgraded *on the existing database* to cover unfinished intake/install statuses only. This is a schema-only migration; no status rewrites, deletions, DNS updates, password replay or account moves.
- The Rich admin view shows paginated owned manual operations (7 per page), supports exact-ID detail navigation and still offers “Add new Edge” beside existing Standby and EDGE_READY entries. Legacy owner checks remain mandatory for every action.
- Cancellation is bound to the selected draft operation ID; old unbound cancellation callbacks are accepted only when the current private intake session binds an exact operation. Install intents and prepared Edges cannot be cancelled from this path.

## Diagnostics and safe failure

- Before a Standby network probe, require the independently recorded `host_pool` row to match the pinned manual operation: inactive, non-default, non-standby, `provider='manual'`, null provider instance and matching customer/admin ports. A missing row reports `MANUAL_HOST_POOL_MISMATCH`; **no implicit inventory repair**.
- After the local consistency check, separately report Core path/SSH/WireGuard probe failure, NAT probe failure or exceptions. Messages are actionable Persian and contain safe diagnostic codes; Core logs include operation ID, action, error type and source function/line, never passwords.
- A delivery failure **after** `EDGE_READY` commit must not downgrade the durable install result to failed or replay a non-idempotent installer.
- `record_ingress_candidate` (F3) requires an *active* host; skip this active-only audit for deliberate manual inactive bootstrap. Egress onboarding and Cloudzy paths remain unchanged.

## Field checklist after deploy

1. Check deployed SHA / Python tests, DB backup and live Core service prior to cutover.
2. Open Programs → Manage Edge → Manual Edge; verify list shows an existing `EDGE_READY` without blocking “Add new server”.
3. Add a second *distinct* Ubuntu 24.04 VPS; confirm independent draft / host pin / inactive inventory / health and then Standby.
4. Verify the first incomplete Edge is preserved, never silently reinstalled and is individually inspectable; no DNS or customer change before explicit cutover.
5. If `104.194.141.86` still shows `EDGE_READY` while absent from `host_pool`, do **not** fabricate a row. Inspect Core peer, remote SSH/WG/NAT and the host deletion/registration journal separately.
6. Keep legacy emergency recovery receipts distinct from manual Edge adoption. The historic receipt for `153.75.87.190 → 45.59.126.73` does not close an `EDGE_READY` adoption operation.

**Safety:** No Cloudzy API calls, no DNS change, no account rebind, no automatic resumption of unresolved CZ07 jobs, no automatic status upgrade.
