# NVL Cloudzy unified workflow — Phase 2 source delivery

**Date:** 2026-10-28  
**Scope:** existing Programs → Cloudzy | Edge & Relay backend, not a new Telegram panel.  
**Implementation status:** New opt-in support module, isolated tests; source only. CI/PR status must be verified separately. Production Core has not deployed Phase 1; do **not** assume Phase 2 is live.

Canonical requirements: [unified lifecycle design](CLOUDZY_UNIFIED_EDGE_LIFECYCLE_DESIGN_2026-10-28.md) and [8-phase roadmap](CLOUDZY_UNIFIED_EDGE_REFACTOR_ROADMAP_2026-10-28.md).

## What exists

- cloudzy_operation_coordinator.py: additive SQLite cloudzy_uo_operations + cloudzy_uo_events, a single CAS version per event, worker lease/heartbeat, monotonically increasing fencing generation, step/status/error code separation, explicit cancellation requests and safe-checkpoint acknowledgment.
- A cancellation during an uncertain side effect is recorded as requested, not reported as completed; live original 6G/CZ-04B/CZ-07 locks are untouched. A stale lease is classified for inspection and never automatically force-released.
- Lost worker may be reclaimed only when a trusted independently supplied quiescence verifier proves the worker stopped, and no external intent was recorded. If any external write intent exists, a separate independently verified reconciler is required; no blind provider POST/DELETE/installer/DNS/batch retry.
- read_legacy_receipts(conn) projects existing CZ-03, CZ-04A, CZ-04B, CZ-06, CZ-07, CZ-08 table statuses with safe machine-code normalization and suggested *inspection* actions. It is SELECT-only, independent of the new tables and never replays old workers. Existing Cloudzy and 6G journals remain the source of truth for actual external writes.
- A new op can be registered manually by future reviewed integration, but the current bot **does not import, register or schedule the new coordinator**. No historical ops are adopted as new mutable records. No automatic snapshot/repair, live Redis queue, or cross-system transaction is claimed.
- Diagnostic/status output is backend-only; admin Telegram 10.3 Rich Message rendering will be added to the existing panel in Phase 7, not by introducing an HTML fallback or an alternate panel in this phase.

## Safety caveats and integration prerequisites

- Fencing is **local to this new journal**. It does NOT yet fence the historical CZ-07 asyncio worker, original 6G lease, legacy installer or Cloudflare. The source module must never be wired directly into old launch/cancel callbacks as if it controlled them.
- Future execution adapter must record intent durably before any paid POST, DELETE, Edge setup, DNS write, or customer batch and enforce every coordinator lease/fence check at the actual side-effect boundary.
- A previously issued Cloudzy request may have succeeded despite a transport timeout; its original CZ-03 idempotency key/hostname and provider identity must be reconciled using independent GET before accepting any retry. Similarly DNS intent requires live Cloudflare + original CZ-04B + 6G evidence.
- Trusted witnesses (worker-quiescent / external-state-verified) are **not supplied by Phase 2**. They default DENY. Only Phase 3/4/5/6 adapters with independent source-specific validation can implement them; never use an admin-supplied string/checkbox as witness.
- Atomic SQLite journal updates cannot make external Cloudzy and Cloudflare calls atomic; ambiguous state remains held. Legacy H​OLD cases are not automatically repaired.
- No new schema is created on import, status inspection or bot startup; explicit new-op registration creates versioned additive tables. No production migration necessary until future integration approval.
- Phase 1 read model cloudzy_route_snapshot.py is unchanged; it is not deployed to the production bot. Original bot CLI and Legacy manual rescue remain intact.

## Regression and acceptance

tests/test_cloudzy_operation_coordinator.py simulates:
- persistence across new coordinator instances and a QUEUED-equivalent unclaimed PLANNED operation,
- stale/duplicate claim and optimistic version CAS,
- bounded lease, expired heartbeat, worker generation fencing,
- cancel before charge vs while executing vs after external-effect intent,
- exact verified worker quiescence and independent external-evidence gates,
- no auto reclaim for ambiguous provider/DNS writes,
- historical six-journal status projection and redaction of arbitrary note bodies,
- no mutation of existing CZ-07 or original 6G tables.

## Operator guidance

This phase does NOT need a bot restart or a core deploy to protect production: it is source-only infrastructure for later phases. If a reviewer stages the module on Core, stage the exact pinned GitHub file in an isolated directory and run unit tests against a temporary SQLite fixture. Do not invoke register() on the live master_bot.db, because that writes new schema and is not necessary for this phase.

Do not confuse passing CI with provider/ISP field acceptance. Next P3 is Cloudzy purchase/idempotency integration; P4 provisioning; P5 public DNS; P6 actual migration, P7 Rich UI, P8 external acceptance and old UI retirement. Future phase integrations require exact deployed source convergence and independent release approval.
