# NVL — Unified Edge Phase 6: CZ07 customer migration checkpoints (source-only)

**Date:** 2026-10-28
**Scope:** Existing CZ07 durable queue and CZ04B per-account CAS. No Cloudflare write, customer move or Core deployment was performed by this change.
**Status:** source staging; release and production acceptance **HOLD** until Phase-4/5 guarded operator acceptance, end-to-end lab and independent ISP SSH CREATE/RENEW evidence.

## What changes

- Keep **one durable CZ07 job for the entire eligible customer cohort**. Increase bounded, sequential **batch size from 50 to 200**, aligned with the existing CZ04B `MAX_BATCH=200`. A 488-account job uses 200 + 200 + 88. No artificial maximum job size is introduced.
- Retain original CZ04B source-fingerprint, provider identity, SSH, WireGuard, NAT, DNS, 6G and per-account compare-and-swap. Run fresh CZ04B checks before **every** batch; no Linux account reconstruction, passwords, Cloudflare mutations or new K2 path.
- Add an additive `cancel_requested` field to original `cloudzy_cz07_jobs`. Authorized owner requests cancellation during `MIGRATING`, persisted before acknowledgement. The worker never interrupts an in-flight CZ04B transaction: on the **next boundary** it computes progress from the authoritative source SSH rows, records `PAUSED_SAFE`, clears cancellation intent and stops.
- `PAUSED_SAFE` can be explicitly resumed only after fresh route readiness, source snapshot / 6G guard, and live DNS verification through the existing callback. Rechecking does not rerun purchase or DNS route stages.
- Recovery from process loss between a committed CZ04B account batch and CZ07 progress event uses the current SQLite source/target assignment (no cursor-only replay), and continues only by explicit resume from `MIGRATING`. Unknown original 6G/CZ04B journal state still holds.
- Completion is now `VERIFYING` / `AWAITING_BUSINESS_E2E` after source empty, target all active, provider/network and routing checks. **Never report `DONE` from migrated metadata counts alone**.
- A source-only `accept_business` requires three durable references (actual SSH CREATE test, RENEW test and affected-ISP real-client check) AND an injected, independently authenticated `independent_verify` callback. No Telegram callback calls it yet. A missing verifier or a false verdict fails closed; accepted references are persisted in `cloudzy_cz07_acceptance` before the same transaction marks `DONE`.

## Compatibility and operator warnings

- Phase 5's **`GuardedCloudzy04B` is staged-only**, not wired to the live CZ07 route callback. Do not mistake this migration change for guarded Phase 5 acceptance. The historical CZ04B route runner may have its own rollback behavior; this PR does not change it.
- `NVL_CZ07_ENABLE` and `NVL_CZ04B_ENABLE` should remain **OFF** in production until the joint P4/P5 failure drills, reviewer approval and a controlled deployment. This phase does not authorize Cloudzy purchases, DNS PUTs, SSH transfers or user data changes.
- `PAUSED_SAFE` is not `ABORTED`. It preserves the single unresolved-job lock. In-progress DNS/ROUTING cannot be cancelled this way. Cancellation is best-effort at batch boundaries, not a rollback.
- New `VERIFYING` remains unresolved until independently verified and recorded. No automatic acceptance button is wired, which is intentional until a trusted verification path and the Phase 7 admin UI exist.
- The existing in-process task plus original 6G guard **is not a separately fenced multi-process worker lease**. No automatic stale worker takeover should be enabled; explicitly reconcile active owners and the original 6G/CZ04B journals before any cross-process resume.
- Existing historical `DONE` rows are not retroactively rewritten or reclassified. An operator must independently review any prior migration.

## Source tests and acceptance gates

`python -m unittest tests.test_cloudzy_cz07_queue -v`

Tests cover: size 200 and cohorts of 0, 1, 50, 51, 200, 201, 473, 493, 495 accounts; pause after first batch; CAS-based resume; crash after source CAS but before CZ07 progress commit; rejection of absent/negative independent verifier; persistent verified receipt references; pre-existing stale ROUTING and provider timeout guards.

**Not yet signed off:** Original CZ04B P5 integration, separate guarded worker fencing/lease acceptance for multi-process restarts, real ISP SSH client CREATE and RENEW, paid provider/installer failure drill, Telegram Rich UI, production rollout.

## Safe release protocol

1. Review precise source diff on isolated branch and exact master baseline; CI + offline regression in staging.
2. No live Phase 6 activation; P4/P5 validation and trusted business verifier must be separately approved first.
3. When approved, first deploy with backups, disabled feature flags, schema/read-only checks, and a reversible code release. Do not overwrite the live DB with a source control fixture.
4. Later conduct a small operator-controlled test with original relay kept available and independent client E2E proof; never infer safety from `VERIFYING` alone.
