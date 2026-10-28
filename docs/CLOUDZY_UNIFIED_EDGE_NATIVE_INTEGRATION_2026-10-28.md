# Unified Edge — Native CZ03/CZ06 to Coordinator Link and Guarded CZ07 Route

**Date:** 2026-10-28
**Scope:** stage of operational integration (source only), not live paid purchase or DNS cutover authorization.

## Delivered

1. A new chargeable Cloudzy purchase registered through the existing CZ03 `ReceiptStore.reserve` now registers the same operation ID in `cloudzy_uo_operations` and `cloudzy_uo_events` **inside the same SQLite transaction**. The existing CZ03 receipt is still the provider/billing authority, not a second independent request.
2. After a fresh stock/price GET, `mark_paid_intent` must durably mark `CLOUDZY_PAID_POST_INTENT` in the coordinator *before* the first Cloudzy `create_server` call. Failure prevents the POST. An unknown paid response never authorizes another POST.
3. Subsequent CZ03 native CAS changes, CZ06 progress and CZ07 job events are mirrored atomically into the UO timeline with stable codes. Each CZ07 checkpoint is linked to the **same Cloudzy CZ03 receipt and owner, provider_server_id and public IPv4**, never by IP alone. Batch count is journalled as `CZ07_BATCH_N_OF_TOTAL`. `EDGE_READY`, `CZ06.READY` and `CZ07.VERIFYING` remain **NEEDS_ATTESTATION** rather than completed client E2E. A CZ07 `DONE` becomes UO `COMPLETED` only if a validated CZ07 acceptance row records CREATE, RENEW and client test evidence in the same native commit.
4. Existing unlinked historic native receipts remain recoverable, including deployments whose UO tables do not exist yet; there is no backfill, secret extraction or migration of historical journal IDs.
5. The main bot instantiates **`GuardedCloudzy04B`** (existing tested Phase 5 subclass) instead of old `Cloudzy04B`. Both CZ04B admin callbacks and CZ07's route stage reuse that same guarded implementation, preserving original 6G lease, exact live Cloudflare DNS record matching and no blind rollback/retry after DNS intent.

## Critical safety boundaries

- This bridge **does not** itself buy, install, move, or accept customers. Only the already explicit and authorized native CZ03/CZ06 flow may call Cloudzy, using its original approved paid POST/SSH gates.
- No new operator button triggers DNS/route/CZ07; old feature switches `NVL_CZ04B_ENABLE` and `NVL_CZ07_ENABLE` are **unchanged** and should remain OFF pending P4/P5 live acceptance. The user's request to remove the **Rich UI** Feature Flag is separate from these safety gates.
- The legacy Edge installer remains non-idempotent. Never rerun setup after unknown result or service partial provisioning.
- UO coordinator is currently an **evidence-based journal envelope** around the native CZ03/CZ06 executor. It is not falsely presented as one fully executable durable worker covering purchase through E2E. The coordinator's generic worker/fencing is still not the authority of live CZ03/CZ07 background tasks; they retain native journals.
- An uncertainty between a paid POST and native receipt commit requires provider reconciliation; no fake `COMPLETED` or automatic acceptance is derived.
- **Outstanding:** phase-4 installer live acceptance; phase-5 guarded DNS staging/live acceptance; independent affected-ISP client acceptance before cutover; explicit shared operation authorization/reconciliation across native CZ06/04B/07; explicit trusted business `accept_business` verifier (CREATE, RENEW, client evidence); cross-process worker fencing. These are mandatory before claiming the replacement can safely migrate a full cohort in production.

## Tests

`python -m unittest tests.test_cloudzy_unified_native -v` plus entire repo CI, original CZ03/CZ06/CZ04B/CZ07 regressions.

Covered: atomic purchase registration, paid intent before request, duplicate paid intent deny, native journal+coordinator atomic failure injection, historical unlinked account compatibility, new guarded route wiring, CZ06 standby ready without fabricated real-client acceptance.

## Deploy and rollback

Source branch may merge after all CI checks, but no deployment or operational mutation was performed as part of this change. Release must include `cloudzy_unified_native.py`, `cloudzy_quick_edge.py`, `cloudzy_cz06_orchestrator.py`, `cloudzy_cz04b_guarded.py` and `bot_final_v49-2.py` **together**, preserving all other runtime dependencies; use exact SHA and read-only production DB preflight. No blanket `git reset --hard` on a dirty worktree. Restore previous executable files on rollback; never restore a stale DB snapshot over completed user/financial writes.
