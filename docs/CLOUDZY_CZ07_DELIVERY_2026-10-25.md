# CZ-07 — Guarded cutover and durable queued SSH migration

**Date:** 2026-10-25  
**Status:** source implementation; paid production E2E/ISP field acceptance deferred.
**Predecessors:** CZ-05 hourly live-stock catalog; CZ-06 Edge/Standby with independent SSH host-key acceptance; CZ-04B verified DNS cutover and per-user CAS.

## Workflow

Programs → Cloudzy → **CZ-07 · انتقال خودکار و صف**.
1. Read latest CZ-06 **READY** operation and verify provider id, Edge receipt and managed active Standby. No manual/non-CZ06 VPS can be auto-adopted.
2. Read-only CZ04B preflight: provider ownership, SSH service and admin, WireGuard, pinned NAT, auto failover/K2/6G and journal guards, exact current Cloudflare DNS. The original Relay must be the only active SSH customer source.
3. The operator must first independently verify the proposed new IP from a **real affected Iranian ISP/customer path**, actual subscription and egress IP. Since no reliable authenticated external customer-path evidence provider is integrated, UI displays a short-lived, one-use attestation **before** starting DNS mutation. **This is a necessary additional security checkpoint**, not a claim that Core/WG/NAT constitutes E2E client verification.
4. SQLite transaction reserves one CZ07 job, snapshots and **persists** the source account fingerprint and count, and records attestation and initial audit event. Just before any DNS write, the worker reloads the source accounts and rejects a changed fingerprint, target or provider ownership. One unresolved job globally, bound to the original CZ06 actor/chat.
5. Async worker starts **after** the Telegram callback; it invokes the **original CZ04B guarded** `_run_route` once. CZ04B holds original 6G lease, journals DNS_WRITE_INTENT, verifies records, commits default/DNS with CAS, verifies again and leaves old Relay active.
6. Once route READY is independently rechecked, pin `settings.hosts` to the new destination **without disabling or deleting old host_pool**; prevent new SSH signups from being allocated back to the former Relay (Issue #191). If unexpected extra host entries/roles exist, fail closed to HOLD and require review.
7. Migrate active SSH accounts in batches of at most **50**, with a minimum scheduling yield and default **200 ms** delay after each batch. Each uses original CZ04B `_run_users`: fresh provider, NAT, WG, DNS checks, 6G lease, per-account compare-and-swap; **no Linux user or password rebuild**. Refresh source snapshot/fingerprint and persisted count after each committed batch, using DB truth rather than a cursor or in-memory count.
8. Require empty old source active list, **no active SSH users outside destination**, exact DNS/default/hosts, fresh CZ04B probe and matching provider; only then mark DONE and notify in Telegram. Source server stays online as rollback fallback.

## Journal, progress and logs

`cloudzy_cz07_jobs`: job id, source CZ06 order, actor/chat, source/target/provider, state `QUEUED/ROUTING/MIGRATING/HOLD/DONE/ABORTED`, original user count, committed count, customer-path operator attestation, timestamps, last safe code.

`cloudzy_cz07_events`: append-only event sequence, timestamp, stage, machine-readable code, moved and remaining counts.

Examples in `journalctl -u nvlbot`:
- `CZ07 job=... stage=ROUTING code=CZ04B_GUARDED_CUTOVER_START source=... target=...`
- `CZ07 job=... stage=MIGRATING batch=50 elapsed_ms=... moved=... remaining=...`
- `CZ07 job=... stage=HOLD code=... hold=1 source=... target=...`

Neither logs nor Telegram contain Cloudzy credentials, SSH private keys, full account lists, or sensitive API bodies. The last five durable events are visible through CZ07 Status, plus a truncated operation identifier. A Telegram delivery failure never replays a provider request.

## Failure/recovery rules

- Default OFF: **`NVL_CZ07_ENABLE=1` AND `NVL_CZ04B_ENABLE=1`** required at runtime. No launch while disabled; read-only status accessible.
- Interrupted/uncertain **ROUTING**: never automatically replay DNS writes. Job HOLD/reconcile only; inspect CZ04B route journal, Cloudflare public/TLS DNS and original 6G lock first.
- Interrupted **MIGRATING**: after bot restart, owner may choose *Safe Resume* if CZ04B route is still READY, no unresolved CZ04B/6G operation and live DNS matches. Reconstruct remaining usernames and progress from SQLite; no duplicate migration of completed users.
- **HOLD** status is not an auto-retry button. Resolve the specific failure and audit the CZ04B operation and 6G lease before any manual intervention. No destructive rollback of a committed default.
- A failed `_run_users` may leave its CZ04B journal/lease unresolved; never assume its transaction failed. The worker marks CZ07 HOLD and stops, and **does not** issue another batch.
- A source-account count increase, unauthorized routing metadata mutation, unknown source host, stale customer evidence, provider/NAT failure or mismatched DNS fails closed.
- Job executes as an asyncio task in the existing bot process; **durability is provided by SQLite and explicit safe resume**, not by an independent systemd worker. The task uses `asyncio.to_thread` for DB and network blocking portions and yields between batches. Deploying an independent service is a potential future enhancement, not claimed as implemented.

## Testing and rollout

Source-level tests use temporary SQLite and fake provider/network; never create Cloudzy instances or mutate production. CI full unit suite + stage-only safety checks + pinned source-bundle/root tests must pass before merging.

**Do not turn on CZ07 just because the code merged.** First deploy pinned SHA with SQLite backup and module compilation; keep `NVL_CZ07_ENABLE=0` and `NVL_CZ04B_ENABLE=0`. Verify navigation and read-only status. For a real production cutover, validate independently from a client on the desired Iranian network, check prior CZ04B journal locks, set explicit feature gates during an approved maintenance period and observe job progress. Do not delete/power-off old Relay immediately after migration. Review source/target users, public/TLS DNS, `host_pool`, `settings.hosts`, `failover_operations`, `cloudzy_cz04b_operations`, `cloudzy_cz07_jobs` and event table.

CZ-07 source does not claim that a mock test proves ISP connectivity. Field acceptance remains a separate operator-controlled step.

## Stale ROUTING recovery after provider-read timeout (2026-10-28)

- Cause: Cloudzy read request failed: TimeoutError from read-only Cloudzy service verification before any CZ04B DNS write or 6G lease. Old CZ07 exception handling generated mixed-case CloudzyError, which failed the journal enum validator (INVALID_LOG_CODE), leaving ROUTING/moved=0.
- Correction: normalize persisted exception codes to upper-case ASCII enum before log transition, reporting Cloudzy errors as CLOUDZY_PROVIDER_UNAVAILABLE; failures now persist HOLD.
- The bot status offers «بررسی و بستن امن Job گیرکرده» only for the original actor/chat, zero-move ROUTING/HOLD, no running worker, and age >= 120s. A two-click nonce-bound approval checks old default, source settings, target role, no target accounts, no CZ04B operation newer than the job, no outstanding CZ04B/CZ04A/shared 6G, and live exact Cloudflare DNS on source. Any failure blocks closure.
- Closure changes only the CZ07 journal row to ABORTED / SAFE_STALE_ROUTING_CLOSED, recording an event. No DNS, user, host-pool, WireGuard or Cloudzy write is made.
- Retry: return to CZ07 home for fresh provider/NAT/WG/DNS preflight and independently verified client-route attestation. The CZ06 operation UNIQUE identity stays intact: a new explicit approval re-arms the same safely aborted CZ07 row with a new snapshot, count, timestamp and durable event history. The old route worker is not automatically replayed.
- No automatic recovery is available for MIGRATING, any committed/default changes, any matching CZ04B operation since the job, unknown DNS, an in-flight route, or target account assignments; those require human reconciliation.
- Operational prerequisite: merge and deploy the patched source on Core. A GitHub merge does not update the running service. If the Cloudzy API still times out, the fresh preview fails closed. Keep the old Relay until a real affected-ISP client verifies the new route.
