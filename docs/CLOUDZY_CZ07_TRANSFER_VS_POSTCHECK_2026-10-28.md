# NVL — CZ07: separate transfer completion from post-transfer verification

**Date:** 2026-10-28. **Scope:** software-only change to remove the incorrect dependency of the next CZ07 transfer on CREATE/RENEW test evidence for a PREVIOUSLY COMPLETED account-host move. No live VPS/DNS/SSH action performed by this PR.

## Operator incident

- Existing CZ07 `97ae84fa4475...`: source `45.61.180.119`, destination `104.194.141.63`, `485/485`, stage `VERIFYING`.
- New standby candidate has IP `144.172.119.190` and previously reported `EDGE_READY / CZ06 READY`.
- Old design treated **post-transfer application tests** (new user CREATE, RENEW and ISP connection) as prerequisites to **release the transfer queue lock**. Those tests use independent application paths and should occur *after* a transport handoff, without falsely declaring them passed.
- This PR changes only that sequencing. No claim about live Core/current Cloudflare is made from historic screenshots.

## State machine

| State | Meaning | Blocks another CZ07 transfer |
|---|---|---|
| `ROUTING`, `MIGRATING`, `HOLD`, `PAUSED_SAFE` | Incomplete/uncertain cutover | **Yes** |
| `VERIFYING` | 100% account-host migration committed; needs live technical closure | **Yes** |
| `MOVED` (NEW) | Completed and independently rechecked route/DNS/account-host transfer; CREATE/RENEW/ISP verification still pending | **No** |
| `DONE` | Separate authenticated business acceptance and post-transfer evidence recorded | No |
| `ABORTED` | Safe aborted workflow, not a migration success | No |

`MOVED` is **not** equivalent to `DONE`. It must never display “business accepted”, “customer connected”, or “CREATE/RENEW passed”. The Unified Journal maps MOVED to `FINAL_VERIFY/NEEDS_ATTESTATION`, with code `CZ07_TRANSPORT_COMPLETE_POSTCHECK_PENDING`; the Rich card reflects it. Phase-8 final audit still requires `DONE` plus evidence, so `MOVED` cannot pass acceptance.

## Existing VERIFYING migration: guided technical close

1. Owner opens **📦 انتقال کاربران SSH**. For the existing `VERIFYING` job, select **✅ بررسی تکمیل انتقال حساب‌ها**.
2. The bot performs *live* provider identity + port/SSH/WireGuard/NAT probes with pinned host key (existing CZ04B `_fresh`); reads current Cloudflare DNS, exact original CZ04B route result, settings/default, original 6G/CZ04A/CZ04B locks and active SSH destinations. It checks that no active account is on old/foreign/null Host and that the old source cohort is empty.
3. Only when all checks succeed does an owner- and chat-bound 180-second confirmation appear. Final click **✅ ثبت تکمیل انتقال حساب‌ها** re-runs provider, probe, DNS and account guard, then uses `BEGIN IMMEDIATE`/CAS on original `VERIFYING` job ID, original `updated_at`, exact source/target/provider/count and no cancellation. It persists `MOVED/TRANSPORT_VERIFIED_POSTCHECK_PENDING`, appends an immutable CZ07 event and updates linked Unified UO atomically. The old 485 accounts are **not** migrated again.
4. A new partial unique index `cloudzy_cz07_one_inflight` protects all nonterminal records. It is created **before** removing the old index `cloudzy_cz07_one_unresolved`; only `MOVED` joins `DONE/ABORTED` as not holding the queue lock. In-progress/HOLD/PAUSED/VERIFYING remain blocked. The index upgrade is additive on the same production SQLite DB; backup and exact code deployment first.
5. Once `MOVED` is persisted, **🚀 بررسی انتقال به Standby** opens existing CZ07 readiness, with fresh CZ06-READY identity checks, relevant flags, owner verification, and original live CZ04B DNS/default/6G/preflight. The next transfer still needs the *separate* existing explicit guarded approval in CZ07; simply opening the screen does not mutate anything.
6. After the *next* transfer, CREATE/RENEW/customer ISP tests are conducted through their respective application operations and recorded independently. `MOVED` jobs can still receive authenticated postchecks and transition to `DONE` **while their original target remains the live route**. If another cutover supersedes the old target before those tests, do not pretend the historical job has business-accepted evidence: it remains `MOVED` with an outstanding postcheck record.

## Safety boundaries

- No force-setting `DONE`, no acceptance record minted, no synthetic ISP evidence, no direct SQL status update on Core.
- Do not drop, disable or wipe the old Relay or customer accounts. Original 6G/CZ04B/provider/DNS CAS, owner and nonce checks remain.
- No second CZ07 can start when an unresolved route, migration, active worker, recovery hold or failed technical closure is present.
- **No route cutover is executed by this PR itself.** Deploy + live technical review + explicit admin confirmations are separately required.
- Keep production `NVL_CZ07_ENABLE` and `NVL_CZ04B_ENABLE` unchanged unless an operator explicitly authorizes activation. A green CI is not permission to change live DNS.

## Verification

Unit tests cover: first job `VERIFYING` still blocks another reserve; owner-bound technical close; stale source account or DNS failure; moving to `MOVED` releases only the migration lock; old 473-account cohort not replayed; second standby qualifies only with genuine CZ06/provider/host identity; repeat/stale callbacks do not advance a job; post-transfer signed receipts still accepted only through independent witness; unit/release/Edge/Legacy suites.

### Core read-only preflight

```bash
sqlite3 -readonly -header -column /root/master_bot.db "
SELECT substr(id,1,16) AS job,source,target,status,moved,total,code
FROM cloudzy_cz07_jobs ORDER BY started_at DESC LIMIT 6;
SELECT host,active,is_default,is_standby,provider
FROM host_pool WHERE host IN ('104.194.141.63','144.172.119.190');
SELECT host,COUNT(*) AS active_users FROM ssh_accounts
WHERE service_type='ssh' AND status LIKE '%فعال%'
AND status NOT LIKE '%غیر%' GROUP BY host ORDER BY active_users DESC;
"
```

After exact-code deploy and in-bot technical review, a successful old-job closure has `MOVED`, not `DONE`; the next transfer may then be explicitly started through existing preflight/confirmation. **Never execute a SQL shortcut to mark `MOVED`.**

## Rollback / staging

Deploy the **set** of modified Python modules (`cloudzy_cz07_queue.py`, `cloudzy_unified_native.py`, `cloudzy_rich_admin.py`, `cloudzy_phase8_pilot.py`, `cloudzy_cz07_acceptance.py`) with backup and pinned commit. The SQLite index upgrade and new `MOVED` journal must not be blindly rolled back to older code: older versions do not know `MOVED`, and reintroducing the old index/locking model while new jobs exist could fail. Any rollback after state change requires an operator's documented compatibility review of live jobs and schema. Rollback code *before* any `MOVED` transition if a release fault is found.

**Status labels:** `SOURCE_MERGED`, `CORE_DEPLOYED`, `MIGRATION_TRANSFERRED`, `NEW_CUTOVER_COMPLETED` and `BUSINESS_ACCEPTED` are separate milestones. Only mark those which actual field evidence supports.
