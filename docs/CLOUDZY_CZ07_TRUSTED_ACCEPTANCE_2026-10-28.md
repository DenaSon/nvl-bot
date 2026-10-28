# NVL / CZ07 — Independent final acceptance and next-transfer unlock

**Date:** 2026-10-28  
**Scope:** Operational acceptance callback for previously migrated CZ07 jobs; **not** a migration rerun, DNS write, VPS order or automatic ISP proof claim. Release requires the exact merged SHA and a separate Core deploy.

## Production incident / observed state

The last operator-supplied CZ07 status was `97ae84fa44758a70...`, source `45.61.180.119`, destination `104.194.141.63`, moved **485/485**, `VERIFYING/AWAITING_BUSINESS_E2E`. This is *metadata migration finished, business acceptance pending*. A later `144.172.119.190` Cloudzy Edge had `EDGE_READY` and CZ06 `READY`; this does not authorize a second transfer while the older job remains unresolved.

Previously `apps_cz7_home` routes any unresolved CZ07 job to status and the unique active-job index blocks new reservations. `accept_business` existed as a protected method but **no Telegram callback invoked it**.

## Implementation

1. A visible `🔎 بررسی پذیرش نهایی` appears only on the owning admin's existing `VERIFYING` CZ07 status page. No change to `MIGRATING`, `PAUSED_SAFE`, `HOLD`, `ROUTING` controls.
2. It reads **independent, externally generated evidence** via `IndependentCZ07Witness`; absent, stale, changed, unauthenticated or incomplete proof yields a clear Persian warning and **NO state mutation**.
3. If all three external observations are valid, admin sees `✅ اجرای بررسی نهایی و ثبت پذیرش`, protected by a one-time owner/chat-bound nonce, 180-second expiration and pinned job `updated_at` plus proof fingerprint.
4. The existing `accept_business` still performs independent verifier callback, live original CZ04B route/DNS checks, source/target count, shared 6G/CZ04B lock, CAS, and stores three evidence refs in `cloudzy_cz07_acceptance` *in the same transaction as* `DONE`. An error stays `VERIFYING`.
5. Only after real `DONE`, status shows `🚀 بررسی انتقال بعدی`, which goes through existing CZ06 Standby/ownership/flags and CZ07 readiness. It does **not** replay DNS or transfer by merely opening a page.
6. Default production behavior without an independently deployed proof producer is **HOLD**, not silently accepting operator text, screenshots, internal WG/NAT probes, record count or a test flag.

## Trusted evidence contract (separate producer, not an NVL admin form)

The external producer must collect *real* SSH account creation/login, renewal/login, and SSH connectivity/traffic **from the affected customer's ISP** after CZ07 `VERIFYING`. A source that merely queries `ssh_accounts.host`, runs Core localhost NAT probes, or guesses the customer path is **not eligible** to issue this witness. It should run outside the bot's trust/collection path; root must explicitly validate its measurement methodology.

The bot **does not write or sign receipts**. Only the independently deployed observer writes one JSON file for the exact job ID to a private, absolute directory. File must be regular, non-symlink and mode `0600`; directory must not be group/world writable. Limit: 8 KB. The receipt contains:

```json
{
  "version": 1,
  "producer": "independent-customer-observer",
  "source_id": "trusted-observer-id",
  "job_id": "<exact 32-hex CZ07 job ID>",
  "target": "<verified destination IPv4>",
  "issued_at": 0,
  "create": {"reference":"external-create-reference","verified":true,"target":"<IPv4>","observed_at":0,"ssh_login_success":true},
  "renew": {"reference":"external-renew-reference","verified":true,"target":"<IPv4>","observed_at":0,"ssh_login_success":true},
  "client": {"reference":"external-client-reference","verified":true,"target":"<IPv4>","observed_at":0,"isp":"MCI-LTE","ssh_handshake":true,"ssh_auth":true,"traffic_passed":true},
  "signature": "<lowercase HMAC-SHA256 hex>"
}
```

This is a **schema example**, not valid evidence. All timestamps are Unix UTC seconds. The independent producer signs the canonical UTF-8 JSON encoding **excluding** `signature`: `json.dumps(content, sort_keys=True, separators=(',', ':'), ensure_ascii=False)`. The record must have been produced after the latest persisted `VERIFYING` event (job `updated_at`), must be no older than 24 hours, and must include three distinct references bound to the exact current target. The bot checks HMAC with constant-time comparison, unchanged digest at confirmation, file integrity, stage/owner, and the original route/6G/CZ04B safeguards.

**Security boundary:** An HMAC confirms authenticity relative to the configured observer's secret, but is not physical proof by itself. An unauthorized or untrustworthy source must never receive the key; *do not manually create a signed JSON file to trick the bot into DONE*. The software cannot certify an independent Iranian ISP path without actually deployed field measurement.

For production, configure these two secrets **privately** in the service manager only after a trustworthy, independently instrumented producer exists:

- `NVL_CZ07_TRUSTED_EVIDENCE_DIR`: absolute, private directory containing `<job-id>.json`
- `NVL_CZ07_TRUSTED_EVIDENCE_KEY`: shared secret, at least 32 UTF-8 bytes, accessible to bot verifier and independent producer only

No default/fallback key, auto-write or operator-entered reference is accepted. Config must be applied via a separately approved secret change and bot restart. Never paste the key or receipt containing customer identifiers into Telegram or GitHub.

## Operator flow after deploying this PR

1. Open **📦 انتقال کاربران SSH**. Existing job remains `VERIFYING` until valid receipts exist.
2. Press **🔎 بررسی پذیرش نهایی**. If missing, deployment integration has not been updated; do not force status in SQLite.
3. If absent witness, status shows `TRUSTED_WITNESS_NOT_CONFIGURED` or `TRUSTED_WITNESS_NOT_RECEIVED`. Configure the real independent field observer; **do not** fabricate results.
4. When three independent tests actually pass, press **✅ اجرای بررسی نهایی و ثبت پذیرش**. Confirmation expires and proof/job snapshot are checked again.
5. On verified success the existing transaction records `BUSINESS_E2E_ACCEPTED` and `DONE`. The next transfer link appears, with the new Standby independently rechecked. Do not enable mutation flags or run another cutover without explicit authorization.

### Read-only Core audit

```bash
sqlite3 -readonly -header -column /root/master_bot.db "
SELECT substr(id,1,16) job,source,target,status,moved,total,code,
       datetime(updated_at,'unixepoch') updated_utc
FROM cloudzy_cz07_jobs ORDER BY started_at DESC LIMIT 5;
"
sqlite3 -readonly -header -column /root/master_bot.db "
SELECT substr(job_id,1,16) job,at,create_ref,renew_ref,client_ref
FROM cloudzy_cz07_acceptance ORDER BY at DESC LIMIT 5;
"
```

A `VERIFYING` job with 485/485 and **no** matching acceptance row is not DONE; a signed but unobserved or fake receipt is also not acceptable. Compare live Cloudflare DNS and customer-path evidence separately.

## Testing & rollout

Run the new `tests.test_cloudzy_cz07_acceptance`, modified `tests.test_cloudzy_cz07_queue`, full Python CI/release package, Legacy migration safety and Edge stage-only safety. Offline fake witnesses are used ONLY in tests. On Core deploy `cloudzy_cz07_acceptance.py`, `cloudzy_cz07_queue.py`, and `bot_final_v49-2.py` as an atomic pinned release after staging compile/unit tests and runtime backup. There is **no schema migration** for this patch; the original `cloudzy_cz07_acceptance` table is preserved. Keep existing user data, provider, DNS, service flags and 6G unchanged during code rollout.

Rollback restores only those runtime Python files, never the database or Cloudflare. Never mark `VERIFYING` as `DONE` manually, delete a job to release the unique index, or assume that CI success closes a real ISP verification gate.

**Acceptance outcomes:** `SOURCE_MERGED` can be reported after CI and PR merge. `PRODUCTION_DEPLOYED` needs Core SHA evidence. `BUSINESS_ACCEPTED` requires the independent actual signed observation, successful live guard and recorded `DONE`. The final two cannot be inferred from GitHub.
