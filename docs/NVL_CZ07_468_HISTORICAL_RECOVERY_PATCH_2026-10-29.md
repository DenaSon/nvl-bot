# NVL — patch for CZ07 historical 468-account emergency evidence (2026-10-29)

**Status:** source patch, not Core deployment, not permission to change live jobs. This note is scoped to `a0b997e06a92ca35261561f8a5aa5f87` only.

## Verified operator-side read-only inventory

- Started at 2026-10-29 09:08:59 UTC, original immutable cohort: 468 active SSH usernames at source `144.172.69.19`; the SHA256 of the exact sorted `(username,host,status)` tuples matches `cloudzy_cz07_jobs.source_fingerprint`.
- Two independently journaled CZ04B `DONE` batches: 200+200 = 400 distinct usernames, all still registered at destination `144.172.69.61`.
- Snapshots at 09:17 and 09:22 preserve the same 68 distinct active source users, disjoint from the 400 names and exactly the complement of the original fingerprint-matched cohort.
- Emergency audit and CZ07 event attest `affected=68`, `moved=468`, `remaining=0`, with `EMERGENCY_LOCAL_CAS_E2E_PENDING`.
- Live destination has 472 SSH records: 468 original usernames (including inactive accounts) and 4 outside the historical cohort. This is **not** a client-connectivity or billing acceptance receipt.

## Implementation

`cloudzy_cz07_legacy_proof.py` performs a fail-closed, read-only forensic check of **three pinned backup files**, the old journal fingerprint, the exact CZ04B payload rosters, emergency audit, event, and the current database identities (including inactive records). A missing/changed original account, forged replacement, inconsistent batch, different 68, missing/corrupt backup, changed route, another active SSH host, audit mismatch or different job fails closed.

`DurableCutoverQueue._hold_evidence()` uses this verifier **only** if all conditions hold:

- Exact job ID `a0b997e06a92ca35261561f8a5aa5f87`.
- Original `HOLD / EMERGENCY_LOCAL_CAS_E2E_PENDING` state and the preserved source/target/total/moved.
- Operator explicitly set `NVL_CZ07_HISTORICAL_RECOVERY_A0B997_ENABLED=1` on the bot process.

Otherwise, the existing generic Recovery logic remains unchanged. `review_hold()` still checks original route, SSH/WG/NAT, live Cloudflare DNS, 6G and owner and provides a preview without transferring users. The operator's separate one-use confirmation runs `reconcile_hold()`, which **re-verifies snapshots/roster under the original CAS guards**, persists only the three snapshot file SHA256s and a combined proof SHA256 in `cloudzy_cz07_legacy_proofs` *in the same transaction as the original CZ07 HOLD→VERIFYING CAS and event*. No usernames or passwords are stored in the new proof table. The further `VERIFYING→MOVED` live technical check is separate. `DONE` requires authenticated CREATE/RENEW/client-ISP postcheck evidence.

There is **no** automatic repair, runtime account migration, DNS cutover, Cloudzy API call, provider purchase, or bulk user action in this patch.

## Production preflight before any enablement

1. Treat the three snapshot backups as forensic material. Store secure off-host backups and record their SHA256s before deployment. Do **not** overwrite originals or run SQLite write operations on them.
2. Pin the merged source commit; stage all required root Python modules **and matching existing shell assets**, preserve `/root/master_bot.db`, production `.env`, secret keys and state. Never copy a source repository's database over live DB.
3. Verify `PRAGMA quick_check` and restore-test an online SQLite backup; compare current Core/Cloudflare/default/6G/CZ07 journals, pending workers, service unit `ExecStart`, and upstream imports. Ensure unrelated interrupted operations do not hold the shared lease. Confirm all three pinned backup paths exist and are genuine, regular, stable SQLite files.
4. Deploy code only behind `NVL_CZ07_HISTORICAL_RECOVERY_A0B997_ENABLED` **off**. Smoke-test bot controls and read-only diagnostics; only then independently approve enabling the one-job flag. Do not enable manual-edge wizard flags simply to recover this historical job.
5. From the original owner/operator Telegram admin UI select **🔎 بررسی و ادامه انتقال**, inspect preview and separately confirm. Expect `HOLD→VERIFYING` with **zero account/DNS migration**. Once independent SSH/WG/NAT/DNS checks pass, confirm `VERIFYING→MOVED`; still not `DONE`.
6. Verify the new `cloudzy_cz07_legacy_proofs` receipt (only after explicit approval), original events, live route and customer E2E. Stop on any mismatch; no direct SQL status edits or replay.
7. Rollback of code **after** a journal transition must account for newer recovery status/index and schema. Do not blindly roll back to a prior release after `VERIFYING` or `MOVED`.

### Historical evidence files

```text
/root/nvl-backups/emergency-pre-reconcile-20261029T090210Z-798849.db
/root/nvl-backups/pre-cz07-68-20261029T091736Z-808450.db
/root/nvl-backups/pre-cz07-68-20261029T092202Z-810588.db
```

### Read-only operator preflight

```bash
for file in \
  /root/nvl-backups/emergency-pre-reconcile-20261029T090210Z-798849.db \
  /root/nvl-backups/pre-cz07-68-20261029T091736Z-808450.db \
  /root/nvl-backups/pre-cz07-68-20261029T092202Z-810588.db; do
  test -f "$file" || exit 1
  sha256sum "$file"
  sqlite3 -readonly "$file" 'PRAGMA quick_check;'
done
sqlite3 -readonly -header -column /root/master_bot.db "
 SELECT substr(id,1,16) AS job,status,code,moved,total
 FROM cloudzy_cz07_jobs
 WHERE id='a0b997e06a92ca35261561f8a5aa5f87';"
```

**Release boundary:** GitHub green CI and merge are source-only milestones. Deployment, live Cloudflare tests, `HOLD→VERIFYING`, `MOVED` and business `DONE` are separately gated.
