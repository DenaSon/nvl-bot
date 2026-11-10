# NVL Super Admin Accounting V1 — source delivery, release gates (2026-11-10)

## Purpose / status

Text-only financial **operational** report for the existing NVL Telegram Super Admin. Period choices: **all recorded history**, **rolling last 7 days**, **rolling last 30 days**. No charts, Excel, ledger rewrite, migration, account/agent updates or changes to buying, receipts, commission, cashback, wallets, emergency credit and withdrawal paths.

The preceding read-only Core audit (PR #288, 2026-11-10) confirmed:
- Both current SQLite schemas present; 33 current agents, 129 approved receipts.
- Of 29 approved receipts submitted on/after Oct 19, **29/29** correlate by receipt ID with a bank-approval finance log, with zero discrepancies or duplicate log IDs. The earlier 100 approved receipts precede finance-log coverage.
- **508/508** activity/finance rows correspond when mapping legacy `activity_log.created_at` UTC to `finance_logs.date` Asia/Tehran; median raw difference +210 minutes and normalized median zero.
- Historical gaps remain by design: 15 receipts reference deleted/missing current agents; `activity_log` does not include every financial path; manual deductions and some refunds/withdrawable-to-wallet moves are not represented in finance log; SQLite REAL is not a bank ledger.

**Important:** Correlation proves data alignment, not externally settled banking. This implementation does NOT reconstruct missing history or claim complete total revenue/profit.

## Changed files

- `nvl_superadmin_accounting_report.py`: standard-library-only service with strict `mode=ro`, `PRAGMA query_only=ON`, required-schema gates, timezone-aware, individually consistent read-only transactions, and Telegram-safe HTML output.
- `bot_final_v49-2.py`: a feature flag, menu entry at both Super Admin menu render paths, and one early `nvl_fin:` callback router. Existing callback classes and selling/billing branches remain untouched.
- `tests/test_nvl_superadmin_accounting_report.py`: isolated synthetic fixtures for period boundaries, amount classification, security, missing DB/schema and text-only render.

## Data contract

| Display | Source | Time basis | Caveat |
| --- | --- | --- | --- |
| Approved/pending/rejected receipts | master `receipts` | `created_at` = bot host local (historically UTC on Core) | **Submission date**, not approval. If `card_owner_agent_id IS NULL`, label as **unmarked**, not verified company bank receipt |
| Recorded SSH/V2Ray create/extend, representative-only cost | master `activity_log` | SQLite UTC | Counts include admin direct creates (cost 0). Sums include only agent rows; some bulk/charge/refund routes missing |
| Manual credits *recorded* | accounting `finance_logs` | Asia/Tehran | Secondary DB starts Oct 18, 2026; may omit older changes; DO NOT sum with approved receipts as cash inflow |
| Withdrawal requests submitted | master `withdrawal_requests.created_at` | bot host local | Request-time scope; includes all present statuses |
| Withdrawal marked done | master `withdrawal_requests.done_at` | bot host local | Current status done + completion timestamp, not external bank verification |
| Current pending withdrawal | master `withdrawal_requests` | current snapshot | Independent from time filter |
| Current wallet, withdrawable and emergency balances | master `agents` | current snapshot | Independent from time filter; do not add historical referral/cashback income again |

**No mixed-source total revenue or profit**. No division into full calendar weeks or Jalali months: last 7/30 means rolling back exactly 7/30 days from rendering in Tehran time.

## Access and availability

New callback namespace `nvl_fin:menu|all|7d|30d`. Every callback checks:
1. `NVL_SUPERADMIN_ACCOUNTING_REPORT_ENABLED == "1"` (default **OFF**);
2. authenticated role `admin`;
3. actual Telegram `user_id` equal to the existing configured Super Admin ID;
4. private Telegram `chat_id` equal to that same ID.

No ordinary admin, reseller or accountant has access. The menu entry is invisible when OFF. The callback does not mutate persistent `context.user_data`. No background jobs are added.

If either DB, schema, needed columns, amounts or report computation fail, the request returns a concise failure without a misleading zero and without exposing user/bank details.

## CI / source verification

```bash
python3 -B -m unittest discover -s tests -p 'test_nvl_superadmin_accounting_report.py' -v
python3 -B -m py_compile nvl_superadmin_accounting_report.py
```

Require PR head `Python checks` and `Legacy Core Migration Safety` green; inspect changed paths. Merge is **not** Production Deploy.

## Production Core deployment (separate, controlled stage)

Existing Core source checkout was documented as `/root/nvl-release`, actual running bot as `/root/bot_final_v49-2.py`, Python as `/root/venv/bin/python3`, systemd unit `nvlbot`, DBs `/root/master_bot.db` and `/root/accounting.db`. **Read back these facts on host**. Do not execute old one-shot `/root/nvl_k2_publish.sh`, mass-copy the repository, change DB/journal, use `git reset --hard`, or restart until version, file allowlist and rollback evidence are reviewed.

1. Gate 0: identify actual running source checksum, active systemd unit, master/accounting DB quick checks (read-only), host timezone `date`/`timedatectl`, clean source checkout, any protected Core/6G locks and deploy safety; snapshot backup and rollback.
2. Git stage verified final squash SHA in separate immutable directory. Confirm `nvl_superadmin_accounting_report.py` accompanies the compatible `bot_final_v49-2.py`; leaving the new module out must not be mistaken for successful deployment.
3. Run isolated tests and compile with live `/root/venv/bin/python3`; compare only the exact intended allowlist. Preserve live credentials, settings, DB and SSH/Edge routing.
4. A controlled code-only bot restart after approval, while `NVL_SUPERADMIN_ACCOUNTING_REPORT_ENABLED` remains **OFF**, followed by baseline bot smoke.
5. Before enabling, verify **Core bot host local timezone is UTC** (the default assumption for receipt/withdrawal timestamps) and underlying DB copies were not changed. If historical bot host timezone was different, do **not** enable until an explicit timezone-aware release revision has been reviewed.
6. Set `NVL_SUPERADMIN_ACCOUNTING_REPORT_ENABLED=1` only in the reviewed systemd EnvironmentFile (not GitHub; do not expose values) and restart **only** `nvlbot` with a rollback plan. Confirm Super Admin private menu and 3 periods; ensure ordinary admin/reseller/accountant cannot view; verify bot selling paths unaffected.

**Do not deploy or activate merely because the PR has merged.** Post-merge acceptance needs a separate Core-side witnessed, operator-approved run.
