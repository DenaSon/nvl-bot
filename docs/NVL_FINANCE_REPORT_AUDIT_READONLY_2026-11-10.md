# NVL Finance Data-Quality Audit — read-only (2026-11-10)

## Scope and non-goals

This is **Data Audit only** for the proposed Super Admin accounting report. It does not implement reports in Telegram, change financial logic, recalculate balances, reconcile/repair any wallet, change schema or run a migration. It imports no bot code and uses only Python standard library.

Source: \`ops/nvl_finance_readonly_audit.py\`. Unit tests: \`tests/test_nvl_finance_readonly_audit.py\`.

**Repository merge is not a Production deploy.** Do not restart or redeploy the bot just to run this independent script. Execute manually only after verifying the actual Core DB locations and ensuring existing operational safety gates are satisfied.

## Read-only guarantees and operational constraints

- Opens each existing SQLite file with \`file:...?mode=ro\` and enables connection-level \`PRAGMA query_only=ON\`.
- Never calls \`init_db\`, \`CREATE\`, \`INSERT\`, \`UPDATE\`, \`DELETE\`, \`ATTACH\`, journal-mode switching or external APIs.
- Output is aggregate JSON on stdout; it deliberately does not print agent names, Telegram IDs, bank card numbers or individual receipt/customer IDs.
- Connects to master and accounting databases separately; this **does not** produce a cross-database atomic snapshot. Live concurrent transactions may cause temporary differences.
- Full-history reads may consume IO; schedule a quiet time and monitor for lock/busy errors.
- SQLite WAL connections may require access to existing \`-wal\`/\`-shm\` sidecars. Do not change journal modes or delete any sidecars to make the audit run.
- Treat all monetary sums as **source-data checks**, not verified bank receipts, business revenue or profit.
- \`receipts.created_at\` tracks submission time, not approval time. \`finance_logs.date\` uses Tehran time; other source timestamps may be server-local or SQLite UTC. Do not publish a 7-day or 30-day financial total until this mapping is verified.
- A missing \`accounting.db\` results in partial output with a warning and \`finance_logs.available=false\`; this is **HOLD**, not audit completion.

## Run (from a checked-out repository at the reviewed commit)

First check what server and files you are on; **do not** edit the files:

\`\`\`bash
pwd
readlink -f /root/master_bot.db
readlink -f /root/accounting.db
stat -c '%n | %s bytes | %y' /root/master_bot.db /root/accounting.db
\`\`\`

Adjust paths if the live Core uses a different location. From the checked-out repo that contains \`ops/nvl_finance_readonly_audit.py\`:

\`\`\`bash
python3 -B ops/nvl_finance_readonly_audit.py \
  --db /root/master_bot.db \
  --accounting /root/accounting.db
\`\`\`

For installations that do not copy the \`ops/\` directory into Production, **do not** overwrite operational files. Use the script directly from a repository clone at the reviewed commit instead. The audit does not require a bot restart.

Recommended isolated tests before running against Production DBs:

\`\`\`bash
python3 -B -m unittest discover -s tests -p 'test_nvl_finance_readonly_audit.py' -v
\`\`\`

## Interpret output

- \`schema\`: which expected tables/columns exist; missing schema means result is incomplete.
- \`agent_current_snapshot\`: current balances/stocks, **not** movement during a date range; missing/deleted agents excluded.
- \`receipts\`: receipt state counts, invalid amounts, unknown agent links and date parseability.
- \`activity_log\`: action/service categories and date quality; not a complete invoice, billing or sale ledger.
- \`withdrawals\`: request states and \`done_at\` completeness; \`done\` is a bot state, not external bank proof.
- \`finance_logs\`: action categories and date quality; entry failure can be suppressed in bot code and mutable agent names are used.
- \`receipt_finance_reconciliation\`: counts of approvals not found in finance logs, duplicates, mismatched recorded amounts, unknown/nonapproved linked IDs. **Discrepancies are prompts for investigation, not proof of fraud or bank settlement.**

If \`schema\` is incomplete, \`finance_logs\` unavailable or dates are unverified, mark the future accounting report's affected metrics as \`DATA_INCOMPLETE\`; never show a precise-looking zero as an independently verified financial figure.

## Follow-up gates

1. Review aggregate output and timezone of the actual Core host. Do not publish any path, secrets or bank information.
2. Reconcile representative anomalies read-only using operator-controlled access to both DBs.
3. Finalize a source-of-truth matrix for all-time / last 7 days / last 30 days, clearly separating current wallet balances from time-window flows.
4. Only then implement the isolated **read-only** Super Admin report module behind an OFF-by-default feature flag and its own regression tests. No charts in V1.
