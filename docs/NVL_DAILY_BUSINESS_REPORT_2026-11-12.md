# NVL Daily Business Report — 2026-11-12

## Scope and policy

**Group-only**, opt-in, read-only daily business digest for reseller sales and
wallet/cash movements. No DNS, Edge, Marzban, price, commission, or purchasing
workflow changes. The existing midnight CSV/report remains unchanged.

Environment in the running Core **systemd** service:

```dotenv
NVL_DAILY_FINANCE_REPORT_ENABLED=1
NVL_DAILY_FINANCE_REPORT_CHAT_ID=-1004495255355
NVL_DAILY_FINANCE_REPORT_TIME=00:05
NVL_DAILY_FINANCE_REPORT_TZ=Asia/Tehran
```

Do not commit bot tokens. The group id is the private group designated by
the operator, not a bot ID. No admin-DM fallback for this daily digest.

## Definitions

- A report day is **00:00 to 00:00, exclusive**, Asia/Tehran, not a rolling 24h
  period. The automatic report starts at 00:05 Tehran for the preceding day.
- `AGENT_CREATED`: a new registered reseller, logged in the SAME master DB
  transaction as the insert.
- `BANK_TOPUP`: a pending receipt successfully approved, logged in the SAME
  master DB transaction as crediting the reseller's wallet. Uses receipt ID
  as idempotency key; distinguishes central bank card versus reseller-owned card.
  A submitted but not approved receipt is not counted.
- `MANUAL_TOPUP`: an administrator's direct wallet credit. This is **not**
  presumed to represent money received at NVL's bank.
- `PURCHASE`: actual reseller wallet debit during purchase, bulk issuance,
  renewal, volume extension, or user-limit extension (positive amounts).
  Direct-admin creation without a reseller wallet debit is deliberately not
  treated as cash revenue.
- `PURCHASE_REFUND`: reseller wallet refund for corresponding reversal, deletion,
  or service reduction (positive amount), subtracted from net consumption.
- Unique purchasing agents and unique topping-up agents use `agent_id`.
- **Central cash inflow = bank receipt approvals addressed to central NVL card**.
  Partner card payments are shown separately: not cash in the central account.
- Wallet top-ups = central bank + partner bank + manual credit, a measure of
  recorded wallet credits, not total outside money received.
- Buying with already credited wallet funds is **NOT** counted again as inflow.
- The comparative metric (net purchase versus yesterday) is omitted until both
  calendar days are fully covered by the new ledger.

## Integrity and known limits

`nvl_business_events` is an append-only-from-application ledger within
`master_bot.db`. Creation, bank approval, manual credit, purchase debits, and
refund credits append in the **same SQLite transaction** as the balance
mutation. The separate `accounting.db` remains unchanged and is not treated
as the source of truth for this new report.

**No historical backfill**: old agents lack reliable creation timestamps; old
receipts lack an approval timestamp; older purchase logs omit some bulk flows.
The rollout timestamp in `nvl_business_metadata` is written only at first
schema installation. Reports covering that first calendar day prominently
indicate partial coverage. Do not assert historical zeros are real zeros.

Price-free direct-admin sales, bank transfers outside the receipt process,
commission/withdrawal settlements, deleted historic operations and old
transactions are outside this ledger. This is **not** a general-ledger,
profit, or bank-reconciliation report.

## Delivery and recovery

`nvl_business_report_deliveries` has one row per Tehran date. The scheduler
claims the oldest missing closed day (up to seven days back) *before* sending.
`SENT` stores a Telegram message ID. An ambiguous error becomes `UNCERTAIN`
and is **not automatically resent**, to prevent duplicate notifications.
Review UNCERTAIN on the Core and check the group before manually resolving.
No private-message fallback. Restart while a delivery was INTENT may leave
the row at `INTENT` for manual reconciliation.

The job runs every minute inside existing `nvlbot`; it does not start
another process, create a cron job or new bot.

Super-admin-only private read-only commands:
- `/daily_business_report today`: today's activity so far.
- `/daily_business_report yesterday`: last closed day.

The manual commands do not write a delivery claim or post to the group.

## Deploy to Core

1. Deploy **both** `bot_final_v49-2.py` and `nvl_daily_business.py` from the
   same green CI commit (do not copy only the main script). Preserve
   `master_bot.db`, `accounting.db`, and persistence. Take a DB backup.
2. Run `/root/venv/bin/python3 -m unittest tests.test_nvl_daily_business -v`
   from the release staging checkout. Compile both modules.
3. Configure the ENV above in `nvlbot.service` / an actual
   `EnvironmentFile` and `systemctl daemon-reload && systemctl restart nvlbot`.
4. Verify `systemctl is-active nvlbot`, process ENV (without tokens),
   `/daily_business_report today` in private super-admin chat,
   `journalctl -u nvlbot | grep NVL_DAILY_BUSINESS_REPORT`.
5. Confirm the group receives the first automatic report at 00:05 Tehran.
   Compare values with independent receipts and posted wallet debits.

Read-only useful queries:

```sql
SELECT kind,COUNT(*) n,ROUND(SUM(amount_toman),2) amount
FROM nvl_business_events GROUP BY kind;
SELECT report_day,status,telegram_message_id,error_kind
FROM nvl_business_report_deliveries ORDER BY report_day DESC LIMIT 10;
```

## Rollback

Disable with `NVL_DAILY_FINANCE_REPORT_ENABLED=0` and restart; existing
business events are not removed. Older code should only be restored with the
matched runtime and backed-up database according to the Core release runbook.
