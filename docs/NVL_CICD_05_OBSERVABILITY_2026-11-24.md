# CICD-05 — group notifications and history

Source-only. The observer service and timer are examples, not installed.
Use the existing /etc/nvlbot/nvlbot.env, BOT_TOKEN and MARZBAN_ALERT_CHAT_ID
(the documented infrastructure group). No new group, token, config secret
copy, private-chat fallback or real Telegram send in CI. Verify presence and
same destination on Core without printing values in CICD-06.
The finance report group is not used. No changes to existing alert services.

Persist independent /var/lib/nvl-deploy/history.sqlite3; no changes to
master_bot.db. Terminal committed/rolled-back/HOLD release states and
actionable drift/manual-plan HOLD are deduplicated by candidate and status.
No notices for each CI pending poll, unchanged master or API backoff.
One delivery attempt per tick with exponential backoff up to one hour.
Telegram delivery is at-least-once (an ambiguous accepted request or crash
before recording success may duplicate); no token, raw exception or raw
runtime path in messages/logs. Missing group config leaves notices queued.
Sent history is bounded to 1000 records / 90 days; unsent entries are
retained. The observer is serialized with deployment through its existing
local lock, never through customer/operation locks.

Retention is report-only: preserve current checkpoint backup and at least
five other verified backups; report older-than-14-day eligible releases
only after final state. Incomplete, corrupted or unverified backups are
not deletion candidates. No deletion until owner accepts retention and
off-host recovery policy. Do not enable live timer or send tests yet.

CICD-06 must also ensure every release outcome is recorded before the next
transaction overwrites its checkpoint, prove actual Telegram application
readiness, reconcile baseline and inventory, and close quiescence and
activation blockers in CICD-04.
