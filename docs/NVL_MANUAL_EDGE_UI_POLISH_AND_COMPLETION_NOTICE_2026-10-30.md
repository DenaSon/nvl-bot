# Manual Edge UI Polish and completed Quick Switch notice

## UI scope
- Title: `مدیریت سرورها` replaces the visible `سرورهای دستی` and `مدیریت Edge` labels.
- Normal Telegram HTML + inline callbacks remain unchanged. No new WebApp, role transition, installer, Cloudflare write, queue or migration code.
- Wizard views emphasize server IP, current readable role, next action. Long explanatory copy is shortened while independent SSH fingerprint confirmation, sensitive credential warnings, DNS/transfer acceptance, cancellation and safety HOLD instructions remain.
- Existing old callbacks, restart recovery and list archive actions stay supported. Do not delete code paths, journal rows or setup receipts.

## DONE-only success notification
- `ManualQuickSwitchUI._execute` obtains the completed Quick Switch job ID after a successful engine `start` or `resume`. It fetches authoritative SQLite journal state under a write transaction and requires `kind='QUICK'`, `status='DONE'`, owner/chat equality, and target as sole active default.
- A unique `manual_quick_success_notices.job_id` persisted `CLAIMED` receipt is committed **before** the Telegram send; a verified message marks it `SENT`. Send errors or ambiguous acknowledgements mark `UNCERTAIN` and are never auto-retried, avoiding duplicate success claims.
- Display target IP, initial migrated account count, verified DNS and **technical completion**; explicitly remind the admin to test post-transfer real client connectivity. Provide `گزارش انتقال` and `مدیریت سرورها` buttons.
- `HOLD`, intermediate stages, failed/uncertain transfers and unrelated/stale defaults never emit success. Existing status page shows actual journal state even if Telegram notification delivery is uncertain.
- Does **not** guarantee exactly-once delivery over Telegram under arbitrary network crashes; it guarantees at most one sending attempt per recorded job.

## Rollout
Deploy as a pinned source-only update after CI. Additive SQLite notice table is created lazily on the first completed notification; no DNS, SSH or account changes are made by this UI patch. Retain backup/rollback of the production database and files.
