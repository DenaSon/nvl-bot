# NVL — Unified Edge Phase 7 / Stage 2 — Direct Admin Rich UI

**Updated:** 2026-10-28. **Scope:** Read-only Rich view integrated directly in the existing admin Programs hub, without a Feature Flag. Production deployment and live Telegram client acceptance are separately verified.

## Direct availability and operator identity

The Rich dashboard entry appears directly for the current **logged-in NVL admin in their own Telegram private chat**. No `NVL_CLOUDZY_RICH_UI_ENABLED` flag or `NVL_CLOUDZY_RICH_ADMIN_IDS` environment list is required. The app uses the existing active NVL admin registry (`_db_get_admin_chat_ids()`, which includes the super-admin and non-logged-out administrator sessions). Every click re-reads that registry. **Historical** admin IDs do not authorize access.

Security requirements are cumulative:

- Existing `is_auth(context)` authenticated session and `context.user_data.role == 'admin'`.
- Actor's positive Telegram user ID equals the private-chat ID.
- Actor is in NVL's current active admin registry at the moment of the click.
- The persisted CZ07/UO journal belongs to that exact actor/chat.
- For Refresh/Details, the callback matches the same admin's **acknowledged Rich message pointer**. Forged, stale, forwarded or other-admin callbacks fail closed.

No additional role, purchase permission or admin password is inferred from a Rich callback. A removed admin fails the next callback automatically. This is not a new backdoor into CZ07 or legacy infrastructure handlers.

## Telegram Rich contract

- Navigation: Admin → «🧩 برنامه‌ها» → «🚀 Unified Edge | داشبورد Rich».
- Render: `sendRichMessage` and `editMessageText.rich_message` with blocks, RTL, compact table and expandable details, consistent with official Telegram Bot API 10.3.
- `u7:r:...` and `u7:d:...` are **read-only** Refresh and Details. No effectful callback is introduced.
- Latest owned CZ07/UO operation is selected via SELECT-only reads; empty journal produces a neutral no-action card.
- Rich delivery outbox/pointers are created only on first authorized use. Uncertain Telegram HTTP delivery is HELD rather than blindly replayed; there is no HTML fallback.
- No CZ07, CZ04B, DNS, Cloudzy, SSH account, K2, or customer migration mutation is made by this UI.

## Tests and release

- Offline tests cover: direct entry for a logged-in active admin; revoked admin denial; role/chat/private guards; ownership isolation; pointer-binding; no effectful callbacks; single-card Rich send/edit; no journal changes.
- Three repo CI suites: Python full unit and root release, Legacy Core Migration Safety and Edge egress Stage-only (3.11/3.12).
- **A successful GitHub merge is not a Core deployment.** Before production rollout, deploy all relevant Python modules consistently, verify `nvlbot` startup and inspect Rich send logs, then test first on a real private admin Telegram client with a known owned journal. Validate compatibility, callback behavior and no duplicate sends.
- Correctness of actual provider/cutover operations and independently verified SSH CREATE/RENEW/affected-ISP client acceptance remain separate gates before Phase 8.
- Legacy menu remains available, and operator-side code rollback restores the previously deployed snapshot without touching the database, Cloudflare or customer routes. No flag-based disable path exists after this change; rollback is via a controlled code release.

## Next Phase

**Phase 7 live acceptance:** actual Telegram client Rich card validation (including version and message-pointer behavior), then separately considered authenticated mutable control wiring after P4/P5 acceptance. **Phase 8:** end-to-end and failure-injection certification, evidence-based retirement of the legacy path.
