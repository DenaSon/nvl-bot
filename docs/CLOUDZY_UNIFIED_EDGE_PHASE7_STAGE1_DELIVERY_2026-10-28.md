# NVL — Unified Edge Phase 7 / Stage 1 — Rich-only admin dashboard

**Date:** 2026-10-28
**Status:** SOURCE-ONLY implementation; no bot callback, network call, scheduler, production schema change or workflow mutation is enabled by this PR.

## Grounded Bot API contract

- Telegram Bot API 10.3 (2026-08-24) supports InputRichMessage \`blocks\` + \`is_rtl\`, \`sendRichMessage\`, \`editMessageText.rich_message\`, compact table, expandable \`details\`, and Rich button blocks with 64-byte callback data.
- Authoritative documentation: https://core.telegram.org/bots/api and https://core.telegram.org/bots/api-changelog
- Our new UI uses **blocks only** (not \`html\`, \`markdown\`, \`sendRichMessageDraft\`, inline plain-HTML fallback or Mini App). Existing Legacy menus are untouched.
- PTB 22.8 compatibility: a narrow async wrapper around raw Bot API methods using Python stdlib; no monkey patch or reliance on PTB private internals. The installed PTB bot token may be explicitly passed by the future handler.

## Implemented in this stage

1. **SELECT-only source projections** for existing \`cloudzy_cz07_jobs\` + \`cloudzy_cz07_events\` and \`cloudzy_uo_operations\`. Both require exact operation ID and matching Telegram actor/chat. Read-only navigation has no CREATE/ALTER. There is no implicit provider identity inference, migration count, or successful milestone claim when source evidence is unavailable.
2. **Rich Persian RTL card** with 8-stage compact timeline, verified-only completion semantics, source/target, DB-derived CZ07 moved/total, technical code, localized typed error guidance, expandable details and two **read-only** controls (Refresh / Details). All callback IDs are short and must be re-authorized server-side.
3. **Rich-only Bot API transport** sends \`sendRichMessage\` or edits with \`editMessageText.rich_message\`. No callback registration, no reuse of an old text/HTML message as the operation card, no silent fallback to HTML.
4. **Durable delivery pointers and outbox** initialized explicitly only on integration, per (operation type, operation, admin chat). Records INTENT before Telegram HTTP; a network ambiguity becomes UNCERTAIN and **prevents automatic send/edit replay**. Acknowledged versions deduplicate updates. Delivery status is separate from workflow success/failure.
5. Stable error catalog: UNKNOWN → neutral explanation + original safe code and correlation fields; no confident misattribution to Cloudzy. The stage-one buttons cannot trigger DNS, VPS purchase, migration, routing, cancel, retry, resume or reconcile effects.

## Acceptance and limitations

- Offline tests with ephemeral SQLite and fake Bot API: wrong admin/chat, stale event, render type and RTL, callback-size restrictions, one-message send/edit, version deduplication, intentional network ambiguity, crash between HTTP intent and ACK, and no effectful callback.
- **No live Telegram Rich smoke** on three real admin clients has occurred. The API schema is verified from current official docs, but display/client compatibility must be tested independently.
- **No mutable Retry/Resume/Reconcile/Cancel buttons** are wired in this first slice. These must be derived from current journal/version/lease/security evidence and have nonce-bound server-side authorization, fresh checks, side-effect journals and original 6G fences. A rich card displaying a suggestion cannot itself authorize an operation.
- This stage does not link P5 guarded route, CZ07 business evidence acceptance, Cloudzy provider, or any admin screen. The final 8-stage accepted timeline cannot be marked all-green until actual independent receipts exist. Per-admin message pointers are persisted, but a prior UNCERTAIN Telegram request requires operator reconciliation before retry. No speculative automatic resend.
- Source branch can be merged after CI while **production integration remains disabled**. A separate owner-controlled operator test is required before any live PTB bot token or Telegram request.

## Follow-on Phase 7 slices

- Map unifying read projection and **verified milestone event receipts**, with real provider/server identities in authorized card only.
- Wire read-only admin entry in a private chat behind explicit opt-in and allowlisted three admin IDs.
- Real device tests for Telegram 10.3 payload, RTL and Details/Buttons; persist per-admin message pointer after successful ack.
- Add authenticated, idempotent, nonce+expected-version actions after Phase 4/5 acceptance: route reconciling, safe CZ07 Resume, cancel after batch; never action from rendered metadata alone.
- Bounded delivery throttle and operator repair for uncertain Telegram sends, with no duplicated business actions.

## Safety/rollback

Only new files. No changes to \`bot_final_v49-2.py\`, original handlers, Core SSH, Linux accounts, Cloudflare, Cloudzy, CZ07 or production SQLite. Rollback is removing or ignoring these modules; they are inert without explicit invocation.
