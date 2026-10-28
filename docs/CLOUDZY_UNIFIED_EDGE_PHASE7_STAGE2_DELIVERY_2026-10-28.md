# NVL — Unified Edge Phase 7 / Stage 2 — Admin Bot Rich integration

Date: 2026-10-28. Status: code-ready; feature OFF until operator-controlled smoke.

## Deployment scope and boundaries

This integrates the stage-one Rich-only operation viewer into the existing NVL admin Programs hub. It does **not** enable CZ07, CZ04B, DNS mutations, Cloudzy purchases, Linux SSH migration or protected K2 mutations. The new entry is conditional and inactive by default.

Files: \`cloudzy_rich_bridge.py\` (new), \`bot_final_v49-2.py\` (only feature import, optional Programs button, read-only callback dispatch), \`tests/test_cloudzy_rich_bridge_phase7.py\` (new). Previous Stage-1 \`cloudzy_rich_admin.py\` and \`cloudzy_rich_transport.py\` are reused unchanged.

## Feature gate and three admins

**Two independent requirements:**

- \`NVL_CLOUDZY_RICH_UI_ENABLED=1\` (default \`0\`).
- \`NVL_CLOUDZY_RICH_ADMIN_IDS=<id1>,<id2>,<id3>\` (explicit positive Telegram numeric IDs; unique; at most 3). No fallback to the historical \`admin_chat_ids\` setting. This must be configured out of source control. The actual three IDs must be approved independently; never guess, hardcode, infer or expose them.

The handler also requires existing successful NVL login (\`is_auth\`), role \`admin\`, and Telegram private chat where \`actor_id == chat_id\`. Every refresh/details callback reopens the original journal and the *same admin's acknowledged Rich message pointer*. A forwarded/forged/stale button or unauthorized admin cannot display another admin's operation.

Only these operations are supported in Stage 2: most recent \`CZ07\` owned job or \`UO\` owned operation from current SQLite journals; no automatic import of manual/historical Cloudzy records and no sidebar list of other administrators' details. Absent journal tables produce a neutral, no-op Rich card.

## Rendering/transport

- Entry: Admin → «🧩 برنامه‌ها» → «🚀 Unified Edge | داشبورد Rich».
- Server-owned Rich-only callbacks \`u7:r:<kind>:<hex-operation-id>\` and \`u7:d:<kind>:<hex-operation-id>\` respectively refresh or expand technical details. Only those two actions are accepted, and each must belong to the original pointer. Data length is <=64 bytes.
- Selects latest owned operation via SELECT only. Read-only projection never writes or creates business journals. On first actual Rich render, the delivery outbox/pointer tables are lazily initialized. **This changes only Rich delivery metadata**.
- Renders \`InputRichMessage.blocks\` in Persian RTL; sends via \`sendRichMessage\` and edits via \`editMessageText.rich_message\`, no HTML/Markdown fallback or streaming draft.
- No message replay on ambiguous HTTP outcome: \`UNCERTAIN\` outbox holds the Rich display until manual reconciliation, **without marking the underlying operation failed**.
- All operational controls such as Resume, Retry, Cancel or DNS Reconcile are unchanged in their original gated paths; none is bridged into Rich action callbacks.

## Acceptance criteria and limitations

- CI: Python syntax, full unit suite, extracted root release test.
- New offline tests: disabled or malformed flag; wrong role, wrong chat, non-private chat, allowlist errors, per-admin owner isolation, read-only journal projection, no-op empty state, original Rich pointer integrity, Rich callback length and intent dedup, no effects on Cloudzy or CZ07 execution.
- Production acceptance remains separate: deploy all corresponding files together, leave flags OFF by default, verify \`nvlbot\` healthy, then independently opt in a single private admin for a real Telegram 10.3 Rich card display test. Confirm title/table/details/edit in actual supported Telegram clients, no duplicated sends, and outbox. Continue only after explicit operator approval.
- This completes **Stage 2 read-only wiring**, NOT the entire Phase-7 live acceptance. Mutable Rich controls remain blocked pending P4/P5 operational certification, independently verified CZ07 E2E and fenced operations.
- Always keep the existing Legacy admin menu available for safe rollback. With \`NVL_CLOUDZY_RICH_UI_ENABLED=0\`, new button disappears and all new callbacks deny without business effects.

## Rollback

Switch \`NVL_CLOUDZY_RICH_UI_ENABLED=0\` and restart the admin bot after an authorized, planned config change. This disables the new UI without touching the original operations. Code rollback restores only exact previously deployed source/modules (not database or Cloudflare); new Rich delivery tables may remain inert for audit.
