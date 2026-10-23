# NVL Cloudzy — CZ-02 Phase 1: Programs Admin Panel

Date: 2026-10-23
Status: SOURCE IMPLEMENTED / OFFLINE TESTS ONLY. A GitHub merge is not production deployment or live Cloudzy account acceptance.

## Scope

- Replace ONLY Programs → مدیریت خروجی (K2 callback hpeg_status) with first-row ☁️ Cloudzy | Edge و Relay (apps_cz_home), and update the corresponding Programs description.
- Do NOT remove any K2 module/handler/state, and do NOT alter any Legacy Settings IP/Edge/Relay callback or screen. K2 protected customer Egress remains unreleased/unaccepted on available source and owner-verified production evidence.
- cloudzy_admin_panel.py is an independent admin-only, asynchronous presentation/controller. Only minimal Programs menu changes and callback wiring live in bot_final_v49-2.py. Existing cloudzy_service.CloudzyService remains the sole provider API abstraction; its blocking reads run in asyncio.to_thread.
- Exactly NINE read-only provider operations: 01 list_regions, 02 list_plans, 07 list_servers, 08 get_server, 09 get_server_status, 18 get_server_usage, 21 list_ssh_keys, 41 whoami and 42 get_balance.
- Read-only UI: paginated VPS list/detail/status/usage; region plans and monthly/hourly/quarterly/annual base pricing; account and wallet; saved SSH key metadata.
- Quick Edge purchase, Edge/Relay control and pending-operation management have clearly nonexecuting future-phase placeholders. Phase 2 handles VPS creation/SSH-key add/Legacy onboarding; Phase 3 handles VPS controls/key deletion/guarded Legacy relay handoff.
- Opaque short callback tokens are bound to actor, chat and a 10-minute TTL. Persist only selected nonsecret identifiers/metadata, NOT provider credentials or whole API objects. HTML-escape provider fields and suppress raw provider errors.
- If CLOUDZY_TOKEN is missing, expired or insufficiently scoped, show a safe HOLD message with no mutation. Set an expiring scoped token in the server environment only; never commit it.

## Telegram route

Programs → ☁️ Cloudzy | Edge و Relay
  - ⚡ ساخت سریع Edge: Phase 2 HOLD
  - 🖥 سرورهای Cloudzy: list/detail/status/usage (read-only)
  - 🌐 Edge و Relay: Phase 3 HOLD
  - 🌍 مناطق و پلن‌ها: plans by region and billing cycle
  - 👤 حساب / 💰 موجودی: read-only account views
  - 🔑 کلیدهای SSH: list and metadata only; no add/delete
  - 📋 عملیات: future-phase HOLD
  - ↩️ برنامه‌ها

A VPS's Cloudzy ACTIVE status is NOT proof of SSH login, WireGuard routing, Iranian carrier reachability, Legacy host_pool/default or real customer Egress. Do not conflate these concepts.

## Testing and release requirements

- Synthetic tests: admin checks, actor/chat/TTL, forged/stale callbacks, provider reads, pagination, escaping, missing/invalid responses, and zero mutating Cloudzy calls.
- Existing Legacy/K2 tests keep their functional assertions, adjusting only the old Programs-shortcut expectation to the newly approved routing.
- CI and source merge are required but not live acceptance. Before production, deploy a pinned reviewed SHA; set CLOUDZY_TOKEN securely; perform operator-approved **read-only** smoke checks against the real account; confirm provider response structures, regions/plans/pricing/usage and the menu on Telegram. Confirm old Settings IP/Edge/Relay behavior has not regressed.
- No real Cloudzy account, Core, WireGuard, DNS, SSH users or customer traffic was changed by these source edits.

Original three-phase plan: docs/CLOUDZY_MANAGEMENT_CZ02_CZ04_3_PHASE_PLAN_2026-10-23.md (Phase 2/3 unchanged).
