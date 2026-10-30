# Manual Edge and Quick Switch: simple Telegram HTML UI

## Motivation
The former Rich-only interface edited a single message via `manual_edge_rich_pointer`, making navigation and stale cards feel locked. The administrator requested standard Telegram HTML formatting with inline buttons, preserving all manual Edge and Quick Switch functionality.

## Implementation
- Uses ordinary `sendMessage` with `parse_mode="HTML"` and `InlineKeyboardMarkup` for Manual Edge administration **and** Quick Switch.
- Each navigation response is a fresh Telegram message; it does not attempt to edit the old Rich card or depend on the old message pointer. Historical Rich messages and callbacks remain valid but the new response is standard HTML.
- Reuses the existing strict callback/WebApp validation, HTTPS-only WebApp path validation, per-admin permission checks and action IDs; no new action routing or bypass.
- Background install success/HOLD notification also uses ordinary HTML messages. Delivery uncertainty never retries the installer.
- No account migration, Cloudflare/DNS, key-pin, Core WG, lock, role-transition or status mutation logic was changed. `Quick Switch` still owns the sole explicit customer+DNS cutover.
- Sensitive Root password intake continues to delete its incoming message before processing, with the existing stop-on-delete-failure rule.
- Old Rich-only renderer remains available to validate action constraints and for legacy/test compatibility; it is no longer the runtime transport for these two menus.

## Trade-off and rollout
Fresh HTML messages may grow the private administrator's chat history. This is intentional for predictable navigation and avoids cross-card edit failures. Callback authorization and one-use operation guards still prevent repeated effects from old buttons. The shared `apps_edge_manual_*` and `apps_edge_quick_*` actions continue to route to their existing guarded handlers.

**Deploy:** pin target commit, verify production files against the previous deployed commit, back up files and SQLite and test on staging before restarting `nvlbot`. Do not re-run installer, change feature flags, DNS or customers as part of this UI-only deployment.
