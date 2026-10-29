# NVL — Phase 3 Rich UI for Manual Quick Switch (2026-10-30)

Status: SOURCE ONLY / PR #253. No production deployment, DNS change, customer transfer or Cloudzy deletion.

## New administrator menu

Programs → Management Edge (native Rich):
- Add manual Edge via existing wizard.
- Change customer IP via Quick Switch preview and one-time confirmation.
- My servers via Legacy host inventory.
- Return to Programs.

Cloudzy purchase, VPS inventory/delete, regions, balance, keys and legacy CZ07 batch controls are removed from active Programs and Edge menus. Underlying Cloudzy modules, APIs, historic journals, callbacks and CZ07 queue remain in source and are not deleted. Previously delivered Telegram messages may retain old callback buttons.

## Auth and execution

The bot routes apps_cz_home and apps_edge_quick_* into QuickSwitchUI. Each entry re-reads live admin IDs and requires admin role, private chat and actor == chat. Standby options come only from registered manual Edges.

Preview checks pinned SSH identity, WireGuard, NAT, original shared route guard, accounts and Cloudflare exact A records with 180-second expiration. Approval is a one-use random nonce bound to actor/chat. The Phase 2 engine independently revalidates before applying DNS/SQLite changes. No Cloudzy provider API request or CZ07 batch migration.

Rich status displays the durable journal. Safe resume observes DNS without repeating a PUT. If DNS is still on the source, a separate nonce-bound explicit retry confirmation is necessary; engine rechecks DNS, source roster and target transport. Uncertain effects remain held. No blind automatic rollback.

The completion card prompts separate NPV Tunnel field acceptance and CREATE/RENEW validation. Operator clicking approval is not independent proof of a postcutover ISP connection.

## Release and testing

1. Three GitHub CI suites must pass (Python, Legacy Core and Edge stage-only).
2. Pin exact SHA, verify deployed source, preserve backup and record current DNS/WG/6G state.
3. Deploy code-only; verify admin-only Rich menu and no Cloudzy buttons.
4. Build a *disposable* manual Standby with no users; verify 2252 fingerprint, NAT, WG and host identity. Do not reinstall the active 45.59.126.73 Edge.
5. Test timeout/partial DNS/restart/recovery on isolated fakes and one controlled live cutover only after separate approval.
6. Preserve original CZ07 HOLD history. GitHub merge is not production deployment or acceptance.
