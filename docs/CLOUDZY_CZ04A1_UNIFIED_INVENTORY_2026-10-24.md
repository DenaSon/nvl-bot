# CZ-04A.1 — Unified NVL Edge Inventory
Date: 2026-10-24

## Delivery

A read-only all-NVL inventory is accessible from Programs → Cloudzy → Edge & Relay (all NVL). The original guarded Cloudzy-managed VPS action list remains a separate choice.

- Home summary: host_pool total/active/inactive/default/standby; number of CZ-03 EDGE_READY provider-bound Cloudzy VPSs that have management eligibility.
- A paginated (eight per page) list of all host_pool rows, including legacy/manual and Cloudzy. No Cloudzy API call is performed while browsing this inventory.
- Detail is loaded fresh from SQLite after actor/chat/TTL-bound random token resolution. Displays host IP, current membership/default/standby/Core role (Core identified only by settings.core_wg_public_ip), raw provider field or "unregistered/manual", whether CZ-03 provider ownership is verified, and last persisted health state/check timestamp. Last health is **not** interpreted as a current connection test.
- SSH assignment counts use service_type='ssh' only: explicit host counts distinguish active and total; NULL or empty host accounts are shown separately as inherited by the current default host, never silently counted for other hosts.
- The legacy/manual inventory is **read-only** even when its IP matches a VPS seen by Cloudzy. There is no automatic provider adoption/ownership inference. Only the separate CZ-04A managed VPS controller can issue Cloudzy commands, after existing ID/IP/EDGE_READY and preflight gates.
- Pagination and detail callbacks use distinct cz4_nvl_refs, separate from the managed-VPS cz4_refs, and are bound to one administrator actor/chat with 600-second expiry.

## Boundaries

No host_pool/ssh_accounts/settings writes; no DNS, NAT, default-host, relay promotion or K2 changes in the unified inventory. This release does **not** upgrade live health telemetry and does not reconcile stale manual IPs; previously registered entries remain visible. VPS power controls and standby promotion are unchanged; real customer traffic cutover remains CZ-04B.

## Regression acceptance

The new test fixture covers 23 legacy host_pool records with three active and zero provider-managed; 3-page navigation, default/Core role labeling, explicit and inherited SSH counts, V2Ray exclusion, stored health labels, empty Cloudzy-managed inventory, forged/cross-user/expired tokens, and verified-Cloudzy read-only details. Existing CZ-03/CZ-04A no-cutover tests remain required.

## Deploy

Deploy pinned merged Git SHA using detached worktree; run targeted unittest suites first. Back up live bot files and SQLite with .backup. Replace only cloudzy_cz04a.py and cloudzy_admin_panel.py; callback dispatch in bot_final_v49-2.py is unchanged. Compile, restart nvlbot and verify active/logs. In Telegram, inspect all-NVL inventory and Cloudzy 0-managed list without any VPS writes.
