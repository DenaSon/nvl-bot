# NVL Cloudzy CZ-04A — Managed VPS and Standby Relay

Date: 2026-10-24
Status: Source implemented / live acceptance pending.

## Safety boundary

CZ-04A "Relay activation" is deliberately a standby-only operation. An inactive Cloudzy Edge becomes active=1 and is_standby=1 in host_pool after fresh checks. The code does NOT change the default host, settings.hosts, Cloudflare, public DNS, NAT, Core role, ssh_accounts.host, existing users, or K2 routing. Real traffic migration and default/DNS handoff belong to CZ-04B, where they must be ordered and reconciled together.

Do not reuse the historical srv_mkactive_ handler: it changes default metadata before Cloudflare/NAT and is unsafe for an automated partial handoff. Legacy manual callbacks remain unmodified.

## Telegram flow

Programs > Cloudzy > Edge & Relay (standby), or Manage VPS. Only a Cloudzy VPS linked through a successfully accepted CZ-03 operation (matching host_pool.provider_instance_id, public IPv4, and cloudzy_edge_operations.EDGE_READY) is actionable. Imported or externally purchased Cloudzy VPSs remain read-only in CZ-02.

- Read provider ID, public IP and power status with a fresh GET.
- Managed VPS start/stop/reboot: only isolated inactive non-standby VPS, no DNS/default/hosts/assigned accounts and no auto-failover; one-use actor/chat/TTL-bound confirmation.
- Standby activation: require provider ACTIVE, matching ID+IP, fresh client/admin SSH reachability from Core, real Core WireGuard peer and tunnel path. Reject protected mode, K2 onboarding, auto-failover, original 6G failover, conflicting VPS operation or user/route ownership.
- User is told standby status does NOT mean Iranian carrier/client reachability.

## Journal / crash handling

Lazy SQLite table cloudzy_cz04a_actions persists an IN_FLIGHT entry before provider writes. Confirmed 4xx rejections become REJECTED, accepted provider commands DONE (verify resulting live state separately), uncertainty becomes HOLD. Interrupted operations remain IN_FLIGHT; both HOLD and IN_FLIGHT block further CZ-04A mutations until manually investigated. There is no automatic retry and no write-side clear-HOLD UI. Standby promotion and journal completion use a single local SQLite transaction.

## Explicit exclusions

No default change, DNS, NAT or customer reassignment; these are CZ-04B. Rename, destructive rebuild/reset-password/delete and SSH-key delete are deliberately NOT exposed in this first controlled 04A increment; safe detachment and one-time secret handling are prerequisites. No paid Cloudzy operation was performed when merging the source.

## Deploy / tests

Deploy pinned SHA in detached staging; run full Python regression, back up DB and runtime, replace cloudzy_cz04a.py, cloudzy_admin_panel.py and bot_final_v49-2.py together, compile and restart nvlbot. Keep the currently deployed Cloudzy token file unchanged. Smoke test read-only menus first, then a single isolated test VPS when the Cloudzy account has balance. Preserve a separate CZ-04B acceptance window for real customer cutover.
