> **Delivery update — 2026-10-23:** CZ-02 Phase 1 read-only Cloudzy UI merged to master (PR #182). CZ-03 Phase 2 purchase/wait/Core-public-key/Legacy-inactive-Edge workflow is implemented **in source in PR #183**; do not claim any live Cloudzy order, production deployment, or customer acceptance. The Legacy manual UI and K2 source remain. CZ-04 Phase 3 is still planned, not implemented. Detailed Phase 2 acceptance and HOLD states: [CZ-03 delivery record](CLOUDZY_CZ03_PHASE2_DELIVERY_2026-10-23.md). The original plan below describes the design baseline, not the latest delivery state.

# NVL — Cloudzy / Legacy Edge management: three-phase plan

Date: 2026-10-23
Status: PLANNING ONLY. No Telegram application, provider VPS, Core, WireGuard, DNS or user-traffic mutation is authorized by this document.

## Navigation decision: supersedes former first-page proposal

The new entry belongs at the TOP of 🧩 برنامه‌ها, replacing only the existing 🌐 مدیریت خروجی -> hpeg_status button and its explanatory text in _build_admin_programs_kb() and _show_admin_programs_hub(). The replacement label is ☁️ Cloudzy | Edge و Relay with a fresh callback namespace cz_ (e.g. cz_home).

Do NOT remove the K2 handlers hpeg_*, K2 source modules, flags, state, database tables, or existing Telegram callback compatibility. K2 customer Egress is NOT RELEASED / NOT ACCEPTED for Production based on checked master defaults and available release evidence; never depend on it for this Cloudzy workflow. This source conclusion is not a fresh live-host inspection.

Keep the existing LEGACY UI untouched, including Settings -> 🖥 وضعیت و نقش سرورها (srv_status), Settings -> 🌐 سرویس IP / خرید سرور جدید(دستی) (ipsvc_menu), hp_addedge manual wizard and input states, srv_mkactive_, hpdef_, hpdef_migrate_, hpdefmig_yes_, hpstandby_ and old failover controls. No rerouting of old callbacks and no programmatic Telegram callback playback.

Keep the existing Marzban nodes, hosts, migration and monitoring rows, and the Programs back/home navigation, byte-for-byte equivalent in user behavior.

## Target Cloudzy home UI

🧩 برنامه‌ها
  ☁️ Cloudzy | Edge و Relay  (new first row)
  🖥 نودها | 🌐 هاست‌ها
  🚚 انتقال Marzban | 🛰 مانیتورینگ
  🏠 منوی اصلی

☁️ Cloudzy | Edge و Relay
  🚀 ساخت و راه‌اندازی سریع Edge
  🖥 سرورهای Cloudzy
  🌐 Edge و Relay
  🔑 کلیدهای SSH
  💳 حساب و موجودی
  📋 عملیات نیمه‌تمام
  ↩️ برنامه‌ها

Server detail: live VPS ID/hostname, region, IP and power state, resources, usage, NVL association (Cloudzy-only / Legacy Edge / Relay), plus authorized actions; paginate provider lists. Distinguish provider VPS status from WireGuard/SSH, NVL host_pool membership, selected default host, public DNS and real customer connectivity. Never label a mere active VPS as a working Relay.

The new wizard uses a FIXED Ubuntu 24.04 template (ubuntu-24.04) internally. No OS selector or user-facing OS question. If this OS template is not supported for the selected plan or provider API rejects it, HOLD without changing the OS. Reuse the current customer SSH port from validated NVL settings.

## Phase 1 — CZ-02: New Programs navigation and read-only dashboard

Deliver:
- Replace ONLY the old K2 Programs button and description, leaving all other menus intact; new admin-only cz_* callbacks with proper cancel/back, TTL and HTML-safe output. Keep most code in a separate Cloudzy UI module, not in the bot monolith.
- Read-only chosen API operations: 01 list_regions, 02 list_plans, 07 list_servers, 08 get_server, 09 get_server_status, 18 get_server_usage, 21 list_ssh_keys, 41 whoami and 42 get_balance (9 of 20).
- Display Cloudzy inventory with paginated live details, prices by region and cycle with BASE-PRICE warning (IPv4 extras not included), account and balance, public SSH keys, and read-only wizard preflight.
- Handle missing/expired token, insufficient scope, provider timeout, empty lists, duplicate/stale callback, wrong user/chat, wrong region/plan and unavailable API. Confirm read-only API with an operator-supplied scoped token before production readiness; never show credentials.

Acceptance: Program entry replaced; Legacy Settings/menu/callback snapshot unchanged; all nine read methods reachable, tested with mocked responses; zero purchase, VPS mutation or customer traffic switch.

## Phase 2 — CZ-03: Cloudzy purchase and automatic Legacy Edge installation

Deliver:
- Chosen write/wait operations: 06 create_server, 10 wait_for_ready, 22 add_ssh_key (3 of 20).
- Wizard: select region, plan and billing cycle -> confirm public IP requirement and pricing caveat -> explicit cost approval -> exactly-one VPS creation -> wait for ACTIVE -> fetch public IPv4 and verify root SSH identity -> reuse existing Legacy _provision_new_edge(... private_key_path=..., provider="cloudzy", provider_instance_id=..., egress_stage_requested=False) -> test WireGuard and customer SSH service -> report Edge prepared. No duplicate SSH/WG installer, no simulated old callbacks.
- Use existing Core ED25519 public key / secure SSH key enrollment. The current Legacy provisioner uses Paramiko AutoAddPolicy for unknown SSH host keys; unattended new provisioning needs a separately trusted host-key fingerprint/pin. Add at most an opt-in security parameter/path with existing Legacy default behavior unchanged, or require manual identity approval and HOLD.
- Use a minimal durable, nonsecret operation receipt with actor/chat, region, plan, billing cycle, Ubuntu template, stable Cloudzy idempotency key, VPS ID, IP, stage and timestamps. No private key or root password in DB. Recheck provider state on purchase timeout/unknown result before retry. Single-flight purchase lock; restart-safe HOLD/resume and no duplicate creation.
- Preflight protected-mode Legacy gate and original 6G/failover locks before modifying host_pool/WG. Cloudzy ACTIVE is not SSH readiness and a WG ping is not full real-client acceptance. Preserve partial artifacts for inspection.
- Phase 2 explicitly EXCLUDES auto Relay promotion, default/DNS cutover, ssh_accounts.host migration, automatic old VPS shutdown/deletion and any K2 routing.

Acceptance: one authorized VPS order becomes a tested Legacy Edge in isolated live trial, correct provider metadata, audit and failure recovery, existing manual wizard unchanged; no customer traffic cutover.

## Phase 3 — CZ-04: Remaining Cloudzy controls + Legacy Relay/customer migration

Deliver:
- Remaining selected API actions (8 of 20): 11 rename_server; 12 power_on; 13 power_off; 14 restart_server; 16 rebuild_server; 17 reset_server_password; 20 delete_server; 23 delete_ssh_key. No other provider API capability.
- Verified ownership by provider VPS ID (not IP alone), fresh state before writes, admin-only one-use confirmations (actor, chat, VPS ID, TTL/revision), two-stage irreversible confirmations, and one-time password handling only in a private admin context with no plaintext persistent logging.
- Block power-off/restart/rebuild/delete of an active/default/DNS-backed Edge, any VPS with user assignments, open failover/operation lease, unmanaged ownership or K2 managed dependencies, except after explicit separate safe-detachment verification. Never automatically delete old VPS or SSH keys required by a running provisioning workflow.
- Edge/Relay submenu: inventory of registered Legacy Edges, selected default, DNS and distinct user Host ownership counts. Only after complete setup and fresh diagnostics present 🎯 فعال‌سازی Relay, then 👥 انتقال Host کاربران with distinct operator confirmations and reconciliation. NO K2 UID Egress migration.
- Reuse existing Legacy semantics (Cloudflare update, DNAT, default host, ssh_accounts.host), NOT the old Telegram callbacks. The old srv_mkactive_ writes default metadata before Cloudflare and NAT; NEVER blindly chain it. Implement a minimal isolated guarded orchestration adapter with preflight, source snapshot, ordered commit, post-checks and explicit HOLD/reconcile for uncertain partial mutations, without changing the existing manual UI.
- Test 0/1/N customers, stale DNS mapping, SSH/ISP reachability versus banner-only health, provider errors, Cloudflare failure, NAT failure, concurrent failover, duplicate requests, restart, protected-mode HOLD and operator recovery.

Acceptance: all 20 owner-selected Cloudzy API operations are reachable in the new UI under their appropriate permissions/safety gates, successful isolated Relay switch and host reassignment with independent real-client verification, and ALL Legacy UI and callbacks remain usable as before.

## Selected capability accounting

CZ-02: 01, 02, 07, 08, 09, 18, 21, 41, 42 = 9.
CZ-03: 06, 10, 22 = 3.
CZ-04: 11, 12, 13, 14, 16, 17, 20, 23 = 8.
Total: exactly 20 chosen Cloudzy capabilities.

The selected CloudzyService catalog prices are BASE estimates; exact IPv4-inclusive quotes are not among the selected calls. If exact provider quote is made mandatory, propose it explicitly for separate scope approval, or HOLD rather than promising the catalog total is final.

## Implementation and testing boundaries

Keep cloudzy_service.py provider-only. New management UI, callbacks and orchestration should live in separate focused modules; only a small Programs-menu replacement and handler registration should touch the large bot_final_v49-2.py. Preserve every original Legacy route, callback contract and behavior.

Every phase requires targeted negative-path tests, full Python CI, PR review and merge into master; a merge does not deploy to production. Do not enable K2, bypass a safety gate, automatically retry an uncertain mutation, change DNS on initial VPS creation or migrate real users without a separately controlled acceptance window and independent connection test.

## Status

All three phases PLANNED, not implemented. This documentation-only update does not change the Telegram UI, underlying VPS, WireGuard, DNS or customer assignment.
