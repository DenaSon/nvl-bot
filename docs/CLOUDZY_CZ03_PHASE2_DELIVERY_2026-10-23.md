# NVL Cloudzy CZ-03 — Paid VPS + Legacy Edge setup

Date: 2026-10-23
Status: SOURCE IMPLEMENTED; NOT DEPLOYED, NOT LIVE-ACCEPTED.

This is Phase 2 of three. Phase 1 Cloudzy read-only panel (CZ-02) was merged; Phase 3 Relay promotion, customer host reassignment, VPS power/delete/rebuild controls and K2 customer Egress are not provided by this feature.

## Telegram UX

Programs → Cloudzy | Edge & Relay → Quick Edge

1. Admin-only preflight on current Core: root/Paramiko, existing Legacy Edge script, Core WireGuard identity/public IP, owner-only Ed25519 private SSH key, validated current customer SSH port, protected-mode gate, no protected K2 UID bindings, original 6G not RUNNING, K2 auto-onboarding disabled.
2. Query Cloudzy regions and region+cycle plans. Choose region, cycle and plan. **OS fixed internally to ubuntu-24.04** and not offered as a UI option. If incompatible with plan/provider, HOLD; never silently downgrade OS.
3. Display region, plan, SSH port and catalog base price. Warn that final charge, IPv4 and extras may differ. Require explicit admin confirmation.
4. BEFORE paid POST /services persist durable single-flight purchase record in Core SQLite table cloudzy_edge_operations, including actor/chat, stage, stable operation ID and Cloudzy Idempotency-Key. No private keys/root password/raw provider data stored. Duplicate callbacks/unfinished operations cannot charge again.
5. CloudzyService.create_server(confirm=True), SSH authorized PUBLIC Core key, ipv4, fixed OS, region/plan/cycle and persisted idempotency key. Unknown API/timeout/5xx/invalid response -> HOLD with **no blind retry**.
6. Wait for ACTIVE via wait_for_ready, require single externally routable IPv4. Cloudzy ACTIVE does not imply working SSH/WG.
7. Observe host public key on SSH 22; present SHA256 fingerprint. Before any privileged command, require admin to verify fingerprint from a trusted independent source (e.g. Cloudzy console command: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub, using the negotiated key type). The same untrusted network observation is NOT independent authentication.
8. Fresh Core/Legacy preflight and one-use actor/chat-bound confirmation; recheck pinned host key and use existing Legacy _provision_new_edge() with Ed25519 private management key. The opt-in trusted_host_key pin rejects SSH host-key mismatch; old manual Legacy default remains unchanged.
9. CZ03-only pool_active=False: register Cloudzy Edge in host_pool as INACTIVE, with provider instance ID and WireGuard peer, without adding it to active hosts settings. Verify tunnel, customer-port SSH banner, provider ownership, inactive/default flags, no DNS/default selection and zero user assignments before journal EDGE_READY.
10. All existing users, DNS, Cloudflare and default Relay unchanged; independent full client acceptance and guarded promotion belong to Phase 3.

## Code

- cloudzy_quick_edge.py: Telegram wizard and durable, restart-safe SQLite receipt; **no new SSH/WireGuard setup engine**.
- bot_final_v49-2.py: small additive, opt-in trusted_host_key and pool_active=False paths for new Cloudzy workflow, plus security preflight/verification. All old hp_addedge, hpdef_, srv_mkactive_, hpdefmig_yes_ and K2 callback paths remain available.
- cloudzy_admin_panel.py: separate operator-confirmed registration of PUBLIC Core SSH key via selected Cloudzy add_ssh_key action (API 22).
- cloudzy_service.py: existing standalone provider adapter, no bot logic introduced.

Journal stages: CREATING → CREATED → WAITING → HOLD_SSH → HOSTKEY_PENDING → PROVISIONING → EDGE_READY. Unknown or interrupted stages persist HOLD / CREATE_UNCERTAIN; no automatic re-purchase and no blind replay of partial SSH/WireGuard installation. Operator may reconcile interrupted create/wait with GET/list_servers and unique operation hostname; never POST twice.

## Safety and acceptance

- No live purchase, production deploy, K2 activation, DNS/Cloudflare change or customer transfer is made by the GitHub source change.
- Legacy installer has nontransactional Core/WG side effects: ambiguous failures are HOLD for manual investigation. Never automatically delete the old Edge.
- Existing Legacy menu/behaviors and operator-facing Callback contracts must remain unchanged. K2 customer Egress remains NOT RELEASED/NOT ACCEPTED.
- Cloudzy developer token is scoped/expiring and configured only as CLOUDZY_TOKEN in host environment. No token/private key/root password in Telegram, logs or Git.
- Catalog prices can show monthly equivalents rather than a charge quote; IPv4/extras may be separate. The wizard labels the price basis.
- Unit tests are hermetic. Production acceptance requires operator-controlled account and catalog reads, template/price/IPv4 check, single explicitly authorized paid trial, independent console fingerprint, SSH/Legacy WG and independent client connection test.
- Cloudzy VPS power, restart, rename, rebuild, delete, saved-key deletion and actual Relay promotion/user host reassignment belong to CZ-04.
