# Legacy NVL: Core migration from the Admin Telegram bot (2026-10-18)

This document applies to the current **WireGuard/DNAT relay topology**, not to the separate K2 Edge-egress work. Clients may still exit through the Core's public IP after migration.

## Canonical Telegram workflow: add Edge, then promote the same host

This is the **legacy ingress/DNAT** workflow, not the K2 "Programs → Manage output" egress wizard.

1. With the current Core healthy, use the Admin bot: **⚙️ Settings → 🌐 IP service → 🛡 IP status / VPS → 🚀 Add new Edge (pre-bought VPS)**. Enter a fresh public IP, the new VPS root password (held only in RAM) and the **customer SSH port** (23–65535; port 22 is reserved for management).
2. The bot connects to **administrative port 22 only**, copies and runs `setup_edge_relay.sh`, validates the installer exit status, installs the permanent management key and registers a unique WG peer on Core. A **fresh WireGuard handshake is required** before adding the server to `host_pool`. Customer-facing and admin ports are recorded separately. A reused/stale IP is blocked rather than overwriting the existing host or duplicating peers.
3. On success, the bot offers **🔎 Check readiness to become Core** directly. Alternatively: **⚙️ Settings → 🖥 Core/Edge server status → 🔎 Promotion readiness** next to that Edge. Readiness checks Core-to-Edge WG reachability, nonduplicate WG identity, administrative SSH, running Edge WG, inbound DNAT, forwarding/MASQUERADE rules, and that the destination bot is **not** active.
4. If ready, choose **🚀 Promote to Core → Start upgrade wizard → Promote via SSH → enter the recorded customer port → final confirmation**. Readiness is checked *again* immediately before scheduling the job; pressing buttons earlier only navigates.
5. After confirming, the detached migration job stages Python/requirements **before** stopping the source bot, securely snapshots the DB, promotes the target, checks the new bot and `core_wg_public_ip`/active `host_pool`, and demotes the old Core to a legacy DNAT Edge. Endpoint sync updates the other WireGuard Edges. A successful systemd-run acceptance is **not** a successful migration.
6. Verify both Core/Edge WG roles, the new bot, SQLite, legacy customer SSH/TLS, and externally observed **client egress = new Core IP** before calling the migration accepted. Observe `/root/failover_migration.log` on the *old* Core; check the detached systemd unit state. Manual redaction is required for any logs.

The previous Core public IP is deliberately retained as an Edge relay after demotion. **DNS is not automatically changed** as part of this source-only flow: changing it without a separate external client probe could cause a new outage. `DNS_UNCHANGED` in the log is an explicit reminder. Operators should verify actual customer DNS and `host_pool` and decide separately if an external DNS cutover is needed.

**Never confirm Promote against an uninstalled/partially installed Edge.** An installation that fails to complete can leave remote files or a Core WG peer; inspect them before attempting to onboard the same IP again. Do not manually wipe active WG, customer rules, SQLite or provider DNS to force a green signal.

## Ordering and safety

- Validate that the selected destination is a real registered WireGuard Edge, and save its soon-to-be-retired private key and WG address for old-Core demotion.
- Before stopping the original bot, stage the **exact** `bot_final_v49-2.py`, `requirements.txt` and user-restoration script, rebuild a clean destination Python virtualenv, install packages, check pip and compile both Python entrypoints.
- Stop original Core bot, take an atomic SQLite backup, export files, and stop its WireGuard interface immediately before starting the destination's Core identity. Avoid two live Core WG identities.
- On the destination, restore DB/peers/TLS, rebuild Linux SSH accounts, start the bot **only after** its prerequisites are configured, and check it is active.
- Demote original Core using the promoted Edge's original WG identity/address; disable its bot and set DNAT/MASQUERADE for customer and TLS/Gost listener ports to 10.77.0.1.
- Update the other Edges' WireGuard endpoints from the new Core. Do not interpret partial endpoint failures as full success.

## Outcomes and recovery boundary

- **Preflight failure:** original Core bot and WireGuard are not stopped. Correct the reported prerequisite before retrying.
- **Failure before new Core bot activation:** the wrapper attempts to restart original Core WireGuard and bot.
- **Failure with destination bot already active:** original bot is deliberately **not** restarted (split-brain protection); operator intervention required.
- **Failure after successful Core promotion or during demotion/endpoint update:** treat as **partial cutover**, not a complete rollback. Preserve the active new Core and diagnose the listed steps; do not blindly rerun Promote.
- `PREPARE_OK`, `DEMOTE_OK`, and `MIGRATION_COMPLETE` are diagnostic milestones, not a substitute for real client connectivity tests.

Do not paste private WG keys, Telegram credentials, customer password values or the migrated database into support chats. The code-only CI checks Bash/Python syntax and control-flow guards; it does **not** substitute for a live migration drill.
