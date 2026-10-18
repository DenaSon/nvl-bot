# Legacy NVL: Core migration from the Admin Telegram bot (2026-10-18)

This document applies to the current **WireGuard/DNAT relay topology**, not to the separate K2 Edge-egress work. Clients may still exit through the Core's public IP after migration.

## Operator workflow

1. Reinstall the destination VPS if necessary, then onboard it as a **working Edge** through the existing Telegram Edge setup wizard. Its WireGuard public key/address must already be present as a peer on the current Core. Confirm administrative SSH key access through `host_pool.admin_ssh_port` (usually port 22).
2. Publish the **matching bot and shell scripts** from this release onto the running Core. The old Core needs `core_side_failover.sh`, `promote_edge_to_core.sh`, `demote_core_to_edge.sh`, `update_all_edges_endpoint.sh`, `update_edge_endpoint.sh`, `02_recreate_ssh_users.py`, live `bot_final_v49-2.py` and `requirements.txt`. A GitHub merge does *not* prove these files are deployed in /root.
3. From **Admin bot > Servers > selected Edge > Promote Edge to Core**, enter the customer SSH port and use the final **Confirm** button. The bot starts a detached systemd job; an accepted job is **not** a successful migration.
4. Inspect `/root/failover_migration.log` and `systemctl list-units --all 'failover-job-*'` on the original Core. Verify `systemctl is-active nvlbot wg-quick@wg0` on the new Core; verify client SSH/TLS through real Edge hostnames.

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
