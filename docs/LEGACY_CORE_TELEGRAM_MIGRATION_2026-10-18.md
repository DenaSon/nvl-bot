# Legacy NVL: Core migration from the Admin Telegram bot (2026-10-18)

This document applies to the current **WireGuard/DNAT relay topology**, not to the separate K2 Edge-egress work. Clients may still exit through the Core's public IP after migration.

## Operator workflow

1. Reinstall the destination VPS if necessary, then onboard it as a **working Edge** through the existing Telegram Edge setup wizard. Its WireGuard public key/address must already be present as a peer on the current Core. Confirm administrative SSH key access through `host_pool.admin_ssh_port` (usually port 22).
2. Publish the **matching bot and shell scripts** from this release onto the running Core. The old Core needs `core_side_failover.sh`, `promote_edge_to_core.sh`, `demote_core_to_edge.sh`, `update_all_edges_endpoint.sh`, `update_edge_endpoint.sh`, `02_recreate_ssh_users.py`, live `bot_final_v49-2.py` and `requirements.txt`. A GitHub merge does *not* prove these files are deployed in /root.
3. From **Admin bot > Servers > selected Edge > Promote Edge to Core**, enter the customer SSH port and use the final **Confirm** button. The bot starts a detached systemd job; an accepted job is **not** a successful migration.
4. Inspect `/root/failover_migration.log` and `systemctl list-units --all 'failover-job-*'` on the original Core. Verify `systemctl is-active nvlbot wg-quick@wg0` on the new Core; verify client SSH/TLS through real Edge hostnames.

## Ordering and safety

- Validate that the selected destination is a real registered WireGuard Edge, and save its soon-to-be-retired private key and WG address for old-Core demotion.
- Preserve the complete Base64 WireGuard key, including its trailing `=` padding, when reading the destination configuration.
- Before stopping the original bot, stage the **exact** `bot_final_v49-2.py`, `requirements.txt` and user-restoration script, rebuild a clean destination Python virtualenv, install packages, check pip and compile both Python entrypoints.
- Stop original Core bot, take an atomic SQLite backup, export files, and stop its WireGuard interface immediately before starting the destination's Core identity. Avoid two live Core WG identities.
- On the destination, restore DB/peers/TLS, rebuild Linux SSH accounts, start the bot **only after** its prerequisites are configured, and check it is active.
- Check effective administrative SSH configuration with an explicit root/port-22 connection context, so the existing `Match LocalPort 22` hardening can be evaluated.
- Demote original Core using the promoted Edge's original WG identity/address; disable its bot and set DNAT/MASQUERADE for customer and TLS/Gost listener ports to 10.77.0.1.
- Update the other Edges' WireGuard endpoints from the new Core. Do not interpret partial endpoint failures as full success.

## Outcomes and recovery boundary

- **Preflight failure:** original Core bot and WireGuard are not stopped. Correct the reported prerequisite before retrying.
- **Source stop reports failure:** abort before backup/promotion; if the stop still left the source bot inactive, attempt to restart it.
- **Promotion failure, including a failed post-start check:** the destination EXIT handler stops/disables its incomplete bot and WireGuard role and checks that no `wg0` interface survives. The source wrapper independently verifies destination shutdown before restarting original Core WireGuard and bot.
- **Destination shutdown cannot be confirmed, or its bot remains active:** original Core is deliberately **not** restarted (split-brain protection); operator intervention required. A successful promotion never runs this failure cleanup.
- **Failure after successful Core promotion or during demotion/endpoint update:** treat as **partial cutover**, not a complete rollback. Preserve the active new Core and diagnose the listed steps; do not blindly rerun Promote.
- `PREPARE_OK`, `DEMOTE_OK`, and `MIGRATION_COMPLETE` are diagnostic milestones, not a substitute for real client connectivity tests.

Do not paste private WG keys, Telegram credentials, customer password values or the migrated database into support chats. CI checks Bash/Python syntax and exercises key extraction, OpenSSH configuration (when available), source-stop faults and target/source rollback with mocked services; it does **not** substitute for a live migration drill.

## Publishing the preflight/rollback follow-up

This follow-up changes only `core_side_failover.sh`, `promote_edge_to_core.sh` and `demote_core_to_edge.sh` at runtime. Stage an exact reviewed commit in a separate worktree, run the migration tests and syntax checks, take an online SQLite backup plus copies of the previous three scripts, and replace only those scripts when no migration is running. Verify the installed hashes. The existing bot launches these helpers from disk, so this shell-only publication does not require restarting the bot or changing Edge onboarding. It does not publish missing prerequisites from earlier migration releases: the matching bot flow, requirements, user-restoration and endpoint helpers in operator step 2 must already be present. Keep the backup directory for code rollback; publication itself does not mutate the database, network or destination VPS.
