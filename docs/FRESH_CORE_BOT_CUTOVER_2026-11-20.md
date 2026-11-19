# Fresh Core bot migration — pre-staged VPS (2026-11-20)

This is distinct from the registered-Edge Promote/Demote wizard. The old promotion path is preserved.

## Scope and source of truth

Source Core: 91.107.170.239. Destination: 185.202.113.79 (already pre-staged with bot, snapshot SQLite DB, Linux identities, WG/AWG keys and peers, GOST, BadVPN, and separate customer SSH 2252). The operator explicitly skips the final live DB sync; changes since the snapshot WILL NOT be transferred. Preflight copies only the Python bot entrypoint, not the database.

During the preflight, duplicate wg0/awg0 listeners on the DESTINATION are stopped and remain passive until the source is frozen at cutover. The source Core remains fully operational during this preparation. Source-key equality is checked against target config private keys offline without printing private keys. Preflight therefore modifies target tunnel runtime (not live source).

The old Core must have passwordless administrative SSH on port 22 to the destination using /root/.ssh/edge_provision_ed25519; its SSH host key must be pinned in /root/.ssh/known_hosts. Missing or changed trust results in HOLD; do not disable SSH host key checking.

## Bot operation

Admin → Server Settings → «انتقال بات به Core جدید» → destination IPv4 → «بررسی آمادگی انتقال» → review → explicit final confirmation. This creates a detached systemd-run job; job registration is NOT success.

Read-only with respect to the live source Core, but stages the code entrypoint on destination:

    bash /root/fresh_core_cutover.sh check 185.202.113.79 2252

This verifies source and target roles, matching WireGuard and AmneziaWG public identities, a healthy snapshot DB, importable bot, root administrative SSH, inactive target bot, active target network listeners, and a dry run of existing SSH account restoration.

The confirmed cutover stops the old bot and WG/AWG, updates only destination settings.core_wg_public_ip, uses the EXISTING 02_recreate_ssh_users.py to restore active users from the destination snapshot, then starts the new bot/customer SSH and enables its boot units. The old VPS stays powered on, but its bot/WG/AWG are stopped. Only one bot poller may run.

On a failure after old bot freeze, rollback first stops and verifies the new bot and WG/AWG before restarting the old Core. If remote shutdown cannot be confirmed, rollback is HOLD and source bot remains stopped to avoid split brain.

Authoritative outcome: FRESH_CORE_BOT_MIGRATION=PASS, with explicit EDGE_ENDPOINTS=NOT_MIGRATED and DNS=UNCHANGED. Source log: /root/fresh_core_migration.log.

## Not included — separate release/acceptance required

- The registered WireGuard and AmneziaWG Edge endpoints are NOT repointed. DNS is NOT changed. Client network disruption may persist.
- No final database synchronization, and no guarantee that 100% of account records, recent transactions, or local SSH sessions reconcile.
- No K2 protected-user egress, cloudflared, probes, or all systemd services acceptance.
- A successful ping to the main relay during previous tests did not prove a handshake on the new Core.
- Publishing code to a GitHub branch or merging does NOT deploy /root on either VPS. Independent operator deployment, external customer tests, and post-cutover review remain required.

The PR does not touch live Core services, live databases, or remote VPSs.
