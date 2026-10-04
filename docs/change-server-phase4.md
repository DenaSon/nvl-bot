# Change Server — Phase 4: Final Sync + IP Rewrite + Start/Verify

Phase 4 is the first intentionally disruptive stage of Change Server.

It consumes a destination that has already completed Phase 3 RESTORE and performs
the last database synchronization from the source before DNS/Cloudflare cutover.

## Safety boundary

Phase 4 still does **not** change DNS or Cloudflare.

It is responsible only for:

1. final readiness plan
2. controlled source stop
3. final SQLite snapshot
4. Source -> NVL -> Destination transfer
5. destination DB safety backup
6. atomic destination DB replacement
7. targeted `hosts.address` rewrite
8. stale old-IP validation
9. destination DB integrity validation
10. destination start + local API/listener health checks

Phase 5 will own external cutover and rollback of DNS/origin routing.

## PLAN_ONLY mode

This is the default and non-disruptive mode.

It verifies:

- source and destination identity
- Phase 2 bundle metadata still matches the source
- source/destination Marzban runtime paths match the bundle
- both SQLite databases pass `PRAGMA integrity_check`
- the exact number of source rows matching:
  `hosts.address = OLD_IP`
- source runtime state
- destination runtime state
- Phase 3 `RESTORE_COMPLETE` marker
- whether Phase 4 was already completed

A destination that is currently running is **not** finalization-ready.

A destination that only ran Phase 3 INSPECT_ONLY is also not finalization-ready,
because it does not have the `RESTORE_COMPLETE` marker.

No service is stopped or started in PLAN_ONLY.

## FINALIZE mode

FINALIZE requires the exact confirmation phrase:

    FINAL-SYNC

Before any mutation it also requires:

- Phase 3 RESTORE_COMPLETE
- destination runtime stopped
- valid source and destination SQLite DBs
- source/destination IPs to be distinct
- exclusive final-sync locks on both servers

Global lock path:

    /root/nvl-migrations/.final-sync-lock

The lock is per server and prevents overlapping final-sync jobs.

## Final source snapshot

If the source is running, Phase 4 stops it with:

    docker compose stop

The source is not removed and no `docker compose down` is used.

Once stopped, Phase 4 creates a fresh final SQLite snapshot with Python's
`sqlite3.Connection.backup()` API.

Both source and snapshot must pass:

    PRAGMA integrity_check = ok

The final snapshot receives its own SHA256.

## Final DB relay

The final DB is relayed:

    Source -> NVL -> Destination

Default NVL staging:

    /var/lib/nvl/migrations/<job-id>/final-sync/<attempt-id>/

Destination staging:

    /root/nvl-migrations/<job-id>/final-sync/<attempt-id>/incoming/

The SHA256 must match after both hops.

## Destination DB safety backup

Before replacing the restored Phase 3 database, Phase 4 creates:

    destination-before-final.sqlite3

inside the attempt directory.

This backup is itself created with the SQLite backup API and integrity-checked.

## Atomic DB replacement

The staged final DB is copied into a temporary file next to the runtime database.

The current runtime DB owner/group/mode are preserved, then `os.replace()` swaps
the file atomically.

Because the destination runtime is required to be stopped, stale:

- `db.sqlite3-wal`
- `db.sqlite3-shm`

can then be removed safely.

## IP rewrite

Phase 4 deliberately does **not** perform a global database string replacement.

Only this exact mutation is allowed:

    UPDATE hosts
    SET address = NEW_IP
    WHERE address = OLD_IP

The number of modified rows is recorded.

Afterward, Phase 4 scans every SQLite table/column for the old IP and reports
only table/column/count metadata — never row contents.

It also checks these runtime text configs for the old IP:

- Docker Compose file
- Marzban .env
- Xray JSON

By default, any residual old-IP reference blocks finalization.

## Destination verification

After rewrite:

    PRAGMA integrity_check

must still return:

    ok

When destination start is enabled, Phase 4 then starts the restored runtime and
uses the same local listener/API verification primitives from Phase 3.

Expected Xray/API ports must become reachable and the local Marzban API must
respond successfully.

## Automatic service recovery before cutover

DNS has not changed yet in Phase 4.

Therefore if finalization fails after the source was stopped, Phase 4 attempts
a limited service recovery:

1. stop destination if it partially started
2. restore destination's pre-final-sync DB backup
3. restart the source **only if it was running when Phase 4 started**
4. re-run source local listener/API health validation

This is intentionally narrower than Phase 5 rollback. It only restores the
pre-cutover service state.

A failed attempt writes a diagnostic marker under its attempt directory when
possible.

## Completion marker

Successful finalization writes:

    /root/nvl-migrations/<job-id>/FINAL_SYNC_COMPLETE

The marker records:

- job ID
- attempt ID
- old/new IP
- final DB SHA256
- rewritten host row count
- DB integrity status
- destination runtime health
- `dns_cutover_performed: false`

## CLI

Safe readiness inspection:

    python3 -m server_migration.phase4_cli \
      --source <OLD_IP> \
      --destination <NEW_IP> \
      --job-id <JOB_ID> \
      --plan-only

Actual final sync:

    python3 -m server_migration.phase4_cli \
      --source <OLD_IP> \
      --destination <NEW_IP> \
      --job-id <JOB_ID> \
      --finalize \
      --confirm FINAL-SYNC

## Expected workflow

    Phase 1  Detector / Preflight
      ->
    Phase 2  Backup / Transfer
      ->
    Phase 3  Restore / Offline validation
      ->
    Phase 4  Final Sync / IP Rewrite / Start / Verify
      ->
    Phase 5  Cloudflare Cutover / External verification / Rollback

The normal bot workflow should chain Phase 4 and Phase 5 closely so downtime
between source stop and external cutover remains minimal.
