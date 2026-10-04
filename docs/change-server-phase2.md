# Change Server — Phase 2: Backup & Transfer

Phase 2 turns a successful Phase 1 preflight into a verified migration bundle
without stopping Marzban/Xray and without touching destination runtime paths.

## Goal

Automate the manual sequence that was proven during the production migration:

1. create a live-safe SQLite snapshot
2. package Marzban config/runtime data/certificates
3. export the exact local Docker image(s)
4. calculate SHA-256 checksums on source
5. relay files Source -> NVL -> Destination
6. verify checksums again on NVL and on Destination

Phase 2 ends with a verified bundle staged on the destination. It does **not**
restore it.

## Source staging layout

Each run gets a unique job ID:

    /root/nvl-migrations/<job-id>/
        bundle/
            bundle.json
            marzban-config.tar.gz
            marzban-data-snapshot.tar.gz
            docker-images.tar.gz
            etc-letsencrypt.tar.gz      # optional
            runtime-extras.tar.gz       # optional
            SHA256SUMS
        snapshot/                       # temporary; removed after packaging

A pre-existing job directory is never overwritten.

## Live SQLite snapshot

The source service remains running.

The database is copied with Python's sqlite3 Connection.backup() API:

    source DB -> isolated snapshot DB

Both source and snapshot databases must return:

    PRAGMA integrity_check = ok

The live database, WAL, and SHM files are excluded from the generic data copy,
so the resulting archive contains only the consistent backup database.

## What is included

### Marzban configuration

The detected Marzban directory, for example:

    /opt/marzban

is archived with its relative root preserved. Backup directories named
"backup" or "backups" inside that tree are excluded to avoid recursive growth.

### Runtime data

The directory containing the detected SQLite database is snapshotted, typically:

    /var/lib/marzban

This includes Xray config, certificates, assets, and other runtime files.

### TLS / Let's Encrypt

If /etc/letsencrypt exists, it is included as a separate optional archive.

If Xray/TLS files live outside the main Marzban data directory, Phase 2 adds a
runtime-extras archive so those detected files are not lost.

### Docker images

Every image referenced by the detected compose file must already be locally
inspectable on the source. Phase 2 exports the exact image(s) using docker save
and compresses the result.

This preserves custom images such as:

    nvl/marzban:xray-26.6.1-compat

instead of assuming the image can be pulled again later.

## Verification chain

The same artifact set is verified three times:

    Source SHA256
        ->
    NVL local SHA256
        ->
    Destination SHA256

The destination receives SHA256SUMS last, after all artifacts are uploaded.
Then the destination independently runs:

    sha256sum -c SHA256SUMS

A mismatch at any hop blocks the workflow.

## NVL-local staging

Default:

    /var/lib/nvl/migrations/<job-id>/bundle

Directories are mode 0700 and files are mode 0600 because archives can contain
.env files and private certificates.

The engine checks available local disk before downloading the bundle.

## Destination staging

Default:

    /root/nvl-migrations/<job-id>/incoming

Phase 2 never writes to:

    /opt/marzban
    /var/lib/marzban
    /etc/letsencrypt

on the destination.

That is deliberately reserved for Phase 3 restore/dry-run.

## Runtime safety boundary

Phase 2 does not execute:

- docker compose stop/start/up/down
- systemctl stop/start/restart
- reboot/shutdown
- UFW/iptables/nft changes
- DNS or Cloudflare changes
- Marzban runtime restore

The source may be fully live while the bundle is created.

## Strict preflight

Normal execution requires:

    preflight.ready == true

For controlled development testing only, the CLI can allow transfer-only
staging when the **only** blockers are:

- DEST_CLEAN
- DEST_PORTS

This does not bypass source/database/SSH/OS/disk/same-server safety failures,
and it still writes only into the isolated migration staging directory.

## CLI

Strict production-style run:

    python3 -m server_migration.phase2_cli \
      --source <OLD_IP> \
      --destination <NEW_IP>

The two SSH passwords are collected with getpass and are never serialized.

Controlled staging test against an already-running destination:

    python3 -m server_migration.phase2_cli \
      --source <OLD_IP> \
      --destination <NEW_IP> \
      --allow-existing-destination-staging

The latter is useful for validating Phase 2 against the already-migrated NVL
servers without overwriting production Marzban.

## Exit codes

- 0: bundle built, relayed, and verified
- 2: blocked by strict Phase 1 preflight
- 3: Phase 2 backup/transfer failure

## Output boundary

At successful completion Phase 2 returns:

- job ID
- source bundle directory
- NVL local bundle directory
- destination incoming directory
- artifact names/sizes/SHA-256
- source/local/destination verification flags

No SSH password is included in any report.

## Next phase

Phase 3 consumes the staged bundle and performs:

- destination Docker preparation
- image load
- config/data/certificate restore
- compose validation
- destination dry run
- direct API/Xray health validation before any DNS cutover
