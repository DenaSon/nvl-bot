# Change Server — Phase 3: Restore & Dry Run

Phase 3 consumes the verified bundle produced by Phase 2.

Its purpose is to prove that the destination can safely reconstruct the
Marzban runtime before the final database sync and DNS cutover phases.

## Two modes

### INSPECT_ONLY

This is the safest validation mode and the default CLI mode.

It:

- re-verifies SHA256SUMS on the destination
- validates bundle.json schema/job identity
- validates archive member paths against traversal/special-file attacks
- validates the Docker image archive and exact image ID
- extracts only into the migration job directory
- checks SQLite integrity from the extracted preview
- reads Xray ports from the preview
- validates the extracted Docker Compose configuration

It does **not**:

- write to /opt/marzban
- write to /var/lib/marzban
- write to /etc/letsencrypt
- load Docker images
- start/stop services
- change DNS/Cloudflare

Preview path:

    /root/nvl-migrations/<job-id>/restore-preview

This mode is specifically useful for testing against an already-running
production destination because it is isolated from runtime paths.

### RESTORE

RESTORE performs all inspection steps first, then requires a clean destination.

It blocks when:

- source/destination architecture is incompatible
- /opt/marzban already exists
- the database runtime directory already exists
- /etc/letsencrypt already exists when the bundle contains it
- an external runtime-extra target already exists
- source Xray/API ports are already in use
- destination free disk is insufficient

Only after those checks pass does it:

1. prepare Docker/Compose when missing and allowed by policy
2. validate Compose from the preview
3. load the exact Docker image archive
4. verify loaded image ID/architecture/OS
5. copy preview data into runtime paths without overwrite
6. verify restored SQLite integrity
7. verify restored Docker Compose configuration

The default RESTORE flow does **not** start Marzban.

That is intentional: the final-sync phase still needs to replace the database
with the last consistent source state and rewrite the server-specific host IP.

## Optional runtime dry run

An explicit option exists:

    --start-runtime-dry-run

It is valid only with:

    --restore

When enabled Phase 3 runs:

    docker compose up -d

then waits for configured Xray/API listeners and checks the local Marzban
/docs endpoint.

This still never changes DNS/Cloudflare.

The option is explicit because starting the cloned controller can have
side-effects with external Marzban nodes. The safer default is an offline
restore validation.

## Archive safety

Before extraction every tar.gz archive is inspected.

Phase 3 rejects:

- absolute archive members
- ../ path traversal
- character/block devices
- FIFOs
- symlinks escaping the archive root
- hard links escaping the archive root
- unexpected archive roots for config/data/Let's Encrypt

The Docker archive is separately validated and its manifest.json must contain
the expected image tag and exact image config SHA from Phase 2 metadata.

## Restore markers

RESTORE writes:

    /root/nvl-migrations/<job-id>/RESTORE_IN_PROGRESS

before copying runtime paths.

After all copies succeed it writes:

    /root/nvl-migrations/<job-id>/RESTORE_COMPLETE

and removes the in-progress marker.

If a restore fails mid-copy, the in-progress marker remains. Phase 3 does not
automatically delete partial runtime data; preserving evidence is safer than an
automatic rm -rf rollback.

## Docker preparation

On Ubuntu/Debian with apt-get, RESTORE can install:

- docker.io
- docker-compose-v2 (or docker-compose-plugin fallback)

and enable Docker.

This happens only in RESTORE mode after clean-target checks pass.

Use:

    --no-install-docker

to require Docker/Compose to already exist.

## CLI

Safe inspection of an already-transferred bundle:

    python3 -m server_migration.phase3_cli \
      --destination <NEW_IP> \
      --job-id <JOB_ID> \
      --inspect-only

Restore onto a clean destination:

    python3 -m server_migration.phase3_cli \
      --destination <NEW_IP> \
      --job-id <JOB_ID> \
      --restore

Restore and explicitly start the clone for local health checks:

    python3 -m server_migration.phase3_cli \
      --destination <NEW_IP> \
      --job-id <JOB_ID> \
      --restore \
      --start-runtime-dry-run

## Production sequence after Phase 3

Successful offline RESTORE means:

    Bundle verified
    -> Restore verified
    -> Exact image verified
    -> SQLite verified
    -> Compose verified
    -> READY FOR FINAL SYNC

Phase 4 will then handle:

- controlled source stop
- final SQLite synchronization
- server-IP rewrite
- old-IP search/verification
- destination start
- final health checks before cutover
