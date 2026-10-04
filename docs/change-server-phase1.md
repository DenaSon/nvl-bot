# Change Server — Phase 1: Detector & Preflight

Phase 1 is the read-only foundation for NVL's future **Change Server** workflow.

## Scope

The operator supplies only connection information for:

- source Marzban server
- destination server
- SSH port/user/password

Phase 1 connects to both endpoints and builds a structured report. It does **not**
copy data, install packages, stop services, start containers, change Marzban,
change DNS/Cloudflare, edit firewall rules, or write to either server.

## Source checks

The detector currently verifies:

- SSH connectivity and root privileges
- Ubuntu/Debian and supported architecture
- RAM and free root-disk metadata
- Docker + Docker Compose
- Marzban compose location
- Marzban .env location without dumping secrets
- SQLite database location + `PRAGMA integrity_check`
- Xray JSON location and inbound ports
- configured Uvicorn API port
- configured TLS certificate/key existence
- compose image names and locally inspectable image IDs
- currently listening ports
- required migration tools
- estimated Marzban/config/certificate payload size

A source with a missing/corrupt database, missing Marzban compose, missing Xray
config, missing local compose image, unsupported OS/architecture, or no root
access is blocked.

## Destination checks

The destination is validated for:

- SSH/root access
- supported OS/architecture
- required utilities
- minimum memory
- enough free disk for source payload + reserve/headroom
- conflicts on source Xray/API ports
- existing Marzban runtime

By default an existing Marzban installation on the destination blocks migration.
That behavior can only be relaxed through an explicit `PreflightPolicy`.

Docker is allowed to be absent on a clean destination. Phase 1 reports a warning
because Docker installation belongs to Phase 2.

## Read-only guard

All remote detector commands pass through `assert_read_only_command()`. The
module rejects known mutation families such as:

- rm/mv/cp
- apt/apt-get/install
- systemctl start/stop/restart
- Docker compose start/stop/up/down
- Docker removal
- sed -i
- direct sqlite3 mutation commands

The regression suite also checks the static command inventory.

## Password handling

`ServerCredentials.password` is excluded from dataclass repr/comparison.
Credentials are never put into `ServerFacts` or serialized into the
`MigrationPreflightReport`.

The CLI prompts with `getpass`; it does not accept a password argument.

## Manual dry run

From the NVL host:

```bash
python3 -m server_migration.cli \
  --source 107.189.22.94 \
  --destination 107.189.22.229
```

The command prompts for the two SSH passwords and prints JSON.

Exit status:

- `0`: ready for Phase 2
- `2`: preflight blocked

## Architecture boundary

Telegram UI is intentionally not coupled to this package in Phase 1.

Future flow:

```text
Telegram handler
    -> MigrationService
        -> Phase 1 Detector/Preflight
        -> Phase 2 Backup/Transfer
        -> Phase 3 Restore/Dry Run
        -> Phase 4 Final Sync
        -> Phase 5 Cutover/Rollback
```

This keeps the migration engine reusable from Telegram, CLI, API, or a future
web control plane.
