# Failover / Migration Baseline — 2026-09-30

This document records the production failover and migration helper sources collected during the infrastructure audit.

## Source archives

### Failover archive

`nvl-failover-export-20260930.tar.gz`

SHA-256:

`48d7aabb3af4d05d75725666c24f303265ab4ea3e0568ca5e496ebe2b88381f2`

### Additional dependencies archive

`nvl-extra-deps-20260930.tar.gz`

SHA-256:

`647b2bd042ea2c15c1afc27089744fccbcfc10801fc275cc07c9ca93758c5d86`

## Imported production sources

- `core_side_failover.sh`
- `sync_bot_to_edges.sh`
- `collect_core_migration_files.sh`
- `setup_edge_datapath.sh`
- `gost_bridge_setup_fixed.sh`
- `preflight_check.sh`
- `apply_edge_fixes.sh`
- `02_recreate_ssh_users.py`
- `legacy/demote_core_to_edge.sh.bak`

All imported shell scripts passed `bash -n` during this audit. `02_recreate_ssh_users.py` passed `python3 -m py_compile`.

## Original production SHA-256

- `core_side_failover.sh`: `53002fce66e5886e2dc8a62659c17a050c3d3eaf566610ba03c175655833e517`
- `sync_bot_to_edges.sh`: `75471f77806c8302f755a47c6ff3891715322a9988fc8b84289df034116734a6`
- `collect_core_migration_files.sh`: `c8449e94f166c2c3fd3cc9f9c6a7f2b4485bb29e91e74e25ac4fce63e66962ef`
- `setup_edge_datapath.sh`: `ba7caa669a0435952561af4b10290e30fb6faba4de7824f6960e233df5b6f212`
- `gost_bridge_setup_fixed.sh`: `339e8aa88c90cdcdf8072694e5b033e457d64bd9b65f263df096234047eea8a6`
- `preflight_check.sh`: `35854408d02fa3145a64aefa3b3c0dee62d77f850931f6f56d1b23e8b8cb1cbd`
- `apply_edge_fixes.sh`: `fe8ecef7ffa6772d387508e206ed4966d8240539ee5f6be02ecf2458f70ae007`
- `02_recreate_ssh_users.py`: `7740c1e667c25cac3d1ac003df5f85837ddade1ec18b0cd9b64bee1a12972d4b`
- legacy source `demote_core_to_edge.sh.bak`: `5d8e52e9efbb3174a5ab1ed05d312683323ade4f83d8cc58402d1d0d85118596`

## Current-topology warnings

### Missing active demote helper

The running bot references `demote_core_to_edge.sh`, but no active file with that name exists on the audited Core.

The recovered backup is intentionally stored only under `legacy/`. It accepts a different argument contract and describes a direct Data-Plane architecture that does not match the currently observed Edge DNAT/WireGuard -> Core SSH termination path. It must not be restored as the active helper without a deliberate redesign and end-to-end validation.

### Management port vs customer service port

`core_side_failover.sh` probes port 22 and customer-service ports while discovering an Edge management SSH endpoint. In the current topology, a customer port on an Edge may DNAT back to Core. Therefore a successful SSH handshake on that port does not prove that the script reached the intended Edge.

This is a critical failover debt and should be fixed before relying on automated failover.

### Edge limiter dependencies

`setup_edge_datapath.sh` and `sync_bot_to_edges.sh` reference:

- `edge_ip_limiter.py`
- `edge-ip-limiter.service`

Neither file exists on the audited Core, and neither was present on the four active Edge hosts checked during the audit.

The current production topology terminates SSH sessions on Core, where `promote_edge_to_core.sh` generates the Core-side `/root/ip_limiter.py` and `ssh-limiter.service`.

Do not fabricate or rename the Core limiter as an Edge limiter.

## Secret handling

A pre-import scan found no embedded private-key blocks, Telegram/GitHub/Cloudflare token literals, or hardcoded password literals in these collected sources.

Runtime databases, environment files, SSH keys, WireGuard private keys, certificates, and other live secret material remain excluded from Git.
