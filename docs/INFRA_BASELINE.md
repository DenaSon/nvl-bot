# Infrastructure Source Baseline — 2026-09-30

Imported from the production infrastructure export:

`nvl-infra-export-20260930.tar.gz`

Archive SHA-256:

`76d6118c1e719a73e7c94b0bec8f1dd4d7247c17ee756d6e42568e89191c8b59`

## Imported files

- `v2ray_engine.py`
- `setup_edge_relay.sh`
- `promote_edge_to_core.sh`
- `update_edge_endpoint.sh`
- `update_all_edges_endpoint.sh`
- `speed_optimizer.sh`
- `promote_standby_for_filtered_edge.py`

All source logic from the production export is present in the repository.

A pre-import scan found **no embedded private-key material, Telegram token literals, GitHub token literals, Cloudflare token literals, or hardcoded password literals** in this archive.

Security-sensitive operational logic is intentionally included because it is source code. Actual runtime secrets and private key files remain outside Git.

## Expected helper not present in export

The main bot references `demote_core_to_edge.sh`, but that file was not present in the uploaded infrastructure export. It still needs to be collected from production if it exists there.

## Original production file SHA-256

- `v2ray_engine.py`: `788c9eea33b55b7e808e0f9bcb488cae0a642eb3b76d373c745b023647f92466`
- `setup_edge_relay.sh`: `ce9d2936d7667ba91615130ee6d3d13391661d67651a9cc7c4c89936d3518ace`
- `promote_edge_to_core.sh`: `b76769fc52d5f0d7d107ef54f1f7ac52228bb1c264a088219779f2fc8bd638df`
- `update_edge_endpoint.sh`: `c09dfc9af12e04f05867e36612e54ea4361346f51ba729e11642666353a39cac`
- `update_all_edges_endpoint.sh`: `f33cad31357f522a95890f525b53b8fa300636ab1e6502c617cb9b67531aa7e5`
- `speed_optimizer.sh`: `8032cbc5ac3a257bcd8830ec6a6cf9a586b990f45d1759cece738fc518200302`
- `promote_standby_for_filtered_edge.py`: `820ec15c24470b10af6e809cfed23b43133e847b42aa9564b09319c7c569ee5f`

Note: GitHub text ingestion may normalize text line endings. The original `v2ray_engine.py` export used CRLF line endings; its source semantics are unchanged.

## Secret-handling policy

The repository is private, but Git history is not treated as a secret store. Runtime API tokens, passwords, SSH/WireGuard private keys, database contents, and production environment files should remain outside the repository and be injected at runtime.
