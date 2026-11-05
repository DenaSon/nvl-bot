# Marzban Node — Pinned Xray Core Installation (2026-11-05)

## Scope and rollout

This change applies to **new, disposable Node installations via the NVL bot Phase 7 wizard**. It does not auto-upgrade Marzban Master or any existing node, and it is **not a production deployment**. Frankfurt (`45.61.176.221`) and Amsterdam (`107.189.15.195`) are intentionally untouched. First live validation is reserved for a **separate fresh VPS**.

## Motivation

The bot previously installed `gozargah/marzban-node:latest` without controlling Xray Core. The nodes were running Xray `25.3.6`, despite Master and the tested Windows client using `26.6.1`. In the controlled A/B comparison, Xray client 25.3.6 successfully connected to Frankfurt (HTTP 200), while client 26.6.1 with the same REALITY configuration failed (connection reset). This is an **observed compatibility failure**, not proof of which upstream change caused it.

## Installation contract

- Bot-side default: `NVL_MARZBAN_NODE_XRAY_VERSION=26.6.1`, override with an explicit stable numeric `MAJOR.MINOR.PATCH` value only.
- Supported CPU architectures: `x86_64`/`amd64` and `aarch64`/`arm64`. Unsupported architectures fail before installation.
- Download the versioned Xray-core ZIP and official `.dgst` SHA256 sidecar over HTTPS from `XTLS/Xray-core`. Verify digest, extract `xray`, verify the executable reports the requested version. The sidecar is integrity protection; stronger independent integrity pinning can be added later.
- Store the executable at `/var/lib/marzban-node/xray-core/xray-v<VERSION>`. Do not overwrite the bundled `/usr/local/bin/xray`.
- Compose config points `XRAY_EXECUTABLE_PATH` to the versioned executable; `/var/lib/marzban-node` is already mounted in the container.
- Validate Compose and verify Xray version *from inside* `marzban-node` after container start; only then report remote-install success.
- Pre-existing running NVL-managed nodes are **refused** by the Phase 7 installer. Interrupted installs without a running Node may retry.
- Credentials remain short-lived in-memory and are scrubbed on both success and failure.

## Test matrix

1. Python unit tests: `python -m unittest tests.test_marzban_node_xray_core tests.test_marzban_node_install -v`.
2. Simulated failures: invalid pinned version, unsupported arch, download/digest stage failure, runtime Xray mismatch, attempt to reinstall running node.
3. Disposable VPS: complete Phase 6 SSH host-key preflight, run Phase 7, confirm reported core `26.6.1` and the pinned executable path.
4. Check `docker exec marzban-node /var/lib/marzban-node/xray-core/xray-v26.6.1 version`; check Node Connected in Marzban and listener ports after Master sync.
5. Perform real VLESS REALITY traffic tests with **both** Xray 25.3.6 and 26.6.1 clients and regression tests for Shadowsocks/Trojan. Pass conditions: successful REALITY handshake and egress, healthy other protocols, no regression.
6. Confirm Phase 7 cannot silently alter an existing running node.

## Failure / rollback

On a new VPS, a failure before container creation leaves only NVL-owned staging files and the marker; the bot reports the failing stage and supports a guarded retry. The download staging directory is cleaned by a shell trap. If a new test Node fails after container start, stop its trial and review its logs before retrying; **do not automate cleanup of an existing Marzban Node record or VPS**.

The old bundled Xray file is not deleted. To roll back a *new disposable test node* after checking its current Compose and volumes, change `XRAY_EXECUTABLE_PATH` to the original bundled path (or a known-good versioned binary) and recreate only that test node's container. Existing production nodes have not changed and require no rollback.

## Operational gates

- Source PR + CI completion is not a live bot deployment.
- No change to existing nodes, certificates, users, inbounds or Host mappings.
- No VPS reinstall, automatic Node deletion, or live service restart in this PR.
- A separate, approved production code-only deployment of the bot is required before its Phase 7 wizard can provision a new VPS with this behavior.
