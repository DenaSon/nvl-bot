# NVL K2 M4.1 — Root Worker source checkpoint

**Date:** 2026-10-15  
**Branch:** `feature/k2-m4-telegram-root-portal-20261014` — stacked PR #148; never merge to auto-deploying `master` as a side effect.  
**Scope:** Source-only root AF_UNIX daemon host, release sealing and IPC framing. **Not a production release, F4 acceptance or real customer transfer.**

## Implemented in M4.1

- `edge_egress_k2_m4_root_worker.py`: serial AF_UNIX socket listener; exactly one request per accepted connection; close/error handling; intentionally no Python-shell/OS command dispatcher; reused existing `RootOperatorIPC`, original M3/P3/6G.
- Root-only release manifest `/etc/nvl-egress/k2-m4/release.json` requires an exact reviewed commit SHA and SHA256 fingerprints for **every** security-sensitive source listed in `PINNED_SOURCE_FILES`, including the worker entrypoint. Mismatches fail closed; manifest cannot be supplied from Telegram.
- Root-only `/etc/nvl-egress/k2-m4/root-hmac.key` requires regular non-symlink file, owner root, mode 0600, minimum 32 bytes. The Worker verifies the Root Portal signing secret comes from this exact file. No root key or hash is echoed across IPC or stored in Telegram.
- Runtime directory is pinned to `/run/nvl-k2-m4`, root-owned with exact 0750 and an explicitly reviewed IPC group; socket `operator.sock` root/group-owned 0660. No stale socket is silently removed. The kernel's `SO_PEERCRED` validates one exact **non-root** bot UID before a request is read.
- `edge_egress_k2_m4_ipc.py` now reads **newline-terminated** bounded 4 KiB request frames with an overall five-second deadline (SOCK_STREAM can split/coalesce writes). Oversized, incomplete, duplicate and multi-request frames HOLD. Server returns only typed JSON; no arbitrary command transport.
- `tests/test_edge_egress_k2_m4_root_worker.py`: integrity/permissions, missing or forged digest, symlink, wrong socket parent/group, stale socket and default-off gates. Existing IPC tests include negative framing/replay and kernel peer checks.
- `ops/k2_m4_root_daemon.py` and `systemd/nvl-k2-m4-root-worker.service.example`: deliberately inert entrypoint and **non-installing** unit example. Neither a running daemon nor a root service installation occurs from this PR.

## Non-negotiable release boundaries

All previous gates remain disabled in source: `M4_ROOT_WORKER_ENABLED=False`, `M4_UNIX_IPC_ENABLED=False`, `M4_ROOT_PORTAL_ENABLED=False`, `M4_CHECKPOINT_RELEASE_ENABLED=False`, original M2/M3/P3 flags OFF. No feature flag, systemd unit, secret, DB, PAM/SSH, WireGuard, iptables/ip rule, DNS, Cloudflare or current customer is changed.

**Current bot runbook example still uses `User=root`.** The M4.1 Worker **requires a separate non-root bot UID**: production cannot connect as root even with a group-writable socket. Safely moving the bot to a non-root service account, identifying its required file/database access, ensuring systemd sandbox compatibility, and independently checking its compatibility with existing SSH/Edge operations belong to a reviewed M4.2/M5 deployment plan—not a blind `User=` edit.

The M4.1 entrypoint deliberately returns 78, regardless of environment flags, because there is **no reviewed live root-port factory**. Tests injecting mock portals do not certify real worker safety. Manifest, secret, group and service deployment must later be done by an **approved automated installer**, not routine manual CLI. The sample unit has no `[Install]` section.

## Remaining chain (before M4 is functionally DONE)

1. **M4.2** bind real root-side factories: original 6G Executor/receipt, independent current SSH session and trusted PAM/WG ingress observer, actual reviewed F4/packet/boot evidence, exact actor/chat role verification, M2 first/Nth UID bootstrap and secure operational bot identity. Keep all deny-first tests.
2. **M4.3** connect existing admin Telegram callbacks to a typed non-root IPC client; PREPARE shows pinned scope and expiry; CONFIRM requires a separate authorized tap; CANCEL is no-execution. No ticket/HMAC/credential in persistent Telegram state.
3. **M4.4** read the root-owned durable checkpoint after restart, reconcile `UNKNOWN_INFLIGHT` against original 6G evidence, surface per-UID HOLD/cancel/progress. Never auto-replay or release 6G.
4. **M4.5/M5** independently test disposable physical Core/Edge F4, actual SSH/SOCKS, IPv4/DNS/NSS/IPv6 no-Core-leak, crash/WG-loss/boot, snapshots/rescue, non-selected neighbours. Only after M5 may M6 one-user canary be authorized. Batch stays OFF to M7.

## CI and acceptance

The GitHub branch must pass **exact-head** full Python checks and Edge staging checks (both Python 3.11/3.12). This certifies source tests only. Separate fields to track: **source implemented / CI passed / merged / deployed / physical acceptance**. No step in this PR authorizes merge or Production changes.

**M4.1 DONE means source packaging and fault-injection CI passed; operational M4 is NOT DONE.**
