# NVL K2 — Package A backend hardening (2026-10-15)

**Scope:** source-level, draft PR #148 stacked on M1/M2/M3. No merge to master, no deployment, no UID move. Exact-head CI must pass before accepting this checkpoint.

## Implementation

1. **Original Phase 6G SQL now shared rather than duplicated.**
   `edge_egress_k2_a_6g_shared.py` contains the original `failover_operations` `BEGIN IMMEDIATE` lease and CAS journal SQL. The legacy bot's `_db_acquire_failover_lock` and `_db_update_failover_operation` delegate to this SAME implementation. Legacy retains its existing timeout/stale-lock behavior; protected recovery-phase records remain fenced. The new **`Original6GRootCallbacks`** acquires through exactly this module with `allow_legacy_stale_recovery=False`: any existing RUNNING original-6G lock (even a stale legacy one) blocks the K2 root attempt. No second lease table or hidden rollback.
2. **Reviewed root composition.**
   `edge_egress_k2_a_root_assembly.py` provides an explicit `assemble_reviewed_root` connecting `HostReviewedPorts`, the existing `RootM42Bindings`, original `DurableWaveCheckpoint`, `RootOperatorIPC` and `RootWorkerService`. Composition refuses arbitrary alternative 6G callbacks and any unpinned unsigned evidence/ingress provider. The assembly flag is source-default `False` and it NEVER starts a listener. All original M2/M3/P3/IPC and RootWorker gates remain separate and OFF.
3. **Non-root service identity fail-closed review.**
   `assert_nonroot_bot_identity` cross-checks the active `nvlbot.service` `User`, `MainPID`, `DynamicUser`, resolved UID, Unix socket group membership, and `/proc/PID/status` real/effective/saved/fs UIDs, then rejects a changed systemd unit/PID. It is read-only; no `setuid`, service restart, `sudo`, group or file changes. Current Production is known to run as root, so this check is expected to HOLD until an independently reviewed privilege split.
4. **Signed evidence byte binding.**
   `edge_egress_k2_m42_evidence.py` now verifies exactly the raw report bytes it later parses, feeding them to a fixed OpenSSL detached signature check on stdin, with root-only signature/pubkey checks before and after. The M42 P3 evidence digest binds the *complete* signed report (accounts, exact check set, scope, validity), rather than the generation/time metadata alone. The fixed root source manifest hashes include the new assembly and 6G shared modules plus modified original bot.
5. New offline tests enforce both root/legacy lock behavior, CAS, nonroot systemd+kernel UID checks, rejected alternative 6G factories, signed report snapshot and evidence digest drift.

## Remaining source/operational barriers (not represented as completed)

- **Root daemon still intentionally inert** (`ops/k2_m4_root_daemon.py` returns 78): the real installed root M2 first/Nth `RootFilePort`, `GuardedProtectedUIDPort`, live role authority, immutable file/policy source, and scoped Core database provider need vetted concrete on-host composition. The new assembly requires *these* providers and never invents them.
- **Do not change the entire existing legacy bot to Non-root blindly.** Its many existing user-management SSH/OS/root tasks must first be migrated behind separately authorized root ports or audited with a safe service split; the bot identity check intentionally refuses the current root process. No second Telegram polling process is allowed.
- **Independent off-host F4/PAM/session/packet witness** still needs a deployed signer and independently reviewed probe methodology; report validation proves provenance, not that observed customer traffic truly followed the claimed path. Physical test needs real SSH/SOCKS IPv4, DNS UDP/TCP, NSS, IPv6 leak, session counts, loss of WG, reboot, isolation, console rescue.
- **Mixed Legacy `protected_mode=0`:** cross-Edge `UID_ATTACH` remains HOLD; the only permitted route is independently attested same-ingress enrollment (`UID_ENROLL_SOURCE`) after an actually observed target re-ingress. No implicit host-field rewrite, mass migration, false idle or mode flip.
- **Production:** global settings, `wg0`, the default relay, customers and release gates remain unchanged. M5 disposable field acceptance and an explicitly approved release are still mandatory.

## Completion categories

| Item | Source | CI | Field/deployed |
|---|---|---|---|
| Original 6G shared adapter | committed | pending exact HEAD | not deployed |
| M4A Root assembly & nonroot preflight | committed | pending exact HEAD | blocked by actual root bot |
| Signed witness snapshot and stronger P3 pin | committed | pending exact HEAD | offhost signer not deployed |
| Concrete real M2/P3 Linux host factory and physical proof | partial adapters | synthetic only | HOLD |
| Cross-Edge mixed Legacy migration | denied by design | denied | HOLD |

**No claim of Package A fully operationally completed.** Treat it as code hardening with exact unresolved dependencies, not a finished production change.
