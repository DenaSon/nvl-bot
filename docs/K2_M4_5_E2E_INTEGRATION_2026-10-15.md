# NVL K2 M4.5 — End-to-end staged integration and adversarial acceptance

**Date:** 2026-10-15  
**PR:** #148 (Draft, stacked on M3)  
**Baseline:** `4eff94e7753557dd4d7d958c8702141f4ef6d4cf`  
**Environment:** GitHub CI only; disposable SQLite and Unix socketpairs, no VPS/production credentials, no network mutation.

## Scope and method

`tests/test_edge_egress_k2_m45_end_to_end.py` connects the actual source modules end-to-end:

1. M4.3 Telegram `EphemeralApprovalStore` and `NonRootOperatorClient` (actor, chat, message ID and exact selected UID).
2. Real `AF_UNIX/SOCK_STREAM` framed JSON and **kernel SO_PEERCRED**, using `handle_accepted_socket` and the original `RootOperatorIPC`. No fake JSON-to-dispatch shortcut for end-to-end cases.
3. The original M4 `RootMigrationPortal` (root-side approval/expiry), M3 `run_migration_wave` per-UID selection and fresh M1 inventory.
4. The original `Existing6GGuardedExecutor` writing **actual original** `failover_operations` SQL `RUNNING/EGRESS_P3_EXECUTE_INTENT` before the simulated host boundary, then `EGRESS_P3_VERIFIED/SUCCEEDED` or `EGRESS_P3_RECOVERY_REQUIRED/RUNNING` after injected faults. No second 6G transaction/lease.
5. Original `DurableWaveCheckpoint` storing PREPARED → RUNNING → verified per-UID receipt → SUCCEEDED/HOLD; M4.4 read-only root STATUS after simulated process restarts.

The **only simulated privileged boundary** is Linux host mutation and external physical F4/PAM/WG/session acceptance. The test-only `SimulatedHostPort` asserts original 6G INTENT is persisted *before* mutation, then records synthetic events; it NEVER changes routes, DNS, PAM, WG, process UIDs or clients. CI also simulates root process identity to exercise Python authority checks without privileged runner access; a kernel peer credential is nevertheless read from a **real local AF_UNIX** socket.

## Required acceptance scenarios

| Scenario | Source acceptance |
|---|---|
| Single-UID prepare/confirm + terminal original 6G receipt | Must produce exact original 6G terminal CAS, checkpoint and read-only scoped receipt |
| Mutation exception after original 6G intent | Preserve original RUNNING, recovery phase and checkpoint HOLD after restart |
| Root crash after original 6G success but before checkpoint terminal | Display HOLD; never auto-promote, replay, or launch a second UID |
| Root IPC restart after PREPARE | Ephemeral request is lost, unconfirmed checkpoint stays PREPARED |
| Actor/chat/message mismatch or replay | Reject before mutation; peer kernel UID always checked |
| Source/F4 drift after PREPARE | Fail closed before P3/6G host operations |
| Explicit CANCEL | Consume approval without original 6G write |
| Batch before M7 | Rejected independently by root and client |
| Read-only STATUS while mutation IPC OFF | Safe restricted status path only; PREPARE still blocked |
| Secrets/ticket/nonce boundary | Never accepted as Telegram-supplied authority |
| Unknown/timeout/partial execution | Hold; do not retry or unlock original 6G |

## Limits — do not mark operationally complete

- **Source/CI green is not physical acceptance.** The live M4.2 `HostReviewedPorts` factory (real M2 first/Nth installer, original 6G callbacks, real independent F4/PAM/WG/session provider and non-root bot identity) is not deployed. Root daemon remains intentionally inert, all runtime gates default OFF and no real UID has moved.
- This is a **simulated privileged host boundary**, not an SSH/SOCKS/IPv4/DNS/NSS/IPv6 packet witness, boot/WG-loss or rescue field test. Field acceptance belongs to disposable-Core/Edge M5, with operator approval.
- No PR merge to master, production changes, fake F4 signed evidence, new root operation engine or automatic reconciliation.
- M7 approval is separately required for batch; UI/UX polish remains separate after M7.

## Completion classification

M4.5 can be **SOURCE/CODE & CI PASS** only when all exact-HEAD GitHub full Python and both Edge 3.11/3.12 matrices pass. Operational M4 and the M5 field gates remain HOLD until an independently accepted implementation and disposable-field test is complete.

**CI exact SHA/result:** enter in PR checkpoint after exact-HEAD success; never mark success based on an earlier SHA.
