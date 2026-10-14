# NVL K2 M4.4 — Root-owned restart recovery, scoped receipts and Telegram status

**Date:** 2026-10-15  
**PR:** #148, branch `feature/k2-m4-telegram-root-portal-20261014`, parent SHA `a33c43ee1b2e40fc26dc99a0d879c0467f8a6aa3`.  
**Safety:** SOURCE-ONLY, no merge, no installed service, no live traffic/UID changes. Root execution flags and batch remain OFF.

## Implemented

- `edge_egress_k2_m44_recovery.py`: **read-only root-only** checkpoint recovery after process restart from original Core SQLite (`k2_m4_wave_checkpoints` + `failover_operations`). Reads exact mode/users/Edge/actor/chat with current root-level admin authorization, bounded payload, original 6G RUNNING count, and independently inspects original P3 terminal rows for each saved UID operation. Does NOT save passwords, raw secrets, HMAC, approval nonces or packet proof.
- A stored `RUNNING` becomes `UNKNOWN_INFLIGHT` even if original 6G appears idle. A stored `HOLD` stays `HOLD`. A stored `SUCCEEDED` is shown only as `RECEIPTS_RECORDED` when each recorded 6G terminal operation's **action, Edge, source/target host and canonical SHA256 scope digest** match the selected Linux username/UID. Missing or forged original-6G scope => `HOLD`, not customer success. The persisted checkpoint lacks the original raw 6G nonce, so this is explicitly NOT a cryptographic replay-proof 6G commit attestation; independently accepted F4 packet, SSH/SOCKS and no-leak verification is still required.
- `edge_egress_k2_m4_checkpoint.py`: new `BEGIN IMMEDIATE` read-before-insert/start gate: **any** existing global `RUNNING` or `HOLD` checkpoint prevents a new PREPARE or BEGIN, including across restart and even if the original 6G appears idle. No automatic release, retry, cleanup, replay, resurrect or change to the original 6G ledger. Human-reviewed reconciliation is a separate future release/authorization and **not** a new Telegram mutation here.
- `edge_egress_k2_m4_ipc.py`: typed `STATUS` action behind separate `M44_ROOT_STATUS_ENABLED=False` flag, original kernel SO_PEERCRED UID/root service requirements, exact actor/chat/selection and root-held database. STATUS performs SELECTs only and can be enabled for future read-only deployment independently of mutating `M4_UNIX_IPC_ENABLED`.
- `edge_egress_k2_m43_client.py`: new strictly validated STATUS response with independent `M44_TELEGRAM_STATUS_ENABLED=False` and original non-root bot restriction. Malformed response, wrong target, unauthorized actor, lost socket, changed UID order => HOLD with no fallback.
- `edge_egress_k2_m4_status.py` and existing `bot_final_v49-2.py`: admin-only `📋 وضعیت` reads root checkpoint via STATUS **only when explicitly enabled**. When disabled, legacy read-only runtime status remains unchanged and is not represented as root checkpoint evidence. If root STATUS is enabled but unavailable, no fallback to a misleading 'NOT_STARTED'; show conservative status unknown. Two-column, short Persian UI, no implementation jargon or credentials shown.
- Root source pin manifest now covers new critical recovery/status/client/bot files. Full and stage safety tests added for restart, scoped receipt/forgery, missing tables, root role access, stale source, UI-safe presentation, root-only mode, and permanent HOLD.

## Operational decision boundaries

| State | Meaning | Allowed operator action |
|---|---|---|
| NO_CHECKPOINT | No record for the exact actor/chat/Edge/users (not proof of no running global wave) | View status only |
| PREPARED / EXPIRED | Prepared scope / expired approval | Review and request a new scoped approval **only after all other root gates clear** |
| UNKNOWN_INFLIGHT | Saved RUNNING or crashed process; old per-UID receipts may exist | **HOLD**, inspect original 6G + rescue/physical evidence, no retry |
| HOLD | Failed or uncertain progress or mismatched original 6G evidence | **HOLD**, independent manual reconciliation |
| RECEIPTS_RECORDED | Saved final per-UID original 6G scoped receipts agree | Not equivalent to verified real IP/SOCKS/DNS/IPv6 client routing; physical acceptance separately required |

Only the M4.4 read-only status path is newly added. No operational "unfreeze/reconcile" command exists: original 6G is never mutated here. A new operation is **blocked** while any unresolved `RUNNING`/`HOLD` wave is present, not automatically cleared when a service comes back.

**Still HOLD:** Trusted M4.2 production root callbacks, non-root bot split (current bot root), off-host physically validated signing/service, root-daemon entrypoint (still returns 78), independently witnessed F4, backup/reboot/WG loss/route/isolation physical acceptance and M4.5 disposable end-to-end. Legacy root-only local status is informational. Batch remains locked until M7.

**Acceptance definition:** exact-head GitHub full Python and Edge stage-only tests on Python 3.11/3.12 PASS is **SOURCE + CI**, not deployed, not physical, not PR merged. Keep PR #148 Draft and master/prod unchanged.
