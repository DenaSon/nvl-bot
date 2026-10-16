# NVL K2 M4.3 — Telegram two-step transfer and non-root IPC client

**Scope:** Source-only / draft PR #148 / no merge to master / no Production modification.  
**Baseline:** M4.2 exact verified SHA `85d813aa7fa3c9d5b2c352c8f15a64296a6e3012`.  
**Status:** Await exact-head GitHub Actions. No physical F4 or customer migration accepted.

## Implemented

1. `edge_egress_k2_m43_client.py`: isolated non-root AF_UNIX client. Fixed `/run/nvl-k2-m4/operator.sock`, validates root-owned socket and runtime directory, verifies server SO_PEERCRED root identity, bounded JSON newline-terminated frames and strict typed PREPARE/CONFIRM/CANCEL results. No arbitrary commands or injected secrets; fail-closed on malformed responses, server timeout, wrong Edge or UID count. `M43_TELEGRAM_EXECUTION_ENABLED=False` by default. A root-running bot is explicitly denied.
2. `edge_egress_k2_m43_workflow.py`: in-memory **not-persisted** operator confirmation. PREPARE result stores an opaque root-issued request ID only in the process-local `EphemeralApprovalStore`, never in `context.user_data`, PicklePersistence, Telegram callback strings, databases or logs. Approval bound to actor, chat, message ID, exact immutable selected names and target Edge, and expires in 90 seconds. One-shot local consume BEFORE CONFIRM/CANCEL network I/O; no replay after socket failure. Duplicate in-flight prepare denied. Navigation invalidates stale outstanding prepare using per-actor generation.
3. `bot_final_v49-2.py` uses the **existing** authenticated admin `hpeg_m4_*` callback handler, not a second bot. Read-only selection/preview now offers an approval-request button. Separate signed root PREPARE creates a short confirmation page with two tap actions: **✅ تأیید انتقال / ❌ انصراف**. The bot passes only actor/chat and selected users (PREPARE), then opaque request ID + actor/chat for CONFIRM/CANCEL. Admin authorization is rechecked on every callback and once again in original root portal. No P3/6G host port imported in the bot. Any unknown result becomes HOLD and the bot never auto-retries.
4. `edge_egress_k2_m4_ipc.py`: **independent Root batch gate** `M4_BATCH_RELEASE_ENABLED=False`. M4.3 does not permit batch PREPARE even if an operator changes the non-root client. Separate `M43_BATCH_EXECUTION_ENABLED=False` in the client. Batch release requires later M7 acceptance.
5. Tests cover wrong actor/chat/message, stale/expired request, duplicate callbacks, no persistent approval, concurrent PREPARE invalidation, untrusted socket and fake response frames, root/non-root boundaries and disabled batch.

## Critical release blockers

M4.3 source wiring does **not** authorize execution. All existing Root/IPC/Portal/Checkpoint/M2/M3/P3 flags remain OFF and M43 flag defaults OFF. `ops/k2_m4_root_daemon.py` still deliberately exits 78. Production `nvlbot` currently runs under root; M43 client explicitly blocks root for privilege separation.

M4.2 physical operator acceptance remains incomplete: actual guarded host factories and original-6G acquire/journal wiring, separate bot non-root identity, independent off-host signed session/F4 witness and disposable real SSH/SOCKS/IPv4/DNS/NSS/IPv6/no-Core-leak/boot/WG-loss tests. Do not toggle release gates or deploy/merge merely because CI passes.

## Next: M4.4 and M4.5

- M4.4 should present the root-owned durable checkpoint after restart and fail-closed UNKNOWN_INFLIGHT reconciliation from original 6G, with no automatic repeat or unlock.
- M4.5 should exercise full IPC/Telegram integration in disposable end-to-end environment and independently prove fail-safe behavior before any authorised single-user canary.
- M7 alone can allow batch after physical/capacity acceptance.

## Security decision

An ambiguous socket timeout after CONFIRM **must not** be displayed as a successful rollback; pending confirmation is consumed locally and the operator receives a conservative HOLD and read-only status guidance. Client never sends a second CONFIRM to compensate for the lost response. Root operation journal/checkpoint remains authoritative.
