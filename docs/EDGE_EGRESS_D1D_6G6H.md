# D1-D1 — Protected 6G / 6H egress handoff contract

**State: offline/injected-port integration only, Draft PR #80. No live 6G/6H bot registration. No merge, no production deploy or host-network mutation.**

## Problem addressed

The existing NVL manual 6G and automatic 6H failover paths were built for legacy mode. Legacy workflows can rebuild SSH accounts on Standby, bulk-reassign ssh_accounts.host, and move the public DNS endpoint via Core during failover. Those actions are **not safe** for a Core-terminated SSH account whose Internet egress is bound to a specific Edge and required to fail closed.

The existing protected-mode setting defaults to **0**, and live legacy 6G/6H entry points are blocked when setting is 1. D1-D1 **does not remove that fence**. It adds a checked composition path for a future separately approved protected adapter.

## Delivered

- edge_egress_failover_guard.py: pure safety verifier binding fresh independent evidence to the exact persisted 6G operation ID, manual_6g/automatic_6h trigger, source/target/Core identities, and the entire immutable SSH account username+UID set. Every UID must demonstrate full-destination IPv4 policy rule, terminal blackhole, IPv6 packet blocking, DNS via selected Edge, OS SSH identity on Core, and freshly observed public IP equal to Edge. No Core fallback. Real disposable VPS boot guard attestation is mandatory.
- edge_egress_protected_6g6h.py: reuse existing run_protected_handoff saga, lock and journal through injected ports. Verify protected setting under lock; automatic 6H additionally requires independently confirmed incident under lock. Source UID proof runs before staging and at revalidation, target UID proof before mapping mutation and again after final verification.
- The guarded adapter intentionally **never delegates** legacy SSH-account reassignment or public DNS replacement. It calls named future commit_protected_mapping_cas_only (dedicated egress mapping CAS, no Unix identity migration) and assert_public_ingress_dns_unchanged (read-only).
- Guarded candidate stage/rekey and route/metadata changes have persisted recovery-hold phases in edge_egress_handoff.py. Crash during candidate staging is not stale-abortable due to timeout. On uncertain failure shared 6G remains RUNNING at EGRESS_RECOVERY_REQUIRED; no Core fallback is installed.
- Tests/test_edge_egress_protected_6g6h.py covers both triggers, unverified 6H incident, busy shared lock, incomplete UID coverage, stale/wrong IP, DNS/IPv6/blackhole bypass, unverified boot, partial staging failure, and target proof failure using in-memory mock ports. No live NVL hosts touched.

## Strict architectural boundaries

1. C3D kernel tests proved dedicated WireGuard and a synthetic UID/DNS path via simulated TLS; they did **not** prove production VM boot.
2. C3E QEMU test failed after guest reboot at SSH timeout; cause is unverified. It is manual-only/deferred. Separate disposable VPS boot evidence is **NOT AVAILABLE**. Therefore real adapters MUST report boot_gate_verified_on_disposable_vps=False and no protected 6G/6H cutover is authorized.
3. No Telegram admin action, scheduler or automatic incident monitor is registered by this PR. There is no production adapter implementing the real protected mapping CAS, packet-level guard proofs or DNS immutable check. Simulated proofs are not sufficient for activation.
4. Changing customer EGRESS is not changing SSH INGRESS. Public SSH endpoint/DNS remains unchanged during the egress-only switch; never move Core SSH identity to the new Edge or point public DNS to Core as an emergency egress fallback.
5. No global route flush, UID rule removal, blackhole removal, broad iptables reset or touch of operational wg0. A failed Edge is an outage, not permission to use Core IP.
6. Production adapter must retain the shared 6G CAS lock during stage, proof, mapping-only CAS and post-cutover verification. 6H incident IDs must be corroborated in the same transaction, not trusted just for their string prefix.

## Next release gates

- Disposable **test VPS**, with console/snapshot, proves actual reboot, SSH dependency enforcement, protected UID deny before Edge attach and deliberately broken guard with recovery.
- Implement actual protected Edge mapping registry/CAS per account without modifying ssh_accounts.host or rebuilding Unix SSH users; independent host UID/DNS/IPv6 proofs bound to 6G.
- Implement opt-in 6H incident revalidation with cooldown/debounce and same 6G lock; UI reports recovery without excess notifications.
- Rehearse real SSH and BadVPN representative traffic, Edge outage, DNS failure, rekey and scoped recovery on test hosts. No Core fallback.
- Offsite backup and restore rehearsal before one-user live canary.

**Release state:** code-level protected failover contract only. Protected runtime OFF, PR Draft, no production deploy approval.
