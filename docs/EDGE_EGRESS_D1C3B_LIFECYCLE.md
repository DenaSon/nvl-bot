# D1-C3B — 6G-locked disposable UID canary lifecycle

**Status:** Implemented in Draft PR #80, default-off and not registered in NVL bot runtime.
**No production deployment, merge, restart or live route change performed by this PR.**

## Background / actual lab proof (2026-10-11)

An operator successfully activated dedicated Core/Standby Edge shadow WireGuard, verified that a Core namespace HTTP request exited as the Standby public IPv4, and rolled back. Next, a test using account nvl0557 (UID 1644) routed just destination 1.1.1.1 through the Edge and observed IP 216.126.229.12. The test returned to the previous route and removed the temporary tunnel.

This proves one destination/UID and a temporary kernel path. It does **not** prove full IPv4, ordinary DNS, IPv6 leak protection, reboot persistence or safe automated failover.

## Delivered

- edge_egress_uid_lifecycle.py: explicit short-lived canary saga, acquires existing persisted Phase 6G lock, records each phase before mutation, revalidates source+UID under lock, arms guard first, starts shadow, attaches Edge route, proves exact Edge IP, verifies the installed IPv6/DNS guard, freezes first and stops shadow, then restores an **explicitly unprotected** canary. Only a fully restored canary marks the shared journal SUCCEEDED.
- If a mutation might have started and anything fails (including restoration), the saga requests a scoped freeze, attempts stopping shadow, and keeps the shared 6G operation RUNNING under EGRESS_UID_RECOVERY_REQUIRED. The result is not READY.
- edge_egress_uid_6g_bridge.py: opt-in adapter reusing Existing6GPreparationAdapter's real Phase 6G lock, SQLite source/target/default/DNS and active account snapshot invariants. Checks the named SSH account, stored assigned host, live OS username-to-UID binding and that the global protected setting is OFF. Journals through the existing update callback's require_running CAS. No new independent lock or schema.
- edge_egress_uid_kernel.py: opt-in Core-local Linux command port, with exact argv (never shell), preflight ownership/collision checks, root-only crash-recovery marker fsync'd *before* kernel changes, UID-specific IPv6/DNS guard + terminal table blackhole before UID selector, veth next-hop, independent HTTPS IP check, scoped freeze and guarded reversal only after shadow resources are stopped.
- edge_egress_handoff.py: registration of all D1-C3B mutating phases in the existing 6G stale-lock recovery-hold predicate so an expired RUNNING lock is not silently released.
- Tests: test_edge_egress_uid_lifecycle.py, test_edge_egress_uid_6g_bridge.py and test_edge_egress_uid_kernel.py. These test callback ordering, real-shaped SQLite state, UID binding, default deny, simulated errors and hold behavior.

## Non-negotiable limitations

1. **This is not a persistent protected-customer service.** The Linux host port writes a root-only recovery *marker*, but does not install boot-order systemd guards, restore blackhole/rule/firewall state automatically after a Core reboot, or implement a persistent protected mode. Do not convert the temporary canary into a long-lived customer route.
2. **DNS leak proof remains outstanding.** Current check confirms the direct-local-port-53 guard exists, not that NSS, systemd-resolved D-Bus, local proxies or app-level DNS remain on Edge. Normal hostnames may not resolve when localhost stub is blocked.
3. **IPv6 requires an independent packet-level test.** Current check confirms ip6tables rule presence, not that every customer process and transport is protected.
4. **Failure means recovery hold, not rollback to Core.** Even a stopped or partially stopped shadow can leave the UID selector/blackhole and a stale marker. Never delete recovery markers, run global route flush or release the 6G lock by timeout. Manually inspect journal, kernel state, exact UID ownership and peer stage first.
5. **No live shadow port is installed by default.** CanaryShadowPort must be separately supplied; the existing pinned SSH transport is not silently activated. No Telegram handler, Failover automation, DNS, accounts, or production bot functionality has been changed.
6. **The canary restores unprotected mode intentionally.** It is forbidden to invoke against an already protected account. The production path must NEVER remove a protected UID guard upon Edge failure.

## Next: D1-C3C / release gating

- Build and rehearse a durable boot-time fail-closed guard and per-account protected DNS; make startup of protected processes conditional on guard restoration.
- Implement kernel crash reconciliation and a reviewed operator action that recovers the 6G RUNNING journal after comparing all affected routes, firewall rules and stage ownership.
- Provide an explicit ShadowPort backed by pinned SSH with verified Edge/Core lifecycle, actual restart/rekey health and independent IPv4/IPv6/DNS tests on isolated hosts.
- Test full-user Internet (not just one destination), Edge loss, Core reboot, multi-user route table ownership, IPv6 bypass attempts, DNS leak and failover to other Edge while remaining fail closed.
- Integrate into the unified Phase 6G/6H handoff only after data plane and rollback are proven.

**Production gate:** Do NOT merge/deploy PR #80 or enable global edge_egress_protected_mode. Do not execute the new local host port against the current live Core/Standby; operator work here was already enough to prove the disposable route. The next tests belong on isolated systems or within a specifically approved and recoverable canary window.
