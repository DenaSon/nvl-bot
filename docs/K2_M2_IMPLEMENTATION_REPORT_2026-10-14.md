# K2 M2 — Shared Protected Infrastructure: source package A progress and remaining gates

**Date:** 2026-10-14. **State:** M2 IN PROGRESS, not a completed production-ready phase. Stacked source feature branch `feature/k2-m2-multiuid-guard-20261014`, based on M1 PR #145 head `1eafec8a90ac8bc44d67b85fdfa12b585fd7b78a`. M1 and docs roadmap PR #144 are open/unmerged; parent chain must be reviewed before integration. No SSH, Linux, DB, routes, PAM or production changes made.

## Before → after this M2 increment

| Area | Before | After (source only) |
| --- | --- | --- |
| Multi-UID roster | `ops/k2_p3_guard_installer.py` explicitly rejects **any second UID** because root-owned roster must not be overwritten | `ops/k2_m2_guard_append.py` plans and guards **second→Nth** UID append, retaining exact existing root manifest digests and preserving existing V1 roster format. One reviewed append per original 6G P3 intent; M3 adds safe waves |
| Collision/ownership | V1 detects duplicate UID and cross-edge table conflicts; installer bootstrap is only first UID | Additional exact Linux username/UID, DNS port, UID policy priority, shared-Edge F3 specification, unchanged old guard, root-owner and PAM digest checks. Host preview change or partial stage → HOLD |
| Install ordering | One UID bootstrap creates roster before PAM last | For subsequent UIDs, globally installed PAM hook is NOT rewritten; new deny-first guard and isolated DNS units are staged/verified BEFORE atomic root-only roster CAS. Failure leaves HOLD/fence; no clearing guards/old roster, global ssh.service restart or wg0 changes |
| Trusted source | M1 requires an injectable recent `LiveIngressWitness` but has no concrete root observer | `edge_egress_k2_m2_ingress_observer.py`: read-only root/PAM account-phase witness, bound to PAM_USER and real PAM_RHOST + root-owned ingress registry + `wg0 allowed-ips` exact /32 key, rejecting spoofed/ambiguous/overlapping peers. No default/source historical-host fallback |
| Safety tests | M1 19 tests and full suite PASS | New fake-root/offline tests for roster append 2→N, collision, 6G loss, partial install, PAM preservation, F4/rescue hold, canonical roster drift, trusted PAM/peer identity and no host write. Actual packet/boot tests NOT yet done |

## New source files

- `ops/k2_m2_guard_append.py`: `plan_next_uid`, immutable `MultiUIDAppendPlan`, `CASRootRosterPort`, strictly gated `apply_next_uid`; `M2_APPEND_ENABLED=False` so no live invocation is possible from bot. Uses original `assert_guarded_6g_intent`; does not create an alternate lock.
- `edge_egress_k2_m2_ingress_observer.py`: `observe_pam_ingress` and `observe_current_pam_ingress`; trusted *current login* observation only, not persisted proof for a user offline; never writes.
- `tests/test_edge_egress_k2_m2_guard_append.py`
- `tests/test_edge_egress_k2_m2_ingress_observer.py`

## Crucial safety boundaries and known missing M2 work

**DO NOT claim M2 complete until all these are implemented/tested:**

1. **First UID + append unified bootstrapping / no-CLI reconciliation**: current bootstrap requires preinstalled pinned module/directories and the old explicit first-UID installer. A crash during append may leave partial guard/unit files and require manual reconciliation. Add idempotent, operator-visible fail-closed reconcile and recovery; no routine CLI in final product.
2. **True current ingress source**: PAM/WG observer checks a present authenticated login only. A trusted durable, authenticated observation store and verifier for *offline* selection is not wired to M1. Do not assume historical DB host proves current Edge or mint an F4 from this witness.
3. **Physical F4/PAM proof**: real mixed Legacy/protected password SSH and SOCKS, PAM hook, independent root/nonroot console rescue, BootGuard cold-boot before SSH, WG outage, UDP/TCP DNS/NSS/IPv6 Core non-leak, neighboring UID, packet capture and edge capacity acceptance are PENDING.
4. **Root execution and telemetry**: the exact reviewed deployed SHA, tamper-proof root file lockdown, secure bot→root worker attestation, trusted independent `independent_f4_ok` provider, exact actor/chat/nonce and operator approvals and Telegram UX are **not** connected. All default live flags stay disabled.
5. **Original 6G** is a prerequisite for applying each append. A fake offline P3 ticket or test monkeypatch is not live authority. Nothing here supports batch execution or customer migration yet.
6. **User effect**: `nvl0555 / UID1636` remains without an accepted dedicated e9 route. The successful e9 namespace IP Stage from Phase1 is not customer SOCKS egress acceptance.

## Definition of Done for M2

An authorized admin can onboard fresh Edge, install pinned dependencies, bootstrap first UID, append second/Nth UIDs, reconcile interrupted stages and show genuine safety/F4 evidence **without typing any SSH/CLI commands**, while mixed Legacy/root customers remain reachable, and verified protected users cannot leak through Core after WG-loss/boot. All work must pass independently reviewed disposable host physical acceptance and exact SHA CI. This full M2 definition is **NOT YET MET** by source package A.

## Before continuing to M3 or any live Production test

Finish the missing M2 bootstrap/reconcile/observer/F4/BootGuard/DNS/IPv6/worker hardening in separate reviewed PRs, with explicit safety tests. Keep Batch execute disabled through M6. Continue from the [M1–M7 canonical roadmap](K2_UNIFIED_MIGRATION_M1_M7_RELEASE_CONTRACT_2026-10-14.md) in docs PR #144, and [M1 source report](K2_M1_IMPLEMENTATION_REPORT_2026-10-14.md) in PR #145. Update milestone report with exact-head CI results after they are actually observed.

**Four independent status tracks:** code authored / exact-head CI / VPS deployed / physical customer tested; never interchange them.
