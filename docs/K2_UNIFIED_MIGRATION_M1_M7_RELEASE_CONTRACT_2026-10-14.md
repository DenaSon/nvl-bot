# NVL K2 — Unified Single + Batch SSH Egress Migration (M1–M7)

**Authoritative future implementation / acceptance contract; agreed 2026-10-14.** This document supersedes the **development sequence** formerly labeled C1–C5 single UID, followed later by D1–D5 bulk work. Older C/D descriptions in the historical handoff are **not** the active backlog. It does **not** supersede observed e9 production evidence or authorize live mutations.

**Owner decision:** Develop **single-user and multi-user transfer capabilities together**, sharing a single protected migration engine and existing 6G operation lock/journal. Release and prove ONLY a single UID through Telegram first; if it fails, correct the shared implementation and retry; if it succeeds, authorize controlled batch waves **without going back for an entire new bulk-feature development project**.

## A. Final product requirement: zero operator CLI and no functional gaps

**Release definition — all seven phases DONE only when:**

- Every standard operator action happens inside the **existing Persian, minimal, two-column, admin-only Telegram Edge UI** (or delegated automatic service): candidate Edge creation, pinned ingress/egress provisioning, installer/module/guard lifecycle, dry-run, capacity/F4 verification, user/source selection, individual and batch migration, policy/admission, status, retry/HOLD diagnostics, safe compensation/recovery, audit, and post-migration verification.
- **Zero mandatory manual SSH/CLI commands** for the ordinary end-to-end workflow, including first setup on a newly registered Edge, onboarding the second/100th protected UID, backing up/restoring task state, proving canary egress, draining eligible sessions, or completing a safe batch. No copy/paste Python, `sqlite3`, `ip rule`, `iptables`, `systemctl`, `wg`, manual Stage activation, manual F4 SQL edits or hand-edited config as a user-facing operation.
- Trusted, narrowly privileged installed worker(s) do root-only server work **behind Telegram** through authenticated, allowlisted, idempotent typed operations. An external independent witness must attest packet/IPv4/IPv6/DNS/boot/loss evidence; bots cannot self-declare F4 by toggling a flag. An admin may review evidence and approve a risky operation **in Telegram**, but must not be required to type host commands.
- Every known **functional blocker** in the happy path, including orphaned/mixed historical source classification, first-UID-only roster, SSH/PAM ingress, deployment/persistence, DNS/NSS/IPv6, global all-protected limitation, Edge capacity and recovery flows, is either implemented and accepted end to end or has an explicit safe, in-app **remediation** path. A prerequisite not implemented in code/UI is a **release blocker**, not a successful `HOLD`.
- A genuine external impediment (offline Edge, invalid credentials, no verified source identity, capacity insufficiency, unavailable independent rescue/provider API) **must still result in fail-closed HOLD**. “No functional gaps” never means bypass safety gates or guarantee all 425 users are eligible despite real-world issues. An honest, actionable hold with in-bot path to resolve the issue is expected; fundamentally unavailable provider rescue may require an outside-the-product disaster response and blocks declaring full zero-CLI operational acceptance for that provider.
- Automated production provisioning/deploy and any boot/restart/network changes require reviewed hardening, independently tested restore and **explicit operator approval in Telegram**. GitHub merge/CI or admin button alone is not a physical safety witness. No irreversible auto-retry; no unsafe fallback to Core public IP.

**Target topology:** Core keeps Unix users, UID, password, SSHD and original `wg0`. Users enter through a specifically authorized Edge endpoint, terminate SSH/SOCKS on Core, and are pinned by UID through an isolated dedicated WG/veth/namespace path to the intended Edge's public egress IP. Ingress IP, historical `ssh_accounts.host`, default relay/DNS and per-UID egress are distinct identities. A customer cannot be declared migrated if their actual client endpoint still enters an incompatible old Edge unless a tested endpoint/relay cutover is included.

**Production snapshot at definition:** 425 active SSH DB rows; 419 historical hosts absent from host_pool (405 at `104.194.144.195`); target `e9=45.61.163.75` F3 STAGED, namespace Internet public IP PASS, not F4 accepted; `nvl0555` UID1636 has no e9 policy, last sampled public route via Core `209.200.246.198`; e7 UID1644/table20007 and mia1 UID1690/table1781 remain existing independent resources; protected mode OFF; no live P3 worker enablement. See [e9 operational handoff](K2_E9_PRODUCTION_CANARY_HANDOFF_2026-10-14.md) for exact evidence and SSH/resource risks.

## B. Product architecture: one engine, two modes, shared safeguards

```text
Admin Telegram:  🛡 مدیریت Egress → 🔀 انتقال کاربران
                ├─ 👤 انتقال تکی  (one account)
                └─ 👥 انتقال گروهی (explicit filtered cohort / chosen list)
                         ↓
        MigrationPlanner / Inventory / Readiness
                         ↓
         GuardedMigrationEngine + original 6G
                         ↓
             UID lifecycle per account
          (admission → guard → route → prove)
                         ↓
        VERIFIED / HOLD with complete audit
```

Design invariants:
- Single is batch-size 1; batch reuses **exactly** the tested UID lifecycle rather than a second route engine, lock, kernel worker or shadow journal.
- Original 6G provides durable exclusivity/fencing/replay protection. Per-UID state is idempotent and exactly accounted for, with immutable request/actor/target/Stage fingerprints and compare-and-swap DB and roster transitions.
- Immutable source and target identities: trusted Core ingress WG peer, actual Edge SSH host-key pin, candidate Stage/module hashes, UID and owner, customer SSH port, network namespaces/tables, status and external witness timestamps.
- Target failure means selected UID BLOCKED/HOLD, with terminal IPv4 blackhole/REJECT and IPv6/DNS/NSS fences. Never route via Core `eth0` as a fallback. Other UIDs and existing e7/mia1 paths must not be disturbed.
- No implicit modification to `host_pool.is_default`, `dns_current_ip`, Cloudflare, `wg0`, legacy 6H or unrelated subscriptions. An optional ingress cutover is explicitly planned, bound to each cohort and verified; never silently reuse the global all-protected switch for a mixed fleet.
- State machine: `DISCOVERED → NEEDS_REVIEW / ELIGIBLE → ARMED → MIGRATING → VERIFYING → VERIFIED`; any unsafe transition → `HOLD/FENCED`, with displayed reason, evidence and permitted recovery actions. No green status without end-to-end evidence.

## C. Seven implementation phases — parallel feature development, staged activation

| Phase | Engineering scope (single **and** multi-user where relevant) | Concrete handoff and acceptance |
| --- | --- | --- |
| **M1 — Inventory & Migration Contract** | Trusted ingress peer/source mapping vs DB historical host; per-UID ownership, users across pool/unpooled/orphans; permissions, active session ownership, F3/F4 capacity inputs; explicit selected user/list/cohort contracts, batch dry-run; no blind mixed-cohort bypass | For all 425 active rows: enumerated with reconciled owner or named actionable `NEEDS_REVIEW` reason; no silent catch-all, no DB rewrite; same preview code powers single/batch. Source and target IDs read from trusted live identity not assumed from historical IP |
| **M2 — Shared Protected Infrastructure** | Refactor first-UID-only installer into safe **multi-UID** add/update/remove (CAS roster + version/hash); PAM for mixed Legacy/Protected, per-UID BootGuard/DoH and stable table/route allocation, fail-closed IPv4/DNS UDP/TCP/NSS/IPv6; persistent dedicated WG+NAT, startup ordering, module pinning; automated installer/backup/safe rescue checks + independent F4 witness integration | First/second/Nth UID isolated; mixed legacy SSH/password/SOCKS and rescue pass; failed boot/WG loss prevents Core egress; all provisioning/reconciliation done through worker/Telegram, no manual host operations |
| **M3 — Unified Migration Engine** | Single and batch worker built simultaneously, both sharing original 6G journal/lease, exact actor/nonce, bounded per-UID CAS, idempotent replay, guarded session drain and source/target preflight; batch-wave concurrency/rate/rollback/fencing, per-account results, transactional ownership and Edge resource reference counts | Source-level engine can plan and safely execute 1, N and partial batches via trusted worker ports, report each account, freeze on drift, resume only with explicit approval; no competing lock or hand-mutated kernel shortcuts |
| **M4 — Complete Telegram Operations UI** | Existing `hpeg_*` admin-only UX: choose Edge, 👤 Single/👥 Batch, filtered cohort, preview count/blocked reasons, start/cancel/freeze/retry, progress per UID, auto diagnostic evidence, safe recovery, F4 and capacity/backup/worker provision views; short Persian copy, 2-col button layout; no parallel bot | End-to-end control **from Telegram only** for normal onboarding, migration, F4 verification, all statuses and safe recovery; batch EXECUTE remains feature-gated/disabled until M7 and explicit approval |
| **M5 — Integration, Fault Injection & Automated Acceptance** | Full tests for fresh Core/Edge commissioning, actual PAM/SOCKS, first→Nth UID roster, mixed/unpooled cohorts, incorrect Stage/host key, 6G lock conflict/replay, mid-batch failure, live sessions, DNS+IPv6, WireGuard-loss/cold-boot, no neighbor impact, resource limits, snapshots and restored clone. Independent probe/packet witness produces signed/time-bounded evidence automatically | Exact-head CI + disposable/live-like acceptance **without operator typing shell commands**. No open functional integration blockers; failing checks surfaced and remediable from UI or honestly HOLD. No Production batch activation |
| **M6 — One-UID Production Canary ONLY** | With approved gated change window and independent snapshots/rescue, Telegram single transfer for `nvl0555 / UID1636 → e9`. Verify actual public SSH/SOCKS ingress, `45.61.163.75` egress, external DNS/NSS/IPv6 packet no-Core-leak, targeted loss/recovery and unaffected neighbors. If FAIL: keep UID securely held, diagnose/repair same code and repeat after approval, do **not** enable batch | Documented externally evidenced `SINGLE_VERIFIED` or clear `HOLD`; no claim that M6 PASS alone grants batch release. Never run disruptive failure injection against production clients without proven isolation and approved safe venue |
| **M7 — Controlled Batch Rollout & Final Release** | After M6 verified and **batch-specific** physical acceptance, enable batch gated actions. Stage 1→small waves→larger cohorts based on measured Core/e9 capacity and owner approvals; controlled ingress endpoint updates where required; full runtime monitoring, per-UID actionable holds, aggregate reconciliation and recovery | Both Single and Batch operated **fully from Telegram**, no required CLI for provisioning/selection/repair/verification. All **eligible** selected accounts reached exact target Edge egress or independently accounted for with actionable, safe non-functional external holds; no unresolved product-side blockers and no neighboring-user regression |

### M1–M5 execution strategy
- Develop single **and** batch contracts from M1, implement them in parallel under M2–M4, and jointly test both in M5.
- M6 runs **only** single, on operator-approved target UID; all batch mutating gates stay disabled. After an M6 failure, repair the **shared** engine and regress both paths in M5, not invent manual server workarounds.
- M7 only activates verified multi-UID migration after separate integration/physical/cohort/capacity approvals. A single Canaray must **not** silently toggle an all-user setting.
- Source PR/test/review and code-only deploy are separately gated. **Do not merge doc/feature PRs directly onto auto-deploying master** without operator awareness and reviewed release boundary.

## D. End-to-end zero-CLI workflow (all required features must be implemented by M7)

In Telegram, an authorized administrator:

1. Registers the new Edge through existing wizard; root worker provisions pinned ingress/WG/namespace/NAT and durable boot services; UI verifies `INGRESS/TRANSPORT/STAGE`, without prompts for terminal commands.
2. Opens `🧪 آماده‌سازی`: orchestrated source/target fingerprint checks, backup and verified restore prerequisite, independent witness probes, service/PAM/mixed-cohort preflight, capacity and external rescue attestation all shown with fresh evidence and expiration. An invalid attestation is `HOLD`, never synthetic F4.
3. Enters `🔀 انتقال کاربران`; selects one username or explicit users/filter/verified source Edge, then target `e9`.
4. Reviews preview: exact UID counts and historical host vs actual ingress, eligible/busy/unresolved counts, CIDR/port, total capacity, estimated active session effect, chosen wave-size and per-UID admission safety; user confirms exact scope with short-lived typed ticket.
5. Taps `تأیید انتقال`. Trusted executor acquires same original 6G, arms fail-closed guards, provisions per-UID route, applies scoped endpoint/relay changes if required and approved, verifies via independent IPv4/IPv6/DNS/real SSH/SOCKS witness, then records durable receipt per UID. All steps are automatically auditable.
6. Follows live progress and receives **only critical** notifications; may freeze/cancel next UID/batch, or choose scoped retry/reconcile/restore from UI. Failure remains fail-closed; no automatic clear-to-Core egress or global PAM/SSH restart.
7. Views final summary: `VERIFIED / HOLD / NEEDS_REVIEW` counts, Core no-leak evidence, original customer routes unchanged, 6G idle/recoverable. Only after independent batch acceptance and explicit admin approval does M7 allow customer waves.

**Protected break-glass distinction:** Independent provider console and off-host encrypted recovery **must exist** for worst-case disaster. These are safety guarantees, not routine CLI steps. Do **not** count a workflow complete if it requires the operator to manually execute shell commands during normal operation, onboarding, verification, transient failure, client migration or ordinary safe rollback. If physical provider failures require external console, fail closed, stop waves and describe the exceptional disaster condition separately; never promise no human intervention under arbitrary infrastructure outage.

## E. Exit checklist / definition of DONE for the entire 7-phase program

**All must be measured and witnessed before marking M7 `DONE`:**

1. **No functional blockers:** No missing live executor, legacy source mapping, multi-UID roster updater, ingress endpoint plan, F4 witness integration, bot handler, safe recovery button, or unresolved migration-engine gap. All development/missing-feature `HOLD` codes eliminated with tested solutions; legitimate runtime holds remain possible.
2. **No routine manual CLI:** Fresh Edge → healthy protected Canary → batch user migration → inspect/repair/retry/fence → verified final egress, executed through Telegram without terminal intervention; repeat from clean state with audit trail.
3. **Correctness:** Each verified target user's observed public SSH/SOCKS egress is precisely the requested Edge's IP and the authorized actual ingress endpoint agrees with declared migration mode; e9 target `45.61.163.75`. No route back to Core IP `209.200.246.198`.
4. **Leak-free failure safety:** Independent packet/no-Core-leak proof for IPv4/TCP+UDP DNS/NSS/IPv6; absence of IPv6 connectivity alone is not a complete proof. WireGuard failure, restart/cold boot and wrong F4/partial transition deny first; original 6G remains consistent.
5. **Isolation:** Other production accounts, legacy Edge IPs, e7 UID1644 and mia1 UID1690 guards, original `wg0`, host_pool default, Cloudflare/DNS and non-selected users remain unaffected unless independently selected and authorized. No global 425-account side effect on a single-user action.
6. **Fleet readiness:** All 425 currently active DB accounts are inventoried as eligible or specifically unresolved, with no silent omissions; unique UID/ownership proven, capacity/resource margins acceptable, per-wave failure/recovery and customer reconnect impact reviewed. **Do not assert 425/425 migrated** if some are actually ineligible or externally blocked.
7. **Provenance:** Exact GitHub source SHA, live deployed SHA, independent snapshots/restore, signed witness, 6G/UID journal receipts and Telegram actor permissions are recorded. Unapproved flags stay OFF.

## F. Boundaries and follow-up instructions

- Historic user tests already demonstrated a temporary e7 `nvl0557` iPhone public egress through its former Edge. That was **not** protected physical F4, and removed e7 artifacts/UID1644 fence must not be silently cleared.
- Current e9 namespace IP PASS is **not** the M6 user E2E PASS. Do not repeat already proven e9 Stage/transport setup.
- Do not resolve source metadata mismatches by rewriting `ssh_accounts.host`, turning on `edge_egress_protected_mode`, faking F4 READY, disabling safety checks or attaching arbitrary active sessions.
- **Next development action:** Start M1 on a narrowly scoped feature branch from **fresh, verified master**; add tests for both `SingleSelection` and `BatchSelection`, source identity reconciliation and preview/hold accuracy. Update this plan after each phase with *actual source/CI/deployed/live* status separately.
- Related physical gates: GitHub issues #106, #108, #129, #102 and documents `K2_P3_GUARD_INSTALL_AND_UID_WORKER_2026-10-14.md`, `NVL_K2_PRODUCTION_SSH_DEPLOY_RUNBOOK_2026-10-14.md`.

**Final product outcome:** One coherent protected Egress transfer system: **One user OR many users**, exact intended Edge IP, full in-Telegram operations, safe rollback/fencing, and **no outstanding product functionality or operator CLI requirement** after verified M7 acceptance. This is the release **target**, NOT the current production condition.
