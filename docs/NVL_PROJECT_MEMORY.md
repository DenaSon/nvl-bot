> **LATEST K2 SCOPE & DELIVERY STATUS — 2026-10-15 (AUTHORITATIVE FOR SINGLE/BATCH HANDOFF):** The user's requested deliverable is **only two operations in the EXISTING Telegram admin bot: 👤 Single transfer and 👥 Batch transfer**. The same original-6G per-UID engine must serve both. Single is implemented in UI and mocked source only, **not** demonstrated end-to-end; Batch UI and sequential ≤10-wave source exist but execution remains independently DISABLED until Single is physically verified. Root worker is not active; existing mixed-Legacy cross-Edge UID_ATTACH remains HOLD and protected-mode/global bot-root constraints unresolved. Only implement critical-path UID ingress/egress + root execution + independent single-VPS egress proof, then enable/test batch with approval; no new product features or further speculative infrastructure. **PR #148 remains Draft/unmerged; no confirmed customer move.** Canonical actionable scope/status and release checklist: [K2 Single/Batch scope & release status](K2_SINGLE_BATCH_SCOPE_AND_RELEASE_STATUS_2026-10-15.md). This scope status does not change the separate 2026-10-14 verified code-only Core deployment record below.

---

> **LATEST PRODUCTION CORE CODE CHECKPOINT — 2026-10-14 (OVERRIDES prior “not deployed” banners below):** Operator completed the reviewed **code-only** Core release on `CloudVPS121849` (`209.200.246.198`) using `/root/nvl_k2_publish.sh`. Script reported `PRECHECK=PASS; REPLACE=8; CREATE=13; SAME=49`, `ALL_70_MODULE_HASHES=PASS` and `K2_DEPLOY_SUCCESS=d5ca38b6e7069d969d8aa33bcb42ef71c8c63b2a`. Source staged at `/root/nvl-k2-stage-d5ca38b6e706`, live entrypoint `/root/bot_final_v49-2.py`, rollback `/root/nvl-k2-predeploy-sJsySowp`, database `/root/master_bot.db`, curated backup `/root/nvl-emergency-backups/core-20261014T144432Z-x4EVRH`. The user confirms provider snapshot/rescue console and an unencrypted downloaded copy at `D:/NVL-Backups/`. This evidence verifies script-level code publish and 10s service start observation, **NOT independent post-deploy service audit or Telegram smoke**. New Edge lab, F4, PAM, protected UID and real customer egress transfer remain NOT accepted. Details, hashes, env and precise recovery paths: [2026-10-14 Core code release record](NVL_K2_CORE_CODE_RELEASE_RECORD_2026-10-14.md). Do not execute publisher again. Historical banners below are superseded **only for code deployment**; earlier safety blockers remain.

---

> **AUTHORITATIVE NVL K2 PROJECT MEMORY UPDATE — 2026-10-14:** GitHub master now contains PR #120 (source Phase1 wizard and dedicated Edge egress; Phase2 Legacy→Protected, single existing 6G journal, guarded cohort promotion and protected relay; Phase3 operator review, testing scaffolds) **and PR #139** (real LocalLinuxProtectedRuntimeKernel P3-A/C worker assembly, one-canary UID root PAM/BootGuard/DNS installer and SHA-reviewed Python source staging). Source baseline before this docs patch is 331fd86e399bd18e2f524071edb7f14d099e00de. Exact PR #139 head passed **1,531 Python tests and 789 Edge Safety tests each for Python 3.11/3.12**. No code merge is a Core/Edge VPS deploy, no real kernel/PAM/WG-loss/SSH/SOCKS/DNS/NSS/IPv6 F4 packet/no-leak or cold-boot results are claimed. Installer handles **first UID only**, rejects an existing roster; module staging and Worker require separate opt-in independent reviewed root release and F4 packet/neighbour safety. No mutating bot callback for those worker actions is wired by default. NEXT: [canonical staged SSH deployment runbook](NVL_K2_PRODUCTION_SSH_DEPLOY_RUNBOOK_2026-10-14.md); collect actual current Core live version/DB/6G/venv/systemd read-only, take independently recoverable provider snapshots + encrypted offhost backups, pin master SHA, safely deploy **code only**, then test new candidate Edge dedicated namespace via existing Telegram wizard; protected UID full acceptance on a disposable Core clone before a production test UID. Issues #106/#108 remain open. Historical banners below retain provenance only and MUST NOT override this checkpoint.

---
> **2026-10-14 K2 Phase2 CODE MILESTONE:** feature draft #120 includes guarded manual all-PROTECTED relay operation (#126) and Phase1→F3 allocation bridge (#128), feature SHA checkpoint `65ed217264b227b08f7d6448c2895260ffe5c968`. Phase1 original pinned WG public keys/Stage/host key are now used to allocate STAGED Egress in existing F3 DB under shared 6G after exact Edge namespace public-IP proof. Manual admin source/target/Cloudflare/UID/F4-gated ticket invokes prior J/K protected host saga, fail-closed HOLD on ambiguity, atomic new Edge host_pool/default/settings.hosts after proof; no automatic 6H or Legacy change. `k2_p2_relay_switch_enabled` absent/0 = OFF. **All-PROTECTED only; mixed Legacy/Protected remains NO-GO and live external SSH/SOCKS/IPv6/DNS/PAM/Boot loss testing/F4 READY not accepted.** No merge to master. Full final-head CI must be checked separately. [K2 Phase2](K2_PHASE2_GUARDED_RELAY_2026-10-14.md).

> **2026-10-14 K2 PHASE 2 WORKSTREAM:** Draft PR #120 (source `0637522f36b0ef368b13a1d8433ca1779ab3edd2`) contains source-only coherent SSH cohort selection from PR #127 and a separately protected manual all-PROTECTED 6G relay handoff. Per-UID Core egress, real ingress/DNS, dedicated SSH Stage and F4 evidence are required; mixed legacy cohorts are **explicit HOLD**. GitHub 1,374 Python tests and Python 3.11/3.12 Egress checks PASS. Toggle `settings.k2_p2_relay_switch_enabled` absent/0 means unavailable; NO production deployment and NO real client SSH/SOCKS IP evidence. Phase 2 is not operationally signed off until existing Legacy clients are handled safely and controlled live acceptance proves actual IP, DNS/IPv6, WireGuard loss, cold boot and rollback/recovery. Reference docs/K2_PHASE2_SOURCE_COHORT_2026-10-14.md and docs/K2_PHASE2_GUARDED_RELAY_2026-10-14.md.

> **AUTHORITATIVE K2 PHASE 1 SOURCE CLOSURE — 2026-10-14:** Draft PR #120 feature head `b48cf3989d42c24d9136e316d17589251e0e1de2` incorporates PRs #121–#123 and #125. **1,352 Python tests PASS** on final code; independent Stage-only Python 3.11/3.12 PASS. Single existing admin Telegram flow: Add new Edge -> immutable Core+Edge Egress Stage and SSH pin -> optional operator-released one-shot dedicated transport activation -> two-sided UP + exact Edge IPv4 proof -> independent fresh read-only `🌍 تست خروجی`. Final Worker now rechecks **specific shared 6G intent and both Stage hashes, unchanged active source, candidate still outside customer pool, and real ingress Stage after lease**, and never resumes RECOVERY. **Master/Production unchanged; no live VPS was tested; `k2_p1_transport_activation_enabled` defaults OFF.** Stage/transport/IP proof are NOT subscriber SSH/SOCKS proof or F3/F4 customer READY. No changes to Failover, auto transfer, original wg0, UID, DNS or default route. Next Phase 2: protected customer egress and relay switch, then Phase 3 Telegram/release/E2E. Canonical: [K2 Phase 1 transport](K2_P1_TRANSPORT_ACTIVATION_2026-10-14.md).

> **2026-10-14 K2 Phase1 source-finish checkpoint:** PR #123 merged into draft PR #120 feature branch only, squash `168c4b240460f251652ac78f71c1b43b51a2bbe7`. Phase 1 source now contains admin-only Telegram `📤 فعال‌سازی خروجی` with one-time authorization and disabled-by-default operator gate, root-only version/stage/SSH-pin Worker using existing 6G intent/HOLD, dedicated Core/Edge WG transport creation, exact Core namespace observed Edge public IPv4, plus **independent fresh read-only Telegram `🌍 تست خروجی`**. No customer DB, UID, active host/default, public DNS, wg0, Failover/6H changes. CI and real VPS acceptance are different: real boot/persistence, IPv6/DNS/SSH SOCKS, external failure drills and F4 customer READY remain unproven. See `docs/K2_P1_TRANSPORT_ACTIVATION_2026-10-14.md`. Only the Phase1 source scope is closed.

> **K2 Phase1 executive source update 2026-10-14:** PR #122 delivered concrete, root-only *dedicated transport-only* Worker + two-step Telegram activation under draft #120 (not master). Existing Edge wizard pins original Core/Edge Stage digests + Edge SSH host key; protected 6G intent/HOLD reuses existing journal; exact external IPv4 via independent Core namespace probe. Admin-only 120s confirmation; release toggle OFF by default. No customer route/UID or public DNS/default/6H modifications. Full source CI pass at PR #122 squash point; new-VPS boot/rollback/F4 and customer exit IP still untested. Read `docs/K2_P1_TRANSPORT_ACTIVATION_2026-10-14.md`; do not claim live production acceptance or full K2 release.

> **2026-10-14 K2 Phase1 SOURCE UPDATE:** [Phase 1 isolated wizard checkpoint](K2_PHASE1_ISOLATED_WIZARD_2026-10-14.md). PR #121 merged **only into draft PR #120 feature branch**, head `9ba26865da06d7cae5034ff2c154084b138ba959`; 1,335 Python tests + Egress 3.11/3.12 CI PASS. New K2 admin wizard stages trusted Ingress/dedicated Egress artifacts while leaving unaccepted Edge **outside active host pool and settings.hosts**; avoids legacy remote root SSH password override. Existing Legacy path and Phase6G/6H Failover unaffected. **Production is unchanged, Egress transport and customer IP switch remain NOT RELEASED**, no real new-VPS validation. Canonical handoff below is authoritative.

> **AUTHORITATIVE 2026-10-13 K2 FINAL SOURCE CHECKPOINT (supersedes all earlier "next phase" banners below):** [Canonical K2 Agent Handoff](NVL_K2_AGENT_HANDOFF_2026-10-13.md) and repository [AGENTS.md](../AGENTS.md). Verified feature `master` `22eba3cda13c0c72407bd3d55d7328ae93496d25`. **P2 retirement PR #112 and P3-A/B/C/D/E/F PR #113–#118 are ALL MERGED; #118 exact-head Python and Edge stage-only CI PASS.** This is **source completion, not Production deploy or accepted protected traffic**. P3-F keeps admin-only compact two-column Persian Telegram Edge UX and read-only orphan listing; existing backup-first Phase2 metadata delete retains its narrow guarded execution, while protected P3-A–E host actions have NO reviewed registered concrete privileged worker and no live Telegram executor. F4/PAM/BootGuard/DNS/NSS/IPv6/packet/WG-loss/reboot/rescue drills remain unaccepted ([#106](https://github.com/DenaSon/nvl-bot/issues/106)); integration, worker security and controlled rollout remain pending ([#108](https://github.com/DenaSon/nvl-bot/issues/108)). Next source work: independently audit full P3 A–F boundaries and finish/test a **pinned, narrowly scoped, root-only guarded worker** only if proven missing; then isolated disposable Core/Edge F4; then single operator-approved pinned Production deploy and canary. Do not alter live `wg0`, global default/DNS/Cloudflare, SSH users, reboot, or enable protected 6H. e7 `172.86.105.67` physical VPS gone; manual P2 ingress registry/F3 metadata retire PASS with `/root/nvl-backups/e7-retire-pRfWH19n`; Core netns/VETH/WG route remnants and UID1644 IPv6/boot protections **not re-audited or removed**. Last operator-stated old Core source pin was `2988d0d71f8c65d10a1fb1c7e133ddf0bc7fc698` (not independently reverified). Keep unrelated Miami UID1690/table1781 and all customers untouched. Chronological earlier P3 phase banners remain historical.

> **2026-10-13 — K2 P3-F Telegram admin UX (PR #118):** Reused the existing admin-only `hpeg_*` dashboard/detail/Stage/health/IP probe/UID selector/review/metadata-retire callbacks. Introduced pure `edge_egress_p3_telegram.py` minimal two-column Persian presentation with concise nontechnical status/help, escaped HTML, short wizard and strict pre-existing onboarding validation, explicit confirmation and safe cancel for Phase2 metadata-only delete, and new **admin-only read-only** orphan stage-directory overview with root-only checks. One-shot operator review remains acknowledgment-only; no P3-A–E live worker/ticket/cloudflare/kernel action wired. Existing DB backup-first Phase2 metadata deletion is the only preserved mutating UI action. Source-only flag `P3F_LIVE_EXECUTION_ENABLED=False`; e7 kernel remnants and UID1644 IPv6/boot/stage still not independently audited, #106/#108 remain OPEN. After green CI/merge: independent disposable F4/live root worker and controlled pinned Production rollout are separate acceptance activities. [P3-F source UX notes](K2_PHASE3_F_TELEGRAM_FINAL_UX_2026-10-13.md).

> **2026-10-13 — K2 P3-E guarded Edge retire / orphan kernel cleanup (PR pending):** Added disabled-by-default `edge_egress_p3_retire.py` for **orphan-only** dedicated Core namespace/VETH/WG/policy next-hop cleanup once Phase2 registry/F3/allocations/readiness/runtime/UID bindings already detached. No new lock: added P3-A allowlisted `EDGE_RETIRE` action with six extra backup/ownership/UID fence/persistence/no-wg0 acceptance gates, existing 6G nonce-bound RUNNING intent and protected HOLD on uncertainty. Source-only injected host port enforces exact pinned Core Stage (SHA, IP/Edge identity), complete DB/registry and read-only kernel ownership audit, no running sessions, no foreign references, existing per-UID IPv4+IPv6 REJECT, retained UID RPDB selector+terminal blackhole. Order: disable only exact owned units → remove only exact preferred orphan Edge next hop(s) → reverify safe fences → retire dedicated transport only → verify no orphan transport but UID fences persist. **e7 remains only metadata retired, not physically cleaned**; UID1644 IPv6 fence/persistence/stage pin still need live READ-ONLY audit; no new root worker, Telegram execution or production mutation. Phase2 metadata-only delete remains separate, live gate #106 and lifecycle #108 open; P3-F must expose preview/blockers only until lab acceptance. See [P3-E](K2_PHASE3_E_SAFE_DECOMMISSION_2026-10-13.md).

> **2026-10-13 — K2 P3-D Edge-to-Edge/Cloudflare CAS source checkpoint (PR #116):** The guarded existing 6G/6H **Egress-only** handoff still NEVER mutates public ingress DNS or rebuilds SSH hosts. The separate *positive Ingress+Egress* source handoff uses protected admission-fence, drain, per-UID REJECT and repin, frozen SQLite mapping CAS, then public Cloudflare cutover under the SAME shared 6G RUNNING journal. `edge_egress_v1_cloudflare.py` now snapshots exact DNS-only A record IDs/TTLs/modified_on, rejects AAAA and pagination, per-record rechecks provider state and 6G guard before every PATCH, verifies after; `edge_egress_p3_dns_cutover.py` adds a **release-disabled** stricter gate for journal phase/kind, default source/DNS, F4 target≠Core, complete FROZEN/target-protected mapping and independently supplied live UID/Ingress proof. `edge_egress_handoff.py` also handles task cancellation after potentially mutating 6G phases, retaining RUNNING/HOLD and attempting freeze. **Cloudflare does not provide atomic multi-record CAS or server-conditional PATCH**; concurrent edits/partial updates require operator-only reconciliation, never automatic DNS rollback/Core fallback. Offline tests use fake Cloudflare/SQLite, not live acceptance. `P3D_INGRESS_DNS_EXECUTOR_ENABLED=False`, no Telegram execution or Production deploy. F4/PAM/Boot/packet acceptance #106, lifecycle work #108, P3-E decommission and P3-F Telegram integration remain. [P3-D details](K2_PHASE3_D_EDGE_HANDOFF_CLOUDFLARE_CAS_2026-10-13.md).

> **2026-10-13 — K2 P3-C Protected UID Lifecycle source checkpoint (PR #115):** `edge_egress_p3_uid.py` introduces a default-disabled, injected P3-A `GuardedProtectedUIDPort` for `UID_ATTACH` (new pre-rostered account or resume FROZEN) and `UID_FREEZE` (emergency per-UID REJECT). No new lock, database schema or parallel lifecycle state: each stage checks the existing P3-A nonce-bearing 6G RUNNING intent and uses the existing F2 `Existing6GUIDRuntimeStore` generation CAS/UID mappings. Attach requires complete root-roster + hashed per-UID guard, PAM/Ingress/Boot/idle/multi-UID evidence, BLOCKED record before kernel actions, actual public Edge IP and independent DNS/NSS/IPv6 non-leak before PROTECTED commit; resume is only FROZEN→PROTECTED under fresh proofs. Emergency freeze does not require healthy Edge/PAM/DNS or empty sessions; shared Edge routes, other UIDs, `wg0`, SSHD, DNS/default and protected mapping are preserved; uncertainty re-arms UID REJECT, attempts HOLD and preserves 6G RUNNING. **Not a live production feature:** `UID_LIFECYCLE_ENABLED=False`, no concrete privileged worker, Telegram executor or lab F4 evidence; no Core changes or deploy. Unprotected release/removal reserved P3-E. [P3-C handoff](K2_PHASE3_C_PROTECTED_UID_2026-10-13.md). Issues #108/#106 remain OPEN; P3-D/E/F before joint disposable acceptance and controlled production deployment.

> **2026-10-13 — K2 Phase 3-B pinned Provisioning/Boot source (PR #114):** Reused existing WireGuard Stage SHA-pinned transport, standalone systemd guard and DNS unit renderers, F2 protected UID BootGuard + roster and F4 PAM human review. Added `edge_egress_p3_boot.py` with deterministic immutable review digest covering the full pinned EgressSpec, unit identities/bytes, roster and PAM review; a **P3-A EDGE_PREPARE-only** injected HostPort rechecks the existing 6G RUNNING INTENT nonce/edge/scope and fresh Stage identity **before each** boot/transport step, requires independent rescue/DENY/PAM/DNS/Boot evidence before calling existing transport `ensure()`, and invokes injected fail-closed Freeze/HOLD on uncertainty. Offline tests validate 6G lease loss, malicious/changed Stage/roster/units, denied boot, verification drift, P3-A recovery. **No live safety provider, PAM installer, systemd or SSH restart, no Core deployment, no change to old wg0 or UID1644.** Live F4/PAM/boot/tunnel-loss acceptance remains unproven (#106); P3-C through P3-F remain. Notes: [P3-B](K2_PHASE3_B_PROVISIONING_BOOT_2026-10-13.md). Continue code-first then disposable lab and joint pinned Production deploy.

> **2026-10-13 — K2 Phase 3-A executor source checkpoint (PR #113):** `edge_egress_p3_executor.py` defines the **disabled-by-default**, root-only, injected HostPort executor for `EDGE_PREPARE` / `UID_ATTACH` / `UID_FREEZE` using exactly the existing 6G persisted lock and journal. It records `EGRESS_P3_EXECUTE_INTENT` before potential host mutation and keeps 6G `RUNNING` at `EGRESS_P3_RECOVERY_REQUIRED` for operator-only reconciliation on uncertainty; both phases are protected from 6G stale-lock automatic recovery. Operator ticket is actor/chat/TTL/scope/fresh-attestation bound; replay nonce hash persists in the original failover journal. `inspect_execution_recovery` is read-only. This is P3-A source/CI, **NOT live execution**, no bot execute callback, no PAM/boot/F4 acceptance, no Core update. P3-B/C must provide audited pinned HostPort and real release evidence; P3-D/E/F remain. [P3-A handoff](K2_PHASE3_A_GUARDED_EXECUTOR_2026-10-13.md); Issue #108 guarded work and #106 live F4 acceptance stay OPEN. Production remains at prior release `2988d0d71f8c65d10a1fb1c7e133ddf0bc7fc698` pending joint final deploy.

> **2026-10-13 — K2 Phase 2 safe Edge retirement (PR #112):** Existing Telegram Egress details now have an admin-only safe-delete preview, one-shot 120s confirmation, and metadata-only finalizer that backs up DB+trusted registry and refuses deletion if Stage, wg0 peer/config, namespace/veth, route table, UID binding, default/DNS, active SSH account, or running 6G exists. The legacy `hpdelconfirm_/hpdelyes_` path is gated against registered K2 Edge deletion (preserving pre-K2 legacy-only DBs). Do **not** interpret this as network/VPS cleanup or F4 READY; owner-verified resource cleanup belongs to Phase 3 guarded executor. Manual e7 metadata retirement on live Core succeeded with backup `/root/nvl-backups/e7-retire-pRfWH19n` and UID1644 REJECT retained. Core live source remains at pinned `2988d0d71f8c65d10a1fb1c7e133ddf0bc7fc698`; **PR #112 is source-only until separately approved deploy**. Operator sequence: finish Phase 3 source+offline CI, then disposable F4/PAM/boot/tunnel-loss E2E, finally one controlled Production deploy; Issues #106/#108 remain safety gates. [Phase 2 retirement notes](K2_PHASE2_SAFE_EDGE_RETIRE_2026-10-13.md).

> **2026-10-13 — K2 Phase 2-B4 ready for Core acceptance testing:** [Telegram Egress Phase 2 handoff](K2_PHASE2_TELEGRAM_EGRESS_UI_2026-10-13.md) documents one existing `hp_addedge` wizard and one new opt-in Egress entrypoint `hpeg_wizard`; *fresh* Edge ingress installation followed by Stage-only dedicated Egress, with safe HOLD and inspection, never switch to default/DNS/UID. Legacy wizard and global settings preserved. No server tests performed yet. **NEXT:** operator-approved Core/Edge acceptance (Issue #106), then Phase 3 guarded relay activation under existing 6G/6H; never repeat e7 onboarding.

> **2026-10-13 K2 Phase 2-B3:** [Telegram Egress implementation handoff](K2_PHASE2_TELEGRAM_EGRESS_UI_2026-10-13.md) includes admin-only, read-only Edge preparation and selected-user attach/freeze review plans with one-time actor/chat/expiry/evidence-bound *read receipts*. Always HOLD; **no execution, no UID change, no F4 promotion, no Core commands**, operator tests deferred to end of source implementation. Source module: `edge_egress_phase2_review.py`.

> **2026-10-13 — K2 Phase 2-B2 source checkpoint:** [Egress Telegram handoff](K2_PHASE2_TELEGRAM_EGRESS_UI_2026-10-13.md) now records per-Edge read-only Stage digest/health (including unallocated e7), paginated Edge dashboard, and admin one-shot protected SSH username preview with mandatory HOLD. No actual Core operation, customer migration, domain switch or F4 release was performed; all end-of-implementation Core testing is deferred at operator request.

> **PHASE 2 SOURCE IMPLEMENTATION START — 2026-10-13:** [Telegram Egress Phase 2 UI/control handoff](K2_PHASE2_TELEGRAM_EGRESS_UI_2026-10-13.md) documents admin-only read-only dashboard/Edge details/transport inspection and gated operation preview in the *existing* host-pool bot flow. Core operator tests and physical F4 failure/reboot/PAM evidence are deferred to the end of all implementations at the user's request; this code does not mark e7 READY or migrate any user.

> **PHASE 1 STARTED — 2026-10-13:** See [K2 protected foundation / live acceptance and planned Telegram UI/UX](K2_PHASE1_PROTECTED_FOUNDATION_2026-10-13.md), together with [the e7 iPhone E2E memory](SSH_EGRESS_K2_E7_MEMORY_2026-10-13.md). Source fixes and tests are distinct from actual Production installation, tunnel-loss/boot/PAM/DNS evidence and F4 READY. Do not infer canary guard status without a fresh read-only snapshot.

> **LATEST NVL SSH EGRESS K2 MEMORY — 2026-10-13:** Read **[K2 New York e7 / iPhone Production E2E memory](SSH_EGRESS_K2_E7_MEMORY_2026-10-13.md)** FIRST for current concrete host/Edge/UID identifiers, successful e7 staging and actual mobile IPv4 proof, the local BootGuard whitespace hotfix, 20-minute Canary fence uncertainty, and exact remaining F4/PAM/boot/fail-closed gates. The on-phone `nvl0557` trace returned **`172.86.105.67`** from the same New York Edge; this is **one-request E2E PASS, NOT F4 READY or a durable production rollout**. Earlier P0 and 2026-10-12 next-step banners below are historical and superseded. No new customer changes, global protected mode, Core reboot, or blind B26 rerun.

> **NEW CURRENT-SCOPE OVERRIDE — 2026-10-12:** For active work on SSH client Internet IP, read **[SSH_EGRESS_V1_PRODUCTION_SCOPE_AND_EVIDENCE.md](SSH_EGRESS_V1_PRODUCTION_SCOPE_AND_EVIDENCE.md)** first. V1 is restricted to real Production, one controlled account, **Egress public IPv4 == that account's genuine Ingress Edge public IPv4**. Current next step: **P0 read-only Root Cause and minimal delta**. **6G/6H expansion and draft PR #92 are deferred/frozen**. Preserve historical evidence and existing failover lock invariants; do not rerun LAB tests or perform Production changes without a separate reviewed change plan. Older handoff and release docs below remain safety references rather than current scope.

> **Current SSH Edge Egress status (2026-10-12):** This file contains historical NVL production runbooks and release notes, including V115.2; do **not** infer today's deployed version from them. For the current F1–F4 implementation, actual CI results, blocked public SSH Egress, and exact next steps, read **[EDGE_EGRESS_CURRENT_HANDOFF.md](EDGE_EGRESS_CURRENT_HANDOFF.md)** first. GitHub `master` last verified at `589625073e5b191529485bd9dc3d1bbbd2119cea`; Production host state still requires read-only verification. **Do not rebuild finished Egress phases or confuse isolated SOCKS success with customer SSH Egress.**

---

# NVL Project Memory / Production Runbook

Last updated: **2026-10-02**  
Current production release: **V115.2-2026-10-02-predeploy-fixes**  
Release commit: `a5ed9e1ec943e1d88032f7ce8abb30e5d7631c66`

## Current system scope

NVL is a Telegram-based control plane for VPN service operations.

Current capabilities include:

- SSH account lifecycle, expiry, capacity monitoring, Hidden Hold and reseller sales.
- V2Ray/Marzban sales for timed and volume-based plans, including custom volume, expiry selection, subscription naming and reseller settlement.
- Marzban administration for users, nodes, inbounds and hosts through a dedicated service layer.
- Agent/reseller panel with wallet, commission, emergency credit and owned-user management.
- Core/Edge infrastructure with WireGuard relay topology, standby/failover tooling and Edge synchronization scripts.
- Phase 6A: explicit separation of customer `service_port` and management `admin_ssh_port`.
- Phase 6B: typed, persisted health evidence and canonical host health states.
- Phase 6C: per-Edge observability using WireGuard handshake freshness, Core-path evidence and optional external/regional probe evidence. Phase 6C is diagnostic only and does not itself trigger failover.
- Current Core is explicitly classified as `CORE_LOCAL` and excluded from Edge filtering probes.

## V115.2 production changes

- Fixed the reseller V2Ray sale path so a successful Marzban create does not fail afterward because of a redundant second user GET.
- The verified `subscription_url` returned by Marzban create is reused; fallback GET is only used when that field is absent.
- Agent action labels were cleaned up by removing possessive “من”; legacy labels remain accepted as compatibility aliases.
- V2Ray/Marzban endpoint is configuration-driven through `settings.marzban_url`.
- Production value observed during the V115.2 deploy: `https://gate.nvlsup.xyz:2053`.
- `ws.nvlsup.com` belongs to SSH/TLS and is separate from V2Ray/Marzban. Do not modify it during V2Ray endpoint work.
- V115.2 staging validation passed **172 unit/regression tests**.

---

# Canonical Production Deployment Procedure

This is the standard NVL deployment workflow. **Do not deploy by running Git directly in `/root`.**  
The Git checkout and validation environment are separate from the production runtime.

## 1. Pre-deploy database check

```bash
sqlite3 /root/master_bot.db "PRAGMA integrity_check;"
```

Expected:

```text
ok
```

Take an initial DB/source backup when appropriate.

## 2. Fetch the release repository

Persistent Git checkout:

```text
/root/nvl-release
```

GitHub deploy key:

```text
/root/.ssh/nvl_github_deploy
```

Fetch:

```bash
GIT_SSH_COMMAND="ssh -i /root/.ssh/nvl_github_deploy -o IdentitiesOnly=yes" \
git -C /root/nvl-release fetch origin master
```

Verify the target commit:

```bash
git -C /root/nvl-release rev-parse origin/master
```

Never continue if the fetched SHA is not the release SHA expected for the deployment.

## 3. Create an isolated staging worktree

Example:

```bash
rm -rf /root/nvl-v1152-stage

git -C /root/nvl-release worktree add --detach \
  /root/nvl-v1152-stage origin/master
```

All tests are run here before production cutover.

## 4. Compile and test staging

```bash
cd /root/nvl-v1152-stage

/root/venv/bin/python3 -m py_compile \
  bot_final_v49-2.py \
  marzban_admin.py \
  v2ray_engine.py \
  edge_observability.py

/root/venv/bin/python3 -m unittest discover \
  -s tests \
  -p 'test_*.py' \
  -v
```

Deployment gate:

```text
compile success
+ all tests PASS
+ final unittest result = OK
```

If staging fails, production files are not changed.

## 5. Compare release files with runtime

Before cutover, identify what actually changed:

```bash
for f in bot_final_v49-2.py marzban_admin.py v2ray_engine.py edge_observability.py; do
    echo "===== $f ====="
    if [ -f "/root/$f" ]; then
        cmp -s "/root/$f" "/root/nvl-v1152-stage/$f" \
          && echo "same" \
          || echo "CHANGED"
    else
        echo "NEW FILE"
    fi
done
```

Only release/runtime files required by that version should be copied.

## 6. Final pre-cutover backup

Create a timestamped rollback directory:

```bash
TS=$(date +%Y%m%d-%H%M%S)
B="/root/nvl-backups/pre-v1152-$TS"
mkdir -p "$B"

cp -a /root/bot_final_v49-2.py "$B/"
[ -f /root/marzban_admin.py ] && cp -a /root/marzban_admin.py "$B/"
[ -f /root/v2ray_engine.py ] && cp -a /root/v2ray_engine.py "$B/"
[ -f /root/edge_observability.py ] && cp -a /root/edge_observability.py "$B/"

sqlite3 /root/master_bot.db ".backup '$B/master_bot.db'"
```

## 7. Production cutover

Keep the validation phase separate from the runtime cutover. Stop/restart the service only for the short file-replacement window.

Copy the validated files from the staging worktree:

```bash
cp -a /root/nvl-v1152-stage/bot_final_v49-2.py /root/
cp -a /root/nvl-v1152-stage/marzban_admin.py /root/
cp -a /root/nvl-v1152-stage/v2ray_engine.py /root/
cp -a /root/nvl-v1152-stage/edge_observability.py /root/
```

Recompile the **actual runtime files**:

```bash
cd /root

/root/venv/bin/python3 -m py_compile \
  bot_final_v49-2.py \
  marzban_admin.py \
  v2ray_engine.py \
  edge_observability.py
```

Then start/restart:

```bash
systemctl restart nvlbot
```

If the service was intentionally stopped before cutover:

```bash
systemctl start nvlbot
```

## 8. Post-deploy verification

```bash
systemctl is-active nvlbot
systemctl status nvlbot --no-pager -l
journalctl -u nvlbot -n 100 --no-pager
```

Required checks:

- service = `active (running)`
- Telegram application starts and polling/API calls succeed
- no traceback or repeated restart loop
- expected version/release behavior is present
- Phase 6C identifies the current Core as `CORE_LOCAL`
- perform feature-specific smoke tests for the release; for V115.2 this includes reseller V2Ray creation and subscription delivery

## 9. Rollback

If post-deploy validation fails:

1. stop `nvlbot`
2. restore runtime files from the latest `/root/nvl-backups/pre-<version>-*`
3. restore the DB backup only if the release changed/migrated DB state and rollback requires it
4. compile restored runtime files
5. start `nvlbot`
6. verify service status and journal

---

## Deployment invariants

- `/root/nvl-release` is the persistent Git checkout; `/root` is the production runtime.
- Always validate in a separate detached staging worktree before copying files to production.
- Always verify the exact release commit SHA.
- Always compile both staging and final runtime files.
- Unit/regression tests must pass before cutover.
- Always create a rollback backup before replacing production files.
- ENV and systemd configuration are **not part of the normal code deploy**. Do not modify them unless a specific release explicitly requires a configuration migration.
- Never mix SSH/TLS domain changes with V2Ray/Marzban endpoint changes.
- Production secrets, DB files, private keys and logs must never be committed to Git.
