> **LATEST IMPLEMENTATION PLAN / OPERATOR CONTRACT — 2026-10-14:** The previous **C1–C5 first, D1–D5 later** work sequencing is **SUPERSEDED**. Use [K2 Unified Migration M1–M7 with mandatory zero-CLI final acceptance](K2_UNIFIED_MIGRATION_M1_M7_RELEASE_CONTRACT_2026-10-14.md) as the **authoritative active development plan**. Build **Single and Batch together in M1–M5** on one engine and original 6G, keep Batch EXECUTE OFF, test **only** one Production UID `nvl0555/1636 → e9 45.61.163.75` in M6, then independently authorize M7 progressive group migration. M7 is **NOT DONE** while any ordinary provisioning, F4 evidence, roster, recovery, capacity, ingress transition, transfer or validation requires manually running SSH/CLI. No missing product-side functional blockers are acceptable at final sign-off. Genuine infrastructure failure must fail closed with an actionable in-app HOLD; independent provider rescue stays a disaster safeguard, not a routine UI workaround. Read [actual e9 live source/host/SSH evidence](K2_E9_PRODUCTION_CANARY_HANDOFF_2026-10-14.md) before implementation. e9 dedicated namespace IP PASSED, but customer UID Egress/PAM/F4 NOT accepted. No code or Production actions are authorized by this docs update; master is auto-deploying.

---

> **LATEST CORE PRODUCTION DEPLOYMENT — 2026-10-14:** The operator on `CloudVPS121849` reported **successful code-only publication** of exact K2 merged SHA `d5ca38b6e7069d969d8aa33bcb42ef71c8c63b2a`: 8 root modules replaced, 13 added, all 70 module hashes matched, `nvlbot` stopped and started, and the release script observed 10 seconds of active stable PID. Staging `/root/nvl-k2-stage-d5ca38b6e706`; live `/root/bot_final_v49-2.py`; release script `/root/nvl_k2_publish.sh` (host local, not in GitHub); rollback + immediate SQLite snapshot `/root/nvl-k2-predeploy-sJsySowp/`; curated Core backup `/root/nvl-emergency-backups/core-20261014T144432Z-x4EVRH`. User confirms VPS provider snapshot/console and a downloaded unencrypted backup. **Fresh post-deploy audit and Telegram smoke are NEXT**, not already observed. Prior “source only; not deployed” statements below are historical. No per-UID PAM/route/WG/6G or customer migration was authorized; F4 stays HOLD. Full [current release record](NVL_K2_CORE_CODE_RELEASE_RECORD_2026-10-14.md).

---

## AUTHORITATIVE CURRENT K2 HANDOFF — 2026-10-14 (supersedes historical checkpoints below)

- **GitHub merged state:** PR #120 (Phase 1/2/3 integration) MERGED, PR #139 (P3 packages 1+2 / first-UID installer + real Linux worker code) MERGED. Verified master source baseline at this checkpoint: 331fd86e399bd18e2f524071edb7f14d099e00de. CI on PR #139 head: 1,531 full Python PASS; 789 Edge stage-only PASS on Python 3.11 and 789 PASS on 3.12. Confirm the final docs merge HEAD before any staging.
- **Release boundary:** GitHub master is a code state, NOT proof of VPS deploy. Operational Production status remains unknown until live read-only inspection. All relevant P3 release defaults OFF, no root privileged UID execution via Telegram is automatically registered, no actual physical SSH/SOCKS public egress/no Core IP leak, IPv4/IPv6/DNS/NSS, WG loss, cold boot, provider rescue or restore has been accepted.
- **Phase 1:** New Edge wizard + original pinned Core/Edge stage, opt-in dedicated namespace transport and IP test code present; new VPS real first-pass test pending.
- **Phase 2:** UID source enrollment and all-protected atomic global mode/guarded 6G relay code present; mixed Legacy/Protected migration and full customer transfer remain gated on live PAM/F4 and verified cohort evidence. Accounts/passwords/Unix UIDs stay on Core; the target is *outbound Edge IPv4*, not migrating Linux accounts.
- **Phase 3:** ops/k2_p3_module_stage.py (SHA-reviewed root-owned readable Python import set), ops/k2_p3_guard_installer.py (first disposable UID only: deny-first isolated systemd/DNS and PAM-last CAS, rollback file), ops/k2_p3_uid_worker.py (original 6G/P3-A/P3-C/F2 and real Linux Kernel port, mandatory independent packet and other-UID probes) merged. **Cannot claim full Production release:** existing multi-UID protected roster CAS is not implemented, no independently accepted packet/nonleak witness or default live Telegram executor binding. These MUST NOT be invoked during code-only deploy.
- **Canonical deploy steps:** [NVL K2 SSH deployment and new-Edge runbook](NVL_K2_PRODUCTION_SSH_DEPLOY_RUNBOOK_2026-10-14.md). First read-only inspect real Core systemd/venv, currently deployed SHA, SQLite and RUNNING 6G; take snapshots of Core and *new* Edge + encrypted off-host backup and tested clone restore. Then pin exact master HEAD, stage/cross-check imports/production env, code-only replace with explicit manifest and controlled bot restart, finally test the dedicated namespace Edge public IPv4 through existing Telegram admin UI. Production users, default, Cloudflare, wg0, SSHD/PAM and UID routing unchanged. Actual protected UID acceptance must be proven on a disposable Core clone. #106/#108 remain OPEN.
- **Backup fix in this release:** ops/backup_nvl_host.sh NUL→newline inventory conversion corrected, test verifies actual tr arguments. An older backup script can fail its root archive coverage audit; never base Production backup on an unreviewed earlier copy.
- **History notice:** any older lines below saying PR #120 remains Draft, master unchanged, or no concrete Linux worker exists refer to *past source milestones*. Do not treat them as the latest status.

---
## 2026-10-14 — P3 packages 1+2: installer and real Linux UID worker checkpoint

See `docs/K2_P3_GUARD_INSTALL_AND_UID_WORKER_2026-10-14.md` and PR #139. Source code now contains `ops/k2_p3_module_stage.py` (independently SHA-pinned Python import closure staged as root-owned 0644 to permit non-root DoH), `ops/k2_p3_guard_installer.py` (explicit one-UID root-only roster+guard+isolated systemd DoH, deny-first with PAM-last CAS, durable PAM backup, real `sshd -T -C`, no global SSH restart), and `ops/k2_p3_uid_worker.py` (existing P3-A actor/chat/nonce/6G, F2 SQLite, P3-C and real `LocalLinuxProtectedRuntimeKernel`, mandatory outside packet/no-Core leak and other UID proof ports). All default OFF; no Telegram execute handler, no host deployment and no automatic un-fence. Fault injection tests include fake root filesystem and fake kernel positive/bad egress IPv4, deliberate 6G HOLD. **First-canary-only** roster installer still refuses an already-populated roster; multi-UID roster CAS and audited live root/SSH/SOCKS/WG-loss/cold-boot F4 remain unaccepted. Production test on a new Edge follows independent clone and snapshot acceptance; never claim a full release based solely on CI.

---
## 2026-10-14 — Production canary logical backup/restore release prerequisite

New checkpoint `docs/K2_PRODUCTION_CANARY_ROLLBACK_2026-10-14.md`: The existing root-only `ops/backup_nvl_host.sh` now captures **when present** the K2 V1 PAM/roster/BootGuard at `/opt/nvl-egress`, `/etc/nvl-egress`, stage/transport/key pins at `/root/nvl-egress-v1`, `/root/nvl-egress-staging`, `/root/nvl-egress-keys`, and deployed code tree `/root/nvl-release` (excluding caches). It enforces core identity-path coverage, produces a checksum-covered `diagnostics/archived-roots.txt` inventory, and retains SQLite online `.backup`/integrity. `ops/k2_canary_backup_gate.py` provides a read-only, root-only local tar/sha/SQLite/active-guard coverage inspection; `LOCAL_CONSISTENT` **never** grants live customer operations or verifies off-host encrypted copy, provider snapshots, console rescue, in-memory route/firewall rollback, or successful clone restore. Required separately: encrypted off-host copy, **full VM snapshots of both Core and Edge**, independent root/non-root console and tested disposable clone restore; stop/freeze-only recovery with retained 6G HOLD on kernel state uncertainty. First production test must be P1 *dedicated namespace transport-only*; real protected canary UID and any customer migration require independently reviewed installer/worker and external SSH/SOCKS/DNS/IPv6/WG-loss/reboot F4; #106/#108 open. Keep PR #120 Draft and release flags OFF.

---
## 2026-10-14 — Telegram new-VPS rehearsal page checkpoint

New K2 P3 stage-only bot panel: `🛡 مدیریت سرورها → Edge → 🧪 آزمایش VPS`. The original admin-only bot callback `hpeg_lab_<edge_id>` calls `edge_egress_k2_vps_lab.review_vps_lab`, a DB-only audit combining trusted H ingress, F3 staging, root stage pin metadata, default/DNS source, original 6G idle, Legacy/PROTECTED active SSH counts and F4 freshness. Safe navigation links to existing `hpeg_p1_probe_<edge_id>` **namespace** Edge public IPv4 (not UID SOCKS proof), existing per-user review, existing guarded relay review. Never mints F4, P3 ticket or host release; no mutation handlers or other bot. See `docs/K2_P3_VPS_LAB_TELEGRAM_2026-10-14.md`. Source-level work only; actual VPS canary with packet/F4 and root installer remains blocked by #106/#108. Keep #120 Draft and no master merge.

---
## 2026-10-14 — P3 read-only Core host witness checkpoint

Nested PR (P3 root host witness, see `docs/K2_P3_ROOT_HOST_WITNESS_2026-10-14.md`) composes live V1 root PAM module SHA/owner, per-connection `sshd -T -C`, trusted roster/guard, F3 source+target identity, real OS UID and source SSH ownership, fresh F4, original 6G availability, actual WG0 ingress validation, F4 UID Kernel+BootGuard+DNS, and V1 protected admission. It is a **root-only SELECT/inspection CLI** with zero server or DB writes. Result `LOCAL_PASS` is *strictly non-authorizing*, never packet/F4 customer ready. Offline SQLite/fake-observation regressions cover absence and drift; keep all P3-A/K2 operator release flags OFF. After CI, use an independently approved disposable VPS to collect physical SSH/SOCKS + packet/no-leak + reboot/failure evidence before building a tightly reviewed privileged mutating worker and Telegram execute binding. Parent #120 must stay Draft and unmerged to master.

---
## 2026-10-14 — K2 Phase 2 guarded all-PROTECTED promotion (feature-only)

Nested PR #133 adds `COHORT_PROMOTE` under original P3-A+6G: distinct source/target Edge identity, live source+target F4, exact all-active UID/runtime/binding/OS ownership, complete root-only roster/BootGuard and no foreign/legacy accounts, independent rescue/PAM/packet and failure/boot safety port. It executes a **single** SQLite CAS of `edge_egress_protected_mode: 0→1` only under the exact same original 6G RUNNING nonce/scope/phase and revalidates fingerprint and source/target F4 before/after the write. No host/DNS/host_pool/SSH mutation; no live port factory/Telegram execute registration. The original extracted production `_db_acquire_failover_lock` is exercised for source==target enrollment and protected P3 stale HOLD. See `docs/K2_PHASE2_PROTECTED_PROMOTION_2026-10-14.md`.

**NOT PRODUCTION READY:** rollout/fence failure must never claim a kernel freeze; source-only promotion explicitly leaves `frozen=false` in P3 recovery while holding RUNNING 6G. Real Linux root host safety, PAM/BootGuard and external DNS/IPv6/WG-loss/reboot proofs, source/target F4 and deployment of the runtime are still pending. Do not flip settings, register a mutating Telegram handler, or merge draft PR #120 to master. The existing J protected Edge→Edge handoff is a separate later manual operation.

---
## 2026-10-14 — K2 Phase 2 Source enrollment implementation (feature-only)

Nested PR #132 adds guarded **same-Edge Legacy → PROTECTED** source code: explicit P3-A `UID_ENROLL_SOURCE` action (same source/target IP only, global mode must remain `0`), fresh independent safety gates; `SameEdge6GUIDRuntimeStore` checks exact nonce/scope/action of the original 6G RUNNING lease and keeps the base F2 store unchanged; `GuardedSourceEnrollmentPort` rechecks whole-cohort Legacy snapshot under that lease before calling the existing P3-C deny-first UID lifecycle. No Linux accounts, public DNS, host metadata, default relay, global mode or original wg0 are changed by this code path. See `docs/K2_PHASE2_SOURCE_ENROLLMENT_2026-10-14.md`.

**Important: source/offline mocks are NOT an accepted live migration.** Source Edge itself requires F3 + independently attested F4, a separately verified complete PAM/roster/BootGuard and 6G operator rescue; existing production 6G acquisition with same source/target is still unverified, and external SSH/SOCKS + DNS/IPv6/loss/cold-boot evidence is still required. Do not register an execute callback, switch `edge_egress_protected_mode` to 1, or merge parent draft PR #120 into master. Current next work: final concrete privileged host safety provider + disposable-VPS F4 acceptance, then approved source enroll canary, eventually a separately gated mixed-mode→all-protected promotion followed by existing protected J handoff.

---
## 2026-10-14 — Phase 2 Legacy enrollment inventory (feature branch, not a release)

The nested K2 Phase 2 PR #131 adds SELECT-only `edge_egress_k2_legacy_enrollment.py` and shows Legacy/inconsistent UID counts in the existing Telegram relay review. It independently checks the current source Edge F3 identity, target F3, source/target F4, real OS UID/host, partial protected mappings, DNS and shared 6G busy status. Its fingerprint and audit are **not** a transfer ticket or F4 acceptance. See `docs/K2_PHASE2_LEGACY_ENROLLMENT_2026-10-14.md`.

**Critical remaining blocker:** existing P3-A/P3-C source-level UID_ATTACH assumes a distinct source/target Edge and protected mode already enabled. There is **no accepted same-Edge Legacy→PROTECTED bootstrap worker or mixed-mode migration**. Do not flip `edge_egress_protected_mode`, enable `k2_p2_relay_switch_enabled`, or merge draft #120 to master as though customers can migrate. Continue with independently reviewed 6G-scoped fail-closed enrollment design and disposable F4/PAM/Boot/DNS/IPv6 tests, then guarded one-user acceptance and batch cutover. No Production changes.

---

> **2026-10-14 — K2 Phase 2 source integration milestone:** PR #126 manual guarded all-PROTECTED Telegram relay cutover plus PR #128 Phase1→F3 allocation bridge have been merged **only into draft PR #120**, latest source checkpoint `65ed217264b227b08f7d6448c2895260ffe5c968`; independent read-only source cohort inventory also exists (#127). The existing 6G handoff performs deny-first per-UID egress repin, SSH idle/PAM guard, protected DNS Edge-to-Edge CAS and final host_pool/settings.hosts selection; the Phase1 Worker now writes original-public-key-pinned F3 `STAGED` allocation after dedicated IP evidence while avoiding early host_pool admission. **Source completion is not live acceptance**: cannot automatically convert/migrate Legacy mixed cohorts, F4 READY must be independently proven (not set from flags), PAM/BootGuard and real disposable VPS SSH/SOCKS, IPv6/DNS/packet loss/reboot proof are still outstanding. Feature switch OFF; no master/prod changes. See [Phase2 guarded cutover](K2_PHASE2_GUARDED_RELAY_2026-10-14.md).

> **2026-10-14 — K2 Phase 2 active development (source verified):** [PR #127](https://github.com/DenaSon/nvl-bot/pull/127) merged into draft #120 only, adding **read-only unique-default SOURCE-scoped SSH account inventory** and explicit OTHER-Edge/unknown-owner exclusion. Concurrently merged Phase-2 guarded manual all-PROTECTED relay Worker at source SHA `0637522f36b0ef368b13a1d8433ca1779ab3edd2`: existing protected 6G handoff and original K host driver, preflight F3/F4/SSH/WG0/DNS/UID/PAM/Boot, 90s admin/chat/Edge ticket, per-UID guarded routing, CAS account+default, Edge-to-Edge DNS and protected HOLD. Exact source CI: **1,374 Python tests PASS**, Egress Stage-only Python 3.11/3.12 PASS. **Not live tested; operator flag `k2_p2_relay_switch_enabled` defaults OFF. Mixed Legacy/Protected cohorts are blocked, not silently migrated; therefore Phase 2 is NOT accepted for existing mixed customers or production.** No master merge, VPS deployment or automatic Failover changes. Docs: [source cohort](K2_PHASE2_SOURCE_COHORT_2026-10-14.md), [guarded relay](K2_PHASE2_GUARDED_RELAY_2026-10-14.md).

> **AUTHORITATIVE K2 PHASE 1 SOURCE CLOSURE — 2026-10-14:** Draft PR #120 feature head `b48cf3989d42c24d9136e316d17589251e0e1de2` incorporates PRs #121–#123 and #125. **1,352 Python tests PASS** on final code; independent Stage-only Python 3.11/3.12 PASS. Single existing admin Telegram flow: Add new Edge -> immutable Core+Edge Egress Stage and SSH pin -> optional operator-released one-shot dedicated transport activation -> two-sided UP + exact Edge IPv4 proof -> independent fresh read-only `🌍 تست خروجی`. Final Worker now rechecks **specific shared 6G intent and both Stage hashes, unchanged active source, candidate still outside customer pool, and real ingress Stage after lease**, and never resumes RECOVERY. **Master/Production unchanged; no live VPS was tested; `k2_p1_transport_activation_enabled` defaults OFF.** Stage/transport/IP proof are NOT subscriber SSH/SOCKS proof or F3/F4 customer READY. No changes to Failover, auto transfer, original wg0, UID, DNS or default route. Next Phase 2: protected customer egress and relay switch, then Phase 3 Telegram/release/E2E. Canonical: [K2 Phase 1 transport](K2_P1_TRANSPORT_ACTIVATION_2026-10-14.md).

> **2026-10-14 — K2 PHASE 1 SOURCE CLOSED / LIVE ACCEPTANCE PENDING:** PR #123 merged into the still-draft PR #120 feature branch (not `master`), squash `168c4b240460f251652ac78f71c1b43b51a2bbe7`. Existing pinned transport Worker, restricted one-shot Telegram activation and exact namespace Edge IPv4 probe are now complemented by the `🌍 تست خروجی` per-Edge, fresh **read-only** post-start test. The probe requires BOTH owned Core/Edge tunnels UP, exact Edge public IP and post-proof reinspection; no subscribers moved and no new DNS/default/Failover/UID code. Worker independently rejects wrong IP from alternative proof implementations and invalid remote `ensure` results. P1 *code* is complete for controlled new-VPS deploy/test; boot persistence/real cold-boot, rescue, leak/SSH SOCKS/F4 customer readiness have NOT been tested and do not authorize Phase2 user cutover. Operator activation flag defaults OFF. Detail: [P1 transport implementation](K2_P1_TRANSPORT_ACTIVATION_2026-10-14.md). Keep #120 draft, never merge to production before Phase2/3 and live acceptance.

> **2026-10-14 — K2 Phase1 EXECUTABLE SOURCE update (supersedes prior Stage-only marker):** PR #122 merged into draft PR #120 source branch ONLY, NOT master. `edge_egress_k2_p1_worker.py` is a concrete root-only transport-only worker: immutable original Core+Edge Stage SHA/pinned SSH identity captured by existing Wizard, 6G shared journal intent/HOLD before remote/local NAT+WG start, one-shot admin confirmation and isolated Core namespace Edge-IP proof. Operator toggle `k2_p1_transport_activation_enabled` defaults OFF; partial errors retain RUNNING lock, no fallback. No customer moves/default/DNS/Failover changes, no automatic Stage activation. Source CI for PR #122 Stage-only 3.11/3.12 PASSED; full Python CI on branch after squash PASSED; check current head before release. **Phase1 code is wired, but no real disposable VPS activation or cold-boot acceptance has happened; a successful namespace probe does not prove SSH/SOCKS customer IP, PAM, F4, DNS/IPv6 or reboot persistence.** See [concrete worker handoff](K2_P1_TRANSPORT_ACTIVATION_2026-10-14.md).

> **2026-10-14 — K2 Phase 1 isolated wizard source checkpoint:** PR #121 was merged **into the feature branch of draft PR #120, NOT master**. Current PR #120 head `9ba26865da06d7cae5034ff2c154084b138ba959` passed Python checks (**1,335 unit tests**) and Egress Stage-only checks (3.11 and 3.12). New `hpeg_wizard` uses narrow admin-only protected-mode bypass, read-only IP/port/6G/duplicate admission, skips legacy root SSH password override/restart, and publishes Ingress plus dedicated Stage **without adding the candidate to active `host_pool`, `settings.hosts`, DNS, default relay or customer hosts**. Trusted registry-only candidate remains visible and Stage-inspectable in Telegram. **Not a full Phase 1 activation sign-off**: actual root-privileged dedicated transport/Boot/PAM worker, stage allocation+pin, verified new-VPS evidence and F4 release are outstanding. Failover and automated transfers untouched. Detail: [Phase 1 checkpoint](K2_PHASE1_ISOLATED_WIZARD_2026-10-14.md).

> **Legacy Relay semantics verified (2026-10-13, PR #120):** User's 'transfer users' means *route existing SSH/SOCKS traffic only*, not moving/deleting/rebuilding users or secrets. Legacy Edge `setup_edge_relay.sh` DNATs customer SSH/TLS to Core `10.77.0.1`; Legacy `hpdef_` updates default `host_pool/settings.hosts`; subsequent `hpdefmig_yes_` changes `ssh_accounts.host` and Cloudflare ingress DNS, but **does not change UID internet Egress**, which can remain Core public IP. **Emergency 6G Failover is a different, account-rebuild/Core-fallback path and must not be reused.** This PR now adds `🔀 تغییر مسیر ترافیک` read-only review in Wizard and Edge details and keeps direct Linux account recreation OUT of scope. Implementation is not yet live-executable: independent Worker, Stage/F4, mixed-mode safety and VPS acceptance remain open. Full evidence: [Legacy traffic contract](NVL_K2_LEGACY_TRAFFIC_SWITCH_2026-10-13.md).\n\n> **2026-10-13 K2 Final Integration source WIP — [PR #120](https://github.com/DenaSon/nvl-bot/pull/120) (DRAFT, not merged/released):** User scope is ONLY old-style Telegram Edge onboarding + moving existing SSH users to new Edge with SAME public ingress/egress IP. Branch adds Wizard/detail `👥 انتقال کاربران` **read-only readiness** and repairs unguarded Round-Robin legacy host mutation; also adds an opt-in composite P3-A/UID protected route→same-6G account-host CAS HostPort, with fake-port tests. **Opt-in one-user Telegram execute confirmation is source-wired but not available by default: no registered/accepted concrete root worker, no authorized production batch migration, no release**; implementation is not complete until that executor and F4/VPS acceptance are real. Read [K2 final deploy & disposable VPS acceptance runbook](NVL_K2_FINAL_INTEGRATION_DEPLOY_ACCEPTANCE_2026-10-13.md). Preserve older P3-A–F merged status and separate code vs live evidence.\n\n# NVL K2 — Canonical Agent Handoff / Release Readiness

**Updated:** 2026-10-13 (Asia/Tehran)  
**Repository:** `DenaSon/nvl-bot`; **branch:** `master`  
**Source baseline before this documentation update:** `22eba3cda13c0c72407bd3d55d7328ae93496d25` (P3-F PR #118)  
**Authoritative status:** K2 Phase 2 + Phase 3 **A–F source and offline CI complete**. **NOT** live feature activation, end-to-end F4 acceptance, worker readiness, or Production deployment.

> This is the **first document to read in a new coding-agent session**. `AGENTS.md` points here. Where older README, `AGENTS.md` historical paragraphs, K1/K2 notes, `EDGE_EGRESS_CURRENT_HANDOFF.md`, or chronological project memory name outdated next actions, **this checkpoint takes precedence**. Historical evidence remains evidence, not an up-to-date observation.

## 1. Hard boundary: source ≠ deployed ≠ accepted

| Layer | Status | What evidence means |
|---|---|---|
| GitHub `master` | Phase 2 + P3-A/B/C/D/E/F merged | PR-head Python / Edge stage-only CI PASS |
| Telegram new K2 UI | Implemented in source, **not yet deployed as this bundle** | Existing `hpeg_*` callbacks with two-column Persian UX |
| P3-A–E protected executable flows | **Default-off / no reviewed concrete live privileged worker** | Mocked/injected interfaces and fail-closed tests, not production commands |
| F4 independent live acceptance | **OPEN**: [#106](https://github.com/DenaSon/nvl-bot/issues/106) | Requires real disposable full-system Core/Edge tests |
| Overall guarded lifecycle / rollout | **OPEN**: [#108](https://github.com/DenaSon/nvl-bot/issues/108) | Integration, Worker review, operator-approved rollout |
| Production Core | **Not upgraded by P3 source work** | Previous operator-stated K2 runtime pin: `2988d0d71f8c65d10a1fb1c7e133ddf0bc7fc698`; independently verify *read-only* before any deploy |
| e7 metadata | Manually retired; backup confirmed | Does **not** imply old e7 kernel/netns/VETH/UID resources removed |

**Do not claim** F4 READY, operational protected Failover, completed kernel deletion, production parity, or customer-ready routing based on source merges, Stage SHA, a Telegram review receipt, manual DB flags or a single public-IP trace.

## 2. Completed source milestones — exact provenance

| Milestone | PR | Squash merge SHA | Scope |
|---|---|---|---|
| K2 Phase2: safe Edge metadata retirement | [#112](https://github.com/DenaSon/nvl-bot/pull/112) | `93c4c33d936a2afd6d5459b3b573f0b0ed0b6e53` | Existing admin UI, backup-first guarded metadata deletion; old delete bypass blocked |
| P3-A | [#113](https://github.com/DenaSon/nvl-bot/pull/113) | `f14396c623dcadc7e0cdf9c4ae8d34d55185f5f0` | One 6G RUNNING lock/journal, allowlisted intent, ticket/nonce, manual crash recovery |
| P3-B | [#114](https://github.com/DenaSon/nvl-bot/pull/114) | `8ddfa415823520d47df52efb46bb2a2996198493` | Pinned Core Stage, deny-before-transport Boot/PAM/DNS/systemd review and injected port |
| P3-C | [#115](https://github.com/DenaSon/nvl-bot/pull/115) | `3b3a274d4e41e619dff2dfbbab888de90db19cd0` | Per-UID guarded enroll, emergency freeze and FROZEN→PROTECTED resume with F2 CAS |
| P3-D | [#116](https://github.com/DenaSon/nvl-bot/pull/116) | `9d27f9b1c302e4c8ec4855980fba8342b2c2428e` | 6G/6H Egress-only separation, pinned Cloudflare multi-record best-effort CAS, cancellation HOLD |
| P3-E | [#117](https://github.com/DenaSon/nvl-bot/pull/117) | `1343a476c9e912f2b1ae698af1710e73edf8b248` | Orphan-only owned-resource retirement contract; UID REJECT/blackhole preserved |
| P3-F | [#118](https://github.com/DenaSon/nvl-bot/pull/118) | `22eba3cda13c0c72407bd3d55d7328ae93496d25` | Existing admin `hpeg_*` Telegram callbacks, minimal two-column Persian UI; orphan read-only listing |

[#118 Python checks](https://github.com/DenaSon/nvl-bot/actions/runs/38387773638) and [Edge stage-only checks](https://github.com/DenaSon/nvl-bot/actions/runs/38387773747) both succeeded on the PR head. No Production or physical packet testing is implied.

### Key code map for the next agent

| Task | Source of truth |
|---|---|
| Main bot/admin `hpeg_*` callbacks | `bot_final_v49-2.py` |
| Operator UI text, two-column layout | `edge_egress_p3_telegram.py` |
| Existing Edge dashboard / proofs | `edge_egress_phase2_console.py`, `edge_egress_phase2_review.py` |
| Safe **metadata only** retirement | `edge_egress_phase2_retire.py` |
| Shared 6G guarded executor/intent/recovery | `edge_egress_p3_executor.py`, `edge_egress_handoff.py`, `edge_egress_6g_bridge.py` |
| Prepared boot/transport guard | `edge_egress_p3_boot.py`, `edge_egress_uid_boot.py`, `edge_egress_uid_systemd.py`, `ops/edge_egress_v1_transport.py` |
| Protected UID state/kernel and CAS | `edge_egress_p3_uid.py`, `edge_egress_uid_runtime_store.py`, `edge_egress_uid_runtime_kernel.py` |
| Dedicated Egress-only vs Ingress+Egress transfer | `edge_egress_protected_6g6h.py`, `edge_egress_v1_handoff_adapter.py` |
| Provider/6G gated DNS cutover | `edge_egress_p3_dns_cutover.py`, `edge_egress_v1_cloudflare.py` |
| Orphan-only stage-bounded teardown | `edge_egress_p3_retire.py` |
| Independent acceptance tooling | `edge_egress_f4_preflight.py`, `edge_egress_f4_pam.py`, `edge_egress_f4_kernel_audit.py`, `edge_egress_f4_release.py` |

Detailed design decisions: `docs/K2_PHASE3_A_GUARDED_EXECUTOR_2026-10-13.md` through `docs/K2_PHASE3_F_TELEGRAM_FINAL_UX_2026-10-13.md`. Phase2 UX and retirement docs remain relevant.

## 3. Invariants — never break these

1. **Ingress is not Egress.** Existing Edge relay exposes customer SSH/TLS through `wg0` and Core SSHD; `ssh_accounts.host`, `host_pool.is_default`, Cloudflare public DNS and a Linux UID's selected Egress are **distinct authorities**. One field update does not migrate protected traffic.
2. All protected host writes require the **same existing 6G persisted lock** and `failover_operations` journal, exact owned resource scope, actor/chat/TTL-bound authorization, independently verified current evidence and a recorded protected intent **before** mutation. Replay, crash, cancellation or uncertainty leave `RUNNING`/operator HOLD, not hidden unlock or automatic Core fallback.
3. **Single UID freeze != Edge-wide freeze.** Protect and preserve other UIDs, shared Edge table, existing `wg0`, public SSH service, Core default route, DNS and legacy mixed customer population. For affected UID preserve exact owner selector, IPv4/IPv6 OUTPUT REJECT and terminal blackhole even after orphan transport cleanup.
4. Positive `FROZEN → PROTECTED` resume demands real F4/admission/boot/actual remote egress IPv4/DNS/NSS/IPv6 evidence; Emergency Freeze must not require healthy Edge/PAM/DNS or an idle session.
5. **Egress-only 6G/6H does not change public DNS.** Full Ingress+Egress transfer requires admission fence, session drain, target F4, owned UID repin, independent proofs and Cloudflare reread. Cloudflare multiple PATCH calls are **not atomic**; any partial/uncertain mutation => users FROZEN and manual reconcile, no automatic rollback to Core.
6. Telegram stays admin-only and minimal. UI may inspect/preview and may use the preexisting Phase2 *metadata-only* delete with its strict checks; protected provisioning, UID attach/freeze, cloud cutover and P3-E kernel teardown are **not connected** to a live privileged worker. No technical/developer status strings in user-facing Persian bot UI.
7. Do not restart global SSH, change `wg0`, flush `iptables` or routes/rules, change Cloudflare or `dns_current_ip`, turn on global protected mode, reboot Production, migrate arbitrary users, or launch automatic protected 6H without independent acceptance and explicit approval.
8. Never commit or paste private WireGuard keys, SSH passwords, API/Telegram/Cloudflare tokens, databases, secrets or customer data. Use redacted, read-only diagnostics.
9. Preserve the user's chosen development order: finish/source-review guarded interfaces, run CI, then an isolated disposable lab with out-of-band rescue and F4 acceptance, then **one** pinned controlled Production release and **separate** canary activation. No live tests or destructive commands merely to validate source work.

## 4. Production evidence: New York e7 is now a retired orphan

Earlier `docs/SSH_EGRESS_K2_E7_MEMORY_2026-10-13.md` recorded a successful **historical** iPhone SSH/SOCKS request exiting via `172.86.105.67`. Later the provider deleted e7. An operator manually retired its ingress Registry and F3 candidate metadata with:

- Result: `E7_REGISTRY=RETIRED`, `E7_F3_CANDIDATE=RETIRED`, `NETWORK_RESOURCES=UNCHANGED`, `UID1644_FENCE=UNCHANGED`.
- Backup: `/root/nvl-backups/e7-retire-pRfWH19n`.
- Core: `CloudVPS121849`, `209.200.246.198`.
- Previous last-known remnants: namespace `nvl-egress-e7`, VETH `vnh-e7`, dedicated `wg-nvl-e7`, UID `nvl0557`/1644, RPDB priority 1782/table 20007 with terminal blackhole, IPv4 REJECT observed. These are **historical observations**, not fresh host attestations.
- At last production read-only query `dns_current_ip=144.172.84.82`, default active `144.172.84.82`, global protected mode `0`, no RUNNING 6G operations. Another Miami UID1690/table1781 is completely separate and must never be touched.
- `nvl0557` has a historical *different* `ssh_accounts.host` entry; user describes it as disposable test account, **but this does not authorize account deletion or unfencing**.

**Open:** IPv6 OUTPUT REJECT proof, exact Stage hash/provenance after metadata retirement, root-only systemd/netns ownership and persistence, active sessions, all UID references and BootGuard behavior after reboot. **No actual e7 kernel teardown performed.** P3-E's source-only host port is *not* permission to run old `down.sh` or delete `vnh-e7` now. Read-only reconciliation first.

## 5. Next work — strict order and acceptance gates

### R0 — Source/release audit (no Production changes)
- Fetch fresh `master` SHA and open PRs/Issues; check no unexpected commits or deployment. Audit the **end-to-end chain**, including the boundaries between P3-A's generic interface, P3-B/C's independent safety ports, P3-D DNS gate and P3-E owned retire port.
- Inventory **missing concrete privileged Worker/HostSafetyPort** and release wiring rather than assuming the merged mock interfaces make the feature operational. Check root ownership, command allowlist, stage SHA/SSH host key pin, idempotency, atomic journal/rollback semantics, lease recheck immediately before every external write and exact per-resource scope.
- Ensure no shadow execution path in legacy bot handlers. Preserve protected 6H HOLD until genuine positive canary evidence. Prepare narrowly reviewed worker PR(s) with offline fault tests, **no Production execution**.
- Build deployment manifest from an exact Git SHA: changed files, dependencies, Python version, `systemd`, SQLite schema, backout criteria and bot smoke tests; reconcile old Core-only hotfixes and current runtime **read-only**. Do not infer GitHub and Core are identical.

### R1 — Disposable full-VPS F4 and fail-closed drills ([#106](https://github.com/DenaSon/nvl-bot/issues/106))
- Only on isolated, purpose-built Core/Edge lab, with non-production credentials/IP/DNS, **out-of-band root rescue**, healthy non-root admin, and reviewed backups/restoration.
- Install/review PAM F2/H + root-owned roster/guard, independent per-UID DNS/DoH, BootGuard/systemd ordering before SSH customer admission; verify actual normal SSH, `SSH -D` SOCKS, `direct-tcpip`, mixed-user separation, external same-Edge IPv4, DNS UDP/TCP/NSS, IPv6 and packet capture no-Core leak.
- Perform **dedicated WG loss**, failed-Edge reboot, recovery, 6G lock-loss/replay/cancellation, Cloudflare partial record update/propagation, orphan/active Edge teardown with ownership controls and successful rollback/rescue. Record external evidence with times and hashes.
- A green mock CI run or locally attested `READY` is **not** F4 approval. Independent review must accept evidence before root-worker release.

### R2 — Controlled Production release ([#108](https://github.com/DenaSon/nvl-bot/issues/108))
- Operator approves pinned release and explicit change window. Snapshot backups, rollback staging and independent console access before touching Production.
- Code rollout separately from feature activation: deploy pinned files, compile/test, restart only the approved bot service if needed, check Telegram menus and legacy flows; keep all P3 privileged execution gates OFF initially.
- Run read-only Core/DB/route/UID/SSH/WG/DNS baseline before and after; enable only an explicitly approved disposable UID and one qualified Edge, then external no-Core-leak + fail-closed probes.
- Follow protected 6G journal and stop/hold on any drift. **No automatic 6H**, no all-user rollout, no unverified orphan delete. Record verified host version and updated status after deployment; close Issues only for gates independently satisfied.

### Stop conditions / next assistant response
If no fresh host evidence is available, only plan source diffs or issue read-only inspection; do not claim evidence. If real privileged Worker is missing, **say it is missing** and write/test it in an isolated PR. Do not perform live actions until explicit operator permission for that exact test/deploy. Do not promise direct SSH execution via the GitHub connector.

## 6. Agent/document workflow

- Start with `AGENTS.md` → **this file** → `docs/NVL_PROJECT_MEMORY.md` → appropriate P3 module doc and code/tests. For prior e7 proof use `docs/SSH_EGRESS_K2_E7_MEMORY_2026-10-13.md` **only as historical evidence**.
- Keep feature scope closed; no new framework, second dashboard, alternate 6G lock, or unrelated SSH/V2Ray changes.
- Each change: pinned `master` → branch → narrow diff/test → CI at exact PR head → review → merge; update this document/AGENTS/Memory with **only actual outcomes** at meaningful milestones.
- Clearly separate: **merged source**, **deployed files**, **verified live behavior**, **operator authorization**. These are four different states.
