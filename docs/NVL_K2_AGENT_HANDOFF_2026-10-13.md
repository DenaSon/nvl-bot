> **2026-10-13 K2 Final Integration source WIP — [PR #120](https://github.com/DenaSon/nvl-bot/pull/120) (DRAFT, not merged/released):** User scope is ONLY old-style Telegram Edge onboarding + moving existing SSH users to new Edge with SAME public ingress/egress IP. Branch adds Wizard/detail `👥 انتقال کاربران` **read-only readiness** and repairs unguarded Round-Robin legacy host mutation; also adds an opt-in composite P3-A/UID protected route→same-6G account-host CAS HostPort, with fake-port tests. **No concrete accepted root worker, no Telegram execute callback, no authorized production batch migration, no release**; implementation is not complete until that executor and F4/VPS acceptance are real. Read [K2 final deploy & disposable VPS acceptance runbook](NVL_K2_FINAL_INTEGRATION_DEPLOY_ACCEPTANCE_2026-10-13.md). Preserve older P3-A–F merged status and separate code vs live evidence.\n\n# NVL K2 — Canonical Agent Handoff / Release Readiness

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
