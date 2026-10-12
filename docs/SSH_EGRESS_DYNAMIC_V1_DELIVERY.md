# NVL — Dynamic SSH Egress V1 / implementation handoff

**Date:** 2026-10-12. **Status:** F1 merged to `master` via [PR #93](https://github.com/DenaSon/nvl-bot/pull/93), commit `0e9d976129cccbd47cb3ab6f9d14f93de468a64d`. **Product scope:** only Core-terminated SSH/SOCKS same-Edge IPv4 egress, fail-closed, frequently changing 6H active ingress, lifecycle of new Edges and safe incremental customer rollout. No Marzban, sales, Xray, wallet, extra controller or rewriting 6G/6H.

## Current real Production evidence (historical snapshot)

- Core `209.200.246.198`; Miami Edge `144.172.84.76`; dedicated live `wg-nvl-mia1`, Core `nvl-egress-mia1`, UID `nvl-egc1=1690`, routing table `1781`, terminal blackhole.
- `curl` under UID and ordinary **Windows → Miami:2252 → Core SSHD → SOCKS** both observed public egress `144.172.84.76`. Deleting only the user table's dedicated default led to `FAIL_CLOSED=PASS`; restoring it led to `EGRESS_RECOVERY=PASS`. Neither result attests WG peer-death behavior, DNS/IPv6 or reboot.
- Latest operator observation: `wg0` on both hosts is enabled. On Miami, **zero** `nvl-egress*` systemd units. On Core, only three unrelated `nvl-egress-pilot-*` static units; no managed Miami transport unit. Core `ssh.service disabled` but `active` (socket-activation behavior **not established**); `nvlbot enabled/active`, `wg-quick@wg0 enabled`. Do not modify SSH service enablement.
- Existing Miami Egress is **manually started**, and UID 1690 routing/IPv6/DNS guards were **manually added**. They are **not safely reboot persistent**. In particular, if UID selector disappears on boot the Canary may use the Core main default; **do not reboot Production or onboard customers before guard/admission gating**.
- Core local backup verified: `/root/nvl-egress-backups/core-20261012-153159-0MgVNi`. No verified offsite restore. Full evidence: [canonical V1 §14](SSH_EGRESS_V1_PRODUCTION_SCOPE_AND_EVIDENCE.md).

## Delivery stages (finish development first, deploy once, validate with a NEW Edge)

| Phase | Deliverable | Current |
|---|---|---|
| F1 — dedicated transport supervisor | One idempotent, hash-pinned, per-Edge state probe / start, simple offline systemd unit renderer; never uninstall active resources | **Merged / focused CI PASS and existing Python checks PASS** |
| F2 — fail-closed boot and admission | Durable protected UID roster, strict PAM gate, exact wg0 reply route, deny-first boot guard/unit candidates; no global SSH dependency | **Merged PR #94; checks PASS; NOT deployed** |
| G — shared-Edge multi-UID | Immutable Edge default + owner-scoped UID deny/release, multi-UID roster, opt-in shared DB reservation under 6G | **Merged PR #95; all final-head checks PASS; NOT deployed** |
| H — session-to-ingress ownership | Pin actual SSH sessions to real ingress Edge; prohibit ambiguous same-UID multi-Edge access until a verified per-session method exists | Not implemented |
| I — Edge onboarding | Extend existing `hp_addedge` ingress wizard with separate dedicated Egress allocation/stage/readiness, no changes to operational `wg0` | Not implemented |
| J — 6H integration | Manual and automatic active-relay switch must check Egress readiness and preserve old-session mapping; deny protected sessions when target unready | Not implemented |
| K — deploy + acceptance | One reviewed deployment after code complete, NEW Edge onboarding E2E, two-Edge switch, limited users, observed egress and negative-failure proof | Not started |

**Boundary:** Production customer migration is forbidden until F2 and the shared-table/ingress ownership path work. Avoid blanket re-running past tests. Build lightweight unit tests for each new behavior. Keep the existing `python-checks.yml` unchanged; no new heavyweight CI jobs. Each stage updates this file and `AGENTS.md` with actual implemented vs pending.

## F1 implementation (this commit, code-only)

- `ops/edge_egress_v1_transport.py`: accepts an existing generated stage directory from `ops/edge_egress_provision.py` (on Core / Miami, respectively `/root/nvl-egress-mia1-core-stage` and `/root/nvl-egress-mia1-edge-stage`).
- `fingerprint` computes a stable SHA-256 over four staged files. `inspect` and `ensure` require the same explicit digest and the exact stage role/spec. Root-only files, no symlinks, existing WireGuard peer/tunnel address, Core namespace+veth/default, or Edge listen port + labeled NAT are checked.
- `ensure`: exact already-running transport → no-op; no owned resources → explicit existing read-only preflight then stage `up.sh`; partial/mismatch → HOLD. **Never invoke down.sh or modify UID rules**, including on failed/uncertain start. The design is reusable for new Edge IDs; no Miami-specific condition.
- `render-unit`: generates a *candidate* systemd unit (OneShot with `RemainAfterExit=yes`, no `ExecStop`, no dependency on shared SSH). The agent is intended to be installed under `/opt/nvl-egress` and invoked with `python3 -m ops.edge_egress_v1_transport`; the unit is **not installed/enabled or started** by the script.
- Six small tests in `tests/test_edge_egress_v1_transport.py`: staged identity, tamper/mismatch, permissions/symlink, missing/partial, idempotency, refusal of destructive cleanup. Run: `python3 -m unittest -v tests.test_edge_egress_v1_transport`. No live network access required.

**Known F1 limitations:** The module is a transport-only component, not an installer, PAM gate or per-UID boot guard. It does not assert packets cannot leak via Core WAN and does not declare Edge `READY`. In particular the existing manually launched Canary is *not* made reboot-safe by merging or installing this module alone. A generated unit for an existing interface can only be adopted after operator verifies it is really owned by the staged Core/Edge pair. Full code delivery must complete before adding Production startup commands.

## Immediate next action

**F2 merged**. Next **G shared-Edge multi-UID**, then H/I/J and the one controlled new-Edge deployment. One dedicated new test Edge will be used for the final real end-to-end acceptance; no repeated general full-lab exercise after every tiny change.

### F1 acceptance record (2026-10-12)

PR #93 **merged** into `master` after successful checks on the final PR head `28d00d6c12beb60958ea5c3d677d3ed8dd6530c6`: `Python checks=success`; `Edge egress stage-only checks=success` (Python 3.11 and 3.12). Squash merge `0e9d976129cccbd47cb3ab6f9d14f93de468a64d`. This proves only source checks, not Production persistence or feature completion. **Next F2, no deployment yet.**


## F2 — Boot Guard / Admission (2026-10-12; code checkpoint)

**Status:** F2 source merged via [PR #94](https://github.com/DenaSon/nvl-bot/pull/94) (`29e66d7390c469b330e87eb06c7e741ece6b0b0e`); all checks on PR head `696ad265cf4b60a8af1d1e44880ad772b3017b7a` PASSED: Python checks, stage-only checks (3.11/3.12) and pre-existing disposable kernel lab. No Production PAM, systemd, protected roster, route, SSH, database, or reboot changed.

**Implementation:**
- `edge_egress_uid_route_state.py`: opt-in acceptance of only `10.77.0.0/24 dev wg0 scope link src 10.77.0.1` as safe ingress-return route; foreign WAN or duplicate routes stay rejected.
- `edge_egress_uid_boot.py`: optional `ingress_return=true` manifest; after IPv6/loopback-DNS blockers and terminal blackhole, add precise ingress reply route BEFORE the UID selector. During boot recovery remove only an owned Edge next hop; retain deny-only route.
- `edge_egress_uid_admission.py` and `edge_egress_uid_runtime_kernel.py` understand the same narrowly scoped return route; the latter arms guards with ingress-return support.
- New `edge_egress_v1_admission.py`: read-only PAM account hook. A separate root-only durable roster stores protected `username`, numeric UID, SHA-256 of the exact guard manifest. Roster ownership and identity checked before the existing F2 SQLite runtime/mapping/readiness/6G/Kernel/DNS admission. If protected DB intent vanishes the roster still forces DENY; no silent downgrade to LEGACY. Missing roster, broken DB, mismatched UID, uncertain kernel/6G state deny non-root; root remains an emergency exception.
- Pure roster/PAM-review/deny-only per-UID systemd unit renderers, no installer or SSH restart. Generated guard service has wg0 startup ordering, **not** global `ssh.service` dependency.
- Seven small isolated cases in `tests/test_edge_egress_v1_f2.py` for exact routes, boot ordering, legacy vs protected identity, deleted DB row, 6G lock, root exception, PAM/unit renderers.

**Deployment sequence (later K):** Validate independent root/admin recovery and backup; apply required existing F1/F2 schema under genuine 6G guard; install root-owned reviewed manifests and complete durable roster **before** DB protected intent; install/review PAM hook only with a rescue path; configure guarded per-UID boot units; attach only after kernel protection and full readiness. An unavailable roster or DB intentionally denies **all non-root SSH logins**; this is why PAM must not be hot-installed by a bot callback. Keep a protected account roster entry until its sessions are drained and all protected state is intentionally retired.

**Not yet solved:** F2 still uses single-user shared-Edge BootGuard freeze and roster restriction; G must implement non-disruptive multi-UID per-Edge ownership. Previously established SSH sessions cannot be revoked by a PAM account hook. Actual broken-WG peer and reboot acceptance, other Edge provisioning, 6H and customer rollout remain later phases.

### F2 closure and G handoff (2026-10-12)

**F2 is code-complete and merged, not Production-enabled.** Exact committed components: `edge_egress_v1_admission.py`, targeted `edge_egress_uid_boot.py` + `edge_egress_uid_route_state.py` compatibility, `edge_egress_uid_admission.py`, `edge_egress_uid_runtime_kernel.py`, and seven focused F2 tests. No host modifications were performed. The PAM hook and roster are *proposed root-owned deployment assets*, not currently installed on Core. `nvl-egc1` remains the manually routed Canary; do not reboot Core or switch real customers on F2 source merge alone.

**G merged. Next H (actual ingress/session identity)**, then I (new Edge), J (6H); one controlled deploy + NEW Edge acceptance in K.


## G — Shared-Edge Multi-User Egress (2026-10-12, merged code checkpoint)

**What changed:** one per-Edge dedicated WG tunnel and one shared Edge table, with **per-UID firewall OUTPUT owner REJECT** as the deny-only freeze. The Edge default is **not removed** by arming or freezing one subscriber. Explicit 6G lease/journal and F2 admission are retained; there is no second coordinator, DB, new daemon or CI pipeline.

- `edge_egress_uid_boot.py`: opt-in `shared_edge=true` in a protected manifest (requires `ingress_return=true`). FIRST installs/attests an exact UID-only IPv4 OUTPUT reject, then IPv6/local DNS guards, terminal blackhole, ingress reply route and UID selector. Existing protected Edge default remains attached. A frozen UID cannot send IPv4 traffic even if the shared default remains active. Old F2 single-user behavior is preserved for legacy manifests.
- `edge_egress_uid_runtime_kernel.py`: `arm()` installs the per-UID gate, `attach()` verifies owned shared route/guards before releasing ONLY its UID's reject, and `freeze()` inserts ONLY that UID's reject. Never deletes the shared table default when a protected user freezes; terminal blackhole + UID selector stay installed.
- `edge_egress_uid_runtime_store.py`: default rejects a second protected account exactly as before; `shared_edge_enabled=True` opt-in allows distinct UIDs to use the same Edge allocation after first user reaches a settled state. Rejects another in-flight `BLOCKED`/`ROUTED_UNVERIFIED` account, route-table conflict across Edges, duplicate UID/priority/DNS port. Same existing 6G `failover_operations` transaction and CAS path.
- `edge_egress_v1_admission.py`: roster can contain multiple UID manifests for one Edge if all share identical tunnel/route identity and have `shared_edge=true`; disallows cross-Edge route-table collisions or mismatched Edge specifications. The local admission guard also denies a frozen UID even when the shared route remains active.
- `edge_egress_uid_runtime.py`: updates only the contract documentation of per-UID freeze. No change to 6G journal orchestration.
- Focused tests extend the existing F2/kernel/store cases plus a tiny G-specific suite. No new CI workflow.

**Important boundaries:** `shared_edge_enabled` is OFF unless the rollout coordinator explicitly attests **all** active/proposed protected manifests for that Edge use G per-UID fencing. **Do not mix old F2 boot units that remove a shared route** with new multi-user manifests: migrate them before enrolling second UID. This is source-only until K. No protected customers were attached, production PAM/SSH untouched, no reboot and no evidence of actual WireGuard peer-death fail-closed or multi-Edge ingress binding. Account removal is HOLD/freeze, not an unfenced deletion. A single raw iptables owner rule is not a claim to cover traffic emitted on behalf of a user by privileged DNS/helper processes. H must resolve same-UID simultaneous ingress across different Edges before automated failover.

### G merge verification (2026-10-12)

[PR #95](https://github.com/DenaSon/nvl-bot/pull/95) squash-merged to `master`, SHA `222a782da9b4a6bbbb5c17aee248260540918a6d`; last reviewed PR head `583c1ff8c2697b4032e6a94823570baba7d65374`. GitHub CI PASS on that head: `Python checks`, `Edge egress stage-only checks` (Python 3.11/3.12), and existing `Edge egress disposable kernel lab`. One prior test run failed due to outdated blocked-simultaneous-UID Store assumptions; the tests were aligned to the new deliberate opt-in/sequential state contract, and **all final-head checks passed**. No new heavy CI workflow was added.

**Next action H:** detect actual ingress Edge per public SSH connection, bind/deny conflicting same-UID multi-Edge sessions while old sessions exist, do not depend on `dns_current_ip` or merely `ssh_accounts.host`. Preserve old sessions/fail closed under 6H switching. G source merge is **not** authorization to deploy, reboot, or mass-attach users; do that once code stages H/I/J are completed and reviewed for K.
