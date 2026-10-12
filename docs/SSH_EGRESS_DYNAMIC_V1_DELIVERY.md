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
| H — session-to-ingress ownership | PAM_RHOST on Core checked against root-only wg0 Peer↔Edge registry and live WireGuard AllowedIPs; deny conflicting Edge for pinned UID | **Merged PR #96; Python + Stage-only CI PASS; NOT deployed** |
| I — Edge onboarding | Optional in existing `hp_addedge`: verify wg0 /32+public key, collision-screen new /30, stage Core and Edge, atomic H registry; readiness stays STAGED_NOT_READY | **Merged PR #97; Python + Stage-only CI PASS; OFF / NOT deployed** |
| J — 6H integration | Shared read-only F4-ready + sticky-UID HOLD gate in manual 6G and auto 6H; never invoke legacy Core DNS fallback | **J gate merged PR #98; positive application adapter on PR #99 (CI pending); live host driver and K acceptance NOT done** |
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

**H merged (PR #96). Next I (new Edge provisioning and root-owned ingress registry)**, then J (6H/drain transition), then K one controlled deploy/new Edge validation.

## H — Session/Ingress Binding (2026-10-12; merged code checkpoint)

**Scope:** V1 uses **sticky UID-to-Edge** rather than unproven per-socket cross-Edge routing. Every *new protected SSH authentication* must enter from the very same Edge that owns the UID's protected Egress table. Existing sessions may continue using the existing Edge during a 6H relay change; different-Edge SSH is DENIED until a safe idle/drain/rebind is explicitly performed. This knowingly prioritizes correct Egress over seamless immediate re-login during switch; J is responsible for transition policy, not H.

- `edge_egress_v1_ingress.py` (new): a fixed root-controlled `/etc/nvl-egress/v1-ingress-peers.json` maps each `edge_id`, public IPv4, **ingress wg0 source /32** (e.g. Miami `10.77.0.8`) and its WG **public** key. Reject duplicate IDs/IPs/keys, any source outside `10.77.0.0/24`, Core `10.77.0.1`, missing/unknown source, forged key, bad schema or untrusted file. It compares the actual PAM SSH TCP peer with the pinned UID's `edge_id+edge_ipv4` and live read-only `wg show wg0 allowed-ips` peer public-key → exact source /32 mapping. If another peer also covers that source, DENY. Pure registry renderer supplied for Edge-onboarding stage I; nothing installed or configured in H.
- `edge_egress_v1_admission.py`: existing root-only PAM hook now validates `PAM_SERVICE=sshd` and `PAM_RHOST` before allowing any **protected** UID; absent H ingress probe causes DENY even if F2/G database, DNS, route and readiness checks pass. Legacy (unprotected) users retain the previous F2 gate behavior, conditional on registry/DB being available. Root-only break-glass exception preserved. The PAM hook **must actually execute for dynamic TCP forwarding as well as shell auth** during the one K acceptance.
- `tests/test_edge_egress_v1_h.py`: seven offline focused cases for exact Miami ingress, relay switch old/new, unknown public/local peer, overlapping WG peers, registry collisions/tamper, protected admission without H evidence and failed WG inventory. Old F2 test fixtures explicitly inject the trusted ingress result; no new heavy CI workflow.

**Contract for I:** adding an Edge must record its actual `wg0` Core-observed /32 and WG **public** key in the root-owned ingress registry atomically, from the existing verified ingress WireGuard provisioning (never guessed from public IP). Readiness should remain HOLD unless the registry agrees with the live Core `wg0` peer. No secrets or private keys are placed in GitHub. **Contract for J:** do not repoint protected UID's Egress on active 6H/default/DNS change; refuse cross-Edge entry until old SSH sessions drain or a separately verified per-session routing mechanism replaces sticky UID. H itself makes no root route, PAM, DNS, DB or sshd mutation.

**Limit:** production E2E has not yet established whether every Core `sshd` connection's `PAM_RHOST` equals the Edge's `wg0` source (prior TCP snapshots showed `10.77.0.8` for Miami). If the Edge forwards without SNAT, it can instead be the originating client IP and the new protected login must fail closed, not silently guess. Kernel/SSH session handling for already authenticated clients, stream re-entrancy, BadVPN and full rollback are NOT claimed completed. K validates with a new Edge after code delivery.

### H merge acceptance and I handoff (2026-10-12)

[PR #96](https://github.com/DenaSon/nvl-bot/pull/96) **squash-merged** to `master` as `e40d812c4a11ceacd3edd8211f923563fa7080e4` (tested PR head `dbf05df8321e7726757b20e9c2eff4492e6d90d0`). Existing GitHub `Python checks` and `Edge egress stage-only checks` (3.11/3.12) all PASS. Seven new H tests cover correct ingress, wrong Edge/default relay switch, overlapping/unlisted wg0 sources, roster validation, missing proof, and kernel inventory failure. **No server changes, reboot, PAM install, protected accounts or real new-Edge acceptance yet.**

**I merged into master:** extends the **existing** `hp_addedge` / `_provision_new_edge` wizard without reimplementing WG0/DNAT. Securely capture/attest the Core-observed ingress wg0 peer source /32 and public key; atomically maintain `v1-ingress-peers.json` (root-only) with allocation/transport readiness when new Edge is provisioned. Persist dedicated Egress Stage and test readiness, without declaring an incomplete Edge customer-ready. Preserve existing Edge onboarding and rollback. No independent new Edge manager, no extra CI suite. **J later** must handle 6H switch while old pinned SSH sessions are live (hold/retry/rebind, not silent route rewrites). **K** remains the only planned real new-Edge end-to-end acceptance.

## I — Automatic Edge Provisioning (2026-10-12; merged code checkpoint)

**Scope merged on master (not installed):** In `bot_final_v49-2.py`, after the *existing* `_provision_new_edge_sync` finishes Ingress `wg0` onboarding and verifies its peer, opt-in setting `edge_egress_v1_onboard_enabled=1` invokes new `edge_egress_v1_onboarding.onboard_after_ingress`. Setting absent/`0` keeps legacy behavior. When enabled, incomplete Egress staging returns explicit HOLD and does not advance normal successful host_pool registration; the previously created ingress `wg0` peer and remote host may remain as partial state, so operator reconciliation is needed before retry. An Edge is **never declared READY** simply from staging.

- Source of identity: actual allocated `10.77.0.x`, public Edge IPv4, `wg0` public key returned from the existing installer and **live** `wg show wg0 allowed-ips` exact `/32` ownership. No use of current DNS, default relay or a guessed Edge key.
- Deterministic Edge Egress identity derived from the new ingress /32, e.g. `10.77.0.9` → edge id `e9`, `10.79.9.0/30` tunnel, `10.80.9.0/30` veth, UDP `52009`, route table `20009`. Existing preflight screens Core resource collisions. This range and exact allocation must be checked at real deployment; no migration of old `mia1` or unreviewed overwrite.
- Uses **existing `ops/edge_egress_provision.py`** stage generator: on Core, restricted stage directory with WireGuard private key; on Edge, only restricted remote stage files delivered over **pinned same SSH server public host key** as the existing onboarding connection. Stage files generated with new per-Edge WG keys. SSH/password/privkeys not stored in the H ingress registry/GitHub or returned to Telegram.
- After both stage directories succeed, atomically add an unambiguous root-owned entry to `/etc/nvl-egress/v1-ingress-peers.json`. Existing H registry must validate. No partial registry published. One root-owned lock controls concurrent registry writers.
- **No dedicated WireGuard startup**, systemd/PAM install, routing, protected UID attach or F3 `READY` promotion. Normal existing `record_ingress_candidate` still writes `INGRESS_ONLY` when available. This is deliberate: F1 Systemd guards and F2 Admission must be deployed together at K before routes/users are exposed; J must integrate actual dedicated Egress activation/readiness and 6H safely, not treat `STAGED_NOT_READY` as customer-ready.
- Legacy protected-mode `legacy_new_edge_gate` remains in place; J is responsible for opening only the guarded lifecycle once an Egress-ready transition and 6G handoff are genuinely supported. Default-OFF means previous onboarding is unaffected.
- Six isolated tests in `tests/test_edge_egress_v1_i.py`; no new CI workflow. Tests validate deterministic slots, invalid/ambiguous subnet, exact live wg0 ownership, wrong key/overlap denial, no remote on failed Core preflight and non-READY semantics.

**Known acceptance conditions still held for K:** existing Miami `mia1` needs separately reviewed legacy identity migration/backfill; no customer use until READY attestation, boot guard, real external SSH/SOCKS + Egress-IP match and one new Edge switch test. No Production reboot or customer migration under I source changes. Do not tell operators to flip `edge_egress_v1_onboard_enabled` before controlled K rollout.

### I merge closure and J handoff (2026-10-12)

[PR #97](https://github.com/DenaSon/nvl-bot/pull/97) squash-merged to `master` commit `185cba018f1de7c1fc00d1e85daa6eba62b8467d` (reviewed head `0d6f0da2c767c17e9a84aa9bf6a0bfa8d9e17e6d`). Both existing GitHub checks **PASS**: `Python checks` and `Edge egress stage-only checks` on Python 3.11 and 3.12. Only six small offline I tests added; no heavy new workflow. No Production config/deploy, customer migration, new Edge creation or live WireGuard mutation.

**Current development snapshot:** F1, F2, G, H and I are merged code only; Egress on Production is still the manually started Miami Canary, not reboot-persistent or customer-ready. Opt-in `edge_egress_v1_onboard_enabled` MUST remain OFF until K deploy. **Next J** must integrate new staged Egress and protected user routing with the existing 6G/6H journal/lock: authenticate readiness of a candidate before default/DNS change, ensure old sessions drain before sticky UID rebind, preserve protected fallback-deny, reconcile stage/frozen resources, and keep `READY` separate from `INGRESS_ONLY`/`STAGED_NOT_READY`. The current protected-mode `legacy_new_edge_gate` is still intentional and must be replaced only by a guarded path. J must not create a second failover controller. **Then K**: one controlled deployment and one NEW Edge real SSH/SOCKS test, with basic leak/rollback checks; no unbounded test loop.

## J — 6H Safety Integration (2026-10-12; merged safety-gate checkpoint)

**Narrow implemented scope:** the existing manual Phase 6G preflight and automatic Phase 6H evaluation use a shared, read-only protected switch classifier `edge_egress_v1_6h.py`. Existing `hpdef_*` / `hpdefmig_yes_*` callbacks still DENY protected legacy mutations, but now give a focused HOLD reason. Unprotected mode preserves the original legacy preflight/rebuild, with its independent 6G protections. No extra failover controller, scheduler, host migrations or new CI workflow.

- Source/target IPv4 must be distinct, existing F3 schema must exist, destination must have `INGRESS_ONLY` candidate identity and **fresh F4-production `READY`** readiness (`admission_eligible`: observed Edge public IP, witness, live TTL). `STAGED` and `VERIFIED_LAB` are **never eligible**.
- Inspect the full protected runtime intent and matching mapping. Any `BLOCKED`, `ROUTED_UNVERIFIED`, `FROZEN`, `HOLD`, missing mapping or mismatched schema remains HOLD. Any still-pinned `PROTECTED` UID forces `EGRESS_J_PINNED_UIDS_REQUIRE_DRAIN_REBIND`, including when global active relay changes frequently. **No reassigning `ssh_accounts.host`** or changing UID route/default as a side effect of 6H observation.
- The currently shipping legacy 6G engine must never execute after a protected preflight, even with fresh `READY`. With zero pinned UIDs and valid target, decision is still `EGRESS_J_PROTECTED_6G_HANDOFF_NOT_RELEASED`: the existing `edge_egress_handoff.run_protected_handoff` is still injectable-only, with no production cutover implementation. **The classifier is a safety guard, not the actual positive customer handoff.**
- J is wired BEFORE existing automatic candidate selection/incident start, so an unsafe automatic attempt does not start account rebuilding, fallback DNS, 6G operation or customer state mutation; logging uses a stable reason, no repeated new admin notifications.
- Tests `tests/test_edge_egress_v1_j.py` cover legacy isolation, invalid/missing schema, STAGED/LAB/expired evidence, F4 witness/IP mismatch, still-pinned UID, incomplete mapping, ready-but-unreleased and no DB write.
- No Production modifications, no dedicated peer start, no boot persistence, no customer migrations and no real zero-leak/failover acceptance from code merge.

**Production-release blocker and handoff to K:** For a genuinely successful protected switch (not just a safe refusal), a reviewed live `HandoffPorts` adapter to the SAME 6G lock/journal must provide: observed live ingress identity, current SSH session drain/idle for each affected UID, checked per-UID freeze and pinned-manifest/roster updates, separate target dedicated WG transport activation and externally witnessed same-Edge Egress IPv4, source/target readiness and CAS recheck, DNS cutover **Edge→Edge only**, recovery HOLD without opening Core fallback, and non-disruptive rollback. The legacy rebuild/DNS-to-Core routine remains forbidden. This is required as part of final integration/pilot acceptance **before** enabling protected automatic 6H; if not delivered, protected 6H must remain HOLD. Do not claim IP-fixed on active users just because a safety gate passes CI.

### J safety gate closure — NOT protected handoff release

[PR #98](https://github.com/DenaSon/nvl-bot/pull/98) merged into `master` as `f0df4fd01410e1cc03989f5b2ff80bd1de8941ea`, final reviewed PR head `26227a04b115bd019e33a98d1bb0cc15f98b3bc4`. Existing GitHub **Python checks** and **Edge egress stage-only checks (3.11/3.12)** all PASS. Includes nine focused new J cases, plus minimal legacy AST test-fixture compatibility updates. No new workflow, no Production changes.

**Explicit residual requirement before K rollout**: a positive, audited protected Edge-to-Edge transfer path with actual live implementation of existing `edge_egress_handoff.HandoffPorts`, using the same 6G operation/journal and account drain/per-UID repin. At present the J gate intentionally returns HOLD even for an otherwise READY new target; we did **not** silently enable the previous Core fallback. The final deploy/acceptance cannot be counted successful or enable auto protected failover until that separate positive path is implemented and externally proven on the NEW Edge. If this is not provided, leave protected failover disabled/HOLD and do not migrate customers.


## J2 — Positive Protected 6G Handoff Adapter (2026-10-12; PR #99 development)

**Scope delivered in source:** `edge_egress_v1_handoff_adapter.py` implements the application-side `HandoffPorts` integration for `run_protected_handoff(..., guarded_failover=True, require_admission_drain=True)`. It consumes ONLY the existing bot's `_db_acquire_failover_lock`, `_db_update_failover_operation`, existing SQLite schema, and independently supplied K-audited `HostActions`. It does not create a second lock, scheduling loop, DNS controller or new customer table.

Ordered J2 path: acquire 6G → snapshot exact protected active usernames/OS UIDs and source/default/DNS/F4 READY under lock → stage/prove target dedicated WG peer and live ingress → recheck identity and accounts → persist FROZEN runtime intent (F2 PAM denies new login) → prove all SSH sessions drained → install each per-UID fail-closed guard → repin boot manifest/roster and UID routing under protection via audited host driver → prove actual target IPv4 per UID while still admission-blocked → CAS update both runtime and binding, and exact SSH account host for the drained batch, keeping state FROZEN → Cloudflare public DNS DIRECT Edge→Edge, with no Core fallback → CAS update default host and DNS setting → verify real target ingress and each UID → release individual guards and commit final PROTECTED state → mark shared 6G SUCCEEDED.

**Crash behavior:** Every candidate-host-modifying and subsequent stage is protected against shared 6G stale-lock recovery, including F2 ADMISSION_FENCE, DRAIN_SOURCE_SESSIONS and EDGE_ONLY_PROTECTED_DNS_CUTOVER. Any uncertain failure after user mutation forces per-UID freeze, persisted HOLD where possible, and shared journal RUNNING/EGRESS_RECOVERY_REQUIRED for operator reconciliation. No automatic rollback to the Core public IP.

**Critically important distinction:** This is a **concrete 6G/DB adapter**, not yet a verified *live HostActions driver*. There is deliberately NO default network/SSH/DNS driver; `execute_protected_switch` refuses to run without one. The host driver must be implemented and operator-attested during K: actual SSH session/process drain after PAM barrier, root-owned updated manifest+roster and per-UID Linux policy/table migration with no other UID interruption, pinned Core/Edge transport start, fresh external per-UID IPv4 and IPv6/DNS/blackhole proof, direct DNS cutover verification, and local fail-closed re-arm under fault. Old J gate **continues to HOLD** protected automatic failovers; PR #99 is not authority to flip a Production feature switch or migrate customers.

**Tests:** `tests/test_edge_egress_v1_positive_handoff.py` has five small real-SQLite/fake-host cases (successful dual-UID guarded cutover, active-session HOLD, DNS fault recovery HOLD, invalid F4 READY refusal, no-live-driver refusal); existing protected lab-only tests retain their own distinct semantics and the positive adapter alone opts into mandatory admission/drain. No additional CI workflow.
