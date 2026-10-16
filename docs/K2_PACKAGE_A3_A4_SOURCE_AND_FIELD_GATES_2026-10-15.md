# NVL K2 — Package A3/A4 source handoff and field blockers (2026-10-15)

**Branch:** `feature/k2-m4-telegram-root-portal-20261014`; **PR:** #148 (Draft, stacked on M1/M2/M3). No production deploy, no master merge, no root worker activation, no bot UID change, no M2/P3/6G side effects.

## Added source deliverables

### A3 — honest privilege inventory
- `edge_egress_k2_a3_privilege_audit.py`: AST-only review of the **actual legacy bot** to surface privileged subprocess, OS mutation, dynamic shell/command and indirect execution callsites, with exact source SHA and line/function names. **This is conservative static analysis, not a complete dataflow/security proof.**
- `ops/k2_a3_privilege_inventory.py`: a read-only inventory CLI. It outputs `state=HOLD`, enumerates code review leads, and intentionally exits 78. No subprocesses, service restart, chmod, usermod, SQL or Telegram polling.
- `tests/test_edge_egress_k2_a3_privilege_audit.py`: synthetic sink coverage; actual checked-in legacy bot is parsed and is never implicitly certified safe for nonroot execution.
- **Still blocked:** existing bot owns historical privileged SSH/account/payment/host actions. Merely changing `nvlbot.service User` breaks compatibility. The actual feature-to-permission graph, reviewed root RPC surface for every privileged feature, bot user cutover, real current-session admin authorization (not historic `admin_chat_ids`), and rollback safety require a separately reviewed A3 operational checkpoint. Preserve **one Telegram polling bot**.

### A4 — off-Core witness artifact hardening
- `edge_egress_k2_a4_observer.py` builds the existing strict M42 signed wire protocol only from a complete tuple of **independently measured** artifacts: one receipt per mandatory check (client SSH/SOCKS/IPv4, DNS UDP/TCP, NSS/IPv6, Core packet/no-leak, source sessions, boot guard, WireGuard-loss, console rescue and neighbor isolation). All proofs must name the exact Edge, target IP, run ID, evidence hash and age. Fail/stale/missing/duplicate/incorrect observed IP => HOLD. Active sessions cannot be guessed as zero.
- A nonroot-only signer **separate from the Core** accepts only these complete typed observations, uses a fixed off-Core private-key path, and signs exactly the rendered canonical bytes with OpenSSL detached RSA signature. It does not accept arbitrary boolean JSON passed from Telegram/Core. Signing gate defaults `False`.
- `tests/test_edge_egress_k2_a4_observer.py` covers missing/stale/tampered/wrong-scope reports, forged zero sessions, all required checks, and real disposable OpenSSL signature verification in nonroot CI where OpenSSL is available.
- M42's existing root consumer reads root-pinned **public key** only and verifies the exact signed bytes. The private key must **never** be installed on Core.
- **Still blocked:** this protocol is not a physical probe implementation. Only independent Core/Edge/client/console observers can produce truthful raw measured artifacts; a self-attested `PASS`/hash does not prove a SOCKS packet route. M5 must validate the actual collector methodology and inspect original raw captures before approving live release.

## Release invariant

**All original execution flags remain source-default OFF.** Existing `ops/k2_m4_root_daemon.py:main` intentionally exits 78. A3/A4 tests do not enable the root listener, impersonate a production external witness, convert the root legacy bot, alter original 6G or release cross-Edge mixed-Legacy `UID_ATTACH`.

## Explicit phased remaining work

| Phase | Acceptance required | Type | Status |
|---|---|---|---|
| A3.1 Host provider | Read actual reviewed M2 First/Nth manifest, root-owned PAM/module/roster/service snapshots; construct locked `ReviewedUIDHostSnapshot`, no pre-6G writes | Code + disposable host test | HOLD |
| A3.2 Admin and bot privilege | Complete existing bot privileged-callsite inventory, root RPC per allowed operation, nonroot one-bot transition, live actor/chat/session recheck, restart/rollback test | Code + systemd acceptance | HOLD |
| A4.1 External probe agent | Independent *real* SSH/SOCKS, packet capture, DNS/NSS/IPv6, active-session, WG-loss/reboot/rescue/neighbour checks; raw receipts and off-Core signer | Code + external server | HOLD |
| A4.2 Physical verification | Verify generation/timestamp/digest + witnessed source and target IP against raw captures; no-core leak, no stale/forged proof | Field acceptance | HOLD |
| M5 | Disposable new Edge/VPS + one non-customer UID, prove egress Edge IP on device and failure containment | Field | NOT STARTED |
| M6 | Manual recovery/unknown-inflight, boot/WG cut, mixed-Legacy neighbors, static security review, canary gates | Code + field | NOT STARTED |
| M7 | Bounded batch <=10 with capacity/F4 gates and double admin confirmation; UX polish + explicit staged release | Code + field | NOT STARTED |

**Classification:** Package A source security improvements are delivered here, but Package A as a whole **must not be marked operationally complete** until A3/A4 physical dependencies have passed. Reducing an unresolved gap to a Type/interface is useful but does not constitute a working installed root provider or an independently verified packet observer.

**CI evidence:** linked to the exact final SHA in the PR conversation, never reused from an earlier SHA.


## A4.3 — Mandatory raw-measurement byte attestation (2026-10-15)

The off-Core signer now refuses to sign even an otherwise valid complete set of `PASS` measurement receipts unless **all corresponding raw capture files exist and exactly match their submitted SHA-256 and claim metadata**. This closes the prior weak boundary where the signer could accept only an asserted hash without possessing any original measurements.

- New independent default-OFF gate `A4_RAW_ARTIFACT_INTEGRITY_ENABLED=False`, separate from `A4_OFFCORE_SIGNING_ENABLED=False`. The signing path calls `verify_raw_artifacts` **both before and after** the OpenSSL detached-signature operation, and never signs when a raw artifact is missing, mutated, stale, wrong-scope or incorrectly owned.
- Raw file paths are fixed under the off-Core `/var/lib/nvl-observer/raw/<run_id>/`, derived only from strictly validated probe/session IDs. Each has exact-key metadata and nonempty `capture` text. Probe files: `probe-<probe_id>.json`, session files: `session-<username>-<uid>.json`. Files must be owner-only, regular, single link, and non-symlink; parent directories owner-only. The signer private key is still off Core; no live SSH/WG/PAM interactions are added.
- Disallows missing raw source, symlink, digest mismatch, duplicate/forged metadata, changed scope and untrusted modes. This is a cryptographic integrity control, **not** independent verification that the raw text actually came from a client or host packet capture. The existing `capture` field is an auditable raw evidence carrier; the external measurement *method* remains a required M5 field deliverable.
- Regression tests include raw missing/tamper, mode changes, mismatched claims, source-default OFF, and off-Core real detached RSA sign/verify with disposable CI keys.

**Operational status is unchanged**: A4.1 actual independently operated SSH/SOCKS/DNS/NSS/IPv6/Core packet/WG-loss/console probes and review of their source still remain HOLD. A3.1/3.2 remain HOLD. This code must not be used to mark the F4 physical proof READY, unlock 6G or deploy.


## A3.1 — Real root-owned read-only first/next UID plan input (2026-10-15)

`edge_egress_k2_a3_host_plans.py` now implements `RootOwnedM2PlanSource` behind **`A3_ROOT_OWNED_PLAN_SOURCE_ENABLED=False`**. It reads the prospective UID's approved manifest only from the hardcoded owner-only `/etc/nvl-egress/k2-m4/uid-plans/<username>.json`; checks effective root identity, exact `UID_ENROLL_SOURCE` and P3 ticket scope; reads installed `/etc/pam.d/sshd`, the original pinned M2 module, Linux UID and current M2 roster using owned/no-follow readers.

- **First UID**: checks for zero prior guard files *and* zero entries in both existing protected UID tables. A missing roster alone is not trusted. Calls the existing pure `plan_guard_install` with exact current root PAM bytes and SHA.
- **Next UID**: loads every existing root-owned guard by its current roster identity, verifies each SHA and the complete original roster's canonical bytes, then calls existing pure `plan_next_uid`. Unknown, existing, partial, orphaned, symlinked, changed or unowned state is HOLD.
- Returns the immutable `ReviewedRootM2Plan` and **does not provide physical F4/PAM/packet safety callbacks, install any M2 artifacts, launch a root service or alter the existing 6G lease**. It is preparatory input to a later vetted `ReviewedUIDHostSnapshot`, not a drop-in ready-to-deploy live host factory.
- The file is now included in the sealed root-worker source SHA manifest. Synthetic tests cover default-OFF, wrong root/scope, first/next plans, old protected UID, and root-roster byte drift.

**Still required to close A3:** on-host reviewed gate binding for the generated plans, independent external packet/console evidence; dedicated privilege-safe RPC for existing legacy bot root features, admin live-session authority and a proven one-bot nonroot cutover. CI without an audited live Core/Edge cannot assert these items.

## A3.1 follow-up — strict root inventory reconciliation (2026-10-15)

Scope: **fix an existing M4 migration safety gap, no feature expansion**.

- For an existing protected roster, `RootOwnedM2PlanSource` now requires the entire root-owned Guard directory inventory to equal the exact `<username>.json` set derived from the verified roster. An orphan, missing guard or partial first/next UID stage stops NEXT_UID before building a plan; no implicit repair/adoption.
- The next-UID planner also checks both original F2 tables (`edge_egress_uid_runtime` and `edge_egress_uid_bindings`): an existing row for the selected username **or numeric UID** outside the approved root roster stops the plan. Missing tables, unreadable DB and incomplete filesystem reads remain HOLD.
- Added synthetic negative tests for orphaned/missing guards and candidate runtime/binding identity collision; exact-HEAD CI runs are authoritative, not earlier green results.

**Boundary remains unchanged:** this is only read-only A3.1 plan hardening. No live `ReviewedUIDHostSnapshot`, independently accepted physical F4/session/packet witness, root daemon activation, non-root legacy-bot cutover, customer migration or master merge occurred. A3.1/A3.2/A4 operational gates are **HOLD** until real disposable-host and Telegram acceptance. Never toggle release switches to mask an incomplete gate.


## A3.1 continuation — existing DeferredOriginal6GHostPort snapshot wiring (2026-10-15)

This is **closure work on the existing M4 A3.1 gate**, not a new feature or operational release.

- \`RootOwnedUIDSnapshotSource\` reads the original one-user M1 selection again with a trusted inventory provider; refuses any different ingress UID/Edge/IP, missing F4/session readiness or blockers. It then obtains the existing \`RootOwnedM2PlanSource\` exact root-only First/Nth plan, re-reads PAM and verifies its original SHA and the manifest's UID/Edge/DNS scope.
- The source builds the existing \`ReviewedUIDHostSnapshot\` and original \`GuardBootstrap\` with real \`RootFilePort\` for first UID or \`CASRootRosterPort\` for next UID. Both remain fully **deferred** until \`DeferredOriginal6GHostPort.apply\` checks the already-persisted original P3/6G intent. No planning-time Linux, PAM, DNS, WG, or customer mutation.
- \`RootHostSafetyGates\` only binds vetted independent callbacks and \`IndependentSafety\`; the mere presence of callback objects cannot certify F4 packets. Missing/incorrect bindings or PAM hash drift => HOLD. Two independent explicit source-release flags remain OFF.
- \`assemble_reviewed_root\` now additionally requires a **typed root-owned Snapshot source with identical DB/root/OS UID providers**, rather than accepting an arbitrary \`read_root_snapshot\` function; original 6G callbacks still must come from the same original provider.
- Synthetic regression covers source default OFF, cross-edge denial, first/next concrete deferred port types, PAM drift, missing external safety and factory-to-deferred integration; root assembly rejects arbitrary snapshot functions.

**Still blocked from server-ready acceptance:** A3.2 existing privileged bot action audit and proven one-poller nonroot cutover; installed reviewed Root Daemon/systemd/socket; independently operated external physical packet/SSH/SOCKS/DNS/NSS/IPv6/session/WG-loss/console rescue witnesses and exact F4 signature provenance; non-customer disposable VPS Telegram E2E. The new snapshot reader is only source wiring, not a running factory on Core. Do **not** remove default-OFF flags, forge physical PASS, merge to \`master\`, or call M4 operationally complete before these independent gates pass.


## A3.2 continuation — legacy operator trust boundary (2026-10-15)

**No new user functionality, no live privilege change.**

- The existing static AST audit now resolves explicit import aliases for privileged sink calls, including `import subprocess as sp`, `from subprocess import run as r`, aliased `os.system` / `os.chmod`, and aliased asynchronous `create_subprocess_exec`. Star imports are recorded as unresolved manual-review leads rather than treated as an implicitly safe non-root path. This still cannot prove complete dynamic dataflow or establish a privilege split.
- Inspected the **real checked-in** `bot_final_v49-2.py` (29,961 source lines). Direct source review confirms existing `sudo useradd/chpasswd/userdel` account management, Paramiko remote Edge provisioning, local `wg set wg0 ... remove`, `iptables` remote mutation, systemd and SSH administrative paths. The legacy bot starts a single `ApplicationBuilder().run_polling()` and has numerous background loops. An unaudited `User=nvlbot` switch would break these existing features and is therefore **not authorized**.
- The existing root-side `live_admin_role` provider has been narrowed in production assembly to the **typed `LegacyCurrentAdminRole`**, which consults the current `settings.admin_chat_ids` allowlist on each authorization. It rejects historic IDs, missing/corrupt settings, group-chat or actor/chat mismatch, and malformed/duplicated IDs, with no hidden fallback. The independent pinned root actor/chat policy remains separately necessary. Neither stored `historical_admin_ids` nor a Telegram callback can grant root authority. Tests include revocation, malformed data and arbitrary callback rejection.
- **Limit:** `admin_chat_ids` is a legacy *current-login allowlist*, **not a cryptographic live session token**. This source-only check must not be misrepresented as completed end-to-end Telegram session verification. Its effective authorization must be checked against the real login/logout behavior during user-run server acceptance.
- **Unfinished A3.2:** preserving **all** legacy privileged/account/SSH/host actions while moving the only Telegram poller to non-root requires a reviewed and tested privilege transition or pre-existing compatible route for those actions. No generic root command RPC or parallel bot has been added here. Root Daemon entrypoint still exits 78; default-off gates remain OFF.

**Release verdict remains HOLD.** No `master` merge, no release flags enabled, no systemd User change and no live migration. The current work is testable source hardening; field testing must come only after safe service integration.


## M4 IPC/A3.2 continuation — bounded PREPARE queue and live revocation (2026-10-15)

- The existing root AF_UNIX `RootOperatorIPC` now discards **only** expired, process-local opaque `PREPARE` request IDs before enforcing its fixed limit of 20 outstanding approvals. Without reclamation, twenty expired approvals could permanently block fresh legitimate requests until restarting the root worker. The original durable checkpoint records, `failover_operations`, 6G lock, and authenticated confirm state are **never modified** during reclamation.
- A malformed in-memory pending entry or invalid clock fails closed **without partial pruning**. Fresh pending approvals remain reserved and cannot be evicted to bypass the queue limit. Expired request IDs cannot be confirmed/replayed after reclamation.
- Added targeted IPC regression tests for expiry reclamation, live-queue saturation, corrupted clock/entry, and admin revocation **after PREPARE but before CONFIRM**. The latter must refuse execution and consume the one-shot confirmation even after a later re-login, preserving original P3/6G safety.
- This is existing M4 reliability and A3.2 access-boundary closure, **not** a new admin/customer feature or permission to activate the root worker.

**Remaining operative HOLD:** the root worker entrypoint intentionally exits 78; `nvlbot.service` still has many historical privileged operations; no nonroot one-poller cutover, real external F4 witness, physical SSH/SOCKS egress acceptance, or Legacy cross-Edge `UID_ATTACH` was accepted. PR #148 stays Draft and **must not** merge into production-triggering `master` until the later operator-run disposable host/Telegram acceptance. CI successes and regressions prove only source-level behavior.


## M4 source/target egress contract — honest PREPARE/6G semantics (2026-10-15)

The existing migration UI lists the selected target Edge. **It does not prove that a legacy account on a *different* observed ingress Edge can already acquire that target's public egress.** This distinction is now enforced in the root service, not just documented.

- `RootMigrationPortal.prepare` refuses a selected member whose **independently observed** `source_edge_id` or `source_ipv4` differs from the target. This happens **before** issuing the signed root approval, inserting a `PREPARED` checkpoint, or sending a root ticket. A second fail-closed check is performed at `execute`.
- The only currently reviewed live host adapter is `ReviewedM2P3HostFactory` with `RootOwnedUIDSnapshotSource` → `UID_ENROLL_SOURCE` **on the same ingress/target Edge**. The root PREPARE now also checks global protected mode is exactly `0` without changing it, and `execute` checks again **before** changing a durable checkpoint to RUNNING or acquiring the original 6G lease.
- The existing `UID_ATTACH` **is present in original P3** but **not ready** for arbitrary Legacy source→target Edge transfer. An operational cross-Edge implementation requires all of: (1) a independently proven source/target/account/UID/F4 scope; (2) an explicit M4 **root host port** using the existing original P3 and deny-first per-UID guard instead of substituting a synthetic success receipt; (3) resolving original `Existing6GUIDRuntimeStore._owner` constraints that currently require source to match historical SSH host, active default Edge and DNS current source; (4) resolving P3's existing `UID_ATTACH` global protected-mode `1` requirement **without flipping global mode of mixed Legacy customers**; (5) preserving all 6G nonce/replay, PAM, packet, DNS/NSS/IPv6, neighbour, WG-loss and independent off-Core no-leak evidence; (6) user-run disposable non-customer VPS acceptance.
- Prior synthetic RootPortal tests incorrectly represented an s8→e9 operation with injected fake positive ticket/execution callbacks. They now test **supported same-Edge** one-UID enrollment, plus new explicit tests that **cross-edge** and wrong global mode cannot mint approval/checkpoint, and that mode drift before CONFIRM is HOLD without P3/6G mutation.
- `RootM42Bindings` now reclaims only expired *root-side P3 tickets* before enforcing its 20-ticket bound, after validating every pending entry and clock. This mirrors the previously repaired IPC PREPARE queue; it cannot delete DB checkpoints or a real 6G lease. Tests cover expiry, active capacity and corrupt pending state.

**Field verdict: HOLD.** These are concrete fail-closed fixes, **not** a functional cross-Edge migration implementation. Do not enable `UID_ATTACH`, assume e9 customer egress, change global protected mode, authorize batch M7, install the root daemon, or merge auto-deploying master on the basis of CI. Actual cross-edge source-proof and port integration, safe privileged-worker operation/nonroot bot separation, independent A4 evidence and M5/M6 host acceptance remain required.


## M4 single-UID admission/UI handoff — shared source contract (2026-10-15)

This update **does not** authorize cross-Edge attach or merge.

- Added the single pure `m4_same_ingress_reviewed(plan)` contract in the original M3 wave module, shared by the original `RootMigrationPortal.prepare/execute` and the Telegram presentation. A Legacy UID must be unprotected, independently source-attested, idle, and arrive **on the selected target Edge** already; only then is the current reviewed per-UID host source compatible. All existing F4/6G/root gates remain separate and default OFF.
- Fixed a misleading M4 Telegram preview: earlier `M1.inventory_clear` for an s8→e9 source could produce green **“ready for review”** even though the actual Root port required SAME-EDGE and would HOLD. Cross-Edge selections now display 0 ready/1 needing review (or matching counts), without developer/internal error strings.
- Changed `preview_buttons` to **default deny PREPARE** without a freshly supplied exact source inventory. Wired the two existing handlers in `bot_final_v49-2.py` to pass their read-only just-observed inventory for first preview and REFRESH. STATUS and post-CONFIRM screens have no inherited PREPARE affordance. Root still always independently re-checks the source and F4 at PREPARE and CONFIRM.
- Root ticket issuance now binds the original signed off-Core F4 account row's **source_edge** and **source_ipv4** to the exact P3 `ExecutionScope`, not merely matching UID/target; a source drift after M1 inventory cannot produce a signed ticket. Regression tests cover this mismatch without host mutation.
- Added source-level negative tests for cross-Edge UI/root disagreement, preview→button coupling and all-administrator scope pinning. Existing Telegram callback names, actions and user workflow remain unchanged.

### Concrete unresolved dependencies — do not call M4 code closed

1. **Mixed-Legacy cross-Edge:** original `UID_ATTACH` requires global protected mode=1; the real runtime store's `_owner` also requires historical SSH source/default/DNS identity; actual PAM/WG guard and `IndependentSafety` conflate ingress source and protected egress target. Supporting s8 ingress→e9 egress without moving all Legacy users needs an independently reviewed source/target split, fail-closed per-UID boot admission and real 6G port. It cannot be implemented safely by just changing mode 1 to 0 or faking the current SAME-EDGE port.
2. **Privileged execution:** the 29,961-line historical bot has numerous unrelated root-only actions. Nonroot one-poller conversion with all legacy actions retained, root daemon real fixed assembly, systemd identity and rollback acceptance are not implemented. `ops/k2_m4_root_daemon.py:main()` still exits 78.
3. **Field:** independently produced signed off-Core F4 captures, M5 disposable VPS Telegram/SSH/SOCKS/DNS/NSS/IPv6/WG-loss/rescue checks, and then the specifically authorized ONE real user M6 remain unperformed.
4. **No auto-deploy:** PR #148 stays DRAFT, stacked on M3; `master`, `nvlbot.service`, kernel policies, customer routes and records remain untouched. Never batch M7 before explicit approval after verified M6.

**Status:** M4 UI/root-admission consistency and independent source-ticket binding improved. **M4 operational closure: HOLD**, pending the three nontrivial gaps above and operator-run acceptance. CI is source/simulation evidence, never field proof.


## M4 source/target identity separation — ingress-only read path (2026-10-15)

**What is implemented here:** the original M1 `preview_migration` can now record an ingress-only Legacy Edge as the user's attested **SSH source** even when that Edge has no STAGED `edge_egress_allocations` row (because it is not a protected Egress allocation). This is a narrow, read-only change, not cross-Edge execution.

- The original root M2 PAM journal/WG observation factory now returns a typed, callable `RootReadOnlyIngressEvidence` holding the already root-verified `v1-ingress-peers.json` registry + single snapshot of current `wg show wg0 allowed-ips`, in addition to validating UID and journal freshness on each call. Its producer still requires root; a non-root Telegram callback cannot supply the privileged registry.
- `preview_migration(..., trusted_ingress_peers=...)` strictly parses the root registry format, validates unique Edge IDs, source WG /32 identifiers, unique public addresses and pinned keys, rejects any identity conflict with existing F3 Egress allocations, and includes the complete peer snapshot in the M1 inventory fingerprint. A claimed ingress-only Edge without both a currently verified trusted registry entry and independently observed PAM/WG UID source remains **HOLD**.
- The root `RootM42Bindings.review` passes additional ingress identities **only when** the original pinned `make_m1_readonly_ingress_provider` returns the exact typed `RootReadOnlyIngressEvidence`. Fake generic callback providers used in hermetic tests cannot silently grant extra source identities. The signed off-Core F4 row still independently must match each account's source Edge/IP and zero sessions.
- The existing bot's read-only `inspect_telegram_migration` also understands the typed root provider, but `MigrationInventory.can_execute` remains **False**. UI and Root Portal still default to HOLD for s8→e9, and **no approval, execution ticket, 6G lease or UID kernel mutation** is enabled by these changes.
- Regression tests cover ingress-only s8 recognition when s8 lacks F3 allocation, source registry collisions/malformed values, actual PAM/WG provider integration in M4 UI, root signed F4 cross-source classification, and refusal of `UID_ATTACH`.

**Still blocked:** cross-Edge Legacy `UID_ATTACH` remains an unimplemented real per-UID source→target protected execution path. The current PAM gate binds the protected UID's ingress Edge to its Egress Edge, current P3 `UID_ATTACH` assumes global protected mode=1, and the original F2 store's `_owner` enforces same-default historic source/DNS. Those constraints need an independent designed/tested source/egress binding under unchanged global mode and original 6G, not a bypass. A3.2 single nonroot poller with all historical root features, active root daemon, and real A4/M5 physical evidence also remain HOLD. **No `master` merge / no server action.**


## M4 ingress≠egress per-UID identity artifact — preparatory implementation (2026-10-15)

**Implemented in source (default inert, non-mutating):** `edge_egress_k2_uid_ingress_egress.py` now defines a strict root-owned, per-UID identity record with separately pinned `ingress_edge/ingress_ipv4` and `egress_edge/egress_ipv4`, username and Linux UID. It validates a fixed root-only file path `/etc/nvl-egress/k2-m4/uid-ingress-egress.json`, rejects duplicate JSON keys/users/UIDs, unsupported fields, invalid/non-public/duplicate IPs, impossible same-edge records and mismatches with the existing `PROTECTED` runtime Egress row. The loader uses the existing V1 trusted root-only file/directory readers; no fallback to a Telegram-provided path, DNS, historical SSH host or default Edge. A missing or malformed file is an explicit error rather than an implicit approval.

**Crucial scope boundary:** this is a *new policy artifact/parser and pure runtime identity comparator*, not a registered PAM reader, activated cross-Edge V1 admission rule, migration command, 6G-integrated writer or physical egress test. No routing, WG, SSH account, customer or production service changes were made. In particular **the current PAM V1 `verify_ingress` still rejects s8 SSH ingress for a PROTECTED e9 egress runtime row** and current root M4 still refuses `UID_ATTACH`.

To complete this gate later, the existing PAM reader must be explicitly reviewed to consume only this exact root policy while continuing to verify live SSH PAM_RHOST↔WG0 public-key ownership, PROTECTED runtime Egress identity, 6G quiescence and per-UID frozen/DNS/IPv6 packet safety. Critically, a root 6G-owned, crash-safe *writer* must persist identity and per-UID DENY state in correct order before such a policy is relied upon. A manually copied root policy or a green parser test is **not** deployment authorization. Existing Legacy admission and root break-glass must remain intact. Host-level M5 evidence then validates the real SSH/SOCKS data path.

**Status:** root policy type/parser and hermetic negative tests added; **PAM integration, P3/6G migration and operational M4 = HOLD**. No release flags enabled, no `master` merge.


## M4 UID ingress/egress admission-proof strengthening — draft-only (2026-10-15)

The uninstalled per-UID source→egress **root policy schema is now V2**. Each record still pins the exact `username/uid`, SSH ingress Edge/public IPv4, protected Internet-egress Edge/public IPv4, and now additionally:
- `ingress_wg_public_key`: exact 32-byte base64 WireGuard peer key for the current SSH ingress;
- `runtime_generation` and `operation_id`: exact `PROTECTED` runtime CAS generation and original 6G operation ID;
- `guard_sha256`: digest of the **installed** per-UID deny-first boot manifest (not metadata from `ssh_accounts.host`).

`UIDIngressEgressBinding.matches_runtime` now rejects any change in protected UID, Egress identity, state, 6G operation, runtime generation or independently supplied installed manifest digest. Previous V1 draft JSON is deliberately rejected; this is **not** a production format migration because no writer/PAM consumer has been installed.

New `verify_readonly_cross_edge_ingress` is a **pure proof checker**, not an SSH admission callback. Given root-pinned policy, current protected RuntimeBinding, installed guard digest, authenticated PAM_RHOST, root-owned ingress peer registry and current `wg show wg0 allowed-ips` text, it fails closed unless all exact identities agree, source is valid wg0 /32, the expected public key currently owns the address, and **no other WireGuard key overlaps that source IP**. It refuses duplicate/forged peers and drifted operation/guard. Unlike the original V1 `verify_ingress`, its pure result may be TRUE for s8 ingress/e9 egress, but **V1 PAM remains unmodified and continues to DENY** such a login. Only an independently reviewed, root 6G-owned writer and hard-gated PAM integration could change that later, with F4/M5 physical acceptance.

Added negative/positive hermetic tests for stale runtime generation or 6G op, changed guard digest, invalid WireGuard key, spoofed PAM_RHOST, changed peer public identity or key, overlapping allowed-ips, reused registry peer, and old V1 unchanged behavior. No release flags, new dispatcher command, running daemon, customer state, SSH route or DNS changed. **M4 operational acceptance remains HOLD.**
