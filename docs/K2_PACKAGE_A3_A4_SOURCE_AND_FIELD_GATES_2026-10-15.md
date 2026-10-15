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
