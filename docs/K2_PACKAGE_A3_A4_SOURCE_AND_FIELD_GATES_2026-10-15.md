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
