# DenaProbe — Core/Telegram companion to the board-first Password Deep SSH plan
**Date:** 2026-11-04  
**Status:** DOCUMENTATION ONLY; no source, service, database, account, DNS or network changes.  
**Canonical implementation scope:** [DenaProbe / docs/017](https://github.com/DenaSon/DenaProbe/blob/master/docs/017-DEEP-SSH-PASSWORD-DATA-PATH-FIELD-PLAN-2026-11-04.md). This file governs only the downstream Core/NVLBot work after physical board acceptance.

## Decision and context

The deployed DenaProbe R3 has already demonstrated a real fast D0 TCP alert, native Rich notification and confirmed recovery. A real Edge-IP disruption that left TCP and SSH preauth apparently healthy was **not detected**. Previous MCI audits include a first authenticated data sample completing, then subsequent transfer timeout/session reset. We need to observe the *authenticated SSH forwarding path*, not reinterpret preauth PASS as full NPV health.

**Order:** A0 baseline/source review → A1 password-auth board source → A2 physical serial/hardware test → **explicit owner sign-off** → B0 Core SSH/forwarding path review → B1 deterministic transfer witness and telemetry → B2 classifier/Rich alerts → B3 matched operator field acceptance. Do not collapse the board gate.

## Hard boundaries in Core

- **No Core change before A2 approval.** No edits or deploys to `nvlbot.service`, `denaprobe-collector.service`, `gost`, SSHD, firewall, WireGuard, user accounts, NPV routes, Edge DNS, or SQLite schema during A0–A2.
- The SSH identity is operator-provisioned (username/password) for the **same user-facing SSH domain/port and path** as NPV, with independently pinned server host key. It is **not** the Collector's DPT/2 HMAC credential. Do not copy password/username/secret into GitHub source, docs, CI, logs or Telegram cards.
- Account renewal preserving the same password/username should not require a board flash. Changing password **will** require a controlled firmware reprovisioning in this scope; remote config/OTA are explicitly not being built.
- Board Deep opt-in remains OFF by default until physical tests. Retain known-good binary/rollback, existing D0 warning path and DPT/1 + DPT/2 coexistence.
- The real SSH termination path must be verified (existing code mentions Edge-as-Relay and accounts on Core). A loopback responder on the terminating Core tests authenticated transport and `direct-tcpip`, but **does not prove full internet egress or NPV application/payload behavior**.
- No production customer's real account or traffic is mutated or inspected. A short-lived pilot identity, if used, must be limited and rotated before unattended operation. No automatic rerouting or traffic switching.

## B0 — Reviewed permissions / path gate (after A2)

**Read-only evidence first:** determine effective `sshd` auth mode and forwarding rights (including account expiry/lock state), target's exact SSH termination host, and permitted `direct-tcpip` destination. Require no changes to existing customer accounts. If policy changes are necessary, separately approve a minimal SSHD config patch with `sshd -t`, rollback and no unguarded restart.

**Controlled destination:** default deterministic witness is `ops/denaprobe_static_responder.py` bound **only to 127.0.0.1:18180 on the SSH termination machine**. SSH account may forward only to the reviewed destination; forbid shell, PTY, arbitrary public egress and privileged access. A second whitelisted egress-like destination is considered separately if NPV fidelity requires it.

**Acceptance:** documented SSH termination, authentication and forwarding scope, allowed endpoint, app/CPU/LTE budget, zero customer disruption. A real NPV test client must run on the same operator and target for comparison.

## B1 — Deep transfer witness and DPT/2 integration

- Deterministic per-channel response: 16KiB 0x5A followed by EOF; two separately opened `direct-tcpip` channels in one authenticated SSH session with a configurable dwell. Validate exact bytes, integrity, timing and EOF.
- Explicit tests: password success/failure, host-key mismatch, forwarding denied, first success then reset/timeout, slow complete, incomplete, Wi-Fi down, retry/queue, replay/history-only, and same-target MCI vs RighTel comparison.
- Reuse existing `c`, `z`, `f`, `g` DPT/2 payload shape and current independent SQLite tables. Check strict 1024-byte body cap, correct HMAC, device boot+q continuity, signed sender-age, target revision, Collector checksum/ACK; never send secrets or user payload.
- Preserve preexisting DPT/1 and D0 incident data. No SQLite migration unless an audited, test-proven schema incompatibility demands one, with online backup and rollback.

**Acceptance:** actual ESP32 sample containing verified Deep auth/channel/first+second transfer gets collected, stored, read and correlated with serial evidence. No false success from mere SSH preauth. Keep server responder private.

## B2 — Classifier and native Telegram Rich messages

Existing D0 first-failure alert must remain unchanged. Add Deep evidence with clear operational distinction:

| Observation | Interpretation | Notification behavior |
|---|---|---|
| TCP connect error while Wi-Fi available | D0 TCP reachability | Existing rapid D0 path |
| TCP/KEX/preauth PASS but authenticated session reset or channel times out in an **allowed** context | Candidate D1 | Alert after separately validated Deep evidence; no unsupported attribution |
| Two transfers attempted; incomplete, timed out or severely slow relative to same-size baseline | Candidate D2 | Calibrated threshold, repeated evidence and explicit sample metadata |
| Wrong password, account expired/locked, unauthorized forwarding, host-key mismatch | AUTH/CONFIG/SECURITY | Diagnostic, **not** a censorship/failure-of-carrier accusation |
| Wi-Fi down, stale/out-of-order or missing telemetry | MONITORING_UNKNOWN | No false D1/D2 alert and no automatic recovery |
| Verified post-incident consecutive success at the measured level | RECOVERED | One recovery notification, scoped to tested layer |

- Rich UI: show Preauth, Authentication, Forward Channel, Transfer 1/2, duration, actual/expected bytes, freshness, measured route, baseline and caveat that NPV end-to-end remains unmeasured where applicable.
- Version and test the updated classifier without conflating the same SSH session's two channel transfers with two independent probe cycles.
- Keep admin-only authorization and existing Bot API 10.3 Rich transport, durable delivery/hold semantics, incident deduplication and recovery.
- Deep timing may exceed the 30-second lightweight probe interval. Define and **measure** the real D1/D2 alert latency instead of promising D0-like 30 seconds.

**Acceptance:** unit/integration tests for D0/D1/D2, AUTH rejected, stale Wi-Fi and unknown statuses, no duplicate alerts, one recovery, old historical dashboard, real native Telegram preview. Apply changes only through reviewed guarded/pinned deployment.

## B3 — Field test and release closeout

- Two operators (MCI and RighTel), same destination and comparable window; keep exact device+target revision, raw signed evidence identifiers, source firmware SHA, host-key policy proof, serial performance, service logs and notification timestamps.
- Compare when NPV on the same mobile network fails while TCP and SSH preauth remain green; only the authenticated data-path probe can supply additional evidence. If NPV fails yet measured Deep succeeds, record an honest **coverage gap**; do not declare healthy.
- Negative matrix includes wrong credentials, account extension/expiration, SSH forwarding rights, Wi-Fi loss, HTTPS control slow, DPT queue gap, server responder stopped, SSH reset, and slow transfer.
- Stop/rollback on unexplained resource use, watchdog, credential leak, failed host-key validation, collector format regression or user-visible service disruption.

**Milestones:** `DOCUMENTED` → `BOARD_SOURCE_READY` → `BOARD_FIELD_ACCEPTED` → `CORE_SOURCE_READY` → `CORE_DEPLOYED` → `NPV_FIELD_ACCEPTED`. Do not mark any later milestone until evidence and explicit approval exist.

## Ownership and deliverables

| Gate | Owner artifact |
|---|---|
| A0–A2 (ESP32 repo) | frozen SHA, review, serial logs, hardware heap/stack/watchdog + signed sample, A2 acceptance |
| B0 | reviewed Core/SSH topology and `PermitOpen` mapping, egress equivalence limits |
| B1 | isolated responder test, DPT/2 fixture and signed real event, DB/collector safety |
| B2 | classifier/Rich notifications + recovery tests and administrator acceptance |
| B3 | paired operator evidence, NPV reference, latency/baseline calibration, rollback record |

**Development not authorized by this documentation alone.** Next implementation action is only A0/A1 on the board repo, after the owner's separate start request. Core/Telegram remain frozen until A2 is explicitly accepted.
