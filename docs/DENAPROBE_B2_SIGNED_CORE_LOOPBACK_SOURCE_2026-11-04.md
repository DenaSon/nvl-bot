# DenaProbe B2 — signed Core-loopback Deep evidence
**2026-11-04 | Source preparation only; no production deployment**

## Physical gate
The operator accepted B1 ESP32 real evidence: four independently authenticated SSH sessions, each with two 16KiB validated direct-tcpip transfers to the Core-only 127.0.0.1:18180 responder, with 20s dwell. Minimum heap declined to about 63.5KiB in that excerpt; no reset observed. This is NOT proof of the NPV public egress or filtering causality.

## B2 wire/collector/classifier
- Board candidate in DenaProbe repo adds opt-in signed DPT/2 `z.rt=1`, meaning a **Core-loopback deterministic witness**. DPT2 HMAC signs the JSON including route field. All `z.s`, `f`, `g`, previous status codes and FIFO contracts are unchanged. No secrets enter the body.
- DPT2 validates `rt` strictly as integer 1, optional for legacy data. Raw JSON persists in existing SQLite schema; no migration needed.
- B2 classifier: a Core-loopback success is no more than PREAUTH_REACHABLE. It is NEVER end-to-end NPV HEALTHY and must NOT open D1/D2. Channel/auth/transfer faults within a loopback route are diagnostic UNKNOWN, not provider filtering allegations. Existing D0 first-event warnings remain; two separate fresh preauth samples can resolve a confirmed D0, exactly as before. Host-key, Wi-Fi and stale cases retain existing limits.
- Native Rich operator dashboard shows the loopback route and two samples with explicit 'not NPV egress' wording. Existing synthetic legacy untagged Deep fixtures remain backward-compatible; tagged route 1 has its own security-specific regressions.

## Deployment gates — no automatic Core/board changes
1. Both PRs must pass all CI. Merge Core **before** board; merge is never equivalent to production deployment.
2. Pre-deploy Core: read-only state inventory (running process, live commit, versioned collector state), complete online SQLite backup with restore validation, and pinned source staging. Do not reset tables, routes, SSHD, accounts, Cloudflare Tunnel, firewall or responder port.
3. Deploy Core code with the existing approved safe deployment mechanism, then verify legacy D0 + fresh DPT/2, and tagged route 1 accepted/readable in Rich without D1/D2 or false recovery. Preserve existing single bot poller/Telegram Rich transport.
4. Only after Core tagged-route policy is live, explicitly build and manually flash isolated `esp32dev_b2_loopback_telemetry_compile` in the DenaProbe repo, preserving ignored local credentials, pinned host-key, 4MiB backup and active loopback responder. Verify actual DPT/2 z.rt=1, f/g and HTTP 200. Existing B1 firmware masks z; it may safely run indefinitely until Core is ready.
5. **B3 next:** validate MCI/RighTel in matched time windows and a separate *egress-equivalent* test. Only enable real D1/D2 Telegram alerting with scoped routing metadata and calibrated baseline; loopback route must never trigger these alerts.

## Source-only acceptance
Tests: validate strict rt, legacy backward compatibility; raw signed route read, correct explicit Rich display, no D1/D2 or HEALTHY for loopback success/failures, D0 first alert and two-sample preauth recovery intact, no schema regression. No Production edits or board flash at this stage.
