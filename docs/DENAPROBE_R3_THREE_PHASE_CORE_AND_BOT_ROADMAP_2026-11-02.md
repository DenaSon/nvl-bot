# DenaProbe R3 — Core & Telegram three-phase rollout (approved scope)
**Date:** 2026-11-02 | **Status:** DOCS/CONTRACT ONLY; zero runtime changes, bot actions disabled, not merged or deployed.
**Companion firmware roadmap:** [DenaProbe R3](https://github.com/DenaSon/DenaProbe/blob/docs/denaprobe-r3-roadmap-dpt2-20261102/docs/015-R3-THREE-PHASE-FILTERING-MONITORING-ROADMAP-2026-11-02.md)
**Draft DPT/2:** [wire specification](https://github.com/DenaSon/DenaProbe/blob/docs/denaprobe-r3-roadmap-dpt2-20261102/docs/016-DPT2-DEEP-SSH-TELEMETRY-CONTRACT-DRAFT.md).
**Mandatory admin UI:** [Rich Message contract](DENAPROBE_R3_TELEGRAM_RICH_MESSAGE_UX_CONTRACT.md).

## Owner-approved product outcome
ESP32 hardware gathers observations; the independent Core DPT Collector receives/verifies/saves them; a separate Core classifier assigns observed D0/D1/D2 and conservative filtering-suspicion confidence; existing NVLBot sends alert + recovery to authorized administrators and provides a **native Telegram Bot API 10.3 Rich Message monitoring dashboard**. No independent UI platform. No vendor/censorship certainty from one hotspot. Do not add relay-switch timestamps/events or automatic failover.

## Actual source boundary / deployment truth
- `master` does NOT yet contain the R2-B collector source. `feature/dpt-r2b-core-collector-20261031` PR #262 is open; `feature/r2c-hardening-live-state-20261031` PR #263 is open and stacked on #262. DenaProbe R2-A PR #6 and R2-C PR #7 also open.
- A separately operator-installed collector at `/opt/nvl-dpt-collector/denaprobe_ingest/collector.py` with `denaprobe-collector.service`, nonroot `denaprobe`, loopback `127.0.0.1:18081`, independent `/var/lib/denaprobe/telemetry.sqlite3` was **field-smoke-verified** on 2026-10-31 over Cloudflare `board.nvlsup.online` (HTTPS 200 signed ACK); last live state `monitoring_gap=1,https_sequence=NULL` before hardening. Never call the currently deployed collector hardened without direct operator verification.
- Core/Edge production services `nvlbot.service`, `gost.service`, existing user/tunnel DB and Cloudflare public routing are outside the implementation scope unless explicitly reviewed for guarded bot integration. The isolated telemetry store is not the bot's user database.

## Phase 1: R2-C sender/ingest reliability (prerequisite)
**Board:** FIFO queue across boot/probe/local events, bounded retries, stable HMAC/idempotent ACK, proof of lost/old events, local buffered measurement; never forge new timestamps on old samples.
**Collector:** signed DPT/1 accept 200/403/409; strict stored raw body, boot+q uniqueness, ordered/fresh promotion, gap cleared only after two *fresh eligible SSH probe* events, HTTPS last-new-sample separate; older/reordered samples history-only and never actionable; ensure k1 revoked while retaining k2, with safe key-ID-only check.
**Acceptance:** open PRs review/test/merge in controlled sequence; staged collector compatibility, live ESP32 signed q continuity, current `monitoring_gap=0` and fresh HTTPS; invalid HMAC and replay, 429/5xx, offline bursts, no secrets and no production service interruption. **No incident classification/Telegram sending before passing**.

## Phase 2: DPT/2 authenticated evidence
**Firmware dependency:** independent TCP connect plus authenticated SSH session and two bounded `direct-tcpip` transfer samples from a restricted account, plus existing SSH pre-auth/HTTPS controls. Full independent NPV application connection NOT claimed.
**Collector:** implement new **DPT/2 separate signed endpoint `/api/dpt/v2/telemetry`** and versioned code registry; preserve existing `/api/dpt/v1/telemetry` unchanged. Both verified at raw-UTF8/HMAC boundary; strict 1024-byte cap; version-scoped keys; target id and immutable registered revision; store independent `c`, `z`, `h` fields with accurate measured/receipt timestamps, age and freshness. Existing v1 records MUST NOT become VPN_PASS. Unknown codes -> retain/historic UNKNOWN, never trigger filtering.
**Core/Edge boundaries:** no customer SSH passwords or plaintext test content in telemetry; restricted test account and forwarding-only controlled test responder; no administration or relay mutation. Testing Auth on ESP32 is a phase gate, not an assumption.
**Acceptance:** versioned fixture + HMAC golden vector pass on C++ and Python, both v1/v2 parsed correctly, D0 connect-timeout, D1 first full then reset/second timeout, healthy two complete, D2 partial/slow, local Wi-Fi, host key, stale/missing data and target revision change; real ESP32 and Core E2E. Don't activate v2 in production without hardware stability/data budget verification.

## Phase 3: classifier + admin Rich Messages
**Module:** introduce an isolated read-only detector consuming **accepted current** records of registered devices and targets. Preserve Collector security and data tenancy; no public read endpoint. Store incident episodes with `target_revision,device_id,operator_claim,observed_class,filtering_suspicion,confidence_reasons,started_at,last_evidence_at,last_ingested_at,first_alert_at,recovered_at` plus per-channel freshness and evidence IDs (not secrets). Device-reported `operator_claim` is only configured provenance; do not automatically trust SSID as cellular network proof.
**State machine:** `HEALTHY`, `D0_TCP_UNREACHABLE`, `D1_SESSION_FAILURE`, `D2_DATA_DEGRADED`, `MONITORING_UNKNOWN`, `RECOVERED`. D0 uses independent c; D1 uses verified pre-auth PASS plus z authenticated session error; D2 requires failed/full but slow transfer with validated size+healthy baseline. Alert only after fresh corroborated samples; safety-exclude Wi-Fi down, key mismatch, local memory, stale HTTPS, absent ACK, history_only and sequence gaps. Monitor gap -> UNKNOWN; *no auto-recovery from silence*. Severity and suspicion are **server judgments**, never embedded in ESP32 wire body.
**Suspicion:** `INCONCLUSIVE`, `SUSPECTED`, `HIGH_CONFIDENCE` (only with independent reachability/server-healthy/cross-operator corroboration). No claimed definitive DPI, censorship culprit or numerical likelihood unsupported by calibration.
**Scheduler:** bounded evaluation interval per active target; deduped idempotent incident open/escalation/recovery; cooldown, multi-admin scoped delivery; separately persist notification attempts/failures and retry without duplicate Telegram flood. Status banner and recovery messages must use timestamps and explain evidence limitations.
**Bot:** mandatory Bot API 10.3 Rich Message admin dashboard and incident card contract in sibling document. Short Persian labels, compact table-like columns and a useful contextual footer, existing admin-only RBAC; includes evidence, samples, age, source, confidence, independent control and actions limited to View/History/Refresh. Not a new Mini App or HTML fallback dashboard.
**Acceptance:** replay D0/D1/D2/healthy/no Wi-Fi/no telemetry/host-key failure, controlled live incident + recovery, bot rendering on iPhone/Android, role authorization and one-notification-per-episode. Operator explicitly enables production alert gate.

## Performance / policy
Design goal **<=90s** event-to-manager alert when sampling/dwell/delivery/evaluation permit. Degraded auth deep interval must be sufficiently short or escalation-triggered; cannot promise 90s from a deep run less often than 90s. Record `measured_at, received_at, classified_at, sent_at` separately and report distribution from field acceptance. If DPT delivery fails during outage, detection via stale data is prohibited; emit a separate monitoring-gap alert only when corroborated. Maintain a bounded LTE data budget on 2.4GHz hotspot with adjustable test bytes/cadence; not a permanent speed-test loop.

## Release and stop conditions
1. No direct imports of core bot database by collector; no `root` service requirement for ingestion.
2. No changes to `nvlbot.service` or `gost.service`, NPV user records, active edge, DNS or customer provisioning without a separate change.
3. Keep key `k1` revoked after checking; key material never in repository/logs; independently pin target SSH host key.
4. **All development begins only after docs/contract review.** This document does not authorize deployment.
5. No SIM800L, automatic relay switching, manager relay-switch event logging, external dashboard or miniapp.
