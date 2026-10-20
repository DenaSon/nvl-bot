# NVL Health Center — HD-01 / HD-02 MVP Roadmap

**Status:** PLANNED / NOT IMPLEMENTED — 2026-10-20  
**Owner scope:** Two development phases only: **HD-01 diagnostic engine/reports**, **HD-02 Telegram admin UI**.  
**Canonical context:** [MCI-specific SSH incident](HEALTH_INCIDENT_2026-10-20_MCI_EDGE.md), [6D TCP provider](PHASE6D_CHECKHOST.md), [6E classification](PHASE6E_FILTERING.md), [6F runtime](PHASE6F_RUNTIME.md), [6H automatic failover](PHASE6H_AUTOMATIC_FILTERING_FAILOVER.md).

## 1. Why this exists

On 2026-10-20, users of an Edge relay IP (172.86.92.41, service TCP/2252) reported "Connecting". Core sshd was available; the WireGuard link was transferring traffic; the Edge had healthy external Internet, low conntrack utilization and no measured interface drops. Check-Host returned `CLEAR / HEALTHY_QUORUM / 7/7`. Nevertheless, SSH attempts from the affected network stalled **after SSH KEX and EXT_INFO and before SERVICE_ACCEPT**, while another network reached authentication. The operator subsequently identified **MCI / Hamrah-e Aval-specific filtering of the old public IP**, while Rightel access worked; a replacement VPS/new IP restored customer connections.

**Lesson:** `IP available != TCP connected != SSH authentication-ready != functioning customer tunnel`. Also `TCP healthy from seven provider nodes != reachable via every Iranian ISP`. No existing single verdict may be relabeled as end-to-end or per-ISP health.

We have an operator-confirmed ISP-specific incident; the exact packet-dropping mechanism and network device responsible were **not** forensically proven. Do not claim DPI, MTU or a provider-side firewall as established facts.

## 2. Scope and invariants

The Health Center is a **read-only diagnostic surface for infrastructure and connectivity**, not an alternative failover/control plane. Reuse 6C/6D/6E/6F stored observations and typed decisions where possible; do not duplicate monitoring schedules, classifiers or the Phase 6G/6H execution engine.

- **Primary customer service port: TCP/2252** from `host_pool.service_port`, not admin SSH/22. Treat optional TCP/2088/TLS as a **separate** service; never use success on 2088 as proof for 2252.
- Target the selected Edge's public address/domain; check the intended Edge identity and show the Core-terminated SSH/Edge-DNAT/WireGuard topology explicitly. Preserve Core-local exclusion from Edge regional quorum.
- An SSH protocol probe is meaningful only **from the named measurement vantage**. Core/Edge probes cannot represent MCI, Irancell or Rightel clients by inference.
- Results from a network with no qualified/identified probe are `UNKNOWN` / `NOT_TESTED`, never `CLEAR`. Preserve Check-Host `CLEAR` as a **TCP-only regional signal**.
- No diagnostic result can alter `filter_state`, `is_default`, `active`, DNS, accounts, WireGuard, SSHD, routing, standby, 6G/6H authorization or failover eligibility in this MVP. Phase 6H remains governed exclusively by its existing safety policy and inputs. Automatic failover status must be *shown*, not toggled by Health.
- No new permanent agent fleet, external paid provider, scheduler, SSH auth attempts, customer password handling or new monitoring subsystem in MVP. If a reliable operator-owned MCI measurement endpoint is unavailable, show MCI `NOT_TESTED`; do not simulate or infer a pass.
- `read-only` refers to **infrastructure/network mutation**: exporting diagnostics and minimal admin audit records are permitted. No write to operational `host_pool` state as a consequence of a Health run.

## 3. Health dimensions and display semantics

Show **separate** dimensions, each with `PASS | FAIL | DEGRADED | UNKNOWN | NOT_TESTED` plus timestamp, source/vantage and reason. A green aggregate must not mask an unknown operator.

| Dimension | Source / proof | Limitation |
|---|---|---|
| Core bot / Core sshd | current service/sshd status and TCP listener | Not customer reachability |
| Edge management | admin SSH port and host availability | Not the customer port |
| WireGuard/Core path | last handshake, peer, route and simple Core path | Doesn't show public ingress |
| Edge ingress TCP/2252 | existing 6D Check-Host; optional Core direct TCP | TCP handshake only |
| SSH protocol TCP/2252 | isolated zero-credential client: TCP → SSH banner → KEX/NEWKEYS → service-accept/auth-method availability | No login or forwarding verified |
| Per-network / per-ISP | identical protocol probe executed from explicit operator-owned MCI/Irancell/Rightel vantage, independently labeled and timestamped | Missing/stale/unverifiable provenance => UNKNOWN |
| Real customer tunnel | **manual** operator-observed authenticated SOCKS/HTTP test, optional evidence note | Never automatically store credentials or claim from protocol-only success |
| Provider health | existing Check-Host provider response/backoff | Provider `OK` is not network reachability |

A stage is reached only with *positive evidence*; stage names must not be used as a blanket "SSH OK". Suggested machine-readable stages: `TCP_CONNECTED`, `SSH_BANNER_RECEIVED`, `KEX_COMPLETE`, `SERVICE_ACCEPT_RECEIVED`, `AUTH_METHODS_RECEIVED`, and `TUNNEL_E2E_CONFIRMED` (manual-only). Record `STOP_STAGE` and categorized reason: `TIMEOUT`, `RESET`, `REFUSED`, `HOST_KEY_MISMATCH`, `PROTOCOL_ERROR`, `NETWORK_UNREACHABLE`, `UNKNOWN`. `Auth methods received` is a readiness marker, not a successful login.

A host-key change/mismatch is **not** a harmless connectivity failure. Do not disable trust checks globally or silently accept an unpinned host key. Do not overwrite `known_hosts` automatically. For probes, use an approved expected SSH host public-key fingerprint / pinned known-hosts trust source and explicit no-credential, no-password-attempt settings; incompatible target identity => `HOST_KEY_MISMATCH / FAIL_CLOSED`.

For per-ISP evidence, use `vantage_id`, declared network/ISP, how it was validated, acquisition time, sampling window, probe version and original target. An ISP label supplied by an operator without independently measured provenance is an **operator declaration**, not an automatically verified ASN binding. Mark user-supplied notes separately.

## 4. Data contract — version 1

Each **per-Edge, per-vantage** report has:

- `schema_version`, generated UTC time, unique diagnostic run ID, target `edge_id/host`, `service_port=2252`, target hostname and resolved IP; `role=EDGE`;
- `vantage_id`, `vantage_type=CORE|PUBLIC_PROVIDER|OPERATOR_OWNED|CLIENT_MANUAL`, optional declared ISP/network, provenance/verification level, observation time, freshness age;
- network/infrastructure: Core/Edge/admin/WG/Core path, 6D TCP provider status/node counts, classifier/6H state **as read**, and `last_checked_at`;
- protocol stages with actual reached/not-reached status, durations, `stop_stage`, normalized reason, no misleading aggregate;
- evidence quality: `CURRENT|STALE|PARTIAL|UNAVAILABLE`; coarse confidence and gaps;
- `operator_notes`, optional sanitized incident references; `actions_performed=[]` for network/operational mutations.

**Output:** human-readable `.txt` plus machine-readable `.json` with matching run ID and timestamps. No passwords, tokens, usernames, customer IP addresses, SSH private keys, raw packets or unredacted transcripts. Keep existing sensitive DB values out of exports. Errors are bounded/sanitized.

Persistence design for MVP: reuse existing 6F read models for baseline data; HD-01 can emit local artifacts without new production DB migrations. HD-02 needs only a small, reviewed read model / bounded sanitized diagnostic report register **if** necessary for viewing the last run. Do not introduce a second source of truth for filtering or duplicate `host_probe_results`.

## 5. HD-01 — Diagnostic engine and TXT/JSON reports

**Goal:** a deterministic, safe, manually invocable per-Edge health run, independent from failover.

**Work:**
1. Inspect actual 6C–6F storage/probe contracts and use `service_port`; never guess `admin_ssh_port` or mix TCP/2088 and 2252.
2. Implement pure typed result/status normalization, clock/freshness validation, redacted report serialisers; fail `UNKNOWN` on missing telemetry.
3. Add a bounded no-credentials SSH protocol diagnostic for **one explicitly chosen target** and **one explicitly chosen vantage**. If a suitable vantage lacks the probe capability, mark `NOT_TESTED`. Prefer running the same reviewed helper from a separately operator-controlled endpoint; no Core pretending to be MCI.
4. Correlate **without overriding** Check-Host TCP `CLEAR` and existing 6H state. Show contradictions as `TCP_PASS / SSH_FAIL` per vantage.
5. Produce matching TXT and JSON artifacts; no live service actions, no user/account mutation, no password prompts, no new periodic job.

**Acceptance gates:**
- Tests for TCP pass + SSH timeout immediately after `EXT_INFO`; TCP pass + auth-methods reached; network-specific MCI FAIL / Rightel PASS; missing MCI vantage => UNKNOWN; stale and provider-limited => UNKNOWN; wrong host key => FAIL_CLOSED; port 2088 success cannot pass 2252; Core-only reachable cannot pass Iranian reachability.
- Reports contain timestamp, source, phase reached and cause; sanitize all private data.
- Static guards prove diagnostics cannot call 6G/6H, Cloudflare, account migration, `host_pool` mutators or SSH/WG restarts.
- Independent module/CLI tests pass. One strictly approved **read-only** field trial per identified vantage before any claim of Iranian operator coverage.
- Document supported failure classifications, operational caveats, release marker and sample redacted reports.

**Deliverable:** diagnostic module/CLI + versioned TXT/JSON contract + tests, ready for bot wiring. No Telegram UI in HD-01.

## 6. HD-02 — Telegram Health Center (Admin/Superadmin)

**Goal:** surface HD-01 with minimal friction inside the existing host/Filtering management flow.

**UI:** `سرورها / مدیریت IP → 🩺 سلامت سیستم`, with a per-Edge list, current host/default marker, last-check time and separate statuses for Core, Edge, WG, TCP/2252, SSH protocol, and per-ISP. Report coverage always visible: `همراه اول: مشکل مشاهده‌شده / سالم / بررسی نشده` only when corresponding evidence justifies it.

**Actions (strictly read-only):**
- `🔍 بررسی این Edge` — explicit admin request, bounded execution, progress and timeout; shows the **vantage** actually used.
- `📋 جزئیات` — stage-by-stage result with specific reasons, provider limits and evidence freshness.
- `📄 گزارش TXT` / `📦 گزارش JSON` — send sanitized artifacts from the current run, not raw logs.
- `🕘 آخرین گزارش` — bounded recent report review if an approved small report register exists.

**Non-actions:** no switch-active, change-IP, failover, retry loop across all Edge servers, account/port/SSH changes or automatic ISP filtering labels. The existing Filtering Monitor and failover buttons remain owned by 6F/6G/6H. Slow probes must never block the Telegram polling loop; bounded background execution, one run per target at a time, timeout, admin authorization and safe cancellation/status are needed, but no new orchestration platform.

**Acceptance gates:**
- End-to-end admin UI paths, permission checks, callbacks, timeouts, double-click dedupe, accurate freshness and unavailable-vantage labels.
- A report from Core-only cannot say MCI is CLEAR; `7/7` Check-Host does not imply authentication readiness; an observed `EXT_INFO` timeout remains distinguishable from a TCP failure.
- TXT/JSON delivery tested and structurally identical to HD-01 outputs.
- Source + regressions must pass; **operator-run** Telegram smoke test on staging before production, production release separately approved. No network mutations from UI.

**Deliverable:** complete admin entry, diagnostic detail, run action, exports and tests. No agent provisioning or auto recovery.

## 7. Explicitly deferred until separately approved

- An always-on probe fleet with guaranteed MCI / Irancell / Rightel coverage.
- Scheduled recurring protocol probes, thresholds, new ISP-specific alarms, or new Telegram notification cadence.
- Changing the 6E/6F global classifier or adding new automatic 6H failure criteria.
- Authenticated customer accounts, stored test passwords, synthetic traffic tunnels on servers, automated packet captures, packet-level ISP attribution.
- Auto-switch of DNS / default Edge from any Health result; any automatic remediation.
- New dashboards outside Telegram, complex history/analytics and paid monitoring integrations.

These may be proposed **after** MVP field evidence; do not slip them into HD-01/02.

## 8. Safety / release discipline

- Freeze functional scope at this plan. Do not expand implementation complexity without owner confirmation.
- Branch → review → isolated tests → docs → PR → merge only after acceptance. **Git master merge != production deploy**.
- No unsupervised SSH access, service restart, `iptables`/`nft`/`wg`/DNS changes, migrations or live customer handling.
- Default diagnostic run is opt-in and read-only. Provider errors and missing vantages are recorded as UNKNOWN, not healthy or filtered.
- This roadmap documents planned work only; no HD-01/HD-02 implementation, source tests or live deployment are implied by this documentation commit.
