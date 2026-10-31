# DenaProbe R2-D1 — Core collector, NVLBot dashboard, Rightel/MCI/Rightel A/B/A handoff

**Canonical state for next conversations, as observed 2026-10-31 (Asia/Tehran).** This document extends rather than overwrites historical [R2-C collector handoff](DENAPROBE_R2C_HARDENING_LIVE_STATE_2026-10-31.md), [R2-D1 Core metrics/dashboard](DENAPROBE_R2D1_METRICS_NVL_ADMIN_DASHBOARD_2026-10-31.md) and [dashboard UI polish](DENAPROBE_R2D1_DASHBOARD_POLISH_GUIDE_2026-10-31.md). Firmware counterpart: [DenaProbe canonical hardware handoff](https://github.com/DenaSon/DenaProbe/blob/feature/docs-denaprobe-aba-field-handoff-20261031/docs/015-DENAPROBE-R2D1-ABA-CARRIER-FIELD-HANDOFF-2026-10-31.md).

## Status matrix: independently distinguish source, CI, observed server, and user-facing UI

| Component | Source | Field/operational evidence | Unverified / deferred |
| --- | --- | --- | --- |
| ESP32 signed telemetry sender | [Firmware R2-A PR #6](https://github.com/DenaSon/DenaProbe/pull/6), [R2-C FIFO PR #7](https://github.com/DenaSon/DenaProbe/pull/7); both open at last GitHub check | Actual ESP32 posts signed DPT/1, collector stores 331 events in inspected sample; previous HMAC HTTPS/ACK physically observed | Exact flashed SHA, R2-C full soak/adverse criteria |
| Isolated Core Collector | R2-B branch `feature/dpt-r2b-core-collector-20261031`, [R2-C Core PR #263](https://github.com/DenaSon/nvl-bot/pull/263) open | Owner-run SQLite read-only query succeeded, records received until 20:52:01 on 2026-10-31 | Exact deployed Collector file SHA, confirmed key `k1` revocation, long-running failure tests |
| Analytics metrics and NVLBot dashboard | [PR #264](https://github.com/DenaSon/nvl-bot/pull/264), open, atop R2-C | Operator screenshot confirmed first dashboard **really visible inside NVLBot** and live data updating; DB report code source-tested | Exact deployed bot SHA not independently attested; source PR not merged |
| Polished Persian dashboard and interpretation guide | [PR #265](https://github.com/DenaSon/nvl-bot/pull/265) open, CI at `430613c88ae282435212c5348f8b2eee0656face` all 3 workflows successful | Production deploy command was supplied; user thanked assistant, but no deploy stdout/independent screenshot of **polished** version in current evidence | Do **not** assert polished code deployed or accepted until verified |
| Alerts/classifier/network actions | **Not implemented in DenaProbe** | No operator-accepted incident engine | R2-D2/D3 and separate authorization for R2-E |

**Critical:** GitHub PR source ≠ merged master ≠ deployed files ≠ physical acceptance. The Core's existing production `nvlbot.service`, `gost.service`, protected routing and `/root/master_bot.db` are separate from DPT Collector.

## Architecture, security and metrics

```text
ESP32 DEVKITV1 -- Wi-Fi to phone hotspot (carrier operator-labeled)
    | SSH probe public Edge host :2252 -> pinned SSH host key, KEX, SERVICE_ACCEPT only
    | independent public HTTPS 64 KiB sample
    |
    +-- DPT/1 signed HTTPS POST --> Cloudflare Tunnel published application
                                   board.nvlsup.online/api/dpt/v1/telemetry
                                   -> 127.0.0.1:18081
                                   -> denaprobe-collector.service [nonroot denaprobe]
                                   -> /var/lib/denaprobe/telemetry.sqlite3
                                              |
                              query-only SQLite URI ?mode=ro
                               /                     \
               denaprobe_ingest/metrics.py     denaprobe_admin_dashboard.py
               local JSON CLI                  NVLBot private-admin Programs UI
                                              24h/7d, refresh, metric help
```

- HMAC device registry `/var/lib/denaprobe/devices.json` must remain private (0600). Initial `k1` was exposed earlier; `k2` used later, but revocation of `k1` remains to be **privately checked without printing any secrets**.
- Collector event table: `telemetry_events(device_id, boot_id, sequence, event_kind, ssh_code, stop_stage, observed_bits, target_id, target_revision, wifi_code, wifi_rssi, https_code, measurement_uptime_ms, https_uptime_ms, sent_uptime_ms, sender_age_ms, https_sender_age_ms, received_at_ms, history_only, unknown_code, body_sha256, raw_json)`. Latest-state: `device_latest_state(ssh_sequence, ssh_received_ms, https_sequence, https_received_ms, last_event_sequence, monitoring_gap)`.
- Freshness in R2-D1: SSH **90s**, HTTPS **360s**, delivery **180s** (presentation heuristic). Historical data never becomes an actionable "network down". `monitoring_gap` is cleared after **two successive eligible fresh SSH results**; a BOOT, Wi-Fi event, or history-only record cannot establish continuity.
- Metrics read via `denaprobe_ingest/metrics.py` (`--db`, `summary --hours 24`, `report --device dp-mci-01 --hours 168 --json`) with SQLite `mode=ro` + `query_only`; bounded rows, no access to keys, no DB mutation. Percentiles are **nearest-rank**; `n` matters.
- Native Telegram admin entry: `🧩 برنامه‌ها → 📡 پایش DenaProbe`. `apps_dpt_24`, `apps_dpt_168`, `apps_dpt_help_24`, `apps_dpt_help_168`; current admin role + live admin registry + actor/private chat revalidated each callback; help page static and DB-free. It distinguishes **staleness, sequence gaps, history-only, and failure classes**, not a VPN/censorship verdict.
- Do not add a public analytics API or grant broad DB/HMAC permissions to the bot. Do not auto-change DNS, Cloudflare, Edge, GOST, user/UID, 6G/6H, or notify admins on every failure.

## The observed A/B/A carrier experiment

Owner-reported network changes (Iran local time): **Rightel → MCI around 20:20; MCI → Rightel around 20:39**, second with a link interruption. These are annotations from the operator, not machine-attested SIM/operator IDs. UTC equivalents **16:50 / 17:09**. The board's Wi-Fi status/RSSI cannot prove which cellular carrier the phone used.

The operator ran a **read-only SQLite/Python extraction** on Core. Dataset: 331 loaded events since 18:00, most recent receive at **20:52:01** Iran local, device `dp-mci-01`; historical cutoff is not "current now". To reduce transition contamination, steady windows exclude ~2 minutes around changes.

| Period (Iran time) | Event rows | SSH eligible PASS / all | History only | SSH transport p50 / p95 ms | SSH Service Accept p50 / p95 ms | HTTPS PASS | HTTPS body p50 / p95 ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rightel 18:18–20:18 (2h) | 236 | **179/184 (97.3%)** | 50 | 3327 / 5752 | 198 / 278 | 28 (+1 slow, +1 clock-not-ready) | 2628 / 2843 |
| Rightel pre 20:03–20:18 | 30 | **30/30 (100%)** | 0 | 3345 / 5585 | **183 / 215** | 5 | 2585 / 2641 |
| **MCI 20:22–20:37** | 30 | **30/30 (100%)** | 0 | 3356 / 4414 | **199 / 392** | 5 | 2830 / 3869 |
| Rightel post 20:41–20:56 | 22 | **22/22 (100%)** | 0 | 3318 / 3440 | **198 / 214** | 4 | 2624 / 3067 |

Note: final "Rightel post" was **incomplete at 20:52**, so it must not be treated as 15 minutes of complete independent coverage. Rightel pre and MCI are each 30 probe observations. MCI DNS p50/p95 = 1/324ms, versus Rightel-pre 1/418ms, Rightel-post 1/315ms. Sender-age p50/p95 MCI 34848/62427ms, Rightel-pre 34851/62404ms, Rightel-post 34843/64110ms. Age captures device measurement→attempted send, not RTT.

### Interpret without overclaim

1. **The counterexample is decisive for scope:** MCI **30/30 SSH Service Accept PASS** and independent HTTPS **5/5 PASS**, *while user reported actual NPV Tunnel/SSH Direct failing*. The probe has **not reproduced** client authentication, channel/forwarding or the exact client routing path. This does **not** prove MCI has no SSH filtering at other stages/destinations; it only demonstrates the tested public Edge pre-auth path works during those attempts.
2. **Service-stage jitter:** MCI Service Accept P95 **392ms** versus **215ms** Rightel-pre and **214ms** Rightel-post, approximately **82% higher vs pre**; sample **20:28:55 seq #198** still PASS with `service_ms=1398` and transport=4490ms. At least ~12/30 MCI observations had `service_ms >=300` from operator-provided timeline. No causal attribution or statistical population inference from this small A/B/A.
3. **Older Rightel errors also exist:** two-hour Rightel baseline included **five `ssh_code=50` `SERVICE_ACCEPT_TIMEOUT`**, `stop_stage=51`, and **50 `history_only`** records. Do not map all 2h anomalies to MCI. Old out-of-order/history-only can coexist with zero observed interior sequence gaps in a period.
4. **Switch-transient failure:** **20:40:31** Iran local, `q=221, ssh_code=30 (SSH_TRANSPORT_TIMEOUT), stop_stage=30 (TCP_OR_SSH_BANNER_UNKNOWN), observed_bits=0, transport_ms=12007`. The next **20:40:54**, `q=222`, was PASS. This is inside the intentionally excluded Rightel re-entry/transitional buffer. It is *not* definitive intentional interference.
5. **RSSI script bug:** ad-hoc `percentile()` filtered values `>=0`, so negative Wi-Fi dBm produced `p50=None,p95=None`. Do not interpret as absent RSSI. Fix analysis helper to allow legitimate negative RSSI; never equate hotspot Wi-Fi signal with carrier RSRP/RSRQ.
6. **Timestamp precision:** the ad-hoc script approximated measurement epoch as `received_at_ms - sender_age_ms`, which **still includes upload/network/ingest time**. Without a bounded upload delay and device clock mapping, this is not an exact measurement timestamp. Preserve ±2m guard and verify reboot/boot ID, sender queue and any outage before attribution.

### Core schema code reference

- Firmware [DPT/1 code registry](https://github.com/DenaSon/DenaProbe/blob/feature/r2c-hardening-fifo-20261031/contracts/dpt/v1/code-registry.json): SSH `1=SERVICE_ACCEPT_PASS`, `30=SSH_TRANSPORT_TIMEOUT`, `50=SERVICE_ACCEPT_TIMEOUT`, stage `30=TCP_OR_SSH_BANNER_UNKNOWN`, `51=WAIT_SERVICE_ACCEPT`, `52=SERVICE_ACCEPT_RECEIVED`. `observed_bits=255` in shown PASS samples denotes pre-auth observed milestones, not full VPN.
- `ssh_code=41 HOST_KEY_MISMATCH` deserves trust/security escalation, never casually label it ISP filtering.
- Missing collector data = unknown delivery/monitor status. SSH `FAILURE` without other independent evidence cannot automatically mean blocked network.

## Reproducible safe read-only Core inspection

Use this to verify current record coverage without printing raw payloads, identities beyond known device id, keys or credentials:

```bash
runuser -u denaprobe -- python3 - <<'PY'
import sqlite3
from datetime import datetime
from zoneinfo import ZoneInfo
db = sqlite3.connect(
    "file:/var/lib/denaprobe/telemetry.sqlite3?mode=ro",
    uri=True
)
db.row_factory = sqlite3.Row
db.execute("PRAGMA query_only=ON")
device = "dp-mci-01"
row = db.execute("""
    SELECT COUNT(*) as n, MIN(received_at_ms) as first_ms,
           MAX(received_at_ms) as last_ms,
           SUM(CASE WHEN history_only=1 THEN 1 ELSE 0 END) AS history
    FROM telemetry_events WHERE device_id=?
""", (device,)).fetchone()
print("records:", row["n"], "history_only:", row["history"])
zone=ZoneInfo("Asia/Tehran")
for label in ("first_ms","last_ms"):
    value=row[label]
    print(label, (datetime.fromtimestamp(value/1000,zone).isoformat()
                  if value is not None else "NO_DATA"))
print("live:", dict(db.execute("""
    SELECT boot_id,ssh_sequence,https_sequence,
           ssh_received_ms,https_received_ms,
           last_event_sequence,monitoring_gap
    FROM device_latest_state WHERE device_id=?
""", (device,)).fetchone() or {}))
db.close()
PY
```

To repeat carrier comparison correctly: use the saved local user-provided A/B/A extraction, filter by approximate `received_at_ms - sender_age_ms` and operator boundaries; preserve `boot_id,sequence,history_only,ssh_code,stop_stage,observed_bits,https_code`; parse only nonsecret diagnostic timing fields `d,x,a,h.bt`. Do not publish `raw_json` wholesale; the original extraction's raw body remained inside the Core script.

**Data limitations:** The ad-hoc extractor's `pass_rate` excludes history-only events, whereas stored events and code breakdown include different sample populations. Treat device local events separately from SSH result kinds. A historical `NOT_TESTED` is not a filtered network.

## Next action — real Windows OpenSSH/NPV comparison, not firmware changes yet

Operator confirmed **OpenSSH Client installed on Windows 10**. No `ssh -vvv` log has been provided; a result/failure stage cannot be inferred.

1. Confirm Windows and board **same target host/IP/port/address-family/forwarding path**. Board tests public Edge TCP/2252, while user verbally said "SSH to Core"; there may be a Core↔Edge indirection. Resolve before interpreting discrepancy.
2. On Windows laptop directly on MCI hotspot (VPN/proxy OFF), collect `ssh -4 -vvv -E "$env:USERPROFILE\Desktop\ssh-mci.log" -p 2252 -o ConnectTimeout=12 -o ConnectionAttempts=1 TESTUSER@PUBLIC_EDGE_HOST`. Verify host key from an independent trusted fingerprint, do not disable StrictHostKeyChecking. Redact user/IP/token/keys/password prior to sharing. Repeat same tested profile on Rightel, output `ssh-rightel.log`.
3. Compare exact SSH phases: TCP; Banner; `KEXINIT/NEWKEYS`; pinned host identity; `ssh-userauth` authentication; session/channel; `direct-tcpip` forwarding. If authenticated, optional single disposable least-privilege test profile can use `ssh -4 -vvv -N -D 127.0.0.1:1080` and `curl.exe --socks5-hostname` for real tunneled traffic, if server permits forwarding.
4. If OpenSSH succeeds but NPV fails on same MCI path, capture safe NPV client log/config differences and compare transport/key/cipher/channel/forwarding behavior; don't assume OpenSSH equivalence.
5. Only after isolating a post-Service-Accept failure should a new **opt-in Phase R2-D2** design userauth/channel probes (bounded, safe, separate disposable credentials, no customer account exposure); not implemented by existing ESP32. Continue R2-D2 controlled fault/queue tests, R2-D3 >=24h soak, R2-E incident hysteresis/notifications later with separate release approval.
6. Quality of data can later be improved with operator-marked carrier switching and per-boot time mapping, but this requires a **design decision** and does not justify silently changing DPT/1 or SQL now.

## Guardrails / release

- Read-only collection analysis is safe; **never use this audit to change DNS, routing, Edge, WireGuard, GOST, customer SSH accounts or failover**.
- Never print or commit `devices.json`, HMAC secret, hotspot password, private host pins or raw credentials. Check `k1` revocation privately.
- PRs #263/#264/#265 open at this handoff. UI polish source at `430613c88ae282435212c5348f8b2eee0656face` had **DenaProbe, Legacy Core Migration and Edge safety CI all SUCCESS**; don't confuse CI green with server rollout.
- No scripts or files in the production Core modified by this documentation handoff.

## Next-chat starter

> Continue DenaProbe R2-D1 A/B/A fault attribution. Read the current paired source docs in DenaSon/DenaProbe: `docs/015-DENAPROBE-R2D1-ABA-CARRIER-FIELD-HANDOFF-2026-10-31.md`, and DenaSon/nvl-bot: `docs/DENAPROBE_R2D1_ABA_FIELD_ANALYSIS_HANDOFF_2026-10-31.md`. The operator observed real NPV SSH Direct trouble on MCI, but ESP32 SSH pre-auth SERVICE_ACCEPT PASS was 30/30 on both Rightel pre and MCI, 22/22 Rightel post (partial). MCI Service P95 392ms vs Rightel 215/214ms; transition q221 20:40:31 ssh_code30 stage30 o0 timeout12s, recovered q222 20:40:54. Telemetry HTTPS continues; it is independent from SSH. Board target is public Edge, user says Core — verify path equality. Windows 10 OpenSSH is installed; next collect scrubbed ssh -4 -vvv and, if suitable, SOCKS test on both mobile networks; no log yet supplied. Avoid merging/deploying or altering prod services absent explicit approval.
