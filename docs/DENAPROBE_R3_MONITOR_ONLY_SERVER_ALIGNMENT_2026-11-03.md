# DenaProbe R3 — Server/Board Monitor-Only Alignment (2026-11-03)

## Decision

DenaProbe is a small, evidence-first ESP32. The current physical rollout uses
`PROBE_DEEP_ENABLED=0`: phone hotspot -> DNS/TCP/pre-auth SSH on the
configured `n1.nvlsup.com:2252` path, plus an independent direct HTTPS control.
No SSH account, private SSH key, relay-side test responder, or change to customer
NPV, Edge, DNS, GOST or network routing is a prerequisite.

Future authenticated Deep SSH remains **deferred**; do not delete its code or
reuse customer login credentials. A pre-auth success never proves NPV traffic
delivery or VPN health.

## Verified compatibility

- Current Collector `--enable-v2` accepts signed DPT/2 messages with `c`
  (independent TCP) and **without** `z` (optional Deep). No change to the
  `/api/dpt/v2/telemetry` API, DPT/1, database schema, HMAC or ACK.
- Existing Core R3 SQLite `/var/lib/denaprobe/telemetry-r3.sqlite3`
  supports the lightweight board: no migration, deletion or rebuild.
- Target 1 was operator-updated to revision 2 using hostname
  `n1.nvlsup.com` and port `2252`. Do not register the target again
  unless the actual monitored endpoint changes.
- `denaprobe_ingest.detector` uses fresh accepted ordered DPT/2 samples;
  no inference of filtering source or health from missing data.

## Minimal classifier alignment

- A signed, current DPT2 measurement with `c.s=1`, pre-auth `s=1`,
  fresh independent HTTPS and **no `z`** is only
  `PREAUTH_REACHABLE` **for recovery of an already-confirmed D0 incident**
  (internal classifier value; not a new DPT wire field).
- With no active D0, pre-auth success still reports `MONITORING_UNKNOWN`
  for full service health: it never becomes `HEALTHY`, opens D1/D2, or
  recovers an existing D1/D2. Deep evidence is required for those classes.
  Loss of hotspot Wi-Fi remains unmeasurable, never a healthy state.
- Two distinct, sequential, fresh `PREAUTH_REACHABLE` observations can
  close an active **D0 TCP unreachable** incident, because they establish
  recovery of the tested initial path only. A RECOVERED Rich Message must
  explicitly say TCP/SSH preauth reachability restored, NOT VPN recovery.
- Existing guards still require fresh direct HTTPS, valid current boot
  and target revision, ordered sequence, and no Wi-Fi/local/unknown failures.
  Silence, failed direct control, old events or gaps never close incidents.
- D0 detection remains observed TCP-path failure, not proof of censorship.

## Deployment status and gates

**Source-only change. No Core or Edge runtime change is made by this PR.**

1. Review CI: `python -m unittest discover -s tests -p 'test_denaprobe*.py' -q`;
   verify R3 detector + Telegram native Rich message tests.
2. Ensure actual R3 bot code (not merely Collector) has been deployed
   and matches its configured DPT2 SQLite path before enabling UI.
3. Keep `NVL_DENAPROBE_R3_ENABLED=0` on the Core bot until the ESP32
   successfully sends fresh DPT2 BOOT + sequential q messages with real ACKs,
   confirmed by read-only SQLite/CLI checks. The Collector may remain live.
4. Field-test healthy TCP+SSH preauth, simulated/reproduced D0 and recovery,
   Wi-Fi loss, direct HTTPS freshness and no Deep evidence. Only after
   permissioned review activate native Telegram Rich notifications.
5. Do not promise D1, D2, full tunnel health or a 90-second alert SLA
   from monitor-only measurements. Validate actual sampling cadence and
   delivery freshness first.

`devices.json` contains secrets. Never paste HMAC keys, SSH private keys,
or unredacted configuration into GitHub, docs, logs or chat.


## Phase A: live-board Rich dashboard and incident notification polish

- The dashboard reads latest accepted current-boot DPT/2 SSH and independent
  HTTPS observations. Board freshness is derived from signed measurement age
  and server receipt time, **not** from the classifier's full-tunnel-health
  result. Local Wi-Fi-down observations and monitoring gaps never masquerade
  as a healthy link.
- One-board cards show initial TCP/SSH reachability, independent HTTPS
  PASS/SLOW/unknown, live-data continuity, last receipt, and the explicit
  unmeasured VPN data path. Compact Persian labels and a contextual footer;
  no implementation notes, internal class names or raw JSON in Telegram.
- Rich incident/recovery notifications report only confirmed transitions:
  two distinct current, ordered observations, then a brief target/route/time
  message with a scoped explanatory tip. Existing SQLite outbox deduplicates
  by transition/recipient, and historical backlogs do not trigger fresh alerts.
- The existing bot owns both tasks, with independent flags:
  `NVL_DENAPROBE_R3_ENABLED=1` enables the admin-only
  dashboard and 30s detector loop; `NVL_DENAPROBE_R3_ALERTS_ENABLED=1`
  enables delivery of incident/recovery notifications. Both default OFF.
  Set alerts ON only with dashboard ON. Disabling alerts leaves live dashboard
  evaluation running without Telegram sends.
- No change to Collector wire formats, firmware, network routing, existing
  DPT/2 database schema or private device secrets. No migration required.
- Core operator preflight (2026-11-03): Collector service path
  `/opt/nvl-dpt-collector-r3` and DB
  `/var/lib/denaprobe/telemetry-r3.sqlite3` reported schema PASS,
  WAL, quick_check OK and 87 DPT/2 events. Current bot
  `/root/bot_final_v49-2.py` has the dashboard flag OFF and does
  not yet contain `denaprobe_rich_admin.py` or
  `denaprobe_alerts.py` on disk; source updates alone are not
  deployment.
- Next operator release: stage exact bot main + R3 modules under
  `/root`, keep isolated Collector running, audit live
  DB access, then explicitly activate flags and test native Rich interactions
  and controlled D0/recovery Telegram delivery. Do not reload bot or
  activate notifications during this source-only phase.

## Fast TCP early-warning sensitivity — 2026-11-03

- On the owner's field-test request, the first **fresh, signed, current-boot,
  nonhistorical** failed TCP probe (`c.s=20/21/22`) now opens a single **early
  observation** notification when Wi-Fi remains connected and sequence
  continuity is valid. The primary goal is earliest useful warning, not a
  censorship verdict. Repeated failed samples within an episode are deduplicated.
- Direct HTTPS control PASS is **not a gate for the early notification**:
  SLOW, absent or failed direct control must not mask an observed failed TCP
  probe. The message explicitly calls the cause uncertain (DNS, target or
  network) and does not claim that the VPN tunnel has failed.
- A subsequent independent valid TCP failure upgrades evidence internally;
  authenticated D1/D2 still require two consecutive samples. A D0 recovery
  still requires **two** fresh consecutive TCP/SSH preauth success samples.
- Wi-Fi-down, unknown/unsupported TCP codes, stale events, history-only
  samples, failed continuity and contradictory SSH success do **not** trigger
  this fast warning. A successful telegram delivery is recorded once per
  transition and admin recipient. The existing `NVL_DENAPROBE_R3_ALERTS_ENABLED`
  remains the delivery gate; no additional env flag is required.
- The detector reads only the last eligible SSH result once per 30-second bot
  cycle. Fast alerts are bounded by that schedule and actual board sample
  delivery, never guaranteed real time. DNS propagation and measurement cadence
  can delay recovery beyond the two-sample confirmation logic.

- For an existing D0, two new signed TCP+SSH preauth PASS samples can
  establish recovery of the **initial tested path** even while independent
  HTTPS is SLOW/unavailable. This does not recover D1/D2 or claim full
  VPN-path health; it avoids stale HTTPS controls artificially delaying TCP
  recovery. No recovery follows silence, skipped history or Wi-Fi loss.

## Fast-alert-only code update on an existing R3 Core bot

This is an **incremental** release: the existing Core already has R3 deployed,
so do **not** re-run the initial full Core R3 code publisher (it intentionally
refuses already-integrated bots), the old one-shot Core publisher, or any ad-hoc
text merge. Only the two changed runtime modules are allowlisted:
`/root/denaprobe_ingest/detector.py` and `/root/denaprobe_rich_admin.py`.

Use the **exact merged master SHA**, not the branch PR SHA. With the clean,
separate checkout at `/root/nvlbot-r3-source`, fetch/checkout that SHA, then:

```bash
SRC=/root/nvlbot-r3-source
SHA=<exact-merged-40-character-commit>
python3 "$SRC/ops/denaprobe_r3_fast_alert_publish.py" --src "$SRC" --sha "$SHA"
# Only if PREFLIGHT_PASS: repeat with --apply to back up, atomically replace
# both files, verify imports in live /root, restart only nvlbot and auto-revert
# those files if the reload fails.
```

This does not modify `nvlbot.env`, `bot_final_v49-2.py`, existing SQLite
records or schema, Collector or firmware. The already-configured
`NVL_DENAPROBE_R3_ALERTS_ENABLED=1` remains required for actual Telegram
notification delivery. Verify the *running bot's* environment, not just the
env file, and confirm a fresh real DPT2 failure and recovery separately.
