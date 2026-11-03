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
