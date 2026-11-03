# R2-D1 — Telemetry quality, reliability and NVLBot administrator dashboard

**Status:** Source implementation and tests on `feature/r2d1-metrics-nvl-dashboard-20261031`; based on **open R2-C Collector branch/PR #263**. **Not merged, deployed or operated on Production NVLBot.** This supersedes the earlier R2-D1 assumption that only Core CLI would be affected: owner explicitly requested a native read-only NVLBot dashboard.

## Confirmed 2026-10-31 field baseline (user-provided, real ESP32)

- Active boot `0f5ce74e91a3d2e2446953019067e47a`: 47 stored events, **0 observed sequence gaps**, **0 history-only**.
- SSH 44 PASS / 45 samples; DNS p50/p95 **1/356 ms**, Transport **3307/3706 ms**, Service Accept **184/806 ms**.
- HTTPS body p50/p95 **2624/2843 ms** (8 samples), sender age p50/p95 **30331/65045 ms**.
- Post-R2-C Core live state `(ssh_sequence=33,https_sequence=28,last_event_sequence=33,monitoring_gap=0)`; later PASS sample q34 had complete independent HTTPS `h`.
- These are **small-sample baseline observations**, NOT enforced service thresholds, packet loss measurements, censorship verdicts, LTE radio quality, VPN login tests, or automatic incident triggers.

## Source architecture

```text
ESP32 (existing DPT/1 HTTPS signed POST)
     |
     v
Cloudflare -> loopback isolated DPT Collector -> /var/lib/denaprobe/telemetry.sqlite3
                                              |
                  SQLite read-only mode=ro/query_only, no keyfile access
                          |                              |
                  metrics.py CLI                  denaprobe_admin_dashboard.py
                                                         |
                            Existing NVLBot private admin "🧩 برنامه‌ها" menu
                                     "📡 پایش DenaProbe"
                                     [24 ساعت] [7 روز] [بروزرسانی] [بازگشت]
```

1. `denaprobe_ingest/metrics.py` is stdlib-only, query-only and always uses SQLite URI `mode=ro`, `PRAGMA query_only=ON`; it never imports bot/collector service internals or writes any DB. Windows of 24 hours or 168 hours. `MAX_ROWS=30000` protects memory, explicitly signals truncation. SQL is parameterized, device identifier is validated.
2. Reports include per-boot **interior observed sequence gaps within the selected time window** (not loss attributed to network, nor unknown missing leading/tail events), `history_only`, unknown-code count, counts by kind, sender age p50/p95, SSH success/path/nonpath counts and healthy SSH DNS/transport/service P50/P95, independent HTTPS body P50/P95 and codes.
3. Live state is separately labeled: persisted `monitoring_gap`, latest SSH/HTTPS sequence, and **computed server-receipt freshness at report time** (SSH 90s, HTTPS 360s, delivery 180s). Missing data returns NOT_TESTED. Backend cannot prove filtering from silence. Sender age means sender-reported elapsed uptime from measurement to send, not RTT or complete end-to-end delay. Percentiles use nearest-rank and are marked with sample counts.
4. `denaprobe_admin_dashboard.py` makes an **admin-only private-chat Telegram inline keyboard** panel. Every callback checks both persisted role `admin` and **fresh** active-admin ID registry, then strict `actor == private chat ID`. Callback data is fixed (`apps_dpt_24`, `apps_dpt_168`) and cannot contain device ID, SQL or a file path. Bot connects directly to the read-only SQLite report API; no public statistics endpoint, no exposed SQLite raw payload, no HMAC credentials, no Telegram remote control of board.
5. Existing monolithic `bot_final_v49-2.py` has a minimal Programs hub row and dispatch hook reusing the `apps_*` admin-only gate. No changes to customer traffic, migration, Cloudflare DNS, protected UID, GOST, 6G/6H, failure classification, alerts, or notification workers.

## CLI (private Core)

```bash
cd /root/nvl-dpt-r2d1-check
python3 -m denaprobe_ingest.metrics summary --hours 24
python3 -m denaprobe_ingest.metrics report --device dp-mci-01 --hours 168 --json
# Optional custom path BEFORE subcommand:
python3 -m denaprobe_ingest.metrics --db /var/lib/denaprobe/telemetry.sqlite3 report --device dp-mci-01 --json
```

The bot reads `DENAPROBE_TELEMETRY_DB` (default `/var/lib/denaprobe/telemetry.sqlite3`) and `DENAPROBE_DASHBOARD_DEVICE_ID` (default `dp-mci-01`). Both are **host environment controls**, never Telegram inputs or public settings. The bot process must have read permission for the SQLite DB and WAL-related files without making them world-readable. Do not chown private key files or weaken the `denaprobe` service sandbox.

## Release workflow and regression checks

```bash
python3 -m unittest discover -s tests -p 'test_denaprobe_collector.py' -v
python3 -m unittest discover -s tests -p 'test_denaprobe_metrics_dashboard.py' -v
python3 -m py_compile denaprobe_ingest/metrics.py denaprobe_admin_dashboard.py bot_final_v49-2.py
```

Review the gigantic bot-file PR patch especially carefully. The dashboard is still a code-only artifact until the new module path is staged into the **same Python import root as `bot_final_v49-2.py`**. If the running bot is `/root/bot_final_v49-2.py`, it needs `/root/denaprobe_admin_dashboard.py`, `/root/denaprobe_ingest/__init__.py`, `/root/denaprobe_ingest/metrics.py` and the updated bot script published **as one tested bundle**. Merely updating `/opt/nvl-dpt-collector` does **not** make a new button appear in NVLBot. Do **not** restart NVLBot until independent review/approval and backup of all files it will replace.

Operator-controlled deployment gate after full CI:
1. Make independent backup and SHA inventory of current NVLBot code and its modules. Verify the bot's *actual* service working directory and Python interpreter; never guess.
2. Verify `denaprobe-collector.service` already active and SQLite read-only query returns data. Ensure bot account can read SQLite without changing private HMAC key permissions or bot DB ownership.
3. Stage all three new module files + exact updated bot source in independent checkout. Run tests and Python compile using the bot's actual runtime interpreter.
4. Replace only pre-approved bot code/modules in an atomic, reversible step; restart **only nvlbot** when explicitly approved, keeping the Collector running. Preserve all old handlers/user_data and persistence, and do not touch GOST/WG/DNS/Cloudflare.
5. Private-chat active admin tests: Programs -> DenaProbe 24h -> 7d -> Refresh -> Programs; check current device, freshness and no raw JSON. Unauthorized actor, old callback, group chat, demoted admin must be denied. Close stale/no-data errors safely.
6. Roll back the bot bundle only if startup or UI fails; do not restore/write Collector DB or touch independent service.

## Next phase (not implemented here)

**R2-D2** controlled failure/retry/outage/overflow/reboot scenarios and measurement; **R2-D3** 24-hour hardware soak/baseline calibration; **R2-E** separately approved incident jobs and Telegram alerts. R2-D1's dashboard itself performs **no timer, no background sampling and no auto-actions**.
