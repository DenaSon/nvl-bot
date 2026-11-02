# DenaProbe R3 Phase 1 — independent Core Collector source closeout
**Date:** 2026-11-02 | **Scope:** DPT/1 only, no DPT/2 endpoint/incident engine/bot notifications | **Status:** SOURCE-MERGED to `master` (NVLBot PR #263 -> PR #262; master merge `f68f51e008f41d1e893cfa9df4c6156add3cbd19`), PR-head Python checks and Legacy Core safety passed; **live isolated Collector replacement / ESP32 field acceptance NOT VERIFIED**, post-merge master CI separate.
**Paired firmware:** DenaProbe `feature/r2c-hardening-fifo-20261031`, parent R2-A. Previous live experimental collector on `127.0.0.1:18081` was verified 2026-10-31 *before hardening*; do not assume the installed SHA matches source.

## Reliable live-state invariants
- All inbound raw bytes HMAC-authenticated before durable SQLite record; exact duplicate idempotency ACK; version, boot, target authorization and unknown numeric codes validated. DPT/1 ACK values unchanged.
- Only `k=1` eligible, known, current-boot, sequential, **fresh** SSH results may update `ssh_sequence`. Two eligible SSH samples with consecutive q and at most 90s apart on **Core receipt time** clear `monitoring_gap`. A BOOT or local DEVICE_EVENT is never the first corroborating SSH sample.
- `https_sequence` advances only on a new accepted fresh `h` subobject. Missing `h` does not erase the last legitimate sample; freshness expiry is a downstream monitoring interpretation, not implicit remeasurement.
- Unknown or old `k=2` local events from offline backlog are saved `HISTORY_ONLY` and cannot overwrite `device_latest_state` or generate a new live gap. An actual fresh local event may set `monitoring_gap=1`, but never advance SSH status.
- Threaded HTTP handler admission is bounded to 12 concurrent workers, less than systemd `TasksMax=24`. Saturation responds `503 Retry-After: 5` without launching another handler; bounded read deadline, loopback-only bind. Pending socket queue depth is **not** a thread limit.
- No writes to `/root/master_bot.db`, no imports of live NVLBot, no relay/DNS/GOST changes, no public read/admin endpoint or automatic Telegram alerts.

## Must-pass tests
`python3 -m unittest discover -s tests -p 'test_denaprobe_collector.py' -v` and `python3 -m py_compile denaprobe_ingest/collector.py`, exact-head Python checks.
Test stale local events (q consecutive but age>90s) remain HISTORY_ONLY; unknown local code is not live; overload with all handler permits held returns HTTP 503 and subsequent normal health 200. Include HMAC golden vector, tamper/403, boot replay, duplicate ACK, continuity/gap, fresh HTTPS and SQLite recovery.

## Deployment gate (operator-controlled)
- Review running `denaprobe-collector` PID, installed Python SHA and `/var/lib/denaprobe/telemetry.sqlite3` recent/latest state; confirm `k1` revoked while `k2` active **by key ID only**; do not print secrets.
- Run tests in independent staging checkout; backup installed collector and **SQLite online backup**. Never replace a live sqlite DB from a file copy while WAL active.
- Deploy only independent service file under `/opt/nvl-dpt-collector`, restart **only** `denaprobe-collector.service`, validate public `/healthz` 200, unsigned POST 403, signed ESP32 accepted ACK and latest HTTPS q. Preserve dedicated nonroot service + file mode 0600.
- On regression restore code from backup and restart only isolated collector; do not delete historical telemetry or touch `gost.service`, `nvlbot.service`, private bot DB, tunnel/DNS, customer accounts.
- **No production acceptance** without real operator-run E2E evidence: two sequential fresh SSH q clear gap, HTTPS sample changes q, FIFO delivery across reboot/overflow, no false current status from stale/backlog. Phase 2/3 and alerts remain disabled.
