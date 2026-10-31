# R2-C Hardening — Collector live-state corroboration

**Source branch**: `feature/r2c-hardening-live-state-20261031` (based on **open/unmerged** R2-B PR #262); **status: source/test implementation only; NOT installed on Core**.

**Field finding (2026-10-31):** Real ESP32 signed HTTP posts produced durable Core ACK and 8 recorded events, but separate later `device_latest_state` read gave `ssh_sequence=12`, `https_sequence=NULL`, `monitoring_gap=1`. The ESP32 source queued newest-first; older HTTPS-carrying events were HISTORY_ONLY. The paired DenaProbe branch `feature/r2c-hardening-fifo-20261031` fixes delivery order. This Collector change fixes a **separate** confidence bug: previous `last_event_sequence` check counted BOOT or DEVICE_EVENT as the first of the supposed two consecutive SSH observations.

## Code delta

Within existing `store()`, unchanged HMAC/authentication, schema, DB transaction, ordered fresh admission, target-revision lookup and same-body ACK semantics remain in force. For fresh eligible SSH `k=1`:

- `device_latest_state.ssh_sequence` **must** equal `incoming_q-1` for continuity.
- The previous SSH event must have a recorded `ssh_received_ms`, no more than `SSH_MAX_AGE_MS` earlier (server receipt).
- Only if both conditions hold may `monitoring_gap` become 0. First SSH after BOOT or local Wi-Fi status still has gap 1. Local `k=2` events do not overwrite SSH; old/historical/unknown/stale results do not promote latest.
- Missing HTTPS `h` does not clear/reset `https_sequence`. A fresh accepted SSH containing `h` updates HTTPS live channel.

No schema migrations, no DPT/1 wire changes, no alert/Telegram hooks, no other NVLBot imports, no GOST/NPV changes.

## Tests

`tests/test_denaprobe_collector.py` adds:
1. BOOT -> Wi-Fi event -> first fresh SSH+HTTPS: latest HTTPS recorded, monitoring gap remains 1; second fresh SSH result clears gap.
2. Gap and history-only sample followed by two consecutive fresh SSH events: gap clears, later stale event forces next sample to be a new anchor until corroborated again.
3. A prior otherwise eligible SSH event delivered more than the SSH freshness window before the next is not sufficient to establish fresh continuity.

Existing 10 Collector tests (including HMAC golden vector, raw-byte tamper/duplicate 409, exact duplicate r=1, 403, invalid schema, replay protection) remain. New counts and CI must be verified before deployment. Run:

```bash
python3 -m unittest discover -s tests -p 'test_denaprobe_collector.py' -v
python3 -m py_compile denaprobe_ingest/collector.py
```

## Safe migration path (operator approval required)

1. Confirm separate firmware/Collector parent PRs and hardening PRs are reviewed/CI green; do **not** merge/deploy prematurely.
2. On Core, verify `denaprobe-collector` only, capture versions and its live PID. Reconfirm current `board.nvlsup.online` Tunnel origin is `127.0.0.1:18081`.
3. Run isolated new branch unit tests, compare full diff and checksum against previously staged collector `/opt/nvl-dpt-collector/denaprobe_ingest/collector.py`.
4. Use SQLite **online backup** of `/var/lib/denaprobe/telemetry.sqlite3`; take a private backup of old collector file, record checksums; retain all historical rows and the private `devices.json` key registry. Verify k1 revocation via key-id-only inspection; never print secrets.
5. After explicit approval, stop/restart **only** `denaprobe-collector.service` to swap isolated collector code, then verify local/public `/healthz` 200, unsigned POST 403 and signed traffic 200. Do not touch `nvlbot.service`, `gost.service`, port 443 or DNS.
6. Then flash DenaProbe's matching hardening firmware with private `k2` and verified CA; record a **new boot**. Monitor sequential ACK and latest-state `monitoring_gap=0` after **two SSH observations** and a non-null fresh `https_sequence`.
7. On failed validation restore old isolated collector file, restart only that unit and verify 200/403. Do not reset DB or revoke valid k2. Firmware rollback requires a new flash.

**Release acceptance:** not fulfilled until tests, live hardware and operator-run validation pass. No Telegram alert/automated failover changes here.

See [paired DenaProbe hardening runbook](https://github.com/DenaSon/DenaProbe/blob/feature/r2c-hardening-fifo-20261031/docs/014-R2C-HARDENING-FIFO-LIVE-STATE-2026-10-31.md).
