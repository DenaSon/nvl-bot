# NVL Core — P0/P1 operator runbook (offline only)

**Do not run from an unreviewed branch in Production.** Execute only after checking the PR and its CI. This tooling never interacts with `sshd`, GOST, AWG, UDPGW, bot, Netdata or systemd. Archiving writes **new files only** under the archive destination, not under the collector source.

The repository PR contains source and synthetic unit tests. **Actual Core evidence is not included**; real replay/archival is pending an explicit operator execution on Core.

## 0. Inspect the existing Core evidence (read-only)

```bash
ls -lh /root/nvl-network-observations/
systemctl is-active nvl-network-sampler.timer
python3 -V
```

Do not modify the existing `/root/nvl_network_sampler.py` or its timer. Download/copy the reviewed `ops/nvl_network_intelligence.py` to a separate location on Core (example: `/root/nvl-network-intelligence.py`) and verify the SHA/commit against the reviewed PR; **do not execute unpinned remote URLs**. The CLI examples below use `python3 /root/nvl-network-intelligence.py`.

## 1. P0: archive the Nov 22 incident, preserving raw records

The incident window uses explicit UTC offsets. Nov 22 **15:10–16:45 Tehran** is **11:40–13:15 UTC**.

```bash
umask 077
python3 /root/nvl-network-intelligence.py archive \
  --source /root/nvl-network-observations \
  --dest /root/nvl-network-evidence-archive \
  --event-id NVL-INC-20261122-A \
  --start '2026-11-22T11:40:00+00:00' \
  --end   '2026-11-22T13:15:00+00:00'

python3 /root/nvl-network-intelligence.py verify \
  --folder /root/nvl-network-evidence-archive/NVL-INC-20261122-A
```

Expected: `PASS`, non-zero archived JSONL records, and the four corresponding incident/recovery snapshots. The archiver preserves each snapshot **byte-for-byte** and a lossless **time-scoped slice** of JSONL lines; manifest records SHA256 and file size. It rejects pre-existing event IDs, malformed samples, and keys that may contain identity data. On any failure, do not delete/rebuild a prior immutable event; audit the cause.

For the preceding midnight event, use a **separate event ID and range**, e.g.:

```bash
python3 /root/nvl-network-intelligence.py archive \
  --source /root/nvl-network-observations \
  --dest /root/nvl-network-evidence-archive \
  --event-id NVL-INC-20261122-MIDNIGHT \
  --start '2026-11-21T20:30:00+00:00' \
  --end   '2026-11-21T22:30:00+00:00'
```

This separate archive contains the prior disruption snapshot but will **not invent the missing Netdata metrics**. Share only counts, manifest hash summary and de-identified reports; never post raw logs to a public repository or a Telegram group.

## 2. P1: read-only quality audit and replay

Because the only close-in pre-incident verified interval is **29 minutes** (15:20–15:49 Tehran), production baseline rules intentionally **reject** it. Use `--research` exclusively for this historical replay:

```bash
python3 /root/nvl-network-intelligence.py audit \
  --source /root/nvl-network-observations \
  --start '2026-11-22T11:50:00+00:00' \
  --end '2026-11-22T13:15:00+00:00' \
  --baseline-start '2026-11-22T11:50:00+00:00' \
  --baseline-end '2026-11-22T12:20:00+00:00' \
  --research

python3 /root/nvl-network-intelligence.py replay \
  --source /root/nvl-network-observations \
  --start '2026-11-22T11:50:00+00:00' \
  --end '2026-11-22T13:15:00+00:00' \
  --baseline-start '2026-11-22T11:50:00+00:00' \
  --baseline-end '2026-11-22T12:20:00+00:00' \
  --research
```

Expected: `baseline.status=RESEARCH_ONLY`, coverage >= 0.8, a replay timeline in UTC with transition reasons, `telegram_messages_sent=0`. Read the sequence critically: the real samples are not included in Git, and **detection time cannot be certified until replay has run on those actual JSONL rows**. The snapshot labeled `normal` at 16:17 is not used for baseline.

For future production-grade baseline evaluation, pass a separately confirmed **>=60 minute clean window** and **omit** `--research`. Never auto-train on periods previously flagged as anomaly or recovery.

## 3. Safety/quality checklist

- Verify source files remain byte-identical and timestamps retain timezone offset.
- Netdata outage should **not** stop replay if independent `interface_rates_kbps.awg0` exists.
- Missing kernel rate, interface re-creation, reboot/counter reset and impossible numeric values must yield `UNKNOWN` or insufficient coverage, not zero.
- `7300` established uses **local** port; its CLOSE-WAIT uses **remote** port. Counting both loopback endpoints inflates connection counts.
- Do not interpret a `normal` filename as verified training data.
- A missing event's telemetry or prolonged gap must **not** generate false recovery.
- Unit tests (from the reviewed repository): `python3 -m unittest tests.test_nvl_network_intelligence -v`.
- No alarms, Telegram sends, daemon installs, timer changes, restarts or traffic reconfiguration are authorized by this runbook.

## 4. P0/P1 acceptance

| Deliverable | Current stage |
|---|---|
| Incident evidence chronology and source list | Source documented |
| Archive/verify tool with SHA256 and immutable ID | Source implemented |
| Replay/median baseline and sensor quality gates | Source implemented |
| Synthetic replay, archive, tainted-label tests | Implemented (CI pending) |
| Actual Core archive + independent hash verification | **Pending operator-run commands** |
| Real minute-by-minute replay report on Core | **Pending operator-run commands** |
| P2 Shadow / P3 Telegram / P4 live monitoring | **Not started** |

Core user connectivity stays out of scope. The bot and Netdata panel are not touched by this phase.
