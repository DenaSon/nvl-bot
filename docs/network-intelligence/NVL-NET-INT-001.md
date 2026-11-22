# NVL-NET-INT-001 — Core-only Network Intelligence

**Status:** P0/P1 source delivery, **not deployed**; Telegram alerts OFF.  
**Scope:** one Core, at most one active Edge, SSH customer TCP 2252, local UDPGW TCP 7300, AWG interface awg0.  
**Event date:** 2026-11-22 (Asia/Tehran, UTC+03:30).  
**Evidence authority:** owner-observed Core CLI outputs; source JSON/JSONL remains on the live Core until locally archived and independently verified.

## Invariants

- Do not touch `gost:443`, `sshd:2252`, `badvpn-udpgw:7300`, `awg0`, `wg0`, `nvlbot`, `netdata` or the current sampler.
- Use the existing Core JSONL files. No Edge agent or new source of truth.
- Data collection is independent from Netdata via kernel byte counters; Netdata may supply optional corroboration.
- No user IP, username, Telegram token, chat ID or credentials in evidence, reports or repo.
- Never sum RX and TX, nor eth0 and awg0 to infer unique consumption. Do not double-count UDPGW loopback.
- `normal` in a manual snapshot is an **operator label**, not a proof of safe training data.

## Archived source filenames to preserve on Core

```
/root/nvl-network-observations/20261121T180249.761648Z_normal.json
/root/nvl-network-observations/20261121T212715.200902Z_disruption.json
/root/nvl-network-observations/20261122T124126.679100Z_disruption.json
/root/nvl-network-observations/20261122T124734.991008Z_normal.json
/root/nvl-network-observations/20261122T125207.139768Z_normal.json
/root/nvl-network-observations/20261122T125540.611344Z_normal.json
/root/nvl-network-observations/nvl-samples-20261121.jsonl
/root/nvl-network-observations/nvl-samples-20261122.jsonl
```

The late-night incident snapshot contains socket counts but zero Netdata charts: all eight queries failed. It must never be treated as a zero-bandwidth observation.

## Main 2026-11-22 incident observations

A measured **provisional** baseline from 29 one-minute samples between 15:20 and 15:49 Tehran:

| Window | N | SSH 2252 | UDPGW 7300 | UDPGW CLOSE-WAIT | AWG RX Mbps | AWG TX Mbps |
|---|---:|---:|---:|---:|---:|---:|
| 15:20 | 10 | 152.40 | 137.20 | 11.00 | 4.36 | 31.18 |
| 15:30 | 9 | 156.33 | 144.67 | 8.44 | 5.10 | 43.40 |
| 15:40 | 10 | 153.30 | 139.40 | 11.00 | 4.56 | 35.55 |
| **Weighted 29-sample mean** | **29** | **153.93** | **140.28** | **10.21** | **4.66** | **36.48** |
| 15:50 | 10 | 197.40 | 133.60 | 54.80 | 3.91 | 35.79 |
| 16:00 | 9 | 287.78 | 121.44 | 139.67 | 3.41 | 30.35 |
| 16:10 | 4 | 260.00 | 107.00 | 130.50 | 2.33 | 22.75 |

The window beginning 16:10 contains **only 4 samples**; no claim of 10-minute completeness is justified. The first visible group-level change was around **15:50**, not necessarily the ISP's actual onset time.

### Snapshots (point-in-time socket counts)

| Tehran | Label | SSH established | UDPGW established | UDPGW CLOSE-WAIT |
|---|---|---:|---:|---:|
| 16:11:26 | disruption | 259 | 107 | 133 |
| 16:17:34 | normal, **contaminated** | 248 | 29 | 202 |
| 16:22:07 | normal, recovery | 130 | 114 | 14 |
| 16:25:40 | normal, recovery | 134 | 122 | 7 |

`20261122T124734.991008Z_normal.json` MUST be excluded from training despite the label. Recovery at 16:25 shows socket normalization; it is not proof that every end user successfully reconnected.

### Netdata 10-minute rolling averages (not instantaneous)

| Tehran | AWG RX | AWG TX | ETH RX | ETH TX |
|---|---:|---:|---:|---:|
| Nov 21 21:32 normal | 5.67 | 38.24 | 42.95 | 43.68 |
| Nov 22 16:11 disruption | 4.06 | 39.58 | 42.10 | 43.53 |
| Nov 22 16:22 recovery | 2.68 | 21.40 | 23.40 | 23.98 |
| Nov 22 16:25 recovery | 3.66 | 33.92 | 36.20 | 37.54 |

These windows overlap different phases. Never equate a rolling Netdata mean with a one-minute kernel rate. Under the same host, 108 UDPGW-related CLOSE-WAIT sockets were held by `sshd`; a later audit showed 28 across 28 separate `sshd` PIDs, all with an established customer-port socket. That observation does not prove a software bug.

## P0 scope and acceptance

1. Preserve exact incident snapshots and lossless raw JSONL record slices, plus SHA-256 and sizes.
2. Validate all timestamps, original schema, correct local/remote port direction and kernel Mbps conversion.
3. Validate no sensitive identity keys in selected JSON.
4. Archive into a permission-restricted, new, **never overwritten** event directory. Verify hashes.
5. Keep the original Core files and sampler intact. Do **not** check raw incident files into public GitHub.

**Core archival is pending:** repository access cannot read `/root/nvl-network-observations` on the customer's server. Follow the operator runbook to execute P0 against real Core data.

## P1 scope and acceptance

1. Use only an *explicit operator-confirmed* clean time interval for baseline. Never infer trust from filenames.
2. Standard baseline: >=60 minutes and >=80% valid distinct-minute coverage, per-sample complete 5-signal data.
3. Historical 29-minute evidence: permitted with explicit `--research`, marked `RESEARCH_ONLY` and never eligible for production alerting.
4. Use median (robust center), never mean of the incident-contaminated recovery snapshot.
5. Candidate states: `NORMAL`, `SUSPECTED`, `DEGRADED`, `RECOVERING`, `UNKNOWN`.
6. Initial research thresholds: suspected SSH >=1.25x and CW >=max(3x, baseline+20), degraded SSH >=1.4x and CW >=max(5x, baseline+40) plus AWG TX <=.75x or UDPGW <=.80x; 3 of 5 samples. Recovering: 5 of 7 candidates, then >=10 stable candidates to NORMAL.
7. If required Core metric is absent, classify `UNKNOWN`, never fabricate a zero; telemetry gap must not be a recovery.
8. Replay is offline and creates **zero Telegram messages**. A false-positive rate cannot be established from one labeled event.

## Boundaries

**P2** periodic Shadow detector, **P3** Telegram routing/deduplication, and **P4** production rollout remain expressly out of scope here. No alerts are connected or enabled by P0/P1.

See [P0/P1 Core runbook](P0_P1_RUNBOOK.md).
