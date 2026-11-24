# NVL Network Intelligence — P0/P1 Field Acceptance (2026-11-22)

**Scope:** Production Core, one active Edge, observational telemetry only.  
**Acceptance basis:** Operator-supplied CLI stdout on 2026-11-22, running the pinned merged tool at commit `796d7f1016b4c8d65bfc17a1e0ad0fbd313ef962`. This record does not claim independent SSH access or independent retrieval of the raw source files.

## P0 — evidence archive: PASS

Executed on the live Core:

```
python3 /root/nvl-network-intelligence.py archive
    --source /root/nvl-network-observations
    --dest /root/nvl-network-evidence-archive
    --event-id NVL-INC-20261122-A
    --start 2026-11-22T11:40:00+00:00
    --end 2026-11-22T13:15:00+00:00
```

Output:

- Archive path: `/root/nvl-network-evidence-archive/NVL-INC-20261122-A`
- Archive manifest schema: `nvl-network-evidence-1`
- Archive created (UTC): `2026-11-22T13:32:17.500242+00:00`
- 5 files total: **4 exact snapshot copies, 1 JSONL slice of 91 records**
- Verification: `{"status":"PASS","file_count":5,"event_id":"NVL-INC-20261122-A"}`

| File | SHA-256 | Bytes |
|---|---|---:|
| `20261122T124126.679100Z_disruption.json` | `3aa0d571cf8f5898fd9c5bcdf9d50191eac5070c1ad117609860d1f1f902fe19` | 1899 |
| `20261122T124734.991008Z_normal.json` | `2e3aad84133ad2bc056bcccf0850db101c22dc17bff0baaa6ba89f25347b0507` | 1886 |
| `20261122T125207.139768Z_normal.json` | `662385e82bc3fd738a404d7db097e6e81926636d76c1661925bb2f76b3581e54` | 1892 |
| `20261122T125540.611344Z_normal.json` | `aec4b1b3cacff72ec5674cbf928086126a958dff4c0d7f3e2f9c69b4b2578dda` | 1894 |
| `nvl-samples-20261122.jsonl` (scoped slice) | `1802b8a7febf087efb238b348ed926c50eb1c084eeb1c306b63b1c304f6fcd43` | 137245 |

**Evidence custody:** manifest and raw archived files exist on the Core according to CLI output; only this de-identified acceptance report and hashes are committed to Git. An independent off-host backup and verified restoration were **not** completed or claimed.

## P1 — offline research replay: PASS

- Replay input: `2026-11-22T11:50:00+00:00` to `13:15:00+00:00`
- Baseline input: `11:50:00` to `12:20:00` UTC (15:20 to 15:50 Asia/Tehran)
- Baseline sample count: **29**; valid: **29**; coverage: **96.67%**
- Baseline status: **RESEARCH_ONLY**, not production-qualified.
- Input observations: **82** total (29 baseline + 53 post-baseline replay)
- Replay sample count: **53 valid**, **0 UNKNOWN**
- Resulting state: **NORMAL**
- False-positive-rate evidence: `NOT_ESTIMABLE_FROM_ONE_LABELED_EVENT`
- Telegram messages: **0**, production alerts: **false**

Median baseline:

| SSH 2252 | UDPGW 7300 | UDPGW CLOSE-WAIT | AWG RX Mbps | AWG TX Mbps |
|---:|---:|---:|---:|---:|
| 154.0 | 140.0 | 10.0 | 4.3377 | 33.2739 |

### Replay transitions

| UTC | Tehran (UTC+03:30) | From | To | Reason |
|---|---|---|---|---|
| 12:27:43.668966 | 15:57:43 | NORMAL | SUSPECTED | MULTI_SIGNAL |
| 12:39:07.970838 | 16:09:07 | SUSPECTED | DEGRADED | MULTI_SIGNAL |
| 12:56:42.165874 | 16:26:42 | DEGRADED | RECOVERING | MULTI_SIGNAL |
| 13:07:06.734708 | 16:37:06 | RECOVERING | NORMAL | MULTI_SIGNAL |

First grouped evidence change was around **15:50 Tehran**, and the replay SUSPECTED transition was around 7m44s later. This is an **approximate retrospective lag relative to a 10-minute group boundary**, *not* independently measured filtering onset or live alert latency.

Snapshot `20261122T124734.991008Z_normal.json`, collected during an evidently unstable period, remains explicitly **excluded from clean baseline** despite its operator label. The last NORMAL transition reflects the research model's threshold/hysteresis rules, not independent end-to-end user connectivity proof.

## Status and next gates

- **P0:** complete for the 2026-11-22 afternoon incident; local SHA-256 verification PASS.
- **P1:** complete for an offline research replay of this incident; *not* production classifier approval.
- The prior 2026-11-21 night incident was **not** archived by this command. A malformed older record at `nvl-samples-20261121.jsonl:107` was observed previously. Preserve that original file; inspect and archive it separately with a documented evidence-handling decision.
- **P2 (Shadow): NOT DEPLOYED**. Before proceeding, collect and operator-verify >=60 minutes of clean baseline and measure detector false-positive characteristics on additional normal and incident periods.
- **P3 Telegram:** not started; no group notifications wired or sent.
- The system still has no direct Edge probe; these are Core-only *indicators* of probable disruption, not proof of ISP filtering.

## Reference

- [Canonical incident and project scope](NVL-NET-INT-001.md)
- [P0/P1 read-only operator runbook](P0_P1_RUNBOOK.md)
- [P0/P1 source PR #326](https://github.com/DenaSon/nvl-bot/pull/326)
- [P0/P1 cross-day archive hotfix PR #327](https://github.com/DenaSon/nvl-bot/pull/327)
