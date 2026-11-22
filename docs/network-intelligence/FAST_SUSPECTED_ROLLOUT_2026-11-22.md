# NVL fast initial warning — 2026-11-22

## Evidence and scope

Observed real NVL Core pilot event (`NVL-20261122T172836Z-001`):
- 20:55:29 Tehran: first partial anomaly, SSH 184, UDPGW CLOSE-WAIT 26.
- 20:56:32: first SUSPECTED-class sample, SSH 215, CLOSE-WAIT 44.
- **20:57:34: second consecutive SUSPECTED-class sample**, SSH 244, CLOSE-WAIT 67.
- 20:58:36: first real alert from the prior 3-of-5 gate, sent at approximately 20:58:39.
- 21:10:01: DEGRADED transition, retained in this patch.

User's read-only audit of 207 decision rows (17:50–21:25 Tehran) reported:
- 0 pre-event matches for fast 2-consecutive (control period ending 20:55).
- 20:57:34 first event match for 2-consecutive (62s faster than production).
- 2-of-3 also fires 20:57:34 but may accept intermittent noise.
- Stronger 2-consecutive fires 20:58:36, no gain; aggressive single fires 20:56:32, but lacks the second-sample safety guard.
- Recorded decision latency ~2.1s median, max 2.6s; 43/43 raw event samples present in SQLite.

**Decision:** Add one conservative fast gate to the live `SUSPECTED` transition: original two-signal classifier threshold **on two consecutive valid samples**, while preserving existing **3 of 5** fallback. Never fire from only one sample. Do **not** modify classifier thresholds, DEGRADED, RECOVERING, recovery duration, unknown-data handling, 20-minute cooldown, Telegram group, or durable SQLite/outbox semantics. The live timer remains ~60s.

**Limitations:** The proposed 62s gain is an offline replay over one field-labeled incident. No false positives in a ~3h observation window does not quantify a long-term FPR. Detection still depends on the sampler cadence and may not trigger if real filtering does not produce the two-signal pattern.

## Telegram alert UX — English body, Persian title only

This release also includes the final compact Telegram copy requested before the Fast Detection rollout. It is **the same pinned deployment**; do not deploy PR #331 separately first.

- Keep only the event title in Persian for all six message types: SUSPECTED, DEGRADED, RECOVERED, UNKNOWN, RESUMED, TEST.
- All content after the title is English, with no Persian stage labels, verbose notes or repeating 'relative to baseline' on every metric.
- Two compact groups: **Connections** (SSH, UDPGW, CLOSE-WAIT) and **Traffic** (AWG/ETH RX/TX, Mbps). Signed delta percentages always compare against the verified baseline. Missing values show `N/A`; never invent zero.
- One Core + Tehran timestamp line, one optional incident ID line with detection **Age** after minute 0, and one succinct evidence statement/disclaimer.
- Monitor-only messages omit traffic and connections entirely. A test message explicitly says no incident was reported.
- No changes to Telegram send method, API credentials, chat ID, thresholds, recovery, retry, dedup or persisted outbox. Already-queued messages keep the body generated at queue time.

Sample rendered DEGRADED body (illustrative metric values):

```text
🔴 NVL | تشدید اختلال ارتباط
Core · 2026-11-22 21:10:01 Tehran
ID NVL-20261122T172734Z-001 · Age 12m

Connections · vs baseline
SSH 359 +135% · UDPGW 125 -7%
CLOSE-WAIT 202 +1583%

Traffic · Mbps · vs baseline
AWG  RX 3.2 -35% · TX 23.2 -34%
ETH  RX 28.0 -29% · TX 25.9 -37%

Signal: Connection surge + AWG TX / UDPGW decline.
Core telemetry only · ISP filtering not confirmed.
```

The actual Bot API uses HTML bold/italics and the original baseline values. No additional live Telegram message is sent by deployment.

## Safe live deployment (pinned merge SHA)

Install only when checks are green and the GitHub PR has been squash-merged. Replace the placeholder with the precise 40-hex merge commit.

```bash
SHA=REVIEWED_MERGE_SHA
curl -fLsS --retry 2 \
  "https://raw.githubusercontent.com/DenaSon/nvl-bot/$SHA/ops/nvl_network_fast_alert_patch.sh" \
  -o /root/nvl-network-fast-alert-patch.sh
bash -n /root/nvl-network-fast-alert-patch.sh
bash /root/nvl-network-fast-alert-patch.sh --sha "$SHA"
bash /root/nvl-network-fast-alert-patch.sh --sha "$SHA" --apply
```

The installer:
1. Confirms existing live monitor, baseline, config, and active timer.
2. Stages and compiles precisely pinned alert source; stage mode never stops timer.
3. Backs up previous Python source in a private root folder.
4. Temporarily pauses **only** the alert timer, waits for an inflight one-shot run, then atomically swaps source.
5. Does **not** rewrite baseline, ETH reference, DB, queued/sent alerts or Telegram token.
6. Validates status and `eth_reference_active=true`; resumes timer.
7. On failure after a swap, restores original code and restarts only the alert timer.

No `nvlbot`, SSH, AWG/WG, GOST, UDPGW, Netdata or sampler restart. No new send-test or synthetic incident is required. Existing incident state is preserved and is not replayed as a new event. Any previously queued alert keeps its already-rendered body.

## Field verification

```bash
systemctl is-active nvl-network-alerts.timer
systemctl list-timers nvl-network-alerts.timer --no-pager
python3 /opt/nvl-network-alerts/nvl_network_live_alerts.py status
journalctl -u nvl-network-alerts.service -n 12 --no-pager
```

Expect `FAST_ALERT_PATCH_APPLY_PASS`, `LIVE_TIMER=ACTIVE`, `eth_reference_active=true` and advancing sample timestamps. `phase` may be NORMAL, SUSPECTED, DEGRADED or RECOVERING depending on real conditions; never assume NORMAL.

Retain backup printed by installer. For rollback, temporarily stop **only** the monitor timer, restore its previous Python file from that backup, then start the timer; do not reset SQLite or clear the outbox.

## Tests

Synthetic tests confirm:
- First alert on second consecutive valid suspicious sample (one sample earlier than prior 3/5).
- Isolated suspicious spikes never warn.
- Data gaps (>150s) and invalid observations break consecutive confirmation.
- Original 3-of-5 fallback still works with nonconsecutive anomalies.
- Long incidents produce no extra SUSPECTED messages; escalation and recovery are still unchanged.
- All existing Telegram token, group-only delivery, outbox dedup and retry tests remain green.

After deployment, retain labeled events and track first suspicious sample → send time, missed incidents and false positives. Compare before changing escalation thresholds.
