# NVL Network Intelligence — live group alerts (P2/P3 combined pilot)

> **2026-11-22 real-event tuning:** A field-confirmed filtering incident showed first suspicious sample at 20:56:32 Tehran, second at 20:57:34 and original 3-of-5 alarm at 20:58:36. Offline audit of 207 decision records (17:50–21:25 Tehran) showed zero Fast-2-consecutive matches before 20:55; proposed time saving 62 seconds. This sample is too short to claim a general false-positive rate. Live fast alert rollout is a separate pinned hotpatch: [Fast SUSPECTED release guide](FAST_SUSPECTED_ROLLOUT_2026-11-22.md). Keep original DEGRADED and recovery gates unchanged.\n\n> **2026-11-22 operator field update:** Core live timer, a 60-minute verified baseline and a successful Telegram group send-test were reported. For the follow-up ETH baseline/UI update **do not reinstall or reset** the active service; use the [pinned code-only ETH reference and alert UX hotpatch](LIVE_ALERT_UX_ETH_REFERENCE_PATCH_2026-11-22.md). The original deployment procedure below is for first-time installations.

**Status:** source and deployment tooling delivered; production activation is a separate operator-controlled action.  
**Decision:** owner explicitly waived Shadow Mode on 2026-11-22. Group alerts will therefore be sent directly with a visible **LIVE PILOT / evaluation** disclaimer. The goal is to assess alert usefulness and refine thresholds, **not** to certify filtering cause.

## Fixed scope

- **Core only**, one active Edge at any time; existing 60-second JSONL collector only.
- SSH established local TCP `2252`; UDPGW established local TCP `7300`; UDPGW CLOSE-WAIT **remote** TCP `7300`. Do not sum opposite loopback sides.
- AWG `awg0` RX/TX Mbps calculated from Linux kernel counters; no dependency on Netdata API uptime.
- Delivery: one **explicit, negative Telegram group chat ID** using the existing NVL bot's sendMessage token; optional topic ID. Never fallback to administrator DMs. No additional Telegram getUpdates poller.
- Do not modify Core's live `gost`, SSH, UDPGW, `awg0`, `wg0`, DNS, user sessions, firewall, failover, bot worker, or Netdata.
- The monitor is its own `nvl-network-alerts.service` + timer; no changes to `nvl-network-sampler.timer` and no restart to `nvlbot`.
- No client IPs, user IDs, usernames, plaintext bot token, or raw customer telemetry in group notifications or GitHub.

## Gate 1 — exact-release stage and installation

Run commands as root on the real Core. Choose the **squash merge SHA of this PR**, not an unpinned `master` URL.

```bash
# Replace with the actual reviewed 40-hex merge SHA
SHA=REVIEWED_MERGE_SHA

curl -fLsS --retry 2 \
 "https://raw.githubusercontent.com/DenaSon/nvl-bot/$SHA/ops/nvl_network_live_alert_install.sh" \
 -o /root/nvl-network-live-alert-install.sh

# No changes; compile and stage checks only.
bash /root/nvl-network-live-alert-install.sh --sha "$SHA"

# Installs only separate program files and disabled systemd units.
bash /root/nvl-network-live-alert-install.sh --sha "$SHA" --apply
```

Expected `STAGE_PASS` and `INSTALL_PASS`. Confirm the existing sampler still runs:

```bash
systemctl is-active nvl-network-sampler.timer nvlbot netdata
systemctl is-enabled nvl-network-alerts.timer || true
```

The new timer is deliberately **not** enabled by installation.

## Gate 2 — configure **one confirmed Telegram group**

The installed Bot API sender reads the original bot token from `/etc/nvlbot/nvlbot.env` (the normal repository systemd template) and writes a **private 0600** copy restricted to this monitor. **Do not paste the token in a CLI argument, GitHub or chat.**

First check the actual live systemd EnvironmentFile path (output only the path, never environment values):

```bash
systemctl show nvlbot -p EnvironmentFiles --value
```

Then:

```bash
python3 /opt/nvl-network-alerts/nvl_network_live_alerts.py configure \
  --bot-env /etc/nvlbot/nvlbot.env
```

The command prompts only for the **negative Telegram group chat ID**, e.g. `-1001234567890` is a placeholder, NOT your real group. If the group uses topics, optionally supply `--topic <actual_positive_thread_id>`. The bot must already be a member with permission to send messages.

Send ONE explicitly labeled test:

```bash
python3 /opt/nvl-network-alerts/nvl_network_live_alerts.py send-test
```

Expected `TEST_SENT` with `message_id`. **Check the exact intended group** received the test before enabling periodic alerts.

If BOT_TOKEN is not in that exact environment file, stop and inspect the running bot's EnvironmentFile path; do not copy secrets into Git or output them in logs. The group ID can be supplied with `--chat-id '-100...'` without interactive prompt.

## Gate 3 — generate a genuine baseline from a verified healthy hour

The historical **29-minute** pre-disruption baseline from 15:20–15:49 Tehran remains `RESEARCH_ONLY` and is **rejected for live use**.

Choose one FULL 60-minute UTC interval when the operator has independently confirmed user connectivity and network recovery. Verify the window does not include an incident or recovery. Example to calculate the most recent 60 minutes ending five minutes ago on Ubuntu:

```bash
END="$(date -u -d '5 minutes ago' +'%Y-%m-%dT%H:%M:00+00:00')"
START="$(date -u -d '65 minutes ago' +'%Y-%m-%dT%H:%M:00+00:00')"
printf 'Check independently that this full window was healthy: %s .. %s\n' "$START" "$END"

python3 /opt/nvl-network-alerts/nvl_network_live_alerts.py baseline \
  --start "$START" --end "$END" --confirmed-normal
```

**`--confirmed-normal` is an explicit human declaration.** Do not use it while filtering is underway. The baseline command rejects <60 minutes, <80% valid distinct-minute coverage, missing AWG rates, extremely weak traffic, excessive CLOSE-WAIT or disproportionate UDPGW loss. The generated baseline is immutable after the live state database exists; rotate it only in a separately approved, stopped maintenance operation.

## Gate 4 — turn on **real** notifications

Only after the operator has verified the test message and the baseline result is `BASELINE_READY`:

```bash
systemctl daemon-reload
systemctl enable --now nvl-network-alerts.timer
systemctl start nvl-network-alerts.service
systemctl is-active nvl-network-alerts.timer
journalctl -u nvl-network-alerts.service -n 30 --no-pager
python3 /opt/nvl-network-alerts/nvl_network_live_alerts.py status
```

**This sends real Telegram group notifications** when the detection rules match. No flags are needed in the existing `nvlbot`. The sender is synchronous, queue-backed, and retrying, with no admin-DM fallback.

Emergency disable (does not touch sampler/SSH/Bot): `systemctl disable --now nvl-network-alerts.timer`. Unsent outbox and incident state remain available for inspection.

## Rules and messages

| Transition | Core evidence gate | Group message |
|---|---|---|
| `NORMAL → SUSPECTED` | **Fast:** SSH >=1.25× and CLOSE-WAIT >=max(3×, baseline+20) in **2 consecutive valid** samples; **fallback:** same conditions in >=3 of last 5 samples | **🟠 اختلال احتمالی**: ID, time, 5 detector metrics plus 2 optional ETH metrics and relative changes |
| `SUSPECTED → DEGRADED` | SSH >=1.40× and CLOSE-WAIT >=max(5×, baseline+40), plus either AWG TX <=0.75× or UDPGW <=0.80× in >=3 of 5 | **🔴 تشدید اختلال** (once per incident) |
| `DEGRADED/SUSPECTED → RECOVERING` | >=5 of last 7 recovery candidates | State logged; no extra group message |
| `RECOVERING → NORMAL` | >=10 consecutive recovery samples, >=10 min elapsed since entering RECOVERING | **🟢 بازیابی** (once if incident was announced) |
| Stale/missing essential evidence | No fresh sample for >5 min, or 5 incomplete metric samples | **⚪ وقفه در پایش** (one; never treated as recovery) |
| Live source resumes | 5 valid samples for non-incident path, or sufficient recovery confirmation during incident | **🔵 پایش از سر گرفته شد** (once) |

- Recurrence within 20 minutes of recovery suppresses duplicate SUSPECTED messages; a new DEGRADED escalation still sends.
- An event outbox has `incident_id:phase` idempotency keys and persisted delivery attempts/message ID. Telegram retries have exponential backoff. As with other Bot API integrations, a crash *after Telegram accepts a send but before local state commits* can produce a duplicate: true exactly-once transport is not guaranteed.
- `UNKNOWN` pauses recovery, not mistaken as `NORMAL`.
- `N/A` and an unavailable bandwidth sample are never treated as zero.
- Timezone is Asia/Tehran; timestamps are grounded in sample `timestamp_utc`.
- No per-user identity or IP is displayed.
- Pilot metrics are **indicators, not proof of ISP filtering**. No changes to traffic routing or Edge failover.

## Measurement/evaluation after enabling

- File source: `/root/nvl-network-observations/nvl-samples-YYYYMMDD.jsonl` (collector still writes it).
- Alert state, outbox, and de-identified per-sample decision rows: `/var/lib/nvl-network-alerts/state.sqlite3`, root-only.
- Immutable baseline: `/var/lib/nvl-network-alerts/baseline.json`.
- Group messages include Incident ID, timing, SSH, UDPGW established/CLOSE-WAIT, AWG RX/TX, optional corroborating ETH RX/TX, and percentage change vs baseline. ETH and AWG traffic are never summed.
- Periodically audit `decisions` and `outbox` from the DB **without exposing Telegram token**.
- Evaluate sensitivity, first-warning lag, escalation lag, closure lag, duplicate count, misses and false positives against operator-labeled incidents.
- Baseline refresh and new threshold tuning require an explicit separate reviewed patch or planned stopped release. Never auto-learn from disruption/unknown/recovery periods.

## Tests and production acceptance

```bash
python3 -m unittest tests.test_nvl_network_live_alerts -v
```

Acceptance requires: CI green; stage installer PASS; expected group test message observed; 60min operator-confirmed baseline PASS; running timer; a staged real/pending event in group with metrics; no duplicate chatter; no effect on existing Core users. GitHub merge and install alone do not constitute live group delivery.

### Rollback

```bash
systemctl disable --now nvl-network-alerts.timer
systemctl stop nvl-network-alerts.service 2>/dev/null || true
```

No SSH/GOST/UDPGW/AWG/Bot/Netdata/collector restart is needed.
