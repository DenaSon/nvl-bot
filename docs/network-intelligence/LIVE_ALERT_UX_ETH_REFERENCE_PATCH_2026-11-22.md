# NVL Network Intelligence — ETH reference and Telegram alert UX hotpatch (2026-11-22)

## Scope and change

A production Core live alert timer has already been **activated** and a test Telegram message delivered to group `-1004495255355`. This patch updates the **existing** monitor code only, without touching the bot, network, source sampler, or Telegram configuration.

- Removes the user-facing phrase **«بدون Shadow»** completely.
- Uses compact RTL-aware Telegram HTML: incident ID, Tehran sample time, duration **from first detection** (not proven network onset), aligned metric groups and explicit caution.
- Separates **connection counts** (SSH local 2252, UDPGW local 7300, UDPGW remote CLOSE-WAIT 7300) from **rates** (AWG RX/TX, ETH RX/TX).
- All rate units are Mbps derived from the existing JSONL `interface_rates_kbps`. AWG and ETH are **not summed**.
- Fixes prior reference bug: the normalized P1 baseline intentionally drops ETH0 data; the old baseline builder could not compute ETH medians from these normalized rows. New reference extraction uses the **raw source JSONL** and requires >=80% distinct-minute ETH coverage in the same original verified >=60-minute normal window.
- The existing `baseline.json` is **never modified or replaced**. A one-time owner-only `eth-reference.json` sidecar is bound to it via a SHA-256 fingerprint of the original baseline's created timestamp, window and five classifier values. Existing `state.sqlite3`, outbox, incident ID, bot token and group ID are preserved.
- New `baseline` creations (in future) read ETH from raw data correctly, if available; if unavailable the five Core detector metrics remain usable.
- No new Telegram messages are generated simply by deploying a UX patch; old messages already queued in the outbox retain their originally rendered content.
- All real alarms still go through the existing state machine, confirmations, cooldowns and durable outbox. Thresholds, scheduler and traffic routing are unchanged.

## Exact-release live deployment

**Only** use after PR checks pass and the patch is squash-merged. Replace `PINNED_MERGE_SHA` with the reviewed 40-character SHA.

```bash
SHA=PINNED_MERGE_SHA
curl -fLsS --retry 2 \
  "https://raw.githubusercontent.com/DenaSon/nvl-bot/$SHA/ops/nvl_network_live_alert_ux_patch.sh" \
  -o /root/nvl-network-live-alert-ux-patch.sh

# Read-only stage check. No service changes:
bash /root/nvl-network-live-alert-ux-patch.sh --sha "$SHA"

# Atomic monitored swap and auto ETH sidecar backfill from original baseline:
bash /root/nvl-network-live-alert-ux-patch.sh --sha "$SHA" --apply
```

The script:
1. Checks original live monitor, group config and verified baseline.
2. Downloads pinned replacement, compiles and stages it.
3. Backs up only old monitor Python source in a restricted root folder.
4. Temporarily pauses **only** `nvl-network-alerts.timer`; waits for any inflight one-shot send to finish.
5. Atomically swaps the monitor source, derives `eth-reference.json` from the **existing** approved baseline window and verifies it; never starts another Telegram poller.
6. Starts the same timer and checks active state.
7. Restores the original Python source and restarts timer automatically on a failed swap. If the new sidecar was created before failure, it is harmless to the old code; manually inspect it before rerunning.

Fail closed: insufficient original ETH0 coverage, mismatched sidecar, missing source logs, malformed in-scope rows, failed Python compilation or invalid baseline will abort applying the patch. No recovery of actual customer routes is involved.

## Verification (production)

```bash
python3 /opt/nvl-network-alerts/nvl_network_live_alerts.py status
systemctl is-active nvl-network-alerts.timer
systemctl list-timers nvl-network-alerts.timer --no-pager
journalctl -u nvl-network-alerts.service -n 15 --no-pager
```

Expect `eth_reference_active: true`, phase from the existing detector (not reset), enabled live timer, and normal `IDLE` messages when there is no incident.

Independent baseline compatibility:

```bash
python3 - <<'PY'
from pathlib import Path
import json
a = Path("/var/lib/nvl-network-alerts")
base = json.loads((a / "baseline.json").read_text())
side = json.loads((a / "eth-reference.json").read_text())
print("BASELINE_STATUS:", base["status"])
print("BASELINE_WINDOW:", base["window_start"], base["window_end"])
print("ETH_REFERENCE_SCHEMA:", side["schema"])
print("ETH0_REFERENCE_MBPS:", side["values"])
print("ETH0_COVERAGE:", side["coverage"])
print("SECRETS_PRINTED=NO")
PY
```

**Do not paste `/etc/nvl-network-alerts/telegram.json` or dump `/proc/.../environ`: they contain credentials.**

## Safe fallback / rollback

The patch prints a `BACKUP=/root/nvl-network-alerts-ux-backup-...` containing the original program. To roll back this patch alone, stop only the monitor timer, restore the original file atomically, restart the timer and leave the existing baseline and SQLite untouched. The `eth-reference.json` sidecar is ignored by the older program; keep it for evidence or inspect it separately. **Do not stop nvlbot, SSH, UDPGW, GOST, the AWG tunnel or the sampler.**

## Review and tests

- Unit tests cover correct raw ETH medians, exact original verified normal window, >=80% coverage, immutable original baseline and state, rejection of a sidecar bound to a different baseline, correctly formatted multiline Persian alert cards, 7 metric labels, elapsed time and no `Shadow` phrase.
- Existing tests continue to cover multi-signal incident, dedup, recovery, stale/invalid telemetry, group-only sending and durable retry.
- The real Core patch is **not** deployed merely by GitHub merge. Operator verification is required.
