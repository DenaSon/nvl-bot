#!/usr/bin/env bash
# NVL Core live-alert cosmetic/ETH reference patch; stage-only by default.
# The original bot, network services and sampler are NEVER restarted.
set -Eeuo pipefail
umask 077

SHA=""
APPLY=0
while (($#)); do
  case "$1" in
    --sha) SHA="${2:?SHA missing}"; shift 2 ;;
    --apply) APPLY=1; shift ;;
    *) echo "BAD_ARGUMENT" >&2; exit 64 ;;
  esac
done

[[ "$(id -u)" == 0 ]] || { echo "ROOT_REQUIRED" >&2; exit 77; }
[[ "$SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "PINNED_SHA_REQUIRED" >&2; exit 64; }
ROOT=/opt/nvl-network-alerts
TARGET="$ROOT/nvl_network_live_alerts.py"
[[ -f "$TARGET" && ! -L "$TARGET" ]] || { echo "LIVE_PROGRAM_MISSING" >&2; exit 78; }
[[ -f /var/lib/nvl-network-alerts/baseline.json ]] || { echo "BASELINE_MISSING" >&2; exit 78; }
[[ -f /etc/nvl-network-alerts/telegram.json ]] || { echo "TELEGRAM_CONFIG_MISSING" >&2; exit 78; }

stage="$(mktemp -d /root/nvl-network-ux-stage-XXXXXXXX)"
cleanup() { rm -rf "$stage"; }
trap cleanup EXIT
curl --fail --location --silent --show-error --retry 2 --connect-timeout 10 \
     --max-time 30 \
  "https://raw.githubusercontent.com/DenaSon/nvl-bot/$SHA/ops/nvl_network_live_alerts.py" \
  -o "$stage/nvl_network_live_alerts.py"
python3 -B -m py_compile "$stage/nvl_network_live_alerts.py"
PYTHONPATH="$ROOT:$stage" python3 -B "$stage/nvl_network_live_alerts.py" --help >/dev/null
grep -q 'enrich-eth-baseline' "$stage/nvl_network_live_alerts.py" || {
  echo "REQUIRED_PATCH_COMMAND_MISSING" >&2; exit 78;
}
echo "STAGE_PASS SHA=$SHA"

if [[ "$APPLY" -eq 0 ]]; then
  echo "STAGE_ONLY=yes; live timer unchanged"
  exit 0
fi

systemctl is-active --quiet nvl-network-alerts.timer || {
  echo "LIVE_ALERT_TIMER_NOT_ACTIVE" >&2; exit 78;
}
python3 -B "$TARGET" status >/dev/null || {
  echo "CURRENT_MONITOR_UNHEALTHY" >&2; exit 78;
}

backup="$(mktemp -d /root/nvl-network-alerts-ux-backup-XXXXXXXX)"
chmod 700 "$backup"
cp -a "$TARGET" "$backup/nvl_network_live_alerts.py"
echo "BACKUP=$backup"

replaced=0
restore() {
  rc=$?
  if ((rc != 0 && replaced == 1)); then
    echo "PATCH_FAILED: restoring only monitor source code" >&2
    cp -a "$backup/nvl_network_live_alerts.py" "$ROOT/.nvl_network_live_alerts.py.rollback"
    mv -f "$ROOT/.nvl_network_live_alerts.py.rollback" "$TARGET"
    chmod 700 "$TARGET"
    echo "ROLLBACK_CODE_RESTORED" >&2
  fi
  systemctl start nvl-network-alerts.timer || {
    echo "TIMER_RESTART_NEEDS_OPERATOR_ATTENTION" >&2;
  }
  cleanup
}
# Preserve the existing timer's enabled status; briefly pause ticks during the
# atomic file swap. No runtime state, baseline.json or Telegram credentials change.
systemctl stop nvl-network-alerts.timer
trap restore EXIT

# Allow an in-progress one-shot tick to finish rather than interrupting a send.
for i in $(seq 1 45); do
  if ! systemctl is-active --quiet nvl-network-alerts.service; then
    break
  fi
  sleep 1
done
! systemctl is-active --quiet nvl-network-alerts.service || {
  echo "INFLIGHT_TICK_BUSY" >&2; exit 78;
}
install -m 700 "$stage/nvl_network_live_alerts.py" \
    "$ROOT/.nvl_network_live_alerts.py.next"
mv -f "$ROOT/.nvl_network_live_alerts.py.next" "$TARGET"
replaced=1

# One-time reference anchored to the existing operator-verified healthy hour;
# never rebuild or overwrite baseline.json, state.sqlite3 or the Telegram config.
if [[ -f /var/lib/nvl-network-alerts/eth-reference.json ]]; then
  echo "ETH_REFERENCE_PRESENT: verifying existing binding"
else
  python3 -B "$TARGET" enrich-eth-baseline
fi
python3 -B "$TARGET" status
systemctl start nvl-network-alerts.timer
systemctl is-active --quiet nvl-network-alerts.timer
replaced=0
trap - EXIT
cleanup
echo "PATCH_APPLY_PASS SHA=$SHA"
echo "LIVE_TIMER=ACTIVE"
echo "UNMODIFIED=nvlbot,sshd,gost,udpgw,awg,netdata,sampler,baseline,state,telegram"
