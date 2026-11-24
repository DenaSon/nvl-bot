#!/usr/bin/env bash
# NVL Network Intelligence - code-only install; no bot/SSH/tunnel restarts.
# Stage-only is the default. --apply installs files and inactive systemd units.
set -Eeuo pipefail
umask 077

SHA=""
APPLY=0
while (($#)); do
  case "$1" in
    --sha) SHA="${2:?missing SHA}"; shift 2 ;;
    --apply) APPLY=1; shift ;;
    *) echo "Invalid argument" >&2; exit 64 ;;
  esac
done

[[ "$EUID" -eq 0 ]] || { echo "ROOT_REQUIRED" >&2; exit 77; }
[[ "$SHA" =~ ^[a-f0-9]{40}$ ]] || { echo "PINNED_SHA_REQUIRED" >&2; exit 64; }
command -v python3 >/dev/null
command -v curl >/dev/null
command -v systemctl >/dev/null
[[ -d /root/nvl-network-observations ]] || { echo "SAMPLER_SOURCE_MISSING" >&2; exit 78; }
systemctl is-active --quiet nvl-network-sampler.timer || {
  echo "SAMPLER_TIMER_NOT_ACTIVE" >&2; exit 78;
}
systemctl is-active --quiet nvl-network-alerts.timer && {
  echo "ACTIVE_ALERT_TIMER: stop manually before any source upgrade" >&2; exit 78;
}

stage="$(mktemp -d /root/nvl-net-alerts-stage-XXXXXXXX)"
cleanup() { rm -rf "$stage"; }
trap cleanup EXIT

base="https://raw.githubusercontent.com/DenaSon/nvl-bot/$SHA"
for path in   ops/nvl_network_intelligence.py   ops/nvl_network_live_alerts.py   systemd/nvl-network-alerts.service.example   systemd/nvl-network-alerts.timer.example; do
  curl -fLsS --connect-timeout 10 --max-time 30 --retry 2        "$base/$path" -o "$stage/${path##*/}"
done

python3 -B -m py_compile "$stage/nvl_network_intelligence.py"                         "$stage/nvl_network_live_alerts.py"
python3 -B "$stage/nvl_network_live_alerts.py" --help >/dev/null
echo "STAGE_PASS SHA=$SHA"

if [[ "$APPLY" -ne 1 ]]; then
  echo "STAGE_ONLY=yes (no installation or timer activation)"
  exit 0
fi

install -d -m 700 /opt/nvl-network-alerts
install -d -m 700 /etc/nvl-network-alerts
install -d -m 700 /var/lib/nvl-network-alerts

backup="$(mktemp -d /root/nvl-network-alerts-predeploy-XXXXXXXX)"
chmod 700 "$backup"
for name in nvl_network_intelligence.py nvl_network_live_alerts.py; do
  if [[ -f "/opt/nvl-network-alerts/$name" ]]; then
    cp -a "/opt/nvl-network-alerts/$name" "$backup/$name"
  fi
done
for name in nvl-network-alerts.service nvl-network-alerts.timer; do
  if [[ -f "/etc/systemd/system/$name" ]]; then
    cp -a "/etc/systemd/system/$name" "$backup/$name"
  fi
done

# Two source modules only; do not replace the existing standalone sampler.
install -m 700 "$stage/nvl_network_intelligence.py"   /opt/nvl-network-alerts/nvl_network_intelligence.py
install -m 700 "$stage/nvl_network_live_alerts.py"   /opt/nvl-network-alerts/nvl_network_live_alerts.py
install -m 644 "$stage/nvl-network-alerts.service.example"   /etc/systemd/system/nvl-network-alerts.service
install -m 644 "$stage/nvl-network-alerts.timer.example"   /etc/systemd/system/nvl-network-alerts.timer

systemctl daemon-reload
systemd-analyze verify /etc/systemd/system/nvl-network-alerts.service   /etc/systemd/system/nvl-network-alerts.timer
echo "INSTALL_PASS SHA=$SHA"
echo "BACKUP=$backup"
echo "TIMER_ENABLED=no"
echo "NEXT=configure group; select confirmed 60m normal baseline; send-test; enable timer"
