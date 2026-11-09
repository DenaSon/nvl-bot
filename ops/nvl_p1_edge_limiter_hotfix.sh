#!/usr/bin/env bash
# NVL P1: protect shared Legacy Edge IPs from SSH limiter punishments.
# Only /root/ip_limiter.py and ssh-limiter.service are affected by --apply.
# Default mode: --check (read-only preflight; no service restart).
set -euo pipefail

if (( $# > 1 )); then
  echo 'Usage: bash nvl_p1_edge_limiter_hotfix.sh [--check|--apply]' >&2
  exit 64
fi
MODE="${1:---check}"
if [[ "$MODE" != '--check' && "$MODE" != '--apply' ]]; then
  echo 'Usage: bash nvl_p1_edge_limiter_hotfix.sh [--check|--apply]' >&2
  exit 64
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo 'ERROR: run as root on the Core host' >&2
  exit 1
fi

LIVE=/root/ip_limiter.py
SERVICE=ssh-limiter.service
BASE=38a635fd296a2893cf92bce2957ce2050463c7bb
FIXED=8312b14edad72a2638af6719f156bc8609c368f3
REPO=https://raw.githubusercontent.com/DenaSon/nvl-bot

[[ -f "$LIVE" ]] || { echo "ERROR: $LIVE missing" >&2; exit 1; }
systemctl is-active --quiet "$SERVICE" || { echo "ERROR: $SERVICE is not active; abort" >&2; exit 1; }
command -v curl >/dev/null || { echo 'ERROR: curl missing' >&2; exit 1; }

WORK="$(mktemp -d /root/nvl-p1-limiter.XXXXXX)"
trap 'rm -rf -- "$WORK"' EXIT
curl -fsSL --retry 2 --connect-timeout 10 --max-time 45 \
  "$REPO/$BASE/promote_edge_to_core.sh" -o "$WORK/base.sh"
curl -fsSL --retry 2 --connect-timeout 10 --max-time 45 \
  "$REPO/$FIXED/promote_edge_to_core.sh" -o "$WORK/fixed.sh"

python3 - "$WORK" <<'PY'
from pathlib import Path
import sys
work = Path(sys.argv[1])
marker = "cat << 'EOF' > /root/ip_limiter.py\n"
for version in ('base', 'fixed'):
    script = (work / f'{version}.sh').read_text(encoding='utf-8')
    if script.count(marker) != 1:
        raise SystemExit(f'ERROR: unexpected {version} source format')
    body = script.split(marker, 1)[1].split('\nEOF\n', 1)[0] + '\n'
    (work / f'{version}.py').write_text(body, encoding='utf-8')
fixed = (work / 'fixed.py').read_text(encoding='utf-8')
for guard in ('SHARED_EDGE_NETWORK = ipaddress.ip_network("10.77.0.0/24")',
              'if is_shared_edge_ip(ip): return',
              'if is_shared_edge_ip(peer_ip): continue'):
    if guard not in fixed:
        raise SystemExit(f'ERROR: missing guard {guard}')
PY

python3 -m py_compile "$WORK/fixed.py"
if cmp -s "$LIVE" "$WORK/fixed.py"; then
  echo 'ALREADY_PATCHED: Production limiter matches the merged source.'
  exit 0
fi
if ! cmp -s "$LIVE" "$WORK/base.py"; then
  echo 'HOLD: live limiter differs from original repo version; no change made.' >&2
  echo 'Review the differences before attempting this deployment.' >&2
  echo "LIVE_SHA256=$(sha256sum "$LIVE" | cut -d ' ' -f 1)" >&2
  echo "BASE_SHA256=$(sha256sum "$WORK/base.py" | cut -d ' ' -f 1)" >&2
  exit 2
fi

if [[ "$MODE" == '--check' ]]; then
  echo 'P1_PRECHECK=READY'
  echo 'MATCHES_BASELINE=YES'
  echo 'FIXED_SOURCE_VALID=YES'
  echo 'NO_FILES_CHANGED=YES'
  exit 0
fi

BACKUP="$(mktemp /root/ip_limiter.py.bak.p1.XXXXXX)"
cp -p -- "$LIVE" "$BACKUP"
NEW="$(mktemp /root/.ip_limiter.py.p1.XXXXXX)"
cp -- "$WORK/fixed.py" "$NEW"
chmod --reference="$LIVE" "$NEW"
chown --reference="$LIVE" "$NEW"
BEFORE_RESTARTS="$(systemctl show "$SERVICE" -p NRestarts --value --no-pager)"
mv -f -- "$NEW" "$LIVE"

if ! systemctl restart "$SERVICE"; then
  cp -p -- "$BACKUP" "$LIVE"
  systemctl restart "$SERVICE" || true
  echo "ROLLBACK: service failed to restart. Backup: $BACKUP" >&2
  exit 3
fi
sleep 7
AFTER_RESTARTS="$(systemctl show "$SERVICE" -p NRestarts --value --no-pager)"
if ! systemctl is-active --quiet "$SERVICE" || [[ "$AFTER_RESTARTS" != "$BEFORE_RESTARTS" ]]; then
  cp -p -- "$BACKUP" "$LIVE"
  systemctl restart "$SERVICE" || true
  echo "ROLLBACK: service failed health check. Backup: $BACKUP" >&2
  exit 4
fi

echo "P1_DEPLOY=PASS"
echo "SERVICE=$(systemctl is-active "$SERVICE")"
echo "BACKUP=$BACKUP"
sha256sum "$LIVE"
