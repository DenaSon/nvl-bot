#!/usr/bin/env bash
# Targeted NVL Core health UI deployment; preserves unrelated local changes.
# Usage: NVL_HEALTH_REV=<40-hex merged commit> bash ops/nvl_server_health_quick_deploy.sh
set -Eeuo pipefail
umask 077

PRE_FEATURE_REV="3f489043e28116da50934daf674927471c84e3db"
PIN="$(printenv NVL_HEALTH_REV || true)"
[[ "$PIN" =~ ^[a-f0-9]{40}$ ]] || { echo "STOP: supply a pinned 40-char NVL_HEALTH_REV"; exit 1; }
[[ "$(id -u)" -eq 0 ]] || { echo "STOP: run as root on NVL Core"; exit 1; }
[[ -s /root/bot_final_v49-2.py ]] || { echo "STOP: live bot missing"; exit 1; }
systemctl is-active --quiet nvlbot || { echo "STOP: nvlbot is not active"; exit 1; }

PYTHON="/root/venv/bin/python3"
[[ -x "$PYTHON" ]] || PYTHON="$(command -v python3)"
STAGE="$(mktemp -d /root/nvl-health-stage-XXXXXXXX)"
BACKUP="$(mktemp -d /root/nvl-health-backup-XXXXXXXX)"
BASE="https://raw.githubusercontent.com/DenaSon/nvl-bot"
ROLLOUT=0
MODULE_EXISTED=0
trap 'echo "STAGE=$STAGE BACKUP=$BACKUP"' EXIT

get_source() {
  curl -fLsS --retry 2 --connect-timeout 10 --max-time 100 \
    "$BASE/$1/$2" -o "$3"
  test -s "$3"
}

echo "PRECHECK: fetching immutable source; live runtime unchanged"
get_source "$PRE_FEATURE_REV" "bot_final_v49-2.py" "$STAGE/before.py"
get_source "$PIN" "bot_final_v49-2.py" "$STAGE/after.py"
get_source "$PIN" "nvl_server_health.py" "$STAGE/nvl_server_health.py"

"$PYTHON" - "$STAGE" <<'PY'
from pathlib import Path
import sys

stage = Path(sys.argv[1])
before = (stage / "before.py").read_text(encoding="utf-8")
after = (stage / "after.py").read_text(encoding="utf-8")
live = Path("/root/bot_final_v49-2.py").read_text(encoding="utf-8")

old_start = '    elif d == "srv_health" and role == \'admin\':'
new_start = '    elif d in ("srv_health", "srv_health_details") and role == \'admin\':'
old_menu = 'InlineKeyboardButton("🖥 وضعیت سرور (CPU/RAM)", callback_data="srv_health")'
new_menu = 'InlineKeyboardButton("🩺 سلامت سرور", callback_data="srv_health")'
end = '    elif d == "srv_brand" and role == \'admin\':'

def section(source, start):
    if source.count(start) != 1:
        raise SystemExit("STOP: health callback start ambiguous or missing")
    a = source.index(start)
    b = source.find(end, a)
    if b < 0:
        raise SystemExit("STOP: health callback end missing")
    return source[a:b]

old_section = section(before, old_start)
new_section = section(after, new_start)
if live.count(old_section) == 1:
    live = live.replace(old_section, new_section, 1)
elif live.count(new_section) != 1:
    raise SystemExit("STOP: live health callback diverged; refusing overwrite")

if live.count(old_menu) == 1:
    live = live.replace(old_menu, new_menu, 1)
elif live.count(new_menu) != 1:
    raise SystemExit("STOP: live settings menu diverged; refusing overwrite")

if "from nvl_server_health import render_large_files, scan_large_files" not in live:
    raise SystemExit("STOP: new scan handler missing")
(stage / "bot_final_v49-2.py").write_text(live, encoding="utf-8")
PY

"$PYTHON" -m py_compile "$STAGE/bot_final_v49-2.py" "$STAGE/nvl_server_health.py"
PYTHONPATH="$STAGE" "$PYTHON" -B -c 'import nvl_server_health; assert nvl_server_health.LARGE_FILE_THRESHOLD_BYTES == 3*1024**3'
cp -a /root/bot_final_v49-2.py "$BACKUP/bot_final_v49-2.py"
if [[ -e /root/nvl_server_health.py ]]; then
  MODULE_EXISTED=1
  cp -a /root/nvl_server_health.py "$BACKUP/nvl_server_health.py"
fi
echo "BACKUP=$BACKUP"
echo "Installing ONLY health callback and health module"

rollback() {
  local status="$1"
  trap - ERR
  if [[ "$ROLLOUT" -eq 1 ]]; then
    echo "ROLLBACK: restoring pre-deploy runtime"
    cp -a "$BACKUP/bot_final_v49-2.py" /root/bot_final_v49-2.py
    if [[ "$MODULE_EXISTED" -eq 1 ]]; then
      cp -a "$BACKUP/nvl_server_health.py" /root/nvl_server_health.py
    else
      rm -f /root/nvl_server_health.py
    fi
    systemctl restart nvlbot || true
  fi
  exit "$status"
}
trap 'rollback $?' ERR

ROLLOUT=1
install -m 0644 "$STAGE/nvl_server_health.py" /root/nvl_server_health.py
install -m 0644 "$STAGE/bot_final_v49-2.py" /root/bot_final_v49-2.py
"$PYTHON" -m py_compile /root/bot_final_v49-2.py /root/nvl_server_health.py
systemctl restart nvlbot
sleep 4
systemctl is-active --quiet nvlbot
"$PYTHON" -B -c 'import sys;sys.path.insert(0,"/root");import nvl_server_health;assert nvl_server_health.LARGE_FILE_THRESHOLD_BYTES == 3*1024**3'
trap - ERR
echo "DEPLOY=PASS"
echo "REV=$PIN"
echo "BACKUP=$BACKUP"
systemctl --no-pager --plain is-active nvlbot
journalctl -u nvlbot -n 12 --no-pager
