#!/usr/bin/env bash
# Run as root on the OLD NVL Core. Publishes code only; does NOT launch migration.
set -Eeuo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "STOP: run this on the old Core as root."
  exit 1
fi
cd /root
PIN="4e3c5e4d4a55fe423eaf678b3c12bc7852afa9ba"
BASE="https://raw.githubusercontent.com/DenaSon/nvl-bot/${PIN}"
STAGE="$(mktemp -d /root/nvl-promote-stage-XXXXXX)"
BACKUP="$(mktemp -d /root/nvl-promote-backup-XXXXXX)"
FILES=(core_side_failover.sh promote_edge_to_core.sh update_all_awg_edges_endpoint.sh)

echo "BACKUP=$BACKUP"
test -f /root/bot_final_v49-2.py
systemctl is-active --quiet nvlbot

# Download exact merged source and validate everything before touching the live bot.
for file in "${FILES[@]}"; do
  curl -fLsS --connect-timeout 10 --max-time 60 --retry 2 \
    "$BASE/$file" -o "$STAGE/$file"
  test -s "$STAGE/$file"
  bash -n "$STAGE/$file"
  if test -f "/root/$file"; then cp -a "/root/$file" "$BACKUP/"; fi
done
cp -a /root/bot_final_v49-2.py "$BACKUP/"

# Patch ONLY the installed bot's legacy migration callback and its confirmation
# text; do not overwrite unrelated production bot changes.
python3 - "$STAGE" <<'PY'
import pathlib, sys
original = pathlib.Path('/root/bot_final_v49-2.py').read_text()
old_command = (
    '                    f"set -o pipefail; {{ bash /root/core_side_failover.sh {target_ip} {cust_port} "\n'
    '                    f"&& bash /root/demote_core_to_edge.sh {target_ip} {cust_port}; }} "\n'
)
new_command = (
    '                    f"set -o pipefail; bash /root/core_side_failover.sh {target_ip} {cust_port} "\n'
)
old_message = 'پس از راه‌اندازی Core جدید، Core قدیمی به Edge تبدیل خواهد شد.'
new_message = 'پس از راه‌اندازی Core جدید، Core قدیمی خاموشِ سرویس باقی می‌ماند و به Edge تبدیل نمی‌شود.'

if original.count(old_command) == 1:
    original = original.replace(old_command, new_command)
elif original.count(new_command) != 1:
    sys.exit('STOP: installed bot migration callback differs from expected version')

if original.count(old_message) == 1:
    original = original.replace(old_message, new_message)
elif original.count(new_message) != 1:
    sys.exit('STOP: installed bot confirmation screen differs from expected version')

(pathlib.Path(sys.argv[1]) / 'bot_final_v49-2.py').write_text(original)
PY
python3 -m py_compile "$STAGE/bot_final_v49-2.py"

restore() {
  trap - ERR
  echo "DEPLOY=FAILED — restoring previous bot/scripts"
  for file in "${FILES[@]}"; do
    if test -f "$BACKUP/$file"; then cp -a "$BACKUP/$file" "/root/$file"
    else rm -f "/root/$file"; fi
  done
  cp -a "$BACKUP/bot_final_v49-2.py" /root/bot_final_v49-2.py
  systemctl restart nvlbot || true
  exit 1
}
trap restore ERR

for file in "${FILES[@]}"; do install -m 755 "$STAGE/$file" "/root/$file"; done
install -m 644 "$STAGE/bot_final_v49-2.py" /root/bot_final_v49-2.py
systemctl restart nvlbot
sleep 3
systemctl is-active --quiet nvlbot
trap - ERR

echo "DEPLOY=PASS — Core migration was NOT started"
echo "BACKUP=$BACKUP"
