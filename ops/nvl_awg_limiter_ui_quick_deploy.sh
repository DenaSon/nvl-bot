#!/usr/bin/env bash
# NVL AWG limiter UI ONLY: pinned, staged, syntax-checked, rollback-ready.
# Run as root on the current NVL Core. Never touches AWG/WG/DNS/users/iptables.
set -Eeuo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "DEPLOY=HOLD reason=ROOT_REQUIRED"
  exit 1
fi
REV="${NVL_AWG_UI_REV:-}"
if [[ ! "$REV" =~ ^[0-9a-f]{40}$ ]]; then
  echo "DEPLOY=HOLD reason=PINNED_SHA_REQUIRED"
  exit 1
fi
cd /root
if [[ ! -f /root/master_bot.db || ! -f /root/manual_edge_wizard.py ]]; then
  echo "DEPLOY=HOLD reason=CORE_FILE_MISSING"
  exit 1
fi
if ! systemctl is-active --quiet nvlbot; then
  echo "DEPLOY=HOLD reason=BOT_NOT_RUNNING"
  exit 1
fi
if [[ ! -x /usr/bin/python3 ]]; then
  echo "DEPLOY=HOLD reason=SYSTEM_PYTHON_MISSING"
  exit 1
fi

# Refuse to restart the bot during an in-flight install, route or account batch.
if ! /usr/bin/python3 -B - <<'PY'
import sqlite3, sys
db=sqlite3.connect("file:/root/master_bot.db?mode=ro",uri=True,timeout=5)
db.execute("PRAGMA query_only=ON")
checks={
    "manual_edge_operations":("id","status",("INSTALLING","ROUTING")),
    "cloudzy_cz07_jobs":("id","status",("QUEUED","ROUTING","MIGRATING")),
}
busy=False
for table,(id_column,status_column,states) in checks.items():
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone():
        continue
    cols={x[1] for x in db.execute("PRAGMA table_info("+table+")")}
    if not {id_column,status_column}.issubset(cols):
        print("DEPLOY=HOLD reason=UNKNOWN_SCHEMA table="+table)
        sys.exit(2)
    marks=",".join("?" for _ in states)
    query=f"SELECT {id_column}, {status_column} FROM {table} WHERE {status_column} IN ({marks}) LIMIT 3"
    for op_id, status in db.execute(query,states):
        busy=True
        print("DEPLOY=HOLD reason=TRANSFER_OR_INSTALL_BUSY table="+table+
              " status="+str(status)+" id="+str(op_id)[:20])
db.close()
sys.exit(2 if busy else 0)
PY
then
  exit 2
fi

BASE="https://raw.githubusercontent.com/DenaSon/nvl-bot/${REV}"
STAGE="$(mktemp -d /root/nvl-awg-limiter-ui-stage-XXXXXX)"
BACKUP="$(mktemp -d /root/nvl-awg-limiter-ui-backup-XXXXXX)"
FILES=(nvl_awg_limiter_recovery.py manual_edge_wizard.py)
echo "REV=$REV"
echo "BACKUP=$BACKUP"

for file in "${FILES[@]}"; do
  curl --fail --location --silent --show-error --retry 2 \
    --connect-timeout 10 --max-time 60 \
    "$BASE/$file" --output "$STAGE/$file"
  [[ -s "$STAGE/$file" ]]
done
mkdir -p "$STAGE/tests"
curl --fail --location --silent --show-error --retry 2 \
  --connect-timeout 10 --max-time 60 \
  "$BASE/tests/test_nvl_awg_limiter_recovery.py" \
  --output "$STAGE/tests/test_nvl_awg_limiter_recovery.py"

PYTHONPYCACHEPREFIX="$STAGE/pycache" /usr/bin/python3 -m py_compile \
  "$STAGE/nvl_awg_limiter_recovery.py" "$STAGE/manual_edge_wizard.py"
(cd "$STAGE" && PYTHONPATH="$STAGE:/root" /usr/bin/python3 -B \
  -m unittest discover -s tests -p test_nvl_awg_limiter_recovery.py -v)

for file in "${FILES[@]}"; do
  if [[ -f "/root/$file" ]]; then cp -a "/root/$file" "$BACKUP/$file"; fi
done

rollback() {
  local rc=$?
  trap - ERR
  set +e
  echo "DEPLOY=FAILED restoring previous files"
  for file in "${FILES[@]}"; do
    if [[ -f "$BACKUP/$file" ]]; then
      cp -a "$BACKUP/$file" "/root/$file"
    else
      rm -f "/root/$file"
    fi
  done
  systemctl restart nvlbot || true
  exit "$rc"
}
trap rollback ERR

# Install dependency before changing the wizard's import.
install -m 0644 "$STAGE/nvl_awg_limiter_recovery.py" \
  /root/nvl_awg_limiter_recovery.py
install -m 0644 "$STAGE/manual_edge_wizard.py" \
  /root/manual_edge_wizard.py
systemctl restart nvlbot
sleep 3
systemctl is-active --quiet nvlbot

# A module-level import check exercises all dependencies of the changed wizard.
(cd /root && /usr/bin/python3 -B -c \
  'import nvl_awg_limiter_recovery, manual_edge_wizard; print("IMPORT=PASS")')
trap - ERR
echo "DEPLOY=PASS"
echo "BACKUP=$BACKUP"
echo "NOTE=Existing AWG/WG/DNS/customer routes were not modified."
