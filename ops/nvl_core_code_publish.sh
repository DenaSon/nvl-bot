#!/usr/bin/env bash
# NVL guarded, source-only Core publisher.
# STAGE is the default; APPLY is opt-in. NEVER changes route, account host,
# Cloudflare DNS, WireGuard, env flags, SSH accounts, or user migrations.
set -Eeuo pipefail
umask 077

PIN_SHA="$(printenv NVL_PIN_SHA || true)"
APPROVAL="$(printenv NVL_APPROVE_CODE_DEPLOY || true)"
ROOT=/root
DB=/root/master_bot.db
SERVICE=nvlbot
JOB=a0b997e06a92ca35261561f8a5aa5f87
BEFORE_BOT_SHA=e2a859372196044389c60a6b495d2a281fb7a0435d3e06260cf6076cc762261c
BEFORE_QUEUE_SHA=bf14760d84b50ca89ea96ab375641888cd84b5278605ffc288e29fd64b82ad3a

fail() { echo "STOP: $*" >&2; return 1; }
[[ "$EUID" -eq 0 ]] || fail "root required"
[[ "$PIN_SHA" =~ ^[0-9a-f]{40}$ ]] || fail "set NVL_PIN_SHA to an exact 40-char Git SHA"
for cmd in git sqlite3 python3 systemctl sha256sum cmp readlink stat cp install mktemp find realpath dirname; do
  command -v "$cmd" >/dev/null || fail "missing command: $cmd"
done
[[ -f "$DB" && ! -L "$DB" ]] || fail "live database missing or symlink"
[[ -f "$ROOT/bot_final_v49-2.py" && -f "$ROOT/cloudzy_cz07_queue.py" ]] ||
  fail "known Core bot files missing"
[[ "$(systemctl is-active "$SERVICE")" == active ]] ||
  fail "nvlbot service must be active before stage/apply"
UNIT_USER="$(systemctl show "$SERVICE" -p User --value)"
[[ -z "$UNIT_USER" || "$UNIT_USER" == root ]] ||
  fail "service runs as a non-root user: review file ownership/modes before deployment"
PID="$(systemctl show "$SERVICE" -p MainPID --value)"
[[ "$PID" =~ ^[0-9]+$ && "$PID" -gt 0 ]] || fail "no MainPID"
[[ "$(readlink -f "/proc/$PID/cwd")" == "$ROOT" ]] ||
  fail "bot working directory is not /root; inspect systemctl cat nvlbot"
[[ "$(sqlite3 -readonly "$DB" 'PRAGMA quick_check;')" == ok ]] ||
  fail "live DB quick_check is not OK"

# These are the original forensic files, not replaceable deployment data.
for historical in \
  /root/nvl-backups/emergency-pre-reconcile-20261029T090210Z-798849.db \
  /root/nvl-backups/pre-cz07-68-20261029T091736Z-808450.db \
  /root/nvl-backups/pre-cz07-68-20261029T092202Z-810588.db; do
  [[ -f "$historical" && ! -L "$historical" ]] ||
    fail "historical proof file missing or symlink: $historical"
  [[ "$(sqlite3 -readonly "$historical" 'PRAGMA quick_check;')" == ok ]] ||
    fail "historical proof file invalid: $historical"
done

# Refuse to publish over changed production code without a new operator audit.
LIVE_BOT_SHA="$(sha256sum "$ROOT/bot_final_v49-2.py" | cut -d' ' -f1)"
LIVE_QUEUE_SHA="$(sha256sum "$ROOT/cloudzy_cz07_queue.py" | cut -d' ' -f1)"
echo "LIVE_BOT_SHA=$LIVE_BOT_SHA"
echo "LIVE_CZ07_SHA=$LIVE_QUEUE_SHA"
if [[ "$APPROVAL" == APPLY ]]; then
  [[ "$LIVE_BOT_SHA" == "$BEFORE_BOT_SHA" &&
     "$LIVE_QUEUE_SHA" == "$BEFORE_QUEUE_SHA" ]] ||
    fail "Core code changed since read-only audit: DO NOT overwrite it"
fi

RELEASE="$(mktemp -d /root/nvl-core-release-XXXXXXXX)"
chmod 700 "$RELEASE"
SRC="$RELEASE/source"
echo "RELEASE_DIR=$RELEASE"
git init -q "$SRC"
git -C "$SRC" remote add origin https://github.com/DenaSon/nvl-bot.git
git -C "$SRC" fetch -q --depth=1 origin "$PIN_SHA"
git -C "$SRC" checkout --detach -q FETCH_HEAD
[[ "$(git -C "$SRC" rev-parse HEAD)" == "$PIN_SHA" ]] ||
  fail "downloaded commit does not match pin"

for required in bot_final_v49-2.py cloudzy_cz07_queue.py \
  cloudzy_cz07_legacy_proof.py manual_edge_wizard.py \
  manual_edge_secure_form.py manual_edge_journal.py manual_edge_rich.py \
  setup_edge_relay.sh; do
  [[ -f "$SRC/$required" && ! -L "$SRC/$required" ]] ||
    fail "missing or unsafe release file: $required"
done

python3 - "$SRC" <<'PY'
import pathlib, py_compile, sys
root = pathlib.Path(sys.argv[1])
count = 0
for file in root.rglob('*.py'):
    py_compile.compile(str(file), cfile=str(file.with_suffix('.preflight.pyc')), doraise=True)
    count += 1
print("STAGED_PYTHON_COMPILE=OK", count)
PY

# SQLite's online-backup API, NOT a live-file cp, is used while bot is running.
python3 - "$DB" "$RELEASE/master_bot-online-backup.db" <<'PY'
import sqlite3, sys
src = sqlite3.connect('file:'+sys.argv[1]+'?mode=ro', uri=True, timeout=30)
dst = sqlite3.connect(sys.argv[2])
try:
    with dst:
        src.backup(dst, pages=256, sleep=.05)
    if dst.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
        raise RuntimeError("BACKUP_QUICK_CHECK_FAILED")
    print("ONLINE_BACKUP=OK")
finally:
    dst.close()
    src.close()
PY

mkdir -m 700 "$RELEASE/previous"
: > "$RELEASE/manifest.txt"
: > "$RELEASE/new-files.txt"
# Complete runtime Python graph: root modules plus imported package modules.
# Existing /root/ops and /root/server_migration are versioned and backed up.
[[ -d "$SRC/ops" && -d "$SRC/server_migration" ]] ||
  fail "runtime Python package directories missing"
find "$SRC" -maxdepth 1 -type f \( -name '*.py' -o -name '*.sh' \) -print0 > "$RELEASE/source-list0"
find "$SRC/ops" "$SRC/server_migration" -type f -name '*.py' -print0 >> "$RELEASE/source-list0"
COUNT=0
CHANGED=0
NEW=0
while IFS= read -r -d '' file; do
  rel="$(realpath --relative-to="$SRC" "$file")"
  [[ -n "$rel" && "$rel" != ../* && "$rel" != /* ]] ||
    fail "source outside release"
  [[ ! -L "$ROOT/$rel" ]] || fail "symlink target: /root/$rel"
  COUNT=$((COUNT+1))
  printf '%s\n' "$rel" >> "$RELEASE/manifest.txt"
  if [[ -f "$ROOT/$rel" ]]; then
    mkdir -p "$RELEASE/previous/$(dirname "$rel")"
    cp -p "$ROOT/$rel" "$RELEASE/previous/$rel"
    if ! cmp -s "$ROOT/$rel" "$file"; then
      CHANGED=$((CHANGED+1))
    fi
  elif [[ ! -e "$ROOT/$rel" ]]; then
    NEW=$((NEW+1))
    printf '%s\n' "$rel" >> "$RELEASE/new-files.txt"
  else
    fail "non-regular target: /root/$rel"
  fi
done < "$RELEASE/source-list0"
[[ "$COUNT" -ge 200 ]] || fail "unexpectedly small source+package release"
sha256sum "$RELEASE/master_bot-online-backup.db" > "$RELEASE/backup.sha256"
echo "PINNED_COMMIT=$PIN_SHA"
echo "SOURCE_FILES=$COUNT CHANGED=$CHANGED NEW=$NEW"
echo "ONLINE_BACKUP=$RELEASE/master_bot-online-backup.db"
sqlite3 -readonly -header -column "$DB" \
  "SELECT substr(id,1,16) AS job,status,code,moved,total
   FROM cloudzy_cz07_jobs WHERE id='$JOB';"

if [[ "$APPROVAL" != APPLY ]]; then
  echo "STAGE_ONLY=YES"
  echo "SERVICE_UNTOUCHED=YES"
  echo "RECOVERY_FLAG_NOT_ENABLED=YES"
  echo "NEXT: review change counts, backups, actual process, DNS/6G locks."
  exit 0
fi

publishing=0
on_failure() {
  code=$?
  trap - ERR
  if [[ "$publishing" == 1 ]]; then
    echo "PUBLISH_FAILED: reverting files, leaving nvlbot stopped" >&2
    systemctl stop "$SERVICE" || true
    while IFS= read -r rel; do
      [[ -f "$RELEASE/previous/$rel" ]] || continue
      mkdir -p "$ROOT/$(dirname "$rel")" || true
      cp -p "$RELEASE/previous/$rel" "$ROOT/$rel" || true
    done < "$RELEASE/manifest.txt"
    while IFS= read -r rel; do
      [[ -n "$rel" ]] && rm -f -- "$ROOT/$rel"
    done < "$RELEASE/new-files.txt"
    echo "CODE_RESTORED; SERVICE_STOPPED_FOR_COMPATIBILITY_REVIEW" >&2
  fi
  echo "INSPECT_RELEASE=$RELEASE" >&2
  exit "$code"
}
trap on_failure ERR

systemctl stop "$SERVICE"
publishing=1
while IFS= read -r rel; do
  [[ -f "$SRC/$rel" && ! -L "$SRC/$rel" ]] ||
    fail "staged source changed: $rel"
  if [[ -f "$ROOT/$rel" ]]; then
    mode="$(stat -c %a "$ROOT/$rel")"
  elif [[ "$rel" == *.sh ]]; then
    mode=700
  else
    mode=600
  fi
  install -D -m "$mode" "$SRC/$rel" "$ROOT/$rel"
  cmp -s "$SRC/$rel" "$ROOT/$rel" || fail "copy mismatch: $rel"
done < "$RELEASE/manifest.txt"
systemctl start "$SERVICE"
sleep 4
[[ "$(systemctl is-active "$SERVICE")" == active ]] ||
  fail "nvlbot did not come back active"
PID="$(systemctl show "$SERVICE" -p MainPID --value)"
[[ "$PID" =~ ^[0-9]+$ && "$PID" -gt 0 ]] ||
  fail "no live process after restart"
trap - ERR
publishing=0
echo "CODE_DEPLOYED_SHA=$PIN_SHA"
echo "ROLLBACK_DIRECTORY=$RELEASE"
echo "HISTORICAL_RECOVERY_FLAG=UNCHANGED"
echo "NO_CZ07_STATE_CHANGES_REQUESTED=YES"
echo "NEXT: verify imports, bot UI, status flags and live route BEFORE recovery."
