#!/usr/bin/env bash
# NVL: promote a pre-staged fresh Core without demoting the old Core.
# Intentional: source DB final sync and Edge endpoint rewrites are out of scope.
set -Eeuo pipefail
umask 077

usage() { echo "Usage: $0 check|cutover DESTINATION_IPV4 CUSTOMER_PORT" >&2; exit 2; }
[[ $# -eq 3 ]] || usage
MODE="$1"; DEST="$2"; CUSTOMER_PORT="$3"
[[ "$MODE" == check || "$MODE" == cutover ]] || usage
python3 - "$DEST" "$CUSTOMER_PORT" <<'PY' || usage
import ipaddress, sys
try:
    host=ipaddress.IPv4Address(sys.argv[1]); port=int(sys.argv[2])
    assert host.is_global and 23 <= port <= 65535
except (ValueError, AssertionError):
    sys.exit(1)
PY
[[ $EUID -eq 0 ]] || { echo "HOLD: ROOT_REQUIRED"; exit 1; }
[[ "$MODE" != cutover || "${NVL_FRESH_CUTOVER_APPROVED:-}" == YES ]] || {
    echo "HOLD: CUTOVER_CONFIRMATION_REQUIRED"; exit 1;
}

# Share the same lock with the legacy promotion path.
exec 9>/run/nvl-core-migration.lock
flock -n 9 || { echo "HOLD: CORE_MIGRATION_ALREADY_RUNNING"; exit 1; }
OLD_IP="${NVL_OLD_CORE_IPV4:-91.107.170.239}"
ip -4 -o addr show | grep -Fq "$OLD_IP/" || {
    echo "HOLD: NOT_SOURCE_CORE"; exit 1;
}
[[ "$DEST" != "$OLD_IP" ]] || { echo "HOLD: SAME_HOST"; exit 1; }
SSH_KEY=/root/.ssh/edge_provision_ed25519
[[ -r "$SSH_KEY" ]] || { echo "HOLD: SSH_KEY_MISSING"; exit 1; }
# Host key must already be explicitly trusted; never auto-accept a destination identity.
ssh-keygen -F "$DEST" >/dev/null || { echo "HOLD: DEST_HOST_KEY_NOT_PINNED"; exit 1; }
SSH=(ssh -i "$SSH_KEY" -p 22 -o BatchMode=yes -o IdentitiesOnly=yes
     -o StrictHostKeyChecking=yes -o ConnectTimeout=10 -o ConnectionAttempts=1
     "root@$DEST")
"${SSH[@]}" true || { echo "HOLD: DEST_SSH_KEY_ACCESS_FAILED"; exit 1; }

for service in nvlbot wg-quick@wg0 awg-quick@awg0; do
    systemctl is-active --quiet "$service" || { echo "HOLD: SOURCE_SERVICE_INACTIVE=$service"; exit 1; }
done
[[ -r /root/bot_final_v49-2.py ]] || { echo "HOLD: SOURCE_BOT_MISSING"; exit 1; }
# The destination tunnels were started during previous manual migration attempts.
# Check mode makes them passive while the original Core is still live.
"${SSH[@]}" bash -s <<'REMOTE_PASSIVE'
set -Eeuo pipefail
if systemctl is-active --quiet nvlbot; then
    echo 'HOLD: DEST_BOT_ALREADY_ACTIVE'; exit 1
fi
systemctl stop wg-quick@wg0 awg-quick@awg0
! systemctl is-active --quiet wg-quick@wg0
! systemctl is-active --quiet awg-quick@awg0
echo 'DEST_DUPLICATE_CORE_TUNNELS=STOPPED'
REMOTE_PASSIVE
# Code-only staging is permitted. The operator explicitly skipped database final sync.
# Destination bot remains stopped; update only the Python entrypoint before SHA checks.
command -v rsync >/dev/null || { echo "HOLD: RSYNC_MISSING"; exit 1; }
rsync -az -e "ssh -i $SSH_KEY -p 22 -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes" \
    /root/bot_final_v49-2.py "root@$DEST:/root/bot_final_v49-2.py"
echo 'BOT_CODE_ONLY_STAGE=PASS'
SRC_BOT_SHA=$(sha256sum /root/bot_final_v49-2.py | awk '{print $1}')
DST_BOT_SHA=$("${SSH[@]}" sha256sum /root/bot_final_v49-2.py | awk '{print $1}')
[[ "$SRC_BOT_SHA" == "$DST_BOT_SHA" ]] || {
    echo "HOLD: BOT_CODE_MISMATCH"; exit 1;
}
SRC_WG=$(wg show wg0 public-key)
SRC_AWG=$(awg show awg0 public-key)
DST_IDENTITIES=$("${SSH[@]}" bash -s <<'REMOTE_KEYS'
set -Eeuo pipefail
pub_from_config() {
    local config="$1" tool="$2" secret
    secret=$(awk '/^[[:space:]]*PrivateKey[[:space:]]*=/{sub(/^[^=]*=/, ""); gsub(/[[:space:]]/, ""); print; exit}' "$config")
    [[ -n "$secret" ]] || { echo 'HOLD: CONFIG_PRIVATE_KEY_MISSING' >&2; return 1; }
    printf '%s\n' "$secret" | "$tool" pubkey
}
pub_from_config /etc/wireguard/wg0.conf wg
pub_from_config /etc/amnezia/amneziawg/awg0.conf awg
REMOTE_KEYS
)
DST_WG=${DST_IDENTITIES%%$'\n'*}
DST_AWG=${DST_IDENTITIES##*$'\n'}
[[ -n "$SRC_WG" && "$SRC_WG" == "$DST_WG" ]] || {
    echo "HOLD: WG_IDENTITY_MISMATCH"; exit 1;
}
[[ -n "$SRC_AWG" && "$SRC_AWG" == "$DST_AWG" ]] || {
    echo "HOLD: AWG_IDENTITY_MISMATCH"; exit 1;
}

"${SSH[@]}" bash -s -- "$DEST" "$CUSTOMER_PORT" <<'REMOTE_CHECK'
set -Eeuo pipefail
DEST="$1"; CUSTOMER_PORT="$2"
ip -4 -o addr show | grep -Fq "$DEST/"
[[ $(sqlite3 /root/master_bot.db 'PRAGMA quick_check;') == ok ]]
[[ -x /root/venv/bin/python3 && -s /root/bot_final_v49-2.py ]]
[[ -s /root/02_recreate_ssh_users.py && -s /root/requirements.txt ]]
[[ -s /root/bot_import_preflight.py ]]
[[ -d /etc/nvlbot ]]
systemctl is-active --quiet nvlbot && { echo 'HOLD: DEST_BOT_ALREADY_ACTIVE'; exit 1; }
for unit in wg-quick@wg0 awg-quick@awg0; do
    if systemctl is-active --quiet "$unit"; then
        echo "HOLD: DUPLICATE_DEST_TUNNEL_ACTIVE=$unit"
        exit 1
    fi
done
for unit in nvl-customer-sshd gost; do
    systemctl is-active --quiet "$unit" || { echo "HOLD: DEST_SERVICE_INACTIVE=$unit"; exit 1; }
done
ss -lntH | awk -v p="$CUSTOMER_PORT" '$4 ~ (":" p "$") {yes=1} END {exit !yes}'
/root/venv/bin/python3 -m py_compile /root/bot_final_v49-2.py /root/02_recreate_ssh_users.py
cd /root
PYTHONPATH= /root/venv/bin/python3 /root/bot_import_preflight.py /root/bot_final_v49-2.py >/dev/null
python3 /root/02_recreate_ssh_users.py --dry-run >/dev/null
echo 'DEST_PRECHECK=PASS'
REMOTE_CHECK

echo 'FRESH_CORE_PRECHECK=PASS'
echo 'SNAPSHOT_DB_REUSED=YES'
echo 'FINAL_SYNC=SKIPPED_BY_OPERATOR'
echo 'EDGE_ENDPOINTS=NOT_CHANGED'
[[ "$MODE" == check ]] && exit 0

echo '=== CONTROLLED BOT CUTOVER ==='
FROZEN=0
COMMITTED=0
rollback() {
    rc=$?
    trap - EXIT
    if [[ "$COMMITTED" == 1 || "$FROZEN" != 1 ]]; then exit "$rc"; fi
    echo 'CUTOVER=FAILED; attempting guarded rollback'
    # Never revive source poller unless destination poller is provably inactive.
    if "${SSH[@]}" bash -s <<'REMOTE_ROLLBACK'
set -Eeuo pipefail
systemctl stop nvlbot
systemctl stop wg-quick@wg0 awg-quick@awg0
systemctl stop nvl-customer-sshd || true
! systemctl is-active --quiet nvlbot
! systemctl is-active --quiet wg-quick@wg0
! systemctl is-active --quiet awg-quick@awg0
REMOTE_ROLLBACK
    then
        systemctl start wg-quick@wg0 awg-quick@awg0
        systemctl start nvlbot
        echo 'ROLLBACK=PASS; OLD_CORE_RESTORED'
    else
        echo 'ROLLBACK=HOLD; DESTINATION_NOT_VERIFIABLY_STOPPED'
        echo 'OLD_CORE_BOT_LEFT_INACTIVE_TO_PREVENT_SPLIT_BRAIN'
    fi
    exit "$rc"
}
trap rollback EXIT

if ! systemctl stop nvlbot; then
    echo 'HOLD: SOURCE_BOT_STOP_FAILED'
    if ! systemctl is-active --quiet nvlbot; then systemctl start nvlbot || true; fi
    exit 1
fi
if systemctl is-active --quiet nvlbot; then
    echo 'HOLD: SOURCE_BOT_STILL_ACTIVE'
    exit 1
fi
FROZEN=1
systemctl stop wg-quick@wg0 awg-quick@awg0
! systemctl is-active --quiet wg-quick@wg0
! systemctl is-active --quiet awg-quick@awg0

"${SSH[@]}" bash -s -- "$DEST" "$OLD_IP" <<'REMOTE_ACTIVATE'
set -Eeuo pipefail
DEST="$1"; OLD="$2"
# Reuse target snapshot, never copy the source's live database.
BACKUP="/root/nvl-pre-fresh-cutover-$(date -u +%Y%m%dT%H%M%SZ).db"
sqlite3 /root/master_bot.db ".backup '$BACKUP'"
chmod 600 "$BACKUP"
python3 - "$DEST" "$OLD" <<'PY'
import sqlite3,sys
new,old=sys.argv[1:]
with sqlite3.connect('/root/master_bot.db') as db:
    result=db.execute("SELECT value FROM settings WHERE key='core_wg_public_ip'").fetchone()
    if result is None or result[0] not in (old,new):
        raise SystemExit('HOLD: UNEXPECTED_CORE_IP_IN_DB')
    db.execute("UPDATE settings SET value=? WHERE key='core_wg_public_ip'",(new,))
PY
# Unlock/recreate only active accounts using snapshot data and NVL's existing tool.
systemctl stop nvl-customer-sshd || true
python3 /root/02_recreate_ssh_users.py > /root/nvl-fresh-user-restore.log 2>&1 || {
    echo 'HOLD: USER_RESTORE_FAILED; see root-only /root/nvl-fresh-user-restore.log'
    exit 1
}
systemctl start wg-quick@wg0 awg-quick@awg0
systemctl start nvl-customer-sshd
systemctl start ssh-limiter
systemctl start nvlbot
sleep 5
systemctl is-active --quiet nvlbot
systemctl is-active --quiet wg-quick@wg0
systemctl is-active --quiet awg-quick@awg0
systemctl is-active --quiet nvl-customer-sshd
[[ $(sqlite3 /root/master_bot.db 'PRAGMA quick_check;') == ok ]]
echo 'NEW_CORE_BOT=ACTIVE'
REMOTE_ACTIVATE

# Keep the old VPS powered on with its admin SSH, but retire the duplicate bot/tunnels.
"${SSH[@]}" systemctl enable nvlbot wg-quick@wg0 awg-quick@awg0 nvl-customer-sshd >/dev/null
COMMITTED=1
systemctl disable nvlbot wg-quick@wg0 awg-quick@awg0 >/dev/null || \
    echo 'WARNING: OLD_CORE_BOOT_UNITS_MAY_NEED_MANUAL_DISABLE'
echo 'FRESH_CORE_BOT_MIGRATION=PASS'
echo 'OLD_CORE=ONLINE_STANDBY; BOT_WG_AWG_STOPPED'
echo 'NEW_CORE_BOT=ACTIVE'
echo 'EDGE_ENDPOINTS=NOT_MIGRATED; SEPARATE_NETWORK_CUTOVER_REQUIRED'
echo 'DNS=UNCHANGED'
