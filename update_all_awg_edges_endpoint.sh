#!/usr/bin/env bash
# Move only the AWG Core endpoint on existing AWG Edges after Core promotion.
# AWG peers are inventoried from the migrated Core config, not host_pool alone.
set -uo pipefail

if [[ "$(id -u)" -ne 0 || $# -ne 3 ]]; then
  echo "Usage: bash $0 OLD_CORE_IP NEW_CORE_IP NEW_CORE_AWG_PORT" >&2
  exit 1
fi
OLD_CORE_IP="$1"
NEW_CORE_IP="$2"
NEW_PORT="$3"
CONF="/etc/amnezia/amneziawg/awg0.conf"
DB="/root/master_bot.db"
KEY="/root/.ssh/edge_provision_ed25519"

for addr in "$OLD_CORE_IP" "$NEW_CORE_IP"; do
  if ! python3 -c 'import ipaddress,sys; ipaddress.IPv4Address(sys.argv[1])' "$addr"; then
    echo "AWG_SYNC=INVALID_IP"
    exit 1
  fi
done
[[ "$NEW_PORT" =~ ^[0-9]+$ ]] && ((NEW_PORT >= 1 && NEW_PORT <= 65535)) || exit 1
[[ -s "$CONF" && -r "$KEY" ]] || {
  echo "AWG_SYNC=SKIPPED (no migrated Core AWG configuration or SSH key)"
  exit 0
}

# An AWG peer may be absent from host_pool; preserve those Edge endpoints.
mapfile -t EDGES < <(
  awk -F= '/^[[:space:]]*Endpoint[[:space:]]*=/ {
    gsub(/[[:space:]]/, "", $2)
    split($2, pair, ":")
    print pair[1]
  }' "$CONF" | sort -u
)
if [[ ${#EDGES[@]} -eq 0 ]]; then
  echo "AWG_SYNC=NO_ENDPOINTS"
  exit 0
fi

OK=0
FAIL=0
SKIP=0
for EDGE in "${EDGES[@]}"; do
  if ! python3 -c 'import ipaddress,sys; ipaddress.IPv4Address(sys.argv[1])' "$EDGE" >/dev/null 2>&1; then
    continue
  fi
  if [[ "$EDGE" == "$NEW_CORE_IP" || "$EDGE" == "$OLD_CORE_IP" ]]; then
    SKIP=$((SKIP+1))
    continue
  fi

  PORT=22
  if [[ -r "$DB" ]] && sqlite3 -readonly "$DB" "SELECT 1 FROM pragma_table_info('host_pool') WHERE name='admin_ssh_port';" 2>/dev/null | grep -qx 1; then
    SAFE_EDGE="${EDGE//\'/\'\'}"
    CANDIDATE=$(sqlite3 -readonly "$DB" "SELECT admin_ssh_port FROM host_pool WHERE host='${SAFE_EDGE}' LIMIT 1;" 2>/dev/null || true)
    if [[ "$CANDIDATE" =~ ^[0-9]+$ ]] && ((CANDIDATE >= 1 && CANDIDATE <= 65535)); then
      PORT="$CANDIDATE"
    fi
  fi

  echo "AWG_EDGE=$EDGE management_port=$PORT"
  if ssh -i "$KEY" -p "$PORT" -o BatchMode=yes -o ConnectTimeout=7 \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o LogLevel=ERROR "root@$EDGE" bash -s -- "$OLD_CORE_IP" "$NEW_CORE_IP" "$NEW_PORT" <<'REMOTE'
set -euo pipefail
OLD="$1"
NEW="$2"
PORT="$3"
CONF="/etc/amnezia/amneziawg/awg0.conf"
[[ -s "$CONF" ]] || { echo "EDGE_AWG_CONFIG_MISSING"; exit 1; }
mapfile -t PEERS < <(awg show awg0 peers)
[[ ${#PEERS[@]} -eq 1 ]] || { echo "EDGE_AWG_EXPECTED_ONE_CORE_PEER"; exit 1; }
KEY="${PEERS[0]}"
CURRENT=$(awk -F= '/^[[:space:]]*Endpoint[[:space:]]*=/ {
  gsub(/[[:space:]]/, "", $2); print $2
}' "$CONF")
[[ "$(printf '%s\n' "$CURRENT" | wc -l)" -eq 1 ]] || exit 1
if [[ "$CURRENT" != "$OLD:$PORT" && "$CURRENT" != "$NEW:$PORT" ]]; then
  echo "EDGE_AWG_CONFIG_ENDPOINT_UNEXPECTED"
  exit 1
fi
BACKUP="$CONF.before-core-migration.$(date +%s)"
cp -p "$CONF" "$BACKUP"
sed -i -E "s#^[[:space:]]*Endpoint[[:space:]]*=.*#Endpoint = $NEW:$PORT#" "$CONF"
if ! awg set awg0 peer "$KEY" endpoint "$NEW:$PORT"; then
  cp -p "$BACKUP" "$CONF"
  awg set awg0 peer "$KEY" endpoint "$CURRENT" || true
  echo "EDGE_AWG_LIVE_UPDATE_FAILED"
  exit 1
fi
ACTUAL=$(awg show awg0 endpoints | awk -v k="$KEY" '$1==k {print $2}')
if [[ "$ACTUAL" != "$NEW:$PORT" ]]; then
  cp -p "$BACKUP" "$CONF"
  awg set awg0 peer "$KEY" endpoint "$CURRENT" || true
  echo "EDGE_AWG_VERIFY_FAILED"
  exit 1
fi
echo "EDGE_AWG_ENDPOINT_UPDATED=$NEW:$PORT"
REMOTE
  then
    OK=$((OK+1))
  else
    FAIL=$((FAIL+1))
    echo "AWG_EDGE_UPDATE_FAILED=$EDGE"
  fi
done

echo "AWG_ENDPOINT_SYNC: ok=$OK failed=$FAIL skipped=$SKIP discovered=${#EDGES[@]}"
[[ "$FAIL" -eq 0 ]]
