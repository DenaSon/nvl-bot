#!/bin/bash
# Reuse the promoted Edge's retired WG key/IP as the old Core's relay identity.
set -euo pipefail
umask 077
STATE=/root/.nvl_demote_identity
KEY=/root/.ssh/edge_provision_ed25519
fail() { echo "ERROR: $*" >&2; exit 1; }
PREPARE=0
if [[ "$1" == "--prepare" ]]; then PREPARE=1; shift; fi
[[ $# -ge 2 && $# -le 3 ]] || fail "Usage: [--prepare] IP CUSTOMER_PORT [ADMIN_PORT]"
NEW_IP="$1"; CUSTOMER_PORT="$2"; ADMIN_PORT="${3:-$(cat "$STATE/port" 2>/dev/null || echo 22)}"
[[ "$NEW_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || fail "invalid IP"
[[ "$CUSTOMER_PORT" =~ ^[0-9]+$ ]] && (( CUSTOMER_PORT > 22 && CUSTOMER_PORT <= 65535 )) || fail "invalid customer port"
[[ "$ADMIN_PORT" =~ ^[0-9]+$ ]] && (( ADMIN_PORT > 0 && ADMIN_PORT <= 65535 )) || fail "invalid admin port"
[[ -r "$KEY" ]] || fail "SSH key missing"
SSH=(ssh -i "$KEY" -p "$ADMIN_PORT" -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "root@$NEW_IP")
if (( PREPARE )); then
  systemctl is-active --quiet nvlbot || fail "old Core bot inactive"
  systemctl is-active --quiet wg-quick@wg0 || fail "old Core WG inactive"
  "${SSH[@]}" "systemctl is-active --quiet wg-quick@wg0" || fail "target Edge WG inactive"
  mkdir -p "$STATE"
  chmod 700 "$STATE"
  "${SSH[@]}" "awk -F= '/^PrivateKey/{gsub(/[[:space:]]/,\"\",\$2);print \$2;exit}' /etc/wireguard/wg0.conf" > "$STATE/private"
  [[ -s "$STATE/private" ]] || fail "target Edge key missing"
  pub=$(wg pubkey < "$STATE/private") || fail "invalid target Edge key"
  remote_pub=$("${SSH[@]}" "wg show wg0 public-key") || fail "cannot read target WG key"
  [[ "$pub" == "$remote_pub" ]] || fail "target WG key mismatch"
  addr=$("${SSH[@]}" "ip -4 -o addr show dev wg0 | awk '{print \$4}' | cut -d/ -f1") || fail "target WG address unavailable"
  [[ "$addr" =~ ^10\.77\.0\.[0-9]{1,3}$ && "$addr" != "10.77.0.1" ]] || fail "target is not a relay Edge"
  wg show wg0 allowed-ips | awk -v p="$pub" -v a="$addr/32" '$1==p && $2==a {ok=1} END {exit !ok}' || fail "target Edge not registered as Core peer"
  wg show wg0 public-key > "$STATE/core_pub"
  printf '%s\n' "$addr" > "$STATE/addr"
  printf '%s\n' "$NEW_IP" > "$STATE/ip"
  printf '%s\n' "$ADMIN_PORT" > "$STATE/port"
  echo "PREPARE_OK: Edge identity captured before Core change"
  exit 0
fi
[[ -r "$STATE/private" && -r "$STATE/addr" && -r "$STATE/core_pub" ]] || fail "no prepared Edge identity"
[[ "$(cat "$STATE/ip")" == "$NEW_IP" && "$(cat "$STATE/port")" == "$ADMIN_PORT" ]] || fail "destination mismatch"
systemctl is-active --quiet nvlbot && fail "old Core bot is still running"
"${SSH[@]}" "systemctl is-active --quiet nvlbot" || fail "new Core bot is not active"
[[ "$("${SSH[@]}" "wg show wg0 public-key")" == "$(cat "$STATE/core_pub")" ]] || fail "new Core WireGuard identity mismatch"
pub=$(wg pubkey < "$STATE/private")
"${SSH[@]}" "wg show wg0 allowed-ips" | awk -v p="$pub" -v a="$(cat "$STATE/addr")/32" '$1==p && $2==a {ok=1} END {exit !ok}' || fail "new Core does not have the original Edge peer"
systemctl disable --now nvl-edge-sync.timer >/dev/null 2>&1 || true
systemctl disable --now nvlbot >/dev/null 2>&1 || true
systemctl stop wg-quick@wg0
cp -a /etc/wireguard/wg0.conf "/etc/wireguard/wg0.conf.old_core.$(date +%s)"
install -m 600 "$STATE/private" /etc/wireguard/edge_private.key
cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = $(cat "$STATE/addr")/24
PrivateKey = $(cat "$STATE/private")
[Peer]
PublicKey = $(cat "$STATE/core_pub")
Endpoint = $NEW_IP:51820
AllowedIPs = 10.77.0.1/32
PersistentKeepalive = 25
EOF
chmod 600 /etc/wireguard/wg0.conf
systemctl enable --now wg-quick@wg0
[[ "$(wg show wg0 public-key)" == "$pub" ]] || fail "failed to activate Edge identity"
sysctl -w net.ipv4.ip_forward=1 >/dev/null
printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/99-nvl-relay.conf
PORTS=("$CUSTOMER_PORT")
if [[ -r /root/master_bot.db ]]; then
  TLS_PORT=$(sqlite3 /root/master_bot.db "SELECT value FROM settings WHERE key='tls_port';" 2>/dev/null || true)
  if [[ "$TLS_PORT" =~ ^[0-9]+$ ]] && (( TLS_PORT > 22 && TLS_PORT <= 65535 )); then PORTS+=("$TLS_PORT"); fi
fi
for port in "${PORTS[@]}"; do
  iptables -t nat -C PREROUTING -p tcp -m addrtype --dst-type LOCAL --dport "$port" -j DNAT --to-destination "10.77.0.1:$port" 2>/dev/null ||
    iptables -t nat -I PREROUTING 1 -p tcp -m addrtype --dst-type LOCAL --dport "$port" -j DNAT --to-destination "10.77.0.1:$port"
  iptables -C FORWARD -d 10.77.0.1 -p tcp --dport "$port" -j ACCEPT 2>/dev/null ||
    iptables -I FORWARD 1 -d 10.77.0.1 -p tcp --dport "$port" -j ACCEPT
done
iptables -C FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null ||
  iptables -I FORWARD 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -C POSTROUTING -o wg0 -d 10.77.0.1 -j MASQUERADE 2>/dev/null ||
  iptables -t nat -A POSTROUTING -o wg0 -d 10.77.0.1 -j MASQUERADE
command -v netfilter-persistent >/dev/null || fail "NAT live but persistence package missing"
netfilter-persistent save >/dev/null
rm -rf "$STATE"
echo "DEMOTE_OK: old Core became a WireGuard/DNAT relay; bot disabled"
echo "ENDPOINT_SYNC: updating existing Edge endpoints from new Core"
if ! "${SSH[@]}" "bash /root/update_all_edges_endpoint.sh '$NEW_IP'"; then
  echo "PARTIAL: Core migrated and old Core demoted, but some Edge endpoints need repair" >&2
  exit 2
fi
echo "MIGRATION_COMPLETE: new Core and all reachable Edge endpoints updated"
