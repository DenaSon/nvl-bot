#!/usr/bin/env bash
# Actual kernel networking test: disposable GitHub-hosted Ubuntu runner ONLY.
# This file MUST NEVER be run on NVL Core/Edge or any shared Linux host.
set -Eeuo pipefail
umask 077
if [[ "${GITHUB_ACTIONS:-}" != "true" || "${NVL_CI_KERNEL_LAB:-}" != "1" || "$EUID" != "0" ]]; then
  echo "REFUSED: GitHub Actions ephemeral root lab only" >&2
  exit 69
fi
for tool in ip wg iptables sysctl curl python3 ping nsenter; do
  command -v "$tool" >/dev/null || { echo "Missing: $tool" >&2; exit 69; }
done
BASE="$(pwd)"
TMP="$(mktemp -d /tmp/nvl-ci-egress-XXXXXX)"
CORE="nvlci-core-$$"
EDGE="nvlci-edge-$$"
WAN="nvlci-wan-$$"
INNER="nvl-egress-fra1"
CEND="nvc$$"
EEND="nve$$"
UEND="nvu$$"
WEND="nvw$"
C2WAN="nvy$"
WAN2C="nvz$"
SERVER_PID=""
DOH_PID=""
DNS_PID=""
V6_PID=""
CS=0
ES=0

cleanup() {
  code=$?
  trap - EXIT
  set +e
  for pid in "${DNS_PID:-}" "${DOH_PID:-}" "${V6_PID:-}" "${SERVER_PID:-}"; do
    if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  done
  if [[ "$CS" == "1" ]]; then nsenter --net="/run/netns/$CORE" -- bash "$TMP/core/down.sh" >/dev/null 2>&1 || true; fi
  if [[ "$ES" == "1" ]]; then nsenter --net="/run/netns/$EDGE" -- bash "$TMP/edge/down.sh" >/dev/null 2>&1 || true; fi
  ip netns del "$INNER" >/dev/null 2>&1 || true
  ip netns del "$CORE" >/dev/null 2>&1 || true
  ip netns del "$EDGE" >/dev/null 2>&1 || true
  ip netns del "$WAN" >/dev/null 2>&1 || true
  ip link del "$CEND" >/dev/null 2>&1 || true
  ip link del "$UEND" >/dev/null 2>&1 || true
  ip link del "$C2WAN" >/dev/null 2>&1 || true
  rm -rf -- "$TMP"
  exit "$code"
}
trap cleanup EXIT

if ip netns list | grep -Eq "^$INNER( |$)"; then
  echo "Inner namespace already exists: abort" >&2
  exit 1
fi
echo "[lab] Create three disposable netns: Core, Edge, fake Internet"
ip netns add "$CORE"
ip netns add "$EDGE"
ip netns add "$WAN"

ip link add "$CEND" type veth peer name "$EEND"
ip link set "$CEND" netns "$CORE"
ip link set "$EEND" netns "$EDGE"
ip -n "$CORE" link set "$CEND" name c0
ip -n "$EDGE" link set "$EEND" name e0

ip link add "$UEND" type veth peer name "$WEND"
ip link set "$UEND" netns "$EDGE"
ip link set "$WEND" netns "$WAN"
ip -n "$EDGE" link set "$UEND" name eth0
ip -n "$WAN" link set "$WEND" name w0

# A separate simulated Core-public path means a missing UID guard is a
# measurable LEAK, not a false pass caused by lack of a default gateway.
ip link add "$C2WAN" type veth peer name "$WAN2C"
ip link set "$C2WAN" netns "$CORE"
ip link set "$WAN2C" netns "$WAN"
ip -n "$CORE" link set "$C2WAN" name cw0
ip -n "$WAN" link set "$WAN2C" name wc0

for ns in "$CORE" "$EDGE" "$WAN"; do
  ip -n "$ns" link set lo up
  ip netns exec "$ns" sysctl -q -w net.ipv4.conf.all.rp_filter=0 >/dev/null
  ip netns exec "$ns" sysctl -q -w net.ipv4.conf.default.rp_filter=0 >/dev/null
done

ip -n "$CORE" addr add 10.200.0.1/30 dev c0
ip -n "$CORE" addr add 209.200.246.198/32 dev c0
ip -n "$CORE" link set c0 up
ip -n "$CORE" addr add 10.201.0.1/30 dev cw0
ip -n "$CORE" link set cw0 up
ip -n "$CORE" route add default via 10.201.0.2 dev cw0 src 209.200.246.198
# The direct Core->WAN IPv6 path is an explicit bypass temptation.
ip -n "$CORE" -6 addr add 2001:db8:abcd::1/64 dev cw0

ip -n "$EDGE" addr add 10.200.0.2/30 dev e0
ip -n "$EDGE" addr add 172.86.94.174/32 dev eth0
ip -n "$EDGE" link set e0 up
ip -n "$EDGE" link set eth0 up
ip netns exec "$EDGE" sysctl -q -w net.ipv4.ip_forward=1 >/dev/null
ip -n "$CORE" route add 172.86.94.174/32 via 10.200.0.2 dev c0 src 209.200.246.198
ip -n "$EDGE" route add 209.200.246.198/32 via 10.200.0.1 dev e0
ip -n "$EDGE" route add default dev eth0 src 172.86.94.174

ip -n "$WAN" addr add 203.0.113.50/32 dev w0
ip -n "$WAN" addr add 203.0.113.51/32 dev w0
ip -n "$WAN" addr add 1.1.1.1/32 dev w0
ip -n "$WAN" addr add 10.201.0.2/30 dev wc0
ip -n "$WAN" -6 addr add 2001:db8:abcd::2/64 dev wc0
ip -n "$WAN" link set wc0 up
ip -n "$WAN" route add 209.200.246.198/32 via 10.201.0.1 dev wc0
ip -n "$WAN" link set w0 up
ip -n "$WAN" route add 172.86.94.174/32 dev w0

wg genkey > "$TMP/core.key"
wg genkey > "$TMP/edge.key"
wg pubkey < "$TMP/core.key" > "$TMP/core.pub"
wg pubkey < "$TMP/edge.key" > "$TMP/edge.pub"
chmod 600 "$TMP/core.key" "$TMP/edge.key"
cp "$BASE/ops/examples/edge_egress_fra1.json" "$TMP/spec.json"

python3 "$BASE/ops/edge_egress_provision.py" stage --role edge \
  --spec "$TMP/spec.json" --stage-dir "$TMP/edge" \
  --private-key-file "$TMP/edge.key" --peer-public-key "$(cat "$TMP/core.pub")"
python3 "$BASE/ops/edge_egress_provision.py" stage --role core \
  --spec "$TMP/spec.json" --stage-dir "$TMP/core" \
  --private-key-file "$TMP/core.key" --peer-public-key "$(cat "$TMP/edge.pub")"

echo "[lab] Activate dedicated Edge and Core tunnel only in netns"
nsenter --net="/run/netns/$EDGE" -- bash "$TMP/edge/up.sh"
ES=1
nsenter --net="/run/netns/$CORE" -- bash "$TMP/core/up.sh"
CS=1

ip netns exec "$INNER" ping -c 3 -W 2 10.78.100.1 >/dev/null
HS="$(ip netns exec "$INNER" wg show wg-nvl-fra1 latest-handshakes | awk '{print $2}')"
[[ "$HS" =~ ^[1-9][0-9]*$ ]] || { echo "Missing WG handshake" >&2; exit 1; }

echo "[lab] Forward source veth via WG, Edge NAT to fake WAN"
ip -n "$CORE" route add 203.0.113.50/32 via 10.78.101.2 dev vnh-fra1 src 10.78.101.1
cat > "$TMP/echo.py" <<'PY'
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 18080))
s.listen(5)
while True:
    conn, peer = s.accept()
    with conn:
        conn.settimeout(5)
        conn.recv(4096)
        body = ("observed_ipv4=" + peer[0] + "\n").encode()
        conn.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: " +
                     str(len(body)).encode() + b"\r\n\r\n" + body)
PY
ip netns exec "$WAN" python3 "$TMP/echo.py" >/dev/null 2>&1 &
SERVER_PID=$!
sleep 0.5
REPLY="$(nsenter --net="/run/netns/$CORE" -- curl --noproxy '*' --fail --silent --show-error \
  --max-time 8 --retry 3 --retry-delay 1 http://203.0.113.50:18080/)"
[[ "$REPLY" == "observed_ipv4=172.86.94.174" ]] || {
  echo "Wrong external source: $REPLY" >&2; exit 1;
}
echo "$REPLY"

echo "[lab] Inject Edge outage; Core may NOT reach the fake Internet"
nsenter --net="/run/netns/$EDGE" -- bash "$TMP/edge/down.sh"
ES=0
if nsenter --net="/run/netns/$CORE" -- curl --noproxy '*' --fail --silent     --connect-timeout 2 --max-time 2 http://203.0.113.50:18080/ >/dev/null 2>&1; then
  echo "FAIL: unexpected egress while Edge is down" >&2; exit 1
fi

echo "[lab] Restart Edge and force immediate rekey of stale Core session"
nsenter --net="/run/netns/$EDGE" -- bash "$TMP/edge/up.sh"
ES=1
echo "[lab] Core handshake before rekey (may be stale)"
ip netns exec "$INNER" wg show wg-nvl-fra1 latest-handshakes
echo "[lab] New Edge handshake before rekey"
nsenter --net="/run/netns/$EDGE" -- wg show wg-nvl-fra1 latest-handshakes
# Edge's new instance cannot decrypt packets from Core's previous transport
# session. The existing session may otherwise blackhole traffic until rekey.
# This targeted peer reconfiguration affects only the disposable CI tunnel.
ip netns exec "$INNER" wg set wg-nvl-fra1 peer "$(cat "$TMP/edge.pub")" remove
ip netns exec "$INNER" wg setconf wg-nvl-fra1 "$TMP/core/wg.conf"
ip netns exec "$INNER" ping -c 4 -W 2 10.78.100.1 >/dev/null
REPLY=""
for attempt in 1 2 3 4 5; do
  if REPLY="$(nsenter --net="/run/netns/$CORE" -- curl --noproxy '*' --fail --silent       --connect-timeout 2 --max-time 4 http://203.0.113.50:18080/)"; then
    break
  fi
  sleep 1
done
[[ "$REPLY" == "observed_ipv4=172.86.94.174" ]] || {
  echo "FAIL: Edge did not recover correct source IP: $REPLY" >&2; exit 1
}

echo "[lab] Restart Core tunnel and prove namespace/veth recovery"
nsenter --net="/run/netns/$CORE" -- bash "$TMP/core/down.sh"
CS=0
nsenter --net="/run/netns/$CORE" -- bash "$TMP/core/up.sh"
CS=1
ip -n "$CORE" route add 203.0.113.50/32 via 10.78.101.2 dev vnh-fra1 src 10.78.101.1
ip netns exec "$INNER" ping -c 3 -W 2 10.78.100.1 >/dev/null
REPLY="$(nsenter --net="/run/netns/$CORE" -- curl --noproxy '*' --fail --silent   --connect-timeout 3 --max-time 8 http://203.0.113.50:18080/)"
[[ "$REPLY" == "observed_ipv4=172.86.94.174" ]] || {
  echo "FAIL: Core restart changed external IP: $REPLY" >&2; exit 1
}

echo "[lab] Clean down and verify no resources leak"
nsenter --net="/run/netns/$CORE" -- bash "$TMP/core/down.sh"; CS=0
nsenter --net="/run/netns/$EDGE" -- bash "$TMP/edge/down.sh"; ES=0
if ip netns list | grep -Eq "^$INNER( |$)"; then echo "Namespace leaked" >&2; exit 1; fi
if ip -n "$EDGE" link show wg-nvl-fra1 >/dev/null 2>&1; then echo "Edge link leaked" >&2; exit 1; fi
echo "KERNEL_LAB_PASS: real WG + NAT + Edge outage/recovery + Core restart + cleanup"
