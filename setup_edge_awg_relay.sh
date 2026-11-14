#!/usr/bin/env bash
# NVL-AWG-02: ONE-TIME installer for a *fresh* Ubuntu 24.04 Edge only.
# A pinned Core provisioner must stage a root:root 0600 AWG configuration at
# /root/nvl-awg-stage/awg0.conf. NEVER run on a live/registered Edge or Core.
# No secrets on command line; no automatic retry after partial execution.
set -Eeuo pipefail
umask 077
export DEBIAN_FRONTEND=noninteractive

STAGE=/root/nvl-awg-stage/awg0.conf
CONF=/etc/amnezia/amneziawg/awg0.conf

fail() { echo "AWG_NEW_EDGE_HOLD: $1" >&2; exit 2; }
test "$(id -u)" = 0 || fail ROOT_REQUIRED
test "$#" = 6 || fail EXPECT_SIX_PUBLIC_ARGS
CORE_PUBLIC_IP="$1"
CORE_TUNNEL_IP="$2"
EDGE_TUNNEL_IP="$3"
CUSTOMER_PORT="$4"
TLS_PORT="$5"
ADMIN_PORT="$6"

# Everything here is preflight only. A partial setup is never auto-replayed.
test -f "$STAGE" && test ! -L "$STAGE" || fail STAGED_CONFIG_MISSING
test "$(stat -c %u:%a "$STAGE")" = "0:600" || fail STAGED_CONFIG_NOT_PRIVATE
test ! -e "$CONF" && test ! -L "$CONF" || fail EXISTING_AWG_CONFIG
ip link show awg0 >/dev/null 2>&1 && fail EXISTING_AWG_LINK
ip link show wg0 >/dev/null 2>&1 && fail EXISTING_WG_LINK
test "$CUSTOMER_PORT" != "$TLS_PORT" || fail SERVICE_PORT_COLLISION
test "$CUSTOMER_PORT" != "$ADMIN_PORT" || fail ADMIN_PORT_COLLISION
test "$TLS_PORT" != "$ADMIN_PORT" || fail ADMIN_PORT_COLLISION
grep -q '^ID=ubuntu$' /etc/os-release || fail UBUNTU_REQUIRED
grep -q '^VERSION_ID="24.04"$' /etc/os-release || fail UBUNTU_2404_REQUIRED

python3 - "$STAGE" "$CORE_PUBLIC_IP" "$CORE_TUNNEL_IP" "$EDGE_TUNNEL_IP" "$CUSTOMER_PORT" "$TLS_PORT" "$ADMIN_PORT" <<'PY'
import base64
import configparser
import ipaddress
import pathlib
import sys

path, public, core, edge, customer, tls, admin = sys.argv[1:]
ip = ipaddress.IPv4Address
assert ip(public).is_global and ip(core) != ip(edge), "INVALID_IP"
assert all(1 <= int(p) <= 65535 for p in (customer, tls, admin)), "INVALID_PORT"
cfg = configparser.ConfigParser(interpolation=None, strict=True)
cfg.optionxform = str
with pathlib.Path(path).open() as fh:
    cfg.read_file(fh)
assert cfg.sections() == ['Interface', 'Peer'], "INVALID_CONFIG_SECTIONS"
iface, peer = cfg['Interface'], cfg['Peer']
assert iface['Address'] == edge + '/32'
assert peer['AllowedIPs'] == core + '/32'
assert peer['Endpoint'].startswith(public + ':'), "INVALID_CORE_ENDPOINT"
assert iface['MTU'] == '1320', "MTU_NOT_PILOT_PROFILE"
assert 1 <= int(iface['ListenPort']) <= 65535
for k in ('PrivateKey', 'HeaderProtectionKey', 'PublicKey'):
    value = peer[k] if k == 'PublicKey' else iface[k]
    assert len(base64.b64decode(value, validate=True)) == 32, "INVALID_KEY"
for n in range(1, 5):
    assert int(iface['S' + str(n)]) >= 12
    assert iface['H' + str(n)] == str(n)
assert peer['PersistentKeepalive'] == '25'
assert not any(k.startswith('Post') or k.startswith('Pre') for k in iface)
print("AWG_CONFIG_PROFILE=VERIFIED")  # NEVER emit config or secrets
PY

WAN="$(ip -4 route get "$CORE_PUBLIC_IP" | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1);exit}}')"
test -n "$WAN" && test "$WAN" != awg0 || fail WAN_UNVERIFIED
# No system daemon or preexisting forward/NAT rule may own our data-plane ports.
for p in "$CUSTOMER_PORT" "$TLS_PORT"; do
  if ss -lntH 2>/dev/null | awk '{print $4}' | grep -Eq ":$p$"; then
    fail CUSTOMER_PORT_ALREADY_LISTENING
  fi
done

echo "AWG_EDGE_INSTALL=BEGIN_FRESH_ONLY"
apt-get -o DPkg::Lock::Timeout=30 update -qq
apt-get -o DPkg::Lock::Timeout=30 install -y software-properties-common \
  python3-launchpadlib gnupg2 "linux-headers-$(uname -r)" iptables iptables-persistent >/dev/null
# Official Amnezia PPA; no third-party one-line scripts and no kernel upgrade.
add-apt-repository -y ppa:amnezia/ppa >/dev/null
apt-get -o DPkg::Lock::Timeout=30 update -qq
apt-get -o DPkg::Lock::Timeout=30 install -y amneziawg >/dev/null
modprobe amneziawg
command -v awg >/dev/null && command -v awg-quick >/dev/null || fail AWG_TOOLS_MISSING
modinfo -F version amneziawg | grep -q '^3[.]1[.]' || fail AWG_31_MODULE_REQUIRED
awg --version | grep -q '3[.]1[.]' || fail AWG_31_TOOLS_REQUIRED

# Save staged config without displaying private key / HeaderProtectionKey.
install -d -m 700 /etc/amnezia/amneziawg
install -o root -g root -m 600 "$STAGE" "$CONF"
systemctl enable --now awg-quick@awg0.service
ip -4 addr show awg0 | grep -Fq "$EDGE_TUNNEL_IP/32" || fail AWG_INTERFACE_NOT_READY

install -d -m 755 /etc/sysctl.d
printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/90-nvl-awg.conf
sysctl -p /etc/sysctl.d/90-nvl-awg.conf >/dev/null

ensure() {
  local table="$1" chain="$2"
  shift 2
  if ! iptables -w -t "$table" -C "$chain" "$@" 2>/dev/null; then
    iptables -w -t "$table" -I "$chain" 1 "$@"
  fi
}

for p in "$CUSTOMER_PORT" "$TLS_PORT"; do
  ensure nat PREROUTING -i "$WAN" -p tcp --dport "$p" \
    -j DNAT --to-destination "$CORE_TUNNEL_IP:$p"
  ensure nat POSTROUTING -o awg0 -d "$CORE_TUNNEL_IP" -p tcp --dport "$p" \
    -j SNAT --to-source "$EDGE_TUNNEL_IP"
  ensure filter FORWARD -i "$WAN" -o awg0 -p tcp -d "$CORE_TUNNEL_IP" \
    --dport "$p" -j ACCEPT
  ensure filter FORWARD -i awg0 -o "$WAN" -p tcp -s "$CORE_TUNNEL_IP" \
    --sport "$p" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
done
netfilter-persistent save >/dev/null
systemctl enable netfilter-persistent >/dev/null
rm -f -- "$STAGE"
echo "AWG_EDGE_STAGE=INSTALLED"
echo "AWG_EDGE_BOOT=ENABLED"
echo "AWG_EDGE_CORE_PEER=REQUIRES_SEPARATE_CORE_ADMISSION"
