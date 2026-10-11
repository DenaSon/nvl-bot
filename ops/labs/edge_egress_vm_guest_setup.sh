#!/usr/bin/env bash
# C3E — run INSIDE a disposable VM only, not on NVL Core/Edge.
set -Eeuo pipefail
[[ "$(printenv NVL_DISPOSABLE_VM || true)" == "1" && "$EUID" == "0" ]] || exit 69
[[ -f /tmp/nvl-ci-src/edge_egress_uid_systemd.py ]] || exit 69
id -u labadmin >/dev/null
id nvlciuser >/dev/null 2>&1 || \
  useradd --uid 1659 --no-create-home --shell /usr/sbin/nologin nvlciuser
[[ "$(id -u nvlciuser)" == "1659" ]] || exit 69

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -qq -y \
  openssh-server iproute2 iptables curl python3

mkdir -p /opt/nvl-egress/ops /etc/nvl-egress/protected \
  /etc/systemd/system/ssh.service.d
cp /tmp/nvl-ci-src/edge_egress_uid_{boot,dns,policy,systemd}.py /opt/nvl-egress/
cp /tmp/nvl-ci-src/edge_egress_provision.py /opt/nvl-egress/ops/
touch /opt/nvl-egress/ops/__init__.py
chmod -R a+rX /opt/nvl-egress
# Only within this ephemeral VM: block NSS delegation to systemd-resolved.
python3 - <<'PY'
from pathlib import Path
p=Path("/etc/nsswitch.conf")
lines=p.read_text().splitlines()
assert len([s for s in lines if s.lstrip().startswith("hosts:")]) == 1
p.write_text("\n".join(
    "hosts: files dns" if s.lstrip().startswith("hosts:") else s
    for s in lines
)+"\n")
PY

python3 - <<'PY'
import json
import sys
from pathlib import Path
sys.path.insert(0,"/opt/nvl-egress")
from edge_egress_uid_boot import BootGuardManifest
from edge_egress_uid_systemd import render_ssh_systemd_bundle
raw={
    "mode":"PROTECTED_BOOT_GUARD",
    "username":"nvlciuser","uid":1659,"priority":1780,"dns_port":10553,
    "spec":{
        "edge_id":"fra1","edge_public_ipv4":"216.126.229.12",
        "core_public_ipv4":"209.200.246.198","tunnel_network":"10.78.100.0/30",
        "veth_network":"10.78.101.0/30","edge_uplink":"eth0",
        "edge_listen_port":51832,"route_table":1780,"mode":"relay"
    }
}
p=Path("/etc/nvl-egress/protected/nvlciuser.json")
p.write_text(json.dumps(raw))
p.chmod(0o600)
bundle=render_ssh_systemd_bundle(BootGuardManifest.parse(raw))
Path("/etc/systemd/system",bundle.guard_name).write_text(bundle.guard_unit)
Path("/etc/systemd/system",bundle.dns_name).write_text(bundle.dns_unit)
Path("/etc/systemd/system/ssh.service.d/90-nvl-egress.conf").write_text(
    bundle.ssh_dropin)
PY

# Deliberately retain current administrator SSH session during preparation.
for socket in ssh.socket sshd.socket; do
  systemctl disable --now "$socket" >/dev/null 2>&1 || true
  systemctl mask "$socket" >/dev/null 2>&1 || true
done
systemctl daemon-reload
systemctl enable ssh.service >/dev/null
systemctl is-enabled ssh.socket | grep -Eq 'masked|disabled|not-found'
systemctl show ssh.service -p Requires -p BindsTo -p After --no-pager \
  | grep -q 'nvl-egress-guard-nvlciuser.service'
systemd-analyze verify \
  /etc/systemd/system/nvl-egress-guard-nvlciuser.service \
  /etc/systemd/system/nvl-egress-dns-nvlciuser.service
echo "C3E_GUEST_UNITS_INSTALLED_FOR_NEXT_REBOOT"
