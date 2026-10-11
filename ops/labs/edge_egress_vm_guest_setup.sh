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

# Confined to the disposable VM: no live NVL systems are ever touched.
# SSH socket activation can bypass our RequiredBy ssh.service guard.
# Earlier CI swallowed a failed mask and then died at is-enabled without
# reporting which assertion failed. Fail with actionable diagnostics instead.
on_setup_error() {
  code=$?
  echo "C3E_GUEST_SETUP_FAILED code=$code line=$BASH_LINENO command=$BASH_COMMAND" >&2
  echo "=== SSH socket states ===" >&2
  for name in ssh.socket sshd.socket ssh.service; do
    printf '%s: ' "$name" >&2
    systemctl is-enabled "$name" 2>&1 || true
  done
  echo "=== SSH unit dependencies ===" >&2
  systemctl show ssh.service -p Requires -p BindsTo -p After --no-pager >&2 || true
  echo "=== Unit verification ===" >&2
  systemd-analyze verify /etc/systemd/system/nvl-egress-guard-nvlciuser.service \
    /etc/systemd/system/nvl-egress-dns-nvlciuser.service >&2 || true
  exit "$code"
}
trap on_setup_error ERR
for socket in ssh.socket sshd.socket; do
  if systemctl list-unit-files "$socket" --no-legend --no-pager | grep -q "$socket"; then
    systemctl disable --now "$socket" >/dev/null 2>&1 || true
    systemctl mask --force "$socket" >/dev/null
  fi
done
# Boot diagnostics are independent of SSH and safe only inside this VM.
# Print the actual systemd failure reason to the serial console even if
# ssh.service does not start after a guarded reboot.
mkdir -p /usr/local/libexec
cat > /usr/local/libexec/nvl-c3e-boot-diagnostics.sh <<'DIAG'
#!/usr/bin/env bash
set +e
sleep 30
echo "=== C3E_GUEST_BOOT_DIAGNOSTICS_BEGIN ==="
for unit in nvl-egress-guard-nvlciuser.service nvl-egress-dns-nvlciuser.service ssh.service ssh.socket; do
  echo "--- C3E_UNIT: $unit ---"
  systemctl show "$unit" -p LoadState -p ActiveState -p SubState \
    -p Result -p ExecMainStatus -p ExecMainCode -p After -p Requires \
    --no-pager
  systemctl status "$unit" --no-pager -l | tail -n 24
  journalctl -b -u "$unit" --no-pager -n 35
done
echo "=== C3E_GUEST_BOOT_DIAGNOSTICS_END ==="
DIAG
chmod 0755 /usr/local/libexec/nvl-c3e-boot-diagnostics.sh
cat > /etc/systemd/system/nvl-c3e-boot-diagnostics.service <<'UNIT'
[Unit]
Description=Disposable NVL C3E serial-only boot diagnostics
DefaultDependencies=no
After=local-fs.target
Before=shutdown.target
Conflicts=shutdown.target

[Service]
Type=simple
ExecStart=/usr/local/libexec/nvl-c3e-boot-diagnostics.sh
StandardOutput=tty
StandardError=inherit
TTYPath=/dev/ttyS0
TTYReset=no
TTYVHangup=no
TTYVTDisallocate=no

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable nvl-c3e-boot-diagnostics.service >/dev/null
systemctl enable ssh.service >/dev/null

# Check the actual state without depending on a grep pipeline or silently
# treating a failed mask as successful.
for socket in ssh.socket sshd.socket; do
  state="$(systemctl is-enabled "$socket" 2>&1 || true)"
  echo "C3E_SOCKET_STATE $socket=$state"
  case "$state" in
    masked|disabled|not-found) ;;
    *) echo "UNSAFE_SOCKET_ACTIVATION_STATE $socket=$state" >&2; exit 42 ;;
  esac
done
requires="$(systemctl show ssh.service -p Requires --value --no-pager)"
bindsto="$(systemctl show ssh.service -p BindsTo --value --no-pager)"
after="$(systemctl show ssh.service -p After --value --no-pager)"
for dependency in nvl-egress-guard-nvlciuser.service nvl-egress-dns-nvlciuser.service; do
  for field in "$requires" "$bindsto" "$after"; do
    if [[ " $field " != *" $dependency "* ]]; then
      echo "MISSING_SSH_SYSTEMD_DEPENDENCY $dependency" >&2
      exit 43
    fi
  done
done
systemd-analyze verify \
  /etc/systemd/system/nvl-egress-guard-nvlciuser.service \
  /etc/systemd/system/nvl-egress-dns-nvlciuser.service
trap - ERR
echo "C3E_GUEST_UNITS_INSTALLED_FOR_NEXT_REBOOT"
