#!/usr/bin/env bash
# D1-C3E: destructive reboot test ONLY in disposable GitHub CI QEMU guest.
set -Eeuo pipefail
umask 077
[[ "$(printenv GITHUB_ACTIONS || true)" == "true" &&
   "$(printenv NVL_CI_VM_LAB || true)" == "1" && "$EUID" == "0" ]] || exit 69
BASE="$(pwd)"
TMP="$(mktemp -d /tmp/nvl-egress-vm-XXXXXX)"
VM_PID=""
cleanup() {
  result=$?
  trap - EXIT
  set +e
  if [[ -n "$VM_PID" ]]; then kill "$VM_PID" 2>/dev/null || true; wait "$VM_PID" 2>/dev/null || true; fi
  if [[ "$result" -ne 0 ]]; then
    echo "=== VM SERIAL TAIL ==="
    tail -n 100 "$TMP/serial.log" 2>/dev/null || true
  fi
  rm -rf -- "$TMP"
  exit "$result"
}
trap cleanup EXIT
for cmd in qemu-img qemu-system-x86_64 cloud-localds curl ssh scp ssh-keygen; do
  command -v "$cmd" >/dev/null || { echo "Missing $cmd"; exit 69; }
done
ssh-keygen -q -t ed25519 -N '' -f "$TMP/lab_key"
cat > "$TMP/user-data" <<EOF
#cloud-config
users:
  - name: labadmin
    gecos: NVL isolated VM administrator
    groups: [sudo]
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - $(cat "$TMP/lab_key.pub")
ssh_pwauth: false
disable_root: true
EOF
cat > "$TMP/meta-data" <<'EOF'
instance-id: nvl-c3e-boot-lab
local-hostname: nvl-ci-ubuntu
EOF
cloud-localds "$TMP/seed.iso" "$TMP/user-data" "$TMP/meta-data"
curl -fL --retry 3 --connect-timeout 12 --max-time 300 \
  "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img" \
  -o "$TMP/base.qcow2"
qemu-img create -q -f qcow2 -F qcow2 -b "$TMP/base.qcow2" "$TMP/guest.qcow2"
qemu-img resize "$TMP/guest.qcow2" 7G >/dev/null
qemu-system-x86_64 -machine q35,accel=tcg -cpu max -smp 2 -m 3072 \
  -display none -monitor none -serial "file:$TMP/serial.log" \
  -drive "file=$TMP/guest.qcow2,if=virtio,format=qcow2" \
  -drive "file=$TMP/seed.iso,if=virtio,format=raw,readonly=on" \
  -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:10022-:22" \
  -device virtio-net-pci,netdev=n0 > "$TMP/qemu.log" 2>&1 &
VM_PID=$!
remote() {
  ssh -i "$TMP/lab_key" -p 10022 -o BatchMode=yes \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=3 -o LogLevel=ERROR labadmin@127.0.0.1 "$@"
}
wait_for_ssh() {
  for attempt in $(seq 1 140); do
    kill -0 "$VM_PID" || { echo "QEMU_EXITED"; return 1; }
    if remote true 2>/dev/null; then return 0; fi
    sleep 3
  done
  echo "VM_SSH_START_TIMEOUT"; return 1
}
echo "[VM] First cloud-init boot"
wait_for_ssh
remote "cloud-init status --wait" >/dev/null
remote "mkdir -p /tmp/nvl-ci-src"
scp -q -i "$TMP/lab_key" -P 10022 -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
  "$BASE/edge_egress_uid_boot.py" "$BASE/edge_egress_uid_dns.py" \
  "$BASE/edge_egress_uid_policy.py" "$BASE/edge_egress_uid_systemd.py" \
  "$BASE/ops/edge_egress_provision.py" \
  "$BASE/ops/labs/edge_egress_vm_guest_setup.sh" \
  labadmin@127.0.0.1:/tmp/nvl-ci-src/
echo "[VM] Install guard and notified-DNS dependencies"
remote "sudo env NVL_DISPOSABLE_VM=1 bash /tmp/nvl-ci-src/edge_egress_vm_guest_setup.sh"
echo "[VM] REAL guest reboot; guard+DNS must precede SSH"
remote "sudo systemctl reboot" >/dev/null 2>&1 || true
sleep 8
wait_for_ssh
remote "sudo systemctl is-active --quiet nvl-egress-guard-nvlciuser.service"
remote "sudo systemctl is-active --quiet nvl-egress-dns-nvlciuser.service"
remote "sudo systemctl is-active --quiet ssh.service"
remote "sudo /usr/bin/python3 /opt/nvl-egress/edge_egress_uid_boot.py verify --manifest /etc/nvl-egress/protected/nvlciuser.json"
remote "ip -4 route get 1.1.1.1"
if remote "sudo -u nvlciuser curl --noproxy '*' -4fsS --connect-timeout 3 --max-time 4 https://1.1.1.1/" \
  >/dev/null 2>&1; then
  echo "FAIL: protected UID used guest Core default"; exit 1
fi
echo "VM_REBOOT_GUARD_DNS_READY_AND_DENY_PASS"

echo "[VM] Fault injection: invalid manifest then second real guest reboot"
remote "sudo sh -c 'printf \"%s\" \"INVALID-JSON\" > /etc/nvl-egress/protected/nvlciuser.json'"
remote "sudo systemctl reboot" >/dev/null 2>&1 || true
sleep 15
kill -0 "$VM_PID" || { echo "FAIL: guest VM stopped"; exit 1; }
for attempt in $(seq 1 8); do
  if remote true >/dev/null 2>&1; then
    echo "FAIL: SSH started with invalid boot guard manifest"; exit 1
  fi
  sleep 3
done
echo "VM_REBOOT_BROKEN_GUARD_BLOCKED_SSH_PASS"
echo "VM_BOOT_LAB_PASS: real guest reboots, DNS readiness, invalid guard prevents SSH"
