# D1-C3E — disposable VM reboot and SSH systemd dependency gate

**Status:** Draft PR #80. Automated QEMU VM reboot checks and unit regressions; no production changes or deployment authorization.

## Changes

- The DNS proxy now signals systemd READY=1 only after TCP+UDP local listener sockets are bound, and the DNS unit uses Type=notify / NotifyAccess=main. Listener READY does not imply a working upstream Edge.
- The offline module edge_egress_uid_systemd.py produces a bundle: root-only boot guard oneshot, UID-bound notified DNS service, and an ssh.service drop-in using Requires, BindsTo and After for both dependencies. This is a global SSH stop/start dependency, intentionally **too disruptive for the live Core**.
- A separate socket-activation preflight rejects enabled, active or unknown ssh.socket / sshd.socket states. A direct sshd process or other service not dependent on this guard can still bypass the ordering.
- Additional unit regressions check service dependency presence, Type=notify, and actual UNIX datagram READY=1.

## What the isolated QEMU test does

Workflow file: .github/workflows/edge-egress-vm-boot.yml.
Host script: ops/labs/edge_egress_vm_boot_lab.sh.
Guest script: ops/labs/edge_egress_vm_guest_setup.sh.

1. Download independent Ubuntu 24.04 guest image, create disposable overlay and cloud-init ephemeral administrator key, boot QEMU; no live NVL hosts are accessed.
2. Inside guest, create synthetic UID1659, write root-only explicit protected manifest, restrict guest-only NSS to hosts: files dns, mask SSH socket activation and install the guard + DNS + SSH drop-in.
3. REAL GUEST REBOOT: verify SSH is reachable only after guard and notified DNS become active. Check protected UID cannot reach Internet using ordinary guest default route.
4. Corrupt the guest's protected manifest and REBOOT AGAIN. The guard should fail and ssh.service must not accept logins. QEMU must remain running.
5. Remove guest VM, overlay, temporary keys and files after the test.

The VM test is separate from prior C3D kernel namespace tests that proved Edge IPv4, simulated TLS DoH, IPv6 reject and edge outage fail-closed. A QEMU/cloud-image/apt network failure is classified as a CI blocker, not proof of routing failure.

## Unproven production boundaries

- Only ssh.service startup is guarded. Existing account-owned background processes, cron, socket bypasses, direct sshd invocation, and kernel-rule drift need other controls.
- Protected DNS startup is local listener-ready with a BLACKHOLE route: no working Edge is needed or proven after reboot.
- Privileged NSS/systemd-resolved, nscd, all-app/protocol DNS leaks, real BadVPN/UDP, full multi-user assignment and Phase 6G/6H protected failover are not demonstrated by this reboot test.
- No automatic rollback to Core is allowed for a protected account.
- Actual VPS backup/offsite restore and an operator canary rehearsal are still release blockers.

**KEEP PR #80 DRAFT, PROTECTED MODE OFF, NO LIVE SSH SYSTEMD INSTALL.**
