"""D1-C3E: generate an explicit fail-closed SSH/systemd dependency bundle.

This module is an OFFLINE renderer and verifier. It never installs files,
runs systemctl, touches ssh.service, or enables protected mode. Production
must NOT use it until a disposable VM reboot and recovery test passes.

The shared ssh.service binds to both the UID's deny guard and its DNS
listener. This globally stops NEW SSH logins if either dependency fails;
it is intentionally too disruptive to enable on the live NVL Core.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

from edge_egress_uid_boot import BootGuardManifest, render_ssh_required_unit
from edge_egress_uid_dns import render_dns_required_unit

class SystemdBootError(ValueError):
    pass


@dataclass(frozen=True)
class SSHSystemdBundle:
    guard_name: str
    dns_name: str
    guard_unit: str
    dns_unit: str
    ssh_dropin: str


def render_ssh_systemd_bundle(manifest: BootGuardManifest) -> SSHSystemdBundle:
    request = manifest.request
    request.validate()
    if manifest.mode != "PROTECTED_BOOT_GUARD" or manifest.dns_port is None:
        raise SystemdBootError("PROTECTED_DNS_MANIFEST_REQUIRED")
    username = request.username
    guard = "nvl-egress-guard-" + username + ".service"
    dns = "nvl-egress-dns-" + username + ".service"
    guard_text = render_ssh_required_unit(manifest)
    dns_text = render_dns_required_unit(request, manifest.dns_port)
    # Requires alone doesn't imply order; After is mandatory. BindsTo stops
    # SSH if a dependency service transitions to inactive; it does NOT detect
    # a kernel firewall rule being deleted under an active oneshot service.
    dropin = ("[Unit]\n"
              f"Requires={guard} {dns}\n"
              f"BindsTo={guard} {dns}\n"
              f"After={guard} {dns}\n")
    bundle = SSHSystemdBundle(guard, dns, guard_text, dns_text, dropin)
    verify_bundle(bundle)
    return bundle


def verify_bundle(bundle: SSHSystemdBundle) -> None:
    """Validate declared startup ordering before writing any unit to disk."""
    if bundle.guard_name == bundle.dns_name:
        raise SystemdBootError("COLLIDING_UNIT_IDS")
    names = {bundle.guard_name, bundle.dns_name}
    drop = bundle.ssh_dropin.splitlines()
    for directive in ("Requires=", "BindsTo=", "After="):
        values = [line.split("=", 1)[1].split()
                  for line in drop if line.startswith(directive)]
        if len(values) != 1 or set(values[0]) != names:
            raise SystemdBootError("SSH_MISSING_REQUIRED_UNIT_DEPENDENCY")
    guard = bundle.guard_unit
    dns = bundle.dns_unit
    if ("Type=oneshot" not in guard or "RemainAfterExit=yes" not in guard
            or "Before=ssh.service" not in guard
            or "apply --manifest " not in guard or " --enforce" not in guard):
        raise SystemdBootError("GUARD_NOT_BOOT_BLOCKING")
    if ("Type=notify" not in dns or "NotifyAccess=main" not in dns
            or f"Requires={bundle.guard_name}" not in dns
            or f"After={bundle.guard_name}" not in dns
            or "Before=ssh.service" not in dns):
        raise SystemdBootError("DNS_NOT_BOOT_BLOCKING")
    if re.search(r"(?m)^(ExecStop|ExecStopPost)=", guard + dns):
        raise SystemdBootError("GUARD_DESTRUCTION_ON_STOP")
    if ("WantedBy=ssh.service" in guard or "WantedBy=ssh.service" in dns):
        raise SystemdBootError("NON_BLOCKING_DEPENDENCY")


def assess_ssh_host_socket(enabled_socket_units: dict[str, str]) -> None:
    """Fail when socket-activated SSH could start independently of guard."""
    for socket in ("ssh.socket", "sshd.socket"):
        state = enabled_socket_units.get(socket, "").strip()
        # Accepted: systemd disabled/not-found/masked for both names.
        if state not in ("disabled", "masked", "not-found"):
            raise SystemdBootError("UNVERIFIED_SSH_SOCKET_ACTIVATION")
