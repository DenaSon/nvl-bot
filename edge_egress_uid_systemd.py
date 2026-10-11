"""F1: render isolated per-UID guard and DNS units, never shared SSH coupling.

No production installer or per-user login/session gate exists in F1. Rendering
these services is not proof of protection during real boot. In particular,
a failure in one user's DNS must never bring down global ssh.service.
"""
from __future__ import annotations
from dataclasses import dataclass
from edge_egress_uid_boot import BootGuardManifest, render_ssh_required_unit
from edge_egress_uid_dns import render_dns_required_unit


class SystemdBootError(ValueError):
    pass


@dataclass(frozen=True)
class SSHSystemdBundle:
    # Legacy API identity retained so existing code fails safely rather than
    # generating the old dangerous ssh.service drop-in.
    guard_name: str
    dns_name: str
    guard_unit: str
    dns_unit: str
    ssh_dropin: str = ""


def render_ssh_systemd_bundle(manifest: BootGuardManifest) -> SSHSystemdBundle:
    """Offline-only isolated bundle; F2 must supply protected session gating."""
    request = manifest.request
    request.validate()
    if manifest.mode != "PROTECTED_BOOT_GUARD" or manifest.dns_port is None:
        raise SystemdBootError("PROTECTED_DNS_MANIFEST_REQUIRED")
    username = request.username
    guard = "nvl-egress-guard-" + username + ".service"
    dns = "nvl-egress-dns-" + username + ".service"
    bundle = SSHSystemdBundle(
        guard, dns, render_ssh_required_unit(manifest),
        render_dns_required_unit(request, manifest.dns_port), "",
    )
    verify_bundle(bundle)
    return bundle


def verify_bundle(bundle: SSHSystemdBundle) -> None:
    """Reject any global service coupling (including legacy RequiredBy)."""
    if bundle.guard_name == bundle.dns_name:
        raise SystemdBootError("COLLIDING_UNIT_IDS")
    if bundle.ssh_dropin.strip():
        raise SystemdBootError("GLOBAL_SSH_DEPENDENCY_FORBIDDEN")
    if "ssh.service" in bundle.guard_unit or "ssh.service" in bundle.dns_unit:
        raise SystemdBootError("GLOBAL_SSH_DEPENDENCY_FORBIDDEN")
    if ("Type=oneshot" not in bundle.guard_unit
        or "RemainAfterExit=yes" not in bundle.guard_unit
        or "apply --manifest " not in bundle.guard_unit
        or " --enforce" not in bundle.guard_unit):
        raise SystemdBootError("ISOLATED_GUARD_INVALID")
    if ("Type=notify" not in bundle.dns_unit
        or "NotifyAccess=main" not in bundle.dns_unit
        or f"Requires={bundle.guard_name}" not in bundle.dns_unit
        or f"After={bundle.guard_name}" not in bundle.dns_unit):
        raise SystemdBootError("ISOLATED_DNS_DEPENDENCY_INVALID")
    if any(s in bundle.guard_unit + bundle.dns_unit for s in
           ("ExecStop=", "ExecStopPost=", "RequiredBy=ssh.service",
            "WantedBy=ssh.service", "BindsTo=ssh.service")):
        raise SystemdBootError("UNREVIEWED_SERVICE_LIFECYCLE")


def assess_ssh_host_socket(enabled_socket_units: dict[str, str]) -> None:
    """Retain strict socket preflight for the future F4 reboot acceptance."""
    for socket in ("ssh.socket", "sshd.socket"):
        state = enabled_socket_units.get(socket, "").strip()
        if state not in ("disabled", "masked", "not-found"):
            raise SystemdBootError("UNVERIFIED_SSH_SOCKET_ACTIVATION")
