"""M2 first UID bootstrap with original-6G verification before every host action.

No new 6G journal, PAM hook, CLI workflow or alternative installer. The
existing first-UID installer is reused behind a reviewed scoped root port;
multi-UID additions use k2_m2_guard_append. This adapter is OFF by default,
not registered with Telegram and cannot produce F4 READY.
"""
from __future__ import annotations

import json
import os
from typing import Callable

from edge_egress_p3_executor import (
    ExecutionScope, ExecutionTicket, assert_guarded_6g_intent,
)
from edge_egress_uid_boot import BootGuardManifest
from ops.k2_p3_guard_installer import (
    GuardInstallPlan, RootFilePort, apply_guard_install,
)

M2_FIRST_UID_ENABLED = False


class FirstUIDHold(ValueError):
    pass


class Original6GRootPort:
    """Typed, lease-checked adapter; no dynamic shell command generation."""

    def __init__(self, *, port: RootFilePort, lease: Callable[[], int],
                 before_pam: Callable[[], bool]):
        if port is None or not callable(lease) or not callable(before_pam):
            raise FirstUIDHold("M2_LEASE_AND_PAM_FENCE_REQUIRED")
        self.port, self.lease, self.before_pam = port, lease, before_pam

    def create(self, path, data) -> None:
        self.lease()
        self.port.create(path, data)

    def replace_exact(self, path, expected, replacement) -> None:
        self.lease()
        from ops.k2_p3_guard_installer import PAM
        if path == PAM and self.before_pam() is not True:
            raise FirstUIDHold("M2_BEFORE_PAM_DNS_IPV6_FENCE_NOT_ATTESTED")
        self.port.replace_exact(path, expected, replacement)

    def command(self, *cmd) -> None:
        self.lease()
        self.port.command(*cmd)


def guarded_first_uid_bootstrap(
    *, plan: GuardInstallPlan, scope: ExecutionScope,
    ticket: ExecutionTicket, current_pam: bytes, db_conn: Callable,
    os_uid: Callable[[str], int], port: RootFilePort,
    independent_rescue_ok: Callable[[], bool],
    independent_f4_ok: Callable[[ExecutionScope], bool],
    mixed_legacy_pam_ok: Callable[[], bool],
    account_idle_ok: Callable[[str, int], bool],
    sshd_effective_probe: Callable[[], str],
    guard_frozen_ok: Callable[[BootGuardManifest], bool],
    dns_ipv6_ok: Callable[[BootGuardManifest], bool],
    release_enabled: bool = False,
    geteuid: Callable[[], int] = os.geteuid,
) -> None:
    """Stage first UID deny-before-PAM; F4/PAM/6G/root must remain pinned."""
    if (not M2_FIRST_UID_ENABLED or release_enabled is not True or
        not isinstance(plan, GuardInstallPlan) or
        not isinstance(scope, ExecutionScope) or
        not isinstance(ticket, ExecutionTicket) or
        not isinstance(current_pam, bytes) or
        scope.action not in ("UID_ATTACH", "UID_ENROLL_SOURCE") or
        not callable(db_conn) or port is None or geteuid() != 0 or
        not all(callable(x) for x in (
            os_uid, independent_rescue_ok, independent_f4_ok,
            mixed_legacy_pam_ok, account_idle_ok, sshd_effective_probe,
            guard_frozen_ok, dns_ipv6_ok,
        ))):
        raise FirstUIDHold("M2_FIRST_BOOTSTRAP_RELEASE_NOT_ATTESTED")
    try:
        manifest=BootGuardManifest.parse(json.loads(plan.manifest_bytes))
    except (ValueError, TypeError, KeyError) as exc:
        raise FirstUIDHold("M2_FIRST_MANIFEST_UNTRUSTED") from exc
    req=manifest.request
    if (req.username != plan.username or req.uid != plan.uid or
        req.spec.edge_id != scope.edge_id or
        req.spec.edge_public_ipv4 != scope.target_host or
        scope.username != plan.username or scope.uid != plan.uid or
        os_uid(plan.username) != plan.uid):
        raise FirstUIDHold("M2_FIRST_SCOPE_IDENTITY_DRIFT")
    if (independent_rescue_ok() is not True or
        independent_f4_ok(scope) is not True or
        mixed_legacy_pam_ok() is not True or
        account_idle_ok(plan.username,plan.uid) is not True):
        raise FirstUIDHold("M2_FIRST_PHYSICAL_MIXED_COHORT_HOLD")

    def locked() -> int:
        return assert_guarded_6g_intent(db_conn,scope,ticket)

    locked()
    # Original installer validates installed pinned source bundle, PAM
    # diff, root ownership, canary idleness, kernel denial and systemd;
    # the port reasserts the SAME 6G intent before every host mutation.
    wrapped=Original6GRootPort(
        port=port,lease=locked,
        before_pam=lambda: (
            guard_frozen_ok(manifest) is True and
            dns_ipv6_ok(manifest) is True
        ),
    )
    apply_guard_install(
        plan=plan,current_pam=current_pam,existing_guards={},
        os_uid=os_uid,port=wrapped,
        independent_console_ok=independent_rescue_ok,
        account_idle_ok=account_idle_ok,
        reviewed_module_sha=plan.module_sha256,
        sshd_effective_probe=sshd_effective_probe,
        release_enabled=True,geteuid=geteuid,
    )
    locked()


def resume_first_uid_bootstrap(
    *, plan: GuardInstallPlan, scope: ExecutionScope,
    ticket: ExecutionTicket, current_pam: bytes, db_conn: Callable,
    os_uid: Callable[[str], int], port: RootFilePort,
    rescue_ok: Callable[[], bool], f4_ok: Callable[[ExecutionScope], bool],
    mixed_legacy_ok: Callable[[], bool],
    idle_ok: Callable[[str,int], bool],
    sshd_effective: Callable[[], str],
    guard_frozen_ok: Callable[[BootGuardManifest], bool],
    dns_ipv6_ok: Callable[[BootGuardManifest], bool],
    release_enabled: bool = False,
    geteuid: Callable[[], int] = os.geteuid,
) -> None:
    """Exact staged bootstrap resume, with PAM CAS LAST (never an unguard)."""
    from hashlib import sha256
    from pathlib import Path
    from edge_egress_v1_admission import ROSTER, GUARD_DIR, inspect_pam
    from ops.k2_p3_guard_installer import (
        PAM, UNITS, CODE_DIR, _owned, _safe_read,
    )
    from ops.k2_m2_guard_recovery import inspect_first_uid_stage
    from edge_egress_f4_pam import verify_installed_gate_digest

    if (not M2_FIRST_UID_ENABLED or release_enabled is not True
        or not isinstance(plan, GuardInstallPlan)
        or not isinstance(scope, ExecutionScope)
        or not isinstance(ticket, ExecutionTicket)
        or not isinstance(current_pam, bytes)
        or not callable(db_conn) or port is None or geteuid()!=0
        or not all(callable(x) for x in (
            os_uid,rescue_ok,f4_ok,mixed_legacy_ok,idle_ok,
            sshd_effective,guard_frozen_ok,dns_ipv6_ok,
        ))):
        raise FirstUIDHold("M2_FIRST_RESUME_RELEASE_NOT_ATTESTED")
    try:
        manifest=BootGuardManifest.parse(json.loads(plan.manifest_bytes))
        req=manifest.request
        if (req.username != plan.username or req.uid != plan.uid
            or scope.username != req.username or scope.uid != req.uid
            or req.spec.edge_id != scope.edge_id
            or scope.target_host != req.spec.edge_public_ipv4
            or scope.action not in ("UID_ENROLL_SOURCE","UID_ATTACH")
            or os_uid(req.username) != req.uid):
            raise FirstUIDHold("FIRST_RESUME_SCOPE_DRIFT")
    except (ValueError, TypeError, KeyError) as exc:
        raise FirstUIDHold("FIRST_RESUME_MANIFEST_INVALID") from exc
    if (rescue_ok() is not True or f4_ok(scope) is not True
        or mixed_legacy_ok() is not True or idle_ok(plan.username,plan.uid) is not True
        or not verify_installed_gate_digest(plan.module_sha256)):
        raise FirstUIDHold("FIRST_RESUME_INDEPENDENT_GATES_MISSING")

    def locked() -> int:
        return assert_guarded_6g_intent(db_conn,scope,ticket)

    locked()
    for directory in (ROSTER.parent,GUARD_DIR,UNITS,CODE_DIR):
        _owned(directory,directory=True,strict=False)
    paths = {
        "roster":ROSTER,
        "guard":GUARD_DIR/(plan.username+".json"),
        "pam_backup":ROSTER.parent/("pam-sshd-before-"+plan.pam_before_sha256+".bak"),
        "guard_unit":UNITS/plan.guard_unit_name,
        "dns_unit":UNITS/plan.dns_unit_name,
    }
    existing = {}
    for key,path in paths.items():
        if path.is_symlink():
            raise FirstUIDHold("FIRST_RESUME_SYMLINK")
        existing[key]=_safe_read(path,maximum=262144) if path.exists() else None
    pam_live=_safe_read(PAM,maximum=131072,strict=False)
    if (pam_live != current_pam
        or sha256(current_pam).hexdigest()!=plan.pam_before_sha256
        or not inspect_pam(plan.pam_after.decode(),sshd_effective())):
        raise FirstUIDHold("FIRST_RESUME_PAM_PIN_OR_SSHD_DRIFT")
    review=inspect_first_uid_stage(
        plan=plan,pinned_pam_before=current_pam,
        current_pam=pam_live,staged=existing,
        original_6g_running=True)
    if not review.may_request_replay:
        raise FirstUIDHold("FIRST_RESUME_UNSAFE_"+review.reason)
    expected={
        "roster":plan.roster_bytes,
        "guard":plan.manifest_bytes,
        "pam_backup":current_pam,
        "guard_unit":plan.guard_unit.encode(),
        "dns_unit":plan.dns_unit.encode(),
    }
    wrapped=Original6GRootPort(
        port=port,lease=locked,
        before_pam=lambda: (
            guard_frozen_ok(manifest) is True and
            dns_ipv6_ok(manifest) is True
        ),
    )
    for key,path in paths.items():
        locked()
        if existing[key] is None:
            wrapped.create(path,expected[key])
    wrapped.command("systemctl","daemon-reload")
    wrapped.command("systemctl","enable","--now",plan.guard_unit_name)
    if guard_frozen_ok(manifest) is not True:
        raise FirstUIDHold("FIRST_RESUME_BOOT_DENY_NOT_ATTESTED")
    locked()
    wrapped.command("systemctl","enable","--now",plan.dns_unit_name)
    if dns_ipv6_ok(manifest) is not True:
        raise FirstUIDHold("FIRST_RESUME_DNS_IPV6_NOT_ATTESTED")
    locked()
    # PAM edit is the very last mutation. Protected account stays DENY
    # until M3 commits independently verified runtime via original 6G.
    wrapped.replace_exact(PAM,current_pam,plan.pam_after)
    if _safe_read(PAM,maximum=131072,strict=False)!=plan.pam_after:
        raise FirstUIDHold("FIRST_RESUME_PAM_POST_CAS_MISMATCH")
    locked()
