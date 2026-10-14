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

    def __init__(self, *, port: RootFilePort, lease: Callable[[], int]):
        if port is None or not callable(lease):
            raise FirstUIDHold("M2_LEASE_PORT_REQUIRED")
        self.port, self.lease = port, lease

    def create(self, path, data) -> None:
        self.lease()
        self.port.create(path, data)

    def replace_exact(self, path, expected, replacement) -> None:
        self.lease()
        self.port.replace_exact(path, expected, replacement)

    def command(self, *cmd) -> None:
        self.lease()
        self.port.command(*cmd)


def guarded_first_uid_bootstrap(
    *, plan: GuardInstallPlan, scope: ExecutionScope,
    ticket: ExecutionTicket, db_conn: Callable,
    os_uid: Callable[[str], int], port: RootFilePort,
    independent_rescue_ok: Callable[[], bool],
    independent_f4_ok: Callable[[ExecutionScope], bool],
    mixed_legacy_pam_ok: Callable[[], bool],
    account_idle_ok: Callable[[str, int], bool],
    sshd_effective_probe: Callable[[], str],
    release_enabled: bool = False,
    geteuid: Callable[[], int] = os.geteuid,
) -> None:
    """Stage first UID deny-before-PAM; F4/PAM/6G/root must remain pinned."""
    if (not M2_FIRST_UID_ENABLED or release_enabled is not True or
        not isinstance(plan, GuardInstallPlan) or
        not isinstance(scope, ExecutionScope) or
        not isinstance(ticket, ExecutionTicket) or
        scope.action not in ("UID_ATTACH", "UID_ENROLL_SOURCE") or
        not callable(db_conn) or port is None or geteuid() != 0 or
        not all(callable(x) for x in (
            os_uid, independent_rescue_ok, independent_f4_ok,
            mixed_legacy_pam_ok, account_idle_ok, sshd_effective_probe,
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
    wrapped=Original6GRootPort(port=port,lease=locked)
    apply_guard_install(
        plan=plan,current_pam=b"",existing_guards={},
        os_uid=os_uid,port=wrapped,
        independent_console_ok=independent_rescue_ok,
        account_idle_ok=account_idle_ok,
        reviewed_module_sha=plan.module_sha256,
        sshd_effective_probe=sshd_effective_probe,
        release_enabled=True,geteuid=geteuid,
    )
    locked()
