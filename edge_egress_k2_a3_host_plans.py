"""A3.1 read-only M2 First/Nth UID plan source, tied to trusted root files.

This is a *plan builder*, not a live ReviewedUIDHostSnapshot and not a worker.
No shell, PAM edit, roster write, SQL write or root daemon activation. The
caller must still supply independently measured F4/session/safety providers,
P3 evidence and exact original 6G approval before these plans can be applied.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
from typing import Callable

from edge_egress_k2_m4_root_worker import _read_checked, _verify_root_directory
from edge_egress_p3_executor import ExecutionScope, ExecutionTicket, _scope_digest
from edge_egress_uid_boot import BootGuardManifest
from edge_egress_v1_admission import (
    GUARD_DIR, ROSTER, load_roster, render_roster,
)
from ops.k2_p3_guard_installer import (
    GuardInstallPlan, PAM, MODULE, plan_guard_install,
)
from ops.k2_m2_guard_append import MultiUIDAppendPlan, plan_next_uid

A3_ROOT_OWNED_PLAN_SOURCE_ENABLED = False
ROOT_PLAN_DIR = Path("/etc/nvl-egress/k2-m4/uid-plans")
MAX_MANIFEST = 4096


class A3PlanHold(ValueError):
    pass


@dataclass(frozen=True)
class ReviewedRootM2Plan:
    scope: ExecutionScope
    ticket: ExecutionTicket
    kind: str
    plan: GuardInstallPlan | MultiUIDAppendPlan
    manifest_sha256: str
    original_pam_sha256: str
    installed_module_sha256: str


class RootOwnedM2PlanSource:
    """Only read root-owned current state; decide First/Nth deterministically.

    No trust in historical ssh_accounts.host, Telegram-supplied manifest
    bytes, preview-only F4, or a missing roster as proof of an empty system.
    """

    def __init__(
        self, *, db_conn: Callable, os_uid: Callable[[str],int],
        geteuid: Callable[[],int] = os.geteuid,
    ):
        if not all(callable(x) for x in (db_conn,os_uid,geteuid)):
            raise A3PlanHold("A3_READ_ONLY_PROVIDER_INVALID")
        self.db_conn=db_conn
        self.os_uid=os_uid
        self.geteuid=geteuid

    def __call__(self, scope: ExecutionScope,
                 ticket: ExecutionTicket) -> ReviewedRootM2Plan:
        if (not A3_ROOT_OWNED_PLAN_SOURCE_ENABLED
            or self.geteuid()!=0 or not isinstance(scope,ExecutionScope)
            or scope.action!="UID_ENROLL_SOURCE"
            or scope.source_host!=scope.target_host
            or not isinstance(ticket,ExecutionTicket)
            or ticket.scope_digest!=_scope_digest(scope)
            or not isinstance(scope.username,str)
            or not scope.username.isascii()
            or not __import__("re").fullmatch(
                r"[a-z_][a-z0-9_-]{0,31}",scope.username)
            or type(scope.uid) is not int
            or not 1000<=scope.uid<60000):
            raise A3PlanHold("A3_EXACT_ROOT_SCOPE_REQUIRED")
        _verify_root_directory(ROOT_PLAN_DIR,group=None,private=True)
        raw=_read_checked(
            ROOT_PLAN_DIR/(scope.username+".json"),
            maximum=MAX_MANIFEST,strict=True,
        )
        try:
            manifest=BootGuardManifest.parse(json.loads(raw))
        except (ValueError,KeyError,TypeError,UnicodeError) as exc:
            raise A3PlanHold("A3_REVIEWED_MANIFEST_INVALID") from exc
        request=manifest.request
        if (not manifest.shared_edge or not manifest.ingress_return
            or manifest.dns_port is None
            or request.username!=scope.username or request.uid!=scope.uid
            or request.spec.edge_id!=scope.edge_id
            or request.spec.edge_public_ipv4!=scope.target_host
            or self.os_uid(scope.username)!=scope.uid):
            raise A3PlanHold("A3_ROOT_PLAN_IDENTITY_CHANGED")

        # Neither path is supplied by Telegram. Both open with O_NOFOLLOW,
        # and all writers remain in existing M2 deferred apply under 6G.
        pam=_read_checked(PAM,maximum=131072,strict=False)
        module=_read_checked(MODULE,maximum=2_000_000,strict=False)
        module_sha=sha256(module).hexdigest()
        pam_sha=sha256(pam).hexdigest()
        if ROSTER.is_symlink():
            raise A3PlanHold("A3_PROTECTED_ROSTER_SYMLINK")
        if ROSTER.exists():
            roster_bytes=_read_checked(ROSTER,maximum=262144,strict=True)
            _verify_root_directory(GUARD_DIR,group=None)
            roster=load_roster()
            if not roster or scope.username in roster:
                raise A3PlanHold("A3_EXISTING_OR_EMPTY_ROSTER_HOLD")
            owned={}
            for name,member in roster.items():
                if (not __import__("re").fullmatch(
                    r"[a-z_][a-z0-9_-]{0,31}",name)
                    or name==scope.username):
                    raise A3PlanHold("A3_PRIOR_ROSTER_IDENTITY_UNTRUSTED")
                prior=_read_checked(
                    GUARD_DIR/(name+".json"),maximum=MAX_MANIFEST,strict=True,
                )
                if sha256(prior).hexdigest()!=member.guard_sha256:
                    raise A3PlanHold("A3_EXISTING_UID_GUARD_DRIFT")
                owned[name]=prior
            if roster_bytes!=render_roster(owned).encode("utf-8"):
                raise A3PlanHold("A3_ROOT_ROSTER_CAS_PREVIEW_MISMATCH")
            # A partial prior M2 stage may have left an orphan guard that is
            # absent from the canonical roster. Refuse NEXT_UID before any
            # plan is returned; do not silently adopt or overwrite it.
            try:
                actual_guards={entry.name for entry in GUARD_DIR.iterdir()}
            except OSError as exc:
                raise A3PlanHold("A3_ROOT_GUARD_INVENTORY_UNAVAILABLE") from exc
            expected_guards={name+".json" for name in roster}
            if actual_guards != expected_guards:
                raise A3PlanHold("A3_ORPHANED_OR_MISSING_GUARD_HOLD")
            # Do not enroll a UID that is already in either existing F2
            # runtime table but missing from the root-owned roster. This is
            # an inconsistent/partial protected identity, not a free UID.
            try:
                with self.db_conn() as conn:
                    for table in ("edge_egress_uid_runtime",
                                  "edge_egress_uid_bindings"):
                        present=conn.execute(
                            "SELECT 1 FROM sqlite_master "
                            "WHERE type='table' AND name=?",(table,),
                        ).fetchone()
                        if not present:
                            raise A3PlanHold("A3_PROTECTED_SCHEMA_MISSING")
                        if conn.execute(
                            "SELECT 1 FROM "+table+
                            " WHERE username=? OR uid=? LIMIT 1",
                            (scope.username,scope.uid),
                        ).fetchone():
                            raise A3PlanHold("A3_CANDIDATE_RUNTIME_ALREADY_BOUND")
            except A3PlanHold:
                raise
            except Exception as exc:
                raise A3PlanHold("A3_ROOT_DB_READ_UNAVAILABLE") from exc
            plan=plan_next_uid(
                username=scope.username,manifest_bytes=raw,
                current_roster=roster_bytes,installed_manifests=owned,
                pam_bytes=pam,module_digest=module_sha,os_uid=self.os_uid,
            )
            kind="NEXT_UID"
        else:
            # Missing roster is NOT evidence of a fresh installation if any
            # protected identity or root-owned guard is already present.
            _verify_root_directory(GUARD_DIR,group=None)
            if any(GUARD_DIR.iterdir()):
                raise A3PlanHold("A3_ORPHANED_GUARD_WITHOUT_ROSTER")
            try:
                with self.db_conn() as conn:
                    for table in ("edge_egress_uid_runtime",
                                  "edge_egress_uid_bindings"):
                        present=conn.execute(
                            "SELECT 1 FROM sqlite_master "
                            "WHERE type='table' AND name=?",(table,),
                        ).fetchone()
                        if not present:
                            raise A3PlanHold("A3_PROTECTED_SCHEMA_MISSING")
                        if conn.execute(
                            "SELECT 1 FROM "+table+" LIMIT 1",
                        ).fetchone():
                            raise A3PlanHold("A3_PREVIOUS_PROTECTED_IDENTITY")
            except A3PlanHold:
                raise
            except Exception as exc:
                raise A3PlanHold("A3_ROOT_DB_READ_UNAVAILABLE") from exc
            plan=plan_guard_install(
                username=scope.username,manifest_bytes=raw,
                pam_before=pam,module_sha256=module_sha,
                existing_guard_bytes={},os_uid=self.os_uid,
                expected_pam_sha256=pam_sha,
            )
            kind="FIRST_UID"
        return ReviewedRootM2Plan(
            scope,ticket,kind,plan,sha256(raw).hexdigest(),
            pam_sha,module_sha,
        )
