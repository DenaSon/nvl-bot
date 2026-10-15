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


# This binds the *existing* M2 first/next plan to the *existing* M4
# ReviewedUIDHostSnapshot. It is an adapter for the unfinished A3.1 gate,
# not an authority to declare packet/F4 readiness or change the host.
A3_ROOT_SNAPSHOT_BINDING_ENABLED = False


@dataclass(frozen=True)
class RootHostSafetyGates:
    """Required independently reviewed M2 callbacks; no default PASS values.

    The off-Core F4/session/packet observer and root rescue checks must be
    physically accepted before a deployment integrator can supply these.
    Merely instantiating the dataclass never establishes that acceptance.
    """
    safety: object
    independent_rescue_ok: Callable[[], bool]
    independent_f4_ok: Callable[[ExecutionScope], bool]
    mixed_legacy_pam_ok: Callable[[], bool]
    account_idle_ok: Callable[[str, int], bool]
    sshd_effective_probe: Callable[[], str]
    guard_frozen_ok: Callable[[BootGuardManifest], bool]
    dns_ipv6_ok: Callable[[BootGuardManifest], bool]


class RootOwnedUIDSnapshotSource:
    """Read-only bridge for the canonical SAME-EDGE UID_ENROLL_SOURCE path.

    A trusted host composition supplies root-only review and externally
    witnessed M2/F4 gates; neither Telegram nor the historical account host
    can supply a plan, file port, or truthy evidence. Both original M2 apply
    functions continue to run only under DeferredOriginal6GHostPort.apply.
    """

    def __init__(
        self, *, plan_source: RootOwnedM2PlanSource,
        inventory_provider: Callable,
        gates_provider: Callable[[ExecutionScope, object], RootHostSafetyGates],
        db_conn: Callable, os_uid: Callable[[str], int],
        geteuid: Callable[[], int] = os.geteuid,
    ):
        if (not isinstance(plan_source, RootOwnedM2PlanSource)
            or not all(callable(v) for v in (
                inventory_provider, gates_provider, db_conn, os_uid, geteuid
            ))
            or plan_source.db_conn is not db_conn
            or plan_source.os_uid is not os_uid
            or plan_source.geteuid is not geteuid):
            raise A3PlanHold("A3_SNAPSHOT_PROVIDER_IDENTITY_UNTRUSTED")
        self.plan_source = plan_source
        self.inventory_provider = inventory_provider
        self.gates_provider = gates_provider
        self.db_conn = db_conn
        self.os_uid = os_uid
        self.geteuid = geteuid

    def __call__(self, scope: ExecutionScope, ticket: ExecutionTicket):
        from edge_egress_k2_a_host_factory import ReviewedUIDHostSnapshot
        from edge_egress_k2_m4_bootstrap import GuardBootstrap
        from edge_egress_k2_m3_waves import build_wave_plan
        from edge_egress_k2_migration_inventory import select_migration
        from ops.k2_p3_uid_worker import IndependentSafety
        from ops.k2_p3_guard_installer import RootFilePort
        from ops.k2_m2_guard_append import CASRootRosterPort

        if (not A3_ROOT_SNAPSHOT_BINDING_ENABLED
            or self.geteuid() != 0
            or not isinstance(scope, ExecutionScope)
            or scope.action != "UID_ENROLL_SOURCE"
            or scope.source_host != scope.target_host
            or not isinstance(ticket, ExecutionTicket)
            or ticket.scope_digest != _scope_digest(scope)):
            raise A3PlanHold("A3_SNAPSHOT_ROOT_SAME_EDGE_RELEASE_REQUIRED")

        selection = select_migration(
            "SINGLE", (scope.username,), scope.edge_id
        )
        # This is a second, fresh signed/root review, not the historical
        # ssh_accounts.host or the earlier Telegram preview.
        wave = build_wave_plan(
            self.inventory_provider(selection), wave_size=1
        )
        if (wave.global_blockers or len(wave.members) != 1
            or not wave.members[0].selectable):
            raise A3PlanHold("A3_SNAPSHOT_FRESH_INVENTORY_HOLD")
        member = wave.members[0]
        if (member.username != scope.username or member.uid != scope.uid
            or member.source_edge_id != scope.edge_id
            or member.target_edge_id != scope.edge_id
            or member.source_ipv4 != scope.source_host
            or member.target_ipv4 != scope.target_host):
            raise A3PlanHold("A3_SNAPSHOT_SOURCE_TARGET_DRIFT")

        reviewed = self.plan_source(scope, ticket)
        if (reviewed.scope != scope or reviewed.ticket != ticket
            or reviewed.kind not in ("FIRST_UID", "NEXT_UID")
            or not isinstance(reviewed.plan, (
                GuardInstallPlan, MultiUIDAppendPlan
            ))
            or reviewed.kind == "FIRST_UID"
               and not isinstance(reviewed.plan, GuardInstallPlan)
            or reviewed.kind == "NEXT_UID"
               and not isinstance(reviewed.plan, MultiUIDAppendPlan)):
            raise A3PlanHold("A3_SNAPSHOT_M2_PLAN_UNTRUSTED")
        # Re-open root PAM with no-follow immediately before building a
        # deferred bootstrap; original M2 rechecks again under its 6G lock.
        pam = _read_checked(PAM, maximum=131072, strict=False)
        if sha256(pam).hexdigest() != reviewed.original_pam_sha256:
            raise A3PlanHold("A3_SNAPSHOT_PAM_CHANGED")
        try:
            manifest = BootGuardManifest.parse(
                json.loads(reviewed.plan.manifest_bytes)
            )
        except (ValueError, KeyError, TypeError, UnicodeError) as exc:
            raise A3PlanHold("A3_SNAPSHOT_MANIFEST_INVALID") from exc
        req = manifest.request
        if (req.username != scope.username or req.uid != scope.uid
            or req.spec.edge_id != scope.edge_id
            or req.spec.edge_public_ipv4 != scope.target_host
            or type(manifest.dns_port) is not int
            or not 1024 <= manifest.dns_port <= 65535
            or sha256(reviewed.plan.manifest_bytes).hexdigest()
               != reviewed.manifest_sha256):
            raise A3PlanHold("A3_SNAPSHOT_UID_DNS_IDENTITY_CHANGED")

        gates = self.gates_provider(scope, member)
        if not isinstance(gates, RootHostSafetyGates):
            raise A3PlanHold("A3_SNAPSHOT_INDEPENDENT_GATES_MISSING")
        checks = (
            gates.independent_rescue_ok, gates.independent_f4_ok,
            gates.mixed_legacy_pam_ok, gates.account_idle_ok,
            gates.sshd_effective_probe, gates.guard_frozen_ok,
            gates.dns_ipv6_ok,
        )
        safety = gates.safety
        if (not all(callable(v) for v in checks)
            or not isinstance(safety, IndependentSafety)
            or safety.db_conn is not self.db_conn
            or safety.target_edge_id != scope.edge_id
            or safety.source_ipv4 != scope.source_host
            or not callable(safety.packet_witness)
            or not callable(safety.neighbour_witness)):
            raise A3PlanHold("A3_SNAPSHOT_PHYSICAL_WITNESS_NOT_BOUND")

        args = dict(
            plan=reviewed.plan, scope=scope, ticket=ticket,
            db_conn=self.db_conn, os_uid=self.os_uid,
            release_enabled=True, geteuid=self.geteuid,
        )
        if reviewed.kind == "FIRST_UID":
            args.update(
                current_pam=pam, port=RootFilePort(),
                independent_rescue_ok=gates.independent_rescue_ok,
                independent_f4_ok=gates.independent_f4_ok,
                mixed_legacy_pam_ok=gates.mixed_legacy_pam_ok,
                account_idle_ok=gates.account_idle_ok,
                sshd_effective_probe=gates.sshd_effective_probe,
                guard_frozen_ok=gates.guard_frozen_ok,
                dns_ipv6_ok=gates.dns_ipv6_ok,
            )
        else:
            args.update(
                port=CASRootRosterPort(),
                rescue_ok=gates.independent_rescue_ok,
                idle_ok=gates.account_idle_ok,
                independent_f4_ok=gates.independent_f4_ok,
                legacy_pam_ok=gates.mixed_legacy_pam_ok,
                sshd_effective=gates.sshd_effective_probe,
                guard_verify=gates.guard_frozen_ok,
                dns_ipv6_verify=gates.dns_ipv6_ok,
                resume_partial=False,
            )
        return ReviewedUIDHostSnapshot(
            scope, member, GuardBootstrap(scope, ticket, reviewed.kind, args),
            req, manifest.dns_port, safety,
        )
