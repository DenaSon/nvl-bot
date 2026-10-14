"""Package A: reviewed SAME-INGRESS M2 -> real P3 UID host composition.

No Telegram-controlled factory, plugin importer, command, alternate kernel or
additional 6G ledger. Source-only and default OFF. An actual authorized
installation must supply a vetted *read-only* snapshot of existing root files.
Every M2 mutation is deferred until original P3/6G intent is durable.
Cross-edge legacy transitions are deliberately not accepted here.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Callable

from edge_egress_k2_m4_bootstrap import (
    GuardBootstrap, DeferredOriginal6GHostPort,
)
from edge_egress_k2_m3_ingress_port import (
    GuardedVerifiedIngressUIDPort, VerifiedIngressContract,
)
from edge_egress_k2_m3_waves import MigrationMember, build_wave_plan
from edge_egress_k2_migration_inventory import select_migration
from edge_egress_k2_source_enrollment import SameEdge6GUIDRuntimeStore
from edge_egress_p3_executor import ExecutionScope, ExecutionTicket, _scope_digest
from edge_egress_p3_uid import NEW, GuardedProtectedUIDPort, review_protected_uid
from edge_egress_uid_policy import UIDPolicyRequest
from edge_egress_uid_runtime_kernel import LocalLinuxProtectedRuntimeKernel
from edge_egress_v1_admission import load_roster, checked_guard
from ops.k2_p3_uid_worker import IndependentSafety
from ops.k2_p3_guard_installer import GuardInstallPlan, RootFilePort
from ops.k2_m2_guard_append import MultiUIDAppendPlan, CASRootRosterPort

M4A_REAL_HOST_FACTORY_ENABLED = False


class M4AHostHold(ValueError):
    pass


@dataclass(frozen=True)
class ReviewedUIDHostSnapshot:
    """Read-only root-derived host plan; never a Telegram-supplied object."""
    scope: ExecutionScope
    member: MigrationMember
    bootstrap: GuardBootstrap
    request: UIDPolicyRequest
    dns_port: int
    safety: IndependentSafety


class ReviewedM2P3HostFactory:
    """An explicit typed host factory to bind into HostReviewedPorts.

    read_root_snapshot must be a reviewed root-only reader. It may construct
    *plans* but MUST NOT apply M2, kernel, SSH or PAM writes: those occur
    exclusively inside DeferredOriginal6GHostPort.apply with 6G intent.
    """

    def __init__(
        self, *, db_conn: Callable,
        read_root_snapshot: Callable[[ExecutionScope, ExecutionTicket],
                                     ReviewedUIDHostSnapshot],
        os_uid: Callable[[str], int],
        geteuid: Callable[[], int] = os.geteuid,
        release_enabled: bool = False,
    ):
        if not all(callable(f) for f in (
            db_conn, read_root_snapshot, os_uid, geteuid,
        )):
            raise M4AHostHold("M4A_ROOT_HOST_FACTORY_INVALID")
        self.db_conn = db_conn
        self.read_root_snapshot = read_root_snapshot
        self.os_uid = os_uid
        self.geteuid = geteuid
        self.release_enabled = release_enabled

    def __call__(self, scope: ExecutionScope, ticket: ExecutionTicket,
                 review: Callable) -> DeferredOriginal6GHostPort:
        if (not M4A_REAL_HOST_FACTORY_ENABLED
            or self.release_enabled is not True or self.geteuid() != 0
            or not isinstance(scope, ExecutionScope)
            or scope.action != "UID_ENROLL_SOURCE"
            or scope.source_host != scope.target_host
            or not isinstance(ticket, ExecutionTicket)
            or ticket.scope_digest != _scope_digest(scope)
            or not callable(review)):
            raise M4AHostHold("M4A_SAME_EDGE_ROOT_RELEASE_REQUIRED")

        # Root source and F4/session evidence are recomputed here. No
        # historical ssh_accounts.host fallback or Telegram-provided facts.
        selection = select_migration("SINGLE", (scope.username,), scope.edge_id)
        inventory = review(selection)
        wave = build_wave_plan(inventory, wave_size=1)
        member = wave.members[0] if len(wave.members) == 1 else None
        if (wave.global_blockers
            or member is None or not member.selectable
            or member.source_edge_id != scope.edge_id
            or member.source_ipv4 != scope.source_host
            or member.target_edge_id != scope.edge_id
            or member.target_ipv4 != scope.target_host
            or member.uid != scope.uid):
            raise M4AHostHold("M4A_FRESH_SOURCE_OR_F4_UNTRUSTED")
        spec = self.read_root_snapshot(scope, ticket)
        if not isinstance(spec, ReviewedUIDHostSnapshot):
            raise M4AHostHold("M4A_ROOT_HOST_SNAPSHOT_MISSING")
        bootstrap = spec.bootstrap
        if (spec.scope != scope or spec.member != member
            or not isinstance(bootstrap, GuardBootstrap)
            or bootstrap.scope != scope or bootstrap.ticket != ticket
            or bootstrap.kwargs.get("db_conn") is not self.db_conn
            or bootstrap.kwargs.get("scope") != scope
            or bootstrap.kwargs.get("ticket") != ticket
            or bootstrap.kwargs.get("release_enabled") is not True
            or bootstrap.kwargs.get("resume_partial", False) is not False
            or (bootstrap.kind == "FIRST_UID"
                and not isinstance(bootstrap.kwargs.get("plan"),GuardInstallPlan))
            or (bootstrap.kind == "NEXT_UID"
                and not isinstance(bootstrap.kwargs.get("plan"),MultiUIDAppendPlan))
            or bootstrap.kind not in ("FIRST_UID","NEXT_UID")
            or not isinstance(spec.request, UIDPolicyRequest)
            or spec.request.username != scope.username
            or spec.request.uid != scope.uid
            or spec.request.spec.edge_id != scope.edge_id
            or spec.request.spec.edge_public_ipv4 != scope.target_host
            or type(spec.dns_port) is not int
            or not 1024 <= spec.dns_port <= 65535
            or not isinstance(spec.safety, IndependentSafety)
            or spec.safety.db_conn is not self.db_conn
            or spec.safety.packet_witness is None
            or spec.safety.neighbour_witness is None
            or spec.safety.target_edge_id != scope.edge_id
            or spec.safety.source_ipv4 != scope.source_host):
            raise M4AHostHold("M4A_BOOTSTRAP_OR_PHYSICAL_PORT_UNVERIFIED")
        if (bootstrap.kind == "FIRST_UID"
            and not isinstance(bootstrap.kwargs.get("port"),RootFilePort)):
            raise M4AHostHold("M4A_FIRST_UID_REAL_FILE_PORT_REQUIRED")
        if (bootstrap.kind == "NEXT_UID"
            and not isinstance(bootstrap.kwargs.get("port"),CASRootRosterPort)):
            raise M4AHostHold("M4A_NEXT_UID_CAS_FILE_PORT_REQUIRED")
        # No UID kernel construction or M2 mutation occurs at PREPARE or
        # during root factory assembly. The original 6G lock gates apply().
        def after_bootstrap(live_scope: ExecutionScope,
                            live_ticket: ExecutionTicket):
            if live_scope != scope or live_ticket != ticket:
                raise M4AHostHold("M4A_POST_BOOTSTRAP_SCOPE_CHANGED")
            plan = review_protected_uid(
                self.db_conn, scope, spec.request,
                dns_port=spec.dns_port, purpose=NEW,
                roster_loader=load_roster, guard_loader=checked_guard,
                os_uid_for_username=self.os_uid,
            )
            store = SameEdge6GUIDRuntimeStore(
                self.db_conn, self.os_uid, scope=scope, ticket=ticket,
                shared_edge_enabled=True,
            )
            kernel = LocalLinuxProtectedRuntimeKernel(explicitly_enabled=True)
            uid_port = GuardedProtectedUIDPort(
                db_conn=self.db_conn, plan=plan, ticket=ticket,
                store=store, kernel=kernel, safety=spec.safety,
                roster_loader=load_roster, guard_loader=checked_guard,
                os_uid_for_username=self.os_uid, release_enabled=True,
            )
            return GuardedVerifiedIngressUIDPort(
                contract=VerifiedIngressContract(member,scope),
                ticket=ticket,uid_port=uid_port,db_conn=self.db_conn,
                live_inventory=review,release_enabled=True,
            )

        return DeferredOriginal6GHostPort(
            scope=scope, ticket=ticket, db_conn=self.db_conn,
            bootstrap=bootstrap,port_factory=after_bootstrap,
        )
