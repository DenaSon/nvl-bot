"""K2 P3 package 2: concrete, one-UID Linux worker on ORIGINAL 6G.

No bot registration and no implicit ticket. Reuses P3-A journal, P3-C deny
first, F2 store and LocalLinuxProtectedRuntimeKernel. Real root/packet
acceptance must be provided independently; absent proof => no mutation.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import pwd
import sqlite3
import subprocess
import time
from typing import Callable

from edge_egress_f4_pam import verify_installed_gate_digest
from edge_egress_f4_preflight import sshd_connection_spec
from edge_egress_f3_readiness import admission_eligible, read_readiness
from edge_egress_p3_executor import (
    ExecutionScope, ExecutionTicket, FreshEvidence,
    Existing6GGuardedExecutor, issue_execution_ticket,
)
from edge_egress_p3_uid import GuardedProtectedUIDPort
from edge_egress_k2_source_enrollment import (
    plan_source_enrollment, SameEdge6GUIDRuntimeStore,
    GuardedSourceEnrollmentPort,
)
from edge_egress_uid_boot import BootGuardApplier
from edge_egress_uid_runtime_kernel import LocalLinuxProtectedRuntimeKernel
from edge_egress_v1_admission import (
    GUARD_DIR, ROSTER, PAM_LINE, load_roster, checked_guard,
    inspect_pam,
)
from edge_egress_v1_live_driver import assert_idle_process_snapshot
from edge_egress_v1_ingress import probe_ingress


WORKER_ENABLED = False


class LiveUIDHold(ValueError):
    pass


def _checked(*args:str,timeout=12)->str:
    try:
        p=subprocess.run(list(args),capture_output=True,text=True,
                         timeout=timeout,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise LiveUIDHold("LIVE_HOST_COMMAND_UNAVAILABLE") from exc
    if p.returncode!=0:
        raise LiveUIDHold("LIVE_HOST_PROBE_FAILED")
    return p.stdout


def _uid(username:str)->int:
    return pwd.getpwnam(username).pw_uid


@dataclass
class IndependentSafety:
    """Concrete host checks and REQUIRED independent packet & neighbour probes.

    packet_witness is deliberately NOT given a default. It must be an
    independently executed, scope-bound F4 observer, not the local curl/IP
    check; a boolean in JSON is insufficient to certify it.
    """
    db_conn: Callable
    target_edge_id: str
    source_ipv4: str
    ingress_rhost: str
    ssh_local_addr: str
    ssh_local_port: int
    reviewed_module_sha256: str
    packet_witness: Callable | None = None
    neighbour_witness: Callable | None = None
    now: Callable = lambda: int(time.time())

    def _manifest(self,req):
        members=load_roster()
        if req.username not in members or members[req.username].uid!=req.uid:
            raise LiveUIDHold("ROOT_ROSTER_UID_NOT_PINNED")
        man=checked_guard(members[req.username])
        if man.request!=req or man.mode!="PROTECTED_BOOT_GUARD":
            raise LiveUIDHold("GUARD_MANIFEST_NOT_PINNED")
        return man

    def assert_account_idle(self,req):
        if _uid(req.username)!=req.uid:
            raise LiveUIDHold("LINUX_UID_CHANGED")
        # sshd children and all unrelated user processes must be drained.
        snapshot=_checked("ps","-eo","pid,uid,comm,args","--no-headers")
        service="nvl-egress-dns-"+req.username+".service"
        main_pid=_checked("systemctl","show",service,
                          "-p","MainPID","--value").strip()
        if not main_pid.isdecimal() or int(main_pid)<=1:
            raise LiveUIDHold("PINNED_DNS_SERVICE_PID_UNAVAILABLE")
        try:
            # Only the exact root-recorded DoH MainPID is exempt; all SSH
            # sessions and any second process of the UID still block.
            assert_idle_process_snapshot(snapshot,req.username,req.uid,
                                         allowed_dns_pid=int(main_pid))
        except ValueError as exc:
            raise LiveUIDHold("ACTIVE_SESSIONS_OR_PROCESSES") from exc

    def assert_pam_ingress_boot(self,req):
        if (not isinstance(self.ingress_rhost,str)
                or not self.ingress_rhost.startswith("10.77.0.")
                or req.spec.edge_id!=self.target_edge_id
                or req.spec.edge_public_ipv4!=self.source_ipv4
                or not verify_installed_gate_digest(self.reviewed_module_sha256)):
            raise LiveUIDHold("LIVE_PAM_MODULE_OR_EDGE_IDENTITY_UNVERIFIED")
        manifest=self._manifest(req)
        actual_pam=Path("/etc/pam.d/sshd").read_text(encoding="utf-8")
        sshd=sshd_connection_spec(
            username=req.username,local_addr=self.ssh_local_addr,
            remote_addr=self.ingress_rhost,local_port=self.ssh_local_port,
        )
        effective=_checked("sshd","-T","-C",sshd)
        if not inspect_pam(actual_pam,effective):
            raise LiveUIDHold("LIVE_PAM_CONTEXT_UNVERIFIED")
        # For new enrollment, no F2 runtime row exists yet; verify the
        # actual WireGuard roster identity using the pinned stage + wg0.
        from edge_egress_v1_ingress import load_registry
        peers=load_registry()
        matched=[p for p in peers if p.edge_id==req.spec.edge_id
                 and p.edge_ipv4==req.spec.edge_public_ipv4
                 and p.ingress_ipv4==self.ingress_rhost]
        if len(matched)!=1:
            raise LiveUIDHold("INGRESS_WG0_PEER_NOT_PINNED")
        live=_checked("wg","show","wg0","allowed-ips")
        if (matched[0].wg_public_key not in live
                or self.ingress_rhost+"/32" not in live):
            raise LiveUIDHold("LIVE_WG0_PEER_NOT_ATTESTED")
        with self.db_conn() as db:
            r=read_readiness(db,req.spec.edge_id)
            if (r is None or r.edge_ipv4!=req.spec.edge_public_ipv4
                    or not admission_eligible(r,now=self.now())):
                raise LiveUIDHold("SOURCE_F4_NOT_ACCEPTED")
        BootGuardApplier().verify(manifest,require_frozen=True)

    def assert_multi_uid_isolation(self,req):
        if self.neighbour_witness is None:
            raise LiveUIDHold("INDEPENDENT_NEIGHBOUR_PROOF_REQUIRED")
        if self.neighbour_witness(req) is not True:
            raise LiveUIDHold("OTHER_UID_ROUTING_NOT_ISOLATED")
        with self.db_conn() as db:
            for t in ("edge_egress_uid_runtime","edge_egress_uid_bindings"):
                if db.execute(
                    f"SELECT 1 FROM {t} WHERE uid=? AND username<>? LIMIT 1",
                    (req.uid,req.username),
                ).fetchone():
                    raise LiveUIDHold("NUMERIC_UID_OWNERSHIP_COLLISION")

    def assert_packet_dns_ipv6_no_core_leak(self,req):
        if self.packet_witness is None:
            raise LiveUIDHold("INDEPENDENT_PACKET_WITNESS_REQUIRED")
        # Local Kernel.public_ipv4() and guard presence DO NOT replace an
        # independent packet capture on Core and client-side SOCKS/NSS tests.
        if self.packet_witness(req) is not True:
            raise LiveUIDHold("EXTERNAL_PACKET_DNS_IPV6_EVIDENCE_FAILED")


@dataclass(frozen=True)
class PreparedLiveUIDWorker:
    scope: ExecutionScope
    ticket: ExecutionTicket
    executor: Existing6GGuardedExecutor
    actor_id: int
    chat_id: int

    async def execute(self):
        return await self.executor.execute(
            self.scope,self.ticket,actor_id=self.actor_id,
            chat_id=self.chat_id,
        )


def prepare_live_source_uid_worker(
    *, db_conn:Callable, acquire_6g:Callable, journal_6g:Callable,
    candidate_target_edge_id:str, request, dns_port:int,
    safety:IndependentSafety, evidence:FreshEvidence,
    actor_id:int, chat_id:int,
    reviewed_release:bool=False,
    kernel_factory:Callable=LocalLinuxProtectedRuntimeKernel,
    os_uid:Callable=_uid, geteuid:Callable=os.geteuid,
    clock:Callable=lambda:int(time.time()),
) -> PreparedLiveUIDWorker:
    """One-shot factory. Does NOT run root commands until execute().

    Explicitly rejects absent external F4/no-leak or neighbour observers.
    No fallback to simulated "pass" and no alternative 6G lock.
    """
    if (reviewed_release is not True or geteuid()!=0
            or not isinstance(safety,IndependentSafety)
            or safety.db_conn is not db_conn
            or safety.packet_witness is None
            or safety.neighbour_witness is None
            or not isinstance(evidence,FreshEvidence)
            or not callable(acquire_6g) or not callable(journal_6g)):
        raise LiveUIDHold("EXPLICIT_ROOT_RELEASE_AND_EXTERNAL_PROOF_REQUIRED")
    if (safety.target_edge_id!=request.spec.edge_id
            or safety.source_ipv4!=request.spec.edge_public_ipv4
            or candidate_target_edge_id==request.spec.edge_id):
        raise LiveUIDHold("SAFETY_SCOPE_NOT_PINNED")
    if not callable(kernel_factory):
        raise LiveUIDHold("REAL_LINUX_KERNEL_FACTORY_REQUIRED")
    plan=plan_source_enrollment(
        db_conn,candidate_target_edge_id,request,dns_port=dns_port,
        roster_loader=load_roster,guard_loader=checked_guard,
        os_uid_for_username=os_uid,
    )
    ticket=issue_execution_ticket(plan.scope,evidence,
                                  actor_id=actor_id,chat_id=chat_id,
                                  now=clock())
    store=SameEdge6GUIDRuntimeStore(
        db_conn,os_uid,scope=plan.scope,ticket=ticket,
        shared_edge_enabled=True,
    )
    kernel=kernel_factory(explicitly_enabled=True)
    if not isinstance(kernel,LocalLinuxProtectedRuntimeKernel):
        raise LiveUIDHold("KERNEL_MUST_BE_REAL_LINUX_PORT")
    uid_port=GuardedProtectedUIDPort(
        db_conn=db_conn,plan=plan.uid_plan,ticket=ticket,store=store,
        kernel=kernel,safety=safety,
        roster_loader=load_roster,guard_loader=checked_guard,
        os_uid_for_username=os_uid,release_enabled=True,
    )
    host=GuardedSourceEnrollmentPort(
        db_conn=db_conn,plan=plan,ticket=ticket,uid_port=uid_port,
        os_uid_for_username=os_uid,release_enabled=True,
    )
    # P3-A reads the same immutable external evidence at each lease boundary.
    # A separate F4 observer must revoke it if packet/boot evidence expires.
    executor=Existing6GGuardedExecutor(
        db_conn=db_conn,acquire_fn=acquire_6g,journal_fn=journal_6g,
        review_fn=lambda scope:evidence if scope==plan.scope else None,
        host_port=host,release_enabled=True,geteuid=geteuid,clock=clock,
    )
    return PreparedLiveUIDWorker(plan.scope,ticket,executor,actor_id,chat_id)
