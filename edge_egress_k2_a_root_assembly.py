"""A-package: explicitly reviewed assembly of the existing M4 root service.

This is NOT an installation, migration, or daemon auto-enable mechanism.
No environment variable, Telegram value or dynamic importer can supply a
privileged port. The operator must review every fixed callback first.
"""
from __future__ import annotations

from dataclasses import dataclass
import grp
import os
from pathlib import Path
import pwd
import re
import subprocess
from typing import Callable

from edge_egress_k2_m42_bindings import (
    HostReviewedPorts, RootM42Bindings, load_root_admin_policy,
    LegacyCurrentAdminRole,
)
from edge_egress_k2_m42_evidence import load_external_evidence
from edge_egress_k2_m2_ingress_journal import make_m1_readonly_ingress_provider
from edge_egress_k2_a_6g_shared import Original6GRootCallbacks
from edge_egress_k2_a_host_factory import ReviewedM2P3HostFactory
from edge_egress_k2_a3_host_plans import RootOwnedUIDSnapshotSource
from edge_egress_k2_m4_checkpoint import DurableWaveCheckpoint
from edge_egress_k2_m4_ipc import RootOperatorIPC
from edge_egress_k2_m4_root_worker import (
    RootWorkerService, WorkerPaths, verify_reviewed_release, load_root_secret,
)

M4A_ROOT_ASSEMBLY_ENABLED = False
BOT_UNIT = "nvlbot.service"
_UNIT_FIELDS = frozenset(("User", "MainPID", "ActiveState", "DynamicUser"))
_PROC_UID = re.compile(r"^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$",re.M)
_PROC_GID = re.compile(r"^Gid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$",re.M)
_PROC_GROUPS = re.compile(r"^Groups:\s*([0-9 ]+)\s*$",re.M)
_PROC_CAP = re.compile(r"^Cap(?:Inh|Prm|Eff|Amb):\s*([0-9a-fA-F]{1,16})\s*$",re.M)
_PROC_NO_NEW_PRIVS = re.compile(r"^NoNewPrivs:\s*1\s*$",re.M)


class M4AAssemblyHold(ValueError):
    pass


@dataclass(frozen=True)
class RootAssembly:
    worker: RootWorkerService
    release_sha: str
    bot_uid: int


def assert_nonroot_bot_identity(
    paths: WorkerPaths, *,
    run: Callable = subprocess.run,
    read_status: Callable[[int], str] | None = None,
    getpw: Callable = pwd.getpwnam,
    getgrouplist: Callable = os.getgrouplist,
) -> None:
    """Read-only fail-closed systemd+kernel evidence, not a UID switch.

    An unconfigured User= (root), DynamicUser or a process with effective
    root authority MUST hold. Exact group membership is needed for 0660 IPC.
    No systemctl restart, daemon reload, setuid or chmod is performed.
    """
    paths.validate()
    if read_status is None:
        def read_status(pid: int) -> str:
            return (Path("/proc") / str(pid) / "status").read_text(
                encoding="ascii", errors="strict"
            )[:8192]
    cmd=["systemctl","show",BOT_UNIT,"--no-pager",
         "-p","User","-p","MainPID","-p","ActiveState","-p","DynamicUser"]
    try:
        proc=run(cmd,capture_output=True,text=True,timeout=5,check=False)
        if proc.returncode != 0 or not isinstance(proc.stdout,str) or len(proc.stdout)>2048:
            raise ValueError("UNIT_UNAVAILABLE")
        values={}
        for line in proc.stdout.splitlines():
            key,separator,value=line.partition("=")
            if not separator or key in values or key not in _UNIT_FIELDS:
                raise ValueError("UNIT_FIELDS_UNTRUSTED")
            values[key]=value
        if set(values)!=_UNIT_FIELDS or values["ActiveState"]!="active":
            raise ValueError("UNIT_NOT_ACTIVE")
        if values["DynamicUser"]!="no" or not re.fullmatch(r"[1-9][0-9]{0,7}",values["MainPID"]):
            raise ValueError("UNIT_DYNAMIC_OR_PID_INVALID")
        username=values["User"]
        if username=="root" or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,30}",username):
            raise ValueError("ROOT_OR_UNVERIFIED_UNIT")
        account=getpw(username)
        if (type(account.pw_uid) is not int or account.pw_uid<=0
            or account.pw_uid!=paths.bot_uid
            or type(account.pw_gid) is not int or account.pw_gid<=0
            or paths.ipc_gid not in getgrouplist(username,account.pw_gid)):
            raise ValueError("NONROOT_GROUP_IDENTITY_MISMATCH")
        status=read_status(int(values["MainPID"]))
        match=_PROC_UID.search(status)
        if not match or any(int(value)!=paths.bot_uid for value in match.groups()):
            raise ValueError("RUNNING_BOT_PROCESS_UID_MISMATCH")
        gid=_PROC_GID.search(status)
        groups=_PROC_GROUPS.search(status)
        cap_lines=tuple(
            line for line in status.splitlines()
            if line.startswith(("CapInh:", "CapPrm:", "CapEff:", "CapAmb:"))
        )
        if (gid is None or any(int(value)!=account.pw_gid
                               for value in gid.groups())
            or groups is None
            or paths.ipc_gid not in {int(x) for x in groups.group(1).split()}
            or len(cap_lines)!=4
            or any(_PROC_CAP.fullmatch(line) is None
                   or int(_PROC_CAP.fullmatch(line).group(1),16)!=0
                   for line in cap_lines)
            or _PROC_NO_NEW_PRIVS.search(status) is None):
            raise ValueError("BOT_PROCESS_CAPABILITIES_OR_GROUPS_UNSAFE")
        # Inspect the unit again to detect a restart/PID switch during the
        # identity check. First and second snapshots must be byte identical.
        again=run(cmd,capture_output=True,text=True,timeout=5,check=False)
        if again.returncode!=0 or again.stdout!=proc.stdout:
            raise ValueError("BOT_PID_OR_UNIT_CHANGED")
    except (OSError,KeyError,ValueError,TypeError,AttributeError) as exc:
        raise M4AAssemblyHold("M4A_BOT_NONROOT_IDENTITY_NOT_ATTESTED") from exc


def assemble_reviewed_root(
    *, paths: WorkerPaths, ports: HostReviewedPorts,
    release_enabled: bool=False,
) -> RootAssembly:
    """Assemble *original* M1/M2/M3/P3/6G ports, never a replacement engine.

    Only an explicitly audited root service module may pass ports. Deliberate
    flags in every existing module are independently required; this function
    never modifies flags or starts a service or a socket by itself.
    """
    if (not M4A_ROOT_ASSEMBLY_ENABLED or release_enabled is not True
        or not isinstance(paths,WorkerPaths)
        or not isinstance(ports,HostReviewedPorts)
        or not callable(ports.geteuid) or ports.geteuid()!=0
        or not isinstance(getattr(ports.acquire_6g,"__self__",None),
                          Original6GRootCallbacks)
        or getattr(ports.acquire_6g,"__self__",None)
           is not getattr(ports.journal_6g,"__self__",None)
        or ports.acquire_6g.__self__.db_conn is not ports.db_conn
        or not isinstance(ports.port_factory,ReviewedM2P3HostFactory)
        or ports.port_factory.db_conn is not ports.db_conn
        or not isinstance(ports.port_factory.read_root_snapshot,
                          RootOwnedUIDSnapshotSource)
        or ports.port_factory.read_root_snapshot.db_conn is not ports.db_conn
        or ports.port_factory.read_root_snapshot.os_uid is not ports.os_uid
        or ports.port_factory.read_root_snapshot.geteuid is not ports.geteuid
        or ports.port_factory.os_uid is not ports.os_uid
        or ports.port_factory.geteuid is not ports.geteuid
        or type(ports.live_admin_role) is not LegacyCurrentAdminRole
        or ports.live_admin_role.db_conn is not ports.db_conn
        or ports.external_evidence is not load_external_evidence
        or ports.ingress_provider is not make_m1_readonly_ingress_provider):
        raise M4AAssemblyHold("M4A_ROOT_ASSEMBLY_NOT_AUTHORIZED")
    paths.validate()
    assert_nonroot_bot_identity(paths)
    sha=verify_reviewed_release(paths)
    secret=load_root_secret(paths)
    policy=load_root_admin_policy(geteuid=ports.geteuid)
    root=RootM42Bindings(
        ports=ports,root_secret=secret,admin_policy=policy,
        reviewed_release=True,
    )
    checkpoint=DurableWaveCheckpoint(
        db_conn=ports.db_conn,clock=ports.now,
        geteuid=ports.geteuid,release_enabled=True,
    )
    portal=root.portal(checkpoint=checkpoint)
    ipc=RootOperatorIPC(
        portal=portal,bot_uid=paths.bot_uid,
        geteuid=ports.geteuid,released=True,
    )
    service=RootWorkerService(
        paths=paths,transport=ipc,
        geteuid=ports.geteuid,release_enabled=True,
    )
    return RootAssembly(service,sha,paths.bot_uid)
