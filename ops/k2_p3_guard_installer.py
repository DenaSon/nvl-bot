"""K2 P3 package 1: explicit, root-only one-UID PAM/BootGuard installer.

Not a bot callback. No implicit release, SSH restart, global wg0 mutation,
iptables flush, automatic unguard or 6G unlock. This installs only reviewed
fixed artifacts, then arms and verifies the one-UID boot guard BEFORE a
compare-and-swap PAM edit. An interrupted install must be manually reconciled.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import tempfile
from typing import Callable

from edge_egress_uid_boot import BootGuardManifest
from edge_egress_uid_systemd import render_ssh_systemd_bundle
from edge_egress_v1_admission import (
    PAM_LINE, Member, GUARD_DIR, ROSTER, render_roster,
    load_roster, checked_guard,
)
from edge_egress_f4_pam import verify_installed_gate_digest
from edge_egress_f4_preflight import sshd_connection_spec
from edge_egress_v1_live_driver import assert_idle_process_snapshot


INSTALLER_ENABLED = False
PAM = Path("/etc/pam.d/sshd")
UNITS = Path("/etc/systemd/system")
MODULE = Path("/opt/nvl-egress/edge_egress_v1_admission.py")
CODE_DIR = Path("/opt/nvl-egress")
LOCK_PATH = Path("/run/lock/nvl-k2-p3-installer.lock")


class GuardInstallHold(ValueError):
    pass


@dataclass(frozen=True)
class GuardInstallPlan:
    username: str
    uid: int
    manifest_bytes: bytes
    manifest_sha256: str
    roster_bytes: bytes
    guard_unit: str
    dns_unit: str
    guard_unit_name: str
    dns_unit_name: str
    pam_before_sha256: str
    pam_after: bytes
    module_sha256: str

    @property
    def fingerprint(self):
        fields=(self.username,self.uid,self.manifest_sha256,
                sha256(self.roster_bytes).hexdigest(),
                sha256(self.guard_unit.encode()).hexdigest(),
                sha256(self.dns_unit.encode()).hexdigest(),
                self.pam_before_sha256,sha256(self.pam_after).hexdigest(),
                self.module_sha256)
        return sha256(json.dumps(fields,separators=(",",":")).encode()).hexdigest()


def _owned(path: Path, *, directory=False, strict=True) -> None:
    s=path.lstat()
    if (s.st_uid!=0 or (s.st_mode & (0o077 if strict else 0o022))
            or not (stat.S_ISDIR(s.st_mode) if directory
                    else stat.S_ISREG(s.st_mode))):
        raise GuardInstallHold("ROOT_OWNERSHIP_OR_MODE_INVALID")


def _safe_read(path: Path, *, maximum=262144, strict=True) -> bytes:
    _owned(path,strict=strict)
    data=path.read_bytes()
    if not 1 <= len(data) <= maximum:
        raise GuardInstallHold("INVALID_PINNED_FILE_SIZE")
    return data


def _pam_append_before_first_account(before: bytes) -> bytes:
    if len(before)>131072 or b"\x00" in before:
        raise GuardInstallHold("PAM_FILE_UNTRUSTED")
    try:
        lines=before.decode("utf-8").splitlines(keepends=True)
    except UnicodeError as exc:
        raise GuardInstallHold("PAM_ENCODING_UNSAFE") from exc
    active=[" ".join(x.split()) for x in lines
            if x.strip() and not x.lstrip().startswith("#")]
    if PAM_LINE in active or any("edge_egress_v1_admission.py" in x for x in active):
        raise GuardInstallHold("PAM_ALREADY_MODIFIED_OR_DUPLICATED")
    if any(x.startswith("account ") and "pam_exec.so" in x for x in active):
        raise GuardInstallHold("FOREIGN_PAM_ACCOUNT_EXEC_REVIEW_REQUIRED")
    # Insert ahead of ALL account rules and included account policies.
    idx=next((i for i,line in enumerate(lines)
              if (line.strip() and not line.lstrip().startswith("#")
                  and (line.lstrip().startswith("account ")
                       or line.lstrip().startswith(("@include ","-@include "))))),
             len(lines))
    lines.insert(idx,PAM_LINE+"\n")
    return "".join(lines).encode("utf-8")


def plan_guard_install(*, username: str, manifest_bytes: bytes,
                       pam_before: bytes, module_sha256: str,
                       existing_guard_bytes: dict[str, bytes],
                       os_uid: Callable[[str], int],
                       expected_pam_sha256: str) -> GuardInstallPlan:
    """Pure plan: existing roster is retained; do not replace other UIDs."""
    if (not isinstance(manifest_bytes,bytes) or len(manifest_bytes)>4096
            or not isinstance(pam_before,bytes)
            or not re.fullmatch(r"[0-9a-f]{64}",str(module_sha256))
            or not re.fullmatch(r"[0-9a-f]{64}",str(expected_pam_sha256))
            or sha256(pam_before).hexdigest()!=expected_pam_sha256):
        raise GuardInstallHold("REVIEWED_PINS_REQUIRED")
    try:
        man=BootGuardManifest.parse(json.loads(manifest_bytes))
        req=man.request
    except (ValueError,TypeError,KeyError,UnicodeError) as exc:
        raise GuardInstallHold("INVALID_PROTECTED_MANIFEST") from exc
    if (username!=req.username or not man.ingress_return
            or not man.shared_edge or man.dns_port is None
            or os_uid(username)!=req.uid or username in existing_guard_bytes):
        raise GuardInstallHold("UID_IDENTITY_OR_ALREADY_ENROLLED")
    maps=dict(existing_guard_bytes)
    maps[username]=manifest_bytes
    roster=render_roster(maps).encode("utf-8")
    bundle=render_ssh_systemd_bundle(man)
    after=_pam_append_before_first_account(pam_before)
    return GuardInstallPlan(username,req.uid,manifest_bytes,
        sha256(manifest_bytes).hexdigest(),roster,bundle.guard_unit,
        bundle.dns_unit,bundle.guard_name,bundle.dns_name,
        expected_pam_sha256,after,module_sha256)


class RootFilePort:
    """Fixed root-owned atomic creation; never replace another guard/UID."""

    def __init__(self, run: Callable=subprocess.run):
        self.run=run

    def create(self, path: Path, data: bytes) -> None:
        if path.parent not in (GUARD_DIR,ROSTER.parent,UNITS):
            raise GuardInstallHold("UNREVIEWED_WRITE_DIRECTORY")
        _owned(path.parent,directory=True,strict=False)
        if path.exists() or path.is_symlink():
            raise GuardInstallHold("EXISTING_ARTIFACT_REQUIRES_RECONCILIATION")
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|
                   getattr(os,"O_NOFOLLOW",0),0o600)
        try:
            with os.fdopen(fd,"wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
        except BaseException:
            raise
        dirfd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)

    def replace_exact(self,path:Path,expected:bytes,replacement:bytes) -> None:
        if path!=PAM:
            raise GuardInstallHold("NON_PAM_REPLACEMENT_FORBIDDEN")
        current=_safe_read(path,maximum=131072,strict=False)
        if current!=expected:
            raise GuardInstallHold("PAM_CAS_CHANGED")
        _owned(path.parent,directory=True,strict=False)
        tmp=None
        try:
            with tempfile.NamedTemporaryFile(prefix=".nvl-pam-",dir=path.parent,
                                             delete=False) as f:
                tmp=Path(f.name)
                os.fchmod(f.fileno(),0o600)
                f.write(replacement)
                f.flush()
                os.fsync(f.fileno())
            if _safe_read(path,maximum=131072,strict=False)!=expected:
                raise GuardInstallHold("PAM_CAS_LOST")
            os.replace(tmp,path)
            dirfd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
            try: os.fsync(dirfd)
            finally: os.close(dirfd)
        finally:
            if tmp is not None and tmp.exists(): tmp.unlink()

    def command(self,*cmd:str) -> None:
        p=self.run(list(cmd),capture_output=True,text=True,
                   timeout=30,check=False)
        if p.returncode:
            raise GuardInstallHold("PINNED_HOST_COMMAND_FAILED")


def apply_guard_install(*, plan: GuardInstallPlan,
                        current_pam: bytes, existing_guards: dict[str,bytes],
                        os_uid: Callable[[str],int], 
                        port: RootFilePort | None = None,
                        independent_console_ok: Callable[[],bool] | None = None,
                        account_idle_ok: Callable[[str,int],bool] | None = None,
                        reviewed_module_sha: str = "",
                        release_enabled: bool=False,
                        geteuid: Callable[[],int] = os.geteuid) -> None:
    """One-shot explicitly gated install, PAM edit LAST.

    Requires an external root-console witness and confirmed idle canary.
    The persisted roster is created BEFORE user guard is installed. If an
    intermediate step fails, never remove the roster or deny guard.
    """
    if (release_enabled is not True or not isinstance(plan,GuardInstallPlan)
            or geteuid()!=0 or port is None or independent_console_ok is None
            or account_idle_ok is None):
        raise GuardInstallHold("ROOT_OPERATOR_RELEASE_REQUIRED")
    if independent_console_ok() is not True:
        raise GuardInstallHold("INDEPENDENT_RESCUE_UNVERIFIED")
    if account_idle_ok(plan.username,plan.uid) is not True:
        raise GuardInstallHold("LIVE_UID_NOT_IDLE")
    if not re.fullmatch(r"[a-f0-9]{64}",reviewed_module_sha):
        raise GuardInstallHold("REVIEWED_CODE_DIGEST_REQUIRED")
    if (reviewed_module_sha != plan.module_sha256
            or not verify_installed_gate_digest(reviewed_module_sha)):
        raise GuardInstallHold("INSTALLED_PAM_MODULE_NOT_ATTESTED")
    if os_uid(plan.username)!=plan.uid:
        raise GuardInstallHold("OS_UID_CHANGED")
    man=BootGuardManifest.parse(json.loads(plan.manifest_bytes))
    if (man.request.username!=plan.username or man.request.uid!=plan.uid):
        raise GuardInstallHold("GUARD_IDENTITY_CHANGED")
    previous=_safe_read(PAM,maximum=131072,strict=False)
    if sha256(previous).hexdigest()!=plan.pam_before_sha256:
        raise GuardInstallHold("PAM_PREVIEW_CHANGED")
    if ROSTER.exists() or ROSTER.is_symlink():
        # Existing mixed-population roster must not be overwritten as a side
        # effect of another UID's installation.
        raise GuardInstallHold("ROSTER_UPDATE_NEEDS_SEPARATE_CAS_PLAN")
    if existing_guards:
        raise GuardInstallHold("MULTI_UID_INSTALLER_NOT_RELEASED")
    # Do not arm protected UID kernel until root-only directories & code
    # have been preinstalled and reviewed by an independent operator.
    for directory in (ROSTER.parent,GUARD_DIR,UNITS,CODE_DIR):
        _owned(directory,directory=True,strict=False)
    port.create(ROSTER,plan.roster_bytes)
    port.create(GUARD_DIR/(plan.username+".json"),plan.manifest_bytes)
    port.create(UNITS/plan.guard_unit_name,plan.guard_unit.encode())
    port.create(UNITS/plan.dns_unit_name,plan.dns_unit.encode())
    port.command("systemctl","daemon-reload")
    port.command("systemctl","enable","--now",plan.guard_unit_name)
    # The guard must be effective (deny first) BEFORE installing the PAM
    # account hook or starting the DNS helper. Never restart ssh.service.
    from edge_egress_uid_boot import BootGuardApplier
    BootGuardApplier().verify(man,require_frozen=True)
    port.command("systemctl","enable","--now",plan.dns_unit_name)
    # Important: a protected account in roster is blocked in Legacy mode
    # until the exact P3-C runtime is committed. No automatic un-fence.
    port.replace_exact(PAM,previous,plan.pam_after)
    if _safe_read(PAM,maximum=131072,strict=False)!=plan.pam_after:
        raise GuardInstallHold("PAM_POST_INSTALL_NOT_PINNED")
