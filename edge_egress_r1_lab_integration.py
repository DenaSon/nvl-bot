"""Explicit R1 LAB dependency composition for the EXISTING F2/6G controller.

Never creates a SQLite database, journal, SSH/PAM hook or host resource.
Uses the actual 6G acquisition/update callbacks from the hosting bot.
All requested effects remain default-off, LAB-only and require independent
PAM/session evidence. A missing dependency is a hard refusal.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import pwd
import re
import sqlite3
import stat
import subprocess
from typing import Callable

from edge_egress_r1_lab_topology import TwoHostCoreIngress
from edge_egress_r1_lab_pam import PAM_ACCOUNT_LINE
from edge_egress_r1_lab_launcher import (
    LabHost, LabSSHExecutor, bind_disposable_lab_shadow,
)
from edge_egress_uid_boot import BootGuardApplier, BootGuardManifest
from edge_egress_uid_policy import UIDPolicyRequest
from edge_egress_uid_runtime import attach_protected, RuntimeOutcome
from edge_egress_uid_runtime_bridge import Existing6GUIDRuntimeBridge
from edge_egress_uid_runtime_kernel import LocalLinuxProtectedRuntimeKernel
from edge_egress_f3_readiness import read_readiness, admission_eligible


class LabCompositionUnsafe(ValueError):
    pass


@dataclass(frozen=True)
class ReviewedLabPAMGate:
    """Attest installed *bytes* and sshd account hook, not an E2E login.

    Rechecking the live PAM account rule at F2 admission prevents starting a
    protected route when PAM has not yet been installed. This evidence alone
    does not replace the real F4 external SSH forwarding test.
    """

    reviewed_sha256: str
    module: Path = Path("/opt/nvl-egress/edge_egress_r1_lab_pam.py")
    sshd_pam: Path = Path("/etc/pam.d/sshd")

    def __call__(self, req: UIDPolicyRequest) -> bool:
        try:
            req.validate()
            if os.geteuid() != 0 or (req.username, req.uid) != ("nvlr1test", 1555):
                return False
            if not re.fullmatch(r"[0-9a-f]{64}", self.reviewed_sha256):
                return False
            if self.module != Path("/opt/nvl-egress/edge_egress_r1_lab_pam.py"):
                return False
            if self.sshd_pam != Path("/etc/pam.d/sshd"):
                return False
            for p in (self.module, self.sshd_pam):
                if p.is_symlink() or not p.is_file():
                    return False
                st = p.stat()
                if st.st_uid != 0 or st.st_mode & 0o022:
                    return False
            if hashlib.sha256(self.module.read_bytes()).hexdigest() != self.reviewed_sha256:
                return False
            lines = [
                " ".join(line.split())
                for line in self.sshd_pam.read_text().splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ]
            rules = [line for line in lines if line.startswith("account ")]
            if not rules or rules[0] != PAM_ACCOUNT_LINE or rules.count(PAM_ACCOUNT_LINE) != 1:
                return False
            first = lines.index(PAM_ACCOUNT_LINE)
            if any("common-account" in line or "pam_permit.so" in line
                   for line in lines[:first]):
                return False
            result = subprocess.run([
                "/usr/sbin/sshd", "-T", "-C",
                "user=nvlr1test,host=107.189.16.36,addr=107.189.16.36",
            ], capture_output=True, text=True, timeout=6, check=True)
            return "usepam yes" in result.stdout.lower().splitlines()
        except (ValueError, TypeError, OSError, subprocess.SubprocessError):
            return False


@dataclass(frozen=True)
class LabUIDGuardProbe:
    """Read-only attestation of the already-installed persistent UID guard."""

    def __call__(self, req: UIDPolicyRequest) -> bool:
        try:
            if os.geteuid() != 0 or (req.username, req.uid) != ("nvlr1test", 1555):
                return False
            BootGuardApplier().verify(BootGuardManifest(
                req, "PROTECTED_BOOT_GUARD",
            ))
            result = subprocess.run(
                ["systemctl", "is-enabled", "--quiet",
                 "nvl-egress-lab1-guard.service"],
                timeout=6, capture_output=True,
            )
            return result.returncode == 0
        except (ValueError, OSError, subprocess.SubprocessError):
            return False


@dataclass
class Existing6GLabPilot:
    """Single orchestration entry point. Not an alternate 6G lock or DB."""

    db_conn: Callable
    acquire_fn: Callable
    update_fn: Callable
    session_gate: ReviewedLabPAMGate
    idle_probe: Callable[[UIDPolicyRequest], bool]
    kernel: LocalLinuxProtectedRuntimeKernel
    ssh: LabSSHExecutor
    edge: LabHost
    core: LabHost
    topology: TwoHostCoreIngress
    guard: LabUIDGuardProbe
    enabled: bool = False
    disposable_vps: bool = False

    def build(self, req: UIDPolicyRequest) -> Existing6GUIDRuntimeBridge:
        req.validate()
        if self.enabled is not True or self.disposable_vps is not True:
            raise LabCompositionUnsafe("LAB_RUNTIME_DEFAULT_OFF")
        if (type(self.topology) is not TwoHostCoreIngress or
                self.topology.for_request(req, req.spec.core_public_ipv4) is not True):
            raise LabCompositionUnsafe("LAB_CORE_INGRESS_NOT_ATTESTED")
        if (type(self.session_gate) is not ReviewedLabPAMGate
                or self.session_gate(req) is not True):
            raise LabCompositionUnsafe("PAM_ACCOUNT_GATE_NOT_ATTESTED")
        if type(self.guard) is not LabUIDGuardProbe or self.guard(req) is not True:
            raise LabCompositionUnsafe("PERSISTENT_UID_GUARD_NOT_ATTESTED")
        if (type(self.kernel) is not LocalLinuxProtectedRuntimeKernel
                or self.kernel.enabled is not True):
            raise LabCompositionUnsafe("UID_KERNEL_NOT_OPTED_IN")
        if type(self.ssh) is not LabSSHExecutor:
            raise LabCompositionUnsafe("PINNED_LAB_SSH_REQUIRED")
        if not all(callable(fn) for fn in (
            self.db_conn, self.acquire_fn, self.update_fn, self.idle_probe,
        )):
            raise LabCompositionUnsafe("REAL_6G_AND_SESSION_PORTS_REQUIRED")

        # A real LAB control plane must exist before ANY lease or route work.
        try:
            with self.db_conn() as conn:
                tables = {row[0] for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )}
                required = {
                    "failover_operations", "ssh_accounts", "host_pool",
                    "settings", "edge_egress_allocations",
                    "edge_egress_readiness", "edge_egress_uid_runtime",
                    "edge_egress_uid_bindings",
                }
                if not required <= tables:
                    raise LabCompositionUnsafe("REAL_F2_6G_LAB_SCHEMA_MISSING")
                readiness = read_readiness(conn, req.spec.edge_id)
                if not admission_eligible(readiness):
                    raise LabCompositionUnsafe("INDEPENDENT_F4_READY_REQUIRED")
        except (sqlite3.Error, OSError, TypeError, AttributeError) as exc:
            raise LabCompositionUnsafe("REAL_F2_6G_LAB_DB_UNAVAILABLE") from exc

        self.core.validate(req.spec)
        self.edge.validate(req.spec)
        bridge = Existing6GUIDRuntimeBridge(
            db_conn=self.db_conn,
            acquire_fn=self.acquire_fn,
            update_fn=self.update_fn,
            os_uid_for_username=lambda name: pwd.getpwnam(name).pw_uid,
            kernel=self.kernel,
            session_gate_probe=self.session_gate,
            existing_sessions_probe=self.idle_probe,
        )
        bind_disposable_lab_shadow(
            bridge, spec=req.spec, guard_check=self.guard,
            core=self.core, edge=self.edge, ssh=self.ssh,
            explicitly_enabled=True, disposable_vps=True,
            lab_core_ingress_attestor=self.topology,
            accept_verified_running_transport=True,
        )
        return bridge

    async def attach(self, req: UIDPolicyRequest, *, dns_port: int) -> RuntimeOutcome:
        bridge = self.build(req)
        return await attach_protected(
            bridge, req, source=req.spec.core_public_ipv4,
            dns_port=dns_port, authorized=True,
            lab_core_ingress_attestor=self.topology,
        )
