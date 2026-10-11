"""D1-C3B: explicitly opted-in LOCAL Linux UID canary kernel port.

This is a disposable canary executor, NOT a durable protected-mode service.
There is NO bot import, CLI, systemd unit, boot restoration, or default
activation. Must be injected into the shared-6G-locked canary coordinator
by an operator-reviewed application. The existing wg0 is never targeted.

A root-only recovery marker is persisted *before* applying any commands.
Losing the Python process requires operator reconciliation, not a blind retry.
No shell=True or generic remote command execution is available.
"""
from __future__ import annotations

import asyncio
from dataclasses import asdict
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
from typing import Optional

from edge_egress_uid_lifecycle import UIDCanaryUnsafe
from edge_egress_uid_policy import UIDPolicyRequest, build_policy_plan


class CanaryKernelUnsafe(UIDCanaryUnsafe):
    pass


def _run(*argv: str, timeout: int = 12, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(
        list(argv), capture_output=True, text=True, timeout=timeout,
        check=False,
    )
    if check and result.returncode:
        # Never include arguments/output in a journal; could carry secrets.
        raise CanaryKernelUnsafe("HOST_COMMAND_FAILED")
    return result


class LocalLinuxUIDCanaryKernel:
    """Local Core-only adapter. Creation alone never modifies Linux state."""

    def __init__(self, *, explicitly_enabled: bool = False,
                 state_dir: str = "/root/nvl-egress-uid-canary"):
        self.enabled = explicitly_enabled is True
        self.state_dir = Path(state_dir)
        self._request: Optional[UIDPolicyRequest] = None

    def _binding(self, request: UIDPolicyRequest):
        request.validate()
        if not self.enabled:
            raise CanaryKernelUnsafe("KERNEL_CANARY_DISABLED")
        if os.geteuid() != 0:
            raise CanaryKernelUnsafe("ROOT_REQUIRED")
        try:
            uid = pwd.getpwnam(request.username).pw_uid
        except KeyError as exc:
            raise CanaryKernelUnsafe("USER_NOT_FOUND") from exc
        if uid != request.uid:
            raise CanaryKernelUnsafe("UID_IDENTITY_MISMATCH")
        if self._request is not None and self._request != request:
            raise CanaryKernelUnsafe("REQUEST_IDENTITY_CHANGED")
        self._request = request
        return build_policy_plan(request)

    def _state_path(self, request: UIDPolicyRequest) -> Path:
        return self.state_dir / (request.username + "-" + request.spec.edge_id + ".json")

    def _read_state(self, request: UIDPolicyRequest) -> dict:
        p = self._state_path(request)
        if p.is_symlink() or not p.is_file():
            raise CanaryKernelUnsafe("CANARY_STATE_ABSENT_OR_SYMLINK")
        s = p.stat()
        if s.st_uid != 0 or s.st_mode & 0o077:
            raise CanaryKernelUnsafe("UNSAFE_CANARY_STATE")
        data = json.loads(p.read_text(encoding="utf-8"))
        if data.get("request") != {
            "username": request.username, "uid": request.uid,
            "priority": request.priority,
            "spec": asdict(request.spec),
        }:
            raise CanaryKernelUnsafe("CANARY_STATE_IDENTITY_MISMATCH")
        return data

    def _record(self, request: UIDPolicyRequest):
        if self.state_dir.is_symlink():
            raise CanaryKernelUnsafe("UNSAFE_STATE_DIR_SYMLINK")
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        st = self.state_dir.stat()
        if st.st_uid != 0 or st.st_mode & 0o077:
            raise CanaryKernelUnsafe("UNSAFE_STATE_DIR")
        p = self._state_path(request)
        fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({
                    "phase": "ARMING_RECOVERY_REQUIRED",
                    "request": {
                        "username": request.username, "uid": request.uid,
                        "priority": request.priority,
                        "spec": asdict(request.spec),
                    }
                }, f)
                f.flush()
                os.fsync(f.fileno())
            dirfd = os.open(str(self.state_dir), os.O_RDONLY)
            try:
                os.fsync(dirfd)
            finally:
                os.close(dirfd)
        except Exception:
            # Preserve any uncertain marker for operator reconciliation.
            raise

    def _preflight(self, request: UIDPolicyRequest):
        plan = self._binding(request)
        if self._state_path(request).exists() or self._state_path(request).is_symlink():
            raise CanaryKernelUnsafe("EXISTING_RECOVERY_MARKER")
        rules = _run("ip", "-4", "rule", "show").stdout
        if re.search(r"(?m)^\s*" + re.escape(str(plan.priority)) + r":", rules):
            raise CanaryKernelUnsafe("PRIORITY_OCCUPIED")
        if re.search(r"(?i)uidrange\s*" + str(request.uid) + r"(?=\s|-)", rules):
            raise CanaryKernelUnsafe("UID_RULE_ALREADY_EXISTS")
        routes = _run("ip", "-4", "route", "show", "table",
                      str(plan.table), check=False)
        if routes.stdout.strip():
            raise CanaryKernelUnsafe("ROUTE_TABLE_OCCUPIED")
        if _run("ip", "link", "show", "dev", request.spec.veth_root,
                check=False).returncode == 0:
            raise CanaryKernelUnsafe("VETH_ALREADY_PRESENT")
        for command in plan.guard[:3]:
            # Existing equivalent rule means we cannot claim or later remove it.
            args = list(command.argv)
            args[2:5] = ["-C", "OUTPUT"]  # -I OUTPUT 1 -> -C OUTPUT
            if _run(*args, check=False).returncode == 0:
                raise CanaryKernelUnsafe("UID_GUARD_ALREADY_EXISTS")

    async def preflight(self, request: UIDPolicyRequest):
        await asyncio.to_thread(self._preflight, request)

    def _arm(self, request: UIDPolicyRequest):
        self._preflight(request)
        plan = self._binding(request)
        self._record(request)
        for command in plan.guard:
            _run(*command.argv)
        self._check_guards(request)

    async def arm_guard(self, request: UIDPolicyRequest):
        await asyncio.to_thread(self._arm, request)

    def _check_guards(self, request: UIDPolicyRequest):
        plan = self._binding(request)
        self._read_state(request)
        for command in plan.verify[3:]:
            _run(*command.argv)
        rules = _run("ip", "-4", "rule", "show").stdout
        expected = str(plan.priority) + ":"
        if not any(line.strip().startswith(expected) and
                   ("uidrange " + str(request.uid) + "-" + str(request.uid)) in line and
                   ("lookup " + str(plan.table)) in line
                   for line in rules.splitlines()):
            raise CanaryKernelUnsafe("UID_GUARD_RULE_NOT_PRESENT")
        table = _run("ip", "-4", "route", "show", "table", str(plan.table)).stdout
        if not re.search(r"(?m)^blackhole default\b", table):
            raise CanaryKernelUnsafe("TERMINAL_BLACKHOLE_MISSING")

    def _attach(self, request: UIDPolicyRequest):
        plan = self._binding(request)
        self._check_guards(request)
        if _run("ip", "link", "show", "dev", request.spec.veth_root,
                check=False).returncode != 0:
            raise CanaryKernelUnsafe("SHADOW_VETH_NOT_PRESENT")
        for command in plan.attach:
            _run(*command.argv)

    async def attach_edge(self, request: UIDPolicyRequest):
        await asyncio.to_thread(self._attach, request)

    def _public_ip(self, request: UIDPolicyRequest) -> str:
        self._check_guards(request)
        response = _run(
            "runuser", "-u", request.username, "--",
            "curl", "-4", "-fsS", "--noproxy", "*",
            "--resolve", "one.one.one.one:443:1.1.1.1",
            "--connect-timeout", "5", "--max-time", "15",
            "https://one.one.one.one/cdn-cgi/trace",
            timeout=20,
        )
        match = re.search(r"(?m)^ip=(\d{1,3}(?:\.\d{1,3}){3})\s*$",
                          response.stdout)
        return match.group(1) if match else ""

    async def public_ip(self, request: UIDPolicyRequest) -> str:
        return await asyncio.to_thread(self._public_ip, request)

    async def check_ipv6_dns(self, request: UIDPolicyRequest):
        # Verifies guard presence, not a complete DNS/IPv6 leak-proof.
        await asyncio.to_thread(self._check_guards, request)

    def _freeze(self, request: UIDPolicyRequest):
        plan = self._binding(request)
        self._read_state(request)
        # Keep UID selector/terminal blackhole, regardless of Edge state.
        for command in plan.fail_closed_detach:
            _run(*command.argv, check=False)
        self._check_guards(request)

    async def freeze_uid(self, request: UIDPolicyRequest):
        await asyncio.to_thread(self._freeze, request)

    def _restore(self, request: UIDPolicyRequest):
        plan = self._binding(request)
        self._check_guards(request)
        # Restoring this deliberately *unprotected* canary is allowed only
        # after the shadow is stopped and both its namespace/veth disappeared.
        if _run("ip", "link", "show", "dev", request.spec.veth_root,
                check=False).returncode == 0:
            raise CanaryKernelUnsafe("SHADOW_STILL_RUNNING")
        if request.spec.namespace in _run("ip", "netns", "list").stdout:
            raise CanaryKernelUnsafe("SHADOW_NAMESPACE_STILL_RUNNING")
        table = _run("ip", "-4", "route", "show", "table", str(plan.table)).stdout
        lines = [s.strip() for s in table.splitlines() if s.strip()]
        if len(lines) != 1 or not lines[0].startswith("blackhole default"):
            raise CanaryKernelUnsafe("CANARY_TABLE_NOT_FROZEN")

        # Only remove this exact UID selector; not all policy rules.
        _run("ip", "-4", "rule", "del", "priority", str(plan.priority),
             "uidrange", request.uidrange, "lookup", str(plan.table))
        _run("ip", "-4", "route", "del", "blackhole", "default",
             "table", str(plan.table), "metric", "4096")
        for command in reversed(plan.guard[:3]):
            args = list(command.argv)
            args[2:5] = ["-D", "OUTPUT"]
            _run(*args)
        self._state_path(request).unlink()

    async def restore(self, request: UIDPolicyRequest):
        await asyncio.to_thread(self._restore, request)
