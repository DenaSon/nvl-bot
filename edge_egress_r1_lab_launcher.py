"""R1 disposable LAB host launcher behind the existing F2 shared-6G bridge.

This is a transport-only SSH executor, not a bot entrypoint, PAM installer,
6G owner, systemd manager, or authorization to move customer UIDs. The
existing F2 controller owns the journal and HOLD/freeze on any exception.

Remote execution is limited to a pinned, root-owned lab agent and a
pre-pinned known_hosts key. No passwords, host key auto-acceptance, shell
interpolation, remote private WG keys, or unrestricted arbitrary commands.
"""
from __future__ import annotations

import asyncio
import base64
from dataclasses import asdict, dataclass
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import stat
import subprocess
from typing import Callable

from edge_egress_r1_shared6g import Existing6GR1LeaseProbe
from edge_egress_uid_policy import UIDPolicyRequest
from ops.edge_egress_provision import EgressSpec

_SHA = re.compile(r"^[a-f0-9]{64}$")
_ID = re.compile(r"^[a-f0-9]{32}$")
_FILES = frozenset(("manifest.json", "wg.conf", "up.sh", "down.sh"))
_AGENT = "/root/nvl-egress-lab1-source/edge_egress_r1_lab_agent.py"


class R1LabUnsafe(ValueError):
    pass


@dataclass(frozen=True)
class LabHost:
    role: str
    public_ipv4: str
    machine_id: str
    marker_sha256: str
    stage_sha256: dict[str, str]

    def validate(self, spec: EgressSpec) -> None:
        address = spec.core_public_ipv4 if self.role == "core" else spec.edge_public_ipv4
        if (self.role not in ("core", "edge") or self.public_ipv4 != address
                or not _ID.fullmatch(self.machine_id)
                or not _SHA.fullmatch(self.marker_sha256)
                or not isinstance(self.stage_sha256, dict)
                or set(self.stage_sha256) != _FILES
                or any(not isinstance(x, str) or not _SHA.fullmatch(x)
                       for x in self.stage_sha256.values())):
            raise R1LabUnsafe("LAB_HOST_IDENTITY_UNPINNED")
        if str(ipaddress.IPv4Address(self.public_ipv4)) != self.public_ipv4:
            raise R1LabUnsafe("NON_CANONICAL_HOST_IP")

    def payload(self, spec: EgressSpec) -> str:
        self.validate(spec)
        request = {
            "mode": "DISPOSABLE_ONLY",
            "spec": asdict(spec), "role": self.role,
            "machine_id": self.machine_id,
            "marker_sha256": self.marker_sha256,
            "stage_sha256": self.stage_sha256,
        }
        return base64.b64encode(
            json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
        ).decode("ascii")


@dataclass(frozen=True)
class LabSSHExecutor:
    """Only invoke one pinned agent, with SSH host-key verification enforced.

    Install the agent and pin its commit separately on both disposable hosts.
    These launchers do not generate/accept keys or clone new source code.
    """
    identity_file: Path
    known_hosts: Path
    timeout_seconds: int = 45

    def _check_local_files(self) -> None:
        for path in (self.identity_file, self.known_hosts):
            if not path.is_absolute() or path.is_symlink() or not path.is_file():
                raise R1LabUnsafe("SSH_TRUST_FILE_MISSING")
            s = path.stat()
            if s.st_uid != 0 or s.st_mode & 0o022:
                raise R1LabUnsafe("SSH_TRUST_FILE_UNSAFE")
        if not (5 <= self.timeout_seconds <= 75):
            raise R1LabUnsafe("SSH_TIMEOUT_INVALID")

    def run(self, host: LabHost, action: str, spec: EgressSpec) -> dict:
        if action not in ("probe", "start"):
            raise R1LabUnsafe("HOST_ACTION_NOT_ALLOWED")
        host.validate(spec)
        self._check_local_files()
        args = [
            "ssh", "-F", "/dev/null", "-T",
            "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "UserKnownHostsFile=" + str(self.known_hosts),
            "-o", "ConnectTimeout=8", "-o", "ConnectionAttempts=1",
            "-i", str(self.identity_file),
            "root@" + host.public_ipv4,
            "/usr/bin/python3", _AGENT, action, host.payload(spec),
        ]
        try:
            result = subprocess.run(
                args, capture_output=True, text=True, timeout=self.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise R1LabUnsafe("SSH_HOST_RESULT_UNCERTAIN_HOLD") from exc
        if result.returncode or len(result.stdout) > 8192:
            raise R1LabUnsafe("SSH_HOST_RESULT_UNCERTAIN_HOLD")
        try:
            response = json.loads(result.stdout)
        except (ValueError, TypeError) as exc:
            raise R1LabUnsafe("INVALID_HOST_RESPONSE_HOLD") from exc
        if (not isinstance(response, dict)
                or set(response) != {"ok", "role", "state"}
                or response["ok"] is not True
                or response["role"] != host.role
                or response["state"] != ("OFFLINE_VERIFIED" if action == "probe"
                                          else "TRANSPORT_VERIFIED")):
            raise R1LabUnsafe("HOST_VERIFICATION_FAILED_HOLD")
        return response


@dataclass
class R1Lab6GShadow:
    """Concrete RuntimeShadowPort: injected as Existing6GUIDRuntimeBridge.shadow.

    The F2 attach sequence must already have persisted BLOCKED, drained
    sessions and armed its fail-closed UID guard. No independent acquire_fn,
    SQLite schema, lock, journaling or cleanup is provided here.
    """
    spec: EgressSpec
    shared_lease: Existing6GR1LeaseProbe
    guard_check: Callable[[UIDPolicyRequest], bool]
    edge: LabHost
    core: LabHost
    ssh: LabSSHExecutor
    explicitly_enabled: bool = False
    disposable_vps: bool = False

    def _admit(self, request: UIDPolicyRequest) -> None:
        request.validate()
        self.spec.validate()
        self.edge.validate(self.spec)
        self.core.validate(self.spec)
        if request.spec != self.spec:
            raise R1LabUnsafe("REQUEST_SPEC_CHANGED")
        if not (self.explicitly_enabled is True and self.disposable_vps is True):
            raise R1LabUnsafe("LAB_SHADOW_DEFAULT_OFF")
        # The source of an F2 transaction is the current ingress Edge,
        # NOT the Core public IP or destination Egress Edge.
        if not self.shared_lease.for_request(request):
            raise R1LabUnsafe("LIVE_SHARED_6G_LEASE_REQUIRED")
        try:
            guard = self.guard_check(request)
        except Exception as exc:
            raise R1LabUnsafe("FAIL_CLOSED_GUARD_NOT_ATTESTED") from exc
        if guard is not True:
            raise R1LabUnsafe("FAIL_CLOSED_GUARD_NOT_ATTESTED")

    async def _run(self, host: LabHost, action: str) -> None:
        # The host executor is blocking, never block the F2 event loop.
        await asyncio.to_thread(self.ssh.run, host, action, self.spec)

    async def start(self, request: UIDPolicyRequest) -> None:
        self._admit(request)
        try:
            # Observe both hosts before mutation; never adopt old resources.
            await self._run(self.edge, "probe")
            await self._run(self.core, "probe")
            self._admit(request)

            # Edge first, then a fresh 6G/guard recheck before Core.
            await self._run(self.edge, "start")
            self._admit(request)
            await self._run(self.core, "start")
            self._admit(request)

            # Only proof of both transport identities is accepted.
            # No UID attaches or public-IP success are claimed here.
        except Exception as exc:
            # F2 owns HOLD journal and freezes the protected route. Do not
            # issue down.sh, stop units or restore Core egress on uncertainty.
            raise R1LabUnsafe("R1_DUAL_HOST_START_UNCERTAIN_HOLD") from exc
