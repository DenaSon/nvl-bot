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
_COMMIT = re.compile(r"^[a-f0-9]{40}$")
_FILES = frozenset(("manifest.json", "wg.conf", "up.sh", "down.sh"))
_AGENT = "/root/nvl-egress-lab1-source/edge_egress_r1_lab_agent.py"


class R1LabUnsafe(ValueError):
    pass


@dataclass(frozen=True)
class LabHost:
    role: str
    public_ipv4: str
    machine_id: str
    source_commit: str
    marker_sha256: str
    stage_sha256: dict[str, str]

    def validate(self, spec: EgressSpec) -> None:
        address = spec.core_public_ipv4 if self.role == "core" else spec.edge_public_ipv4
        if (self.role not in ("core", "edge") or self.public_ipv4 != address
                or not _ID.fullmatch(self.machine_id)
                or not _COMMIT.fullmatch(self.source_commit)
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
            "source_commit": self.source_commit,
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
        if action not in ("probe", "start", "inspect"):
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
        states = ({"OFFLINE", "TRANSPORT_VERIFIED", "HOLD"}
                  if action == "inspect" else
                  {"OFFLINE_VERIFIED"} if action == "probe"
                  else {"TRANSPORT_VERIFIED"})
        if (not isinstance(response, dict)
                or set(response) != {"ok", "role", "state"}
                or response["ok"] is not True
                or response["role"] != host.role
                or response["state"] not in states):
            raise R1LabUnsafe("HOST_VERIFICATION_FAILED_HOLD")
        return response


@dataclass(frozen=True)
class CurrentBridge6GLease:
    """Resolve the EXISTING F2 operation acquired *inside* attach_protected.

    Binding a fixed operation_id before bridge.acquire_6g() would be stale or
    unavailable. This adapter NEVER calls acquire_fn, writes a row or invents
    a lock; it reads the already-held bridge identity and checks SQLite.
    """
    bridge: object
    lab_core_ingress_attestor: object | None = None

    def for_request(self, request: UIDPolicyRequest) -> bool:
        op = getattr(self.bridge, "operation_id", None)
        source = getattr(self.bridge, "source", None)
        target = getattr(self.bridge, "target", None)
        if (type(op) is not int or op <= 0
                or not isinstance(source, str) or not source
                or not isinstance(target, str) or not target):
            return False
        try:
            probe = Existing6GR1LeaseProbe(
                self.bridge.db_conn, op, source, target,
            )
            if source == request.spec.core_public_ipv4:
                # Special-case only a real, machine-bound disposable Core ingress.
                # The SAME current 6G RUNNING row is still required.
                from edge_egress_r1_lab_topology import TwoHostCoreIngress
                return bool(
                    target == request.spec.edge_public_ipv4
                    and type(self.lab_core_ingress_attestor) is TwoHostCoreIngress
                    and self.lab_core_ingress_attestor.for_request(request, source) is True
                    and probe.active()
                )
            return probe.for_request(request)
        except (ValueError, TypeError, AttributeError, OSError):
            return False


@dataclass
class R1Lab6GShadow:
    """Concrete RuntimeShadowPort: injected as Existing6GUIDRuntimeBridge.shadow.

    The F2 attach sequence must already have persisted BLOCKED, drained
    sessions and armed its fail-closed UID guard. No independent acquire_fn,
    SQLite schema, lock, journaling or cleanup is provided here.
    """
    spec: EgressSpec
    shared_lease: Existing6GR1LeaseProbe | CurrentBridge6GLease
    guard_check: Callable[[UIDPolicyRequest], bool]
    edge: LabHost
    core: LabHost
    ssh: LabSSHExecutor
    explicitly_enabled: bool = False
    disposable_vps: bool = False
    accept_verified_running_transport: bool = False

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

    async def _run(self, host: LabHost, action: str) -> dict:
        # The host executor is blocking, never block the F2 event loop.
        return await asyncio.to_thread(self.ssh.run, host, action, self.spec)

    async def start(self, request: UIDPolicyRequest) -> None:
        self._admit(request)
        try:
            if self.accept_verified_running_transport is True:
                # Current disposable smoke pair is already UP. Reconcile via
                # read-only identity inspection under the CURRENT 6G lease;
                # never re-run the Stage script on an occupied interface.
                edge_state = await self._run(self.edge, "inspect")
                core_state = await self._run(self.core, "inspect")
                self._admit(request)
                states = (edge_state["state"], core_state["state"])
                if states == ("TRANSPORT_VERIFIED", "TRANSPORT_VERIFIED"):
                    return  # transport-only, never customer READY
                if states != ("OFFLINE", "OFFLINE"):
                    raise R1LabUnsafe("EXISTING_TRANSPORT_ASYMMETRY_HOLD")
            # Brand-new transport still requires the exact offline collision proof.
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


def bind_disposable_lab_shadow(bridge, *, spec: EgressSpec,
                               guard_check: Callable[[UIDPolicyRequest], bool],
                               edge: LabHost, core: LabHost,
                               ssh: LabSSHExecutor,
                               explicitly_enabled: bool = False,
                               disposable_vps: bool = False,
                               lab_core_ingress_attestor: object | None = None,
                               accept_verified_running_transport: bool = False) -> R1Lab6GShadow:
    """Wire an Existing6GUIDRuntimeBridge to this F2 transport port.

    The bridge must have its genuine kernel, PAM gate and existing-session
    probes injected separately. Do not replace a running/foreign shadow.
    The existing controller acquires and journals the 6G operation; the
    CurrentBridge6GLease reads that CURRENT operation at activation time.
    """
    from edge_egress_uid_runtime_bridge import Existing6GUIDRuntimeBridge

    if not isinstance(bridge, Existing6GUIDRuntimeBridge):
        raise R1LabUnsafe("EXISTING_F2_BRIDGE_REQUIRED")
    if (bridge.shadow is not None or bridge.operation_id is not None
            or bridge.kernel is None or bridge.session_gate_probe is None
            or bridge.existing_sessions_probe is None):
        raise R1LabUnsafe("BRIDGE_NOT_FRESH_OR_GUARDS_UNAVAILABLE")
    if not callable(guard_check):
        raise R1LabUnsafe("EXTERNAL_UID_GUARD_PROBE_REQUIRED")
    spec.validate()
    edge.validate(spec)
    core.validate(spec)
    port = R1Lab6GShadow(
        spec, CurrentBridge6GLease(bridge, lab_core_ingress_attestor), guard_check, edge, core, ssh,
        explicitly_enabled=explicitly_enabled,
        disposable_vps=disposable_vps,
        accept_verified_running_transport=accept_verified_running_transport,
    )
    bridge.shadow = port
    return port


@dataclass(frozen=True)
class R1LabRecoveryEvidence:
    """Transport-only reconciliation; never a customer READY/release proof."""
    edge_state: str
    core_state: str
    recovery_required: bool
    customer_ready: bool = False


async def inspect_lab_transport(ssh: LabSSHExecutor, *, spec: EgressSpec,
                                edge: LabHost, core: LabHost) -> R1LabRecoveryEvidence:
    """Observe both hosts without restarting, teardown, UID attach or repair.

    Unknown/partial/asymmetric states mean HOLD. F2 still owns persistent
    frozen UID guards, the 6G journal and operator-led recovery decisions.
    """
    spec.validate()
    edge.validate(spec)
    core.validate(spec)
    try:
        e = await asyncio.to_thread(ssh.run, edge, "inspect", spec)
        q = await asyncio.to_thread(ssh.run, core, "inspect", spec)
    except Exception:
        return R1LabRecoveryEvidence("UNKNOWN", "UNKNOWN", True)
    es, cs = e["state"], q["state"]
    return R1LabRecoveryEvidence(
        es, cs, es == "HOLD" or cs == "HOLD" or es != cs,
    )
