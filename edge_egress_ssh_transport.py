"""D1-C2B3 / D1-C2C: opt-in SSH stage transport and isolated shadow lab.

No bot registration, no production host transport, no customer routing.
SSH host keys MUST be explicitly pinned; keys and private WireGuard config
remain on their owner host. Remote verbs are a finite allowlist.
"""
from __future__ import annotations

import asyncio
import base64
from dataclasses import asdict, dataclass
import ipaddress
import json
from pathlib import Path
import re
import secrets
import shlex
import time
from typing import Protocol

from ops.edge_egress_provision import EgressSpec, validated_key

FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
COMMANDS = frozenset({"preflight", "key", "stage", "discard", "inspect",
                      "start", "stop", "probe"})
MAX_OUTPUT = 16384
SSH_TIMEOUT = 12
COMMAND_TIMEOUT = 45


class EgressSSHError(RuntimeError):
    pass


@dataclass(frozen=True)
class EgressSSHIdentity:
    role: str
    ssh_host: str
    expected_public_ip: str
    host_key_sha256: str
    identity_file: str
    ssh_port: int = 22
    ssh_user: str = "root"

    def validate(self):
        if self.role not in ("core", "edge"):
            raise EgressSSHError("INVALID_ROLE")
        if not self.ssh_host or any(c.isspace() for c in self.ssh_host):
            raise EgressSSHError("INVALID_SSH_HOST")
        try:
            ipaddress.IPv4Address(self.expected_public_ip)
        except ValueError as exc:
            raise EgressSSHError("INVALID_HOST_IDENTITY") from exc
        if not FINGERPRINT.fullmatch(self.host_key_sha256):
            raise EgressSSHError("PINNED_FINGERPRINT_REQUIRED")
        if type(self.ssh_port) is not int or not 1 <= self.ssh_port <= 65535:
            raise EgressSSHError("INVALID_SSH_PORT")
        if self.ssh_user != "root":
            raise EgressSSHError("ROOT_ONLY_LAB")
        if not Path(self.identity_file).is_absolute() or not self.identity_file.strip():
            raise EgressSSHError("ABSOLUTE_KEY_FILE_REQUIRED")


def _remote_source() -> str:
    """Stream reviewed source over stdin; no mutable remote script install."""
    import types
    provision = Path(__file__).parent / "ops" / "edge_egress_provision.py"
    worker = Path(__file__).parent / "ops" / "edge_egress_host_worker.py"
    # Bootstrap creates a package identity for dataclasses, then executes only
    # the two versioned repository modules (not arbitrary supplied shell).
    return (
        "import sys,types\n"
        "pkg=types.ModuleType('ops');pkg.__path__=[];sys.modules['ops']=pkg\n"
        "m=types.ModuleType('ops.edge_egress_provision')\n"
        "m.__file__='edge_egress_provision.py'\n"
        "sys.modules[m.__name__]=m\n"
        "exec(compile(" + repr(provision.read_text(encoding="utf-8")) +
        ",m.__file__,'exec'),m.__dict__)\n"
        "exec(compile(" + repr(worker.read_text(encoding="utf-8")) +
        ",'edge_egress_host_worker.py','exec'),{'__name__':'__main__'})\n"
    )


def _invoke_ssh(identity: EgressSSHIdentity, action: str, payload: dict) -> dict:
    identity.validate()
    if action not in COMMANDS:
        raise EgressSSHError("ACTION_NOT_ALLOWLISTED")
    try:
        import paramiko
    except ImportError as exc:
        raise EgressSSHError("PARAMIKO_REQUIRED") from exc

    from server_migration.ssh import _host_key_sha256

    expected = identity.host_key_sha256

    class PinnedKeyPolicy(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, client, hostname, key):
            if _host_key_sha256(key) != expected:
                raise EgressSSHError("HOST_FINGERPRINT_MISMATCH")
            # For this connection only. No TOFU or persisted known_hosts.
            client.get_host_keys().add(hostname, key.get_name(), key)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(PinnedKeyPolicy())
    try:
        client.connect(hostname=identity.ssh_host, port=identity.ssh_port,
                       username=identity.ssh_user,
                       key_filename=identity.identity_file,
                       password=None, look_for_keys=False, allow_agent=False,
                       timeout=SSH_TIMEOUT, auth_timeout=SSH_TIMEOUT,
                       banner_timeout=SSH_TIMEOUT)
        argument = base64.b64encode(
            json.dumps(payload, separators=(",", ":")).encode()
        ).decode("ascii")
        command = "python3 - " + shlex.quote(action) + " " + shlex.quote(argument)
        stdin, stdout, _stderr = client.exec_command(command, timeout=SSH_TIMEOUT,
                                                     get_pty=False)
        channel = stdout.channel
        channel.set_combine_stderr(True)
        stdin.write(_remote_source())
        stdin.flush()
        channel.shutdown_write()
        output = bytearray()
        deadline = time.monotonic() + COMMAND_TIMEOUT
        while True:
            if time.monotonic() > deadline:
                channel.close()
                raise EgressSSHError("REMOTE_COMMAND_TIMEOUT")
            while channel.recv_ready():
                block = channel.recv(4096)
                output.extend(block)
                if len(output) > MAX_OUTPUT:
                    channel.close()
                    raise EgressSSHError("REMOTE_OUTPUT_LIMIT")
            if channel.exit_status_ready() and not channel.recv_ready():
                break
            time.sleep(0.03)
        exit_code = channel.recv_exit_status()
        try:
            result = json.loads(output.decode("utf-8").strip())
        except (UnicodeDecodeError, ValueError) as exc:
            raise EgressSSHError("UNTRUSTED_REMOTE_RESPONSE") from exc
        if not isinstance(result, dict) or result.get("ok") is not True:
            reason = result.get("error", "REMOTE_ACTION_FAILED") if isinstance(result, dict) else "REMOTE_ACTION_FAILED"
            raise EgressSSHError("REMOTE_ACTION_FAILED:" + str(reason)[:128])
        if exit_code or not isinstance(result.get("data"), dict):
            raise EgressSSHError("REMOTE_EXIT_OR_RESULT_INVALID")
        return result["data"]
    except EgressSSHError:
        raise
    except Exception as exc:
        # Raw exceptions may contain the base64 command arguments, so never
        # include exception text in the journal, telemetry or UI.
        raise EgressSSHError("SSH_TRANSPORT_FAILED:" + type(exc).__name__) from None
    finally:
        client.close()


class PinnedEgressHostPort:
    """One operation / one immutable role/host identity; never bot-registered."""

    def __init__(self, identity: EgressSSHIdentity, *, lab_activation: bool = False):
        identity.validate()
        self.identity = identity
        self.lab_activation = lab_activation
        self._stage_token = secrets.token_hex(24)
        self._spec: EgressSpec | None = None

    def _check(self, spec: EgressSpec) -> None:
        spec.validate()
        expected = (spec.core_public_ipv4 if self.identity.role == "core"
                    else spec.edge_public_ipv4)
        if expected != self.identity.expected_public_ip:
            raise EgressSSHError("SPEC_HOST_IDENTITY_MISMATCH")
        if self._spec is not None and self._spec != spec:
            raise EgressSSHError("SPEC_CHANGED_DURING_OPERATION")
        self._spec = spec

    async def _call(self, action: str, spec: EgressSpec, **kwargs) -> dict:
        self._check(spec)
        payload = {"role": self.identity.role, "spec": asdict(spec), **kwargs}
        if action in {"start", "stop", "probe"}:
            if not self.lab_activation:
                raise EgressSSHError("LAB_ACTIVATION_DISABLED")
            payload["lab_activation"] = True
        return await asyncio.to_thread(_invoke_ssh, self.identity, action, payload)

    async def read_only_preflight(self, spec: EgressSpec) -> tuple[bool, tuple[str, ...]]:
        data = await self._call("preflight", spec)
        issues = data.get("issues")
        if type(data.get("ok")) is not bool or not isinstance(issues, list):
            raise EgressSSHError("INVALID_PREFLIGHT_RESPONSE")
        if any(not isinstance(i, str) for i in issues):
            raise EgressSSHError("INVALID_PREFLIGHT_ISSUES")
        return data["ok"], tuple(issues)

    async def ensure_local_keypair(self, edge_id: str) -> str:
        if self._spec is None or edge_id != self._spec.edge_id:
            raise EgressSSHError("PREFLIGHT_REQUIRED")
        data = await self._call("key", self._spec)
        return validated_key(data.get("public_key"), "remote_public_key")

    async def stage_config_only(self, spec: EgressSpec, *, peer_public_key: str) -> None:
        await self._call("stage", spec, peer_public_key=validated_key(
            peer_public_key, "peer_public_key"), token=self._stage_token)

    async def discard_staged_config_only(self, edge_id: str) -> None:
        if self._spec is None or edge_id != self._spec.edge_id:
            raise EgressSSHError("UNKNOWN_STAGE_OWNER")
        await self._call("discard", self._spec, token=self._stage_token)

    async def inspect_shadow(self, spec: EgressSpec) -> dict:
        return await self._call("inspect", spec)

    async def start_shadow(self, spec: EgressSpec) -> None:
        await self._call("start", spec)

    async def stop_shadow(self, spec: EgressSpec) -> None:
        await self._call("stop", spec)

    async def observe_public_egress(self, spec: EgressSpec) -> str:
        if self.identity.role != "core":
            raise EgressSSHError("PROBE_CORE_ONLY")
        data = await self._call("probe", spec)
        return str(data.get("observed_ip", ""))


class ShadowHost(Protocol):
    async def inspect_shadow(self, spec: EgressSpec) -> dict: ...
    async def start_shadow(self, spec: EgressSpec) -> None: ...
    async def stop_shadow(self, spec: EgressSpec) -> None: ...
    async def observe_public_egress(self, spec: EgressSpec) -> str: ...


@dataclass(frozen=True)
class ShadowProof:
    proven: bool
    reason: str
    observed_ip: str | None = None
    cleanup_uncertain: bool = False


async def activate_and_prove_lab_shadow(spec: EgressSpec, *,
                                        core: ShadowHost, edge: ShadowHost) -> ShadowProof:
    """Explicit lab-only call AFTER staging; no UID route, DB or DNS write.

    Success deliberately leaves shadow tunnels running for independent
    inspection; call stop_lab_shadow() when the lab experiment ends.
    """
    spec.validate()
    core_attempted = edge_attempted = False
    try:
        for name, host in (("edge", edge), ("core", core)):
            state = await host.inspect_shadow(spec)
            if state.get("state") != "STAGED":
                return ShadowProof(False, "STAGE_NOT_PRESENT:" + name)
        edge_attempted = True
        await edge.start_shadow(spec)
        core_attempted = True
        await core.start_shadow(spec)
        observed = await core.observe_public_egress(spec)
        try:
            actual = ipaddress.IPv4Address(observed)
        except ValueError:
            raise EgressSSHError("INVALID_EGRESS_PROOF") from None
        if actual != ipaddress.IPv4Address(spec.edge_public_ipv4):
            raise EgressSSHError("EDGE_PUBLIC_IP_MISMATCH")
        return ShadowProof(True, "SHADOW_EGRESS_PROVEN_NOT_CUSTOMER_READY",
                           observed_ip=observed)
    except Exception as exc:
        reason = str(exc) if isinstance(exc, EgressSSHError) else "SHADOW_ACTIVATION_FAILED"
        uncertain = False
        for attempted, host in ((core_attempted, core), (edge_attempted, edge)):
            if attempted:
                try:
                    await host.stop_shadow(spec)
                except Exception:
                    uncertain = True
        return ShadowProof(False, reason, cleanup_uncertain=uncertain)


@dataclass(frozen=True)
class EgressLabHostFactory:
    """Explicit opt-in identity map for Existing6GPreparationAdapter(host_factory=).

    This factory is NEVER registered in bot_final_v49-2.py or Production.
    Set activation=True only for a disposable two-VM experiment.
    """
    core_identity: EgressSSHIdentity
    edge_identity: EgressSSHIdentity
    activation: bool = False

    def __call__(self, role: str, expected_ip: str) -> PinnedEgressHostPort:
        if role not in ("core", "edge"):
            raise EgressSSHError("INVALID_ROLE")
        identity = self.core_identity if role == "core" else self.edge_identity
        if identity.role != role or identity.expected_public_ip != expected_ip:
            raise EgressSSHError("HOST_FACTORY_IDENTITY_MISMATCH")
        return PinnedEgressHostPort(identity, lab_activation=self.activation)


async def stop_lab_shadow(spec: EgressSpec, *,
                          core: ShadowHost, edge: ShadowHost) -> None:
    """Stop BOTH shadows even if the first remote stop fails."""
    failures = []
    for role, host in (("core", core), ("edge", edge)):
        try:
            await host.stop_shadow(spec)
        except Exception:
            failures.append(role)
    if failures:
        raise EgressSSHError("SHADOW_STOP_UNCERTAIN:" + ",".join(failures))
