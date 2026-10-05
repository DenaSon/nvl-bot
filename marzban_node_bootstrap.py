from __future__ import annotations

import ipaddress
import re
import secrets
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from server_migration.models import CHECK_FAIL, CHECK_PASS, CHECK_WARN, ServerCredentials
from server_migration.ssh import (
    ParamikoRemoteExecutor,
    SSHConnectionError,
    SSHHostKeyInfo,
    probe_ssh_host_key,
)


SESSION_TTL_SECONDS = 600
SUPPORTED_OS = {"ubuntu", "debian"}
SUPPORTED_ARCH = {"x86_64", "amd64", "aarch64", "arm64"}
_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


class NodeBootstrapError(RuntimeError):
    pass


class NodeBootstrapBusy(NodeBootstrapError):
    pass


@dataclass(frozen=True)
class NodePreflightCheck:
    code: str
    status: str
    message: str
    blocking: bool = False


@dataclass(frozen=True)
class NodePreflightReport:
    node_id: int
    host: str
    ssh_port: int
    host_key_algorithm: str
    host_key_sha256: str
    os_id: str = ""
    os_version: str = ""
    os_pretty_name: str = ""
    architecture: str = ""
    docker_installed: bool = False
    docker_version: str = ""
    compose_available: bool = False
    compose_version: str = ""
    listener_ports: tuple[int, ...] = ()
    service_port: int = 62050
    api_port: int = 62051
    marzban_node_detected: bool = False
    checks: tuple[NodePreflightCheck, ...] = ()
    ready: bool = False
    observed_at: str = ""
    error: str = ""

    @property
    def blockers(self) -> tuple[NodePreflightCheck, ...]:
        return tuple(
            check
            for check in self.checks
            if check.status == CHECK_FAIL and check.blocking
        )

    @property
    def warnings(self) -> tuple[NodePreflightCheck, ...]:
        return tuple(check for check in self.checks if check.status == CHECK_WARN)

    def to_dict(self) -> dict[str, Any]:
        # Passwords live only in NodeBootstrapSession and are scrubbed after use.
        return asdict(self)


@dataclass
class NodeBootstrapSession:
    chat_id: int
    node_id: int
    host: str
    service_port: int
    api_port: int
    ssh_port: int = 22
    stage: str = "SSH_PORT"
    host_key_algorithm: str = ""
    host_key_sha256: str = ""
    host_key_nonce: str = ""
    password: str | None = field(default=None, repr=False)
    busy: bool = False
    started_at: float = field(default_factory=time.time)
    last_report: NodePreflightReport | None = field(default=None, repr=False)

    def expired(self, *, now: float | None = None) -> bool:
        current = time.time() if now is None else float(now)
        return current - float(self.started_at) > SESSION_TTL_SECONDS

    def scrub_secret(self) -> None:
        self.password = None

    def credentials(self) -> ServerCredentials:
        if not self.password:
            raise NodeBootstrapError("SSH password is missing")
        return ServerCredentials(
            host=self.host,
            port=self.ssh_port,
            username="root",
            password=self.password,
        )

    def safe_summary(self) -> dict[str, Any]:
        return {
            "chat_id": self.chat_id,
            "node_id": self.node_id,
            "host": self.host,
            "service_port": self.service_port,
            "api_port": self.api_port,
            "ssh_port": self.ssh_port,
            "stage": self.stage,
            "host_key_algorithm": self.host_key_algorithm,
            "host_key_sha256": self.host_key_sha256,
            "busy": self.busy,
            "started_at": self.started_at,
            "ready": bool(self.last_report and self.last_report.ready),
        }


_SESSIONS: dict[int, NodeBootstrapSession] = {}
_SESSIONS_LOCK = threading.RLock()


def normalize_host(value: str) -> str:
    raw = str(value or "").strip().rstrip(".")
    if (
        not raw
        or len(raw) > 253
        or any(ch.isspace() for ch in raw)
        or "://" in raw
        or "/" in raw
    ):
        raise ValueError("invalid node host")
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        pass
    labels = raw.split(".")
    if not labels or not all(_HOST_LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError("invalid node host")
    return raw.lower()


def normalize_port(value: int | str) -> int:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid port") from exc
    if not 1 <= port <= 65535:
        raise ValueError("invalid port")
    return port


def begin_session(
    chat_id: int,
    *,
    node_id: int,
    host: str,
    service_port: int,
    api_port: int,
) -> NodeBootstrapSession:
    session = NodeBootstrapSession(
        chat_id=int(chat_id),
        node_id=int(node_id),
        host=normalize_host(host),
        service_port=normalize_port(service_port),
        api_port=normalize_port(api_port),
    )
    with _SESSIONS_LOCK:
        old = _SESSIONS.pop(session.chat_id, None)
        if old is not None:
            old.scrub_secret()
        _SESSIONS[session.chat_id] = session
    return session


def get_session(chat_id: int) -> NodeBootstrapSession | None:
    chat_id = int(chat_id)
    with _SESSIONS_LOCK:
        session = _SESSIONS.get(chat_id)
        if session is not None and session.expired():
            _SESSIONS.pop(chat_id, None)
            session.scrub_secret()
            return None
        return session


def require_session(chat_id: int) -> NodeBootstrapSession:
    session = get_session(chat_id)
    if session is None:
        raise NodeBootstrapError("Node bootstrap session is not active or has expired")
    return session


def cancel_session(chat_id: int) -> None:
    with _SESSIONS_LOCK:
        session = _SESSIONS.pop(int(chat_id), None)
    if session is not None:
        session.scrub_secret()


def set_ssh_port(session: NodeBootstrapSession, value: int | str) -> int:
    if session.busy:
        raise NodeBootstrapBusy("Node bootstrap is busy")
    port = normalize_port(value)
    session.ssh_port = port
    session.host_key_algorithm = ""
    session.host_key_sha256 = ""
    session.host_key_nonce = ""
    session.scrub_secret()
    session.last_report = None
    session.stage = "HOST_KEY"
    return port


def discover_host_key(
    session: NodeBootstrapSession,
    *,
    probe: Callable[..., SSHHostKeyInfo] = probe_ssh_host_key,
) -> SSHHostKeyInfo:
    if session.busy:
        raise NodeBootstrapBusy("Node bootstrap is busy")
    if session.stage not in {"HOST_KEY", "HOST_KEY_FAILED"}:
        raise NodeBootstrapError("SSH host-key discovery is not allowed from this stage")
    session.busy = True
    try:
        info = probe(session.host, session.ssh_port)
        session.host_key_algorithm = str(info.algorithm)
        session.host_key_sha256 = str(info.sha256)
        session.host_key_nonce = secrets.token_hex(8)
        session.stage = "HOST_KEY_CONFIRM"
        return info
    except Exception:
        session.stage = "HOST_KEY_FAILED"
        raise
    finally:
        session.busy = False


def confirm_host_key(session: NodeBootstrapSession, nonce: str) -> None:
    if session.busy:
        raise NodeBootstrapBusy("Node bootstrap is busy")
    if (
        session.stage != "HOST_KEY_CONFIRM"
        or not session.host_key_sha256
        or not nonce
        or nonce != session.host_key_nonce
    ):
        raise NodeBootstrapError("SSH host-key confirmation is stale or invalid")
    session.stage = "PASSWORD"


def set_password(session: NodeBootstrapSession, password: str) -> None:
    if session.busy:
        raise NodeBootstrapBusy("Node bootstrap is busy")
    if session.stage != "PASSWORD":
        raise NodeBootstrapError("SSH password is not expected at this stage")
    value = str(password or "")
    if not value or len(value) > 1024:
        raise ValueError("invalid SSH password")
    session.password = value
    session.stage = "PREFLIGHT_READY"


def _parse_os_release(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key.strip()] = value
    return values


def _parse_listener_ports(text: str) -> tuple[int, ...]:
    ports: set[int] = set()
    for raw_line in str(text or "").splitlines():
        fields = raw_line.split()
        if len(fields) < 4:
            continue
        local = fields[3]
        match = re.search(r":(\d+)$", local)
        if match:
            port = int(match.group(1))
            if 1 <= port <= 65535:
                ports.add(port)
    return tuple(sorted(ports))


def _command(executor, command: str, *, timeout: int = 20):
    return executor.run(command, timeout=timeout)


def _build_ssh_failure_report(
    session: NodeBootstrapSession,
    error: Exception,
) -> NodePreflightReport:
    message = f"{type(error).__name__}: {error}"
    return NodePreflightReport(
        node_id=session.node_id,
        host=session.host,
        ssh_port=session.ssh_port,
        host_key_algorithm=session.host_key_algorithm,
        host_key_sha256=session.host_key_sha256,
        service_port=session.service_port,
        api_port=session.api_port,
        checks=(
            NodePreflightCheck(
                code="SSH_AUTH",
                status=CHECK_FAIL,
                message=message,
                blocking=True,
            ),
        ),
        ready=False,
        observed_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        error=message,
    )


def run_preflight(
    session: NodeBootstrapSession,
    *,
    executor_factory=ParamikoRemoteExecutor,
) -> NodePreflightReport:
    """Run read-only Node readiness checks over a fingerprint-pinned SSH session."""
    if session.busy:
        raise NodeBootstrapBusy("Node bootstrap is busy")
    if session.stage != "PREFLIGHT_READY":
        raise NodeBootstrapError("Node preflight is not ready to run")
    if not session.host_key_sha256:
        raise NodeBootstrapError("confirmed SSH host-key fingerprint is missing")

    session.busy = True
    executor = None
    try:
        credentials = session.credentials()
        try:
            executor = executor_factory(
                credentials,
                expected_host_key_sha256=session.host_key_sha256,
            )

            uid_result = _command(executor, "id -u")
            if uid_result.exit_code != 0:
                raise SSHConnectionError("remote id command failed")
            uid = int(uid_result.stdout.strip())

            os_result = _command(executor, "cat /etc/os-release")
            if os_result.exit_code != 0:
                raise SSHConnectionError("could not read /etc/os-release")
            os_values = _parse_os_release(os_result.stdout)
            os_id = str(os_values.get("ID") or "").strip().lower()
            os_version = str(os_values.get("VERSION_ID") or "").strip()
            os_pretty = str(os_values.get("PRETTY_NAME") or "").strip()

            arch_result = _command(executor, "uname -m")
            architecture = (
                arch_result.stdout.strip().lower()
                if arch_result.exit_code == 0
                else ""
            )

            docker_probe = _command(executor, "command -v docker")
            docker_installed = docker_probe.exit_code == 0
            docker_version = ""
            compose_available = False
            compose_version = ""
            if docker_installed:
                docker_result = _command(executor, "docker --version")
                if docker_result.exit_code == 0:
                    docker_version = docker_result.stdout.strip()
                compose_result = _command(executor, "docker compose version")
                if compose_result.exit_code == 0:
                    compose_available = True
                    compose_version = compose_result.stdout.strip()

            listeners_result = _command(executor, "ss -H -ltn")
            listener_ports = (
                _parse_listener_ports(listeners_result.stdout)
                if listeners_result.exit_code == 0
                else ()
            )

            files_result = _command(
                executor,
                "test -d /var/lib/marzban-node || "
                "test -d /opt/marzban-node || "
                "test -f /etc/systemd/system/marzban-node.service",
            )
            marzban_node_detected = files_result.exit_code == 0
            if docker_installed:
                containers = _command(
                    executor,
                    "docker ps -a --format '{{.Names}}'",
                )
                if (
                    containers.exit_code == 0
                    and "marzban-node" in containers.stdout.lower()
                ):
                    marzban_node_detected = True

        except Exception as exc:
            report = _build_ssh_failure_report(session, exc)
            session.last_report = report
            session.stage = "PREFLIGHT_BLOCKED"
            return report

        checks: list[NodePreflightCheck] = [
            NodePreflightCheck(
                "SSH_AUTH",
                CHECK_PASS,
                "SSH authentication succeeded with the confirmed host key",
            ),
            NodePreflightCheck(
                "ROOT_ACCESS",
                CHECK_PASS if uid == 0 else CHECK_FAIL,
                "root access confirmed" if uid == 0 else f"remote uid is {uid}, expected 0",
                blocking=uid != 0,
            ),
            NodePreflightCheck(
                "SUPPORTED_OS",
                CHECK_PASS if os_id in SUPPORTED_OS else CHECK_FAIL,
                (
                    os_pretty or f"{os_id} {os_version}".strip() or "unknown OS"
                ),
                blocking=os_id not in SUPPORTED_OS,
            ),
            NodePreflightCheck(
                "SUPPORTED_ARCH",
                CHECK_PASS if architecture in SUPPORTED_ARCH else CHECK_FAIL,
                architecture or "unknown architecture",
                blocking=architecture not in SUPPORTED_ARCH,
            ),
        ]

        if docker_installed:
            checks.append(
                NodePreflightCheck(
                    "DOCKER",
                    CHECK_PASS,
                    docker_version or "Docker is installed",
                )
            )
        else:
            checks.append(
                NodePreflightCheck(
                    "DOCKER",
                    CHECK_WARN,
                    "Docker is not installed; Phase 7 may install it",
                )
            )

        if compose_available:
            checks.append(
                NodePreflightCheck(
                    "DOCKER_COMPOSE",
                    CHECK_PASS,
                    compose_version or "Docker Compose is available",
                )
            )
        else:
            checks.append(
                NodePreflightCheck(
                    "DOCKER_COMPOSE",
                    CHECK_WARN,
                    "Docker Compose is not available; Phase 7 may install it",
                )
            )

        distinct_ports = session.service_port != session.api_port
        checks.append(
            NodePreflightCheck(
                "NODE_PORTS_DISTINCT",
                CHECK_PASS if distinct_ports else CHECK_FAIL,
                (
                    "Service Port and Xray API Port are distinct"
                    if distinct_ports
                    else "Service Port and Xray API Port must be different"
                ),
                blocking=not distinct_ports,
            )
        )

        for code, label, port in (
            ("SERVICE_PORT", "Service Port", session.service_port),
            ("XRAY_API_PORT", "Xray API Port", session.api_port),
        ):
            occupied = port in listener_ports
            checks.append(
                NodePreflightCheck(
                    code,
                    CHECK_FAIL if occupied else CHECK_PASS,
                    (
                        f"{label} {port} is already listening"
                        if occupied
                        else f"{label} {port} is free"
                    ),
                    blocking=occupied,
                )
            )

        checks.append(
            NodePreflightCheck(
                "MARZBAN_NODE_EXISTING",
                CHECK_WARN if marzban_node_detected else CHECK_PASS,
                (
                    "Existing Marzban-node artifacts/container detected; "
                    "Phase 7 must reconcile instead of overwriting"
                    if marzban_node_detected
                    else "No existing Marzban-node installation detected"
                ),
            )
        )

        ready = not any(
            check.status == CHECK_FAIL and check.blocking
            for check in checks
        )
        report = NodePreflightReport(
            node_id=session.node_id,
            host=session.host,
            ssh_port=session.ssh_port,
            host_key_algorithm=session.host_key_algorithm,
            host_key_sha256=session.host_key_sha256,
            os_id=os_id,
            os_version=os_version,
            os_pretty_name=os_pretty,
            architecture=architecture,
            docker_installed=docker_installed,
            docker_version=docker_version,
            compose_available=compose_available,
            compose_version=compose_version,
            listener_ports=listener_ports,
            service_port=session.service_port,
            api_port=session.api_port,
            marzban_node_detected=marzban_node_detected,
            checks=tuple(checks),
            ready=ready,
            observed_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        session.last_report = report
        session.stage = "PREFLIGHT_COMPLETE" if ready else "PREFLIGHT_BLOCKED"
        return report
    finally:
        session.scrub_secret()
        session.busy = False
        if executor is not None:
            try:
                executor.close()
            except Exception:
                pass
