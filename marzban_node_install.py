from __future__ import annotations

import re
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from marzban_node_bootstrap import NodeBootstrapBusy, NodeBootstrapError, NodeBootstrapSession
from server_migration.ssh import ParamikoRemoteExecutor


APP_NAME = "marzban-node"
APP_DIR = "/opt/marzban-node"
DATA_DIR = "/var/lib/marzban-node"
COMPOSE_PATH = f"{APP_DIR}/docker-compose.yml"
CERT_PATH = f"{DATA_DIR}/cert.pem"
MANAGED_MARKER = f"{DATA_DIR}/.nvl-managed"
IMAGE = "gozargah/marzban-node:latest"


class NodeInstallError(NodeBootstrapError):
    def __init__(self, stage: str, message: str):
        super().__init__(message)
        self.stage = str(stage)


@dataclass(frozen=True)
class NodeInstallReport:
    node_id: int
    host: str
    ssh_port: int
    service_port: int
    api_port: int
    success: bool
    stage: str
    docker_installed_now: bool = False
    docker_version: str = ""
    compose_version: str = ""
    container_running: bool = False
    service_port_listening: bool = False
    api_port_listening: bool = False
    image_id: str = ""
    managed_retry: bool = False
    observed_at: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        # Certificate and SSH password are intentionally absent.
        return asdict(self)


def _now_text() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _validate_certificate(certificate: str) -> str:
    value = str(certificate or "").strip()
    if (
        "-----BEGIN CERTIFICATE-----" not in value
        or "-----END CERTIFICATE-----" not in value
    ):
        raise ValueError("Marzban returned an invalid PEM client certificate")
    return value + "\n"


def _compose_text(service_port: int, api_port: int) -> str:
    return (
        "services:\n"
        "  marzban-node:\n"
        "    container_name: marzban-node\n"
        f"    image: {IMAGE}\n"
        "    restart: always\n"
        "    network_mode: host\n"
        "    environment:\n"
        '      SSL_CLIENT_CERT_FILE: "/var/lib/marzban-node/cert.pem"\n'
        f'      SERVICE_PORT: "{int(service_port)}"\n'
        f'      XRAY_API_PORT: "{int(api_port)}"\n'
        '      SERVICE_PROTOCOL: "rest"\n'
        "    volumes:\n"
        "      - /var/lib/marzban-node:/var/lib/marzban\n"
        "      - /var/lib/marzban-node:/var/lib/marzban-node\n"
    )


def _run(executor, command: str, *, stage: str, timeout: int = 60):
    result = executor.run(command, timeout=timeout)
    if result.exit_code != 0:
        detail = (result.stderr or result.stdout or "").strip()
        detail = detail[-1200:] if detail else f"exit code {result.exit_code}"
        raise NodeInstallError(stage, detail)
    return result


def _listener_ports(executor) -> tuple[int, ...]:
    result = _run(
        executor,
        "ss -H -ltn",
        stage="verify-listeners",
        timeout=20,
    )
    ports: set[int] = set()
    for raw_line in result.stdout.splitlines():
        fields = raw_line.split()
        if len(fields) < 4:
            continue
        match = re.search(r":(\d+)$", fields[3])
        if match:
            port = int(match.group(1))
            if 1 <= port <= 65535:
                ports.add(port)
    return tuple(sorted(ports))


def prepare_install(session: NodeBootstrapSession) -> None:
    if session.busy:
        raise NodeBootstrapBusy("Node bootstrap is busy")
    if session.last_report is None or not session.last_report.ready:
        raise NodeBootstrapError("successful Phase 6 preflight is required")
    if session.stage not in {
        "PREFLIGHT_COMPLETE",
        "INSTALL_FAILED",
        "REMOTE_INSTALL_COMPLETE",
    }:
        raise NodeBootstrapError(
            f"Phase 7 cannot start from stage {session.stage!r}"
        )
    session.scrub_secret()
    session.stage = "INSTALL_PASSWORD"
    session.started_at = time.time()


def set_install_password(session: NodeBootstrapSession, password: str) -> None:
    if session.busy:
        raise NodeBootstrapBusy("Node bootstrap is busy")
    if session.stage != "INSTALL_PASSWORD":
        raise NodeBootstrapError("SSH password is not expected for Phase 7")
    value = str(password or "")
    if not value or len(value) > 1024:
        raise ValueError("invalid SSH password")
    session.password = value
    session.stage = "INSTALL_READY"


def run_install(
    session: NodeBootstrapSession,
    *,
    certificate: str,
    executor_factory=ParamikoRemoteExecutor,
) -> NodeInstallReport:
    """Install/reconcile Marzban-node using the current official Docker contract.

    The SSH host key remains pinned to the fingerprint confirmed in Phase 6.
    This function never creates or modifies the Marzban Node API record itself.
    """
    if session.busy:
        raise NodeBootstrapBusy("Node bootstrap is busy")
    if session.stage != "INSTALL_READY":
        raise NodeBootstrapError("Phase 7 install is not ready")
    if session.last_report is None or not session.last_report.ready:
        raise NodeBootstrapError("successful Phase 6 preflight is required")
    if not session.host_key_sha256:
        raise NodeBootstrapError("confirmed SSH host-key fingerprint is missing")

    session.busy = True
    executor = None
    stage = "certificate"
    docker_installed_now = False
    docker_version = ""
    compose_version = ""
    image_id = ""
    managed_retry = False

    try:
        cert = _validate_certificate(certificate)
        credentials = session.credentials()
        executor = executor_factory(
            credentials,
            expected_host_key_sha256=session.host_key_sha256,
            command_timeout=60,
        )

        stage = "root-check"
        uid = _run(executor, "id -u", stage=stage, timeout=20).stdout.strip()
        if uid != "0":
            raise NodeInstallError(stage, f"remote uid is {uid!r}; root is required")

        stage = "ownership-check"
        ownership = _run(
            executor,
            (
                "if [ -e /opt/marzban-node ] || [ -e /var/lib/marzban-node ]; "
                "then if [ -f /var/lib/marzban-node/.nvl-managed ]; "
                "then echo nvl; else echo unmanaged; fi; else echo fresh; fi"
            ),
            stage=stage,
            timeout=20,
        ).stdout.strip()
        if ownership == "unmanaged":
            raise NodeInstallError(
                stage,
                "existing Marzban-node files are not marked as NVL-managed; refusing to overwrite",
            )
        managed_retry = ownership == "nvl"

        stage = "port-recheck"
        before_ports = _listener_ports(executor)
        if not managed_retry:
            conflicts = [
                port
                for port in (session.service_port, session.api_port)
                if port in before_ports
            ]
            if conflicts:
                raise NodeInstallError(
                    stage,
                    "required ports became occupied after preflight: "
                    + ", ".join(str(port) for port in conflicts),
                )

        stage = "prerequisites"
        prereq_probe = executor.run(
            "command -v curl >/dev/null && "
            "dpkg -s ca-certificates >/dev/null 2>&1",
            timeout=20,
        )
        if prereq_probe.exit_code != 0:
            _run(
                executor,
                (
                    "apt-get update -qq && "
                    "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
                    "ca-certificates curl"
                ),
                stage=stage,
                timeout=300,
            )

        stage = "docker"
        docker_probe = executor.run("command -v docker", timeout=20)
        if docker_probe.exit_code != 0:
            _run(
                executor,
                (
                    "rm -f /tmp/nvl-get-docker.sh && "
                    "curl -fsSL https://get.docker.com -o /tmp/nvl-get-docker.sh && "
                    "sh /tmp/nvl-get-docker.sh && "
                    "rm -f /tmp/nvl-get-docker.sh"
                ),
                stage=stage,
                timeout=600,
            )
            docker_installed_now = True

        _run(
            executor,
            "systemctl enable --now docker",
            stage="docker-service",
            timeout=120,
        )
        docker_version = _run(
            executor,
            "docker --version",
            stage="docker-version",
            timeout=20,
        ).stdout.strip()

        stage = "compose"
        compose_probe = executor.run("docker compose version", timeout=30)
        if compose_probe.exit_code != 0:
            _run(
                executor,
                (
                    "apt-get update -qq && "
                    "(DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
                    "docker-compose-plugin || "
                    "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
                    "docker-compose-v2)"
                ),
                stage=stage,
                timeout=300,
            )
        compose_version = _run(
            executor,
            "docker compose version",
            stage="compose-version",
            timeout=30,
        ).stdout.strip()
        _run(
            executor,
            "docker info >/dev/null",
            stage="docker-daemon",
            timeout=60,
        )

        stage = "directories"
        _run(
            executor,
            (
                "install -d -m 755 /opt/marzban-node && "
                "install -d -m 700 /var/lib/marzban-node"
            ),
            stage=stage,
            timeout=30,
        )

        # Claim only the fresh directories that passed the unmanaged-install
        # guard above. Writing this marker first makes interrupted installs
        # safely retryable without ever adopting third-party files.
        executor.write_text(
            MANAGED_MARKER,
            "managed-by=NVL\ncomponent=marzban-node\n",
            mode=0o600,
        )

        stage = "write-config"
        executor.write_text(
            CERT_PATH,
            cert,
            mode=0o600,
        )
        executor.write_text(
            COMPOSE_PATH,
            _compose_text(session.service_port, session.api_port),
            mode=0o600,
        )

        _run(
            executor,
            (
                "test -s /var/lib/marzban-node/cert.pem && "
                "grep -q -- '-----BEGIN CERTIFICATE-----' "
                "/var/lib/marzban-node/cert.pem"
            ),
            stage="certificate-verify",
            timeout=20,
        )
        _run(
            executor,
            "docker compose -f /opt/marzban-node/docker-compose.yml config -q",
            stage="compose-validate",
            timeout=30,
        )

        stage = "image-pull"
        _run(
            executor,
            "docker compose -f /opt/marzban-node/docker-compose.yml -p marzban-node pull",
            stage=stage,
            timeout=600,
        )

        stage = "container-start"
        _run(
            executor,
            (
                "docker compose -f /opt/marzban-node/docker-compose.yml "
                "-p marzban-node up -d --remove-orphans"
            ),
            stage=stage,
            timeout=180,
        )

        stage = "container-verify"
        running = _run(
            executor,
            "docker inspect -f '{{.State.Running}}' marzban-node",
            stage=stage,
            timeout=30,
        ).stdout.strip().lower()
        if running != "true":
            raise NodeInstallError(stage, "Marzban-node container is not running")

        stage = "service-listener"
        wait_command = (
            "for i in $(seq 1 30); do "
            "ss -H -ltn | awk '{print $4}' | "
            f"grep -Eq ':{int(session.service_port)}$' && exit 0; "
            "sleep 1; done; exit 1"
        )
        _run(executor, wait_command, stage=stage, timeout=45)

        ports = _listener_ports(executor)
        image_result = executor.run(
            "docker image inspect gozargah/marzban-node:latest --format '{{.Id}}'",
            timeout=30,
        )
        if image_result.exit_code == 0:
            image_id = image_result.stdout.strip()

        report = NodeInstallReport(
            node_id=session.node_id,
            host=session.host,
            ssh_port=session.ssh_port,
            service_port=session.service_port,
            api_port=session.api_port,
            success=True,
            stage="remote-install-complete",
            docker_installed_now=docker_installed_now,
            docker_version=docker_version,
            compose_version=compose_version,
            container_running=True,
            service_port_listening=session.service_port in ports,
            api_port_listening=session.api_port in ports,
            image_id=image_id,
            managed_retry=managed_retry,
            observed_at=_now_text(),
        )
        session.stage = "REMOTE_INSTALL_COMPLETE"
        session.started_at = time.time()
        return report

    except Exception as exc:
        if isinstance(exc, NodeInstallError):
            failed_stage = exc.stage
            error_text = str(exc)
        else:
            failed_stage = stage
            error_text = f"{type(exc).__name__}: {exc}"
        session.stage = "INSTALL_FAILED"
        session.started_at = time.time()
        return NodeInstallReport(
            node_id=session.node_id,
            host=session.host,
            ssh_port=session.ssh_port,
            service_port=session.service_port,
            api_port=session.api_port,
            success=False,
            stage=failed_stage,
            docker_installed_now=docker_installed_now,
            docker_version=docker_version,
            compose_version=compose_version,
            image_id=image_id,
            managed_retry=managed_retry,
            observed_at=_now_text(),
            error=error_text[-1600:],
        )
    finally:
        session.scrub_secret()
        session.busy = False
        if executor is not None:
            try:
                executor.close()
            except Exception:
                pass
