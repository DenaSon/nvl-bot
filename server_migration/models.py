from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Optional


CHECK_PASS = "PASS"
CHECK_WARN = "WARN"
CHECK_FAIL = "FAIL"


@dataclass(frozen=True)
class ServerCredentials:
    host: str
    port: int = 22
    username: str = "root"
    password: Optional[str] = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        host = str(self.host or "").strip()
        username = str(self.username or "").strip()
        if not host:
            raise ValueError("host is required")
        if not username:
            raise ValueError("username is required")
        if not 1 <= int(self.port) <= 65535:
            raise ValueError("port must be between 1 and 65535")
        object.__setattr__(self, "host", host)
        object.__setattr__(self, "username", username)
        object.__setattr__(self, "port", int(self.port))


@dataclass(frozen=True)
class CommandResult:
    command: str
    exit_code: int
    stdout: str = ""
    stderr: str = ""


@dataclass(frozen=True)
class ServerFacts:
    role: str
    host: str
    ssh_port: int
    ssh_user: str
    ssh_ok: bool = True
    uid: Optional[int] = None
    os_id: str = ""
    os_version: str = ""
    os_pretty_name: str = ""
    architecture: str = ""
    primary_ipv4: str = ""
    memory_mb: int = 0
    root_free_mb: int = 0
    docker_installed: bool = False
    docker_version: str = ""
    compose_version: str = ""
    marzban_compose_file: str = ""
    marzban_dir: str = ""
    marzban_env_file: str = ""
    database_path: str = ""
    database_integrity: str = ""
    xray_config_path: str = ""
    api_port: Optional[int] = None
    ssl_cert_path: str = ""
    ssl_key_path: str = ""
    ssl_cert_exists: bool = False
    ssl_key_exists: bool = False
    compose_images: tuple[str, ...] = ()
    local_image_details: tuple[str, ...] = ()
    listener_ports: tuple[int, ...] = ()
    xray_ports: tuple[int, ...] = ()
    required_tools: tuple[str, ...] = ()
    payload_size_mb: int = 0


@dataclass(frozen=True)
class PreflightCheck:
    code: str
    status: str
    role: str
    message: str
    blocking: bool = False


@dataclass(frozen=True)
class PreflightPolicy:
    supported_os: tuple[str, ...] = ("ubuntu", "debian")
    supported_architectures: tuple[str, ...] = (
        "x86_64",
        "amd64",
        "aarch64",
        "arm64",
    )
    minimum_destination_memory_mb: int = 512
    minimum_destination_free_mb: int = 4096
    destination_payload_multiplier: float = 2.0
    destination_payload_reserve_mb: int = 1024
    require_clean_destination: bool = True


@dataclass(frozen=True)
class MigrationPreflightReport:
    source: Optional[ServerFacts]
    destination: Optional[ServerFacts]
    checks: tuple[PreflightCheck, ...]
    ready: bool
    observed_at: str
    source_error: str = ""
    destination_error: str = ""

    @property
    def blockers(self) -> tuple[PreflightCheck, ...]:
        return tuple(
            check for check in self.checks
            if check.status == CHECK_FAIL and check.blocking
        )

    @property
    def warnings(self) -> tuple[PreflightCheck, ...]:
        return tuple(check for check in self.checks if check.status == CHECK_WARN)

    def to_dict(self) -> dict:
        # Credentials never enter ServerFacts, so this representation cannot
        # accidentally serialize an SSH password.
        return {
            "source": asdict(self.source) if self.source else None,
            "destination": asdict(self.destination) if self.destination else None,
            "checks": [asdict(check) for check in self.checks],
            "ready": self.ready,
            "observed_at": self.observed_at,
            "source_error": self.source_error,
            "destination_error": self.destination_error,
        }


def utc_now_text() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
