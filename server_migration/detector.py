from __future__ import annotations

import ipaddress
import re
import shlex
from typing import Iterable, Optional

from .models import ServerCredentials, ServerFacts
from .ssh import RemoteExecutor


CMD_UID = "id -u"
CMD_OS = (
    ". /etc/os-release 2>/dev/null || true; "
    "printf '%s\t%s\t%s\n' \"$ID\" \"$VERSION_ID\" \"$PRETTY_NAME\""
)
CMD_ARCH = "uname -m"
CMD_PRIMARY_IPV4 = (
    "ip -4 route get 1.1.1.1 2>/dev/null | "
    "awk '{for(i=1;i<=NF;i++) if($i==\"src\"){print $(i+1); exit}}'"
)
CMD_MEMORY_MB = (
    "awk '/MemTotal:/ {printf \"%.0f\\n\", $2/1024}' /proc/meminfo"
)
CMD_ROOT_FREE_KB = "df -Pk / | awk 'NR==2 {print $4}'"
CMD_DOCKER_VERSION = (
    "command -v docker >/dev/null 2>&1 && docker --version 2>/dev/null || true"
)
CMD_COMPOSE_VERSION = "docker compose version 2>/dev/null || true"
CMD_COMPOSE_FILE = (
    "for f in "
    "/opt/marzban/docker-compose.yml "
    "/opt/marzban/docker-compose.yaml "
    "/opt/marzban/compose.yml "
    "/opt/marzban/compose.yaml "
    "/root/marzban/docker-compose.yml "
    "/root/marzban/docker-compose.yaml "
    "/srv/marzban/docker-compose.yml "
    "/srv/marzban/docker-compose.yaml; "
    "do if [ -f \"$f\" ]; then printf '%s\\n' \"$f\"; break; fi; done"
)
CMD_COMMON_DB = (
    "for f in /var/lib/marzban/db.sqlite3 /opt/marzban/db.sqlite3; "
    "do if [ -f \"$f\" ]; then printf '%s\\n' \"$f\"; break; fi; done"
)
CMD_COMMON_XRAY = (
    "for f in /var/lib/marzban/xray_config.json /opt/marzban/xray_config.json; "
    "do if [ -f \"$f\" ]; then printf '%s\\n' \"$f\"; break; fi; done"
)
CMD_LISTENERS = "ss -H -lntup 2>/dev/null || ss -H -lntp 2>/dev/null || true"
CMD_TOOLS = (
    "for c in tar gzip sha256sum python3; do "
    "command -v \"$c\" >/dev/null 2>&1 && printf '%s\\n' \"$c\"; done"
)
CMD_PAYLOAD_KB = (
    "du -sk /opt/marzban /var/lib/marzban /etc/letsencrypt "
    "2>/dev/null | awk '{s+=$1} END {print s+0}'"
)

# Regression tests use this tuple to enforce the Phase 1 no-mutation contract.
STATIC_READ_ONLY_COMMANDS = (
    CMD_UID,
    CMD_OS,
    CMD_ARCH,
    CMD_PRIMARY_IPV4,
    CMD_MEMORY_MB,
    CMD_ROOT_FREE_KB,
    CMD_DOCKER_VERSION,
    CMD_COMPOSE_VERSION,
    CMD_COMPOSE_FILE,
    CMD_COMMON_DB,
    CMD_COMMON_XRAY,
    CMD_LISTENERS,
    CMD_TOOLS,
    CMD_PAYLOAD_KB,
)

_DANGEROUS_TOKENS = (
    " rm ",
    " mv ",
    " cp ",
    " install ",
    " apt ",
    " apt-get ",
    " systemctl start",
    " systemctl stop",
    " systemctl restart",
    " docker compose up",
    " docker compose down",
    " docker compose stop",
    " docker compose start",
    " docker restart",
    " docker rm",
    " docker rmi",
    " sed -i",
    " sqlite3 ",
)


def assert_read_only_command(command: str) -> None:
    normalized = " " + " ".join(str(command).lower().split()) + " "
    for token in _DANGEROUS_TOKENS:
        if token in normalized:
            raise ValueError(f"mutating command rejected by Phase 1 guard: {token.strip()}")


def _run(executor: RemoteExecutor, command: str, timeout: int = 20):
    assert_read_only_command(command)
    return executor.run(command, timeout=timeout)


def _text(executor: RemoteExecutor, command: str, timeout: int = 20) -> str:
    result = _run(executor, command, timeout=timeout)
    if result.exit_code != 0:
        return ""
    return str(result.stdout or "").strip()


def _int(value: str, default: int = 0) -> int:
    try:
        return int(str(value or "").strip())
    except (TypeError, ValueError):
        return default


def _file_exists(executor: RemoteExecutor, path: str) -> bool:
    if not path:
        return False
    q = shlex.quote(path)
    return _text(executor, f"test -f {q} && printf yes || true") == "yes"


def _env_value(executor: RemoteExecutor, env_path: str, key: str) -> str:
    if not env_path or not key:
        return ""
    q = shlex.quote(env_path)
    pattern = shlex.quote(rf"^[[:space:]]*{re.escape(key)}[[:space:]]*=")
    command = (
        f"grep -E {pattern} {q} 2>/dev/null | tail -n1 | "
        "cut -d= -f2- || true"
    )
    raw = _text(executor, command).strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in {'"', "'"}:
        raw = raw[1:-1]
    return raw.strip()


def _sqlite_path(database_url: str) -> str:
    raw = str(database_url or "").strip()
    prefix = "sqlite:///"
    if raw.startswith(prefix):
        return raw[len(prefix):]
    return ""


def _compose_images(
    executor: RemoteExecutor,
    compose_file: str,
    env_file: str,
) -> tuple[str, ...]:
    if not compose_file:
        return ()
    parts = ["docker", "compose", "-f", shlex.quote(compose_file)]
    if env_file and _file_exists(executor, env_file):
        parts.extend(["--env-file", shlex.quote(env_file)])
    parts.extend(["config", "--images"])
    output = _text(executor, " ".join(parts), timeout=30)
    return tuple(dict.fromkeys(line.strip() for line in output.splitlines() if line.strip()))


def _image_details(
    executor: RemoteExecutor,
    images: Iterable[str],
) -> tuple[str, ...]:
    details = []
    for image in images:
        q = shlex.quote(image)
        command = (
            "docker image inspect "
            "--format '{{.Id}}|{{.Architecture}}|{{.Os}}' "
            f"{q} 2>/dev/null || true"
        )
        value = _text(executor, command)
        if value:
            details.append(f"{image}|{value}")
    return tuple(details)


def _sqlite_integrity(executor: RemoteExecutor, db_path: str) -> str:
    if not db_path or not _file_exists(executor, db_path):
        return ""
    q = shlex.quote(db_path)
    code = (
        "import sqlite3,sys;"
        "c=sqlite3.connect(sys.argv[1]);"
        "print(c.execute('PRAGMA integrity_check').fetchone()[0]);"
        "c.close()"
    )
    return _text(executor, f"python3 -c {shlex.quote(code)} {q}", timeout=30)


def _xray_ports(executor: RemoteExecutor, path: str) -> tuple[int, ...]:
    if not path or not _file_exists(executor, path):
        return ()
    q = shlex.quote(path)
    code = (
        "import json,sys;"
        "d=json.load(open(sys.argv[1],encoding='utf-8'));"
        "print('\\n'.join(str(x.get('port')) for x in d.get('inbounds',[]) "
        "if isinstance(x,dict) and isinstance(x.get('port'),int)))"
    )
    output = _text(executor, f"python3 -c {shlex.quote(code)} {q}")
    values = {
        _int(line)
        for line in output.splitlines()
        if 1 <= _int(line) <= 65535
    }
    return tuple(sorted(values))


def _listener_ports(output: str) -> tuple[int, ...]:
    ports = set()
    for line in str(output or "").splitlines():
        for match in re.finditer(r"(?<!\d):(\d{1,5})\b", line):
            port = _int(match.group(1))
            if 1 <= port <= 65535:
                ports.add(port)
    return tuple(sorted(ports))


def _normalize_primary_ipv4(value: str) -> str:
    raw = str(value or "").strip()
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return ""
    return str(ip) if ip.version == 4 else ""


def inspect_server(
    executor: RemoteExecutor,
    credentials: ServerCredentials,
    *,
    role: str,
) -> ServerFacts:
    """Collect a read-only migration inventory from one SSH endpoint."""
    role = str(role or "").strip().lower()
    if role not in {"source", "destination"}:
        raise ValueError("role must be source or destination")

    uid_text = _text(executor, CMD_UID)
    uid = _int(uid_text, default=-1)
    uid = uid if uid >= 0 else None

    os_parts = (_text(executor, CMD_OS).split("\t", 2) + ["", "", ""])[:3]
    architecture = _text(executor, CMD_ARCH)
    primary_ipv4 = _normalize_primary_ipv4(_text(executor, CMD_PRIMARY_IPV4))
    memory_mb = _int(_text(executor, CMD_MEMORY_MB))
    root_free_mb = _int(_text(executor, CMD_ROOT_FREE_KB)) // 1024

    docker_version = _text(executor, CMD_DOCKER_VERSION)
    docker_installed = bool(docker_version)
    compose_version = _text(executor, CMD_COMPOSE_VERSION) if docker_installed else ""

    compose_file = _text(executor, CMD_COMPOSE_FILE)
    marzban_dir = compose_file.rsplit("/", 1)[0] if "/" in compose_file else ""
    env_file = f"{marzban_dir}/.env" if marzban_dir else ""
    if env_file and not _file_exists(executor, env_file):
        env_file = ""

    database_path = _text(executor, CMD_COMMON_DB)
    if not database_path and env_file:
        database_path = _sqlite_path(
            _env_value(executor, env_file, "SQLALCHEMY_DATABASE_URL")
        )
        if database_path and not _file_exists(executor, database_path):
            database_path = ""

    xray_path = _text(executor, CMD_COMMON_XRAY)
    if not xray_path and env_file:
        xray_path = _env_value(executor, env_file, "XRAY_JSON")
        if xray_path and not _file_exists(executor, xray_path):
            xray_path = ""

    api_port = None
    ssl_cert_path = ""
    ssl_key_path = ""
    if env_file:
        candidate = _int(_env_value(executor, env_file, "UVICORN_PORT"))
        api_port = candidate if 1 <= candidate <= 65535 else None
        ssl_cert_path = _env_value(executor, env_file, "UVICORN_SSL_CERTFILE")
        ssl_key_path = _env_value(executor, env_file, "UVICORN_SSL_KEYFILE")

    compose_images = ()
    image_details = ()
    if docker_installed and compose_file:
        compose_images = _compose_images(executor, compose_file, env_file)
        image_details = _image_details(executor, compose_images)

    listener_output = _text(executor, CMD_LISTENERS)
    required_tools = tuple(
        sorted(set(_text(executor, CMD_TOOLS).splitlines()))
    )
    payload_size_mb = (_int(_text(executor, CMD_PAYLOAD_KB)) + 1023) // 1024

    return ServerFacts(
        role=role,
        host=credentials.host,
        ssh_port=credentials.port,
        ssh_user=credentials.username,
        ssh_ok=True,
        uid=uid,
        os_id=os_parts[0].strip().lower(),
        os_version=os_parts[1].strip(),
        os_pretty_name=os_parts[2].strip(),
        architecture=architecture.strip(),
        primary_ipv4=primary_ipv4,
        memory_mb=memory_mb,
        root_free_mb=root_free_mb,
        docker_installed=docker_installed,
        docker_version=docker_version,
        compose_version=compose_version,
        marzban_compose_file=compose_file,
        marzban_dir=marzban_dir,
        marzban_env_file=env_file,
        database_path=database_path,
        database_integrity=_sqlite_integrity(executor, database_path),
        xray_config_path=xray_path,
        api_port=api_port,
        ssl_cert_path=ssl_cert_path,
        ssl_key_path=ssl_key_path,
        ssl_cert_exists=_file_exists(executor, ssl_cert_path),
        ssl_key_exists=_file_exists(executor, ssl_key_path),
        compose_images=compose_images,
        local_image_details=image_details,
        listener_ports=_listener_ports(listener_output),
        xray_ports=_xray_ports(executor, xray_path),
        required_tools=required_tools,
        payload_size_mb=payload_size_mb,
    )
