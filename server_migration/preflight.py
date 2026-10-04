from __future__ import annotations

import math
from typing import Callable, Optional

from .detector import inspect_server
from .models import (
    CHECK_FAIL,
    CHECK_PASS,
    CHECK_WARN,
    MigrationPreflightReport,
    PreflightCheck,
    PreflightPolicy,
    ServerCredentials,
    ServerFacts,
    utc_now_text,
)
from .ssh import ParamikoRemoteExecutor


ExecutorFactory = Callable[[ServerCredentials], object]


def _check(
    checks: list[PreflightCheck],
    code: str,
    status: str,
    role: str,
    message: str,
    *,
    blocking: bool = False,
) -> None:
    checks.append(
        PreflightCheck(
            code=code,
            status=status,
            role=role,
            message=message,
            blocking=blocking,
        )
    )


def _supported(value: str, allowed: tuple[str, ...]) -> bool:
    return str(value or "").strip().lower() in {
        str(item).strip().lower() for item in allowed
    }


def _evaluate_endpoint(
    facts: Optional[ServerFacts],
    error: str,
    *,
    role: str,
    policy: PreflightPolicy,
    checks: list[PreflightCheck],
) -> None:
    if facts is None:
        _check(
            checks,
            f"{role.upper()}_SSH",
            CHECK_FAIL,
            role,
            error or f"{role} SSH inspection failed",
            blocking=True,
        )
        return

    _check(
        checks,
        f"{role.upper()}_SSH",
        CHECK_PASS,
        role,
        f"SSH reachable at {facts.host}:{facts.ssh_port}",
    )

    if facts.uid == 0:
        _check(checks, f"{role.upper()}_ROOT", CHECK_PASS, role, "root privileges confirmed")
    else:
        _check(
            checks,
            f"{role.upper()}_ROOT",
            CHECK_FAIL,
            role,
            "root privileges are required for migration",
            blocking=True,
        )

    if _supported(facts.os_id, policy.supported_os):
        _check(
            checks,
            f"{role.upper()}_OS",
            CHECK_PASS,
            role,
            facts.os_pretty_name or facts.os_id,
        )
    else:
        _check(
            checks,
            f"{role.upper()}_OS",
            CHECK_FAIL,
            role,
            f"unsupported OS: {facts.os_pretty_name or facts.os_id or 'unknown'}",
            blocking=True,
        )

    if _supported(facts.architecture, policy.supported_architectures):
        _check(
            checks,
            f"{role.upper()}_ARCH",
            CHECK_PASS,
            role,
            f"architecture: {facts.architecture}",
        )
    else:
        _check(
            checks,
            f"{role.upper()}_ARCH",
            CHECK_FAIL,
            role,
            f"unsupported architecture: {facts.architecture or 'unknown'}",
            blocking=True,
        )

    missing_tools = sorted(
        {"tar", "gzip", "sha256sum", "python3"} - set(facts.required_tools)
    )
    if missing_tools:
        _check(
            checks,
            f"{role.upper()}_TOOLS",
            CHECK_FAIL,
            role,
            "missing required tools: " + ", ".join(missing_tools),
            blocking=True,
        )
    else:
        _check(
            checks,
            f"{role.upper()}_TOOLS",
            CHECK_PASS,
            role,
            "required transfer and verification tools are available",
        )


def _evaluate_source(
    facts: Optional[ServerFacts],
    checks: list[PreflightCheck],
) -> None:
    if facts is None:
        return

    if facts.docker_installed and facts.compose_version:
        _check(checks, "SOURCE_DOCKER", CHECK_PASS, "source", facts.docker_version)
        _check(checks, "SOURCE_COMPOSE", CHECK_PASS, "source", facts.compose_version)
    else:
        _check(
            checks,
            "SOURCE_DOCKER",
            CHECK_FAIL,
            "source",
            "Docker and Docker Compose are required on source",
            blocking=True,
        )

    if facts.marzban_compose_file:
        _check(
            checks,
            "SOURCE_MARZBAN",
            CHECK_PASS,
            "source",
            f"Marzban compose detected: {facts.marzban_compose_file}",
        )
    else:
        _check(
            checks,
            "SOURCE_MARZBAN",
            CHECK_FAIL,
            "source",
            "Marzban compose file was not detected",
            blocking=True,
        )

    if facts.database_path and facts.database_integrity.lower() == "ok":
        _check(
            checks,
            "SOURCE_DATABASE",
            CHECK_PASS,
            "source",
            f"SQLite integrity OK: {facts.database_path}",
        )
    else:
        detail = (
            f"database={facts.database_path or 'not found'}, "
            f"integrity={facts.database_integrity or 'unknown'}"
        )
        _check(
            checks,
            "SOURCE_DATABASE",
            CHECK_FAIL,
            "source",
            detail,
            blocking=True,
        )

    if facts.xray_config_path:
        _check(
            checks,
            "SOURCE_XRAY",
            CHECK_PASS,
            "source",
            f"Xray config detected: {facts.xray_config_path}",
        )
    else:
        _check(
            checks,
            "SOURCE_XRAY",
            CHECK_FAIL,
            "source",
            "Xray config was not detected",
            blocking=True,
        )

    if facts.compose_images and len(facts.local_image_details) == len(facts.compose_images):
        _check(
            checks,
            "SOURCE_IMAGES",
            CHECK_PASS,
            "source",
            "all compose images are available locally: "
            + ", ".join(facts.compose_images),
        )
    else:
        _check(
            checks,
            "SOURCE_IMAGES",
            CHECK_FAIL,
            "source",
            "one or more compose images cannot be inspected locally",
            blocking=True,
        )

    if facts.ssl_cert_path or facts.ssl_key_path:
        if facts.ssl_cert_exists and facts.ssl_key_exists:
            _check(
                checks,
                "SOURCE_TLS",
                CHECK_PASS,
                "source",
                "configured TLS certificate and key exist",
            )
        else:
            _check(
                checks,
                "SOURCE_TLS",
                CHECK_FAIL,
                "source",
                "configured TLS certificate/key is missing",
                blocking=True,
            )
    else:
        _check(
            checks,
            "SOURCE_TLS",
            CHECK_WARN,
            "source",
            "no Uvicorn TLS certificate paths detected in Marzban .env",
        )

    service_ports = set(facts.xray_ports)
    if facts.api_port:
        service_ports.add(facts.api_port)
    if service_ports:
        missing = sorted(service_ports - set(facts.listener_ports))
        if missing:
            _check(
                checks,
                "SOURCE_LISTENERS",
                CHECK_WARN,
                "source",
                "configured service ports not currently listening: "
                + ", ".join(str(p) for p in missing),
            )
        else:
            _check(
                checks,
                "SOURCE_LISTENERS",
                CHECK_PASS,
                "source",
                "configured Xray/API ports are listening",
            )
    else:
        _check(
            checks,
            "SOURCE_LISTENERS",
            CHECK_WARN,
            "source",
            "no Xray/API service ports could be derived",
        )


def _evaluate_destination(
    facts: Optional[ServerFacts],
    *,
    policy: PreflightPolicy,
    checks: list[PreflightCheck],
) -> None:
    if facts is None:
        return

    if facts.memory_mb >= policy.minimum_destination_memory_mb:
        _check(
            checks,
            "DEST_MEMORY",
            CHECK_PASS,
            "destination",
            f"memory: {facts.memory_mb} MB",
        )
    else:
        _check(
            checks,
            "DEST_MEMORY",
            CHECK_FAIL,
            "destination",
            f"insufficient memory: {facts.memory_mb} MB",
            blocking=True,
        )

    if facts.docker_installed and facts.compose_version:
        _check(
            checks,
            "DEST_DOCKER",
            CHECK_PASS,
            "destination",
            "Docker and Docker Compose already available",
        )
    elif facts.docker_installed:
        _check(
            checks,
            "DEST_DOCKER",
            CHECK_WARN,
            "destination",
            "Docker exists but Compose plugin was not detected; Phase 2 must install it",
        )
    else:
        _check(
            checks,
            "DEST_DOCKER",
            CHECK_WARN,
            "destination",
            "Docker is not installed; Phase 2 must install it before restore",
        )

    destination_has_marzban = bool(
        facts.marzban_compose_file or facts.database_path or facts.xray_config_path
    )
    if destination_has_marzban and policy.require_clean_destination:
        _check(
            checks,
            "DEST_CLEAN",
            CHECK_FAIL,
            "destination",
            "destination already contains Marzban runtime data",
            blocking=True,
        )
    elif destination_has_marzban:
        _check(
            checks,
            "DEST_CLEAN",
            CHECK_WARN,
            "destination",
            "destination already contains Marzban runtime data",
        )
    else:
        _check(
            checks,
            "DEST_CLEAN",
            CHECK_PASS,
            "destination",
            "no existing Marzban runtime detected",
        )


def evaluate_preflight(
    source: Optional[ServerFacts],
    destination: Optional[ServerFacts],
    *,
    source_error: str = "",
    destination_error: str = "",
    policy: PreflightPolicy | None = None,
    observed_at: str | None = None,
) -> MigrationPreflightReport:
    policy = policy or PreflightPolicy()
    checks: list[PreflightCheck] = []

    _evaluate_endpoint(
        source,
        source_error,
        role="source",
        policy=policy,
        checks=checks,
    )
    _evaluate_endpoint(
        destination,
        destination_error,
        role="destination",
        policy=policy,
        checks=checks,
    )
    _evaluate_source(source, checks)
    _evaluate_destination(destination, policy=policy, checks=checks)

    if source is not None and destination is not None:
        same_host = source.host == destination.host
        same_ip = bool(
            source.primary_ipv4
            and destination.primary_ipv4
            and source.primary_ipv4 == destination.primary_ipv4
        )
        if same_host or same_ip:
            _check(
                checks,
                "PAIR_DISTINCT",
                CHECK_FAIL,
                "pair",
                "source and destination resolve to the same server",
                blocking=True,
            )
        else:
            _check(
                checks,
                "PAIR_DISTINCT",
                CHECK_PASS,
                "pair",
                "source and destination are distinct",
            )

        required_free = max(
            int(policy.minimum_destination_free_mb),
            int(
                math.ceil(
                    source.payload_size_mb * policy.destination_payload_multiplier
                    + policy.destination_payload_reserve_mb
                )
            ),
        )
        if destination.root_free_mb >= required_free:
            _check(
                checks,
                "DEST_DISK",
                CHECK_PASS,
                "destination",
                f"free disk {destination.root_free_mb} MB >= required {required_free} MB",
            )
        else:
            _check(
                checks,
                "DEST_DISK",
                CHECK_FAIL,
                "destination",
                f"free disk {destination.root_free_mb} MB < required {required_free} MB",
                blocking=True,
            )

        service_ports = set(source.xray_ports)
        if source.api_port:
            service_ports.add(source.api_port)
        conflicts = sorted(service_ports & set(destination.listener_ports))
        if conflicts:
            _check(
                checks,
                "DEST_PORTS",
                CHECK_FAIL,
                "destination",
                "destination already listens on migration service ports: "
                + ", ".join(str(p) for p in conflicts),
                blocking=True,
            )
        else:
            _check(
                checks,
                "DEST_PORTS",
                CHECK_PASS,
                "destination",
                "no destination conflicts on source Xray/API ports",
            )

    ready = not any(
        check.status == CHECK_FAIL and check.blocking
        for check in checks
    )
    return MigrationPreflightReport(
        source=source,
        destination=destination,
        checks=tuple(checks),
        ready=ready,
        observed_at=observed_at or utc_now_text(),
        source_error=source_error,
        destination_error=destination_error,
    )


def _inspect(
    credentials: ServerCredentials,
    *,
    role: str,
    executor_factory: ExecutorFactory,
) -> tuple[Optional[ServerFacts], str]:
    executor = None
    try:
        executor = executor_factory(credentials)
        return inspect_server(executor, credentials, role=role), ""
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"
    finally:
        if executor is not None:
            close = getattr(executor, "close", None)
            if callable(close):
                close()


def run_preflight(
    source_credentials: ServerCredentials,
    destination_credentials: ServerCredentials,
    *,
    executor_factory: ExecutorFactory = ParamikoRemoteExecutor,
    policy: PreflightPolicy | None = None,
) -> MigrationPreflightReport:
    """Inspect both servers and return a fail-closed, mutation-free report."""
    source, source_error = _inspect(
        source_credentials,
        role="source",
        executor_factory=executor_factory,
    )
    destination, destination_error = _inspect(
        destination_credentials,
        role="destination",
        executor_factory=executor_factory,
    )
    return evaluate_preflight(
        source,
        destination,
        source_error=source_error,
        destination_error=destination_error,
        policy=policy,
    )
