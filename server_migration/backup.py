from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import shlex
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Iterable

from .models import ServerFacts
from .phase2_models import (
    PHASE2_SCHEMA_VERSION,
    BundleArtifact,
    Phase2Error,
    Phase2Policy,
    SourceBundle,
)
from .ssh import RemoteExecutor


_JOB_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,63}$")
_SHA_RE = re.compile(r"^([0-9a-fA-F]{64})[ \t]+\*?([^\r\n]+)$")

FORBIDDEN_RUNTIME_MUTATIONS = (
    "docker compose stop",
    "docker compose down",
    "docker compose start",
    "docker compose up",
    "docker restart",
    "systemctl stop",
    "systemctl start",
    "systemctl restart",
    "service marzban",
    "service docker",
    "reboot",
    "shutdown",
    "ufw ",
    "iptables ",
    "nft ",
)


def new_job_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"chg-{stamp}-{secrets.token_hex(4)}"


def validate_job_id(value: str) -> str:
    value = str(value or "").strip()
    if not _JOB_RE.fullmatch(value):
        raise Phase2Error(
            "invalid migration job id; expected 8-64 safe characters"
        )
    return value


def _safe_abs_path(value: str, *, label: str) -> str:
    raw = str(value or "").strip()
    path = PurePosixPath(raw)
    if not raw.startswith("/") or ".." in path.parts or "\n" in raw or "\r" in raw:
        raise Phase2Error(f"unsafe {label} path: {raw!r}")
    if raw == "/":
        raise Phase2Error(f"{label} path cannot be filesystem root")
    return str(path)


def _is_within(path: str, parent: str) -> bool:
    try:
        PurePosixPath(path).relative_to(PurePosixPath(parent))
        return True
    except ValueError:
        return False


def _assert_runtime_safe(command: str) -> None:
    normalized = " ".join(str(command or "").lower().split())
    for token in FORBIDDEN_RUNTIME_MUTATIONS:
        if token in normalized:
            raise Phase2Error(
                f"Phase 2 runtime mutation rejected: {token.strip()}"
            )


def _run_checked(
    executor: RemoteExecutor,
    command: str,
    *,
    timeout: int = 60,
    label: str = "remote command",
):
    _assert_runtime_safe(command)
    result = executor.run(command, timeout=timeout)
    if int(result.exit_code) != 0:
        detail = (result.stderr or result.stdout or "").strip()
        if len(detail) > 1200:
            detail = detail[-1200:]
        raise Phase2Error(
            f"{label} failed with exit code {result.exit_code}"
            + (f": {detail}" if detail else "")
        )
    return result


def _run_text(
    executor: RemoteExecutor,
    command: str,
    *,
    timeout: int = 60,
    label: str = "remote command",
) -> str:
    return str(
        _run_checked(executor, command, timeout=timeout, label=label).stdout or ""
    ).strip()


def _remote_dir_exists(executor: RemoteExecutor, path: str) -> bool:
    q = shlex.quote(path)
    result = executor.run(f"test -d {q}", timeout=10)
    return int(result.exit_code) == 0


def _remote_file_size(executor: RemoteExecutor, path: str) -> int:
    q = shlex.quote(path)
    raw = _run_text(
        executor,
        f"wc -c < {q}",
        timeout=30,
        label=f"size check for {PurePosixPath(path).name}",
    )
    try:
        return int(raw)
    except ValueError as exc:
        raise Phase2Error(f"invalid remote file size for {path}: {raw!r}") from exc


def parse_checksum_manifest(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = _SHA_RE.fullmatch(line)
        if not match:
            raise Phase2Error(f"invalid SHA256SUMS line: {raw_line!r}")
        digest = match.group(1).lower()
        name = match.group(2).strip()
        if name.startswith("./"):
            name = name[2:]
        if (
            not name
            or "/" in name
            or "\\" in name
            or name in {".", ".."}
            or name.startswith("-")
        ):
            raise Phase2Error(f"unsafe artifact name in SHA256SUMS: {name!r}")
        if name in result:
            raise Phase2Error(f"duplicate artifact in SHA256SUMS: {name}")
        result[name] = digest
    if not result:
        raise Phase2Error("empty SHA256SUMS")
    return result


def _metadata_for_bundle(
    source: ServerFacts,
    *,
    job_id: str,
    config_parent: str,
    config_basename: str,
    data_parent: str,
    data_basename: str,
    runtime_extras: Iterable[str],
    letsencrypt_included: bool,
) -> dict:
    return {
        "schema_version": PHASE2_SCHEMA_VERSION,
        "job_id": job_id,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": {
            "host": source.host,
            "primary_ipv4": source.primary_ipv4,
            "os_id": source.os_id,
            "os_version": source.os_version,
            "architecture": source.architecture,
        },
        "marzban": {
            "compose_file": source.marzban_compose_file,
            "directory": source.marzban_dir,
            "environment_file": source.marzban_env_file,
            "database_path": source.database_path,
            "xray_config_path": source.xray_config_path,
            "api_port": source.api_port,
            "ssl_cert_path": source.ssl_cert_path,
            "ssl_key_path": source.ssl_key_path,
            "compose_images": list(source.compose_images),
            "local_image_details": list(source.local_image_details),
        },
        "archives": {
            "config_restore_parent": config_parent,
            "config_member_root": config_basename,
            "data_restore_parent": data_parent,
            "data_member_root": data_basename,
            "letsencrypt_restore_parent": "/" if letsencrypt_included else None,
            "runtime_extras_restore_parent": "/" if tuple(runtime_extras) else None,
        },
        "runtime_extras": list(runtime_extras),
        "letsencrypt_included": bool(letsencrypt_included),
        "database_snapshot_method": "python-sqlite3-backup-api",
    }


def _validate_source(source: ServerFacts) -> tuple[str, str, str, str]:
    if source.role != "source":
        raise Phase2Error("source facts must have role=source")
    if str(source.database_integrity or "").lower() != "ok":
        raise Phase2Error("source SQLite integrity must be ok before Phase 2")
    if not source.marzban_dir or not source.marzban_compose_file:
        raise Phase2Error("source Marzban directory/compose file is missing")
    if not source.database_path:
        raise Phase2Error("source database path is missing")
    if not source.xray_config_path:
        raise Phase2Error("source Xray config path is missing")
    if not source.compose_images:
        raise Phase2Error("source compose image list is empty")
    if len(source.compose_images) != len(source.local_image_details):
        raise Phase2Error("not all source compose images are locally inspectable")

    config_dir = _safe_abs_path(source.marzban_dir, label="Marzban directory")
    database_path = _safe_abs_path(source.database_path, label="database")
    data_dir = str(PurePosixPath(database_path).parent)
    if data_dir == "/":
        raise Phase2Error("database cannot live directly under filesystem root")
    return (
        config_dir,
        database_path,
        data_dir,
        PurePosixPath(database_path).name,
    )


def _write_remote_metadata(
    executor: RemoteExecutor,
    remote_path: str,
    metadata: dict,
) -> None:
    payload = json.dumps(
        metadata,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    encoded = base64.b64encode(payload).decode("ascii")
    code = (
        "import base64,pathlib,sys;"
        "p=pathlib.Path(sys.argv[1]);"
        "p.write_bytes(base64.b64decode(sys.argv[2]));"
        "p.chmod(0o600)"
    )
    command = (
        f"python3 -c {shlex.quote(code)} "
        f"{shlex.quote(remote_path)} {shlex.quote(encoded)}"
    )
    _run_checked(executor, command, label="write bundle metadata")


def _sqlite_live_backup(
    executor: RemoteExecutor,
    source_db: str,
    snapshot_db: str,
) -> None:
    code = (
        "import sqlite3,sys;"
        "src,dst=sys.argv[1],sys.argv[2];"
        "s=sqlite3.connect('file:'+src+'?mode=ro',uri=True,timeout=30);"
        "d=sqlite3.connect(dst,timeout=30);"
        "s.backup(d);"
        "a=s.execute('PRAGMA integrity_check').fetchone()[0];"
        "b=d.execute('PRAGMA integrity_check').fetchone()[0];"
        "d.close();s.close();"
        "print(str(a)+'|'+str(b));"
        "sys.exit(0 if str(a).lower()=='ok' and str(b).lower()=='ok' else 7)"
    )
    output = _run_text(
        executor,
        f"python3 -c {shlex.quote(code)} "
        f"{shlex.quote(source_db)} {shlex.quote(snapshot_db)}",
        timeout=180,
        label="live SQLite backup",
    )
    if output.strip().lower() != "ok|ok":
        raise Phase2Error(f"unexpected SQLite backup verification: {output!r}")


def _safe_remove_snapshot(
    executor: RemoteExecutor,
    snapshot_dir: str,
    remote_job_dir: str,
) -> None:
    expected_prefix = remote_job_dir.rstrip("/") + "/snapshot"
    if snapshot_dir != expected_prefix:
        raise Phase2Error("refusing to delete unexpected snapshot path")
    _run_checked(
        executor,
        f"rm -rf -- {shlex.quote(snapshot_dir)}",
        timeout=60,
        label="snapshot cleanup",
    )


def create_source_bundle(
    executor: RemoteExecutor,
    source: ServerFacts,
    *,
    job_id: str | None = None,
    policy: Phase2Policy | None = None,
) -> SourceBundle:
    """Create and verify a live migration bundle on the source server.

    Marzban/Xray are never stopped. SQLite is copied with Connection.backup(),
    while non-database runtime data is archived into an isolated job directory.
    """
    policy = policy or Phase2Policy()
    job_id = validate_job_id(job_id or new_job_id())

    config_dir, database_path, data_dir, database_name = _validate_source(source)
    config_parent = str(PurePosixPath(config_dir).parent)
    config_basename = PurePosixPath(config_dir).name
    data_parent = str(PurePosixPath(data_dir).parent)
    data_basename = PurePosixPath(data_dir).name

    remote_root = _safe_abs_path(policy.remote_root, label="remote migration root")
    remote_job_dir = f"{remote_root.rstrip('/')}/{job_id}"
    remote_bundle_dir = f"{remote_job_dir}/bundle"
    snapshot_dir = f"{remote_job_dir}/snapshot"
    snapshot_data_dir = f"{snapshot_dir}/{data_basename}"

    if _remote_dir_exists(executor, remote_job_dir):
        raise Phase2Error(
            f"source migration job already exists: {remote_job_dir}"
        )

    _run_checked(
        executor,
        "install -d -m 700 "
        + " ".join(
            shlex.quote(path)
            for path in (remote_job_dir, remote_bundle_dir, snapshot_data_dir)
        ),
        label="create source staging directories",
    )

    letsencrypt_included = _remote_dir_exists(executor, "/etc/letsencrypt")

    external_paths: list[str] = []
    candidates = [
        source.xray_config_path,
        source.ssl_cert_path if source.ssl_cert_exists else "",
        source.ssl_key_path if source.ssl_key_exists else "",
    ]
    for candidate in candidates:
        if not candidate:
            continue
        safe = _safe_abs_path(candidate, label="runtime extra")
        if not _is_within(safe, data_dir) and safe not in external_paths:
            external_paths.append(safe)

    metadata = _metadata_for_bundle(
        source,
        job_id=job_id,
        config_parent=config_parent,
        config_basename=config_basename,
        data_parent=data_parent,
        data_basename=data_basename,
        runtime_extras=tuple(external_paths),
        letsencrypt_included=letsencrypt_included,
    )
    _write_remote_metadata(
        executor,
        f"{remote_bundle_dir}/bundle.json",
        metadata,
    )

    config_archive = f"{remote_bundle_dir}/marzban-config.tar.gz"
    _run_checked(
        executor,
        "tar "
        f"-C {shlex.quote(config_parent)} "
        f"--exclude={shlex.quote(config_basename + '/backup')} "
        f"--exclude={shlex.quote(config_basename + '/backups')} "
        f"-czf {shlex.quote(config_archive)} "
        f"{shlex.quote(config_basename)}",
        timeout=180,
        label="archive Marzban config",
    )

    # Copy all non-database runtime files into the isolated snapshot tree.
    exclude_db = f"./{database_name}"
    copy_pipeline = (
        "set -o pipefail; "
        f"tar -C {shlex.quote(data_dir)} "
        f"--exclude={shlex.quote(exclude_db)} "
        f"--exclude={shlex.quote(exclude_db + '-wal')} "
        f"--exclude={shlex.quote(exclude_db + '-shm')} "
        "-cf - . | "
        f"tar -C {shlex.quote(snapshot_data_dir)} -xf -"
    )
    _run_checked(
        executor,
        f"bash -lc {shlex.quote(copy_pipeline)}",
        timeout=180,
        label="snapshot non-database Marzban data",
    )

    snapshot_db = f"{snapshot_data_dir}/{database_name}"
    _sqlite_live_backup(executor, database_path, snapshot_db)

    data_archive = f"{remote_bundle_dir}/marzban-data-snapshot.tar.gz"
    _run_checked(
        executor,
        f"tar -C {shlex.quote(snapshot_dir)} "
        f"-czf {shlex.quote(data_archive)} {shlex.quote(data_basename)}",
        timeout=180,
        label="archive Marzban data snapshot",
    )

    artifact_names = [
        "bundle.json",
        "marzban-config.tar.gz",
        "marzban-data-snapshot.tar.gz",
    ]

    if letsencrypt_included:
        letsencrypt_archive = f"{remote_bundle_dir}/etc-letsencrypt.tar.gz"
        _run_checked(
            executor,
            "tar -C / "
            f"-czf {shlex.quote(letsencrypt_archive)} etc/letsencrypt",
            timeout=180,
            label="archive Let's Encrypt data",
        )
        artifact_names.append("etc-letsencrypt.tar.gz")

    if external_paths:
        extras_archive = f"{remote_bundle_dir}/runtime-extras.tar.gz"
        members = " ".join(
            shlex.quote(path.lstrip("/")) for path in external_paths
        )
        _run_checked(
            executor,
            f"tar -C / -czf {shlex.quote(extras_archive)} {members}",
            timeout=180,
            label="archive external runtime files",
        )
        artifact_names.append("runtime-extras.tar.gz")

    image_archive = f"{remote_bundle_dir}/docker-images.tar.gz"
    quoted_images = " ".join(shlex.quote(image) for image in source.compose_images)
    docker_pipeline = (
        "set -o pipefail; "
        f"docker save {quoted_images} | gzip -1 > {shlex.quote(image_archive)}"
    )
    _run_checked(
        executor,
        f"bash -lc {shlex.quote(docker_pipeline)}",
        timeout=900,
        label="export Docker images",
    )
    artifact_names.append("docker-images.tar.gz")

    for name in artifact_names:
        _run_checked(
            executor,
            f"test -s {shlex.quote(remote_bundle_dir + '/' + name)}",
            timeout=20,
            label=f"artifact presence check: {name}",
        )

    checksum_path = f"{remote_bundle_dir}/SHA256SUMS"
    checksum_command = (
        f"cd {shlex.quote(remote_bundle_dir)} && "
        "sha256sum "
        + " ".join(shlex.quote(name) for name in artifact_names)
        + " > SHA256SUMS && sha256sum -c SHA256SUMS"
    )
    _run_checked(
        executor,
        checksum_command,
        timeout=300,
        label="source checksum verification",
    )

    manifest_text = _run_text(
        executor,
        f"cat {shlex.quote(checksum_path)}",
        label="read checksum manifest",
    )
    checksums = parse_checksum_manifest(manifest_text)
    if set(checksums) != set(artifact_names):
        raise Phase2Error(
            "source checksum manifest does not match expected artifact set"
        )

    artifacts = []
    for name in artifact_names:
        remote_path = f"{remote_bundle_dir}/{name}"
        artifacts.append(
            BundleArtifact(
                name=name,
                sha256=checksums[name],
                size_bytes=_remote_file_size(executor, remote_path),
            )
        )

    if not policy.keep_source_snapshot_tree:
        _safe_remove_snapshot(executor, snapshot_dir, remote_job_dir)

    return SourceBundle(
        job_id=job_id,
        source_host=source.host,
        remote_job_dir=remote_job_dir,
        remote_bundle_dir=remote_bundle_dir,
        checksum_file="SHA256SUMS",
        artifacts=tuple(artifacts),
        metadata=metadata,
    )


def sha256_file(path: str, *, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()
