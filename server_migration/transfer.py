from __future__ import annotations

import os
import shlex
import shutil
from pathlib import Path, PurePosixPath

from .backup import parse_checksum_manifest, sha256_file
from .phase2_models import (
    BundleArtifact,
    Phase2Error,
    Phase2Policy,
    SourceBundle,
    TransferReport,
)
from .ssh import RemoteExecutor


def _run_checked(
    executor: RemoteExecutor,
    command: str,
    *,
    timeout: int = 60,
    label: str = "remote command",
):
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


def _require_file_transport(executor, method: str):
    callback = getattr(executor, method, None)
    if not callable(callback):
        raise Phase2Error(
            f"executor does not support required file transport method: {method}"
        )
    return callback


def _safe_remote_root(value: str) -> str:
    raw = str(value or "").strip()
    path = PurePosixPath(raw)
    if (
        not raw.startswith("/")
        or raw == "/"
        or ".." in path.parts
        or "\n" in raw
        or "\r" in raw
    ):
        raise Phase2Error(f"unsafe remote migration root: {raw!r}")
    return str(path)


def _prepare_local_bundle_dir(
    local_root: str,
    bundle: SourceBundle,
    policy: Phase2Policy,
) -> Path:
    root = Path(local_root).expanduser().resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(root, 0o700)

    local_dir = root / bundle.job_id / "bundle"
    if local_dir.exists():
        raise Phase2Error(f"local migration staging already exists: {local_dir}")

    required = bundle.total_size_bytes + max(
        0, int(policy.minimum_local_reserve_mb)
    ) * 1024 * 1024
    free = shutil.disk_usage(root).free
    if free < required:
        raise Phase2Error(
            f"insufficient NVL staging disk: free={free} required={required}"
        )

    local_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chmod(local_dir.parent, 0o700)
    os.chmod(local_dir, 0o700)
    return local_dir


def _read_local_manifest(path: Path) -> dict[str, str]:
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as exc:
        raise Phase2Error(f"cannot read local SHA256SUMS: {exc}") from exc
    return parse_checksum_manifest(text)


def _verify_local_bundle(
    local_dir: Path,
    bundle: SourceBundle,
) -> tuple[BundleArtifact, ...]:
    expected = {artifact.name: artifact for artifact in bundle.artifacts}
    manifest = _read_local_manifest(local_dir / bundle.checksum_file)

    if set(manifest) != set(expected):
        raise Phase2Error("local SHA256SUMS artifact set does not match source bundle")

    verified = []
    for name in sorted(expected):
        artifact = expected[name]
        path = local_dir / name
        if not path.is_file():
            raise Phase2Error(f"downloaded artifact is missing: {name}")
        size = path.stat().st_size
        if size != artifact.size_bytes:
            raise Phase2Error(
                f"downloaded artifact size mismatch for {name}: "
                f"{size} != {artifact.size_bytes}"
            )
        digest = sha256_file(os.fspath(path))
        if digest != artifact.sha256 or digest != manifest[name]:
            raise Phase2Error(f"downloaded artifact checksum mismatch: {name}")
        os.chmod(path, 0o600)
        verified.append(artifact)

    os.chmod(local_dir / bundle.checksum_file, 0o600)
    return tuple(verified)


def relay_bundle(
    source_executor,
    destination_executor,
    bundle: SourceBundle,
    *,
    policy: Phase2Policy | None = None,
) -> TransferReport:
    """Relay a verified bundle Source -> NVL local staging -> Destination.

    Destination writes are isolated under /root/nvl-migrations/<job>/incoming.
    Runtime Marzban paths are never touched in Phase 2.
    """
    policy = policy or Phase2Policy()
    source_download = _require_file_transport(source_executor, "download")
    destination_upload = _require_file_transport(destination_executor, "upload")

    local_dir = _prepare_local_bundle_dir(policy.local_root, bundle, policy)

    remote_manifest = (
        f"{bundle.remote_bundle_dir.rstrip('/')}/{bundle.checksum_file}"
    )
    local_manifest = local_dir / bundle.checksum_file
    source_download(remote_manifest, os.fspath(local_manifest))

    for artifact in bundle.artifacts:
        source_path = f"{bundle.remote_bundle_dir.rstrip('/')}/{artifact.name}"
        local_path = local_dir / artifact.name
        source_download(source_path, os.fspath(local_path))

    verified_artifacts = _verify_local_bundle(local_dir, bundle)

    remote_root = _safe_remote_root(policy.remote_root)
    destination_job_dir = f"{remote_root.rstrip('/')}/{bundle.job_id}"
    destination_bundle_dir = f"{destination_job_dir}/incoming"

    # Refuse to overwrite any previous/incomplete job. A new job_id is required
    # for retry, preserving forensic evidence from the failed attempt.
    prepare_command = (
        f"test ! -e {shlex.quote(destination_job_dir)} || exit 42; "
        f"install -d -m 700 {shlex.quote(destination_bundle_dir)}"
    )
    _run_checked(
        destination_executor,
        prepare_command,
        timeout=30,
        label="create destination staging directory",
    )

    # Upload artifacts first. SHA256SUMS is uploaded last as the completion
    # marker, then the destination independently re-hashes every artifact.
    for artifact in verified_artifacts:
        destination_upload(
            os.fspath(local_dir / artifact.name),
            f"{destination_bundle_dir}/{artifact.name}",
        )
    destination_upload(
        os.fspath(local_manifest),
        f"{destination_bundle_dir}/{bundle.checksum_file}",
    )

    verify_command = (
        f"cd {shlex.quote(destination_bundle_dir)} && "
        f"sha256sum -c {shlex.quote(bundle.checksum_file)}"
    )
    result = _run_checked(
        destination_executor,
        verify_command,
        timeout=300,
        label="destination checksum verification",
    )

    ok_lines = [
        line for line in str(result.stdout or "").splitlines()
        if line.rstrip().endswith(": OK")
    ]
    if len(ok_lines) != len(verified_artifacts):
        raise Phase2Error(
            "destination checksum command succeeded but did not confirm every artifact"
        )

    return TransferReport(
        job_id=bundle.job_id,
        local_bundle_dir=os.fspath(local_dir),
        destination_bundle_dir=destination_bundle_dir,
        artifacts=verified_artifacts,
        source_verified=True,
        local_verified=True,
        destination_verified=True,
    )
