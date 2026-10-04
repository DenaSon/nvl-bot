from __future__ import annotations

import json
import posixpath
import re
import shlex
from pathlib import PurePosixPath
from typing import Iterable, Mapping

from .backup import parse_checksum_manifest, validate_job_id
from .models import ServerFacts
from .phase3_models import (
    PHASE3_MODE_INSPECT,
    PHASE3_MODE_RESTORE,
    Phase3Error,
    Phase3Policy,
)
from .ssh import RemoteExecutor


_REQUIRED_ARTIFACTS = {
    "bundle.json",
    "marzban-config.tar.gz",
    "marzban-data-snapshot.tar.gz",
    "docker-images.tar.gz",
}
_IMAGE_DETAIL_RE = re.compile(
    r"^(?P<tag>[^|]+)\|(?P<id>sha256:[0-9a-fA-F]{64})"
    r"\|(?P<arch>[^|]+)\|(?P<os>[^|]+)$"
)


def _safe_abs_path(value: str, *, label: str) -> str:
    raw = str(value or "").strip()
    path = PurePosixPath(raw)
    if (
        not raw.startswith("/")
        or raw == "/"
        or ".." in path.parts
        or "\n" in raw
        or "\r" in raw
        or "\x00" in raw
    ):
        raise Phase3Error(f"unsafe {label} path: {raw!r}")
    return str(path)


def _safe_remote_root(value: str) -> str:
    return _safe_abs_path(value, label="remote migration root")


def _preview_path(preview_root: str, absolute_path: str) -> str:
    absolute_path = _safe_abs_path(absolute_path, label="restore target")
    return preview_root.rstrip("/") + absolute_path


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
        if len(detail) > 1600:
            detail = detail[-1600:]
        raise Phase3Error(
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


def _exists(executor: RemoteExecutor, path: str) -> bool:
    result = executor.run(f"test -e {shlex.quote(path)}", timeout=10)
    return int(result.exit_code) == 0


def _is_dir(executor: RemoteExecutor, path: str) -> bool:
    result = executor.run(f"test -d {shlex.quote(path)}", timeout=10)
    return int(result.exit_code) == 0


def _command_exists(executor: RemoteExecutor, command: str) -> bool:
    result = executor.run(
        f"command -v {shlex.quote(command)} >/dev/null 2>&1",
        timeout=10,
    )
    return int(result.exit_code) == 0


def _load_json(executor: RemoteExecutor, path: str, *, label: str) -> dict:
    text = _run_text(
        executor,
        f"cat {shlex.quote(path)}",
        timeout=30,
        label=label,
    )
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise Phase3Error(f"invalid JSON in {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise Phase3Error(f"{label} must contain a JSON object")
    return value


def _validate_metadata(
    metadata: Mapping,
    *,
    job_id: str,
    policy: Phase3Policy,
) -> dict:
    data = dict(metadata or {})
    if int(data.get("schema_version") or 0) != int(
        policy.expected_bundle_schema_version
    ):
        raise Phase3Error(
            "unsupported bundle schema version: "
            f"{data.get('schema_version')!r}"
        )
    if str(data.get("job_id") or "") != job_id:
        raise Phase3Error("bundle job_id does not match requested migration job")

    source = data.get("source")
    marzban = data.get("marzban")
    archives = data.get("archives")
    if not isinstance(source, dict):
        raise Phase3Error("bundle source metadata is missing")
    if not isinstance(marzban, dict):
        raise Phase3Error("bundle Marzban metadata is missing")
    if not isinstance(archives, dict):
        raise Phase3Error("bundle archive metadata is missing")

    for key in ("directory", "database_path", "xray_config_path", "compose_file"):
        _safe_abs_path(marzban.get(key), label=f"metadata marzban.{key}")

    env_file = str(marzban.get("environment_file") or "").strip()
    if env_file:
        _safe_abs_path(env_file, label="metadata Marzban environment file")

    cert_path = str(marzban.get("ssl_cert_path") or "").strip()
    key_path = str(marzban.get("ssl_key_path") or "").strip()
    if cert_path:
        _safe_abs_path(cert_path, label="metadata TLS certificate")
    if key_path:
        _safe_abs_path(key_path, label="metadata TLS key")

    images = marzban.get("compose_images")
    details = marzban.get("local_image_details")
    if not isinstance(images, list) or not images:
        raise Phase3Error("bundle compose image list is empty")
    if not isinstance(details, list) or len(details) != len(images):
        raise Phase3Error("bundle image detail list is incomplete")

    runtime_extras = data.get("runtime_extras") or []
    if not isinstance(runtime_extras, list):
        raise Phase3Error("bundle runtime_extras must be a list")
    for path in runtime_extras:
        _safe_abs_path(path, label="runtime extra")

    return data


def verify_incoming_bundle(
    executor: RemoteExecutor,
    *,
    job_id: str,
    policy: Phase3Policy | None = None,
) -> tuple[str, dict, dict[str, str]]:
    policy = policy or Phase3Policy()
    job_id = validate_job_id(job_id)
    remote_root = _safe_remote_root(policy.remote_root)
    incoming_dir = f"{remote_root.rstrip('/')}/{job_id}/incoming"

    if not _is_dir(executor, incoming_dir):
        raise Phase3Error(
            f"destination incoming bundle does not exist: {incoming_dir}"
        )

    checksum_path = f"{incoming_dir}/SHA256SUMS"
    bundle_json_path = f"{incoming_dir}/bundle.json"
    for path in (checksum_path, bundle_json_path):
        if not _exists(executor, path):
            raise Phase3Error(f"required Phase 2 artifact is missing: {path}")

    verify = _run_checked(
        executor,
        f"cd {shlex.quote(incoming_dir)} && sha256sum -c SHA256SUMS",
        timeout=300,
        label="destination bundle checksum verification",
    )
    if "FAILED" in str(verify.stdout or "") or "FAILED" in str(verify.stderr or ""):
        raise Phase3Error("destination SHA256 verification reported a failure")

    manifest_text = _run_text(
        executor,
        f"cat {shlex.quote(checksum_path)}",
        label="read destination checksum manifest",
    )
    manifest = parse_checksum_manifest(manifest_text)

    missing = sorted(_REQUIRED_ARTIFACTS - set(manifest))
    if missing:
        raise Phase3Error(
            "destination bundle is missing required artifacts: "
            + ", ".join(missing)
        )

    metadata = _validate_metadata(
        _load_json(executor, bundle_json_path, label="bundle.json"),
        job_id=job_id,
        policy=policy,
    )

    if metadata.get("letsencrypt_included") and "etc-letsencrypt.tar.gz" not in manifest:
        raise Phase3Error(
            "bundle metadata requires etc-letsencrypt.tar.gz but it is absent"
        )

    runtime_extras = metadata.get("runtime_extras") or []
    if runtime_extras and "runtime-extras.tar.gz" not in manifest:
        raise Phase3Error(
            "bundle metadata requires runtime-extras.tar.gz but it is absent"
        )

    return incoming_dir, metadata, manifest


def _validate_tar_archive(
    executor: RemoteExecutor,
    archive_path: str,
    *,
    expected_prefix: str = "",
) -> int:
    expected_prefix = str(expected_prefix or "").strip("/")
    code = (
        "import posixpath,sys,tarfile;"
        "archive=sys.argv[1];prefix=sys.argv[2].strip('/');"
        "tf=tarfile.open(archive,'r:gz');count=0;"
        "\nfor m in tf.getmembers():"
        "\n n=m.name"
        "\n norm=posixpath.normpath(n)"
        "\n if (not n or n.startswith('/') or norm=='..' or norm.startswith('../') or '\\x00' in n): raise SystemExit('unsafe-member:'+repr(n))"
        "\n if prefix and not (norm==prefix or norm.startswith(prefix+'/')): raise SystemExit('unexpected-root:'+norm)"
        "\n if m.ischr() or m.isblk() or m.isfifo(): raise SystemExit('special-file:'+norm)"
        "\n if m.issym():"
        "\n  link=m.linkname"
        "\n  target=posixpath.normpath(posixpath.join(posixpath.dirname(norm),link))"
        "\n  if link.startswith('/') or target=='..' or target.startswith('../'): raise SystemExit('unsafe-symlink:'+norm)"
        "\n if m.islnk():"
        "\n  link=m.linkname"
        "\n  target=posixpath.normpath(link)"
        "\n  if link.startswith('/') or target=='..' or target.startswith('../'): raise SystemExit('unsafe-hardlink:'+norm)"
        "\n count+=1"
        "\ntf.close()"
        "\nprint(count)"
    )
    raw = _run_text(
        executor,
        f"python3 -c {shlex.quote(code)} "
        f"{shlex.quote(archive_path)} {shlex.quote(expected_prefix)}",
        timeout=180,
        label=f"archive safety validation: {PurePosixPath(archive_path).name}",
    )
    try:
        count = int(raw)
    except ValueError as exc:
        raise Phase3Error(
            f"invalid archive validation output for {archive_path}: {raw!r}"
        ) from exc
    if count <= 0:
        raise Phase3Error(f"archive is empty: {archive_path}")
    return count


def validate_bundle_archives(
    executor: RemoteExecutor,
    incoming_dir: str,
    metadata: Mapping,
    manifest: Mapping[str, str],
) -> None:
    archives = dict(metadata.get("archives") or {})
    config_root = str(archives.get("config_member_root") or "").strip("/")
    data_root = str(archives.get("data_member_root") or "").strip("/")
    if not config_root or "/" in config_root or config_root in {".", ".."}:
        raise Phase3Error("invalid config archive member root")
    if not data_root or "/" in data_root or data_root in {".", ".."}:
        raise Phase3Error("invalid data archive member root")

    _validate_tar_archive(
        executor,
        f"{incoming_dir}/marzban-config.tar.gz",
        expected_prefix=config_root,
    )
    _validate_tar_archive(
        executor,
        f"{incoming_dir}/marzban-data-snapshot.tar.gz",
        expected_prefix=data_root,
    )

    if "etc-letsencrypt.tar.gz" in manifest:
        _validate_tar_archive(
            executor,
            f"{incoming_dir}/etc-letsencrypt.tar.gz",
            expected_prefix="etc/letsencrypt",
        )

    if "runtime-extras.tar.gz" in manifest:
        _validate_tar_archive(
            executor,
            f"{incoming_dir}/runtime-extras.tar.gz",
        )


def inspect_docker_image_archive(
    executor: RemoteExecutor,
    incoming_dir: str,
    metadata: Mapping,
) -> tuple[bool, bool]:
    """Validate docker-save content without assuming Docker .Id semantics.

    Docker Engine 29 uses the containerd image store by default on fresh
    installs. In that store, docker image inspect .Id can identify a top-level
    OCI index/manifest rather than the image config digest. Therefore the
    Config member name in docker-save output is not required to equal the
    Phase 2 docker image inspect ID.

    Identity is instead bound by:
      1. Phase 2 end-to-end SHA256 of the whole docker-images.tar.gz,
      2. the expected RepoTag in manifest.json,
      3. a readable image config blob,
      4. matching architecture/OS from the config payload.
    """
    archive = f"{incoming_dir}/docker-images.tar.gz"
    _run_checked(
        executor,
        f"gzip -t {shlex.quote(archive)}",
        timeout=300,
        label="verify Docker image gzip stream",
    )
    code = (
        "import hashlib,json,sys,tarfile;"
        "p=sys.argv[1];"
        "tf=tarfile.open(p,'r:gz');"
        "m=tf.extractfile('manifest.json');"
        "\nif m is None: raise SystemExit('manifest.json missing')"
        "\ndata=json.load(m)"
        "\nif not isinstance(data,list) or not data: raise SystemExit('invalid manifest')"
        "\nout={}"
        "\nfor row in data:"
        "\n cfg_name=str(row.get('Config') or '')"
        "\n if not cfg_name: raise SystemExit('missing-config-member')"
        "\n cfg_member=tf.extractfile(cfg_name)"
        "\n if cfg_member is None: raise SystemExit('config-member-missing:'+cfg_name)"
        "\n cfg_bytes=cfg_member.read()"
        "\n cfg=json.loads(cfg_bytes.decode('utf-8'))"
        "\n item={'config_sha256':hashlib.sha256(cfg_bytes).hexdigest(),"
        "'architecture':str(cfg.get('architecture') or ''),"
        "'os':str(cfg.get('os') or '')}"
        "\n for tag in row.get('RepoTags') or []: out[str(tag)]=item"
        "\ntf.close()"
        "\nprint(json.dumps(out,sort_keys=True))"
    )
    raw = _run_text(
        executor,
        f"python3 -c {shlex.quote(code)} {shlex.quote(archive)}",
        timeout=300,
        label="inspect Docker image archive",
    )
    try:
        tag_to_config = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise Phase3Error(f"invalid Docker archive inspection output: {raw!r}") from exc
    if not isinstance(tag_to_config, dict) or not tag_to_config:
        raise Phase3Error("Docker archive contains no tagged images")

    marzban = dict(metadata.get("marzban") or {})
    expected_images = [str(x) for x in marzban.get("compose_images") or []]
    detail_rows = [str(x) for x in marzban.get("local_image_details") or []]

    expected_platforms: dict[str, tuple[str, str]] = {}
    for row in detail_rows:
        match = _IMAGE_DETAIL_RE.fullmatch(row)
        if not match:
            raise Phase3Error(f"invalid bundle image detail: {row!r}")
        expected_platforms[match.group("tag")] = (
            match.group("arch").lower(),
            match.group("os").lower(),
        )

    for tag in expected_images:
        item = tag_to_config.get(tag)
        if not isinstance(item, dict):
            raise Phase3Error(f"Docker archive is missing expected image tag: {tag}")

        config_sha = str(item.get("config_sha256") or "").lower()
        architecture = str(item.get("architecture") or "").lower()
        operating_system = str(item.get("os") or "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", config_sha):
            raise Phase3Error(
                f"Docker archive has invalid config digest for {tag}: {config_sha!r}"
            )

        expected = expected_platforms.get(tag)
        if expected is None:
            raise Phase3Error(f"missing expected image platform metadata for {tag}")
        expected_arch, expected_os = expected

        compatible_arch = {
            ("x86_64", "amd64"),
            ("amd64", "x86_64"),
            ("aarch64", "arm64"),
            ("arm64", "aarch64"),
        }
        if (
            architecture != expected_arch
            and (architecture, expected_arch) not in compatible_arch
        ):
            raise Phase3Error(
                f"Docker archive architecture mismatch for {tag}: "
                f"{architecture!r} != {expected_arch!r}"
            )
        if operating_system != expected_os:
            raise Phase3Error(
                f"Docker archive OS mismatch for {tag}: "
                f"{operating_system!r} != {expected_os!r}"
            )

    return True, True


def prepare_preview(
    executor: RemoteExecutor,
    *,
    job_id: str,
    incoming_dir: str,
    metadata: Mapping,
    manifest: Mapping[str, str],
    policy: Phase3Policy | None = None,
) -> str:
    policy = policy or Phase3Policy()
    remote_root = _safe_remote_root(policy.remote_root)
    preview_root = (
        f"{remote_root.rstrip('/')}/{validate_job_id(job_id)}/restore-preview"
    )
    if _exists(executor, preview_root):
        raise Phase3Error(
            f"restore preview already exists; refusing to overwrite: {preview_root}"
        )

    _run_checked(
        executor,
        f"install -d -m 700 {shlex.quote(preview_root)} "
        f"{shlex.quote(preview_root + '/opt')} "
        f"{shlex.quote(preview_root + '/var/lib')}",
        timeout=30,
        label="create restore preview",
    )

    commands = [
        (
            f"tar --no-same-owner -xzf "
            f"{shlex.quote(incoming_dir + '/marzban-config.tar.gz')} "
            f"-C {shlex.quote(preview_root + '/opt')}",
            "extract Marzban config preview",
        ),
        (
            f"tar --no-same-owner -xzf "
            f"{shlex.quote(incoming_dir + '/marzban-data-snapshot.tar.gz')} "
            f"-C {shlex.quote(preview_root + '/var/lib')}",
            "extract Marzban data preview",
        ),
    ]
    if "etc-letsencrypt.tar.gz" in manifest:
        commands.append(
            (
                f"tar --no-same-owner -xzf "
                f"{shlex.quote(incoming_dir + '/etc-letsencrypt.tar.gz')} "
                f"-C {shlex.quote(preview_root)}",
                "extract Let's Encrypt preview",
            )
        )
    if "runtime-extras.tar.gz" in manifest:
        commands.append(
            (
                f"tar --no-same-owner -xzf "
                f"{shlex.quote(incoming_dir + '/runtime-extras.tar.gz')} "
                f"-C {shlex.quote(preview_root)}",
                "extract runtime extras preview",
            )
        )

    for command, label in commands:
        _run_checked(executor, command, timeout=240, label=label)

    return preview_root


def preview_database_integrity(
    executor: RemoteExecutor,
    preview_root: str,
    metadata: Mapping,
) -> str:
    db_path = _safe_abs_path(
        dict(metadata.get("marzban") or {}).get("database_path"),
        label="database",
    )
    preview_db = _preview_path(preview_root, db_path)
    if not _exists(executor, preview_db):
        raise Phase3Error(f"restored preview database is missing: {preview_db}")

    code = (
        "import sqlite3,sys;"
        "c=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True,timeout=30);"
        "r=c.execute('PRAGMA integrity_check').fetchone()[0];"
        "c.close();print(r)"
    )
    result = _run_text(
        executor,
        f"python3 -c {shlex.quote(code)} {shlex.quote(preview_db)}",
        timeout=60,
        label="preview SQLite integrity check",
    )
    if result.strip().lower() != "ok":
        raise Phase3Error(f"preview SQLite integrity failed: {result!r}")
    return result.strip()


def preview_xray_ports(
    executor: RemoteExecutor,
    preview_root: str,
    metadata: Mapping,
) -> tuple[int, ...]:
    path = _safe_abs_path(
        dict(metadata.get("marzban") or {}).get("xray_config_path"),
        label="Xray config",
    )
    preview = _preview_path(preview_root, path)
    if not _exists(executor, preview):
        raise Phase3Error(f"restored preview Xray config is missing: {preview}")

    code = (
        "import json,sys;"
        "d=json.load(open(sys.argv[1],encoding='utf-8'));"
        "ports=sorted({int(x.get('port')) for x in d.get('inbounds',[]) "
        "if isinstance(x,dict) and isinstance(x.get('port'),int) "
        "and 1<=int(x.get('port'))<=65535});"
        "print(','.join(map(str,ports)))"
    )
    raw = _run_text(
        executor,
        f"python3 -c {shlex.quote(code)} {shlex.quote(preview)}",
        timeout=30,
        label="read preview Xray ports",
    )
    ports = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            value = int(item)
        except ValueError as exc:
            raise Phase3Error(f"invalid Xray port in preview: {item!r}") from exc
        if not 1 <= value <= 65535:
            raise Phase3Error(f"invalid Xray port in preview: {value}")
        ports.append(value)
    return tuple(sorted(set(ports)))


def _docker_ready(executor: RemoteExecutor) -> bool:
    if not _command_exists(executor, "docker"):
        return False
    result = executor.run("docker compose version >/dev/null 2>&1", timeout=20)
    return int(result.exit_code) == 0


def ensure_docker(
    executor: RemoteExecutor,
    *,
    policy: Phase3Policy,
) -> None:
    if _docker_ready(executor):
        return
    if policy.mode == PHASE3_MODE_INSPECT:
        raise Phase3Error(
            "Docker/Compose is required for compose validation in inspect-only mode"
        )
    if not policy.install_docker_if_missing:
        raise Phase3Error("Docker/Compose is missing on destination")
    if not _command_exists(executor, "apt-get"):
        raise Phase3Error(
            "automatic Docker preparation currently requires apt-get"
        )

    install = (
        "set -e; export DEBIAN_FRONTEND=noninteractive; "
        "apt-get update; "
        "apt-get install -y docker.io; "
        "(apt-get install -y docker-compose-v2 || "
        " apt-get install -y docker-compose-plugin); "
        "systemctl enable --now docker; "
        "docker --version; docker compose version"
    )
    _run_checked(
        executor,
        f"bash -lc {shlex.quote(install)}",
        timeout=900,
        label="install Docker and Compose",
    )
    if not _docker_ready(executor):
        raise Phase3Error("Docker installation completed but Compose is unavailable")


def validate_preview_compose(
    executor: RemoteExecutor,
    preview_root: str,
    metadata: Mapping,
) -> bool:
    marzban = dict(metadata.get("marzban") or {})
    compose = _preview_path(
        preview_root,
        _safe_abs_path(marzban.get("compose_file"), label="compose file"),
    )
    env_value = str(marzban.get("environment_file") or "").strip()
    env_file = (
        _preview_path(
            preview_root,
            _safe_abs_path(env_value, label="environment file"),
        )
        if env_value
        else ""
    )

    if not _exists(executor, compose):
        raise Phase3Error(f"preview compose file is missing: {compose}")
    if env_file and not _exists(executor, env_file):
        raise Phase3Error(f"preview environment file is missing: {env_file}")

    parts = ["docker", "compose", "-f", shlex.quote(compose)]
    if env_file:
        parts.extend(["--env-file", shlex.quote(env_file)])
    parts.append("config")
    _run_checked(
        executor,
        " ".join(parts) + " >/dev/null",
        timeout=60,
        label="Docker Compose config validation",
    )
    return True


def validate_restore_target(
    executor: RemoteExecutor,
    destination: ServerFacts,
    metadata: Mapping,
    xray_ports: Iterable[int],
    *,
    incoming_dir: str,
    policy: Phase3Policy,
) -> None:
    if policy.mode != PHASE3_MODE_RESTORE:
        return
    if destination.uid != 0:
        raise Phase3Error("Phase 3 restore requires root privileges")

    source = dict(metadata.get("source") or {})
    source_arch = str(source.get("architecture") or "").lower()
    dest_arch = str(destination.architecture or "").lower()
    compatible = {
        ("x86_64", "amd64"),
        ("amd64", "x86_64"),
        ("aarch64", "arm64"),
        ("arm64", "aarch64"),
    }
    if source_arch != dest_arch and (source_arch, dest_arch) not in compatible:
        raise Phase3Error(
            f"source/destination architecture mismatch: {source_arch} != {dest_arch}"
        )

    marzban = dict(metadata.get("marzban") or {})
    database_path = _safe_abs_path(
        marzban.get("database_path"),
        label="database",
    )
    data_dir = str(PurePosixPath(database_path).parent)
    config_dir = _safe_abs_path(
        marzban.get("directory"),
        label="Marzban directory",
    )

    targets = [config_dir, data_dir]
    if metadata.get("letsencrypt_included"):
        targets.append("/etc/letsencrypt")

    covered_roots = (config_dir.rstrip("/") + "/", data_dir.rstrip("/") + "/")
    for extra in metadata.get("runtime_extras") or []:
        extra = _safe_abs_path(extra, label="runtime extra")
        if extra == config_dir or extra == data_dir:
            continue
        if extra.startswith(covered_roots):
            continue
        if metadata.get("letsencrypt_included") and (
            extra == "/etc/letsencrypt"
            or extra.startswith("/etc/letsencrypt/")
        ):
            continue
        targets.append(extra)

    for target in dict.fromkeys(targets):
        if _exists(executor, target):
            raise Phase3Error(
                f"restore target already exists; refusing overwrite: {target}"
            )

    service_ports = set(int(p) for p in xray_ports)
    api_port = marzban.get("api_port")
    if isinstance(api_port, int) and 1 <= api_port <= 65535:
        service_ports.add(api_port)

    conflicts = sorted(service_ports & set(destination.listener_ports))
    if conflicts:
        raise Phase3Error(
            "destination already listens on restore service ports: "
            + ", ".join(str(p) for p in conflicts)
        )

    raw_size = _run_text(
        executor,
        f"du -sm {shlex.quote(incoming_dir)} | awk '{{print $1}}'",
        timeout=30,
        label="measure destination incoming bundle",
    )
    try:
        incoming_mb = int(raw_size)
    except ValueError as exc:
        raise Phase3Error(
            f"invalid incoming bundle size result: {raw_size!r}"
        ) from exc

    required = max(
        int(policy.minimum_destination_free_mb),
        incoming_mb * 3 + 512,
    )
    if int(destination.root_free_mb) < required:
        raise Phase3Error(
            f"insufficient destination disk for restore: "
            f"free={destination.root_free_mb} MB required={required} MB"
        )


def load_docker_images(
    executor: RemoteExecutor,
    incoming_dir: str,
    metadata: Mapping,
) -> bool:
    archive = f"{incoming_dir}/docker-images.tar.gz"
    _run_checked(
        executor,
        f"gzip -dc {shlex.quote(archive)} | docker load",
        timeout=900,
        label="load Docker images",
    )

    marzban = dict(metadata.get("marzban") or {})
    expected_platforms: dict[str, tuple[str, str]] = {}
    for row in marzban.get("local_image_details") or []:
        match = _IMAGE_DETAIL_RE.fullmatch(str(row))
        if not match:
            raise Phase3Error(f"invalid bundle image detail: {row!r}")
        expected_platforms[match.group("tag")] = (
            match.group("arch").lower(),
            match.group("os").lower(),
        )

    compatible_arch = {
        ("x86_64", "amd64"),
        ("amd64", "x86_64"),
        ("aarch64", "arm64"),
        ("arm64", "aarch64"),
    }

    for tag in marzban.get("compose_images") or []:
        tag = str(tag)
        expected = expected_platforms.get(tag)
        if expected is None:
            raise Phase3Error(f"missing expected image platform metadata for {tag}")

        actual = _run_text(
            executor,
            "docker image inspect "
            "--format '{{.Architecture}}|{{.Os}}' "
            f"{shlex.quote(tag)}",
            timeout=30,
            label=f"inspect loaded image {tag}",
        ).lower()
        parts = actual.split("|", 1)
        if len(parts) != 2:
            raise Phase3Error(
                f"unexpected loaded image inspection for {tag}: {actual!r}"
            )
        actual_arch, actual_os = parts
        expected_arch, expected_os = expected

        if (
            actual_arch != expected_arch
            and (actual_arch, expected_arch) not in compatible_arch
        ):
            raise Phase3Error(
                f"loaded Docker image architecture mismatch for {tag}: "
                f"{actual_arch!r} != {expected_arch!r}"
            )
        if actual_os != expected_os:
            raise Phase3Error(
                f"loaded Docker image OS mismatch for {tag}: "
                f"{actual_os!r} != {expected_os!r}"
            )

    return True


def _covered_runtime_extra(
    extra: str,
    *,
    config_dir: str,
    data_dir: str,
    letsencrypt: bool,
) -> bool:
    if extra == config_dir or extra.startswith(config_dir.rstrip("/") + "/"):
        return True
    if extra == data_dir or extra.startswith(data_dir.rstrip("/") + "/"):
        return True
    if letsencrypt and (
        extra == "/etc/letsencrypt"
        or extra.startswith("/etc/letsencrypt/")
    ):
        return True
    return False


def restore_runtime_from_preview(
    executor: RemoteExecutor,
    *,
    job_id: str,
    preview_root: str,
    metadata: Mapping,
    policy: Phase3Policy,
) -> None:
    if policy.mode != PHASE3_MODE_RESTORE:
        raise Phase3Error("runtime restore is disabled outside RESTORE mode")

    remote_root = _safe_remote_root(policy.remote_root)
    job_dir = f"{remote_root.rstrip('/')}/{validate_job_id(job_id)}"
    marker = f"{job_dir}/RESTORE_IN_PROGRESS"
    complete = f"{job_dir}/RESTORE_COMPLETE"
    if _exists(executor, marker) or _exists(executor, complete):
        raise Phase3Error("restore marker already exists for this migration job")

    marzban = dict(metadata.get("marzban") or {})
    config_dir = _safe_abs_path(marzban.get("directory"), label="Marzban directory")
    database_path = _safe_abs_path(marzban.get("database_path"), label="database")
    data_dir = str(PurePosixPath(database_path).parent)
    letsencrypt = bool(metadata.get("letsencrypt_included"))

    copies: list[tuple[str, str]] = [
        (_preview_path(preview_root, config_dir), config_dir),
        (_preview_path(preview_root, data_dir), data_dir),
    ]
    if letsencrypt:
        copies.append(
            (_preview_path(preview_root, "/etc/letsencrypt"), "/etc/letsencrypt")
        )

    for extra in metadata.get("runtime_extras") or []:
        extra = _safe_abs_path(extra, label="runtime extra")
        if _covered_runtime_extra(
            extra,
            config_dir=config_dir,
            data_dir=data_dir,
            letsencrypt=letsencrypt,
        ):
            continue
        copies.append((_preview_path(preview_root, extra), extra))

    for source_path, target in copies:
        if not _exists(executor, source_path):
            raise Phase3Error(f"preview restore source is missing: {source_path}")
        if _exists(executor, target):
            raise Phase3Error(f"runtime restore target already exists: {target}")

    _run_checked(
        executor,
        f"printf '%s\n' {shlex.quote(job_id)} > {shlex.quote(marker)}",
        timeout=20,
        label="write restore in-progress marker",
    )

    for source_path, target in copies:
        parent = str(PurePosixPath(target).parent)
        command = (
            f"mkdir -p -- {shlex.quote(parent)} && "
            f"test ! -e {shlex.quote(target)} && "
            f"cp -a -- {shlex.quote(source_path)} {shlex.quote(target)}"
        )
        _run_checked(
            executor,
            command,
            timeout=300,
            label=f"restore {target}",
        )

    _run_checked(
        executor,
        f"printf '%s\n' {shlex.quote(job_id)} > {shlex.quote(complete)} && "
        f"rm -f -- {shlex.quote(marker)}",
        timeout=20,
        label="write restore completion marker",
    )


def validate_restored_database(
    executor: RemoteExecutor,
    metadata: Mapping,
) -> str:
    db_path = _safe_abs_path(
        dict(metadata.get("marzban") or {}).get("database_path"),
        label="database",
    )
    code = (
        "import sqlite3,sys;"
        "c=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True,timeout=30);"
        "r=c.execute('PRAGMA integrity_check').fetchone()[0];"
        "c.close();print(r)"
    )
    raw = _run_text(
        executor,
        f"python3 -c {shlex.quote(code)} {shlex.quote(db_path)}",
        timeout=60,
        label="restored SQLite integrity check",
    )
    if raw.lower() != "ok":
        raise Phase3Error(f"restored SQLite integrity failed: {raw!r}")
    return raw


def validate_restored_compose(
    executor: RemoteExecutor,
    metadata: Mapping,
) -> bool:
    marzban = dict(metadata.get("marzban") or {})
    compose = _safe_abs_path(marzban.get("compose_file"), label="compose file")
    env_value = str(marzban.get("environment_file") or "").strip()
    env_file = (
        _safe_abs_path(env_value, label="environment file") if env_value else ""
    )
    parts = ["docker", "compose", "-f", shlex.quote(compose)]
    if env_file:
        parts.extend(["--env-file", shlex.quote(env_file)])
    parts.append("config")
    _run_checked(
        executor,
        " ".join(parts) + " >/dev/null",
        timeout=60,
        label="restored Docker Compose config validation",
    )
    return True


def start_runtime_and_verify(
    executor: RemoteExecutor,
    metadata: Mapping,
    xray_ports: Iterable[int],
) -> tuple[bool, bool, tuple[int, ...]]:
    marzban = dict(metadata.get("marzban") or {})
    marzban_dir = _safe_abs_path(
        marzban.get("directory"),
        label="Marzban directory",
    )
    _run_checked(
        executor,
        f"cd {shlex.quote(marzban_dir)} && docker compose up -d",
        timeout=300,
        label="start restored Marzban",
    )

    expected_ports = set(int(p) for p in xray_ports)
    api_port = marzban.get("api_port")
    if isinstance(api_port, int) and 1 <= api_port <= 65535:
        expected_ports.add(api_port)

    port_csv = ",".join(str(p) for p in sorted(expected_ports))
    probe_code = (
        "import socket,sys,time;"
        "ports=[int(x) for x in sys.argv[1].split(',') if x];"
        "deadline=time.time()+60;"
        "missing=ports[:];"
        "\nwhile time.time()<deadline:"
        "\n missing=[]"
        "\n for p in ports:"
        "\n  s=socket.socket();s.settimeout(1)"
        "\n  try:s.connect(('127.0.0.1',p))"
        "\n  except OSError:missing.append(p)"
        "\n  finally:s.close()"
        "\n if not missing:break"
        "\n time.sleep(2)"
        "\nprint(','.join(map(str,missing)))"
        "\nsys.exit(0 if not missing else 8)"
    )
    _run_checked(
        executor,
        f"python3 -c {shlex.quote(probe_code)} {shlex.quote(port_csv)}",
        timeout=75,
        label="wait for restored listeners",
    )

    api_healthy = False
    if isinstance(api_port, int) and 1 <= api_port <= 65535:
        scheme = "https" if (
            marzban.get("ssl_cert_path") and marzban.get("ssl_key_path")
        ) else "http"
        health_code = (
            "import ssl,sys,urllib.request;"
            "url=sys.argv[1];"
            "ctx=ssl._create_unverified_context();"
            "r=urllib.request.urlopen(url,context=ctx,timeout=8);"
            "print(getattr(r,'status',0))"
        )
        status = _run_text(
            executor,
            f"python3 -c {shlex.quote(health_code)} "
            f"{shlex.quote(f'{scheme}://127.0.0.1:{api_port}/docs')}",
            timeout=20,
            label="restored Marzban API health check",
        )
        try:
            api_healthy = 200 <= int(status) < 500
        except ValueError:
            api_healthy = False
        if not api_healthy:
            raise Phase3Error(f"restored Marzban API health failed: {status!r}")

    return True, api_healthy, tuple(sorted(expected_ports))
