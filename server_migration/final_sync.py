from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import secrets
import shlex
from pathlib import Path, PurePosixPath
from typing import Iterable, Mapping

from .backup import validate_job_id
from .models import ServerFacts
from .phase4_models import Phase4Error, Phase4Policy
from .ssh import RemoteExecutor


def new_attempt_id() -> str:
    return "attempt-" + secrets.token_hex(6)


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
        raise Phase4Error(f"unsafe {label} path: {raw!r}")
    return str(path)


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
        raise Phase4Error(
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


def _dir_exists(executor: RemoteExecutor, path: str) -> bool:
    result = executor.run(f"test -d {shlex.quote(path)}", timeout=10)
    return int(result.exit_code) == 0


def normalize_ipv4(value: str, *, label: str) -> str:
    raw = str(value or "").strip()
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise Phase4Error(f"{label} is not a valid IP address: {raw!r}") from exc
    if ip.version != 4:
        raise Phase4Error(f"{label} must be IPv4 for the current Marzban migration")
    return str(ip)


def migration_paths(
    job_id: str,
    *,
    policy: Phase4Policy,
    attempt_id: str | None = None,
) -> dict[str, str]:
    job_id = validate_job_id(job_id)
    remote_root = _safe_abs_path(policy.remote_root, label="remote migration root")
    job_root = f"{remote_root.rstrip('/')}/{job_id}"
    paths = {
        "job_root": job_root,
        "phase3_complete": f"{job_root}/RESTORE_COMPLETE",
        "phase4_complete": f"{job_root}/FINAL_SYNC_COMPLETE",
        "global_lock": f"{remote_root.rstrip('/')}/.final-sync-lock",
    }
    if attempt_id:
        safe_attempt = str(attempt_id or "").strip()
        if not safe_attempt.startswith("attempt-") or not all(
            c.isalnum() or c in "-_" for c in safe_attempt
        ):
            raise Phase4Error(f"invalid attempt id: {safe_attempt!r}")
        attempt_root = f"{job_root}/final-sync/{safe_attempt}"
        paths.update(
            {
                "attempt_root": attempt_root,
                "source_final_db": f"{attempt_root}/source-final.sqlite3",
                "source_sha": f"{attempt_root}/source-final.sqlite3.sha256",
                "destination_incoming": f"{attempt_root}/incoming",
                "destination_final_db": f"{attempt_root}/incoming/source-final.sqlite3",
                "destination_backup": f"{attempt_root}/destination-before-final.sqlite3",
                "failed_marker": f"{attempt_root}/FAILED",
            }
        )
    return paths


def compose_running(
    executor: RemoteExecutor,
    *,
    marzban_dir: str,
) -> bool:
    marzban_dir = _safe_abs_path(marzban_dir, label="Marzban directory")
    result = executor.run(
        f"cd {shlex.quote(marzban_dir)} && "
        "docker compose ps --status running --services",
        timeout=30,
    )
    if int(result.exit_code) != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise Phase4Error(
            "cannot inspect Docker Compose runtime state"
            + (f": {detail}" if detail else "")
        )
    return bool(str(result.stdout or "").strip())


def stop_compose(
    executor: RemoteExecutor,
    *,
    marzban_dir: str,
) -> None:
    marzban_dir = _safe_abs_path(marzban_dir, label="Marzban directory")
    _run_checked(
        executor,
        f"cd {shlex.quote(marzban_dir)} && docker compose stop",
        timeout=180,
        label="stop Marzban runtime",
    )
    if compose_running(executor, marzban_dir=marzban_dir):
        raise Phase4Error("Marzban runtime is still running after docker compose stop")


def database_integrity(
    executor: RemoteExecutor,
    database_path: str,
) -> str:
    database_path = _safe_abs_path(database_path, label="database")
    code = (
        "import sqlite3,sys;"
        "c=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True,timeout=30);"
        "r=c.execute('PRAGMA integrity_check').fetchone()[0];"
        "c.close();print(r)"
    )
    raw = _run_text(
        executor,
        f"python3 -c {shlex.quote(code)} {shlex.quote(database_path)}",
        timeout=60,
        label="SQLite integrity check",
    )
    return raw.strip()


def matching_host_rows(
    executor: RemoteExecutor,
    database_path: str,
    old_ip: str,
) -> int:
    database_path = _safe_abs_path(database_path, label="database")
    old_ip = normalize_ipv4(old_ip, label="old IP")
    code = (
        "import sqlite3,sys;"
        "db,old=sys.argv[1],sys.argv[2];"
        "c=sqlite3.connect('file:'+db+'?mode=ro',uri=True,timeout=30);"
        "tables={r[0] for r in c.execute(\"SELECT name FROM sqlite_master WHERE type='table'\")};"
        "\nif 'hosts' not in tables: raise SystemExit('hosts table missing')"
        "\ncols={r[1] for r in c.execute(\"PRAGMA table_info('hosts')\")}"
        "\nif 'address' not in cols: raise SystemExit('hosts.address column missing')"
        "\nprint(c.execute(\"SELECT COUNT(*) FROM hosts WHERE address=?\",(old,)).fetchone()[0])"
        "\nc.close()"
    )
    raw = _run_text(
        executor,
        f"python3 -c {shlex.quote(code)} "
        f"{shlex.quote(database_path)} {shlex.quote(old_ip)}",
        timeout=60,
        label="inspect hosts.address rewrite impact",
    )
    try:
        return int(raw)
    except ValueError as exc:
        raise Phase4Error(f"invalid hosts.address count: {raw!r}") from exc


def acquire_final_sync_lock(
    executor: RemoteExecutor,
    *,
    lock_path: str,
    job_id: str,
) -> None:
    lock_path = _safe_abs_path(lock_path, label="final-sync lock")
    parent = str(PurePosixPath(lock_path).parent)
    command = (
        f"install -d -m 700 {shlex.quote(parent)} && "
        f"mkdir {shlex.quote(lock_path)} && "
        f"printf '%s\n' {shlex.quote(job_id)} > "
        f"{shlex.quote(lock_path + '/job_id')}"
    )
    _run_checked(
        executor,
        command,
        timeout=20,
        label="acquire final-sync lock",
    )


def release_final_sync_lock(
    executor: RemoteExecutor,
    *,
    lock_path: str,
    job_id: str,
) -> None:
    lock_path = _safe_abs_path(lock_path, label="final-sync lock")
    marker = lock_path + "/job_id"
    if not _exists(executor, lock_path):
        return
    current = _run_text(
        executor,
        f"cat {shlex.quote(marker)}",
        timeout=10,
        label="read final-sync lock owner",
    )
    if current.strip() != job_id:
        raise Phase4Error(
            f"refusing to release final-sync lock owned by {current!r}"
        )
    _run_checked(
        executor,
        f"rm -rf -- {shlex.quote(lock_path)}",
        timeout=20,
        label="release final-sync lock",
    )


def create_final_source_snapshot(
    executor: RemoteExecutor,
    *,
    database_path: str,
    output_path: str,
) -> str:
    database_path = _safe_abs_path(database_path, label="source database")
    output_path = _safe_abs_path(output_path, label="final database snapshot")
    parent = str(PurePosixPath(output_path).parent)

    _run_checked(
        executor,
        f"test ! -e {shlex.quote(output_path)} && "
        f"install -d -m 700 {shlex.quote(parent)}",
        timeout=20,
        label="prepare final source snapshot directory",
    )

    code = (
        "import os,sqlite3,sys;"
        "src,dst=sys.argv[1],sys.argv[2];"
        "s=sqlite3.connect('file:'+src+'?mode=ro',uri=True,timeout=30);"
        "d=sqlite3.connect(dst,timeout=30);"
        "s.backup(d);"
        "a=s.execute('PRAGMA integrity_check').fetchone()[0];"
        "b=d.execute('PRAGMA integrity_check').fetchone()[0];"
        "d.close();s.close();"
        "os.chmod(dst,0o600);"
        "print(str(a)+'|'+str(b));"
        "sys.exit(0 if str(a).lower()=='ok' and str(b).lower()=='ok' else 7)"
    )
    raw = _run_text(
        executor,
        f"python3 -c {shlex.quote(code)} "
        f"{shlex.quote(database_path)} {shlex.quote(output_path)}",
        timeout=180,
        label="create final source SQLite snapshot",
    )
    if raw.lower() != "ok|ok":
        raise Phase4Error(f"final source snapshot integrity failed: {raw!r}")

    digest = _run_text(
        executor,
        f"sha256sum {shlex.quote(output_path)} | awk '{{print $1}}'",
        timeout=60,
        label="hash final source database",
    ).lower()
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise Phase4Error(f"invalid final database SHA256: {digest!r}")
    return digest


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def relay_final_database(
    source_executor,
    destination_executor,
    *,
    source_remote_path: str,
    destination_remote_path: str,
    expected_sha256: str,
    job_id: str,
    attempt_id: str,
    policy: Phase4Policy,
) -> str:
    source_download = getattr(source_executor, "download", None)
    destination_upload = getattr(destination_executor, "upload", None)
    if not callable(source_download) or not callable(destination_upload):
        raise Phase4Error("SSH executor must support SFTP download/upload")

    root = Path(policy.local_root).expanduser().resolve()
    local_dir = root / job_id / "final-sync" / attempt_id
    if local_dir.exists():
        raise Phase4Error(f"local final-sync staging already exists: {local_dir}")
    local_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
    os.chmod(local_dir, 0o700)

    local_db = local_dir / "source-final.sqlite3"
    source_download(source_remote_path, os.fspath(local_db))
    os.chmod(local_db, 0o600)

    local_sha = sha256_file(os.fspath(local_db))
    if local_sha != expected_sha256:
        raise Phase4Error(
            f"Source -> NVL final DB checksum mismatch: "
            f"{local_sha} != {expected_sha256}"
        )

    remote_parent = str(PurePosixPath(destination_remote_path).parent)
    _run_checked(
        destination_executor,
        f"test ! -e {shlex.quote(destination_remote_path)} && "
        f"install -d -m 700 {shlex.quote(remote_parent)}",
        timeout=20,
        label="prepare destination final-sync staging",
    )
    destination_upload(os.fspath(local_db), destination_remote_path)

    remote_sha = _run_text(
        destination_executor,
        f"sha256sum {shlex.quote(destination_remote_path)} | awk '{{print $1}}'",
        timeout=60,
        label="verify destination final database checksum",
    ).lower()
    if remote_sha != expected_sha256:
        raise Phase4Error(
            f"NVL -> destination final DB checksum mismatch: "
            f"{remote_sha} != {expected_sha256}"
        )

    return os.fspath(local_db)


def backup_destination_database(
    executor: RemoteExecutor,
    *,
    database_path: str,
    backup_path: str,
) -> str:
    database_path = _safe_abs_path(database_path, label="destination database")
    backup_path = _safe_abs_path(backup_path, label="destination DB backup")
    parent = str(PurePosixPath(backup_path).parent)

    _run_checked(
        executor,
        f"test ! -e {shlex.quote(backup_path)} && "
        f"install -d -m 700 {shlex.quote(parent)}",
        timeout=20,
        label="prepare destination DB backup",
    )

    code = (
        "import os,sqlite3,sys;"
        "src,dst=sys.argv[1],sys.argv[2];"
        "s=sqlite3.connect('file:'+src+'?mode=ro',uri=True,timeout=30);"
        "d=sqlite3.connect(dst,timeout=30);"
        "s.backup(d);"
        "r=d.execute('PRAGMA integrity_check').fetchone()[0];"
        "d.close();s.close();os.chmod(dst,0o600);print(r)"
    )
    raw = _run_text(
        executor,
        f"python3 -c {shlex.quote(code)} "
        f"{shlex.quote(database_path)} {shlex.quote(backup_path)}",
        timeout=180,
        label="backup destination database",
    )
    if raw.lower() != "ok":
        raise Phase4Error(f"destination DB backup integrity failed: {raw!r}")
    return backup_path


def install_final_database(
    executor: RemoteExecutor,
    *,
    staged_database: str,
    runtime_database: str,
) -> None:
    staged_database = _safe_abs_path(staged_database, label="staged final database")
    runtime_database = _safe_abs_path(runtime_database, label="runtime database")

    code = (
        "import os,shutil,stat,sys;"
        "src,dst=sys.argv[1],sys.argv[2];"
        "st=os.stat(dst);"
        "tmp=dst+'.nvl-final-new';"
        "\nif os.path.exists(tmp): raise SystemExit('temporary target already exists')"
        "\nshutil.copyfile(src,tmp)"
        "\nos.chown(tmp,st.st_uid,st.st_gid)"
        "\nos.chmod(tmp,stat.S_IMODE(st.st_mode))"
        "\nos.replace(tmp,dst)"
        "\nfor suffix in ('-wal','-shm'):"
        "\n p=dst+suffix"
        "\n if os.path.exists(p): os.unlink(p)"
    )
    _run_checked(
        executor,
        f"python3 -c {shlex.quote(code)} "
        f"{shlex.quote(staged_database)} {shlex.quote(runtime_database)}",
        timeout=120,
        label="atomically install final database",
    )


def rewrite_hosts_address(
    executor: RemoteExecutor,
    *,
    database_path: str,
    old_ip: str,
    new_ip: str,
) -> int:
    database_path = _safe_abs_path(database_path, label="database")
    old_ip = normalize_ipv4(old_ip, label="old IP")
    new_ip = normalize_ipv4(new_ip, label="new IP")

    code = (
        "import sqlite3,sys;"
        "db,old,new=sys.argv[1:4];"
        "c=sqlite3.connect(db,timeout=30);"
        "c.execute('BEGIN IMMEDIATE');"
        "tables={r[0] for r in c.execute(\"SELECT name FROM sqlite_master WHERE type='table'\")};"
        "\nif 'hosts' not in tables: c.rollback(); raise SystemExit('hosts table missing')"
        "\ncols={r[1] for r in c.execute(\"PRAGMA table_info('hosts')\")}"
        "\nif 'address' not in cols: c.rollback(); raise SystemExit('hosts.address column missing')"
        "\ncur=c.execute(\"UPDATE hosts SET address=? WHERE address=?\",(new,old))"
        "\nchanged=cur.rowcount"
        "\nc.commit()"
        "\nprint(changed)"
        "\nc.close()"
    )
    raw = _run_text(
        executor,
        f"python3 -c {shlex.quote(code)} "
        f"{shlex.quote(database_path)} {shlex.quote(old_ip)} {shlex.quote(new_ip)}",
        timeout=60,
        label="rewrite hosts.address",
    )
    try:
        return int(raw)
    except ValueError as exc:
        raise Phase4Error(f"invalid hosts.address rewrite count: {raw!r}") from exc


def scan_database_for_old_ip(
    executor: RemoteExecutor,
    *,
    database_path: str,
    old_ip: str,
) -> tuple[str, ...]:
    database_path = _safe_abs_path(database_path, label="database")
    old_ip = normalize_ipv4(old_ip, label="old IP")
    code = (
        "import json,sqlite3,sys;"
        "db,old=sys.argv[1],sys.argv[2];"
        "c=sqlite3.connect('file:'+db+'?mode=ro',uri=True,timeout=30);"
        "hits=[];"
        "tables=[r[0] for r in c.execute(\"SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'\")];"
        "\nfor table in tables:"
        "\n cols=c.execute('PRAGMA table_info(\"'+table.replace(chr(34),chr(34)*2)+'\")').fetchall()"
        "\n for col in cols:"
        "\n  name=col[1]"
        "\n  qt='\"'+table.replace(chr(34),chr(34)*2)+'\"'"
        "\n  qc='\"'+name.replace(chr(34),chr(34)*2)+'\"'"
        "\n  try:"
        "\n   count=c.execute('SELECT COUNT(*) FROM '+qt+' WHERE CAST('+qc+' AS TEXT) LIKE ?',('%'+old+'%',)).fetchone()[0]"
        "\n  except Exception: continue"
        "\n  if count: hits.append({'table':table,'column':name,'count':int(count)})"
        "\nc.close();print(json.dumps(hits,sort_keys=True))"
    )
    raw = _run_text(
        executor,
        f"python3 -c {shlex.quote(code)} "
        f"{shlex.quote(database_path)} {shlex.quote(old_ip)}",
        timeout=180,
        label="scan destination database for old IP",
    )
    try:
        rows = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise Phase4Error(f"invalid residual database scan output: {raw!r}") from exc
    if not isinstance(rows, list):
        raise Phase4Error("residual database scan did not return a list")
    return tuple(
        f"{row.get('table')}.{row.get('column')}:{int(row.get('count') or 0)}"
        for row in rows
        if isinstance(row, dict)
    )


def scan_runtime_configs_for_old_ip(
    executor: RemoteExecutor,
    *,
    metadata: Mapping,
    old_ip: str,
) -> tuple[str, ...]:
    old_ip = normalize_ipv4(old_ip, label="old IP")
    marzban = dict(metadata.get("marzban") or {})
    candidates = []
    for key in (
        "compose_file",
        "environment_file",
        "xray_config_path",
    ):
        value = str(marzban.get(key) or "").strip()
        if value:
            candidates.append(_safe_abs_path(value, label=f"runtime {key}"))

    found = []
    for path in dict.fromkeys(candidates):
        if not _exists(executor, path):
            continue
        result = executor.run(
            f"grep -qF -- {shlex.quote(old_ip)} {shlex.quote(path)}",
            timeout=20,
        )
        if int(result.exit_code) == 0:
            found.append(path)
        elif int(result.exit_code) not in {1}:
            detail = (result.stderr or "").strip()
            raise Phase4Error(
                f"cannot scan runtime config for old IP: {path}"
                + (f": {detail}" if detail else "")
            )
    return tuple(found)


def restore_destination_database(
    executor: RemoteExecutor,
    *,
    backup_path: str,
    runtime_database: str,
) -> None:
    if not _exists(executor, backup_path):
        raise Phase4Error("destination DB recovery backup is missing")
    install_final_database(
        executor,
        staged_database=backup_path,
        runtime_database=runtime_database,
    )
    integrity = database_integrity(executor, runtime_database)
    if integrity.lower() != "ok":
        raise Phase4Error(
            f"destination DB recovery integrity failed: {integrity!r}"
        )


def mark_phase4_complete(
    executor: RemoteExecutor,
    *,
    marker_path: str,
    payload: Mapping,
) -> None:
    marker_path = _safe_abs_path(marker_path, label="Phase 4 completion marker")
    encoded = json.dumps(dict(payload), sort_keys=True, separators=(",", ":"))
    code = (
        "import pathlib,sys;"
        "p=pathlib.Path(sys.argv[1]);"
        "p.write_text(sys.argv[2]+'\\n',encoding='utf-8');"
        "p.chmod(0o600)"
    )
    _run_checked(
        executor,
        f"python3 -c {shlex.quote(code)} "
        f"{shlex.quote(marker_path)} {shlex.quote(encoded)}",
        timeout=20,
        label="write Phase 4 completion marker",
    )
