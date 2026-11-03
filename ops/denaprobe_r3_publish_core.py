#!/usr/bin/env python3
"""Guarded, code-only DenaProbe R3 publisher for the existing Core NVLBot.

Defaults to READ-ONLY preflight. Requires --apply for a release.
Never modifies Collector, SQLite, SSH, routes, keys or other Core services.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

RELEASE = (
    "bot_final_v49-2.py",
    "denaprobe_alerts.py",
    "denaprobe_rich_admin.py",
    "denaprobe_admin_dashboard.py",
    "denaprobe_ingest/__init__.py",
    "denaprobe_ingest/collector.py",
    "denaprobe_ingest/dpt2.py",
    "denaprobe_ingest/detector.py",
    "denaprobe_ingest/metrics.py",
    "denaprobe_ingest/schema_audit.py",
)
FLAGS = (
    "NVL_DENAPROBE_R3_ENABLED=1",
    "NVL_DENAPROBE_R3_ALERTS_ENABLED=1",
    "NVL_DENAPROBE_DB_PATH=/var/lib/denaprobe/telemetry-r3.sqlite3",
)
ALLOWED_BOT_CHANGES = {
    "_build_admin_programs_kb", "_show_admin_programs_hub",
    "callback_handler", "_post_init", "_post_shutdown",
}
R3_IMPORTS = (
    "import denaprobe_alerts, denaprobe_rich_admin, denaprobe_admin_dashboard;"
    "import denaprobe_ingest.collector, denaprobe_ingest.detector,"
    "denaprobe_ingest.metrics; print('IMPORT_PASS')"
)


def fail(message: str) -> None:
    raise RuntimeError(message)


def definitions(source: str) -> dict[str, str]:
    tree = ast.parse(source)
    return {
        node.name: ast.dump(node, include_attributes=False)
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def verify_compatible(live: str, release: str) -> None:
    old, new = definitions(live), definitions(release)
    legacy_only = sorted(set(old) - set(new))
    if legacy_only:
        fail(f"unpublished live functions: {legacy_only}")
    changed = sorted(
        name for name in old.keys() & new.keys()
        if old[name] != new[name] and name not in ALLOWED_BOT_CHANGES
    )
    if changed:
        fail(f"unexpected live function edits: {changed}")
    if "_dp3_monitor_loop" not in new:
        fail("missing R3 detector task")
    if "apps_dpt_24" not in live or "apps_dpt_24" not in release:
        fail("existing DPT/1 dashboard not preserved")
    if "_DP3_ENABLED" in live:
        fail("R3 already integrated in live; do not reinstall blindly")
    if not all(flag.split("=")[0] in release for flag in FLAGS):
        fail("R3 feature gate missing in release")
    if "apps_dp3_home" not in release or "apps_dpt_168" not in release:
        fail("missing historical/new dashboard callback")


def checked_source(src: Path, expected: str, python: Path) -> None:
    rev = subprocess.check_output(
        ("git", "-C", str(src), "rev-parse", "HEAD"), text=True).strip()
    if rev != expected:
        fail(f"release HEAD mismatch: expected={expected} actual={rev}")
    for rel in RELEASE:
        path = src / rel
        if not path.is_file() or path.is_symlink():
            fail(f"release file missing or unsafe: {rel}")
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    # Crucial: Python prepends the CWD to sys.path. Importing from /root while
    # PYTHONPATH points at source still picks /root/denaprobe_ingest first.
    env = os.environ.copy()
    env["PYTHONPATH"] = str(src)
    subprocess.run(
        (str(python), "-c", R3_IMPORTS), cwd=src, env=env,
        check=True, timeout=30,
    )


def safe_path(root: Path, relative: str) -> Path:
    path = root / relative
    if path.is_symlink() or path.parent.is_symlink():
        fail(f"unsafe live file/symlink: {relative}")
    return path


def atomic_bytes(target: Path, data: bytes, mode: int) -> None:
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if target.is_symlink():
        fail(f"symlink target: {target}")
    fd, name = tempfile.mkstemp(prefix=".denaprobe-", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(name, mode)
        os.replace(name, target)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def build_env(original: bytes) -> bytes:
    body = original.decode("utf-8")
    keys = tuple(v.split("=")[0] + "=" for v in FLAGS)
    keep = [line for line in body.splitlines()
            if not line.startswith(keys)]
    return ("\n".join(keep).rstrip() + "\n" + "\n".join(FLAGS) + "\n").encode()


def snapshot_sqlite(db_file: Path, dest: Path) -> None:
    source = sqlite3.connect(db_file.resolve().as_uri() + "?mode=ro",
                             uri=True, timeout=15)
    try:
        if source.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            fail("R3 SQLite quick_check failed")
        with sqlite3.connect(dest) as target:
            source.backup(target, pages=256, sleep=0.05)
            if target.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                fail("R3 SQLite backup quick_check failed")
    finally:
        source.close()


def check_services() -> None:
    for service in ("nvlbot", "denaprobe-collector"):
        subprocess.run(("systemctl", "is-active", "--quiet", service),
                       check=True, timeout=20)


def install(src: Path, root: Path, env_path: Path, backup: Path) -> None:
    for rel in RELEASE:
        old = safe_path(root, rel)
        data = (src / rel).read_bytes()
        mode = (old.stat().st_mode & 0o777) if old.is_file() else 0o644
        atomic_bytes(old, data, mode)
    atomic_bytes(env_path, build_env((backup / "nvlbot.env").read_bytes()), 0o600)


def revert(root: Path, env_path: Path, backup: Path, existed: set[str]) -> None:
    for rel in RELEASE:
        original = backup / "code" / rel
        dest = safe_path(root, rel)
        if rel in existed:
            mode = original.stat().st_mode & 0o777
            atomic_bytes(dest, original.read_bytes(), mode)
        elif dest.is_file():
            dest.unlink()
    atomic_bytes(env_path, (backup / "nvlbot.env").read_bytes(), 0o600)


def publish(src: Path, root: Path, env_path: Path, python: Path,
            db_path: Path) -> None:
    backup = Path(tempfile.mkdtemp(prefix="denaprobe-r3-pre-", dir=root))
    backup.chmod(0o700)
    existed: set[str] = set()
    for rel in RELEASE:
        path = safe_path(root, rel)
        if path.exists():
            dest = backup / "code" / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, dest)
            existed.add(rel)
    shutil.copy2(env_path, backup / "nvlbot.env")
    snapshot_sqlite(db_path, backup / "telemetry-r3.sqlite3")
    print(f"BACKUP={backup}", flush=True)
    changed = False
    try:
        changed = True
        install(src, root, env_path, backup)
        env = os.environ.copy()
        env["PYTHONPATH"] = str(root)
        # Post-copy import must use the *actual* production working directory.
        subprocess.run((str(python), "-c", R3_IMPORTS),
                       cwd=root, env=env, check=True, timeout=30)
        subprocess.run(("systemctl", "restart", "nvlbot"),
                       check=True, timeout=90)
        time.sleep(4)
        subprocess.run(("systemctl", "is-active", "--quiet", "nvlbot"),
                       check=True, timeout=20)
    except BaseException:
        if changed:
            print("DEPLOY_FAILED; RESTORING_CODE_AND_ENV", file=sys.stderr,
                  flush=True)
            try:
                revert(root, env_path, backup, existed)
                subprocess.run(("systemctl", "restart", "nvlbot"),
                               check=True, timeout=90)
                subprocess.run(("systemctl", "is-active", "--quiet", "nvlbot"),
                               check=True, timeout=20)
                print("ROLLBACK_SERVICE_ACTIVE", file=sys.stderr, flush=True)
            except Exception as error:
                print(f"ROLLBACK_REQUIRES_REVIEW={type(error).__name__}",
                      file=sys.stderr, flush=True)
        raise
    print("DEPLOY_SUCCESS", flush=True)
    print(f"BACKUP={backup}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--src", type=Path, required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--root", type=Path, default=Path("/root"),
                        help=argparse.SUPPRESS)
    parser.add_argument("--env", type=Path,
                        default=Path("/etc/nvlbot/nvlbot.env"),
                        help=argparse.SUPPRESS)
    parser.add_argument("--db", type=Path,
                        default=Path("/var/lib/denaprobe/telemetry-r3.sqlite3"),
                        help=argparse.SUPPRESS)
    parser.add_argument("--python", type=Path,
                        default=Path("/root/venv/bin/python3"),
                        help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            fail("root required")
        src, root = args.src.resolve(), args.root.resolve()
        python = args.python.resolve()
        checked_source(src, args.sha, python)
        live = safe_path(root, "bot_final_v49-2.py")
        verify_compatible(live.read_text(encoding="utf-8"),
                          (src / "bot_final_v49-2.py").read_text(encoding="utf-8"))
        if not args.env.is_file() or args.env.is_symlink():
            fail("service EnvironmentFile missing/unsafe")
        check_services()
        if not args.db.is_file():
            fail("R3 SQLite database missing")
        print("PREFLIGHT_PASS", flush=True)
        if args.apply:
            publish(src, root, args.env, python, args.db)
        else:
            print("STAGE_ONLY=YES (nothing installed)", flush=True)
    except Exception as error:
        print(f"STOP: {type(error).__name__}: {error}", file=sys.stderr,
              flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
