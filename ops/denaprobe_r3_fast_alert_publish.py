#!/usr/bin/env python3
"""Deploy only the DenaProbe R3 fast-TCP-alert modules to an already-running Core.

Safe stage-only default; --apply updates only detector and Rich UI and restarts
only nvlbot. Never overwrites bot, env, collector, DB or network configuration.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time


FILES = ("denaprobe_ingest/detector.py", "denaprobe_rich_admin.py")
REQUIRED_SOURCE = ("EARLY_OBSERVATION", "TCP_FAILURE_DIRECT_CONTROL_UNVERIFIED")
IMPORT_TEST = ("import denaprobe_ingest.detector as d; "
               "import denaprobe_rich_admin as r; "
               "assert d.EARLY == 'EARLY_OBSERVATION'; "
               "print('R3_FAST_IMPORT_PASS')")


def require(condition: bool, message: str):
    if not condition:
        raise RuntimeError(message)


def run(*args: str, cwd: Path | None = None, env: dict | None = None):
    return subprocess.run(args, cwd=cwd, env=env,
                          check=True, timeout=60)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def safe_file(path: Path):
    require(path.is_file() and not path.is_symlink()
            and not path.parent.is_symlink(),
            f"missing/unsafe file: {path}")


def validate(src: Path, root: Path, sha: str, python: Path):
    require(len(sha) == 40 and all(c in "0123456789abcdef" for c in sha),
            "expected exact 40-character Git SHA")
    current = subprocess.check_output(
        ("git", "-C", str(src), "rev-parse", "HEAD"),
        text=True, timeout=15,
    ).strip()
    require(current == sha, "source SHA mismatch")
    require(python.is_file(), "bot venv Python unavailable")
    main = root / "bot_final_v49-2.py"
    safe_file(main)
    bot = main.read_text(encoding="utf-8")
    require("NVL_DENAPROBE_R3_ALERTS_ENABLED" in bot
            and "dp3_monitor_task" in bot,
            "running Core bot lacks R3 integration")
    safe_file(root / "denaprobe_alerts.py")
    for relative in FILES:
        staged, active = src / relative, root / relative
        safe_file(staged)
        safe_file(active)
        compile(staged.read_text(encoding="utf-8"),
                str(staged), "exec")
    src_det = (src / FILES[0]).read_text(encoding="utf-8")
    require(all(token in src_det for token in REQUIRED_SOURCE),
            "source is not the reviewed fast-alert detector")
    # Isolate import from the old /root package: CWD wins over PYTHONPATH.
    env = os.environ.copy()
    env["PYTHONPATH"] = str(src)
    run(str(python), "-c", IMPORT_TEST, cwd=src, env=env)
    run("systemctl", "is-active", "--quiet", "nvlbot")
    run("systemctl", "is-active", "--quiet", "denaprobe-collector")
    for relative in FILES:
        print(f"STAGED {relative}: live={digest(root / relative)[:12]}"
              f" source={digest(src / relative)[:12]}", flush=True)
    print("PREFLIGHT_PASS", flush=True)


def atomic_replace(source: Path, target: Path):
    safe_file(source)
    safe_file(target)
    mode = target.stat().st_mode & 0o777
    fd, temp = tempfile.mkstemp(prefix=".denaprobe-r3-", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as dest:
            dest.write(source.read_bytes())
            dest.flush()
            os.fsync(dest.fileno())
        os.chmod(temp, mode)
        os.replace(temp, target)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def publish(src: Path, root: Path, python: Path):
    backup = Path(tempfile.mkdtemp(prefix="denaprobe-fast-pre-", dir=root))
    backup.chmod(0o700)
    for relative in FILES:
        archived = backup / relative
        archived.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copy2(root / relative, archived)
    print(f"BACKUP={backup}", flush=True)
    modified = False
    try:
        modified = True
        for relative in FILES:
            atomic_replace(src / relative, root / relative)
        env = os.environ.copy()
        env["PYTHONPATH"] = str(root)
        run(str(python), "-c", IMPORT_TEST, cwd=root, env=env)
        for relative in FILES:
            require(digest(root / relative) == digest(src / relative),
                    f"publish checksum failed: {relative}")
        run("systemctl", "restart", "nvlbot")
        time.sleep(4)
        run("systemctl", "is-active", "--quiet", "nvlbot")
    except BaseException:
        if modified:
            print("PUBLISH_FAILED: attempting code-only restore",
                  file=sys.stderr, flush=True)
            try:
                for relative in FILES:
                    atomic_replace(backup / relative, root / relative)
                run("systemctl", "restart", "nvlbot")
                run("systemctl", "is-active", "--quiet", "nvlbot")
                print("ROLLBACK_ACTIVE", file=sys.stderr, flush=True)
            except Exception as exc:
                print(f"ROLLBACK_NEEDS_REVIEW: {type(exc).__name__}",
                      file=sys.stderr, flush=True)
        raise
    print("DEPLOY_SUCCESS", flush=True)
    print(f"BACKUP={backup}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--src", type=Path, required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--root", type=Path, default=Path("/root"),
                        help=argparse.SUPPRESS)
    parser.add_argument("--python", type=Path,
                        default=Path("/root/venv/bin/python3"),
                        help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        require(os.geteuid() == 0, "must run as root")
        src, root = args.src.resolve(), args.root.resolve()
        # Preserve the venv entrypoint symlink. Path.resolve() can point to
        # /usr/bin/python3 and silently drop the /root/venv site-packages.
        python = args.python.absolute()
        validate(src, root, args.sha, python)
        if args.apply:
            publish(src, root, python)
        else:
            print("STAGE_ONLY=YES; no changes to Core", flush=True)
    except Exception as exc:
        print(f"STOP: {type(exc).__name__}: {exc}", file=sys.stderr,
              flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
