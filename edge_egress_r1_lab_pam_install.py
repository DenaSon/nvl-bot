"""One-time rollback-capable PAM account gate installer, disposable LAB only.

Does not alter SSH service, sshd_config, customer shell, bot state or routes.
The pilot stays DENY while F2/F4 are incomplete. A cloud console must be
available before running --install; no production installation is supported.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile

from edge_egress_r1_lab_6g_bootstrap import lab_host_attested
from edge_egress_r1_lab_pam import PAM_ACCOUNT_LINE
from edge_egress_r1_lab_pam_runtime import verified_runtime_module
from edge_egress_r1_lab_topology import TwoHostCoreIngress
from edge_egress_uid_boot import read_root_only_manifest

PAM = Path("/etc/pam.d/sshd")
MODULE = Path("/opt/nvl-egress/edge_egress_r1_lab_pam.py")
MODULE_SOURCE = Path("/root/nvl-r1-controlplane-src/edge_egress_r1_lab_pam_runtime.py")
MODULE_GIT_BLOB = "627bcf716bddc9a077b06b156255c9cc7701024b"
BACKUP_DIR = Path("/root/nvl-r1-pam-rollback")
BACKUP = BACKUP_DIR / "sshd.before"
DB = Path("/root/master_bot.db")


class LabPAMUnsafe(ValueError):
    pass


def root_owned_regular(path: Path, *, max_size: int = 100000) -> bytes:
    try:
        metadata = path.lstat()
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
                or metadata.st_mode & 0o022 or metadata.st_size > max_size):
            raise LabPAMUnsafe("UNTRUSTED_FILE")
        return path.read_bytes()
    except OSError as exc:
        raise LabPAMUnsafe("REQUIRED_FILE_NOT_FOUND") from exc


def git_blob(data: bytes) -> str:
    return hashlib.sha1(
        b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    ).hexdigest()


def lab_preflight() -> tuple[bytes, bytes]:
    if not lab_host_attested():
        raise LabPAMUnsafe("NOT_ATTESTED_LAB_CORE")
    acc = pwd.getpwnam("nvlr1test")
    if (acc.pw_uid != 1555 or acc.pw_shell != "/usr/sbin/nologin"):
        raise LabPAMUnsafe("PILOT_ACCOUNT_NOT_LOCKED")
    p = subprocess.run(["passwd", "-S", "nvlr1test"],
                       capture_output=True, text=True, timeout=6, check=True)
    if p.stdout.split()[1] != "L":
        raise LabPAMUnsafe("PILOT_PASSWORD_NOT_LOCKED")
    original = root_owned_regular(PAM)
    if PAM_ACCOUNT_LINE.encode() in original or b"pam_exec.so" in original:
        raise LabPAMUnsafe("UNREVIEWED_OR_EXISTING_PAM_EXEC")
    raw_wrapper = root_owned_regular(MODULE_SOURCE, max_size=30000)
    if git_blob(raw_wrapper) != MODULE_GIT_BLOB:
        raise LabPAMUnsafe("UNPINNED_PAM_WRAPPER_SOURCE")
    if not verified_runtime_module():
        raise LabPAMUnsafe("UNPINNED_PAM_GATE_SOURCE")
    with sqlite3.connect(DB.absolute().as_uri() + "?mode=ro",
                         uri=True, timeout=3) as db:
        db.execute("PRAGMA query_only=ON")
        row = db.execute(
            "SELECT status,source_host,target_host FROM failover_operations "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row != ("SUCCEEDED", "107.189.16.36", "216.126.229.12"):
            raise LabPAMUnsafe("6G_STAGE_NOT_SUCCESSFUL")
        if db.execute(
            "SELECT COUNT(*) FROM failover_operations WHERE status='RUNNING'"
        ).fetchone()[0] != 0:
            raise LabPAMUnsafe("6G_LOCK_STILL_RUNNING")
        if db.execute(
            "SELECT status FROM edge_egress_allocations WHERE edge_id='lab1'"
        ).fetchone() != ("STAGED",):
            raise LabPAMUnsafe("EDGE_NOT_STAGED")
        if db.execute(
            "SELECT state FROM edge_egress_readiness WHERE edge_id='lab1'"
        ).fetchone() != ("STAGED",):
            raise LabPAMUnsafe("UNEXPECTED_LAB_READINESS")
        for table in ("edge_egress_uid_runtime", "edge_egress_uid_bindings"):
            if db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] != 0:
                raise LabPAMUnsafe("PILOT_ALREADY_ATTACHED")
    if not DB.is_file() or DB.is_symlink():
        raise LabPAMUnsafe("LAB_DB_UNTRUSTED")
    info = DB.stat()
    if info.st_uid != 0 or info.st_mode & 0o077:
        raise LabPAMUnsafe("LAB_DB_PERMISSIONS_UNSAFE")
    if not shutil.which("sshd") or not Path("/usr/sbin/sshd").is_file():
        raise LabPAMUnsafe("SSHD_MISSING")
    effective = subprocess.run(
        ["/usr/sbin/sshd", "-T", "-C",
         "user=nvlr1test,host=107.189.16.36,addr=107.189.16.36"],
        capture_output=True, text=True, check=True, timeout=8,
    ).stdout.lower().splitlines()
    if "usepam yes" not in effective:
        raise LabPAMUnsafe("SSHD_USEPAM_REQUIRED")
    if MODULE.exists() or MODULE.is_symlink() or BACKUP.exists() or BACKUP.is_symlink():
        raise LabPAMUnsafe("PAM_ALREADY_STAGED_OR_INSTALLED")
    for directory in (Path("/opt"), Path("/etc/pam.d"), Path("/root")):
        item = directory.lstat()
        if not stat.S_ISDIR(item.st_mode) or item.st_uid != 0 or item.st_mode & 0o022:
            raise LabPAMUnsafe("UNSAFE_PARENT_DIRECTORY")
    return original, raw_wrapper


def atomic_root_file(target: Path, data: bytes, mode: int) -> None:
    fd, candidate = tempfile.mkstemp(prefix=".nvl-pam-", dir=target.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(candidate, target)
    finally:
        if os.path.exists(candidate):
            os.unlink(candidate)


def pam_witness(module: Path) -> None:
    for who, expected in (("root", 0), ("nvlr1test", 1)):
        env = dict(os.environ, PAM_TYPE="account", PAM_USER=who)
        env.pop("PYTHONPATH", None)
        result = subprocess.run(
            ["/usr/bin/python3", str(module)], env=env,
            capture_output=True, text=True, timeout=8,
        )
        if result.returncode != expected:
            raise LabPAMUnsafe("PAM_ACCOUNT_GATE_UNEXPECTED_" + who)


def install() -> None:
    original, runtime = lab_preflight()
    BACKUP_DIR.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.chmod(BACKUP_DIR, 0o700)
    atomic_root_file(BACKUP, original, 0o600)
    parent = MODULE.parent
    parent.mkdir(mode=0o700, parents=False, exist_ok=False)
    atomic_root_file(MODULE, runtime, 0o600)
    pam_witness(MODULE)  # root allows / pilot denies BEFORE modifying PAM
    installed = (PAM_ACCOUNT_LINE + "\n").encode() + original
    atomic_root_file(PAM, installed, 0o644)
    try:
        result = subprocess.run(["/usr/sbin/sshd", "-t"],
                                capture_output=True, timeout=8)
        if result.returncode:
            raise LabPAMUnsafe("SSHD_VALIDATION_FAILED")
        if root_owned_regular(PAM) != installed:
            raise LabPAMUnsafe("PAM_INSTALL_BYTES_CHANGED")
        pam_witness(MODULE)
    except Exception:
        if root_owned_regular(PAM) == installed:
            atomic_root_file(PAM, original, 0o644)
        raise LabPAMUnsafe("INSTALL_VALIDATION_FAILED_RESTORED_PAM")
    print("PAM_GATE: INSTALLED_FIRST_ACCOUNT_RULE")
    print("ROOT_ACCOUNT: PRESERVED_IN_LAB_PAM_GATE")
    print("TEST_UID: DENIED")
    print("ORIGINAL_PAM: BACKED_UP")
    print("SSHD_SERVICE_RESTARTED: NO")
    print("CUSTOMER_READY: NO")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("preflight", "install"))
    parser.add_argument("--console-confirmed", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.action == "preflight":
            lab_preflight()
            print("LAB_PAM_PREFLIGHT: PASS")
            print("HOST_MUTATIONS: 0")
            return 0
        if not args.console_confirmed:
            raise LabPAMUnsafe("INDEPENDENT_CLOUD_CONSOLE_REQUIRED")
        install()
        return 0
    except (LabPAMUnsafe, OSError, sqlite3.Error, IndexError, KeyError,
            subprocess.SubprocessError, ValueError) as exc:
        print("STOP:" + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
