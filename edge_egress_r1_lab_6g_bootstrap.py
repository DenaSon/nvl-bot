"""Bootstrap an EMPTY, LAB-only Phase-6G journal using the exact bot callbacks.

This DOES NOT copy Production data, insert a synthetic RUNNING operation,
start Telegram, enable PAM, unlock SSH, mutate Linux routes or promote READY.

The callbacks are extracted from the SHA-1-pinned *git blob* of the existing
bot's own source (not a reimplementation of the lock). The known bot file
blob is immutable under subsequent R1-only commits. Refuse all foreign hosts.
"""
from __future__ import annotations

import argparse
import ast
from contextlib import contextmanager
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import pwd
import sqlite3
import stat
import subprocess
import sys

from edge_egress_r1_lab_topology import TwoHostCoreIngress
from edge_egress_uid_policy import UIDPolicyRequest
from ops.edge_egress_provision import EgressSpec

from safe_failover import (
    FAILOVER_MODE_MANUAL,
    FAILOVER_STATUS_RUNNING,
    FAILOVER_STATUS_ABORTED_STALE,
)
from edge_egress_handoff import is_egress_recovery_hold

# Reviewed git blob SHA for bot_final_v49-2.py; must be separately pinned
# from the branch HEAD because subsequent PR commits change only R1 code.
REVIEWED_BOT_GIT_BLOB = "268849707efeeaf030a0bd7eb361a88b9980860a"
EXPECTED_CALLBACKS = frozenset({
    "_parse_flexible_datetime",
    "_db_acquire_failover_lock",
    "_db_update_failover_operation",
})
DEFAULT_SOURCE = Path("/root/nvl-egress-lab1-source/bot_final_v49-2.py")
DEFAULT_DATABASE = Path("/root/master_bot.db")
STALE_SECONDS = 1800

# Byte-equivalent failover_operations schema from reviewed bot init_db.
JOURNAL_SCHEMA = """
CREATE TABLE failover_operations (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 mode TEXT NOT NULL,
 source_host TEXT NOT NULL,
 target_host TEXT NOT NULL,
 status TEXT NOT NULL,
 started_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 finished_at TEXT DEFAULT NULL,
 account_count INTEGER DEFAULT 0,
 moved_count INTEGER DEFAULT 0,
 previous_default_host TEXT DEFAULT NULL,
 previous_dns_ip TEXT DEFAULT NULL,
 core_fallback_ip TEXT DEFAULT NULL,
 error TEXT DEFAULT NULL,
 detail_json TEXT DEFAULT NULL
);
CREATE INDEX idx_failover_operations_status_started
 ON failover_operations(status, started_at);
"""


class Lab6GUnsafe(ValueError):
    pass


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(
        b"blob " + str(len(data)).encode("ascii") + b"\\0" + data
    ).hexdigest()


def verified_bot_callbacks(source: Path, db_conn):
    """Load three exact original bot AST definitions without importing the bot.

    Avoids bot import-time side effects, event loops, API calls and secrets.
    Refuses an edited/replaced bot file. Only reviewed function bodies run.
    """
    if source.is_symlink() or not source.is_file():
        raise Lab6GUnsafe("BOT_SOURCE_NOT_REGULAR")
    st = source.stat()
    if st.st_uid != 0 or st.st_mode & 0o022:
        raise Lab6GUnsafe("BOT_SOURCE_UNTRUSTED")
    data = source.read_bytes()
    if git_blob_sha(data) != REVIEWED_BOT_GIT_BLOB:
        raise Lab6GUnsafe("BOT_GIT_BLOB_MISMATCH")
    tree = ast.parse(data, filename=str(source))
    found = [
        node for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in EXPECTED_CALLBACKS
    ]
    if len(found) != 3 or {node.name for node in found} != EXPECTED_CALLBACKS:
        raise Lab6GUnsafe("BOT_CALLBACKS_UNAVAILABLE")
    if any(not isinstance(n, ast.FunctionDef) or n.decorator_list for n in found):
        raise Lab6GUnsafe("BOT_CALLBACK_DEFINITION_UNEXPECTED")
    code = compile(ast.Module(body=found, type_ignores=[]), str(source), "exec")
    env = {
        "__builtins__": __builtins__,
        "db_conn": db_conn,
        "datetime": datetime,
        "json": json,
        "is_egress_recovery_hold": is_egress_recovery_hold,
        "FAILOVER_MODE_MANUAL": FAILOVER_MODE_MANUAL,
        "FAILOVER_STATUS_RUNNING": FAILOVER_STATUS_RUNNING,
        "FAILOVER_STATUS_ABORTED_STALE": FAILOVER_STATUS_ABORTED_STALE,
        "FAILOVER_LOCK_STALE_SECONDS": STALE_SECONDS,
    }
    exec(code, env)
    return env["_db_acquire_failover_lock"], env["_db_update_failover_operation"]


def lab_host_attested() -> bool:
    """Insist on actual fixed Core identity, not user-supplied LAB flags."""
    try:
        from edge_egress_uid_boot import read_root_only_manifest
        if os.geteuid() != 0:
            return False
        mf = read_root_only_manifest(
            Path("/etc/nvl-egress/protected/nvlr1test.json")
        )
        req = mf.request
        return (mf.mode == "PROTECTED_BOOT_GUARD"
                and TwoHostCoreIngress().for_request(
                    req, req.spec.core_public_ipv4
                ) is True)
    except (OSError, ValueError, KeyError, TypeError):
        return False


def make_lab_db_conn(path: Path):
    """DB always opens the one fixed lab path; no URI or ATTACH from inputs."""
    if path != DEFAULT_DATABASE:
        raise Lab6GUnsafe("UNEXPECTED_LAB_DATABASE_PATH")

    @contextmanager
    def db_conn():
        with sqlite3.connect(path, timeout=10) as conn:
            conn.execute("PRAGMA busy_timeout=10000")
            conn.execute("PRAGMA foreign_keys=ON")
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    return db_conn


def install_empty_journal(*, path=DEFAULT_DATABASE, source=DEFAULT_SOURCE) -> None:
    """Exclusive-create a fresh LAB DB, with zero operations and no accounts."""
    if not lab_host_attested():
        raise Lab6GUnsafe("LAB_IDENTITY_NOT_ATTESTED")
    if path != DEFAULT_DATABASE or path.is_symlink() or path.exists():
        raise Lab6GUnsafe("DATABASE_EXISTS_OR_UNEXPECTED")
    root = path.parent
    if root.is_symlink() or root.stat().st_uid != 0:
        raise Lab6GUnsafe("UNSAFE_ROOT_DIRECTORY")
    connector = make_lab_db_conn(path)
    verified_bot_callbacks(source, connector)

    fd = os.open(
        str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
        0o600,
    )
    os.close(fd)
    try:
        with connector() as conn:
            conn.executescript(JOURNAL_SCHEMA)
            num = conn.execute("SELECT COUNT(*) FROM failover_operations").fetchone()[0]
            if num != 0:
                raise Lab6GUnsafe("NONEMPTY_JOURNAL_REFUSED")
        os.chmod(path, 0o600)
    except Exception:
        # Never remove a possibly part-written DB without independent
        # inspection. It must remain visibly blocked for operator repair.
        raise Lab6GUnsafe("PARTIAL_LAB_DATABASE_HOLD")

    print("LAB_JOURNAL_SCHEMA: INSTALLED")
    print("ORIGINAL_BOT_6G_CALLBACKS: SHA_PINNED")
    print("6G_OPERATIONS: 0")
    print("PAM_CHANGED: NO")
    print("SSH_USER_UNLOCKED: NO")
    print("NETWORK_CHANGED: NO")
    print("CUSTOMER_READY: NO")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("preflight", "install-empty"))
    args = parser.parse_args(argv)
    try:
        if not lab_host_attested():
            raise Lab6GUnsafe("NOT_RECOGNIZED_DISPOSABLE_LAB_CORE")
        conn = make_lab_db_conn(DEFAULT_DATABASE)
        verified_bot_callbacks(DEFAULT_SOURCE, conn)
        if args.action == "preflight":
            if DEFAULT_DATABASE.exists() or DEFAULT_DATABASE.is_symlink():
                raise Lab6GUnsafe("DATABASE_ALREADY_EXISTS")
            print("LAB_6G_SOURCE_PREFLIGHT: PASS")
            print("HOST_MUTATIONS: 0")
        else:
            install_empty_journal()
    except (Lab6GUnsafe, OSError, SyntaxError, ValueError, TypeError) as exc:
        print("STOP:" + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
