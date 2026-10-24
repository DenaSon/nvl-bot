"""Disposable Core PAM account gate for the exact R1 pilot UID.

This code is a proposed *account phase* hook, not an installer. Production
PAM/SSH is never modified by importing/running it. Non-pilot users continue
through their existing PAM stack. The pilot is denied until the genuine F2
binding, F4 readiness, exact kernel guard and real shared 6G journal agree.

Installing this global hook requires an independent console and a reviewed
first-account-rule PAM edit. DO NOT install on production.
"""
from __future__ import annotations

import os
from pathlib import Path
import pwd
import sqlite3
from typing import Callable

from edge_egress_uid_admission import decide_account, probe_local_guards
from edge_egress_uid_boot import read_root_only_manifest

LAB_USER = "nvlr1test"
LAB_UID = 1555
LAB_DB = Path("/root/master_bot.db")
LAB_MANIFEST = Path("/etc/nvl-egress/protected/nvlr1test.json")
PAM_ACCOUNT_LINE = (
    "account requisite pam_exec.so quiet "
    "/usr/bin/python3 /opt/nvl-egress/edge_egress_r1_lab_pam.py"
)


def decide_lab_pam(*, username: str, pam_type: str, geteuid: int,
                   lookup: Callable = pwd.getpwnam,
                   db: Path = LAB_DB,
                   manifest: Path = LAB_MANIFEST) -> bool:
    """Return True ONLY if PAM may continue evaluating its existing rules.

    Return False for UID 1555 if authorization data is absent or uncertain.
    Never treat a missing SQLite file as an empty 'allow all' state.
    """
    if geteuid != 0 or pam_type != "account" or not username:
        return False
    try:
        account = lookup(username)
    except (KeyError, OSError, ValueError):
        return False
    if username == "root":
        return account.pw_uid == 0  # break-glass, still subject to PAM
    if username != LAB_USER:
        return account.pw_uid != LAB_UID
    if account.pw_uid != LAB_UID:
        return False
    try:
        stored = read_root_only_manifest(manifest)
        req = stored.request
        if stored.mode != "PROTECTED_BOOT_GUARD":
            return False
        if req.username != LAB_USER or req.uid != LAB_UID:
            return False
        if db.is_symlink() or not db.is_file():
            return False
        with sqlite3.connect(db.absolute().as_uri() + "?mode=ro",
                             uri=True, timeout=2) as conn:
            conn.execute("PRAGMA query_only=ON")
            decision = decide_account(
                conn, LAB_USER, LAB_UID,
                lambda binding: probe_local_guards(conn, binding),
            )
            return decision.permitted and decision.reason == "GUARDED_EDGE_ROUTE"
    except (sqlite3.Error, OSError, ValueError, KeyError, TypeError):
        return False


def main() -> int:
    return 0 if decide_lab_pam(
        username=os.environ.get("PAM_USER", ""),
        pam_type=os.environ.get("PAM_TYPE", ""),
        geteuid=os.geteuid(),
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
