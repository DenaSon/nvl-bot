"""Exact-source LAB PAM wrapper for /opt/nvl-egress (DENY by default).

Must be launched as root by the first PAM account rule on the disposable
Amsterdam Core only. Never imports a file from a mutable user directory.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import sys

BUNDLE = Path("/root/nvl-r1-controlplane-src")
MODULE = BUNDLE / "edge_egress_r1_lab_pam.py"
REVIEWED_GIT_BLOB = "2bb42c82ef42c6ee4341ea2bc5c1a69202b7eb7b"


def verified_runtime_module() -> bool:
    if os.geteuid() != 0:
        return False
    for directory in (Path("/root"), BUNDLE):
        try:
            data = directory.lstat()
        except OSError:
            return False
        if not stat.S_ISDIR(data.st_mode) or data.st_uid != 0 or data.st_mode & 0o022:
            return False
    try:
        info = MODULE.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o022 or info.st_size > 30000):
            return False
        data = MODULE.read_bytes()
    except OSError:
        return False
    return hashlib.sha1(
        b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    ).hexdigest() == REVIEWED_GIT_BLOB


def main() -> int:
    try:
        if not verified_runtime_module():
            return 1
        sys.path.insert(0, str(BUNDLE))
        from edge_egress_r1_lab_pam import main as checked_pam_main
        return int(checked_pam_main())
    except Exception:
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
