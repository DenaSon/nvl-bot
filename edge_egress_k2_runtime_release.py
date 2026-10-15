"""One root-owned release profile shared by the Core bot and PAM interpreter.

Importing this module never enables execution. Missing profile means OFF;
an enabled profile pins the installed PAM source as part of the reviewed
release. This avoids editing Python flags for every login or new UID.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat

CORE_PROFILE = Path("/etc/nvl-egress/k2-m4/core-runtime.json")
INSTALLED_PAM = Path("/opt/nvl-egress/edge_egress_v1_admission.py")


class CoreReleaseHold(ValueError):
    pass


def _root_bytes(path: Path, maximum: int, *, private=False) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_nlink != 1 or info.st_mode & 0o022
            or private and info.st_mode & 0o077
            or not 0 < info.st_size <= maximum):
            raise CoreReleaseHold("CORE_RELEASE_FILE_UNTRUSTED")
        return os.read(fd, maximum + 1)
    finally:
        os.close(fd)


@dataclass(frozen=True)
class CoreReleaseProfile:
    enabled: bool
    pam_module_sha256: str


def load_core_profile() -> CoreReleaseProfile:
    try:
        if not CORE_PROFILE.exists() and not CORE_PROFILE.is_symlink():
            return CoreReleaseProfile(False, "")
        parent = CORE_PROFILE.parent.lstat()
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0
            or parent.st_mode & 0o077):
            raise CoreReleaseHold("CORE_PROFILE_DIRECTORY_UNTRUSTED")
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise CoreReleaseHold("CORE_PROFILE_DUPLICATE_FIELD")
                result[key] = value
            return result
        data = json.loads(_root_bytes(CORE_PROFILE, 2048, private=True),
                          object_pairs_hook=unique)
        if (type(data) is not dict
            or set(data) != {"version", "single_enabled", "pam_module_sha256"}
            or type(data["version"]) is not int or data["version"] != 1
            or type(data["single_enabled"]) is not bool
            or type(data["pam_module_sha256"]) is not str
            or not re.fullmatch(r"[a-f0-9]{64}", data["pam_module_sha256"])):
            raise CoreReleaseHold("CORE_PROFILE_INVALID")
        return CoreReleaseProfile(data["single_enabled"], data["pam_module_sha256"])
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise CoreReleaseHold("CORE_PROFILE_UNAVAILABLE_OR_INVALID") from exc


def pam_cross_edge_released() -> bool:
    """The separate PAM Python process rechecks the real release each login."""
    try:
        profile = load_core_profile()
        if not profile.enabled or os.geteuid() != 0:
            return False
        return sha256(_root_bytes(INSTALLED_PAM, 2_000_000)).hexdigest() == (
            profile.pam_module_sha256
        )
    except (OSError, ValueError):
        return False


def core_single_busy_admission(conn, row) -> bool:
    """Scope original 6G admission to this release's single-UID operation.

    Other protected UIDs keep their independently checked guards. The
    selected UID is admitted only for its post-commit client probe, after
    F2 PROTECTED and under the exact original journal/operation identity.
    Unknown/legacy/global/recovery operations retain the old deny behavior.
    """
    try:
        import sqlite3
        from edge_egress_p3_executor import ExecutionScope, _scope_digest, INTENT_PHASE, RECOVERY_PHASE
        if not pam_cross_edge_released():
            return False
        rows = conn.execute(
            "SELECT id,source_host,target_host,detail_json FROM failover_operations "
            "WHERE status='RUNNING'"
        ).fetchall()
        if len(rows) != 1:
            return False
        op, source, target, raw = rows[0]
        detail = json.loads(raw)
        if (type(detail) is not dict or detail.get("kind") != "K2_P3A"
            or detail.get("single_uid") is not True
            or detail.get("phase") not in (INTENT_PHASE, RECOVERY_PHASE)
            or detail.get("action") not in ("UID_ATTACH", "UID_ENROLL_SOURCE")
            or type(detail.get("nonce_hash")) is not str
            or not re.fullmatch(r"[a-f0-9]{64}", detail["nonce_hash"])):
            return False
        scope = ExecutionScope(detail["action"], detail["edge_id"], source, target,
                               username=detail["username"], uid=detail["uid"])
        if detail.get("scope_digest") != _scope_digest(scope):
            return False
        if row.username != scope.username and row.uid != scope.uid:
            return True
        return bool(
            row.username == scope.username and row.uid == scope.uid
            and row.state == "PROTECTED" and row.last_operation_id == op
            and row.edge_id == scope.edge_id and row.edge_ipv4 == scope.target_host
            and detail["phase"] == INTENT_PHASE and detail.get("probe_only") is True
        )
    except (OSError, ValueError, TypeError, KeyError, AttributeError, sqlite3.Error):
        return False
