#!/usr/bin/env python3
"""Dynamic Egress F2 — conservative PAM account admission, not an installer.

A root-only durable roster fences protected UID identities independently of
SQLite: dropping/restoring a runtime DB row cannot silently make one LEGACY.
All non-root logins require a valid roster AND coherent existing DB schema.
For protected users the existing F2 DB + kernel/DNS/readiness gates must pass.
Missing/corrupt roster or DB: DENY non-root. Root alone is break-glass.

The PAM hook must be installed only during the final reviewed deployment.
No host mutation, schema migration, SSH restart, or network action here.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import sqlite3
import stat
import sys

from edge_egress_uid_admission import (
    AdmissionResult, NAME, FIXED_DB, decide_account, probe_local_guards,
)
from edge_egress_uid_boot import BootGuardManifest, render_ssh_required_unit
from edge_egress_f4_pam import inspect_pam_sshd, REQUIRED_ACCOUNT_LINE

ROSTER = Path("/etc/nvl-egress/v1-protected-users.json")
GUARD_DIR = Path("/etc/nvl-egress/protected")
PAM_LINE = (
    "account requisite pam_exec.so quiet "
    "/usr/bin/python3 /opt/nvl-egress/edge_egress_v1_admission.py"
)
SHA = re.compile(r"^[0-9a-f]{64}$")
MAX_ROSTER_BYTES = 262144
MAX_GUARD_BYTES = 4096


class AdmissionHold(ValueError):
    pass


@dataclass(frozen=True)
class Member:
    username: str
    uid: int
    guard_sha256: str


def _trusted_directory(path: Path) -> None:
    s = path.lstat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
        raise AdmissionHold("UNTRUSTED_DIRECTORY")


def _trusted_bytes(path: Path, limit: int) -> bytes:
    s = path.lstat()
    if (not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o077
            or s.st_size < 1 or s.st_size > limit):
        raise AdmissionHold("UNTRUSTED_FILE")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        check = os.fstat(fd)
        if (not stat.S_ISREG(check.st_mode) or check.st_uid != 0
                or check.st_mode & 0o077 or check.st_ino != s.st_ino
                or check.st_dev != s.st_dev):
            raise AdmissionHold("CHANGED_FILE")
        return os.read(fd, limit + 1)
    finally:
        os.close(fd)


def load_roster(path: Path = ROSTER) -> dict[str, Member]:
    if not path.is_absolute() or path.name != "v1-protected-users.json":
        raise AdmissionHold("INVALID_ROSTER_PATH")
    _trusted_directory(path.parent)
    try:
        data = json.loads(_trusted_bytes(path, MAX_ROSTER_BYTES))
    except (ValueError, UnicodeError, TypeError) as exc:
        raise AdmissionHold("INVALID_ROSTER_JSON") from exc
    if not isinstance(data, dict) or set(data) != {"version", "protected"}:
        raise AdmissionHold("INVALID_ROSTER_SCHEMA")
    if type(data["version"]) is not int or data["version"] != 1 or not isinstance(data["protected"], list):
        raise AdmissionHold("INVALID_ROSTER_VERSION")
    members: dict[str, Member] = {}
    seen_uids = set()
    for obj in data["protected"]:
        if not isinstance(obj, dict) or set(obj) != {"username", "uid", "guard_sha256"}:
            raise AdmissionHold("INVALID_MEMBER")
        user, uid, digest = obj["username"], obj["uid"], obj["guard_sha256"]
        if (not isinstance(user, str) or not NAME.fullmatch(user)
                or user in {"root", "nobody"} or type(uid) is not int
                or not 1000 <= uid < 60000 or not isinstance(digest, str)
                or not SHA.fullmatch(digest) or user in members or uid in seen_uids):
            raise AdmissionHold("INVALID_OR_DUPLICATE_MEMBER")
        members[user] = Member(user, uid, digest)
        seen_uids.add(uid)
    return members


def checked_guard(member: Member, directory: Path = GUARD_DIR) -> BootGuardManifest:
    _trusted_directory(directory)
    path = directory / (member.username + ".json")
    raw = _trusted_bytes(path, MAX_GUARD_BYTES)
    if hashlib.sha256(raw).hexdigest() != member.guard_sha256:
        raise AdmissionHold("GUARD_MANIFEST_CHANGED")
    try:
        manifest = BootGuardManifest.parse(json.loads(raw))
    except (ValueError, UnicodeError, TypeError, KeyError) as exc:
        raise AdmissionHold("INVALID_GUARD_MANIFEST") from exc
    if (manifest.request.username != member.username
            or manifest.request.uid != member.uid
            or not manifest.ingress_return or manifest.dns_port is None):
        raise AdmissionHold("PROTECTED_GUARD_MISMATCH")
    return manifest


def check_account(conn: sqlite3.Connection, username: str, uid: int,
                  members: dict[str, Member], guard_loader=checked_guard,
                  guard_probe=probe_local_guards) -> bool:
    """Pure policy boundary over existing F2 decision, with durable roster."""
    member = members.get(username)
    # A renamed/reused OS UID must never obtain legacy rights.
    if member is None and any(x.uid == uid for x in members.values()):
        return False
    if member is not None:
        if member.uid != uid:
            return False
        try:
            manifest = guard_loader(member)
        except (OSError, ValueError, KeyError):
            return False

        def verified(row):
            req = manifest.request
            if (row.username != username or row.uid != uid
                or row.edge_id != req.spec.edge_id
                or row.edge_ipv4 != req.spec.edge_public_ipv4
                or row.priority != req.priority
                or row.route_table != req.spec.route_table
                or row.dns_port != manifest.dns_port):
                return False
            return guard_probe(conn, row)
        decision = decide_account(conn, username, uid, verified)
        return decision.result is AdmissionResult.ALLOW_PROTECTED
    # The roster must be complete BEFORE any PROTECTED runtime row is created.
    # Even if the DB claims PROTECTED, an unlisted identity is not admitted.
    decision = decide_account(conn, username, uid, lambda _: False)
    return decision.result is AdmissionResult.ALLOW_LEGACY


def inspect_pam(pam_contents: str, sshd_effective: str) -> bool:
    """Reuse the existing F4 PAM order/usepam review, with the V1 hook."""
    mapped = pam_contents.replace(PAM_LINE, REQUIRED_ACCOUNT_LINE)
    return inspect_pam_sshd(mapped, sshd_effective).valid and (
        pam_contents.count(PAM_LINE) == 1
    )



def render_roster(manifest_bytes: dict[str, bytes]) -> str:
    """Pure output only: durable identity roster for reviewed deployment.

    Record every protected identity BEFORE its protected runtime intent.
    A rollback must retain these identities until every UID is safely drained.
    """
    if not isinstance(manifest_bytes, dict) or len(manifest_bytes) > 2000:
        raise AdmissionHold("INVALID_ROSTER_INPUT")
    items = []
    uids = set()
    edges = set()
    for username, raw in sorted(manifest_bytes.items()):
        if (not isinstance(username, str) or not NAME.fullmatch(username)
                or not isinstance(raw, bytes) or len(raw) > MAX_GUARD_BYTES):
            raise AdmissionHold("INVALID_MANIFEST_INPUT")
        try:
            manifest = BootGuardManifest.parse(json.loads(raw))
        except (ValueError, KeyError, TypeError, UnicodeError) as exc:
            raise AdmissionHold("INVALID_MANIFEST_INPUT") from exc
        req = manifest.request
        if (req.username != username or not manifest.ingress_return
                or manifest.dns_port is None or req.uid in uids
                or req.spec.edge_id in edges):
            # Single Canary per Edge until G fixes shared-table boot safety.
            raise AdmissionHold("INVALID_OR_SHARED_EDGE_MANIFEST")
        uids.add(req.uid)
        edges.add(req.spec.edge_id)
        items.append(dict(username=username, uid=req.uid,
                          guard_sha256=hashlib.sha256(raw).hexdigest()))
    return json.dumps(dict(version=1, protected=items), sort_keys=True,
                      indent=2) + "\n"


def render_v1_guard_unit(manifest: BootGuardManifest) -> str:
    """Per-user deny-only boot unit; no global SSH dependency, no install."""
    if not manifest.ingress_return or manifest.dns_port is None:
        raise AdmissionHold("V1_REQUIRES_INGRESS_AND_DNS_GUARD")
    unit = render_ssh_required_unit(manifest)
    if "After=local-fs.target\n" not in unit:
        raise AdmissionHold("UNKNOWN_BOOT_UNIT_SHAPE")
    unit = unit.replace("After=local-fs.target\n",
                        "After=local-fs.target wg-quick@wg0.service\n")
    return unit + "\n[Install]\nWantedBy=multi-user.target\n"


def render_pam_review() -> str:
    return (
        "# Review only: no PAM file is modified by F2.\n"
        "# Install as the FIRST account rule in /etc/pam.d/sshd only after\n"
        "# a tested independent root/admin recovery path and valid DB schema.\n"
        + PAM_LINE + "\n"
        "# Install the root-only roster before enabling this hook.\n"
        "# Missing roster or DB denies every non-root SSH login.\n"
        "# No ssh.service/ssh.socket dependency or automatic restart.\n"
    )

def main() -> int:
    if os.geteuid() != 0 or os.environ.get("PAM_TYPE") != "account":
        return 1
    name = os.environ.get("PAM_USER", "")
    if not isinstance(name, str) or not NAME.fullmatch(name):
        return 1
    try:
        uid = pwd.getpwnam(name).pw_uid
        # Break-glass root must not depend on a working DB, roster or WG.
        if name == "root" and uid == 0:
            return 0
        members = load_roster()
        with sqlite3.connect("file:" + FIXED_DB + "?mode=ro",
                             uri=True, timeout=2) as conn:
            conn.execute("PRAGMA query_only=ON")
            return 0 if check_account(conn, name, uid, members) else 1
    except (OSError, sqlite3.Error, ValueError, KeyError, LookupError):
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
