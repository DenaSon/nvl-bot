"""K2 production canary: OFFLINE snapshot consistency, never a release ticket.

This verifier is intentionally *not* proof of independent recovery: checksum
files can be forged together with an archive, provider VM snapshots may not
exist, and runtime iptables/PAM/SSH state is not restored by copying a tarball.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import stat
import tarfile
from typing import Callable


class CanaryBackupHold(ValueError):
    pass


@dataclass(frozen=True)
class CanaryBackupAudit:
    core_db_ok: bool
    manifest_ok: bool
    archive_ok: bool
    protected_paths_covered: bool
    blockers: tuple[str, ...]
    independent_offhost_copy_verified: bool = False
    provider_volume_snapshot_verified: bool = False
    independent_restore_drill_verified: bool = False
    live_kernel_rollback_verified: bool = False
    authorizes_customer_change: bool = False

    @property
    def local_consistency(self):
        return not self.blockers


CORE_REQUIRED = frozenset({
    "system-configs.tar.gz", "master_bot.sqlite3",
    "diagnostics/archived-roots.txt",
    "diagnostics/host-state.txt", "diagnostics/db-tables.txt",
})
CORE_IDENTITY = frozenset({
    "etc/ssh", "etc/pam.d", "etc/passwd", "etc/shadow",
})
CHECKSUM = re.compile(r"([0-9a-f]{64})  ([a-z0-9][a-zA-Z0-9._/-]*)\Z")
MAX_MANIFEST = 65536
MAX_ROOTS = 2048
MAX_MEMBERS = 150000


def _secure_file(path: Path, owner: int, *, allow_dir=False):
    info=path.lstat()
    if (info.st_uid != owner or info.st_mode & 0o077
            or (not stat.S_ISDIR(info.st_mode) if allow_dir else
                not stat.S_ISREG(info.st_mode))):
        raise CanaryBackupHold("BACKUP_UNTRUSTED_OWNERSHIP")
    return info


def _digest(path: Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _relative(raw: str) -> str:
    if (not raw or raw.startswith("/") or "\\" in raw or "\x00" in raw
            or len(raw)>2048):
        raise CanaryBackupHold("ARCHIVE_PATH_UNTRUSTED")
    p=PurePosixPath(raw)
    if any(x in ("", ".", "..") for x in raw.split("/")) or str(p)!=raw:
        raise CanaryBackupHold("ARCHIVE_PATH_UNTRUSTED")
    return raw


def audit_backup(
    directory: Path, *, owner_uid: int = 0, expected_role: str = "core",
    active_protected_dirs: tuple[str, ...] = (),
) -> CanaryBackupAudit:
    """Verify archive and SQLite backup without touching running Linux state.

    active_protected_dirs MUST be supplied from a separate trusted host
    inventory; an absent path within a backup is otherwise not proof that
    the production source lacked this path.
    """
    if (not isinstance(directory,Path) or not directory.is_absolute()
            or type(owner_uid) is not int or owner_uid < 0
            or expected_role != "core"
            or any(x not in ("etc/nvl-egress","opt/nvl-egress",
                             "root/nvl-egress-v1","root/nvl-egress-keys")
                   for x in active_protected_dirs)):
        raise CanaryBackupHold("INVALID_BACKUP_VERIFICATION_SCOPE")
    blockers=[]
    try:
        _secure_file(directory,owner_uid,allow_dir=True)
        manifest=directory/"SHA256SUMS"
        _secure_file(manifest,owner_uid)
        if manifest.stat().st_size>MAX_MANIFEST:
            raise CanaryBackupHold("CHECKSUM_MANIFEST_TOO_LARGE")
        pairs={}
        for line in manifest.read_text(encoding="ascii").splitlines():
            m=CHECKSUM.fullmatch(line)
            if not m:
                raise CanaryBackupHold("INVALID_CHECKSUM_FORMAT")
            digest,name=m.groups()
            _relative(name)
            if name in pairs:
                raise CanaryBackupHold("DUPLICATE_CHECKSUM_ENTRY")
            pairs[name]=digest
        if set(pairs)!=CORE_REQUIRED:
            raise CanaryBackupHold("INCOMPLETE_BACKUP_CHECKSUM_COVERAGE")
        # Disallow path tricks in intermediates, even though names are known.
        for name,digest in pairs.items():
            file=directory.joinpath(*name.split("/"))
            if len(name.split("/"))>1:
                _secure_file(file.parent,owner_uid,allow_dir=True)
            _secure_file(file,owner_uid)
            if _digest(file)!=digest:
                raise CanaryBackupHold("BACKUP_DIGEST_MISMATCH")
        manifest_ok=True
    except (OSError,UnicodeError,ValueError) as exc:
        blockers.append(str(exc) if isinstance(exc,CanaryBackupHold)
                        else "BACKUP_MANIFEST_UNAVAILABLE")
        manifest_ok=False

    archive_ok=False
    paths_covered=False
    db_ok=False
    if manifest_ok:
        try:
            roots_file=directory/"diagnostics/archived-roots.txt"
            if roots_file.stat().st_size>MAX_MANIFEST:
                raise CanaryBackupHold("ARCHIVE_ROOTS_UNTRUSTED")
            roots=roots_file.read_text(encoding="utf-8").splitlines()
            # GNU sort -zu uses the producer host's LC_COLLATE. Python's
            # Unicode lexical sort is NOT an integrity/security invariant,
            # so an otherwise valid, unique manifest must not be rejected
            # because the VPS and CI use different collation locales.
            # Keep strict path, cardinality, digest and tar coverage checks.
            if not roots or len(roots)>MAX_ROOTS:
                raise CanaryBackupHold("ARCHIVE_ROOTS_UNTRUSTED")
            if len(set(roots)) != len(roots):
                raise CanaryBackupHold("ARCHIVE_ROOTS_DUPLICATED")
            for root in roots:
                _relative(root)
            if not CORE_IDENTITY<=set(roots):
                raise CanaryBackupHold("CORE_ACCOUNT_RECOVERY_FILES_NOT_ARCHIVED")
            members=set()
            with tarfile.open(directory/"system-configs.tar.gz","r:gz") as archive:
                for i,item in enumerate(archive):
                    if i>=MAX_MEMBERS:
                        raise CanaryBackupHold("UNBOUNDED_ARCHIVE_MEMBER_COUNT")
                    name=item.name.removeprefix("./").rstrip("/")
                    _relative(name)
                    if item.issym() or item.islnk() or item.isdev():
                        # Existing linked config resources must not serve as
                        # proof of a complete restorable security policy.
                        continue
                    members.add(name)
            if any(not any(m==r or m.startswith(r+"/") for m in members)
                   for r in roots):
                raise CanaryBackupHold("ARCHIVE_ROOTS_NOT_ACTUALLY_COVERED")
            archive_ok=True
            if any(r not in roots for r in active_protected_dirs):
                blockers.append("ACTIVE_K2_PROTECTION_NOT_SNAPSHOTTED")
            else:
                paths_covered=True
        except (OSError,ValueError,tarfile.TarError,UnicodeError) as exc:
            blockers.append(str(exc) if isinstance(exc,CanaryBackupHold)
                            else "ARCHIVE_UNREADABLE_OR_UNTRUSTED")
        try:
            dbfile=directory/"master_bot.sqlite3"
            # mode=ro and query_only prohibit write even on a trusted file.
            conn=sqlite3.connect(dbfile.as_uri()+"?mode=ro",uri=True,timeout=3)
            try:
                conn.execute("PRAGMA query_only=ON")
                if conn.execute("PRAGMA integrity_check").fetchone()!=("ok",):
                    raise CanaryBackupHold("BACKUP_SQLITE_CORRUPT")
                expected={"settings","ssh_accounts","host_pool","failover_operations"}
                actual={r[0] for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()}
                if not expected<=actual:
                    raise CanaryBackupHold("BACKUP_DB_SCHEMA_INCOMPLETE")
                db_ok=True
            finally:
                conn.close()
        except (OSError,sqlite3.Error,ValueError) as exc:
            blockers.append(str(exc) if isinstance(exc,CanaryBackupHold)
                            else "BACKUP_SQLITE_NOT_READABLE")
    return CanaryBackupAudit(
        db_ok,manifest_ok,archive_ok,paths_covered,
        tuple(dict.fromkeys(blockers)),
    )


def main(argv=None) -> int:
    parser=argparse.ArgumentParser(description="K2 backup consistency ONLY (no release)")
    parser.add_argument("--backup",required=True)
    args=parser.parse_args(argv)
    try:
        if os.geteuid()!=0:
            raise CanaryBackupHold("ROOT_ONLY")
        archive=Path(args.backup)
        if (archive.is_symlink() or not archive.is_absolute()
                or archive.parent != Path("/root/nvl-emergency-backups")):
            raise CanaryBackupHold("BACKUP_ROOT_NOT_PINNED")
        active=tuple(root.removeprefix("/") for root in (
            "/etc/nvl-egress","/opt/nvl-egress",
            "/root/nvl-egress-v1","/root/nvl-egress-keys",
        ) if Path(root).exists() or Path(root).is_symlink())
        result=audit_backup(archive,active_protected_dirs=active)
    except (OSError,ValueError) as exc:
        result=CanaryBackupAudit(False,False,False,False,
                                  (str(exc) if isinstance(exc,CanaryBackupHold)
                                   else "BACKUP_VERIFICATION_UNAVAILABLE",))
    print(json.dumps({
        "status":"LOCAL_CONSISTENT" if result.local_consistency else "HOLD",
        "blockers":list(result.blockers),
        "backup_local_consistency":result.local_consistency,
        "offhost_copy_verified":False,
        "provider_volume_snapshot_verified":False,
        "independent_restore_drill_verified":False,
        "live_kernel_rollback_verified":False,
        "authorizes_customer_change":False,
        "changed":False,
    },sort_keys=True))
    return 0 if result.local_consistency else 2


if __name__=="__main__":
    raise SystemExit(main())
