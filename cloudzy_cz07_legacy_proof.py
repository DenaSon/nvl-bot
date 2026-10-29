"""Read-only, job-pinned forensic evidence for the 2026-10-29 CZ07 emergency.

This is NOT a generic recovery bypass. It checks the original cohort by its
pre-existing SHA256 fingerprint, reconciles exact CZ04B usernames, validates
two historical pre-emergency source snapshots, and checks today's account
identities independently of active/inactive status. No backup/DB writes.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
import pwd
from pathlib import Path
import sqlite3
import stat
from urllib.parse import quote

HISTORICAL_JOB_ID = "a0b997e06a92ca35261561f8a5aa5f87"
HISTORICAL_SOURCE = "144.172.69.19"
HISTORICAL_TARGET = "144.172.69.61"
HISTORICAL_TOTAL = 468
HISTORICAL_BATCH = 400
HISTORICAL_EMERGENCY = 68
OPT_IN_ENV = "NVL_CZ07_HISTORICAL_RECOVERY_A0B997_ENABLED"
ONE_ABSENT_ACK_ENV = "NVL_CZ07_ONE_ABSENT_ACK_A0B997_ENABLED"
# Pinned to the independently observed missing username, without publishing it.
# This narrowly prevents *another* missing user from borrowing the exception.
ONE_ABSENT_USERNAME_SHA256 = (
    "60aebe96f658a6a09d6f4c6ff87bd605f85f24c3308566408f1a7899ab4fff18"
)

# The paths are pinned to existing operator-verified snapshots on this Core;
# no user-supplied path or arbitrary operation may activate this exception.
SNAPSHOTS = (
    "/root/nvl-backups/emergency-pre-reconcile-20261029T090210Z-798849.db",
    "/root/nvl-backups/pre-cz07-68-20261029T091736Z-808450.db",
    "/root/nvl-backups/pre-cz07-68-20261029T092202Z-810588.db",
)


class HistoricalProofHold(ValueError):
    pass


def _deny(reason):
    raise HistoricalProofHold(reason)


def _digest_rows(rows):
    # Identical to cloudzy_cz04b._digest; source rows are sorted by username.
    return hashlib.sha256(json.dumps(
        rows, ensure_ascii=False, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()


def _snapshot(path):
    """Open a stable regular-file SQLite backup; do not create WAL/SHM."""
    file = Path(path)
    if not file.is_absolute():
        _deny("EVIDENCE_PATH_NOT_ABSOLUTE")
    try:
        before = file.lstat()
        if not stat.S_ISREG(before.st_mode) or not 4096 <= before.st_size <= 512 * 1024 * 1024:
            _deny("EVIDENCE_FILE_UNSAFE")
        uri = "file:" + quote(str(file), safe="/") + "?mode=ro&immutable=1"
        with closing(sqlite3.connect(uri, uri=True, timeout=5)) as db:
            if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                _deny("EVIDENCE_SQLITE_INVALID")
            rows = db.execute(
                "SELECT username,host,status FROM ssh_accounts "
                "WHERE service_type='ssh' AND "
                "(host=? OR host IS NULL OR host='') "
                "AND status LIKE '%فعال%' AND status NOT LIKE '%غیر%' "
                "ORDER BY username",
                (HISTORICAL_SOURCE,),
            ).fetchall()
        sha = hashlib.sha256()
        with file.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                sha.update(chunk)
        after = file.lstat()
        if (before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns) != (
            after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns,
        ):
            _deny("EVIDENCE_SNAPSHOT_CHANGED")
    except (OSError, sqlite3.Error, UnicodeError) as exc:
        raise HistoricalProofHold("EVIDENCE_SNAPSHOT_UNAVAILABLE") from exc
    names = [item[0] for item in rows]
    if any(not isinstance(name, str) or not name for name in names):
        _deny("EVIDENCE_USERNAME_INVALID")
    if len(names) != len(set(names)):
        _deny("EVIDENCE_DUPLICATE_USERNAME")
    return rows, set(names), sha.hexdigest()


def _target_present_in_snapshot(path, username, expected_sha):
    """Confirm transferred user exists on target in an immutable historical DB."""
    file = Path(path)
    try:
        st = file.lstat()
        if not stat.S_ISREG(st.st_mode):
            _deny("EVIDENCE_POST_BATCH_FILE_UNSAFE")
        with closing(sqlite3.connect(
                "file:" + quote(str(file), safe="/") + "?mode=ro&immutable=1",
                uri=True, timeout=5)) as db:
            if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                _deny("EVIDENCE_POST_BATCH_SQLITE_INVALID")
            present = db.execute(
                "SELECT 1 FROM ssh_accounts WHERE username=? AND "
                "service_type='ssh' AND host=? LIMIT 1",
                (username, HISTORICAL_TARGET),
            ).fetchone() is not None
        sha = hashlib.sha256()
        with file.open("rb") as handle:
            for chunk in iter(lambda:handle.read(1024 * 1024), b""):
                sha.update(chunk)
        now = file.lstat()
        if ((st.st_ino,st.st_dev,st.st_size,st.st_mtime_ns) !=
                (now.st_ino,now.st_dev,now.st_size,now.st_mtime_ns) or
                sha.hexdigest() != expected_sha):
            _deny("EVIDENCE_POST_BATCH_SNAPSHOT_CHANGED")
        return present
    except (OSError,sqlite3.Error) as exc:
        raise HistoricalProofHold("EVIDENCE_POST_BATCH_UNAVAILABLE") from exc


def verify_historical_job(db, rec, *, snapshots=SNAPSHOTS):
    """Return counts and SHA-only provenance, or fail closed.

    The caller must separately preserve current route/DNS/6G and operator
    approval checks. Return has NO username/password/customer data.
    """
    if (rec["id"] != HISTORICAL_JOB_ID or
            rec["source"] != HISTORICAL_SOURCE or
            rec["target"] != HISTORICAL_TARGET or
            rec["total"] != HISTORICAL_TOTAL or
            rec["moved"] != HISTORICAL_TOTAL or
            rec["status"] != "HOLD" or
            rec["code"] != "EMERGENCY_LOCAL_CAS_E2E_PENDING" or
            rec["cancel_requested"]):
        _deny("EVIDENCE_JOB_IDENTITY_CHANGED")
    if len(snapshots) != 3 or len(set(map(str, snapshots))) != 3:
        _deny("EVIDENCE_SNAPSHOT_SET_INVALID")
    initial_rows, initial, pre_sha = _snapshot(snapshots[0])
    _, after_batch, batch_sha = _snapshot(snapshots[1])
    _, before_emergency, emergency_sha = _snapshot(snapshots[2])
    if (len(initial) != HISTORICAL_TOTAL or
            _digest_rows(initial_rows) != rec["source_fingerprint"]):
        _deny("EVIDENCE_ORIGINAL_COHORT_FINGERPRINT_MISMATCH")

    ops = db.execute(
        "SELECT count,payload_json FROM cloudzy_cz04b_operations "
        "WHERE kind='users' AND status='DONE' AND source=? AND target=? "
        "AND actor=? AND chat=? AND provider_id=? AND started_at>=? "
        "ORDER BY started_at,rowid",
        (rec["source"],rec["target"],rec["actor"],rec["chat"],
         rec["provider_id"],rec["started_at"]),
    ).fetchall()
    if len(ops) != 2:
        _deny("EVIDENCE_BATCH_RECEIPT_COUNT_INVALID")
    selected = []
    try:
        for count, payload in ops:
            names = json.loads(payload)
            if (not isinstance(names, list) or
                    any(not isinstance(name,str) or not name for name in names) or
                    len(names) != int(count)):
                _deny("EVIDENCE_BATCH_PAYLOAD_INVALID")
            selected.extend(names)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise HistoricalProofHold("EVIDENCE_BATCH_PAYLOAD_INVALID") from exc
    batch_names = set(selected)
    if (len(selected) != HISTORICAL_BATCH or
            len(batch_names) != HISTORICAL_BATCH or
            not batch_names.issubset(initial)):
        _deny("EVIDENCE_BATCH_COHORT_MISMATCH")
    missing = initial - batch_names
    if (len(missing) != HISTORICAL_EMERGENCY or
            after_batch != missing or before_emergency != missing):
        _deny("EVIDENCE_EMERGENCY_COHORT_MISMATCH")

    audit = db.execute(
        "SELECT source,target,affected,previous_status,previous_code,event_code "
        "FROM nvl_emergency_migration_audit WHERE job_id=?",
        (rec["id"],),
    ).fetchall()
    if [tuple(row) for row in audit] != [(
            HISTORICAL_SOURCE,HISTORICAL_TARGET,HISTORICAL_EMERGENCY,
            "HOLD","CLOUDZY_PROVIDER_UNAVAILABLE",
            "EMERGENCY_LOCAL_CAS_E2E_PENDING",
    )]:
        _deny("EVIDENCE_EMERGENCY_AUDIT_MISMATCH")
    if not db.execute(
        "SELECT 1 FROM cloudzy_cz07_events WHERE job_id=? "
        "AND stage='HOLD' AND code='EMERGENCY_LOCAL_CAS_E2E_PENDING' "
        "AND moved=? AND remaining=0 LIMIT 1",
        (rec["id"],HISTORICAL_TOTAL),
    ).fetchone():
        _deny("EVIDENCE_EMERGENCY_EVENT_MISSING")

    # Identity check deliberately includes inactive accounts. New accounts
    # cannot substitute for any missing original username.
    current = db.execute(
        "SELECT username FROM ssh_accounts "
        "WHERE service_type='ssh' AND host=?",
        (HISTORICAL_TARGET,),
    ).fetchall()
    target_names = {name for (name,) in current}
    absent = initial - target_names
    absent_hash = None
    if absent:
        if (len(absent) != 1 or
                os.environ.get(ONE_ABSENT_ACK_ENV) != "1"):
            _deny("EVIDENCE_ORIGINAL_ACCOUNT_NOT_AT_TARGET")
        username = next(iter(absent))
        absent_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()
        if (absent_hash != ONE_ABSENT_USERNAME_SHA256 or
                username not in batch_names or username in missing):
            _deny("EVIDENCE_UNEXPECTED_ABSENT_IDENTITY")
        if db.execute(
            "SELECT 1 FROM ssh_accounts WHERE username=? LIMIT 1",
            (username,),
        ).fetchone():
            _deny("EVIDENCE_ACCOUNT_REASSIGNED")
        if (not _target_present_in_snapshot(snapshots[1],username,batch_sha)
                or not _target_present_in_snapshot(
                    snapshots[2],username,emergency_sha)):
            _deny("EVIDENCE_ABSENT_NOT_TRANSFERRED")
        try:
            pwd.getpwnam(username)
        except KeyError:
            pass
        else:
            _deny("EVIDENCE_ABSENT_LINUX_ACCOUNT_PRESENT")
    remaining_active = db.execute(
        "SELECT COUNT(*) FROM ssh_accounts WHERE service_type='ssh' "
        "AND (host=? OR host IS NULL OR host='') "
        "AND status LIKE '%فعال%' AND status NOT LIKE '%غیر%'",
        (HISTORICAL_SOURCE,),
    ).fetchone()[0]
    foreign_active = db.execute(
        "SELECT COUNT(*) FROM ssh_accounts WHERE service_type='ssh' "
        "AND status LIKE '%فعال%' AND status NOT LIKE '%غیر%' "
        "AND COALESCE(host,'') NOT IN (?,?)",
        (HISTORICAL_SOURCE,HISTORICAL_TARGET),
    ).fetchone()[0]
    if remaining_active or foreign_active:
        _deny("EVIDENCE_ACTIVE_ACCOUNT_ROUTE_CHANGED")

    hashes = [pre_sha, batch_sha, emergency_sha]
    proof_hash = hashlib.sha256(json.dumps(
        {"job":rec["id"],"fingerprint":rec["source_fingerprint"],
         "snapshots":hashes,"batches":HISTORICAL_BATCH,
         "emergency":HISTORICAL_EMERGENCY,
         "one_absent_sha256":absent_hash},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    return {
        "moved":HISTORICAL_TOTAL, "remaining":0,
        "batches":HISTORICAL_BATCH, "emergency":HISTORICAL_EMERGENCY,
        "extra_target":len(target_names - initial),
        "historical_proof_sha256":proof_hash,
        "historical_snapshots_sha256":hashes,
        "historical_identity_verified":True,
        "one_absent_sha256":absent_hash,
        "one_absent_acknowledged":bool(absent_hash),
    }
