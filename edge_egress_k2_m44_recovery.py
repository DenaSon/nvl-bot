"""K2 M4.4 root-owned, SELECT-only restart recovery view.

Checkpoint is an operator projection; original failover_operations is the
sole P3/6G authority. Do not infer real packet egress from a DB success row,
and NEVER retry, resume, unlock or rewrite a stuck operation here.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import hmac
import json
import os
import pwd
import re
import sqlite3
import time
from typing import Callable

from edge_egress_k2_migration_inventory import MigrationSelection, select_migration
from edge_egress_p3_executor import ExecutionScope, _scope_digest

M44_ROOT_STATUS_ENABLED = False
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_STATES = frozenset(("PREPARED", "RUNNING", "SUCCEEDED", "HOLD"))


class M44StatusHold(ValueError):
    pass


@dataclass(frozen=True)
class RecoveredUser:
    username: str
    state: str


@dataclass(frozen=True)
class RecoveredWave:
    edge_id: str
    wave_state: str
    original_6g_busy: bool
    unresolved: bool
    users: tuple[RecoveredUser, ...]
    # No nonce/hash/ticket/secret/protected-IP routing assertions in this view.
    note: str


def _select_only(conn: sqlite3.Connection, query: str, params=()):
    """The caller opens original Core DB read-only and this adapter SELECTs only."""
    return conn.execute(query, params).fetchall()


def _receipt_scope_matches(conn: sqlite3.Connection, *, name: str, uid: int,
                           edge_id: str, target: str, op_id: int) -> bool:
    try:
        rows = _select_only(
            conn, "SELECT status,source_host,target_host,detail_json "
                  "FROM failover_operations WHERE id=?", (op_id,),
        )
        if len(rows) != 1:
            return False
        status, source, destination, raw = rows[0]
        if (status != "SUCCEEDED" or destination != target
            or not isinstance(raw, str) or len(raw) > 16384):
            return False
        details = json.loads(raw)
        if not isinstance(details, dict):
            return False
        action = "UID_ENROLL_SOURCE" if source == target else "UID_ATTACH"
        scope = ExecutionScope(action, edge_id, source, destination,
                               username=name, uid=uid)
        digest = _scope_digest(scope)
        return bool(
            details.get("kind") == "K2_P3A"
            and details.get("phase") == "EGRESS_P3_VERIFIED"
            and details.get("action") == action
            and details.get("edge_id") == edge_id
            and details.get("manual_recovery", False) is False
            and isinstance(details.get("scope_digest"), str)
            and _DIGEST.fullmatch(details["scope_digest"])
            and hmac.compare_digest(details["scope_digest"], digest)
            and isinstance(details.get("nonce_hash"), str)
            and _DIGEST.fullmatch(details["nonce_hash"])
        )
    except (sqlite3.Error, ValueError, TypeError, KeyError):
        return False


def _read_checkpoint(conn: sqlite3.Connection, selection: MigrationSelection,
                     actor: int, chat: int):
    if not _select_only(
        conn, "SELECT 1 FROM sqlite_master "
              "WHERE type='table' AND name='k2_m4_wave_checkpoints'",
    ):
        raise M44StatusHold("M44_CHECKPOINT_SCHEMA_MISSING")
    # Root-only role-scope: never give another actor's historic cohort status.
    rows = _select_only(
        conn, "SELECT plan_digest,actor_id,chat_id,edge_id,usernames_json,"
              "state,expires_at,progress_json,reason "
              "FROM k2_m4_wave_checkpoints "
              "WHERE actor_id=? AND chat_id=? AND edge_id=? "
              "AND usernames_json=? ORDER BY created_at DESC,rowid DESC LIMIT 1",
        (actor, chat, selection.target_edge_id,
         json.dumps(selection.usernames)),
    )
    return rows[0] if rows else None


def inspect_root_recovery(
    db_conn: Callable, selection: MigrationSelection, *, actor_id: int,
    chat_id: int, admin_authorized: Callable[[int, int], bool],
    os_uid: Callable[[str], int] = lambda n: pwd.getpwnam(n).pw_uid,
    clock: Callable[[], int] = lambda: int(time.time()),
    geteuid: Callable[[], int] = os.geteuid,
    release_enabled: bool = False,
) -> RecoveredWave:
    if (not M44_ROOT_STATUS_ENABLED or release_enabled is not True
        or not callable(geteuid) or geteuid() != 0
        or not callable(db_conn) or not callable(admin_authorized)
        or not callable(os_uid) or not callable(clock)
        or type(actor_id) is not int or actor_id <= 0
        or type(chat_id) is not int or chat_id == 0
        or not isinstance(selection, MigrationSelection)
        or select_migration(selection.mode, selection.usernames,
                            selection.target_edge_id) != selection
        or len(selection.usernames) > 10):
        raise M44StatusHold("M44_ROOT_STATUS_NOT_RELEASED")
    # Fail closed *before* touching any DB row if role was revoked.
    if admin_authorized(actor_id, chat_id) is not True:
        raise M44StatusHold("M44_ROOT_ADMIN_NOT_AUTHORIZED")
    now = clock()
    if type(now) is not int or now <= 0:
        raise M44StatusHold("M44_CLOCK_UNTRUSTED")
    try:
        with db_conn() as conn:
            global_busy = _select_only(
                conn, "SELECT COUNT(*) FROM failover_operations "
                      "WHERE status='RUNNING'",
            )
            unresolved_rows = _select_only(
                conn, "SELECT COUNT(*) FROM k2_m4_wave_checkpoints "
                      "WHERE state IN ('RUNNING','HOLD')",
            )
            if (len(global_busy) != 1 or len(unresolved_rows) != 1
                or type(global_busy[0][0]) is not int
                or type(unresolved_rows[0][0]) is not int):
                raise M44StatusHold("M44_6G_OR_CHECKPOINT_UNAVAILABLE")
            busy = global_busy[0][0] > 0
            unresolved = busy or unresolved_rows[0][0] > 0
            row = _read_checkpoint(conn, selection, actor_id, chat_id)
            if row is None:
                return RecoveredWave(
                    selection.target_edge_id, "NO_CHECKPOINT", busy,
                    unresolved, tuple(
                        RecoveredUser(name, "UNKNOWN") for name in selection.usernames
                    ), "NO_ROOT_CHECKPOINT_FOR_SCOPE",
                )
            (digest, actor, chat, edge, names_json, state, expires,
             progress_json, reason) = row
            if (type(digest) is not str or not _DIGEST.fullmatch(digest)
                or actor != actor_id or chat != chat_id
                or edge != selection.target_edge_id or state not in _STATES
                or type(expires) is not int or not isinstance(reason, str)
                or len(reason) > 250 or not isinstance(progress_json, str)
                or len(progress_json) > 4096):
                raise M44StatusHold("M44_CHECKPOINT_CORRUPT")
            # Decode exact names and original DB ordered per-UID receipts.
            if (json.loads(names_json) != list(selection.usernames)
                or not isinstance(json.loads(progress_json), list)):
                raise M44StatusHold("M44_CHECKPOINT_SELECTED_SCOPE_CHANGED")
            progress = json.loads(progress_json)
            if len(progress) > len(selection.usernames) or (
                state == "SUCCEEDED"
                and len(progress) != len(selection.usernames)
            ):
                raise M44StatusHold("M44_CHECKPOINT_PROGRESS_LENGTH_UNTRUSTED")
            users = []
            mismatch = False
            for index, name in enumerate(selection.usernames):
                if index >= len(progress):
                    users.append(RecoveredUser(name, "UNKNOWN" if state in ("RUNNING","HOLD")
                                              else "NOT_STARTED"))
                    continue
                item = progress[index]
                if (not isinstance(item, list) or len(item) != 3
                    or item[0] != name or item[1] not in (
                        "VERIFIED", "HOLD", "DEFERRED",
                    )):
                    raise M44StatusHold("M44_PROGRESS_ORDER_OR_STATE_CORRUPT")
                if item[1] != "VERIFIED":
                    if item[2] is not None:
                        raise M44StatusHold("M44_NON_VERIFIED_RECEIPT_FORGED")
                    users.append(RecoveredUser(name,item[1]))
                    continue
                op = item[2]
                if type(op) is not int or op <= 0:
                    raise M44StatusHold("M44_OPERATION_ID_CORRUPT")
                try:
                    uid = os_uid(name)
                except (OSError, KeyError, ValueError, TypeError):
                    uid = None
                good = (type(uid) is int and 1000 <= uid < 60000
                        and len(_select_only(
                            conn, "SELECT edge_public_ipv4 "
                                  "FROM edge_egress_allocations "
                                  "WHERE edge_id=?", (edge,),
                        )) == 1)
                if good:
                    ip = _select_only(
                        conn, "SELECT edge_public_ipv4 "
                              "FROM edge_egress_allocations "
                              "WHERE edge_id=?", (edge,),
                    )[0][0]
                    good = _receipt_scope_matches(
                        conn, name=name, uid=uid, edge_id=edge,
                        target=ip, op_id=op,
                    )
                if not good:
                    mismatch = True
                users.append(RecoveredUser(
                    name, "RECEIPT_SCOPED" if good else "RECEIPT_UNVERIFIED",
                ))
            if state == "RUNNING":
                wave = "UNKNOWN_INFLIGHT"
            elif state == "PREPARED":
                wave = "EXPIRED" if expires <= now else "PREPARED"
            elif state == "SUCCEEDED":
                wave = ("RECEIPTS_RECORDED"
                        if not mismatch and all(u.state == "RECEIPT_SCOPED"
                                                for u in users)
                        else "HOLD")
            else:
                wave = "HOLD"
            if mismatch or wave in ("HOLD", "UNKNOWN_INFLIGHT"):
                unresolved = True
            return RecoveredWave(
                edge, wave, busy, unresolved, tuple(users),
                "REQUIRES_INDEPENDENT_PACKET_PROOF" if wave == "RECEIPTS_RECORDED"
                else "MANUAL_RECONCILIATION_REQUIRED"
                if unresolved else "ROOT_CHECKPOINT_READ_ONLY",
            )
    except M44StatusHold:
        raise
    except (sqlite3.Error, ValueError, TypeError, KeyError, OSError) as exc:
        raise M44StatusHold("M44_CHECKPOINT_READ_ONLY_UNAVAILABLE") from exc
