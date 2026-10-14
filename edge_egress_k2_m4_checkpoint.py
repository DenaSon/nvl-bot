"""K2 M4 durable *operator projection*, never a second 6G lock or authority.

One root-owned SQLite table in the original Core DB, with a unique RUNNING
wave slot. The authoritative mutation and per-UID success receipt remain
ONLY in failover_operations (original P3/6G).

A crashed RUNNING wave remains UNKNOWN_INFLIGHT: no auto-retry, auto-unlock,
"SUCCEEDED" promotion or removal of the original 6G intent is possible here.
Install the table only through a reviewed root migration before live release.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import hmac
import json
import re
import sqlite3
import time
from typing import Callable

from edge_egress_k2_m3_waves import MigrationWavePlan, WaveApproval, WaveReport

M4_CHECKPOINT_RELEASE_ENABLED = False
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_STATES = frozenset(("PREPARED","RUNNING","SUCCEEDED","HOLD"))


class CheckpointHold(ValueError):
    pass


@dataclass(frozen=True)
class CheckpointView:
    plan_digest: str
    actor_id: int
    chat_id: int
    usernames: tuple[str,...]
    edge_id: str
    state: str
    expires_at: int
    progress: tuple[tuple[str,str,int | None],...]
    reason: str


def install_checkpoint_schema(conn: sqlite3.Connection) -> None:
    """Reviewed root DB migration, OFF by default; no actor authorizations."""
    conn.execute(
        "CREATE TABLE IF NOT EXISTS k2_m4_wave_checkpoints ("
        " approval_hash TEXT PRIMARY KEY,"
        " plan_digest TEXT NOT NULL,"
        " actor_id INTEGER NOT NULL,"
        " chat_id INTEGER NOT NULL,"
        " edge_id TEXT NOT NULL,"
        " usernames_json TEXT NOT NULL,"
        " state TEXT NOT NULL CHECK(state IN "
        " ('PREPARED','RUNNING','SUCCEEDED','HOLD')),"
        " expires_at INTEGER NOT NULL,"
        " progress_json TEXT NOT NULL DEFAULT '[]',"
        " reason TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL,"
        " updated_at INTEGER NOT NULL"
        ")"
    )
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS k2_m4_single_running_wave "
        "ON k2_m4_wave_checkpoints ((1)) WHERE state='RUNNING'"
    )


def _pin(plan: MigrationWavePlan, approval: WaveApproval) -> tuple[str,str]:
    if (not isinstance(plan,MigrationWavePlan)
        or not isinstance(approval,WaveApproval)
        or plan.digest!=approval.plan_digest
        or not _DIGEST.fullmatch(plan.digest)
        or not isinstance(approval.signature,str)
        or not _DIGEST.fullmatch(approval.signature)
        or len(plan.members)<1 or len(plan.members)>10
        or tuple(m.username for m in plan.members)!=plan.selection.usernames):
        raise CheckpointHold("M4_CHECKPOINT_UNTRUSTED_PLAN")
    return sha256(approval.signature.encode("ascii")).hexdigest(),plan.digest


def _valid_payload(plan: MigrationWavePlan, progress: WaveReport) -> str:
    if (not isinstance(progress,WaveReport)
        or progress.plan_digest!=plan.digest
        or tuple(p.username for p in progress.progress)!=plan.selection.usernames
        or any(p.status not in ("VERIFIED","HOLD","DEFERRED")
               or type(p.uid) is not int
               or p.uid!=m.uid
               or (p.status=="VERIFIED" and (
                   type(p.operation_id) is not int or p.operation_id<=0))
               for p,m in zip(progress.progress,plan.members))
        or (progress.all_verified and (
            progress.halted or any(p.status!="VERIFIED" for p in progress.progress)))):
        raise CheckpointHold("M4_PROGRESS_NOT_VERIFIABLE")
    return json.dumps([
        (p.username,p.status,p.operation_id if p.status=="VERIFIED" else None)
        for p in progress.progress
    ],ensure_ascii=True,separators=(",",":"))


class DurableWaveCheckpoint:
    """Root-only, original-DB transaction port with no 6G lease mutation."""

    def __init__(self, *, db_conn: Callable,
                 geteuid: Callable[[],int],clock: Callable[[],int] =
                 lambda:int(time.time()),release_enabled: bool = False):
        self.db_conn=db_conn
        self.geteuid=geteuid
        self.clock=clock
        self.release_enabled=release_enabled

    def _gate(self) -> int:
        if (not M4_CHECKPOINT_RELEASE_ENABLED
            or self.release_enabled is not True
            or not callable(self.db_conn) or not callable(self.geteuid)
            or not callable(self.clock) or self.geteuid()!=0):
            raise CheckpointHold("M4_ROOT_CHECKPOINT_NOT_RELEASED")
        ts=self.clock()
        if type(ts) is not int or ts<=0:
            raise CheckpointHold("M4_CHECKPOINT_TIME_UNTRUSTED")
        return ts

    def prepare(self,plan: MigrationWavePlan,approval: WaveApproval) -> None:
        stamp=self._gate()
        key,digest=_pin(plan,approval)
        if (approval.expires_at<=stamp or
            approval.expires_at>stamp+300):
            raise CheckpointHold("M4_CHECKPOINT_APPROVAL_EXPIRED")
        try:
            with self.db_conn() as conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    "INSERT INTO k2_m4_wave_checkpoints "
                    "(approval_hash,plan_digest,actor_id,chat_id,"
                    "edge_id,usernames_json,state,expires_at,created_at,updated_at)"
                    " VALUES(?,?,?,?,?,?,'PREPARED',?,?,?)",
                    (key,digest,approval.actor_id,approval.chat_id,
                     plan.selection.target_edge_id,
                     json.dumps(plan.selection.usernames),approval.expires_at,
                     stamp,stamp),
                )
        except sqlite3.IntegrityError as exc:
            raise CheckpointHold("M4_CHECKPOINT_DUPLICATE_APPROVAL") from exc
        except sqlite3.Error as exc:
            raise CheckpointHold("M4_CHECKPOINT_DB_UNAVAILABLE") from exc

    def begin(self,plan: MigrationWavePlan,approval: WaveApproval,
              *,actor_id:int,chat_id:int) -> None:
        stamp=self._gate()
        key,digest=_pin(plan,approval)
        try:
            with self.db_conn() as conn:
                conn.execute("BEGIN IMMEDIATE")
                # A crashed previous wave must not make an idle 6G claim.
                busy=conn.execute(
                    "SELECT COUNT(*) FROM failover_operations "
                    "WHERE status='RUNNING'"
                ).fetchone()
                if busy is None or type(busy[0]) is not int or busy[0]!=0:
                    raise CheckpointHold("M4_ORIGINAL_6G_BUSY_OR_UNKNOWN")
                count=conn.execute(
                    "UPDATE k2_m4_wave_checkpoints "
                    "SET state='RUNNING',updated_at=? "
                    "WHERE approval_hash=? AND plan_digest=? "
                    "AND actor_id=? AND chat_id=? "
                    "AND edge_id=? AND usernames_json=? "
                    "AND expires_at>? AND state='PREPARED'",
                    (stamp,key,digest,actor_id,chat_id,
                     plan.selection.target_edge_id,
                     json.dumps(plan.selection.usernames),stamp),
                ).rowcount
                if count!=1:
                    raise CheckpointHold("M4_CHECKPOINT_CONSUMED_OR_CHANGED")
                # Unique RUNNING index forbids another wave, including
                # after a process restart. Never modify the 6G journal.
        except sqlite3.IntegrityError as exc:
            raise CheckpointHold("M4_ANOTHER_WAVE_UNKNOWN_INFLIGHT") from exc
        except sqlite3.Error as exc:
            raise CheckpointHold("M4_CHECKPOINT_DB_UNAVAILABLE") from exc

    def record_verified(self,plan: MigrationWavePlan,
                        approval: WaveApproval,username: str,
                        uid: int,operation_id: int) -> None:
        """Commit one verified original-6G UID before dispatching the next."""
        stamp=self._gate()
        key,digest=_pin(plan,approval)
        if type(uid) is not int or type(operation_id) is not int or operation_id<=0:
            raise CheckpointHold("M4_UID_RECEIPT_UNTRUSTED")
        try:
            with self.db_conn() as conn:
                conn.execute("BEGIN IMMEDIATE")
                row=conn.execute(
                    "SELECT progress_json,state FROM k2_m4_wave_checkpoints "
                    "WHERE approval_hash=? AND plan_digest=?",
                    (key,digest),
                ).fetchone()
                if row is None or row[1]!="RUNNING":
                    raise CheckpointHold("M4_NO_RUNNING_WAVE_FOR_UID")
                old=json.loads(row[0])
                if not isinstance(old,list) or len(old)>=len(plan.members):
                    raise CheckpointHold("M4_UID_PROGRESS_LENGTH_CHANGED")
                expected=plan.members[len(old)]
                if expected.username!=username or expected.uid!=uid:
                    raise CheckpointHold("M4_UID_PROGRESS_ORDER_CHANGED")
                if any(not isinstance(item,list) or len(item)!=3
                       or item[0]!=plan.members[i].username
                       or item[1]!="VERIFIED" or type(item[2]) is not int
                       or item[2]<=0
                       for i,item in enumerate(old)):
                    raise CheckpointHold("M4_UID_PRIOR_PROGRESS_CORRUPT")
                old.append([username,"VERIFIED",operation_id])
                changed=conn.execute(
                    "UPDATE k2_m4_wave_checkpoints "
                    "SET progress_json=?,updated_at=? "
                    "WHERE approval_hash=? AND plan_digest=? "
                    "AND state='RUNNING' AND progress_json=?",
                    (json.dumps(old,separators=(",",":")),stamp,
                     key,digest,row[0]),
                ).rowcount
                if changed!=1:
                    raise CheckpointHold("M4_UID_PROGRESS_CAS_FAILED")
        except CheckpointHold:
            raise
        except (sqlite3.Error,ValueError,TypeError,KeyError,IndexError) as exc:
            raise CheckpointHold("M4_UID_PROGRESS_PERSISTENCE_FAILED") from exc

    def finish(self,plan: MigrationWavePlan,approval: WaveApproval,
               report: WaveReport) -> None:
        stamp=self._gate()
        key,digest=_pin(plan,approval)
        payload=_valid_payload(plan,report)
        terminal="SUCCEEDED" if report.all_verified else "HOLD"
        try:
            with self.db_conn() as conn:
                conn.execute("BEGIN IMMEDIATE")
                old=conn.execute(
                    "SELECT progress_json FROM k2_m4_wave_checkpoints "
                    "WHERE approval_hash=? AND plan_digest=? AND state='RUNNING'",
                    (key,digest),
                ).fetchone()
                if old is None:
                    raise CheckpointHold("M4_CHECKPOINT_TERMINAL_CAS_FAILED")
                recorded=json.loads(old[0])
                actual=json.loads(payload)
                if (not isinstance(recorded,list)
                    or recorded!=actual[:len(recorded)]
                    or len(recorded)!=sum(
                        p.status=="VERIFIED" for p in report.progress)):
                    raise CheckpointHold("M4_UID_PROGRESS_NOT_CONSISTENT")
                count=conn.execute(
                    "UPDATE k2_m4_wave_checkpoints "
                    "SET state=?,progress_json=?,reason=?,updated_at=? "
                    "WHERE approval_hash=? AND plan_digest=? "
                    "AND state='RUNNING' AND progress_json=?",
                    (terminal,payload,
                     ("P3_6G_TERMINAL_RECEIPTS" if report.all_verified
                      else "M4_WAVE_REQUIRES_OPERATOR_REVIEW"),
                     stamp,key,digest,old[0]),
                ).rowcount
                if count!=1:
                    raise CheckpointHold("M4_CHECKPOINT_TERMINAL_CAS_FAILED")
        except sqlite3.Error as exc:
            raise CheckpointHold("M4_CHECKPOINT_DB_UNAVAILABLE") from exc

    def hold(self,plan: MigrationWavePlan,approval: WaveApproval) -> None:
        """Called on a caught exception; if caller crashes, RUNNING remains."""
        stamp=self._gate()
        key,digest=_pin(plan,approval)
        try:
            with self.db_conn() as conn:
                conn.execute("BEGIN IMMEDIATE")
                row=conn.execute(
                    "SELECT state FROM k2_m4_wave_checkpoints "
                    "WHERE approval_hash=? AND plan_digest=?",
                    (key,digest),
                ).fetchone()
                if row!=("RUNNING",):
                    raise CheckpointHold("M4_HOLD_ONLY_INFLIGHT")
                conn.execute(
                    "UPDATE k2_m4_wave_checkpoints "
                    "SET state='HOLD',reason=?,updated_at=? "
                    "WHERE approval_hash=? AND state='RUNNING'",
                    ("M4_UNCERTAIN_OR_INTERRUPTED_EXECUTION",stamp,key),
                )
        except sqlite3.Error as exc:
            raise CheckpointHold("M4_CHECKPOINT_DB_UNAVAILABLE") from exc

    def inspect(self,plan: MigrationWavePlan,approval: WaveApproval
                ) -> CheckpointView:
        self._gate()
        key,digest=_pin(plan,approval)
        try:
            with self.db_conn() as conn:
                row=conn.execute(
                    "SELECT actor_id,chat_id,edge_id,usernames_json,"
                    "state,expires_at,progress_json,reason "
                    "FROM k2_m4_wave_checkpoints "
                    "WHERE approval_hash=? AND plan_digest=?",
                    (key,digest),
                ).fetchone()
            if row is None or row[2]!=plan.selection.target_edge_id or (
                tuple(json.loads(row[3]))!=plan.selection.usernames
            ) or row[4] not in _STATES:
                raise CheckpointHold("M4_CHECKPOINT_IDENTITY_CHANGED")
            progress=json.loads(row[6])
            if not isinstance(progress,list) or len(progress)>10:
                raise CheckpointHold("M4_CHECKPOINT_CORRUPT_PROGRESS")
            display=tuple(tuple(v) for v in progress)
            if any(len(v)!=3 or v[0] not in plan.selection.usernames
                   or v[1] not in ("VERIFIED","HOLD","DEFERRED")
                   or (v[1]=="VERIFIED" and
                       (type(v[2]) is not int or v[2]<=0))
                   for v in display):
                raise CheckpointHold("M4_CHECKPOINT_CORRUPT_PROGRESS")
            state=("UNKNOWN_INFLIGHT" if row[4]=="RUNNING" else
                   "EXPIRED" if row[4]=="PREPARED" and
                   row[5]<=self.clock() else row[4])
            return CheckpointView(digest,row[0],row[1],
                                  plan.selection.usernames,row[2],
                                  state,row[5],display,row[7])
        except (sqlite3.Error,TypeError,ValueError,KeyError) as exc:
            raise CheckpointHold("M4_CHECKPOINT_INSPECTION_FAILED") from exc
