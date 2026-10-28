"""Opt-in Phase-2 operation journal. Never executes legacy infrastructure effects.

Old CZ03/04A/04B/06/07/08 + original 6G remain their own authorities.
No bot startup hook or Telegram callback is installed by this module.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import secrets
import sqlite3
import time

KINDS = ("CLOUDZY_NEW", "MANUAL_ADOPT")
STEPS = ("PREFLIGHT", "PURCHASE", "PROVIDER_WAIT", "SSH_IDENTITY",
         "EDGE_INSTALL", "STANDBY", "CLIENT_E2E", "DNS_CUTOVER",
         "CUSTOMER_MIGRATION", "FINAL_VERIFY")
STATES = ("PLANNED", "RUNNING", "WAITING_EXTERNAL", "NEEDS_ATTESTATION",
          "RETRYABLE", "RECONCILE_REQUIRED", "CANCELLATION_REQUESTED",
          "PAUSED_SAFE", "COMPLETED", "CANCELLED_SAFE", "NEEDS_OPERATOR")
FINISHED = ("COMPLETED", "CANCELLED_SAFE")
WORKING = ("RUNNING", "WAITING_EXTERNAL", "CANCELLATION_REQUESTED")
CODE = re.compile(r"[A-Z][A-Z0-9_]{0,89}\Z")
REF = re.compile(r"[A-Za-z0-9_:.-]{1,96}\Z")
WORKER_ID = re.compile(r"[A-Za-z0-9_-]{8,80}\Z")

# Fixed table/field names; user data never interpolated as SQL identifiers.
HISTORICAL = (
    ("CZ03", "cloudzy_edge_operations", "id", "status", "hold_reason"),
    ("CZ06", "cloudzy_cz06_runs", "operation_id", "stage", "detail_code"),
    ("CZ04A", "cloudzy_cz04a_actions", "id", "status", "note"),
    ("CZ04B", "cloudzy_cz04b_operations", "id", "status", "note"),
    ("CZ07", "cloudzy_cz07_jobs", "id", "status", "code"),
    ("CZ08", "cloudzy_cz08_deletions", "id", "status", "detail_code"),
)
CLOSED = {
    "CZ03": ("EDGE_READY", "REJECTED", "CANCELLED"),
    "CZ06": ("READY", "CANCELLED"),
    "CZ04A": ("DONE", "REJECTED"),
    "CZ04B": ("READY", "DONE", "ABORTED"),
    "CZ07": ("DONE", "ABORTED"),
    "CZ08": ("DONE", "REJECTED"),
}


class OperationHold(RuntimeError):
    pass


@dataclass(frozen=True)
class LegacyReceipt:
    system: str
    operation_id: str
    state: str
    code: str
    next_action: str


@dataclass(frozen=True)
class RecoveryPreview:
    operation_id: str
    state: str
    step: str
    code: str
    next_action: str
    lease_stale: bool
    cancel_requested: bool
    external_intent: bool


def _safe_code(value):
    code = str(value or "").upper()
    return code if CODE.fullmatch(code) else "UNSPECIFIED"


def legacy_action(system, status):
    """Display advice only, not a license to call the original executors."""
    if system == "CZ03" and status in ("CREATING", "CREATE_UNCERTAIN"):
        return "RECONCILE_CLOUDZY_CREATE_NO_POST"
    if system == "CZ08" and status in ("DELETING", "HOLD"):
        return "RECONCILE_CLOUDZY_DELETE_NO_POST"
    if system in ("CZ04B", "CZ07") and status in (
            "ROUTING", "DNS_WRITE_INTENT", "DNS_TARGET_CONFIRMED", "HOLD"):
        return "RECONCILE_DNS_CORE_6G_NO_REPLAY"
    if system == "CZ07" and status == "QUEUED":
        return "INSPECT_WORKER_NO_AUTO_LAUNCH"
    if system == "CZ07" and status == "MIGRATING":
        return "VERIFY_ROUTE_AND_BATCHES_NO_AUTO_RESUME"
    if system == "CZ03" and status in ("PROVISIONING", "HOLD_PROVISION"):
        return "VERIFY_EXISTING_INSTALL_NO_RERUN"
    if status in CLOSED[system]:
        return "HISTORICAL_CLOSED"
    return "INSPECT_JOURNAL_NO_REPLAY"


def read_legacy_receipts(db: sqlite3.Connection, *, per_system=10):
    """SELECT-only existing journal projection, no CREATE or external reads.

    Do not return arbitrary exception notes, provider bodies, keys or tokens.
    """
    if type(per_system) is not int or not 1 <= per_system <= 50:
        raise ValueError("INVALID_LIMIT")
    present = {r[0] for r in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}
    result = []
    for system, table, id_col, state_col, reason_col in HISTORICAL:
        if table not in present:
            continue
        for key, state, reason in db.execute(
            f"SELECT {id_col},{state_col},{reason_col} FROM {table} "
            f"ORDER BY rowid DESC LIMIT ?", (per_system,)
        ).fetchall():
            state = str(state or "").upper()[:60]
            result.append(LegacyReceipt(system, str(key or "")[:64], state,
                                        _safe_code(reason),
                                        legacy_action(system, state)))
    return tuple(result)


def _identity(actor, chat):
    if type(actor) is not int or actor <= 0 or type(chat) is not int:
        raise OperationHold("INVALID_OWNER")


def _code(value):
    if not isinstance(value, str) or not CODE.fullmatch(value):
        raise OperationHold("INVALID_EVENT_CODE")


class DurableCoordinator:
    """New-workflow journal only. External effects are ALWAYS out of scope.

    db_factory yields sqlite3.Connection in a context manager.
    Trusted witness hooks default DENY and must be independent observers.
    """

    def __init__(self, db_factory, *, now=time.time,
                 worker_quiescent=None, external_verified=None):
        self.db = db_factory
        self.now = now
        self.worker_quiescent = worker_quiescent
        self.external_verified = external_verified

    @staticmethod
    def initialize(db):
        """Additive schema, called only on explicit registration."""
        db.execute("""CREATE TABLE IF NOT EXISTS cloudzy_uo_operations(
            id TEXT PRIMARY KEY, kind TEXT NOT NULL, source_ref TEXT NOT NULL,
            actor INTEGER NOT NULL, chat INTEGER NOT NULL,
            step TEXT NOT NULL, state TEXT NOT NULL,
            version INTEGER NOT NULL DEFAULT 0,
            fencing INTEGER NOT NULL DEFAULT 0,
            worker TEXT, deadline INTEGER, heartbeat INTEGER,
            external_intent INTEGER NOT NULL DEFAULT 0,
            cancel_requested INTEGER NOT NULL DEFAULT 0,
            code TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
            UNIQUE(kind,source_ref)
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS cloudzy_uo_events(
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            operation_id TEXT NOT NULL, version INTEGER NOT NULL,
            at INTEGER NOT NULL, event TEXT NOT NULL,
            state TEXT NOT NULL, step TEXT NOT NULL, code TEXT NOT NULL,
            UNIQUE(operation_id,version)
        )""")

    def _now(self):
        return int(self.now())

    @staticmethod
    def _row(db, op):
        db.row_factory = sqlite3.Row
        r = db.execute("SELECT * FROM cloudzy_uo_operations WHERE id=?",
                       (op,)).fetchone()
        if r is None:
            raise OperationHold("OPERATION_NOT_FOUND")
        return dict(r)

    @staticmethod
    def _actor(r, actor, chat):
        _identity(actor, chat)
        if r["actor"] != actor or r["chat"] != chat:
            raise OperationHold("OPERATOR_MISMATCH")

    @staticmethod
    def _version(r, expected):
        if type(expected) is not int or expected != r["version"]:
            raise OperationHold("STALE_OPERATION_VERSION")

    def _transition(self, db, r, *, state, code, event, step=None,
                    worker=None, deadline=None, fencing=None, heartbeat=None,
                    external_intent=None, cancel_requested=None):
        _code(code)
        if state not in STATES or (step is not None and step not in STEPS):
            raise OperationHold("INVALID_TRANSITION")
        fields = {
            "state": state, "step": step or r["step"],
            "version": r["version"] + 1, "updated_at": self._now(),
            "code": code, "worker": worker, "deadline": deadline,
            "fencing": r["fencing"] if fencing is None else fencing,
            "heartbeat": r["heartbeat"] if heartbeat is None else heartbeat,
            "external_intent": r["external_intent"] if external_intent is None else int(bool(external_intent)),
            "cancel_requested": r["cancel_requested"] if cancel_requested is None else int(bool(cancel_requested))
        }
        assignments = ",".join(f"{key}=?" for key in fields)
        if db.execute(
            f"UPDATE cloudzy_uo_operations SET {assignments} "
            "WHERE id=? AND version=?",
            (*fields.values(), r["id"], r["version"])
        ).rowcount != 1:
            raise OperationHold("TRANSITION_CAS_FAILED")
        db.execute(
            "INSERT INTO cloudzy_uo_events "
            "(operation_id,version,at,event,state,step,code) VALUES(?,?,?,?,?,?,?)",
            (r["id"], fields["version"], self._now(), event,
             state, fields["step"], code)
        )
        return fields["version"]

    def register(self, *, kind, source_ref, actor, chat):
        _identity(actor, chat)
        if kind not in KINDS or not isinstance(source_ref, str) or not REF.fullmatch(source_ref):
            raise OperationHold("INVALID_OPERATION_REFERENCE")
        op = secrets.token_hex(16)
        with self.db() as db:
            self.initialize(db)
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute(
                    "INSERT INTO cloudzy_uo_operations "
                    "(id,kind,source_ref,actor,chat,step,state,created_at,updated_at) "
                    "VALUES (?,?,?,?,?,'PREFLIGHT','PLANNED',?,?)",
                    (op, kind, source_ref, actor, chat, self._now(), self._now())
                )
            except sqlite3.IntegrityError as exc:
                raise OperationHold("OPERATION_ALREADY_REGISTERED") from exc
            db.execute(
                "INSERT INTO cloudzy_uo_events "
                "(operation_id,version,at,event,state,step,code) "
                "VALUES (?,0,?,'REGISTER','PLANNED','PREFLIGHT','REGISTERED')",
                (op, self._now())
            )
        return op

    def get(self, op):
        with self.db() as db:
            return self._row(db, op)

    def events(self, op):
        with self.db() as db:
            db.row_factory = sqlite3.Row
            return tuple(dict(x) for x in db.execute(
                "SELECT version,at,event,state,step,code FROM cloudzy_uo_events "
                "WHERE operation_id=? ORDER BY version", (op,)
            ).fetchall())

    @staticmethod
    def _worker(r, worker, fencing, ts):
        if (not isinstance(worker, str) or not WORKER_ID.fullmatch(worker)
                or type(fencing) is not int or fencing <= 0
                or r["worker"] != worker or r["fencing"] != fencing):
            raise OperationHold("WORKER_FENCED")
        if r["deadline"] is None or ts >= r["deadline"]:
            raise OperationHold("LEASE_EXPIRED")

    @staticmethod
    def _duration(seconds):
        if type(seconds) is not int or not 10 <= seconds <= 300:
            raise OperationHold("INVALID_LEASE_SECONDS")

    def claim(self, op, *, actor, chat, worker, expected_version, seconds=60):
        self._duration(seconds)
        if not isinstance(worker, str) or not WORKER_ID.fullmatch(worker):
            raise OperationHold("INVALID_WORKER")
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            r = self._row(db, op)
            self._actor(r, actor, chat)
            self._version(r, expected_version)
            if r["state"] not in ("PLANNED", "PAUSED_SAFE", "RETRYABLE"):
                raise OperationHold("STATE_NOT_CLAIMABLE")
            if r["external_intent"] or r["cancel_requested"] or r["worker"]:
                raise OperationHold("RECONCILIATION_REQUIRED")
            generation = r["fencing"] + 1
            self._transition(db, r, state="RUNNING", code="WORKER_CLAIM",
                             event="CLAIM", worker=worker,
                             deadline=self._now()+seconds, heartbeat=self._now(),
                             fencing=generation)
            return generation

    def heartbeat(self, op, *, worker, fencing, expected_version, seconds=60):
        self._duration(seconds)
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            r = self._row(db, op)
            self._version(r, expected_version)
            self._worker(r, worker, fencing, self._now())
            if r["state"] not in WORKING:
                raise OperationHold("INVALID_HEARTBEAT_STATE")
            return self._transition(db, r, state=r["state"], code="WORKER_ALIVE",
                                    event="HEARTBEAT", worker=worker,
                                    deadline=self._now()+seconds,
                                    heartbeat=self._now())

    def checkpoint(self, op, *, worker, fencing, expected_version,
                   step, state="RUNNING", code="STAGE_CHECKPOINT",
                   external_intent=False):
        """Must record external intent BEFORE any external write.

        External intent is sticky, cannot be cleared with a checkpoint.
        """
        if step not in STEPS or state not in ("RUNNING", "WAITING_EXTERNAL",
                                              "NEEDS_ATTESTATION"):
            raise OperationHold("INVALID_CHECKPOINT")
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            r = self._row(db, op)
            self._version(r, expected_version)
            self._worker(r, worker, fencing, self._now())
            if r["cancel_requested"] or r["state"] != "RUNNING":
                raise OperationHold("CANCEL_OR_STAGE_CHANGED")
            return self._transition(
                db, r, state=state, step=step, code=code,
                event="EXTERNAL_INTENT" if external_intent else "CHECKPOINT",
                worker=worker, deadline=r["deadline"],
                external_intent=bool(r["external_intent"] or external_intent)
            )

    def request_cancel(self, op, *, actor, chat, expected_version):
        """Idempotent request; active/uncertain effects never force-unlocked."""
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            r = self._row(db, op)
            self._actor(r, actor, chat)
            self._version(r, expected_version)
            if r["state"] in FINISHED or r["cancel_requested"]:
                return r["state"]
            if r["state"] == "PLANNED" and not r["external_intent"]:
                state, code = "CANCELLED_SAFE", "NO_EFFECT_CANCEL"
            elif r["state"] in WORKING:
                state, code = "CANCELLATION_REQUESTED", "STOP_AT_SAFE_CHECKPOINT"
            else:
                state, code = "RECONCILE_REQUIRED", "CANCEL_REQUIRES_RECONCILIATION"
            self._transition(db, r, state=state, code=code,
                             event="CANCEL_REQUESTED", worker=r["worker"],
                             deadline=r["deadline"], cancel_requested=True)
            return state

    def stop_at_checkpoint(self, op, *, worker, fencing, expected_version):
        """A live worker acknowledges cancel at a proven no-write boundary."""
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            r = self._row(db, op)
            self._version(r, expected_version)
            self._worker(r, worker, fencing, self._now())
            if r["state"] != "CANCELLATION_REQUESTED":
                raise OperationHold("CANCEL_NOT_REQUESTED")
            state = "RECONCILE_REQUIRED" if r["external_intent"] else "CANCELLED_SAFE"
            self._transition(db, r, state=state, code="CHECKPOINT_STOPPED",
                             event="WORKER_STOP", worker=None, deadline=None)
            return state

    def recovery_preview(self):
        """Read-only startup inspector; never re-launches worker or unlocks 6G."""
        with self.db() as db:
            if not db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='cloudzy_uo_operations'"
            ).fetchone():
                return ()
            db.row_factory = sqlite3.Row
            rows = db.execute(
                "SELECT * FROM cloudzy_uo_operations "
                "WHERE state NOT IN ('COMPLETED','CANCELLED_SAFE') "
                "ORDER BY updated_at,id"
            ).fetchall()
        result = []
        for rec in rows:
            r = dict(rec)
            stale = (r["state"] in WORKING and
                     (r["deadline"] is None or self._now() >= r["deadline"]))
            if stale and r["external_intent"]:
                action = "RECONCILE_EXTERNAL_NO_REPLAY"
            elif stale:
                action = "VERIFY_QUIESCENCE_BEFORE_RECLAIM"
            elif r["cancel_requested"]:
                action = "WAIT_SAFE_STOP_OR_RECONCILE"
            elif r["state"] == "PLANNED":
                action = "CLAIM_PREFLIGHT_ONLY"
            elif r["state"] in ("RECONCILE_REQUIRED", "NEEDS_OPERATOR"):
                action = "INSPECT_EXTERNAL_JOURNALS"
            else:
                action = "INSPECT_CURRENT_STAGE"
            result.append(RecoveryPreview(
                r["id"], r["state"], r["step"], r["code"], action,
                bool(stale), bool(r["cancel_requested"]), bool(r["external_intent"])
            ))
        return tuple(result)

    def reclaim_stale_no_effect(self, op, *, actor, chat, expected_version):
        """Never reclaim without independently proving the old worker stopped."""
        if self.worker_quiescent is None or self.worker_quiescent(op) is not True:
            raise OperationHold("TRUSTED_WORKER_QUIESCENCE_REQUIRED")
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            r = self._row(db, op)
            self._actor(r, actor, chat)
            self._version(r, expected_version)
            if (r["state"] not in WORKING or r["deadline"] is None
                    or self._now() < r["deadline"]):
                raise OperationHold("NOT_STALE")
            if r["external_intent"]:
                raise OperationHold("EXTERNAL_RECONCILIATION_REQUIRED")
            state = "CANCELLED_SAFE" if r["cancel_requested"] else "PAUSED_SAFE"
            self._transition(db, r, state=state, code="QUIESCENCE_VERIFIED",
                             event="RECLAIM_VERIFIED", worker=None, deadline=None)
            return state

    def reconcile_external(self, op, *, actor, chat, expected_version):
        """Default DENY; trusted external observer is mandatory.

        No evidence string from Telegram/operator grants a transition.
        """
        if self.external_verified is None or self.external_verified(op) is not True:
            raise OperationHold("TRUSTED_EXTERNAL_EVIDENCE_REQUIRED")
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            r = self._row(db, op)
            self._actor(r, actor, chat)
            self._version(r, expected_version)
            if r["state"] not in ("RECONCILE_REQUIRED", "NEEDS_OPERATOR",
                                  "CANCELLATION_REQUESTED", "WAITING_EXTERNAL"):
                raise OperationHold("STATE_NOT_RECONCILABLE")
            if r["worker"] and r["deadline"] and self._now() < r["deadline"]:
                raise OperationHold("LIVE_WORKER_NOT_FENCED")
            state = "CANCELLED_SAFE" if r["cancel_requested"] else "PAUSED_SAFE"
            self._transition(db, r, state=state, code="EXTERNAL_VERIFIED",
                             event="RECONCILED", worker=None, deadline=None,
                             external_intent=False)
            return state
