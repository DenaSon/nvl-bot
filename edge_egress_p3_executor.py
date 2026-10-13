"""K2 P3-A: opt-in, stage-only guarded executor on the EXISTING 6G journal.

This is NOT a bot callback or live installer. All host operations are injected.
The protected phase is persisted BEFORE any host mutation; on uncertainty the
6G RUNNING lease is deliberately retained for human reconciliation.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest
import json
import re
import secrets
import sqlite3
import time
from typing import Callable, Protocol

# There is no implicit live port or Telegram authorisation.
EXECUTOR_ENABLED = False
TICKET_TTL_SECONDS = 120
INTENT_PHASE = "EGRESS_P3_EXECUTE_INTENT"
RECOVERY_PHASE = "EGRESS_P3_RECOVERY_REQUIRED"
ALLOWED_ACTIONS = frozenset({"EDGE_PREPARE", "UID_ATTACH", "UID_FREEZE"})
BASE_GATES = frozenset({
    "OPERATOR_RESCUE", "STAGE_PIN", "SSH_HOST_PIN",
    "RESOURCE_OWNERSHIP", "NO_CORE_FALLBACK",
})
ATTACH_GATES = frozenset({
    "F4_ACCEPTED", "PAM_ADMISSION", "BOOT_DENY_BEFORE_SSH",
    "DNS_IPV6_NO_LEAK", "UID_IDLE_AND_FROZEN",
})


class ExecutorHold(ValueError):
    """Safe-deny. Never publish raw host/provider errors into a journal."""


@dataclass(frozen=True)
class ExecutionScope:
    action: str
    edge_id: str
    source_host: str
    target_host: str
    username: str = ""
    uid: int | None = None

    def __post_init__(self):
        if self.action not in ALLOWED_ACTIONS:
            raise ExecutorHold("ACTION_NOT_ALLOWLISTED")
        if not isinstance(self.edge_id, str) or not re.fullmatch(r"e[1-9][0-9]{0,4}", self.edge_id):
            raise ExecutorHold("EDGE_ID_INVALID")
        if any(not isinstance(v, str) or not v or len(v) > 255
               for v in (self.source_host, self.target_host)):
            raise ExecutorHold("HOST_IDENTITY_REQUIRED")
        if self.action in ("UID_ATTACH", "UID_FREEZE"):
            if (not isinstance(self.username, str)
                    or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", self.username)
                    or type(self.uid) is not int or not 1000 <= self.uid < 60000):
                raise ExecutorHold("EXACT_UID_IDENTITY_REQUIRED")
        elif self.username or self.uid is not None:
            raise ExecutorHold("UNEXPECTED_UID_FOR_EDGE_PREPARE")


@dataclass(frozen=True)
class FreshEvidence:
    digest: str
    checked_at: int
    gates: frozenset[str]
    blockers: tuple[str, ...] = ()

    def verify(self, scope: ExecutionScope, now: int):
        if (not isinstance(self.digest, str) or not re.fullmatch(r"[a-f0-9]{64}", self.digest)
                or type(self.checked_at) is not int
                or self.checked_at > now or now - self.checked_at > 30
                or not isinstance(self.gates, frozenset)
                or any(not isinstance(g, str) for g in self.gates)
                or self.blockers):
            raise ExecutorHold("FRESH_EVIDENCE_NOT_ACCEPTED")
        required = BASE_GATES | (ATTACH_GATES if scope.action == "UID_ATTACH" else frozenset())
        if not required <= self.gates:
            raise ExecutorHold("MISSING_ACCEPTANCE_GATES")


@dataclass(frozen=True)
class ExecutionTicket:
    actor_id: int
    chat_id: int
    nonce: str
    expires_at: int
    scope_digest: str
    evidence_digest: str


@dataclass(frozen=True)
class ExecutionReceipt:
    allowed: bool
    result: str
    operation_id: int | None
    manual_recovery: bool = False


class GuardedHostPort(Protocol):
    async def apply(self, scope: ExecutionScope) -> None: ...
    async def verify(self, scope: ExecutionScope) -> bool: ...
    async def freeze_or_hold(self, scope: ExecutionScope) -> None: ...


def _scope_digest(scope: ExecutionScope) -> str:
    return sha256(json.dumps(
        {"action": scope.action, "edge_id": scope.edge_id,
         "source_host": scope.source_host, "target_host": scope.target_host,
         "username": scope.username, "uid": scope.uid},
        separators=(",", ":"), sort_keys=True,
    ).encode()).hexdigest()


def issue_execution_ticket(scope: ExecutionScope, evidence: FreshEvidence, *,
                           actor_id: int, chat_id: int,
                           now: int | None = None) -> ExecutionTicket:
    """Issue a preview-bound ticket; still NOT a release to execute."""
    ts = int(time.time()) if now is None else now
    evidence.verify(scope, ts)
    if type(actor_id) is not int or actor_id <= 0 or type(chat_id) is not int or chat_id == 0:
        raise ExecutorHold("INVALID_OPERATOR_CONTEXT")
    return ExecutionTicket(
        actor_id, chat_id, secrets.token_hex(16), ts + TICKET_TTL_SECONDS,
        _scope_digest(scope), evidence.digest,
    )


def _locked(conn, operation_id: int, scope: ExecutionScope, *,
            nonce_hash: str | None = None):
    rows = conn.execute(
        "SELECT id,status,source_host,target_host,detail_json "
        "FROM failover_operations WHERE status='RUNNING'"
    ).fetchall()
    if len(rows) != 1 or rows[0][:4] != (
        operation_id, "RUNNING", scope.source_host, scope.target_host
    ):
        raise ExecutorHold("SHARED_6G_LEASE_LOST_OR_CONTENDED")
    if nonce_hash is not None:
        try:
            data = json.loads(rows[0][4])
        except (TypeError, ValueError):
            raise ExecutorHold("PROTECTED_INTENT_NOT_DURABLE") from None
        if (not isinstance(data, dict) or data.get("phase") != INTENT_PHASE
                or data.get("kind") != "K2_P3A"
                or data.get("nonce_hash") != nonce_hash
                or data.get("scope_digest") != _scope_digest(scope)):
            raise ExecutorHold("PROTECTED_INTENT_NOT_DURABLE")


def _nonce_seen(conn, nonce_hash: str) -> bool:
    # Scan existing 6G journal, not a second replay/transaction table.
    # A malformed row fails closed instead of hiding a possible replay.
    for (raw,) in conn.execute("SELECT detail_json FROM failover_operations "
                               "WHERE detail_json IS NOT NULL"):
        try:
            detail = json.loads(raw)
        except (TypeError, ValueError):
            raise ExecutorHold("6G_JOURNAL_AMBIGUOUS") from None
        if not isinstance(detail, dict):
            raise ExecutorHold("6G_JOURNAL_AMBIGUOUS")
        if detail.get("kind") == "K2_P3A" and detail.get("nonce_hash") == nonce_hash:
            return True
    return False


class Existing6GGuardedExecutor:
    """Inject EXACT existing 6G acquire/update callbacks and guarded host port.

    A fresh instance handles one attempt only. This class is not reachable from
    the bot and defaults to disabled. No subprocess, SQL schema or network code.
    """

    def __init__(self, *, db_conn: Callable, acquire_fn: Callable,
                 journal_fn: Callable, review_fn: Callable,
                 host_port: GuardedHostPort | None = None,
                 release_enabled: bool = False, geteuid: Callable | None = None,
                 clock: Callable | None = None):
        self.db_conn = db_conn
        self.acquire_fn = acquire_fn
        self.journal_fn = journal_fn
        self.review_fn = review_fn
        self.host_port = host_port
        self.release_enabled = release_enabled
        self.geteuid = geteuid or __import__("os").geteuid
        self.clock = clock or (lambda: int(time.time()))
        self._used = False

    def _journal(self, operation_id, status, phase, scope, nonce_hash, **details):
        allowed = {"RUNNING", "SUCCEEDED"}
        if status not in allowed or any(
            type(v) not in (str, int, bool, type(None)) for v in details.values()
        ):
            raise ExecutorHold("UNSAFE_JOURNAL_UPDATE")
        detail = {
            "kind": "K2_P3A", "phase": phase, "action": scope.action,
            "edge_id": scope.edge_id, "scope_digest": _scope_digest(scope),
            "nonce_hash": nonce_hash, **details,
        }
        self.journal_fn(
            operation_id, status=status, detail=detail,
            finished=(status == "SUCCEEDED"), require_running=True,
        )

    def _lease(self, operation_id, scope, nonce_hash=None):
        with self.db_conn() as conn:
            _locked(conn, operation_id, scope, nonce_hash=nonce_hash)

    async def execute(self, scope: ExecutionScope, ticket: ExecutionTicket, *,
                      actor_id: int, chat_id: int) -> ExecutionReceipt:
        if self._used:
            raise ExecutorHold("EXECUTOR_ONE_SHOT")
        self._used = True  # consume locally before any awaits
        if (self.release_enabled is not True or self.host_port is None
                or self.geteuid() != 0):
            raise ExecutorHold("K_RELEASE_AND_PRIVILEGED_PORT_REQUIRED")
        ts = self.clock()
        if (not isinstance(ticket, ExecutionTicket)
                or type(actor_id) is not int or type(chat_id) is not int
                or ticket.actor_id != actor_id or ticket.chat_id != chat_id
                or ts >= ticket.expires_at
                or not isinstance(ticket.nonce, str)
                or not re.fullmatch(r"[0-9a-f]{32}", ticket.nonce)
                or not compare_digest(ticket.scope_digest, _scope_digest(scope))):
            raise ExecutorHold("EXPIRED_OR_UNAUTHORIZED_TICKET")
        # Readiness MUST be re-evaluated inside the acquired lease too.
        fresh = self.review_fn(scope)
        if not isinstance(fresh, FreshEvidence):
            raise ExecutorHold("FRESH_REVIEW_UNAVAILABLE")
        fresh.verify(scope, ts)
        if not compare_digest(fresh.digest, ticket.evidence_digest):
            raise ExecutorHold("PREVIEW_STALE")
        nonce_hash = sha256(ticket.nonce.encode("ascii")).hexdigest()
        with self.db_conn() as conn:
            if _nonce_seen(conn, nonce_hash):
                raise ExecutorHold("TICKET_REPLAY")

        operation_id, busy = self.acquire_fn(scope.source_host, scope.target_host)
        if operation_id is None:
            return ExecutionReceipt(False, "SHARED_6G_BUSY", busy)
        if type(operation_id) is not int or operation_id <= 0:
            raise ExecutorHold("INVALID_6G_OPERATION_ID")
        touched = False
        intent_written = False
        try:
            self._lease(operation_id, scope)
            # A second replay-check AFTER acquiring the only shared 6G lease.
            with self.db_conn() as conn:
                if _nonce_seen(conn, nonce_hash):
                    raise ExecutorHold("TICKET_REPLAY_AFTER_ACQUIRE")

            # Before ANY external mutation, persist a 6G phase protected
            # against legacy 6G stale-lease recovery.
            self._journal(operation_id, "RUNNING", INTENT_PHASE, scope, nonce_hash)
            intent_written = True
            self._lease(operation_id, scope, nonce_hash)
            current = self.review_fn(scope)
            if not isinstance(current, FreshEvidence):
                raise ExecutorHold("LOCKED_REVIEW_UNAVAILABLE")
            current.verify(scope, self.clock())
            if not compare_digest(ticket.evidence_digest, current.digest):
                raise ExecutorHold("LOCKED_ACCEPTANCE_CHANGED")
            self._lease(operation_id, scope, nonce_hash)
            touched = True  # must assume partial mutation on an exception
            await self.host_port.apply(scope)
            self._lease(operation_id, scope, nonce_hash)
            if await self.host_port.verify(scope) is not True:
                raise ExecutorHold("POST_ACTION_PROOF_MISSING")
            self._lease(operation_id, scope, nonce_hash)
            self._journal(operation_id, "SUCCEEDED", "EGRESS_P3_VERIFIED", scope, nonce_hash)
            return ExecutionReceipt(True, "SUCCEEDED", operation_id)
        except BaseException:
            # Never write FAILED for an ambiguous host action, because 6G
            # interprets it as unlock. Keep RUNNING + recognized HOLD marker.
            frozen = False
            if touched:
                try:
                    await self.host_port.freeze_or_hold(scope)
                    frozen = True
                except BaseException:
                    pass
            if intent_written:
                try:
                    self._journal(operation_id, "RUNNING", RECOVERY_PHASE,
                                  scope, nonce_hash, frozen=frozen)
                except BaseException:
                    pass
            return ExecutionReceipt(False, "HOLD_RECONCILIATION_REQUIRED",
                                    operation_id, manual_recovery=True)
