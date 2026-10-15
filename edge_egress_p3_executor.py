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
import ipaddress
import json
import re
import secrets
import sqlite3
import time
from typing import Callable, Protocol

# There is no implicit live port or Telegram authorisation.
EXECUTOR_ENABLED = False
# Never permit mode-0 UID_ATTACH with a generic fake host or 6G callback.
P3_CROSS_EDGE_LEGACY_UID_ATTACH_ENABLED = False
P3_UID_POST_COMMIT_PROBE_ENABLED = False
TICKET_TTL_SECONDS = 120
INTENT_PHASE = "EGRESS_P3_EXECUTE_INTENT"
RECOVERY_PHASE = "EGRESS_P3_RECOVERY_REQUIRED"
ALLOWED_ACTIONS = frozenset({"EDGE_PREPARE", "UID_ATTACH", "UID_FREEZE", "EDGE_RETIRE", "UID_ENROLL_SOURCE", "COHORT_PROMOTE"})
# Scope-specific source enrollment: no global mode toggle or DNS/host mutation.
SOURCE_ENROLL_GATES = frozenset({
    "SOURCE_EDGE_F4", "MIXED_PAM_COMPATIBILITY",
    "SOURCE_INGRESS_PIN", "BOOT_ROSTER_PREINSTALLED",
})
PROMOTION_GATES = frozenset({
    "SOURCE_AND_TARGET_F4", "ALL_ACTIVE_UIDS_PROTECTED",
    "ROOT_ROSTER_AND_GUARDS", "PAM_BOOT_ADMISSION",
    "EXTERNAL_IPV4_DNS_IPV6_NO_LEAK", "ALL_CUSTOMERS_IDLE",
    "RESCUE_AND_REBOOT_RECOVERY", "NO_LEGACY_FALLBACK",
})
BASE_GATES = frozenset({
    "OPERATOR_RESCUE", "STAGE_PIN", "SSH_HOST_PIN",
    "RESOURCE_OWNERSHIP", "NO_CORE_FALLBACK",
})
ATTACH_GATES = frozenset({
    "F4_ACCEPTED", "PAM_ADMISSION", "BOOT_DENY_BEFORE_SSH",
    "DNS_IPV6_NO_LEAK", "UID_IDLE_AND_FROZEN",
})
RETIRE_GATES = frozenset({
    "BACKUP_VERIFIED", "ORPHAN_OWNERSHIP", "NO_CUSTOMER_DEPENDENCIES",
    "UID_FENCES_PRESERVED", "PERSISTENCE_AUDITED", "WG0_UNTOUCHED",
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
        if not isinstance(self.edge_id, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{1,23}", self.edge_id):
            raise ExecutorHold("EDGE_ID_INVALID")
        for host in (self.source_host, self.target_host):
            try:
                canonical = str(ipaddress.IPv4Address(host))
            except (TypeError, ipaddress.AddressValueError) as exc:
                raise ExecutorHold("HOST_IDENTITY_REQUIRED") from exc
            if canonical != host or not ipaddress.IPv4Address(host).is_global:
                raise ExecutorHold("PUBLIC_IPV4_IDENTITY_REQUIRED")
        if self.source_host == self.target_host and self.action != "UID_ENROLL_SOURCE":
            raise ExecutorHold("SAME_EDGE_OPERATION_NOT_ALLOWED")
        if self.action == "UID_ENROLL_SOURCE" and self.source_host != self.target_host:
            raise ExecutorHold("SOURCE_ENROLLMENT_MUST_STAY_ON_CURRENT_EDGE")
        if self.action in ("UID_ATTACH", "UID_FREEZE", "UID_ENROLL_SOURCE"):
            if (not isinstance(self.username, str)
                    or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", self.username)
                    or type(self.uid) is not int or not 1000 <= self.uid < 60000):
                raise ExecutorHold("EXACT_UID_IDENTITY_REQUIRED")
        elif self.username or self.uid is not None:
            raise ExecutorHold("UNEXPECTED_UID_FOR_EDGE_ACTION")


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
        required = BASE_GATES | (ATTACH_GATES if scope.action in ("UID_ATTACH", "UID_ENROLL_SOURCE")
                                 else RETIRE_GATES if scope.action == "EDGE_RETIRE"
                                 else frozenset())
        if scope.action == "UID_ENROLL_SOURCE":
            required = required | SOURCE_ENROLL_GATES
        if scope.action == "COHORT_PROMOTE":
            required = required | PROMOTION_GATES
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


def assert_guarded_6g_intent(db_conn: Callable, scope: ExecutionScope,
                             ticket: ExecutionTicket) -> int:
    """Read the ONE existing durable P3-A 6G lease before an owned action.

    No alternative transaction/lease authority. Throws HOLD if a lease was
    replaced, the P3 intent changed, or the confirmation is for a different
    scope. Host ports must call again before each privileged step.
    """
    if (not isinstance(scope, ExecutionScope)
            or not isinstance(ticket, ExecutionTicket)
            or not isinstance(ticket.nonce, str)
            or not re.fullmatch(r"[a-f0-9]{32}", ticket.nonce)
            or not compare_digest(ticket.scope_digest, _scope_digest(scope))):
        raise ExecutorHold("P3_INTENT_TICKET_INVALID")
    nonce_hash = sha256(ticket.nonce.encode("ascii")).hexdigest()
    with db_conn() as conn:
        rows = conn.execute(
            "SELECT id FROM failover_operations WHERE status='RUNNING'"
        ).fetchall()
        if len(rows) != 1 or type(rows[0][0]) is not int:
            raise ExecutorHold("SHARED_6G_LEASE_AMBIGUOUS")
        op = rows[0][0]
        _locked(conn, op, scope, nonce_hash=nonce_hash)
    return op


@dataclass(frozen=True)
class RecoveryInspection:
    operation_id: int
    journal_status: str
    journal_phase: str
    requires_manual_recovery: bool


def inspect_execution_recovery(db_conn: Callable, operation_id: int) -> RecoveryInspection:
    """READ ONLY after process crash. This never retries or releases 6G."""
    if type(operation_id) is not int or operation_id <= 0:
        raise ExecutorHold("RECOVERY_OPERATION_ID_INVALID")
    with db_conn() as conn:
        row = conn.execute(
            "SELECT status, detail_json FROM failover_operations WHERE id=?",
            (operation_id,),
        ).fetchone()
    if row is None:
        raise ExecutorHold("RECOVERY_JOURNAL_NOT_FOUND")
    status, raw = row
    try:
        item = json.loads(raw)
    except (TypeError, ValueError):
        raise ExecutorHold("RECOVERY_JOURNAL_UNTRUSTED") from None
    if not isinstance(item, dict) or item.get("kind") != "K2_P3A":
        raise ExecutorHold("RECOVERY_OPERATION_IDENTITY_UNVERIFIED")
    phase = item.get("phase")
    if (not isinstance(phase, str)
            or phase not in (INTENT_PHASE, RECOVERY_PHASE, "EGRESS_P3_VERIFIED")):
        raise ExecutorHold("RECOVERY_PHASE_UNRECOGNIZED")
    if status == "RUNNING":
        if phase == "EGRESS_P3_VERIFIED":
            raise ExecutorHold("RECOVERY_TERMINAL_PHASE_NOT_COMMITTED")
        return RecoveryInspection(operation_id, status, phase, True)
    if status == "SUCCEEDED" and phase == "EGRESS_P3_VERIFIED":
        return RecoveryInspection(operation_id, status, phase, False)
    raise ExecutorHold("RECOVERY_STATUS_OR_PHASE_UNTRUSTED")


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
        self._execution_ticket = None

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
        if self._core_single_host_bound(scope):
            detail.update(single_uid=True, username=scope.username, uid=scope.uid)
        self.journal_fn(
            operation_id, status=status, detail=detail,
            finished=(status == "SUCCEEDED"), require_running=True,
        )

    def _core_single_host_bound(self, scope: ExecutionScope) -> bool:
        from edge_egress_k2_core_reassignment import CoreReassignmentPort,CORE_REASSIGNMENT_ENABLED
        from edge_egress_k2_core_prerequisites import CoreGuardBootstrap
        from edge_egress_k2_m4_bootstrap import (
            DeferredOriginal6GHostPort, DeferredCrossEdgeOriginal6GHostPort,
        )
        port = self.host_port
        if (P3_UID_POST_COMMIT_PROBE_ENABLED and CORE_REASSIGNMENT_ENABLED
            and type(port) is CoreReassignmentPort and port.scope==scope
            and port.db_conn is self.db_conn and port.ticket==self._execution_ticket
            and scope.action in ('UID_ATTACH','UID_ENROLL_SOURCE')):
            return True
        return (
            P3_UID_POST_COMMIT_PROBE_ENABLED
            and scope.action in ("UID_ATTACH", "UID_ENROLL_SOURCE")
            and type(port) in (DeferredOriginal6GHostPort, DeferredCrossEdgeOriginal6GHostPort)
            and port.scope == scope and port.db_conn is self.db_conn
            and port.ticket == self._execution_ticket
            and type(port.bootstrap) is CoreGuardBootstrap
        )

    def _legacy_cross_edge_host_bound(self, scope: ExecutionScope) -> bool:
        """Only the original M4 reviewed deferred port may bypass mode=1.

        The port still must install real root PAM/UID guards after original
        6G intent and use the typed cross-Edge F2 CAS store. No arbitrary
        host_port, preview bool, or Telegram-supplied marker is accepted.
        """
        from edge_egress_k2_m4_bootstrap import (
            DeferredCrossEdgeOriginal6GHostPort,
        )
        port = self.host_port
        from edge_egress_k2_core_reassignment import CoreReassignmentPort,CORE_REASSIGNMENT_ENABLED
        if (CORE_REASSIGNMENT_ENABLED and P3_CROSS_EDGE_LEGACY_UID_ATTACH_ENABLED
            and type(port) is CoreReassignmentPort and port.scope==scope
            and port.db_conn is self.db_conn and port.ticket==self._execution_ticket
            and scope.action=='UID_ATTACH' and port.release_enabled is True):
            return True
        return (
            P3_CROSS_EDGE_LEGACY_UID_ATTACH_ENABLED
            and scope.action == "UID_ATTACH"
            and scope.source_host != scope.target_host
            and type(port) is DeferredCrossEdgeOriginal6GHostPort
            and port.scope == scope
            and port.db_conn is self.db_conn
            and port.release_enabled is True
            and isinstance(port.ticket, ExecutionTicket)
            and port.ticket.scope_digest == _scope_digest(scope)
            and self._execution_ticket is not None
            and port.ticket == self._execution_ticket
        )

    def _lease(self, operation_id, scope, nonce_hash=None):
        with self.db_conn() as conn:
            _locked(conn, operation_id, scope, nonce_hash=nonce_hash)
            if scope.action in ("UID_ATTACH", "UID_ENROLL_SOURCE"):
                # The new *same-edge* source-enrollment path runs in unchanged
                # Legacy global mode, with per-UID F2 PAM/roster enforcement.
                # The existing cross-Edge UID_ATTACH still requires mode 1.
                mode = conn.execute(
                    "SELECT value FROM settings "
                    "WHERE key='edge_egress_protected_mode'"
                ).fetchone()
                expected = ("0",) if (
                    scope.action == "UID_ENROLL_SOURCE"
                    or self._legacy_cross_edge_host_bound(scope)
                ) else ("1",)
                if mode != expected:
                    raise ExecutorHold(
                        "SOURCE_ENROLL_REQUIRES_LEGACY_MODE"
                        if scope.action == "UID_ENROLL_SOURCE"
                        else "PROTECTED_MODE_REQUIRED_FOR_UID_ATTACH"
                    )

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
        self._execution_ticket = ticket
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
            if scope.action in ("UID_ATTACH", "UID_ENROLL_SOURCE"):
                mode = conn.execute(
                    "SELECT value FROM settings "
                    "WHERE key='edge_egress_protected_mode'"
                ).fetchone()
                expected = ("0",) if (
                    scope.action == "UID_ENROLL_SOURCE"
                    or self._legacy_cross_edge_host_bound(scope)
                ) else ("1",)
                if mode != expected:
                    raise ExecutorHold(
                        "SOURCE_ENROLL_REQUIRES_LEGACY_MODE"
                        if scope.action == "UID_ENROLL_SOURCE"
                        else "PROTECTED_MODE_REQUIRED_FOR_UID_ATTACH"
                    )

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
            if self._core_single_host_bound(scope):
                # The F2 UID is already PROTECTED and independently route-
                # checked. Permit its real SSH probe while retaining the
                # SAME original 6G lease; no next migration can start yet.
                self._journal(operation_id, "RUNNING", INTENT_PHASE, scope,
                              nonce_hash, probe_only=True)
            if await self.host_port.verify(scope) is not True:
                raise ExecutorHold("POST_ACTION_PROOF_MISSING")
            self._lease(operation_id, scope, nonce_hash)
            last = self.review_fn(scope)
            if not isinstance(last, FreshEvidence):
                raise ExecutorHold("FINAL_REVIEW_UNAVAILABLE")
            last.verify(scope, self.clock())
            if not compare_digest(ticket.evidence_digest, last.digest):
                raise ExecutorHold("FINAL_EVIDENCE_CHANGED")
            self._lease(operation_id, scope, nonce_hash)
            self._journal(operation_id, "SUCCEEDED", "EGRESS_P3_VERIFIED", scope, nonce_hash)
            return ExecutionReceipt(True, "SUCCEEDED", operation_id)
        except BaseException as exc:
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
            if isinstance(exc, (asyncio.CancelledError, KeyboardInterrupt, SystemExit)):
                raise  # preserve cancellation semantics; 6G remains protected
            return ExecutionReceipt(False, "HOLD_RECONCILIATION_REQUIRED",
                                    operation_id, manual_recovery=True)
