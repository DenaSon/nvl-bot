"""K2 final guarded per-account ingress host commit.

Composite P3-A HostPort around the EXISTING P3-C UID_ATTACH port. The
protected UID route must be verified FIRST; only then may the old account
host metadata be moved in the SAME existing 6G RUNNING/nonce transaction.

This module is NOT registered in the live bot and has no default worker.
A root-only factory must prove real ingress, admission, F4, DNS/IPv6 and
boot safety independently before enabling it on a disposable VPS.
"""
from __future__ import annotations

from hashlib import sha256
from hmac import compare_digest
import sqlite3
from typing import Callable, Protocol

from edge_egress_p3_executor import (
    ExecutionScope, ExecutionTicket, ExecutorHold,
    _locked, assert_guarded_6g_intent,
)
from edge_egress_f3_readiness import admission_eligible, read_readiness

K2_LIVE_HOST_BINDING_ENABLED = False


class CustomerBindingHold(ValueError):
    pass


class VerifiedUIDPort(Protocol):
    async def apply(self, scope: ExecutionScope) -> None: ...
    async def verify(self, scope: ExecutionScope) -> bool: ...
    async def freeze_or_hold(self, scope: ExecutionScope) -> None: ...


class GuardedCustomerIngressBindingPort:
    """One user / one proven Edge, never the Legacy bulk migration writer."""

    def __init__(self, *, db_conn: Callable, scope: ExecutionScope,
                 ticket: ExecutionTicket, uid_port: VerifiedUIDPort | None,
                 independent_ingress_proof: Callable | None,
                 release_enabled: bool = False):
        if (not isinstance(scope, ExecutionScope) or scope.action != "UID_ATTACH"
                or not isinstance(ticket, ExecutionTicket)
                or not compare_digest(ticket.scope_digest, _scope_digest_checked(scope))):
            raise CustomerBindingHold("EXACT_ATTACH_TICKET_REQUIRED")
        self.db_conn, self.scope, self.ticket = db_conn, scope, ticket
        self.uid_port, self.ingress_proof = uid_port, independent_ingress_proof
        self.release_enabled = release_enabled
        self._started = False

    def _gate(self, scope: ExecutionScope):
        if (scope != self.scope or self.release_enabled is not True
                or self.uid_port is None or self.ingress_proof is None):
            raise CustomerBindingHold("REVIEWED_ROOT_WORKER_NOT_RELEASED")
        # A validated RUNNING P3-A intent is required before each side effect.
        return assert_guarded_6g_intent(self.db_conn, scope, self.ticket)

    def _db_checks(self, conn, scope, operation_id: int, *, require_target: bool):
        nonce_hash = sha256(self.ticket.nonce.encode("ascii")).hexdigest()
        _locked(conn, operation_id, scope, nonce_hash=nonce_hash)
        if conn.execute(
            "SELECT value FROM settings WHERE key='edge_egress_protected_mode'"
        ).fetchone() != ("1",):
            raise CustomerBindingHold("PROTECTED_MODE_NOT_CURRENT")
        host = conn.execute(
            "SELECT host,service_type,status FROM ssh_accounts WHERE username=?",
            (scope.username,),
        ).fetchone()
        expected_host = scope.target_host if require_target else scope.source_host
        if (host is None or host[0] != expected_host or host[1] != "ssh"
                or "فعال" not in str(host[2]) or "غیر" in str(host[2])):
            raise CustomerBindingHold("SSH_OWNERSHIP_OR_SOURCE_CHANGED")
        target = conn.execute(
            "SELECT active FROM host_pool WHERE host=?", (scope.target_host,)
        ).fetchone()
        if target != (1,):
            raise CustomerBindingHold("TARGET_INGRESS_NOT_ACTIVE")
        allocation = conn.execute(
            "SELECT edge_id,status FROM edge_egress_allocations "
            "WHERE edge_public_ipv4=?", (scope.target_host,),
        ).fetchall()
        if len(allocation) != 1 or allocation[0] != (scope.edge_id, "STAGED"):
            raise CustomerBindingHold("TARGET_ALLOCATION_NOT_PINNED")
        ready = read_readiness(conn, scope.edge_id)
        if not admission_eligible(ready) or ready.edge_ipv4 != scope.target_host:
            raise CustomerBindingHold("F4_ACCEPTANCE_NOT_CURRENT")
        runtime = conn.execute(
            "SELECT uid,edge_id,edge_ipv4,state FROM edge_egress_uid_runtime "
            "WHERE username=?", (scope.username,),
        ).fetchone()
        binding = conn.execute(
            "SELECT uid,edge_id,edge_ipv4,status FROM edge_egress_uid_bindings "
            "WHERE username=?", (scope.username,),
        ).fetchone()
        expected = (scope.uid, scope.edge_id, scope.target_host, "PROTECTED")
        if runtime != expected or binding != expected:
            raise CustomerBindingHold("EXACT_PROTECTED_UID_ROUTE_NOT_COMMITTED")

    async def apply(self, scope: ExecutionScope) -> None:
        if self._started:
            raise CustomerBindingHold("HOST_BINDING_PORT_ONE_SHOT")
        self._started = True
        op = self._gate(scope)
        # Guard the old host BEFORE the UID port starts any privileged effect.
        with self.db_conn() as conn:
            row = conn.execute(
                "SELECT host,service_type,status FROM ssh_accounts WHERE username=?",
                (scope.username,),
            ).fetchone()
            if (row is None or row[0] != scope.source_host
                    or row[1] != "ssh" or "فعال" not in str(row[2])
                    or "غیر" in str(row[2])):
                raise CustomerBindingHold("OLD_ACCOUNT_HOST_CHANGED")
        await self.uid_port.apply(scope)
        self._gate(scope)
        if await self.uid_port.verify(scope) is not True:
            raise CustomerBindingHold("UID_EGRESS_NOT_VERIFIED")
        self._gate(scope)
        # Source-provided independent proof MUST include real customer ingress
        # identity; a changed DB host or hostname lookup is not that proof.
        if self.ingress_proof(scope) is not True:
            raise CustomerBindingHold("ACTUAL_INGRESS_NOT_ATTESTED")
        self._gate(scope)
        with self.db_conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._db_checks(conn, scope, op, require_target=False)
            written = conn.execute(
                "UPDATE ssh_accounts SET host=? "
                "WHERE username=? AND host=? AND service_type='ssh' "
                "AND status LIKE '%فعال%' AND status NOT LIKE '%غیر%'",
                (scope.target_host, scope.username, scope.source_host),
            ).rowcount
            if written != 1:
                raise CustomerBindingHold("EXACT_ACCOUNT_HOST_CAS_FAILED")

    async def verify(self, scope: ExecutionScope) -> bool:
        if not self._started:
            raise CustomerBindingHold("PORT_NOT_APPLIED")
        op = self._gate(scope)
        if await self.uid_port.verify(scope) is not True:
            raise CustomerBindingHold("POST_MOVE_EGRESS_NOT_VERIFIED")
        self._gate(scope)
        if self.ingress_proof(scope) is not True:
            raise CustomerBindingHold("POST_MOVE_INGRESS_NOT_ATTESTED")
        with self.db_conn() as conn:
            self._db_checks(conn, scope, op, require_target=True)
        return True

    async def freeze_or_hold(self, scope: ExecutionScope) -> None:
        # Called by P3-A on any ambiguity. Never rewrite the account to Core.
        if self._started and self.uid_port is not None and scope == self.scope:
            await self.uid_port.freeze_or_hold(scope)


def _scope_digest_checked(scope: ExecutionScope) -> str:
    # Reuse P3-A canonical digest; don't invent a parallel ticket identity.
    from edge_egress_p3_executor import _scope_digest
    return _scope_digest(scope)
