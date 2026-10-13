"""K2 P3-C: guarded per-UID attach, freeze and protected re-admission.

Source-only. Reuses the EXISTING F2 runtime store/kernel and P3-A/6G intent.
No Telegram action, production worker, roster installer, sshd modification or
unprotected UID release is registered. Unknown kernel state => fenced HOLD.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Callable, Protocol

from edge_egress_p3_executor import (
    ExecutionScope, ExecutionTicket, ExecutorHold, assert_guarded_6g_intent,
)
from edge_egress_uid_policy import UIDPolicyRequest
from edge_egress_uid_runtime_store import (
    Existing6GUIDRuntimeStore, RuntimeBinding, read_binding,
)
from edge_egress_v1_admission import load_roster, checked_guard, Member

UID_LIFECYCLE_ENABLED = False
NEW = "NEW"
RESUME = "RESUME_FROZEN"
FREEZE = "FREEZE_PROTECTED"


class ProtectedUIDHold(ValueError):
    pass


class PerUIDKernelPort(Protocol):
    def arm(self, req: UIDPolicyRequest, dns_port: int) -> None: ...
    def attach(self, req: UIDPolicyRequest) -> None: ...
    def freeze(self, req: UIDPolicyRequest) -> None: ...
    def assert_frozen(self, req: UIDPolicyRequest) -> None: ...
    def public_ipv4(self, req: UIDPolicyRequest) -> str: ...
    def assert_dns_ipv6(self, req: UIDPolicyRequest) -> None: ...


class UIDIndependentSafety(Protocol):
    """Must reflect live F4/PAM/ingress/boot and independent packet tests."""
    def assert_account_idle(self, req: UIDPolicyRequest) -> None: ...
    def assert_pam_ingress_boot(self, req: UIDPolicyRequest) -> None: ...
    def assert_multi_uid_isolation(self, req: UIDPolicyRequest) -> None: ...
    def assert_packet_dns_ipv6_no_core_leak(self, req: UIDPolicyRequest) -> None: ...


@dataclass(frozen=True)
class ProtectedUIDPlan:
    scope: ExecutionScope
    request: UIDPolicyRequest
    dns_port: int
    purpose: str
    roster_digest: str
    guard_sha256: str
    initial_generation: int | None

    def __post_init__(self):
        if (self.purpose not in (NEW, RESUME, FREEZE)
                or self.request.username != self.scope.username
                or self.request.uid != self.scope.uid
                or self.request.spec.edge_id != self.scope.edge_id
                or self.request.spec.edge_public_ipv4 != self.scope.target_host
                or self.scope.action != ("UID_FREEZE" if self.purpose == FREEZE
                                          else "UID_ATTACH")):
            raise ProtectedUIDHold("UID_PLAN_SCOPE_MISMATCH")


def _roster_digest(members: dict[str, Member]) -> str:
    return sha256(json.dumps(
        sorted((name, value.uid, value.guard_sha256)
               for name, value in members.items()),
        separators=(",", ":"),
    ).encode()).hexdigest()


def _binding_matches(row: RuntimeBinding, req: UIDPolicyRequest,
                     dns_port: int) -> bool:
    return (
        (row.username, row.uid, row.edge_id, row.edge_ipv4,
         row.route_table, row.priority, row.dns_port) ==
        (req.username, req.uid, req.spec.edge_id,
         req.spec.edge_public_ipv4, req.spec.route_table,
         req.priority, dns_port)
    )


def _mapping(conn, username: str):
    return conn.execute(
        "SELECT uid,edge_id,edge_ipv4,status "
        "FROM edge_egress_uid_bindings WHERE username=?", (username,),
    ).fetchone()


def _assert_roster_complete(conn, roster: dict[str, Member]) -> None:
    """Do not silently turn any previously protected UID into a legacy user."""
    # Both tables MUST already exist, never implicit schema installation.
    for table in ("edge_egress_uid_runtime", "edge_egress_uid_bindings"):
        if not conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (table,),
        ).fetchone():
            raise ProtectedUIDHold("PROTECTED_SCHEMA_MISSING")
    for name, uid in conn.execute(
        "SELECT username,uid FROM edge_egress_uid_runtime"
    ):
        member = roster.get(name)
        if member is None or member.uid != uid:
            raise ProtectedUIDHold("INCOMPLETE_PROTECTED_ROSTER")
    for name, uid in conn.execute(
        "SELECT username,uid FROM edge_egress_uid_bindings"
    ):
        member = roster.get(name)
        if member is None or member.uid != uid:
            raise ProtectedUIDHold("INCOMPLETE_PROTECTED_MAPPING_ROSTER")


def review_protected_uid(db_conn: Callable, scope: ExecutionScope,
                         req: UIDPolicyRequest, *, dns_port: int, purpose: str,
                         roster_loader: Callable = load_roster,
                         guard_loader: Callable = checked_guard,
                         os_uid_for_username: Callable) -> ProtectedUIDPlan:
    """Read-only pinned preview. Never mint F4 acceptance or modify the roster."""
    req.validate()
    if (type(dns_port) is not int or not 1024 <= dns_port <= 65535
            or not isinstance(scope, ExecutionScope)
            or scope.username != req.username or scope.uid != req.uid
            or scope.edge_id != req.spec.edge_id
            or scope.target_host != req.spec.edge_public_ipv4):
        raise ProtectedUIDHold("UID_IDENTITY_OR_DNS_INVALID")
    if purpose not in (NEW, RESUME, FREEZE):
        raise ProtectedUIDHold("UID_PURPOSE_INVALID")
    members = roster_loader()
    if not isinstance(members, dict) or req.username not in members:
        raise ProtectedUIDHold("PREINSTALLED_PROTECTED_ROSTER_REQUIRED")
    member = members[req.username]
    if member.uid != req.uid or os_uid_for_username(req.username) != req.uid:
        raise ProtectedUIDHold("UNIX_UID_IDENTITY_CHANGED")
    manifest = guard_loader(member)
    if (manifest.request != req or manifest.dns_port != dns_port
            or not manifest.shared_edge or not manifest.ingress_return
            or manifest.mode != "PROTECTED_BOOT_GUARD"):
        raise ProtectedUIDHold("ROOT_GUARD_MANIFEST_NOT_PINNED")
    with db_conn() as conn:
        _assert_roster_complete(conn, members)
        row = read_binding(conn, req.username)
        mapping = _mapping(conn, req.username)
        # A numeric UID or a username may NEVER have an owner in a second
        # protected row, regardless of whether this target has a binding.
        if conn.execute(
            "SELECT 1 FROM edge_egress_uid_runtime WHERE uid=? "
            "AND username<>? LIMIT 1", (req.uid, req.username)
        ).fetchone() or conn.execute(
            "SELECT 1 FROM edge_egress_uid_bindings WHERE uid=? "
            "AND username<>? LIMIT 1", (req.uid, req.username)
        ).fetchone():
            raise ProtectedUIDHold("UID_ALREADY_OWNED_BY_OTHER_ACCOUNT")
        if purpose == NEW:
            if row is not None or mapping is not None:
                raise ProtectedUIDHold("EXISTING_UID_CANNOT_BE_REENROLLED")
            generation = None
        else:
            state = "FROZEN" if purpose == RESUME else "PROTECTED"
            if (row is None or row.state != state
                    or not _binding_matches(row, req, dns_port)
                    or mapping != (
                        req.uid, req.spec.edge_id,
                        req.spec.edge_public_ipv4, "PROTECTED",
                    )):
                raise ProtectedUIDHold("UID_RUNTIME_OR_MAPPING_STATE_CHANGED")
            generation = row.generation
    return ProtectedUIDPlan(
        scope, req, dns_port, purpose, _roster_digest(members),
        member.guard_sha256, generation,
    )


class GuardedProtectedUIDPort:
    """Injected P3-A UID_ATTACH / UID_FREEZE port, release disabled by default.

    The only allowed 'Release' here is RESUME_FROZEN -> PROTECTED after fresh
    proofs. Unprotected legacy release/unregistration is reserved for P3-E.
    """
    def __init__(self, *, db_conn: Callable, plan: ProtectedUIDPlan,
                 ticket: ExecutionTicket, store: Existing6GUIDRuntimeStore,
                 os_uid_for_username: Callable,
                 kernel: PerUIDKernelPort | None = None,
                 safety: UIDIndependentSafety | None = None,
                 roster_loader: Callable = load_roster,
                 guard_loader: Callable = checked_guard,
                 release_enabled: bool = False):
        self.db_conn, self.plan, self.ticket = db_conn, plan, ticket
        self.store, self.os_uid_for_username = store, os_uid_for_username
        self.kernel, self.safety = kernel, safety
        self.roster_loader, self.guard_loader = roster_loader, guard_loader
        self.release_enabled = release_enabled
        self._applied = False
        self._touched = False
        self._operation_id = None
        if (not isinstance(plan, ProtectedUIDPlan)
                or plan.scope.action not in ("UID_ATTACH", "UID_FREEZE")
                or store.db_conn is not db_conn):
            raise ProtectedUIDHold("UNTRUSTED_UID_PORT_CONSTRUCTION")

    def _check(self, scope: ExecutionScope, allowed_states: tuple[str | None, ...]):
        if (scope != self.plan.scope or not self.release_enabled
                or self.kernel is None or self.safety is None):
            raise ProtectedUIDHold("UID_OPERATION_NOT_RELEASED")
        # Recheck exact P3-A nonce-bearing RUNNING intent BEFORE every
        # kernel/DB operation; no second transaction system is created.
        op = assert_guarded_6g_intent(self.db_conn, scope, self.ticket)
        members = self.roster_loader()
        if (_roster_digest(members) != self.plan.roster_digest or
                members[scope.username].guard_sha256 != self.plan.guard_sha256
                or self.guard_loader(members[scope.username]).request
                   != self.plan.request or
                self.os_uid_for_username(scope.username) != scope.uid):
            raise ProtectedUIDHold("ROSTER_GUARD_OR_UID_CHANGED")
        with self.db_conn() as conn:
            _assert_roster_complete(conn, members)
            row = read_binding(conn, scope.username)
            if row is None:
                if None not in allowed_states or self.plan.initial_generation is not None:
                    raise ProtectedUIDHold("UID_RUNTIME_NOT_RESERVED")
                if _mapping(conn, scope.username) is not None:
                    raise ProtectedUIDHold("FOREIGN_UID_MAPPING")
            else:
                if (not _binding_matches(row, self.plan.request, self.plan.dns_port)
                        or row.state not in allowed_states
                        or (self.plan.initial_generation is not None and
                            row.generation < self.plan.initial_generation)):
                    raise ProtectedUIDHold("UID_RUNTIME_STATE_DRIFT")
                mapping = _mapping(conn, scope.username)
                if self.plan.purpose != NEW and mapping != (
                        scope.uid, scope.edge_id, scope.target_host, "PROTECTED"):
                    raise ProtectedUIDHold("PROTECTED_MAPPING_CHANGED")
        return op

    def _step(self, scope: ExecutionScope, allowed: tuple[str | None, ...],
              callback: Callable):
        op = self._check(scope, allowed)
        callback()
        return op

    async def apply(self, scope: ExecutionScope) -> None:
        if self._applied:
            raise ProtectedUIDHold("ONE_SHOT_UID_OPERATION")
        self._applied = True
        p, req = self.plan, self.plan.request
        first = (None,) if p.purpose == NEW else (
            ("FROZEN",) if p.purpose == RESUME else ("PROTECTED",)
        )
        op = self._check(scope, first)
        self._operation_id = op
        if p.purpose != FREEZE:
            # Frozen a troubled UID is an emergency containment action.
            # Do not require healthy PAM/DNS/Edge or idle sessions to deny.
            self.safety.assert_pam_ingress_boot(req)
            self._check(scope, first)
            self.safety.assert_multi_uid_isolation(req)
            self._check(scope, first)
            self.safety.assert_account_idle(req)
            self._check(scope, first)

        if p.purpose == FREEZE:
            self._touched = True
            self._step(scope, first, lambda: self.kernel.freeze(req))
            self._step(scope, first, lambda: self.kernel.assert_frozen(req))
            self._step(scope, first, lambda: self.store.transition(
                op, req, source=scope.source_host,
                expected="PROTECTED", target="FROZEN",
            ))
            return

        if p.purpose == NEW:
            # Persist BLOCKED BEFORE any privileged host command. PAM
            # admission must deny BLOCKED even when global mode is legacy.
            self._touched = True
            self._step(scope, first, lambda: self.store.reserve_blocked(
                op, req, source=scope.source_host, dns_port=p.dns_port,
            ))
            previous = "BLOCKED"
        else:
            self._step(scope, first, lambda: self.store.assert_frozen_binding(
                op, req, source=scope.source_host, dns_port=p.dns_port,
            ))
            previous = "FROZEN"
            self._touched = True

        self._step(scope, (previous,), lambda: self.kernel.arm(req,p.dns_port))
        self._step(scope, (previous,), lambda: self.kernel.assert_frozen(req))
        self._step(scope, (previous,), lambda: self.kernel.attach(req))
        self._step(scope, (previous,), lambda: self.store.transition(
            op, req, source=scope.source_host,
            expected=previous, target="ROUTED_UNVERIFIED",
        ))
        self._check(scope, ("ROUTED_UNVERIFIED",))
        if self.kernel.public_ipv4(req) != scope.target_host:
            raise ProtectedUIDHold("WRONG_PUBLIC_EGRESS_IPV4")
        self._step(scope, ("ROUTED_UNVERIFIED",),
                   lambda: self.kernel.assert_dns_ipv6(req))
        self._step(scope, ("ROUTED_UNVERIFIED",),
                   lambda: self.safety.assert_packet_dns_ipv6_no_core_leak(req))
        self._step(scope, ("ROUTED_UNVERIFIED",),
                   lambda: self.store.commit_protected(
                       op, req, source=scope.source_host,
                   ))

    async def verify(self, scope: ExecutionScope) -> bool:
        if not self._applied:
            raise ProtectedUIDHold("UID_OPERATION_NOT_APPLIED")
        p, req = self.plan, self.plan.request
        if p.purpose == FREEZE:
            self._step(scope, ("FROZEN",), lambda: self.kernel.assert_frozen(req))
            return True
        self._check(scope, ("PROTECTED",))
        if self.kernel.public_ipv4(req) != scope.target_host:
            raise ProtectedUIDHold("POST_COMMIT_PUBLIC_IP_DRIFT")
        self._step(scope, ("PROTECTED",), lambda: self.kernel.assert_dns_ipv6(req))
        self._step(scope, ("PROTECTED",),
                   lambda: self.safety.assert_packet_dns_ipv6_no_core_leak(req))
        return True

    async def freeze_or_hold(self, scope: ExecutionScope) -> None:
        # A preflight rejection cannot freeze an unrelated account. Once
        # reserved/started, do not undo the UID guard or protected mapping.
        if (scope != self.plan.scope or not self._touched
                or self.kernel is None):
            return
        req = self.plan.request
        # Fencing is the first and most important recovery action. The
        # kernel independently validates exact OS UID ownership.
        self.kernel.freeze(req)
        self.kernel.assert_frozen(req)
        # Metadata downgrade must be scoped to same original 6G owner;
        # a changed lease must NOT be used to clobber a different owner.
        try:
            op = assert_guarded_6g_intent(self.db_conn, scope, self.ticket)
            with self.db_conn() as conn:
                row = read_binding(conn, req.username)
            if row is not None and _binding_matches(row, req, self.plan.dns_port):
                if row.state in ("BLOCKED","ROUTED_UNVERIFIED","FROZEN","PROTECTED"):
                    self.store.transition(op,req,source=scope.source_host,
                                          expected=row.state,target="HOLD")
        except Exception:
            # P3-A journal persists RECOVERY_REQUIRED. Never silently set
            # PROTECTED or remove mappings on failed recovery.
            raise ProtectedUIDHold("UID_METADATA_HOLD_RECONCILIATION_REQUIRED")
