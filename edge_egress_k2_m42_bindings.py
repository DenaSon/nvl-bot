"""M4.2 reviewed root-only composition of M1/M2/M3 and ORIGINAL P3/6G.

No parallel worker, second 6G, Telegram callback, dynamic plugin loader, shell
executor or implicit enablement. Host-specific root callbacks must be audited
and wired at a separately approved deployment checkpoint. Deny if unavailable.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import pwd
import re
import sqlite3
import subprocess
import time
from typing import Callable

from edge_egress_k2_m4_root_worker import _read_checked, _verify_root_directory
from edge_egress_k2_m4_root_portal import RootMigrationPortal
from edge_egress_k2_m4_checkpoint import DurableWaveCheckpoint
from edge_egress_k2_m4_operator import inspect_telegram_migration
from edge_egress_k2_m2_ingress_journal import (
    RootReadOnlyIngressEvidence, make_m1_readonly_ingress_provider,
)
from edge_egress_k2_m42_evidence import (
    M42EvidenceHold, SignedExternalEvidence, load_external_evidence,
)
from edge_egress_k2_migration_inventory import MigrationInventory, MigrationSelection
from edge_egress_k2_m4_bootstrap import DeferredOriginal6GHostPort
from edge_egress_k2_m3_journal import confirm_original_6g_commit
from edge_egress_k2_m3_waves import build_wave_plan
from edge_egress_p3_executor import (
    ExecutionScope, ExecutionTicket, Existing6GGuardedExecutor,
    FreshEvidence, issue_execution_ticket, _scope_digest, BASE_GATES,
    ATTACH_GATES, SOURCE_ENROLL_GATES,
)

M42_LIVE_BINDINGS_ENABLED = False
# Never issue original 6G UID_ATTACH in Legacy mode unless a separate
# reviewed physical single transfer path is explicitly released.
M42_CROSS_EDGE_LEGACY_SINGLE_ENABLED = False
ADMIN_FILE = Path("/etc/nvl-egress/k2-m4/admin-policy.json")
MAX_ADMIN_BYTES = 8192


class M42BindingHold(ValueError):
    pass


@dataclass(frozen=True)
class RootAdminPolicy:
    principals: frozenset[tuple[int, int]]

    def permits(self, actor: int, chat: int) -> bool:
        return (type(actor) is int and type(chat) is int
                and (actor, chat) in self.principals)


def load_root_admin_policy(*, geteuid: Callable[[], int] = os.geteuid
                           ) -> RootAdminPolicy:
    if geteuid() != 0:
        raise M42BindingHold("M42_ROOT_POLICY_REQUIRED")
    _verify_root_directory(ADMIN_FILE.parent, group=None, private=True)
    raw = _read_checked(ADMIN_FILE, maximum=MAX_ADMIN_BYTES, strict=True)
    def no_duplicates(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                raise M42BindingHold("M42_POLICY_DUPLICATE_FIELD")
            d[k] = v
        return d
    try:
        obj = json.loads(raw, object_pairs_hook=no_duplicates)
        if (not isinstance(obj, dict)
            or set(obj) != {"version", "principals"}
            or type(obj["version"]) is not int or obj["version"] != 1
            or not isinstance(obj["principals"], list)
            or not 1 <= len(obj["principals"]) <= 20):
            raise ValueError()
        pairs = []
        for person in obj["principals"]:
            if not isinstance(person, dict) or set(person) != {"actor_id", "chat_id"}:
                raise ValueError()
            actor, chat = person["actor_id"], person["chat_id"]
            if (type(actor) is not int or actor <= 0
                or type(chat) is not int or chat == 0):
                raise ValueError()
            pairs.append((actor, chat))
        if len(set(pairs)) != len(pairs):
            raise ValueError()
        return RootAdminPolicy(frozenset(pairs))
    except (TypeError, ValueError, KeyError, UnicodeError) as exc:
        raise M42BindingHold("M42_ADMIN_POLICY_INVALID") from exc


class LegacyCurrentAdminRole:
    """Read-only current admin allowlist; never historical admin IDs.

    This is one factor in the existing root authorization check (the
    independent root-owned actor/chat policy is the other). Telegram private
    messages have actor_id == chat_id; group impersonation is rejected.
    Login/session verification remains a separate A3.2 field gate.
    """

    def __init__(self, db_conn: Callable):
        if not callable(db_conn):
            raise M42BindingHold("M42_ADMIN_DB_SOURCE_REQUIRED")
        self.db_conn = db_conn

    def __call__(self, actor: int, chat: int) -> bool:
        if (type(actor) is not int or type(chat) is not int
            or actor <= 0 or actor != chat):
            return False
        try:
            with self.db_conn() as db:
                rows=db.execute(
                    "SELECT value FROM settings "
                    "WHERE key='admin_chat_ids' LIMIT 2"
                ).fetchall()
            if len(rows) != 1 or type(rows[0][0]) is not str:
                return False
            raw=rows[0][0]
            if not raw or len(raw) > 8192:
                return False
            tokens=raw.split(",")
            if (len(tokens) > 20 or
                any(not re.fullmatch(r"[1-9][0-9]{0,19}",v) for v in tokens)
                or len(set(tokens)) != len(tokens)):
                return False
            return str(actor) in tokens
        except (sqlite3.Error, OSError, ValueError, TypeError,
                AttributeError, KeyError):
            return False


@dataclass(frozen=True)
class HostReviewedPorts:
    """Root-owned fixed providers, NEVER constructed from Telegram payload.

    port_factory must construct the existing GuardedVerifiedIngressUIDPort
    with a real GuardedProtectedUIDPort + SameEdge6GUIDRuntimeStore. It must
    not change host/PAM/kernel state; all writes are only in P3.apply under 6G.
    M5 must physically vet implementation before enabling these callbacks.
    """
    db_conn: Callable
    acquire_6g: Callable
    journal_6g: Callable
    port_factory: Callable
    live_admin_role: Callable[[int, int], bool]
    protected_mode: Callable[[], str]
    external_evidence: Callable[[], SignedExternalEvidence] = load_external_evidence
    ingress_provider: Callable = make_m1_readonly_ingress_provider
    os_uid: Callable[[str], int] = lambda name: pwd.getpwnam(name).pw_uid
    now: Callable[[], int] = lambda: int(time.time())
    geteuid: Callable[[], int] = os.geteuid


class RootM42Bindings:
    """Bind authoritative sources; root-only, staged and disabled by default."""

    def __init__(self, *, ports: HostReviewedPorts, root_secret: bytes,
                 admin_policy: RootAdminPolicy,
                 reviewed_release: bool = False):
        if (not isinstance(ports, HostReviewedPorts)
            or not isinstance(admin_policy, RootAdminPolicy)
            or type(root_secret) is not bytes or len(root_secret) < 32
            or not all(callable(c) for c in (
                ports.db_conn, ports.acquire_6g, ports.journal_6g,
                ports.port_factory, ports.live_admin_role,
                ports.protected_mode, ports.external_evidence,
                ports.ingress_provider, ports.os_uid, ports.now,
                ports.geteuid))):
            raise M42BindingHold("M42_ROOT_PORTS_NOT_VERIFIED")
        self.ports = ports
        self.secret = root_secret
        self.policy = admin_policy
        self.reviewed_release = reviewed_release is True
        self._outstanding: dict[str, tuple[ExecutionScope, ExecutionTicket]] = {}

    def _gate(self):
        if (not M42_LIVE_BINDINGS_ENABLED or not self.reviewed_release
            or self.ports.geteuid() != 0):
            raise M42BindingHold("M42_LIVE_BINDINGS_NOT_RELEASED")

    def admin(self, actor: int, chat: int) -> bool:
        self._gate()
        # Both pinned root actor/chat list AND live DB role must agree.
        return (self.policy.permits(actor, chat)
                and self.ports.live_admin_role(actor, chat) is True)

    def _proof(self) -> SignedExternalEvidence:
        self._gate()
        ev = self.ports.external_evidence()
        if not isinstance(ev, SignedExternalEvidence):
            raise M42BindingHold("M42_SIGNED_EXTERNAL_EVIDENCE_ABSENT")
        ev.verify_pre_attach()
        now = self.ports.now()
        if (type(now) is not int or now < ev.observed_at or now >= ev.expires_at
            or now - ev.observed_at > 30):
            raise M42BindingHold("M42_EXTERNAL_EVIDENCE_EXPIRED")
        return ev

    def review(self, selected: MigrationSelection) -> MigrationInventory:
        self._gate()
        if not isinstance(selected, MigrationSelection):
            raise M42BindingHold("M42_SELECTION_REQUIRED")
        evidence = self._proof()
        if evidence.target_edge != selected.target_edge_id:
            raise M42BindingHold("M42_SIGNED_EDGE_MISMATCH")
        now = self.ports.now()
        sources = self.ports.ingress_provider(
            now=now, run=subprocess.run, geteuid=self.ports.geteuid,
            resolve_uid=self.ports.os_uid,
        )
        if not callable(sources):
            raise M42BindingHold("M42_ROOT_PAM_WG_SOURCE_ABSENT")

        def source(name: str):
            w = sources(name)
            if not any(
                a.username == name
                and a.source_edge == w.edge_id and a.source_ipv4 == w.edge_ipv4
                and a.uid == self.ports.os_uid(name)
                for a in evidence.accounts
            ):
                raise M42BindingHold("M42_SIGNED_PAM_SOURCE_DRIFT")
            return w

        def count(name: str, uid: int):
            w = source(name)
            return evidence.verify_account(
                name, uid, source_edge=w.edge_id, source_ipv4=w.edge_ipv4,
            )

        result = inspect_telegram_migration(
            self.ports.db_conn, selected, now=now,
            uid_lookup=self.ports.os_uid, source_provider=source,
            session_provider=count, geteuid=self.ports.geteuid,
            root_ingress_peers=(
                sources.peers if type(sources) is RootReadOnlyIngressEvidence
                and self.ports.ingress_provider is make_m1_readonly_ingress_provider
                else None
            ),
        )
        evidence.verify_target(
            selected.target_edge_id, result.target_ipv4, selected.usernames,
        )
        return result

    def physical_f4(self, plan) -> bool:
        self._gate()
        try:
            ev = self._proof()
            ev.verify_target(plan.selection.target_edge_id,
                             plan.target_ipv4, plan.selection.usernames)
            for member in plan.members:
                ev.verify_account(
                    member.username, member.uid,
                    source_edge=member.source_edge_id,
                    source_ipv4=member.source_ipv4,
                )
            current = self.review(plan.selection)
            return bool(current.target_f4_accepted
                        and build_wave_plan(current).digest == plan.digest
                        and not plan.global_blockers and not plan.blocked)
        except (M42EvidenceHold, AttributeError, ValueError, TypeError):
            return False

    def mode(self) -> str:
        self._gate()
        observed = self.ports.protected_mode()
        if type(observed) is not str or observed not in ("0", "1"):
            raise M42BindingHold("M42_PROTECTED_MODE_UNTRUSTED")
        return observed

    def _post_commit_under_current_6g(
        self, scope: ExecutionScope, ticket: ExecutionTicket | None = None,
    ) -> bool:
        """Read original 6G and F2, NEVER infer a transfer from a UI flag.

        The final P3 evidence check runs after per-UID PROTECTED CAS but before
        the original 6G journal becomes SUCCEEDED. M1 then reports
        TARGET_ALREADY_PROTECTED. Accept that *single* issue only for the
        exact still-RUNNING nonce-bearing operation and protected mapping.
        """
        from edge_egress_uid_runtime_store import read_binding
        from edge_egress_p3_executor import INTENT_PHASE
        # Never infer the 6G nonce from a syntactically valid journal value:
        # the caller must present the exact issued one-shot P3 ticket.
        if (type(scope) is not ExecutionScope
            or type(ticket) is not ExecutionTicket
            or ticket.scope_digest != _scope_digest(scope)
            or type(ticket.nonce) is not str
            or not re.fullmatch(r"[a-f0-9]{32}", ticket.nonce)):
            return False
        expected_nonce_hash = sha256(ticket.nonce.encode("ascii")).hexdigest()
        try:
            with self.ports.db_conn() as db:
                binding = read_binding(db, scope.username)
                if (binding is None or binding.state != "PROTECTED"
                    or binding.uid != scope.uid
                    or binding.edge_id != scope.edge_id
                    or binding.edge_ipv4 != scope.target_host):
                    return False
                mapped = db.execute(
                    "SELECT uid,edge_id,edge_ipv4,status "
                    "FROM edge_egress_uid_bindings WHERE username=?",
                    (scope.username,),
                ).fetchone()
                if mapped != (
                    scope.uid,scope.edge_id,scope.target_host,"PROTECTED"
                ):
                    return False
                rows = db.execute(
                    "SELECT id,status,source_host,target_host,detail_json "
                    "FROM failover_operations WHERE status='RUNNING'"
                ).fetchall()
                if len(rows) != 1:
                    return False
                op_id,status,source,target,raw = rows[0]
                if (op_id != binding.last_operation_id
                    or source != scope.source_host
                    or target != scope.target_host):
                    return False
                detail = json.loads(raw)
                return (
                    type(detail) is dict
                    and detail.get("kind") == "K2_P3A"
                    and detail.get("phase") == INTENT_PHASE
                    and detail.get("action") == scope.action
                    and detail.get("edge_id") == scope.edge_id
                    and detail.get("scope_digest") == _scope_digest(scope)
                    and type(detail.get("nonce_hash")) is str
                    and re.fullmatch(r"[a-f0-9]{64}", detail["nonce_hash"])
                        is not None
                    and hmac.compare_digest(
                        detail["nonce_hash"], expected_nonce_hash
                    )
                )
        except (sqlite3.Error,ValueError,TypeError,KeyError):
            return False

    def fresh_p3_evidence(
        self, scope: ExecutionScope, *,
        expected_ticket: ExecutionTicket | None = None,
    ) -> FreshEvidence:
        self._gate()
        if not isinstance(scope, ExecutionScope):
            raise M42BindingHold("M42_P3_SCOPE_UNTRUSTED")
        same_ingress = (
            scope.action == "UID_ENROLL_SOURCE"
            and scope.source_host == scope.target_host
        )
        cross_ingress = (
            M42_CROSS_EDGE_LEGACY_SINGLE_ENABLED
            and scope.action == "UID_ATTACH"
            and scope.source_host != scope.target_host
        )
        if not (same_ingress or cross_ingress):
            raise M42BindingHold("M42_ONLY_SAME_EDGE_LEGACY_ALLOWED")
        from edge_egress_k2_migration_inventory import select_migration
        selection = select_migration("SINGLE", (scope.username,), scope.edge_id)
        reviewed = self.review(selection)
        chosen = [a for a in reviewed.accounts if a.selected]
        # M1 deliberately reports both TARGET_ALREADY_PROTECTED and
        # PROTECTED_SOURCE_DRIFT after a cross-Edge per-UID commit.  Neither
        # may authorize a fresh ticket or another UID: accept exactly that
        # pair *only* while original 6G still owns the verified F2 CAS.
        completed_issues = (
            ("TARGET_ALREADY_PROTECTED", "PROTECTED_SOURCE_DRIFT")
            if cross_ingress else ("TARGET_ALREADY_PROTECTED",)
        )
        postcommit = bool(
            len(chosen) == 1
            and chosen[0].issues == completed_issues
            and expected_ticket is not None
            and self._post_commit_under_current_6g(scope, expected_ticket)
        )
        if (any(issue != 'SHARED_6G_BUSY' for issue in reviewed.global_issues)\
            or not reviewed.target_f4_accepted
            or len(chosen) != 1
            or chosen[0].issues not in ((), completed_issues)
            or chosen[0].issues == completed_issues and not postcommit
            or chosen[0].username != scope.username
            or chosen[0].uid != scope.uid
            or chosen[0].source_ipv4 != scope.source_host
            or not chosen[0].source_proven
            or chosen[0].active_sessions != 0
            or (chosen[0].protected_edge_id != (
                scope.edge_id if postcommit else ""
            ))
            or (cross_ingress and chosen[0].source_edge_id == scope.edge_id)
            or (same_ingress and chosen[0].source_edge_id != scope.edge_id)
            or self.mode() != "0"):
            raise M42BindingHold("M42_P3_FRESH_EVIDENCE_HOLD")
        proof = self._proof()
        # The signed report must name the same *currently observed ingress*.
        # Target-only identity and UID are insufficient to authorize a 6G
        # ticket if the operator moved the SSH ingress between witnesses.
        proof.verify_account(
            scope.username, scope.uid,
            source_edge=chosen[0].source_edge_id,
            source_ipv4=scope.source_host,
        )
        if (proof.target_edge != scope.edge_id or
            proof.target_ipv4 != scope.target_host):
            raise M42BindingHold("M42_P3_EXTERNAL_SCOPE_DRIFT")
        # Bind a P3 ticket to the complete signed observation, not only
        # generation/time. A witness replacement with identical metadata
        # but different accounts, checks or validity must invalidate P3.
        observed = {
            "scope": _scope_digest(scope),
            "generation": proof.generation,
            "observed_at": proof.observed_at,
            "expires_at": proof.expires_at,
            "target_edge": proof.target_edge,
            "target": proof.target_ipv4,
            "phase": proof.phase,
            "checks": sorted(proof.checks),
            "accounts": [
                {
                    "username": account.username, "uid": account.uid,
                    "source_edge": account.source_edge,
                    "source_ipv4": account.source_ipv4,
                    "active_sessions": account.active_sessions,
                } for account in sorted(proof.accounts,
                                         key=lambda item:item.username)
            ],
        }
        digest = sha256(json.dumps(observed, sort_keys=True,
                                  separators=(",", ":")).encode()).hexdigest()
        return FreshEvidence(
            digest=digest, checked_at=self.ports.now(),
            gates=BASE_GATES | ATTACH_GATES |
                  (SOURCE_ENROLL_GATES if same_ingress else frozenset()),
        )

    def _prune_expired_one_shot_tickets(self) -> None:
        """Reclaim only expired unconsumed root ticket cache entries.

        Original P3/6G nonce and journal authority is never mutated. A
        malformed clock or cache entry holds *before* any partial eviction.
        """
        now=self.ports.now()
        if type(now) is not int or now<=0:
            raise M42BindingHold("M42_TICKET_CLOCK_UNTRUSTED")
        expired=[]
        for nonce, record in self._outstanding.items():
            if (type(nonce) is not str or not isinstance(record,tuple)
                or len(record)!=2 or not isinstance(record[0],ExecutionScope)
                or not isinstance(record[1],ExecutionTicket)
                or record[1].nonce!=nonce
                or type(record[1].expires_at) is not int):
                raise M42BindingHold("M42_TICKET_QUEUE_CORRUPT")
            if record[1].expires_at<=now:
                expired.append(nonce)
        for nonce in expired:
            del self._outstanding[nonce]

    def issue_ticket(self, scope: ExecutionScope,
                     actor: int, chat: int) -> ExecutionTicket:
        self._gate()
        if not self.admin(actor, chat):
            raise M42BindingHold("M42_ROOT_OPERATOR_UNAUTHORIZED")
        fresh = self.fresh_p3_evidence(scope)
        ticket = issue_execution_ticket(
            scope, fresh, actor_id=actor, chat_id=chat, now=self.ports.now(),
        )
        # Only expired root-only tickets can be reclaimed; live one-shot
        # approvals are never evicted just to make room for new requests.
        self._prune_expired_one_shot_tickets()
        if len(self._outstanding) >= 20:
            raise M42BindingHold("M42_ROOT_TICKET_QUEUE_FULL")
        self._outstanding[ticket.nonce] = (scope, ticket)
        return ticket

    async def execute_single(self, scope: ExecutionScope,
                             ticket: ExecutionTicket,
                             actor: int, chat: int):
        self._gate()
        if not self.admin(actor, chat):
            raise M42BindingHold("M42_ROOT_OPERATOR_UNAUTHORIZED")
        record = self._outstanding.pop(ticket.nonce, None)
        if (record is None or record != (scope, ticket)
            or ticket.actor_id != actor or ticket.chat_id != chat
            or ticket.scope_digest != _scope_digest(scope)):
            raise M42BindingHold("M42_P3_ONE_SHOT_TICKET_UNTRUSTED")
        # This is deliberately a root-owned, reviewed factory. Its output is
        # the REAL M3 guarded port, not an arbitrary callable/boolean.
        port = self.ports.port_factory(scope, ticket, self.review)
        if (not isinstance(port, DeferredOriginal6GHostPort)
            or port.scope != scope or port.ticket != ticket
            or port.db_conn is not self.ports.db_conn):
            raise M42BindingHold("M42_GUARDED_UID_HOST_PORT_REQUIRED")
        executor = Existing6GGuardedExecutor(
            db_conn=self.ports.db_conn,
            acquire_fn=self.ports.acquire_6g,
            journal_fn=self.ports.journal_6g,
            review_fn=lambda current_scope: self.fresh_p3_evidence(
                current_scope, expected_ticket=ticket,
            ),
            host_port=port, release_enabled=True,
            geteuid=self.ports.geteuid, clock=self.ports.now,
        )
        return await executor.execute(scope, ticket,
                                      actor_id=actor, chat_id=chat)

    def confirm_6g(self, scope: ExecutionScope,
                   ticket: ExecutionTicket, op_id: int) -> bool:
        self._gate()
        return confirm_original_6g_commit(
            self.ports.db_conn, scope, ticket, op_id,
        )

    def portal(self, *, checkpoint: DurableWaveCheckpoint) -> RootMigrationPortal:
        self._gate()
        if not isinstance(checkpoint, DurableWaveCheckpoint):
            raise M42BindingHold("M42_ORIGINAL_DB_CHECKPOINT_REQUIRED")
        return RootMigrationPortal(
            root_secret=self.secret,
            review=self.review,
            admin_authorized=self.admin,
            independent_physical_f4=self.physical_f4,
            current_protected_mode=self.mode,
            issue_single_ticket=self.issue_ticket,
            execute_single=self.execute_single,
            committed_6g=self.confirm_6g,
            checkpoint=checkpoint,
            clock=self.ports.now,
            geteuid=self.ports.geteuid,
            release_enabled=True,
        )
