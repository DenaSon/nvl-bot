"""K2 P2: atomic, fail-closed all-protected cohort mode promotion.

Source-only. Only the original P3-A/6G RUNNING journal may authorize a
single SQLite settings CAS from Legacy mode 0 to Protected mode 1.
No host/DNS/SSH/Edge changes, worker, Telegram mutation or auto release.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest
from ipaddress import IPv4Address
import json
import pwd
import sqlite3
from typing import Callable, Protocol

from edge_egress_f3_readiness import admission_eligible, read_readiness
from edge_egress_p3_executor import (
    ExecutionScope, ExecutionTicket, INTENT_PHASE, _scope_digest,
    assert_guarded_6g_intent,
)
from edge_egress_v1_admission import load_roster, checked_guard

COHORT_PROMOTION_RELEASED = False
MODE_KEY = "edge_egress_protected_mode"


class CohortPromotionHold(ValueError):
    pass


@dataclass(frozen=True)
class PromotionReview:
    scope: ExecutionScope
    protected_accounts: int
    fingerprint: str


class PromotionSafety(Protocol):
    """Each method must independently return literal True; False/None HOLD."""
    def assert_root_rescue_and_pam_boot(self, scope: ExecutionScope) -> bool: ...
    def assert_all_users_idle(self, scope: ExecutionScope) -> bool: ...
    def assert_kernel_uid_routes(self, scope: ExecutionScope) -> bool: ...
    def assert_external_ipv4_dns_ipv6(self, scope: ExecutionScope) -> bool: ...
    def assert_failure_reboot_recovery(self, scope: ExecutionScope) -> bool: ...


def _setting(conn, key: str) -> str | None:
    r = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return r[0] if r is not None else None


def _ipv4(value: object) -> bool:
    try:
        return isinstance(value, str) and str(IPv4Address(value)) == value and IPv4Address(value).is_global
    except (ValueError, TypeError):
        return False


def _snapshot(conn, scope: ExecutionScope, expected_mode: str, *, now: int,
              os_uid: Callable, roster_loader: Callable, guard_loader: Callable) -> PromotionReview:
    """Exact all-active source snapshot, including root guard and F4 evidence.

    The digest intentionally excludes the mode field: P3-A requires the
    independent acceptance digest to remain pinned across the single CAS.
    """
    if (scope.action != "COHORT_PROMOTE"
            or not _ipv4(scope.source_host) or not _ipv4(scope.target_host)
            or scope.source_host == scope.target_host
            or _setting(conn, MODE_KEY) != expected_mode
            or _setting(conn, "dns_current_ip") != scope.source_host):
        raise CohortPromotionHold("SOURCE_MODE_OR_DNS_CHANGED")
    pool = conn.execute(
        "SELECT host,service_port FROM host_pool "
        "WHERE active=1 AND is_default=1"
    ).fetchall()
    if len(pool) != 1 or pool[0][0] != scope.source_host or type(pool[0][1]) is not int or pool[0][1] <= 0:
        raise CohortPromotionHold("SOURCE_DEFAULT_NOT_UNIQUE")
    alloc = tuple(conn.execute(
        "SELECT edge_id,edge_public_ipv4,core_public_ipv4,route_table,status "
        "FROM edge_egress_allocations ORDER BY edge_id"
    ).fetchall())
    source = [x for x in alloc if x[1] == scope.source_host and x[4] == "STAGED"]
    target = [x for x in alloc if x[1] == scope.target_host and x[4] == "STAGED"]
    if (len(source) != 1 or len(target) != 1
            or source[0][0] != scope.edge_id
            or source[0][2] != target[0][2]
            or len([x for x in alloc if x[1] == scope.source_host]) != 1
            or len([x for x in alloc if x[1] == scope.target_host]) != 1):
        raise CohortPromotionHold("SOURCE_TARGET_F3_IDENTITY_UNVERIFIED")
    f4 = []
    for edge, address in ((scope.edge_id, scope.source_host), (target[0][0], scope.target_host)):
        r = read_readiness(conn, edge)
        if r is None or r.edge_ipv4 != address or not admission_eligible(r, now=now):
            raise CohortPromotionHold("SOURCE_OR_TARGET_F4_NOT_ACCEPTED")
        f4.append((r.witness, r.probed_at, r.expires_at, r.observed_ipv4))
    accounts = tuple(conn.execute(
        "SELECT username,host,service_type,status FROM ssh_accounts "
        "WHERE service_type='ssh' AND status LIKE '%فعال%' "
        "AND status NOT LIKE '%غیر%' ORDER BY username"
    ).fetchall())
    if not accounts or len(accounts) > 10000:
        raise CohortPromotionHold("COHORT_EMPTY_OR_TOO_LARGE")
    runtime = tuple(conn.execute(
        "SELECT username,uid,edge_id,edge_ipv4,route_table,priority,"
        "dns_port,state,generation,last_operation_id "
        "FROM edge_egress_uid_runtime ORDER BY username"
    ).fetchall())
    mapping = tuple(conn.execute(
        "SELECT username,uid,edge_id,edge_ipv4,status "
        "FROM edge_egress_uid_bindings ORDER BY username"
    ).fetchall())
    members = roster_loader()
    if (not isinstance(members, dict) or len(members) != len(accounts)
            or len(runtime) != len(accounts) or len(mapping) != len(accounts)):
        raise CohortPromotionHold("MIXED_OR_INCOMPLETE_PROTECTED_ROSTER")
    seen_uid = set()
    pins = []
    for (name, host, _, _), rr, bb in zip(accounts, runtime, mapping):
        if (not isinstance(name, str) or name != rr[0] or name != bb[0]
                or host != scope.source_host or name not in members
                or type(rr[1]) is not int or not 1000 <= rr[1] < 60000
                or rr[1] in seen_uid):
            raise CohortPromotionHold("SSH_ACCOUNT_OR_UID_OWNERSHIP_UNVERIFIED")
        seen_uid.add(rr[1])
        member = members[name]
        if (member.username != name or member.uid != rr[1]
                or os_uid(name) != rr[1]
                or rr[2:5] != (scope.edge_id, scope.source_host, source[0][3])
                or rr[7] != "PROTECTED"
                or bb != (name, rr[1], scope.edge_id, scope.source_host, "PROTECTED")):
            raise CohortPromotionHold("PROTECTED_UID_OR_SOURCE_DRIFT")
        manifest = guard_loader(member)
        req = manifest.request
        if (manifest.mode != "PROTECTED_BOOT_GUARD"
                or manifest.ingress_return is not True
                or manifest.shared_edge is not True
                or req.username != name or req.uid != rr[1]
                or req.spec.edge_id != scope.edge_id
                or req.spec.edge_public_ipv4 != scope.source_host
                or req.spec.core_public_ipv4 != source[0][2]
                or req.spec.route_table != rr[4]
                or req.priority != rr[5] or manifest.dns_port != rr[6]):
            raise CohortPromotionHold("ROOT_GUARD_OR_ROUTE_NOT_PINNED")
        pins.append((name,rr[1],rr[4],rr[5],rr[6],member.guard_sha256))
    digest = sha256(json.dumps(
        (scope.edge_id,scope.source_host,scope.target_host,alloc,pool,
         accounts,runtime,mapping,tuple(pins),tuple(f4)),
        sort_keys=True,separators=(",",":"),
    ).encode()).hexdigest()
    return PromotionReview(scope,len(accounts),digest)


def inspect_promotion(db_conn: Callable, scope: ExecutionScope, *, now: int,
                      os_uid: Callable = lambda name: pwd.getpwnam(name).pw_uid,
                      roster_loader: Callable = load_roster,
                      guard_loader: Callable = checked_guard) -> PromotionReview:
    """READ ONLY. A PASS is not a ticket, F4 proof or release."""
    try:
        with db_conn() as conn:
            if conn.execute(
                "SELECT 1 FROM failover_operations WHERE status='RUNNING' LIMIT 1"
            ).fetchone():
                raise CohortPromotionHold("SHARED_6G_BUSY")
            return _snapshot(conn,scope,"0",now=now,os_uid=os_uid,
                             roster_loader=roster_loader,guard_loader=guard_loader)
    except CohortPromotionHold:
        raise
    except (KeyError, OSError, ValueError, TypeError, AttributeError, sqlite3.Error) as exc:
        raise CohortPromotionHold("PROMOTION_EVIDENCE_UNAVAILABLE") from exc


class GuardedCohortPromotionPort:
    """Injected P3-A host port, one-shot, CAS-only and NO automatic downgrade."""

    def __init__(self, *, db_conn: Callable, review: PromotionReview,
                 ticket: ExecutionTicket, safety: PromotionSafety | None,
                 clock: Callable[[], int],
                 os_uid: Callable,
                 roster_loader: Callable, guard_loader: Callable,
                 release_enabled: bool = False):
        if (not isinstance(review, PromotionReview)
                or not isinstance(ticket, ExecutionTicket)
                or not compare_digest(ticket.scope_digest,_scope_digest(review.scope))):
            raise CohortPromotionHold("PROMOTION_SCOPE_TICKET_NOT_PINNED")
        self.db_conn,self.review,self.ticket = db_conn,review,ticket
        self.safety,self.clock = safety,clock
        self.os_uid,self.roster_loader,self.guard_loader = os_uid,roster_loader,guard_loader
        self.release_enabled=release_enabled is True
        self._started=False

    def _intent(self, scope: ExecutionScope) -> int:
        if (scope != self.review.scope or not self.release_enabled
                or self.safety is None):
            raise CohortPromotionHold("PROMOTION_NOT_INDEPENDENTLY_RELEASED")
        return assert_guarded_6g_intent(self.db_conn,scope,self.ticket)

    def _recheck(self, conn, scope, op: int, mode: str) -> PromotionReview:
        row = conn.execute(
            "SELECT source_host,target_host,status,detail_json "
            "FROM failover_operations WHERE id=?", (op,),
        ).fetchone()
        if (row is None or row[:3] != (scope.source_host,scope.target_host,"RUNNING")):
            raise CohortPromotionHold("PROMOTION_6G_LEASE_CHANGED")
        try:
            detail = json.loads(row[3])
        except (ValueError,TypeError) as exc:
            raise CohortPromotionHold("PROMOTION_INTENT_UNTRUSTED") from exc
        nonce = sha256(self.ticket.nonce.encode("ascii")).hexdigest()
        if (not isinstance(detail,dict)
                or detail.get("kind") != "K2_P3A"
                or detail.get("phase") != INTENT_PHASE
                or detail.get("action") != "COHORT_PROMOTE"
                or detail.get("edge_id") != scope.edge_id
                or not isinstance(detail.get("nonce_hash"),str)
                or not isinstance(detail.get("scope_digest"),str)
                or not compare_digest(detail["nonce_hash"],nonce)
                or not compare_digest(detail["scope_digest"],_scope_digest(scope))
                or conn.execute(
                    "SELECT COUNT(*) FROM failover_operations WHERE status='RUNNING'"
                ).fetchone()[0] != 1):
            raise CohortPromotionHold("PROMOTION_6G_INTENT_NOT_PINNED")
        snap = _snapshot(
            conn,scope,mode,now=self.clock(),os_uid=self.os_uid,
            roster_loader=self.roster_loader,guard_loader=self.guard_loader,
        )
        if not compare_digest(snap.fingerprint,self.review.fingerprint):
            raise CohortPromotionHold("PROMOTION_COHORT_OR_F4_DRIFT")
        return snap

    def _host_safety(self, scope: ExecutionScope):
        if (self.safety.assert_root_rescue_and_pam_boot(scope) is not True
                or self.safety.assert_all_users_idle(scope) is not True
                or self.safety.assert_kernel_uid_routes(scope) is not True
                or self.safety.assert_external_ipv4_dns_ipv6(scope) is not True
                or self.safety.assert_failure_reboot_recovery(scope) is not True):
            raise CohortPromotionHold("INDEPENDENT_HOST_SAFETY_NOT_PROVEN")

    async def apply(self, scope: ExecutionScope) -> None:
        if self._started:
            raise CohortPromotionHold("PROMOTION_PORT_ONE_SHOT")
        self._started=True
        op=self._intent(scope)
        # RUNNING 6G admission denies protected logins. Existing sessions
        # must be proved drained by a real, independently trusted host port.
        self._host_safety(scope)
        self._intent(scope)
        with self.db_conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._recheck(conn,scope,op,"0")
            changed=conn.execute(
                "UPDATE settings SET value='1' WHERE key=? AND value='0'",
                (MODE_KEY,),
            ).rowcount
            if changed != 1:
                raise CohortPromotionHold("PROTECTED_MODE_CAS_LOST")
            self._recheck(conn,scope,op,"1")

    async def verify(self, scope: ExecutionScope) -> bool:
        op=self._intent(scope)
        if not self._started:
            raise CohortPromotionHold("PROMOTION_NOT_APPLIED")
        with self.db_conn() as conn:
            self._recheck(conn,scope,op,"1")
        self._host_safety(scope)
        self._intent(scope)
        return True

    async def freeze_or_hold(self, scope: ExecutionScope) -> None:
        # No privileged UID-fence operation exists in this source-only port.
        # Never claim "frozen" to P3-A: report it as unverified so its durable
        # RECOVERY_REQUIRED journal retains the 6G lock for manual rescue.
        # Never flip mode back to Legacy or remove protected mappings.
        raise CohortPromotionHold("COHORT_KERNEL_FENCE_NOT_INDEPENDENTLY_VERIFIED")
