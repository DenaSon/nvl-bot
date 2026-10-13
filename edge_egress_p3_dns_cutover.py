"""P3-D: source-only, 6G-scoped Cloudflare ingress cutover gate.

Only positive Ingress+Egress migration changes public DNS. Protected Egress-
only 6G/6H deliberately leaves ingress DNS unchanged. This port is not wired
to a live bot or host driver and cannot certify real-world F4 evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from typing import Callable, Protocol

from edge_egress_f3_readiness import read_readiness, admission_eligible
from edge_egress_v1_cloudflare import PinnedDnsCutover

P3D_INGRESS_DNS_EXECUTOR_ENABLED = False
DNS_CUTOVER_PHASE = "EDGE_ONLY_PROTECTED_DNS_CUTOVER"
DNS_KIND = "PROTECTED_EGRESS_J"


class ProtectedDnsHandoffHold(ValueError):
    pass


class DnsSwitchPort(Protocol):
    def switch_edge_to_edge(self, source: str, target: str, *,
                            pinned_plan: PinnedDnsCutover, guard: Callable): ...
    def assert_target(self, target: str): ...


class IndependentHandoffProof(Protocol):
    def __call__(self, source: str, target: str,
                 identities: tuple[tuple[str, int], ...]) -> bool: ...


@dataclass(frozen=True)
class DnsHandoffAuthorization:
    """Immutable preview identity. Never puts Cloudflare tokens in the DB."""
    operation_id: int
    plan: PinnedDnsCutover
    active_uids: tuple[tuple[str, int], ...]

    def __post_init__(self):
        if (type(self.operation_id) is not int or self.operation_id <= 0
                or not isinstance(self.plan, PinnedDnsCutover)
                or not self.active_uids
                or any(not isinstance(name, str) or type(uid) is not int
                       or uid < 1000 or uid >= 60000
                       for name, uid in self.active_uids)
                or len(set(self.active_uids)) != len(self.active_uids)):
            raise ProtectedDnsHandoffHold("DNS_AUTH_IDENTITY_INVALID")


class GuardedIngressCloudflarePort:
    """Bounded adapter invoked only after protected admission/drain/UID repin.

    Makes NO lock/journal of its own, does not set 6H automatic flags, and
    never attempts a provider rollback after any uncertain partial write.
    Requires explicit opt-in and a root-only external supervisor; tests inject
    a fake proof and provider, production has no registered factory.
    """

    def __init__(self, *, db_conn: Callable, authorization: DnsHandoffAuthorization,
                 cloudflare: DnsSwitchPort | None = None,
                 independent_proof: IndependentHandoffProof | None = None,
                 release_enabled: bool = False,
                 geteuid: Callable = os.geteuid):
        self.db_conn = db_conn
        self.authorization = authorization
        self.cf = cloudflare
        self.proof = independent_proof
        self.enabled = release_enabled is True
        self.geteuid = geteuid
        self.used = False

    def _guard(self, *, phase=DNS_CUTOVER_PHASE):
        a = self.authorization
        if (not self.enabled or self.cf is None or self.proof is None
                or self.geteuid() != 0):
            raise ProtectedDnsHandoffHold("K_CUTOVER_RELEASE_OR_ROOT_REQUIRED")
        with self.db_conn() as conn:
            rows = conn.execute(
                "SELECT id,source_host,target_host,detail_json "
                "FROM failover_operations WHERE status='RUNNING'"
            ).fetchall()
            if (len(rows) != 1 or rows[0][:3] != (
                    a.operation_id, a.plan.source, a.plan.target)):
                raise ProtectedDnsHandoffHold("SHARED_6G_LOCK_LOST_OR_CONTENDED")
            try:
                journal = json.loads(rows[0][3])
            except (TypeError, ValueError):
                raise ProtectedDnsHandoffHold("6G_JOURNAL_UNKNOWN") from None
            if (not isinstance(journal, dict)
                    or journal.get("phase") != phase
                    or journal.get("kind") != DNS_KIND):
                raise ProtectedDnsHandoffHold("6G_PHASE_NOT_DNS_CUTOVER")
            if conn.execute(
                "SELECT value FROM settings WHERE key='edge_egress_protected_mode'"
            ).fetchone() != ("1",):
                raise ProtectedDnsHandoffHold("PROTECTED_MODE_REQUIRED")
            if conn.execute(
                "SELECT value FROM settings WHERE key='dns_current_ip'"
            ).fetchone() != (a.plan.source,):
                raise ProtectedDnsHandoffHold("DNS_SOURCE_DB_CAS_LOST")
            if conn.execute(
                "SELECT active,is_default FROM host_pool WHERE host=?",
                (a.plan.source,)
            ).fetchone() != (1, 1):
                raise ProtectedDnsHandoffHold("SOURCE_HOST_NO_LONGER_DEFAULT")
            if conn.execute(
                "SELECT active,is_default,is_standby FROM host_pool WHERE host=?",
                (a.plan.target,)
            ).fetchone() != (1, 0, 1):
                raise ProtectedDnsHandoffHold("TARGET_HOST_NO_LONGER_STANDBY")
            edges = conn.execute(
                "SELECT edge_id,core_public_ipv4 FROM edge_egress_allocations "
                "WHERE edge_public_ipv4=? AND status='STAGED'",
                (a.plan.target,)
            ).fetchall()
            if (len(edges) != 1 or a.plan.target == edges[0][1]
                    or a.plan.source == edges[0][1]
                    or not admission_eligible(read_readiness(conn, edges[0][0]))):
                raise ProtectedDnsHandoffHold("TARGET_F4_OR_CORE_IDENTITY_INVALID")
            active = tuple(conn.execute(
                "SELECT username FROM ssh_accounts WHERE service_type='ssh' "
                "AND status LIKE '%فعال%' AND status NOT LIKE '%غیر%' "
                "ORDER BY username"
            ).fetchall())
            if tuple(name for name, _ in a.active_uids) != tuple(
                    name for (name,) in active):
                raise ProtectedDnsHandoffHold("ACTIVE_ACCOUNT_SET_CHANGED")
            runtime = tuple(conn.execute(
                "SELECT username,uid,edge_ipv4,state FROM edge_egress_uid_runtime "
                "ORDER BY username"
            ).fetchall())
            mapping = tuple(conn.execute(
                "SELECT username,uid,edge_ipv4,status FROM "
                "edge_egress_uid_bindings ORDER BY username"
            ).fetchall())
            if (len(runtime) != len(a.active_uids)
                    or len(mapping) != len(a.active_uids)):
                raise ProtectedDnsHandoffHold("INCOMPLETE_PROTECTED_UID_SET")
            for (name, uid), rr, bb in zip(a.active_uids, runtime, mapping):
                if (rr != (name, uid, a.plan.target, "FROZEN")
                        or bb != (name, uid, a.plan.target, "PROTECTED")):
                    raise ProtectedDnsHandoffHold("UID_REPIN_NOT_FROZEN_OR_OWNED")
            for (name, _uid) in a.active_uids:
                host = conn.execute(
                    "SELECT host FROM ssh_accounts WHERE username=?", (name,)
                ).fetchone()
                if host != (a.plan.target,):
                    raise ProtectedDnsHandoffHold("INGRESS_ACCOUNT_CAS_MISSING")
        # Not just a claimed DB F4 row. Must be an independently measured
        # current positive proof for every member, checked again per DNS PUT.
        if self.proof(a.plan.source, a.plan.target, a.active_uids) is not True:
            raise ProtectedDnsHandoffHold("INDEPENDENT_INGRESS_UID_PROOF_MISSING")

    def cutover(self):
        if self.used:
            raise ProtectedDnsHandoffHold("DNS_CUTOVER_ONE_SHOT")
        self.used = True
        self._guard()
        a = self.authorization
        return self.cf.switch_edge_to_edge(
            a.plan.source, a.plan.target, pinned_plan=a.plan, guard=self._guard,
        )

    def verify_provider_target(self):
        """Provider state only; final UID release remains with guarded saga."""
        if not self.used:
            raise ProtectedDnsHandoffHold("DNS_CUTOVER_NOT_ATTEMPTED")
        self._guard()
        self.cf.assert_target(self.authorization.plan.target)
