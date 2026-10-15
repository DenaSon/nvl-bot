"""F2: durable per-UID Egress intent + CAS under the EXISTING Phase 6G lock.

No implicit migration, SSH configuration change, Linux routing mutation or
customer activation. A protected binding can only be committed after an
external controller proves the full route/DNS/IPv6 path under its 6G lease.
Shared Edge tables are intentional; UID, rule priority and DNS port are unique.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Callable

from edge_egress_uid_policy import UIDPolicyRequest
from edge_egress_f3_readiness import read_readiness, admission_eligible


class RuntimeStoreUnsafe(ValueError):
    pass


RUNTIME_SCHEMA = """
CREATE TABLE IF NOT EXISTS edge_egress_uid_runtime (
  username TEXT PRIMARY KEY,
  uid INTEGER NOT NULL UNIQUE CHECK(uid BETWEEN 1000 AND 59999),
  edge_id TEXT NOT NULL,
  edge_ipv4 TEXT NOT NULL,
  route_table INTEGER NOT NULL,
  priority INTEGER NOT NULL UNIQUE CHECK(priority BETWEEN 1000 AND 31999),
  dns_port INTEGER NOT NULL UNIQUE CHECK(dns_port BETWEEN 1024 AND 65535),
  state TEXT NOT NULL CHECK(state IN (
    'BLOCKED', 'ROUTED_UNVERIFIED', 'PROTECTED', 'FROZEN', 'HOLD')),
  generation INTEGER NOT NULL DEFAULT 1 CHECK(generation >= 1),
  last_operation_id INTEGER NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_egress_uid_runtime_edge
  ON edge_egress_uid_runtime(edge_id, state);
"""


def install_runtime_schema(conn: sqlite3.Connection) -> None:
    """Explicit operator migration; never run on connection startup."""
    conn.executescript(RUNTIME_SCHEMA)


@dataclass(frozen=True)
class RuntimeBinding:
    username: str
    uid: int
    edge_id: str
    edge_ipv4: str
    route_table: int
    priority: int
    dns_port: int
    state: str
    generation: int
    last_operation_id: int


def read_binding(conn: sqlite3.Connection, username: str) -> RuntimeBinding | None:
    row = conn.execute(
        "SELECT username,uid,edge_id,edge_ipv4,route_table,priority,dns_port,"
        "state,generation,last_operation_id FROM edge_egress_uid_runtime "
        "WHERE username=?", (username,),
    ).fetchone()
    return RuntimeBinding(*row) if row else None


@dataclass
class Existing6GUIDRuntimeStore:
    db_conn: Callable
    os_uid_for_username: Callable[[str], int]
    # Opt-in only after per-UID fences + complete durable roster are attested.
    shared_edge_enabled: bool = False
    qualified_target: Callable | None = None

    def _core_target_qualified(self, req):
        from edge_egress_k2_core_observer import CorePhysicalObservations
        from edge_egress_k2_core_operations import CORE_OPERATIONS_ENABLED
        callback=self.qualified_target
        return bool(CORE_OPERATIONS_ENABLED and callable(callback)
            and type(getattr(callback,'__self__',None)) is CorePhysicalObservations
            and getattr(callback,'__func__',None) is CorePhysicalObservations.target_qualified
            and callback(req) is True)

    @staticmethod
    def _lock(conn, op_id: int, source: str, target: str) -> None:
        if type(op_id) is not int or op_id <= 0 or source == target:
            raise RuntimeStoreUnsafe("INVALID_SHARED_6G_LEASE")
        row = conn.execute(
            "SELECT status,source_host,target_host FROM failover_operations "
            "WHERE id=?", (op_id,),
        ).fetchone()
        if row != ("RUNNING", source, target):
            raise RuntimeStoreUnsafe("SHARED_6G_LOCK_NOT_CURRENT")
        # A different RUNNING operation must never coexist, even if the
        # underlying legacy 6G lock acquisition was improperly bypassed.
        other = conn.execute(
            "SELECT 1 FROM failover_operations "
            "WHERE status='RUNNING' AND id!=? LIMIT 1", (op_id,),
        ).fetchone()
        if other:
            raise RuntimeStoreUnsafe("CONCURRENT_SHARED_6G_OPERATION")

    @staticmethod
    def _schema(conn) -> None:
        for name in ("edge_egress_uid_runtime",
                     "edge_egress_uid_bindings", "edge_egress_allocations"):
            if not conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (name,),
            ).fetchone():
                raise RuntimeStoreUnsafe("EXPLICIT_MIGRATION_REQUIRED:" + name)

    def _source_owner(self, conn, req: UIDPolicyRequest, source: str) -> None:
        """Legacy global/default ingress rule; unchanged for existing users."""
        row = conn.execute(
            "SELECT host,service_type,status FROM ssh_accounts WHERE username=?",
            (req.username,),
        ).fetchone()
        if not row or row[1] != "ssh" or not isinstance(row[2], str) or (
            "فعال" not in row[2] or "غیر" in row[2]
        ) or row[0] not in (source, "", None):
            raise RuntimeStoreUnsafe("SSH_ACCOUNT_SOURCE_NOT_VERIFIED")
        source_row = conn.execute(
            "SELECT active,is_default FROM host_pool WHERE host=?", (source,)
        ).fetchone()
        if source_row != (1, 1):
            raise RuntimeStoreUnsafe("SOURCE_NOT_ACTIVE_DEFAULT_EDGE")
        dns_row = conn.execute(
            "SELECT value FROM settings WHERE key='dns_current_ip'"
        ).fetchone()
        if dns_row != (source,):
            raise RuntimeStoreUnsafe("INGRESS_DNS_NOT_AT_SOURCE_EDGE")

    def _owner(self, conn, req: UIDPolicyRequest, source: str, *,
               require_ready: bool = True) -> None:
        req.validate()
        self._source_owner(conn, req, source)
        if self.os_uid_for_username(req.username) != req.uid:
            raise RuntimeStoreUnsafe("UID_OS_IDENTITY_CHANGED")
        edge = conn.execute(
            "SELECT edge_public_ipv4,core_public_ipv4,route_table,status,"
            "tunnel_network,veth_network FROM edge_egress_allocations "
            "WHERE edge_id=?", (req.spec.edge_id,),
        ).fetchone()
        if edge != (
            req.spec.edge_public_ipv4, req.spec.core_public_ipv4,
            req.spec.route_table, "STAGED", req.spec.tunnel_network,
            req.spec.veth_network,
        ):
            raise RuntimeStoreUnsafe("STAGED_EDGE_ALLOCATION_MISMATCH")
        # F3 removes the old ability to commit a protected customer from a
        # mere STAGED allocation or a disposable namespace IP probe.
        # READY is NOT produced by F3; the separate F4 acceptance is required.
        if not conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='edge_egress_readiness'"
        ).fetchone():
            raise RuntimeStoreUnsafe("F3_READINESS_MIGRATION_REQUIRED")
        if require_ready and not admission_eligible(
            read_readiness(conn, req.spec.edge_id)
        ) and not self._core_target_qualified(req):
            raise RuntimeStoreUnsafe("F4_PRODUCTION_READINESS_REQUIRED")

    def _tx(self, operation_id, source, target, task):
        with self.db_conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._lock(conn, operation_id, source, target)
            self._schema(conn)
            value = task(conn)
            self._lock(conn, operation_id, source, target)
            return value

    def reserve_blocked(self, operation_id: int, req: UIDPolicyRequest,
                        *, source: str, dns_port: int) -> RuntimeBinding:
        """Durable DENY intent committed before ANY host mutation.

        Existing protected users must be explicitly frozen and re-validated
        separately; never silently overwrite or de-protect their ownership.
        """
        if type(dns_port) is not int or not 1024 <= dns_port <= 65535:
            raise RuntimeStoreUnsafe("INVALID_DNS_PORT")
        def work(conn):
            self._owner(conn, req, source)
            if read_binding(conn, req.username) is not None:
                raise RuntimeStoreUnsafe("UID_BINDING_ALREADY_EXISTS")
            # G: the shared Edge next hop is stable; arming a second UID
            # must never freeze that route. The kernel boot path instead
            # inserts a per-UID IPv4 deny before selecting its policy table.
            other = conn.execute(
                "SELECT route_table,edge_ipv4,state "
                "FROM edge_egress_uid_runtime WHERE edge_id=? "
                "AND username<>? LIMIT 1",
                (req.spec.edge_id, req.username),
            ).fetchone()
            if other:
                if not self.shared_edge_enabled:
                    raise RuntimeStoreUnsafe("SHARED_EDGE_CANARY_ISOLATION_REQUIRED")
                if other[0:2] != (req.spec.route_table, req.spec.edge_public_ipv4):
                    raise RuntimeStoreUnsafe("SHARED_EDGE_IDENTITY_CONFLICT")
                if other[2] in ("BLOCKED", "ROUTED_UNVERIFIED"):
                    raise RuntimeStoreUnsafe("SHARED_EDGE_PENDING_UID_HOLD")
            # Different Edges must never reference the same route table.
            if conn.execute(
                "SELECT 1 FROM edge_egress_uid_runtime "
                "WHERE edge_id<>? AND route_table=? LIMIT 1",
                (req.spec.edge_id, req.spec.route_table),
            ).fetchone():
                raise RuntimeStoreUnsafe("CROSS_EDGE_ROUTE_TABLE_COLLISION")
            if conn.execute(
                "SELECT 1 FROM edge_egress_uid_bindings WHERE "
                "username=? OR uid=? LIMIT 1", (req.username, req.uid),
            ).fetchone():
                raise RuntimeStoreUnsafe("EXISTING_PROTECTED_MAPPING")
            try:
                conn.execute(
                    "INSERT INTO edge_egress_uid_runtime "
                    "(username,uid,edge_id,edge_ipv4,route_table,priority,"
                    "dns_port,state,last_operation_id) "
                    "VALUES(?,?,?,?,?,?,?,'BLOCKED',?)",
                    (req.username, req.uid, req.spec.edge_id,
                     req.spec.edge_public_ipv4, req.spec.route_table,
                     req.priority, dns_port, operation_id),
                )
            except sqlite3.IntegrityError as exc:
                raise RuntimeStoreUnsafe("UID_PRIORITY_OR_DNS_PORT_COLLISION") from exc
            return read_binding(conn, req.username)
        return self._tx(operation_id, source, req.spec.edge_public_ipv4, work)

    def transition(self, operation_id: int, req: UIDPolicyRequest, *,
                   source: str, expected: str, target: str) -> RuntimeBinding:
        """CAS one state. Never marks PROTECTED: commit_protected does that."""
        if (expected, target) not in {
            ("BLOCKED", "ROUTED_UNVERIFIED"),
            ("ROUTED_UNVERIFIED", "FROZEN"),
            ("PROTECTED", "FROZEN"),
            ("FROZEN", "ROUTED_UNVERIFIED"),
            ("BLOCKED", "FROZEN"),
            ("BLOCKED", "HOLD"),
            ("ROUTED_UNVERIFIED", "HOLD"),
            ("FROZEN", "HOLD"),
            ("PROTECTED", "HOLD"),
        }:
            raise RuntimeStoreUnsafe("UNSAFE_STATE_TRANSITION")
        def work(conn):
            # Deny-only FROZEN/HOLD must remain possible if a previously
            # verified Edge loses readiness or its acceptance has expired.
            self._owner(
                conn, req, source,
                require_ready=target not in ("FROZEN", "HOLD"),
            )
            previous = read_binding(conn, req.username)
            if not previous or (
                previous.uid, previous.edge_id, previous.edge_ipv4,
                previous.route_table, previous.priority
            ) != (
                req.uid, req.spec.edge_id, req.spec.edge_public_ipv4,
                req.spec.route_table, req.priority
            ):
                raise RuntimeStoreUnsafe("BINDING_IDENTITY_MISMATCH")
            if previous.state != expected:
                raise RuntimeStoreUnsafe("BINDING_STALE_STATE")
            changed = conn.execute(
                "UPDATE edge_egress_uid_runtime SET state=?,"
                "generation=generation+1,last_operation_id=?,"
                "updated_at=CURRENT_TIMESTAMP "
                "WHERE username=? AND generation=? AND state=?",
                (target, operation_id, req.username,
                 previous.generation, expected),
            ).rowcount
            if changed != 1:
                raise RuntimeStoreUnsafe("BINDING_CAS_LOST")
            return read_binding(conn, req.username)
        return self._tx(operation_id, source, req.spec.edge_public_ipv4, work)

    def commit_protected(self, operation_id: int, req: UIDPolicyRequest,
                         *, source: str) -> RuntimeBinding:
        """Last transactional step after independent IP/DNS/IPv6 proof.

        F1 legacy fences see the permanent PROTECTED mapping after commit.
        No write to ssh_accounts.host, DNS or host_pool is allowed.
        """
        def work(conn):
            self._owner(conn, req, source)
            before = read_binding(conn, req.username)
            if not before or before.state != "ROUTED_UNVERIFIED" or (
                before.uid, before.edge_id, before.edge_ipv4,
                before.route_table, before.priority
            ) != (
                req.uid, req.spec.edge_id, req.spec.edge_public_ipv4,
                req.spec.route_table, req.priority
            ):
                raise RuntimeStoreUnsafe("PROTECTION_PROOF_STATE_STALE")
            old = conn.execute(
                "SELECT uid,edge_id,edge_ipv4,status FROM "
                "edge_egress_uid_bindings WHERE username=?",
                (req.username,),
            ).fetchone()
            if old and old != (req.uid, req.spec.edge_id,
                               req.spec.edge_public_ipv4, "PROTECTED"):
                raise RuntimeStoreUnsafe("FOREIGN_EXISTING_PROTECTED_BINDING")
            if not old:
                try:
                    conn.execute(
                        "INSERT INTO edge_egress_uid_bindings "
                        "(username,uid,edge_id,edge_ipv4,status) "
                        "VALUES(?,?,?,?,'PROTECTED')",
                        (req.username, req.uid, req.spec.edge_id,
                         req.spec.edge_public_ipv4),
                    )
                except sqlite3.IntegrityError as exc:
                    raise RuntimeStoreUnsafe("PROTECTED_UID_MAPPING_COLLISION") from exc
            changed = conn.execute(
                "UPDATE edge_egress_uid_runtime SET state='PROTECTED',"
                "generation=generation+1,last_operation_id=?,"
                "updated_at=CURRENT_TIMESTAMP "
                "WHERE username=? AND generation=? AND state='ROUTED_UNVERIFIED'",
                (operation_id, req.username, before.generation),
            ).rowcount
            if changed != 1:
                raise RuntimeStoreUnsafe("BINDING_CAS_LOST")
            return read_binding(conn, req.username)
        return self._tx(operation_id, source, req.spec.edge_public_ipv4, work)

    def assert_frozen_binding(self, operation_id: int, req: UIDPolicyRequest,
                              *, source: str, dns_port: int) -> RuntimeBinding:
        """Only an already FROZEN binding may resume under a fresh 6G lock."""
        def work(conn):
            self._owner(conn, req, source)
            row = read_binding(conn, req.username)
            if not row or (
                row.uid, row.edge_id, row.edge_ipv4, row.route_table,
                row.priority, row.dns_port, row.state
            ) != (
                req.uid, req.spec.edge_id, req.spec.edge_public_ipv4,
                req.spec.route_table, req.priority, dns_port, "FROZEN"
            ):
                raise RuntimeStoreUnsafe("FROZEN_BINDING_NOT_VERIFIED")
            mapping = conn.execute(
                "SELECT uid,edge_id,edge_ipv4,status "
                "FROM edge_egress_uid_bindings WHERE username=?",
                (req.username,),
            ).fetchone()
            if mapping != (req.uid, req.spec.edge_id,
                           req.spec.edge_public_ipv4, "PROTECTED"):
                raise RuntimeStoreUnsafe("FROZEN_PROTECTED_MAPPING_MISSING")
            return row
        return self._tx(operation_id, source, req.spec.edge_public_ipv4, work)

# Opt-in only after the 6G-owned PAM policy writer and host port are accepted.
K2_CROSS_EDGE_RUNTIME_STORE_ENABLED = False


class K2CrossEdgeUIDRuntimeStore(Existing6GUIDRuntimeStore):
    """Exact UID_ATTACH, unchanged global Legacy mode and original F2 CAS.

    The source is re-attested from root PAM journal/live wg0, not default
    host_pool or dns_current_ip. Target F3/F4 readiness and every original
    F2 state transition remain enforced by the inherited implementation.
    """

    def __init__(self, db_conn: Callable, os_uid_for_username: Callable,
                 *, scope, ticket, ingress_edge_id: str,
                 source_evidence: Callable, geteuid: Callable,
                 reviewed_release: bool = False):
        from edge_egress_p3_executor import ExecutionScope, ExecutionTicket, _scope_digest
        if (not isinstance(scope, ExecutionScope)
            or scope.action != "UID_ATTACH"
            or scope.source_host == scope.target_host
            or not isinstance(ticket, ExecutionTicket)
            or ticket.scope_digest != _scope_digest(scope)
            or type(ingress_edge_id) is not str or not ingress_edge_id
            or ingress_edge_id == scope.edge_id
            or not all(callable(x) for x in
                       (db_conn, os_uid_for_username, source_evidence, geteuid))):
            raise RuntimeStoreUnsafe("K2_CROSS_EDGE_STORE_CONTRACT_INVALID")
        super().__init__(db_conn, os_uid_for_username, shared_edge_enabled=True)
        self.scope, self.ticket = scope, ticket
        self.ingress_edge_id = ingress_edge_id
        self.source_evidence, self.geteuid = source_evidence, geteuid
        self.reviewed_release = reviewed_release is True

    def _cross_gate(self, req: UIDPolicyRequest | None = None,
                    source: str | None = None) -> None:
        if (not K2_CROSS_EDGE_RUNTIME_STORE_ENABLED
            or not self.reviewed_release or self.geteuid() != 0):
            raise RuntimeStoreUnsafe("K2_CROSS_EDGE_STORE_NOT_RELEASED")
        if req is not None and (
            req.username != self.scope.username or req.uid != self.scope.uid
            or req.spec.edge_id != self.scope.edge_id
            or req.spec.edge_public_ipv4 != self.scope.target_host
            or source != self.scope.source_host
        ):
            raise RuntimeStoreUnsafe("K2_CROSS_EDGE_UID_SCOPE_CHANGED")

    def _lock(self, conn, op_id: int, source: str, target: str) -> None:
        from hashlib import sha256
        from hmac import compare_digest
        from edge_egress_p3_executor import INTENT_PHASE, _scope_digest
        import json
        self._cross_gate()
        super()._lock(conn, op_id, source, target)
        if source != self.scope.source_host or target != self.scope.target_host:
            raise RuntimeStoreUnsafe("K2_CROSS_EDGE_6G_SCOPE_CHANGED")
        row = conn.execute(
            "SELECT detail_json FROM failover_operations WHERE id=?", (op_id,)
        ).fetchone()
        try:
            detail = json.loads(row[0]) if row else None
        except (TypeError, ValueError):
            detail = None
        if (not isinstance(detail, dict)
            or detail.get("kind") != "K2_P3A"
            or detail.get("phase") != INTENT_PHASE
            or detail.get("action") != "UID_ATTACH"
            or detail.get("edge_id") != self.scope.edge_id
            or not isinstance(detail.get("scope_digest"), str)
            or not compare_digest(detail["scope_digest"], _scope_digest(self.scope))
            or not isinstance(detail.get("nonce_hash"), str)
            or not compare_digest(
                detail["nonce_hash"], sha256(self.ticket.nonce.encode("ascii")).hexdigest()
            )):
            raise RuntimeStoreUnsafe("K2_CROSS_EDGE_6G_INTENT_NOT_PINNED")
        mode = conn.execute(
            "SELECT value FROM settings WHERE key='edge_egress_protected_mode'"
        ).fetchone()
        if mode != ("0",):
            raise RuntimeStoreUnsafe("K2_LEGACY_GLOBAL_MODE_CHANGED")

    def _source_owner(self, conn, req: UIDPolicyRequest, source: str) -> None:
        from edge_egress_k2_m2_ingress_journal import RootReadOnlyIngressEvidence
        from edge_egress_v1_ingress import IngressPeer
        self._cross_gate(req, source)
        observed = self.source_evidence()
        if type(observed) is not RootReadOnlyIngressEvidence:
            raise RuntimeStoreUnsafe("K2_ROOT_SOURCE_EVIDENCE_REQUIRED")
        try:
            witness = observed(req.username)
        except (OSError, ValueError, KeyError, LookupError) as exc:
            raise RuntimeStoreUnsafe("K2_CURRENT_PAM_WG_SOURCE_INVALID") from exc
        if (witness.username != req.username
            or witness.edge_id != self.ingress_edge_id
            or witness.edge_ipv4 != source
            or sum(
                type(peer) is IngressPeer
                and peer.edge_id == self.ingress_edge_id
                and peer.edge_ipv4 == source
                for peer in observed.peers
            ) != 1):
            raise RuntimeStoreUnsafe("K2_INGRESS_NOT_INDEPENDENTLY_PINNED")
        # M1 treats ssh_accounts.host as historical metadata; only
        # authenticated root PAM journal and live wg0 can prove SSH ingress.
        # A different historical host must not veto real source evidence.
        # Require exactly one active SSH account; never rewrite its host.
        accounts = conn.execute(
            "SELECT host,service_type,status FROM ssh_accounts WHERE username=?",
            (req.username,),
        ).fetchall()
        if (len(accounts) != 1 or accounts[0][1] != "ssh"
            or not isinstance(accounts[0][2], str)
            or "فعال" not in accounts[0][2] or "غیر" in accounts[0][2]
            or (accounts[0][0] is not None
                and type(accounts[0][0]) is not str)):
            raise RuntimeStoreUnsafe("K2_LEGACY_ACCOUNT_CHANGED")

    def stage_pam_admission(self, req: UIDPolicyRequest, *,
                            source: str) -> None:
        """Original P3 calls this after packet evidence, before F2 commit.

        The persistent cross-ingress PAM policy must reference the future F2
        PROTECTED CAS generation, not an early BLOCKED/UNVERIFIED state.
        """
        from edge_egress_k2_uid_ingress_egress import stage_6g_cross_edge_binding
        self._cross_gate(req, source)
        stage_6g_cross_edge_binding(
            db_conn=self.db_conn, scope=self.scope, ticket=self.ticket,
            source_evidence=self.source_evidence, geteuid=self.geteuid,
            release_enabled=True,
        )
