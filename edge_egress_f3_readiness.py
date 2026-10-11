"""F3: separate evidence-backed Edge Egress readiness, never inferred from STAGED.

A successful disposable-namespace probe is VERIFIED_LAB, *not* READY.
F3 provides no READY promotion or customer assignment side effects. Only an
independent F4 acceptance migration/controller may authorize READY after
reboot, PAM, DNS/IPv6 and no-Core-leak evidence.

All writes require the SAME existing 6G RUNNING operation and transaction.
No changes to host_pool, ssh_accounts, public DNS, wg0 or Unix identities.
"""
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address
import sqlite3
import time


class ReadinessUnsafe(ValueError):
    pass


READINESS_SCHEMA = """
CREATE TABLE IF NOT EXISTS edge_egress_readiness (
  edge_id TEXT PRIMARY KEY,
  edge_ipv4 TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN
    ('STAGED','VERIFIED_LAB','READY','HOLD','REVOKED')),
  observed_ipv4 TEXT,
  witness TEXT,
  probed_at INTEGER,
  expires_at INTEGER,
  generation INTEGER NOT NULL DEFAULT 1 CHECK(generation >= 1),
  last_operation_id INTEGER NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_edge_egress_readiness_state
  ON edge_egress_readiness(state, expires_at);
CREATE TABLE IF NOT EXISTS edge_egress_f3_ingress_candidates (
  edge_ipv4 TEXT PRIMARY KEY,
  state TEXT NOT NULL DEFAULT 'INGRESS_ONLY'
     CHECK(state = 'INGRESS_ONLY'),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


def install_readiness_schema(conn: sqlite3.Connection) -> None:
    """Explicit migration only; no implicit invocation from the bot."""
    conn.executescript(READINESS_SCHEMA)


@dataclass(frozen=True)
class EdgeReadiness:
    edge_id: str
    edge_ipv4: str
    state: str
    observed_ipv4: str | None
    witness: str | None
    probed_at: int | None
    expires_at: int | None
    generation: int
    last_operation_id: int


def read_readiness(conn, edge_id: str) -> EdgeReadiness | None:
    row = conn.execute(
        "SELECT edge_id,edge_ipv4,state,observed_ipv4,witness,"
        "probed_at,expires_at,generation,last_operation_id "
        "FROM edge_egress_readiness WHERE edge_id=?", (edge_id,)
    ).fetchone()
    return EdgeReadiness(*row) if row else None


def _shared_lock(conn, operation_id: int, source: str, target: str) -> None:
    if type(operation_id) is not int or operation_id < 1 or source == target:
        raise ReadinessUnsafe("INVALID_SHARED_6G_OPERATION")
    row = conn.execute(
        "SELECT status,source_host,target_host FROM failover_operations "
        "WHERE id=?", (operation_id,)
    ).fetchone()
    if row != ("RUNNING", source, target):
        raise ReadinessUnsafe("SHARED_6G_LEASE_NOT_CURRENT")
    if conn.execute(
        "SELECT 1 FROM failover_operations WHERE status='RUNNING' "
        "AND id!=? LIMIT 1", (operation_id,)
    ).fetchone():
        raise ReadinessUnsafe("ANOTHER_6G_OPERATION_RUNNING")


@dataclass
class Existing6GReadinessStore:
    db_conn: object

    def _tx(self, operation_id, source, edge_id, target, mutation):
        with self.db_conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            _shared_lock(conn, operation_id, source, target)
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND "
                "name IN ('edge_egress_allocations','edge_egress_readiness')"
            ).fetchall()
            if len(tables) != 2:
                raise ReadinessUnsafe("READINESS_OR_ALLOCATION_MIGRATION_MISSING")
            allocation = conn.execute(
                "SELECT edge_public_ipv4,status FROM edge_egress_allocations "
                "WHERE edge_id=?", (edge_id,)
            ).fetchone()
            if allocation != (target, "STAGED"):
                raise ReadinessUnsafe("EXACT_STAGED_ALLOCATION_REQUIRED")
            result = mutation(conn)
            _shared_lock(conn, operation_id, source, target)
            return result

    def mark_staged(self, operation_id: int, *, source: str,
                    edge_id: str, target: str) -> EdgeReadiness:
        """Initial stage acknowledgement; never upgrades an existing row."""
        def save(conn):
            old = read_readiness(conn, edge_id)
            if old:
                if old.edge_ipv4 != target or old.state != "STAGED":
                    raise ReadinessUnsafe("EXISTING_READINESS_NOT_REUSABLE")
                return old
            conn.execute(
                "INSERT INTO edge_egress_readiness "
                "(edge_id,edge_ipv4,state,last_operation_id) "
                "VALUES(?,?,'STAGED',?)",
                (edge_id, target, operation_id),
            )
            return read_readiness(conn, edge_id)
        return self._tx(operation_id, source, edge_id, target, save)

    def record_lab_verification(self, operation_id: int, *, source: str,
                                edge_id: str, target: str,
                                observed_ip: str, now: int | None = None,
                                ttl_seconds: int = 900) -> EdgeReadiness:
        """Only exact independently observed public IPv4 can mark VERIFIED_LAB."""
        if type(ttl_seconds) is not int or not 60 <= ttl_seconds <= 3600:
            raise ReadinessUnsafe("INVALID_LAB_EVIDENCE_TTL")
        try:
            if str(IPv4Address(observed_ip)) != target:
                raise ReadinessUnsafe("EDGE_EGRESS_IP_MISMATCH")
        except ValueError as exc:
            raise ReadinessUnsafe("INVALID_OR_MISMATCHED_IPV4") from exc
        stamp = int(time.time()) if now is None else now
        if type(stamp) is not int or stamp <= 0:
            raise ReadinessUnsafe("INVALID_EVIDENCE_TIMESTAMP")

        def save(conn):
            old = read_readiness(conn, edge_id)
            if not old or old.edge_ipv4 != target or old.state not in (
                "STAGED", "VERIFIED_LAB"
            ):
                raise ReadinessUnsafe("STALE_OR_UNSAFE_READINESS_TRANSITION")
            updated = conn.execute(
                "UPDATE edge_egress_readiness SET state='VERIFIED_LAB',"
                "observed_ipv4=?,witness='PINNED_SHADOW_NAMESPACE',"
                "probed_at=?,expires_at=?,generation=generation+1,"
                "last_operation_id=?,updated_at=CURRENT_TIMESTAMP "
                "WHERE edge_id=? AND generation=? AND state=?",
                (observed_ip, stamp, stamp + ttl_seconds, operation_id,
                 edge_id, old.generation, old.state),
            ).rowcount
            if updated != 1:
                raise ReadinessUnsafe("READINESS_COMPARE_AND_SWAP_LOST")
            return read_readiness(conn, edge_id)
        return self._tx(operation_id, source, edge_id, target, save)

    def hold(self, operation_id: int, *, source: str, edge_id: str,
             target: str) -> EdgeReadiness:
        """Uncertain network cleanup revokes evidence and retains 6G hold."""
        def save(conn):
            old = read_readiness(conn, edge_id)
            if not old or old.edge_ipv4 != target:
                raise ReadinessUnsafe("NO_OWNED_READINESS_TO_HOLD")
            conn.execute(
                "UPDATE edge_egress_readiness SET state='HOLD',"
                "observed_ipv4=NULL,witness=NULL,probed_at=NULL,expires_at=NULL,"
                "generation=generation+1,last_operation_id=?,"
                "updated_at=CURRENT_TIMESTAMP WHERE edge_id=?",
                (operation_id, edge_id),
            )
            return read_readiness(conn, edge_id)
        return self._tx(operation_id, source, edge_id, target, save)



def stage_in_existing_6g_transaction(conn, operation_id: int, *,
                                     source: str, edge_id: str,
                                     target: str) -> None:
    """Use INSIDE Existing6GPreparationAdapter's STAGED allocation write.

    The caller already owns BEGIN IMMEDIATE; never open another connection or
    acquire a second lock. If F3 migration was not installed, staging keeps
    its old stage-only behavior and cannot become verified/customer ready.
    """
    _shared_lock(conn, operation_id, source, target)
    if not conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' "
        "AND name='edge_egress_readiness'"
    ).fetchone():
        return
    existing = read_readiness(conn, edge_id)
    if existing is not None:
        raise ReadinessUnsafe("EXISTING_READINESS_REQUIRES_RECONCILIATION")
    allocation = conn.execute(
        "SELECT edge_public_ipv4,status FROM edge_egress_allocations "
        "WHERE edge_id=?", (edge_id,),
    ).fetchone()
    if allocation != (target, "STAGED"):
        raise ReadinessUnsafe("EXACT_STAGED_ALLOCATION_REQUIRED")
    conn.execute(
        "INSERT INTO edge_egress_readiness "
        "(edge_id,edge_ipv4,state,last_operation_id) "
        "VALUES(?,?,'STAGED',?)", (edge_id, target, operation_id),
    )


def record_ingress_candidate(db_conn, edge_ipv4: str) -> bool:
    """After successful legacy ingress onboarding: record intent only.

    Never reserve Egress resources, change Edge or claim WireGuard data-plane
    readiness. Missing F3 migration retains existing legacy onboarding.
    """
    try:
        canonical = str(IPv4Address(edge_ipv4))
        if canonical != edge_ipv4 or not IPv4Address(canonical).is_global:
            raise ReadinessUnsafe("INVALID_INGRESS_IP")
    except ValueError as exc:
        raise ReadinessUnsafe("INVALID_INGRESS_IP") from exc
    with db_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='edge_egress_f3_ingress_candidates'"
        ).fetchone()
        if not exists:
            return False
        host = conn.execute(
            "SELECT active FROM host_pool WHERE host=?", (edge_ipv4,)
        ).fetchone()
        if host is None or host[0] != 1:
            raise ReadinessUnsafe("INGRESS_HOST_NOT_ACTIVE")
        conn.execute(
            "INSERT OR IGNORE INTO edge_egress_f3_ingress_candidates "
            "(edge_ipv4,state) VALUES(?,'INGRESS_ONLY')", (edge_ipv4,),
        )
        return True

def admission_eligible(row: EdgeReadiness | None, *, now: int | None = None) -> bool:
    """F4 ONLY: READY + fresh production attestation; LAB never admits."""
    clock = int(time.time()) if now is None else now
    return bool(row and row.state == "READY"
                and row.witness == "F4_PRODUCTION_ACCEPTANCE"
                and row.observed_ipv4 == row.edge_ipv4
                and row.probed_at is not None and row.expires_at is not None
                and row.probed_at <= clock < row.expires_at)


def assignment_preview(conn, username: str, edge_id: str, *,
                       now: int | None = None) -> dict:
    """Read-only admin preview, not reservation or assignment."""
    if not isinstance(username, str) or not isinstance(edge_id, str):
        raise ReadinessUnsafe("INVALID_PREVIEW_INPUT")
    row = conn.execute(
        "SELECT service_type,status FROM ssh_accounts WHERE username=?",
        (username,),
    ).fetchone()
    readiness = read_readiness(conn, edge_id)
    if row is None or row[0] != "ssh" or not isinstance(row[1], str) or (
        "فعال" not in row[1] or "غیر" in row[1]
    ):
        return {"eligible": False, "reason": "SSH_USER_NOT_ACTIVE"}
    if not readiness:
        return {"eligible": False, "reason": "EDGE_READINESS_UNKNOWN"}
    if readiness.state == "VERIFIED_LAB":
        return {"eligible": False, "reason": "LAB_PROOF_NOT_CUSTOMER_READY"}
    if not admission_eligible(readiness, now=now):
        return {"eligible": False, "reason": "F4_PRODUCTION_EVIDENCE_REQUIRED"}
    # Even if ready, this F3 preview DOES NOT authorize a live assignment:
    # F4 must verify per-account PAM/reboot/UID gate and hold the 6G lease.
    return {"eligible": False, "reason": "F4_UID_GATE_AND_CUTOVER_REQUIRED"}
