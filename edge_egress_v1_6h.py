"""J: read-only 6H Egress switch gate for the EXISTING 6G/6H entrypoints.

Protected Core-terminated SSH must not use legacy 6G (DNS fallback to Core,
SSH account rebuild on standby). Current H is sticky UID-to-Edge, not
per-session routing: moving global ingress while UID is pinned is unsafe.

This module returns precise HOLD states, NEVER authorizes the legacy switch,
and never changes routes, DNS, SSH, customer mappings, or the 6G journal.
A separately reviewed 6G-locked guarded handoff adapter and K acceptance
must exist before any positive protected cutover may run.
"""
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address
import sqlite3

from edge_egress_f3_readiness import admission_eligible, read_readiness
from edge_egress_lifecycle import _mode


@dataclass(frozen=True)
class SwitchGate:
    allowed_legacy: bool
    reason: str
    protected: bool
    edge_id: str | None = None
    pinned_users: int = 0
    target_ready: bool = False


HOLD_MODE = "EGRESS_J_MODE_INVALID"
HOLD_MISSING_SCHEMA = "EGRESS_J_SCHEMA_MISSING"
HOLD_TARGET_NOT_REGISTERED = "EGRESS_J_TARGET_INGRESS_UNVERIFIED"
HOLD_TARGET_NOT_READY = "EGRESS_J_TARGET_NOT_F4_READY"
HOLD_MAPPING_UNCERTAIN = "EGRESS_J_MAPPING_UNCERTAIN"
HOLD_PINNED = "EGRESS_J_PINNED_UIDS_REQUIRE_DRAIN_REBIND"
HOLD_NEEDS_EXECUTOR = "EGRESS_J_PROTECTED_6G_HANDOFF_NOT_RELEASED"


def _has_table(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def _read_protected(conn: sqlite3.Connection) -> tuple[int, int]:
    """Count every protected runtime intent and its durable mapping.

    A BLOCKED/FROZEN/HOLD UID is NOT a legacy user. Corrupt/mismatched schemas
    or a runtime row missing a PROTECTED mapping trigger HOLD, never downgrade.
    """
    if not _has_table(conn, "edge_egress_uid_runtime") or not _has_table(
        conn, "edge_egress_uid_bindings"
    ):
        raise ValueError(HOLD_MISSING_SCHEMA)
    runtime = conn.execute(
        "SELECT username,uid,edge_id,edge_ipv4,state "
        "FROM edge_egress_uid_runtime"
    ).fetchall()
    bindings = conn.execute(
        "SELECT username,uid,edge_id,edge_ipv4,status "
        "FROM edge_egress_uid_bindings"
    ).fetchall()
    rt = {(u, uid, eid, ipv4) for u, uid, eid, ipv4, _ in runtime}
    mapped = {(u, uid, eid, ipv4) for u, uid, eid, ipv4, _ in bindings}
    if len(rt) != len(runtime) or len(mapped) != len(bindings):
        raise ValueError(HOLD_MAPPING_UNCERTAIN)
    if not mapped.issubset(rt):
        raise ValueError(HOLD_MAPPING_UNCERTAIN)
    valid_states = {"BLOCKED", "ROUTED_UNVERIFIED", "PROTECTED", "FROZEN", "HOLD"}
    by_key = {(u, uid, eid, ipv4): state for u, uid, eid, ipv4, state in runtime}
    if any(state not in valid_states for state in by_key.values()):
        raise ValueError(HOLD_MAPPING_UNCERTAIN)
    if any(status != "PROTECTED" or by_key[(u, uid, eid, ipv4)] != "PROTECTED"
           for u, uid, eid, ipv4, status in bindings):
        raise ValueError(HOLD_MAPPING_UNCERTAIN)
    # Unmapped BLOCKED/ROUTED_UNVERIFIED intent still means a pinned UID;
    # only stable PROTECTED rows with matching binding may be considered settled.
    unsettled = sum(1 for key, state in by_key.items()
                    if state != "PROTECTED" or key not in mapped)
    return len(runtime), unsettled


def review_protected_switch(
    conn: sqlite3.Connection,
    *,
    source_host: str,
    target_host: str,
    now: int | None = None,
) -> SwitchGate:
    """Read-only decision for manual and automatic 6H switch attempts."""
    try:
        if (str(IPv4Address(source_host)) != source_host
                or str(IPv4Address(target_host)) != target_host
                or source_host == target_host):
            return SwitchGate(False, "EGRESS_J_INVALID_EDGE_PAIR", True)
        required = ("edge_egress_readiness", "edge_egress_f3_ingress_candidates",
                    "edge_egress_uid_runtime", "edge_egress_uid_bindings")
        if any(not _has_table(conn, name) for name in required):
            return SwitchGate(False, HOLD_MISSING_SCHEMA, True)
        candidate = conn.execute(
            "SELECT state FROM edge_egress_f3_ingress_candidates "
            "WHERE edge_ipv4=?", (target_host,)
        ).fetchone()
        if candidate != ("INGRESS_ONLY",):
            return SwitchGate(False, HOLD_TARGET_NOT_REGISTERED, True)
        matching = conn.execute(
            "SELECT edge_id FROM edge_egress_readiness WHERE edge_ipv4=?",
            (target_host,),
        ).fetchall()
        if len(matching) != 1:
            return SwitchGate(False, HOLD_TARGET_NOT_READY, True)
        edge_id = matching[0][0]
        ready = read_readiness(conn, edge_id)
        accepted = bool(ready and ready.edge_ipv4 == target_host
                        and admission_eligible(ready, now=now))
        if not accepted:
            return SwitchGate(False, HOLD_TARGET_NOT_READY, True, edge_id)
        protected, unsettled = _read_protected(conn)
        if unsettled:
            return SwitchGate(False, HOLD_MAPPING_UNCERTAIN, True,
                              edge_id, protected, True)
        if protected:
            return SwitchGate(False, HOLD_PINNED, True,
                              edge_id, protected, True)
        # A READY record cannot authorize a legacy DNS->Core fallback.
        return SwitchGate(False, HOLD_NEEDS_EXECUTOR, True, edge_id, 0, True)
    except (ValueError, sqlite3.DatabaseError):
        return SwitchGate(False, HOLD_MAPPING_UNCERTAIN, True)


def evaluate_j_switch(
    db_conn,
    protected_setting: str | None,
    source_host: str,
    target_host: str,
    *,
    now: int | None = None,
) -> SwitchGate:
    """A single gate; no setting flips from HOLD into legacy positive path."""
    mode = _mode(protected_setting)
    if mode == "0":
        # Normal legacy still needs all its existing preflights and fences.
        return SwitchGate(True, "LEGACY_6G_PREFLIGHT_REQUIRED", False)
    if mode != "1":
        return SwitchGate(False, HOLD_MODE, True)
    try:
        with db_conn() as conn:
            return review_protected_switch(
                conn, source_host=source_host, target_host=target_host, now=now
            )
    except (OSError, sqlite3.Error, ValueError):
        return SwitchGate(False, HOLD_MAPPING_UNCERTAIN, True)
