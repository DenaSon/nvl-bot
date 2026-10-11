"""D1-C2B: SQLite reservation registry for future per-Edge Egress ownership.

No ssh, iptables, WireGuard, DNS, bot account or host_pool operations.
This module writes only its OWN allocation table when explicitly called.
The existing NVL production bot does not call it; default feature remains OFF.

Reservations are append-only: a filtered/replaced Edge gets a new ID and
tunnel/veth/route-table allocation. No key reuse or silent reassign to another
IP. No private keys are stored. Activation/verification are NOT exposed here.
"""
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Network
from typing import Optional
import sqlite3

from ops.edge_egress_provision import EgressSpec, ProvisionError, validated_key


SCHEMA = """
CREATE TABLE IF NOT EXISTS edge_egress_allocations (
    edge_id TEXT PRIMARY KEY,
    edge_public_ipv4 TEXT NOT NULL UNIQUE,
    core_public_ipv4 TEXT NOT NULL,
    tunnel_network TEXT NOT NULL UNIQUE,
    veth_network TEXT NOT NULL UNIQUE,
    route_table INTEGER NOT NULL UNIQUE,
    edge_listen_port INTEGER NOT NULL,
    edge_uplink TEXT NOT NULL,
    core_public_key TEXT NOT NULL,
    edge_public_key TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'RESERVED'
        CHECK(status IN ('RESERVED', 'STAGED', 'RETIRED')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


class AllocationConflict(ValueError):
    pass


@dataclass(frozen=True)
class EdgeReservation:
    edge_id: str
    edge_ip: str
    tunnel_network: str
    veth_network: str
    route_table: int
    status: str
    created: bool


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Migration only. In PR #80 there is no automatic Production invocation."""
    conn.executescript(SCHEMA)


def _row(conn: sqlite3.Connection, edge_id: str):
    return conn.execute(
        "SELECT edge_public_ipv4, core_public_ipv4, tunnel_network, veth_network, "
        "route_table, edge_listen_port, edge_uplink, core_public_key, "
        "edge_public_key, status "
        "FROM edge_egress_allocations WHERE edge_id=?",
        (edge_id,),
    ).fetchone()


def reserve_allocation(
    conn: sqlite3.Connection, spec: EgressSpec, *,
    core_public_key: str, edge_public_key: str,
) -> EdgeReservation:
    """Reserve only after external caller has acquired existing 6G lock.

    Calling code MUST use SQLite BEGIN IMMEDIATE or equivalent serialisation
    before invoking this function. The function must never be used as a second
    failover lock. It does not commit and can be rolled back with its caller.
    """
    if not conn.in_transaction:
        raise AllocationConflict("SHARED_TRANSACTION_REQUIRED")
    spec.validate()
    core_key = validated_key(core_public_key, "core_public_key")
    edge_key = validated_key(edge_public_key, "edge_public_key")
    if core_key == edge_key:
        raise AllocationConflict("REUSED_WG_PUBLIC_KEY")
    current = _row(conn, spec.edge_id)
    fields = (
        spec.edge_public_ipv4, spec.core_public_ipv4, spec.tunnel_network,
        spec.veth_network, spec.route_table, spec.edge_listen_port,
        spec.edge_uplink, core_key, edge_key,
    )
    if current:
        if tuple(current[:9]) != fields:
            raise AllocationConflict("EDGE_ID_IMMUTABLE_RESERVATION")
        if current[9] == "RETIRED":
            raise AllocationConflict("RETIRED_EDGE_ID_MUST_NOT_BE_REUSED")
        return EdgeReservation(
            spec.edge_id, spec.edge_public_ipv4, spec.tunnel_network,
            spec.veth_network, spec.route_table, current[9], False,
        )

    # ip_network string equality alone cannot detect cross-overlaps between
    # tunnel and veth resources belonging to different Edges.
    existing = conn.execute(
        "SELECT edge_id, edge_public_ipv4, tunnel_network, veth_network, "
        "route_table, core_public_key, edge_public_key "
        "FROM edge_egress_allocations"
    ).fetchall()
    for edge_id, ip, tunnel, veth, route_table, cpub, epub in existing:
        if ip == spec.edge_public_ipv4:
            raise AllocationConflict(f"EDGE_IP_ALREADY_RESERVED:{edge_id}")
        if route_table == spec.route_table:
            raise AllocationConflict(f"ROUTE_TABLE_ALREADY_RESERVED:{edge_id}")
        if core_key in (cpub, epub) or edge_key in (cpub, epub):
            raise AllocationConflict(f"WIREGUARD_PUBLIC_KEY_REUSE:{edge_id}")
        for other in (IPv4Network(tunnel), IPv4Network(veth)):
            if other.overlaps(spec.tunnel) or other.overlaps(spec.veth):
                raise AllocationConflict(f"NETWORK_SUBNET_COLLISION:{edge_id}")

    try:
        conn.execute(
            "INSERT INTO edge_egress_allocations "
            "(edge_id, edge_public_ipv4, core_public_ipv4, tunnel_network, "
            "veth_network, route_table, edge_listen_port, edge_uplink, "
            "core_public_key, edge_public_key) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (spec.edge_id, *fields),
        )
    except sqlite3.IntegrityError as exc:
        raise AllocationConflict("CONCURRENT_EDGE_ALLOCATION_COLLISION") from exc
    return EdgeReservation(
        spec.edge_id, spec.edge_public_ipv4, spec.tunnel_network,
        spec.veth_network, spec.route_table, "RESERVED", True,
    )


def mark_stage_only(
    conn: sqlite3.Connection, edge_id: str, *,
    expected_status: str = "RESERVED",
) -> None:
    """Only a staged-file acknowledgement; NOT proof that the Edge is live."""
    if not conn.in_transaction:
        raise AllocationConflict("SHARED_TRANSACTION_REQUIRED")
    if expected_status not in ("RESERVED", "STAGED"):
        raise AllocationConflict("INVALID_EXPECTED_STATUS")
    cur = conn.execute(
        "UPDATE edge_egress_allocations SET status='STAGED', "
        "updated_at=CURRENT_TIMESTAMP WHERE edge_id=? AND status=?",
        (edge_id, expected_status),
    )
    if cur.rowcount != 1:
        raise AllocationConflict("STALE_OR_UNKNOWN_EDGE_RESERVATION")
