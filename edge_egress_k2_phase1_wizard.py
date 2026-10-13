"""K2 Phase 1: isolated new-Edge wizard admission.

The integrated Telegram wizard is allowed to stage a NEW Ingress/Egress Edge
without enrolling it into the Legacy active customer host pool. It does not
change existing SSH user hosts, public DNS, routing or automatic failover.
This is a conservative read-only admission check, NOT customer/transport release.
"""
from __future__ import annotations

from ipaddress import IPv4Address
import sqlite3


class K2WizardHold(ValueError):
    """Stop before remote provisioning when a candidate is unsafe."""


def _table(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def assert_isolated_new_edge_candidate(db_conn, edge_ip: str,
                                       customer_port: int) -> None:
    """Check once before any remote side effect, again after Stage publication.

    Protected users on OTHER Edge IPs are not a reason to mutate or unprotect
    them. The wizard remains isolated: no active host-pool registration, no
    domain/host changes. A competing 6G operation or reused IP always HOLDS.
    """
    try:
        ip = IPv4Address(edge_ip)
    except (TypeError, ValueError) as exc:
        raise K2WizardHold("INVALID_EDGE_IP") from exc
    if str(ip) != edge_ip or not ip.is_global:
        raise K2WizardHold("INVALID_EDGE_IP")
    if type(customer_port) is not int or not 1 <= customer_port <= 65535:
        raise K2WizardHold("INVALID_CUSTOMER_PORT")

    try:
        with db_conn() as conn:
            if not all(_table(conn, name) for name in (
                "host_pool", "settings", "failover_operations",
            )):
                raise K2WizardHold("CORE_CONTROL_SCHEMA_UNAVAILABLE")
            if conn.execute(
                "SELECT 1 FROM failover_operations WHERE status='RUNNING' LIMIT 1"
            ).fetchone():
                raise K2WizardHold("SHARED_6G_OPERATION_BUSY")
            if conn.execute(
                "SELECT 1 FROM host_pool WHERE host=?", (edge_ip,)
            ).fetchone():
                raise K2WizardHold("EDGE_ALREADY_IN_HOST_POOL")
            if (_table(conn, "edge_egress_allocations") and conn.execute(
                "SELECT 1 FROM edge_egress_allocations "
                "WHERE edge_public_ipv4=?", (edge_ip,)
            ).fetchone()):
                raise K2WizardHold("EGRESS_ALLOCATION_EXISTS")
            if (_table(conn, "edge_egress_f3_ingress_candidates") and
                    conn.execute(
                        "SELECT 1 FROM edge_egress_f3_ingress_candidates "
                        "WHERE edge_ipv4=?", (edge_ip,)
                    ).fetchone()):
                raise K2WizardHold("INGRESS_ALREADY_REGISTERED")
    except sqlite3.Error as exc:
        raise K2WizardHold("CORE_DATABASE_UNAVAILABLE") from exc
