"""Pending-only Legacy IP inventory registration, with no network/route effects.

An address supplied via Telegram is NEVER evidence of a configured Relay.
New IPs enter host_pool inactive; client-facing default, Cloudflare, account
assignments and WireGuard remain untouched. Existing route safety fences apply.
"""
from __future__ import annotations

from datetime import datetime
from ipaddress import IPv4Address
import sqlite3


class PendingEdgeHold(ValueError):
    pass


def register_pending_edge(factory, ip, *, guard, clock=None):
    """Register exactly one new publicly-routable IPv4 as inactive inventory.

    Atomic uniqueness and protected-mode checks are done in the SAME
    transaction. Never mutates an existing record or active customer route.
    """
    if not isinstance(ip, str) or ip.strip() != ip:
        raise PendingEdgeHold("INVALID_PUBLIC_IPV4")
    try:
        addr = IPv4Address(ip)
    except (ValueError, TypeError) as exc:
        raise PendingEdgeHold("INVALID_PUBLIC_IPV4") from exc
    if str(addr) != ip or not addr.is_global:
        raise PendingEdgeHold("INVALID_PUBLIC_IPV4")
    when = (clock or datetime.now)().strftime("%Y-%m-%d %H:%M:%S")
    with factory() as db:
        db.execute("BEGIN IMMEDIATE")
        guard(db)  # Existing, authoritative protected-host mutation fence.
        cfg = dict(db.execute(
            "SELECT key,value FROM settings WHERE key IN "
            "('core_wg_public_ip','dns_current_ip','hosts','port')"
        ).fetchall())
        core = cfg.get("core_wg_public_ip")
        if not core:
            raise PendingEdgeHold("CORE_IDENTITY_UNAVAILABLE")
        if ip == core:
            raise PendingEdgeHold("CORE_CANNOT_BE_EDGE")
        # An already-adopted Edge must never be reclassified or rewritten.
        if db.execute("SELECT 1 FROM host_pool WHERE host=?", (ip,)).fetchone():
            raise PendingEdgeHold("EDGE_ALREADY_REGISTERED")
        if db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='manual_edge_operations' "
            "AND type='table'"
        ).fetchone() and db.execute(
            "SELECT 1 FROM manual_edge_operations "
            "WHERE ip=? AND status!='CANCELLED' LIMIT 1",(ip,)
        ).fetchone():
            raise PendingEdgeHold("MANUAL_EDGE_OPERATION_EXISTS")
        if db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='cloudzy_edge_operations' "
            "AND type='table'"
        ).fetchone() and db.execute(
            "SELECT 1 FROM cloudzy_edge_operations WHERE public_ipv4=? "
            "AND status NOT IN ('CANCELLED','REJECTED') LIMIT 1",(ip,)
        ).fetchone():
            raise PendingEdgeHold("CLOUDZY_EDGE_ALREADY_EXISTS")
        try:
            port=int(cfg.get("port") or 2252)
        except (TypeError,ValueError) as exc:
            raise PendingEdgeHold("CUSTOMER_PORT_INVALID") from exc
        if not 1<=port<=65535:
            raise PendingEdgeHold("CUSTOMER_PORT_INVALID")
        # Only inventory insertion. Explicitly inactive, non-default and not
        # Standby, because no independently verified SSH/WG/NAT proof exists.
        try:
            db.execute(
                "INSERT INTO host_pool "
                "(host,active,is_default,is_standby,added_at,"
                "ssh_port,service_port,admin_ssh_port) "
                "VALUES (?,0,0,0,?,?,?,22)",
                (ip,when,port,port)
            )
        except sqlite3.IntegrityError as exc:
            raise PendingEdgeHold("EDGE_ALREADY_REGISTERED") from exc
    return {"ip":ip,"service_port":port,"status":"INVENTORY_PENDING"}
