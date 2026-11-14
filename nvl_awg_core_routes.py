"""Fail-closed Core AWG /32 routes: live peer admission and boot reconciliation.

Adding a peer with 'awg set' does not add a Linux route. Neither this module
nor its systemd oneshot restarts AWG, writes DNS, or changes customer records.
"""
from __future__ import annotations

import argparse
import fcntl
import ipaddress
import os
from pathlib import Path
import sqlite3
import subprocess
import sys


class AWGRouteHold(RuntimeError):
    pass


LOCK = "/run/lock/nvl-awg-core-peer.lock"


def _ips(edge, core):
    try:
        edge, core = ipaddress.IPv4Address(edge), ipaddress.IPv4Address(core)
        if edge == core or edge not in ipaddress.IPv4Network(str(core) + "/24", strict=False):
            raise ValueError()
        return str(edge), str(core)
    except (TypeError, ValueError):
        raise AWGRouteHold("AWG_CORE_ROUTE_ADDRESS_INVALID") from None


def _run(runner, argv):
    try:
        result = runner(argv, capture_output=True, text=True, timeout=8)
        if (result.returncode != 0 or not isinstance(result.stdout, str)
                or len(result.stdout) > 8192):
            raise AWGRouteHold("AWG_CORE_ROUTE_COMMAND_FAILED")
        return result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        raise AWGRouteHold("AWG_CORE_ROUTE_COMMAND_FAILED") from None


def _owned_line(edge, core, runner):
    lines = _run(runner, ["ip", "-4", "route", "show", "table",
                          "main", "exact", edge + "/32"]).splitlines()
    if not lines:
        return False
    if len(lines) != 1:
        raise AWGRouteHold("AWG_CORE_ROUTE_CONFLICT")
    fields = lines[0].split()
    if (fields[0] not in (edge, edge + "/32") or "via" in fields
            or "dev" not in fields or
            fields[fields.index("dev") + 1:fields.index("dev") + 2] != ["awg0"]
            or ("src" in fields and
                fields[fields.index("src") + 1:fields.index("src") + 2] != [core])):
        raise AWGRouteHold("AWG_CORE_ROUTE_CONFLICT")
    return True


def verify_core_route(edge, core, *, runner=subprocess.run):
    """Check BOTH exact /32 route ownership and a normal from-Core lookup."""
    edge, core = _ips(edge, core)
    if not _owned_line(edge, core, runner):
        raise AWGRouteHold("AWG_CORE_ROUTE_MISSING")
    result = _run(runner, ["ip", "-4", "route", "get", edge, "from", core])
    first = result.splitlines()[0].split() if result else []
    if (not first or first[0] != edge or "via" in first
            or "dev" not in first or
            first[first.index("dev") + 1:first.index("dev") + 2] != ["awg0"]):
        raise AWGRouteHold("AWG_CORE_ROUTE_WRONG_DEVICE")
    return True


def remove_owned_core_route(edge, core, *, runner=subprocess.run):
    """For rollback ONLY when this transaction created the route."""
    edge, core = _ips(edge, core)
    if _owned_line(edge, core, runner):
        _run(runner, ["ip", "-4", "route", "del", edge + "/32", "dev", "awg0"])


def ensure_core_route(edge, core, *, runner=subprocess.run):
    """Add a missing /32 only; never replace unrelated or preexisting routes."""
    edge, core = _ips(edge, core)
    if _owned_line(edge, core, runner):
        verify_core_route(edge, core, runner=runner)
        return False
    try:
        _run(runner, ["ip", "-4", "route", "add", edge + "/32",
                      "dev", "awg0", "src", core])
    except AWGRouteHold:
        raise AWGRouteHold("AWG_CORE_ROUTE_ADD_FAILED") from None
    try:
        verify_core_route(edge, core, runner=runner)
    except Exception:
        try:
            remove_owned_core_route(edge, core, runner=runner)
        except Exception:
            raise AWGRouteHold("AWG_CORE_ROUTE_ROLLBACK_UNCERTAIN") from None
        raise AWGRouteHold("AWG_CORE_ROUTE_POSTCHECK_FAILED") from None
    return True


def reconcile_registered_routes(*, db_path="/root/master_bot.db",
                                runner=subprocess.run, root_check=os.geteuid,
                                lock_path=LOCK):
    """At boot, admit only VERIFIED DB peers whose exact /32 is live in AWG."""
    if root_check() != 0:
        raise AWGRouteHold("AWG_CORE_ROUTE_ROOT_REQUIRED")
    dbfile = Path(db_path)
    if dbfile.is_symlink() or not dbfile.is_file():
        raise AWGRouteHold("AWG_CORE_ROUTE_DB_UNAVAILABLE")
    lock = Path(lock_path)
    lock.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        live = _run(runner, ["awg", "show", "awg0", "allowed-ips"])
        peers = {}
        for line in live.splitlines():
            fields = line.split()
            if len(fields) != 2 or fields[0] in peers:
                raise AWGRouteHold("AWG_CORE_ROUTE_PEER_UNVERIFIED")
            peers[fields[0]] = fields[1]
        try:
            with sqlite3.connect("file:" + str(dbfile) + "?mode=ro",
                                 uri=True, timeout=5) as db:
                entries = db.execute(
                    "SELECT core_tunnel_ip,edge_tunnel_ip,peer_public_key "
                    "FROM edge_tunnel_bindings "
                    "WHERE backend='amneziawg' AND state='VERIFIED' "
                    "ORDER BY edge_tunnel_ip"
                ).fetchall()
        except sqlite3.Error:
            raise AWGRouteHold("AWG_CORE_ROUTE_DB_UNAVAILABLE") from None
        # Verify every peer first, then allow route creation.
        for core, edge, key in entries:
            edge, core = _ips(edge, core)
            if peers.get(key) != edge + "/32":
                raise AWGRouteHold("AWG_CORE_ROUTE_PEER_UNVERIFIED")
        for core, edge, _ in entries:
            ensure_core_route(edge, core, runner=runner)
        return len(entries)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ensure", action="store_true", required=True)
    parser.parse_args()
    try:
        count = reconcile_registered_routes()
    except AWGRouteHold as exc:
        print("AWG_CORE_ROUTES=HOLD " + str(exc), file=sys.stderr)
        return 2
    except Exception:
        print("AWG_CORE_ROUTES=HOLD UNEXPECTED_FAILURE", file=sys.stderr)
        return 2
    print("AWG_CORE_ROUTES=READY count=" + str(count))
    return 0


if __name__ == "__main__":
    sys.exit(main())
