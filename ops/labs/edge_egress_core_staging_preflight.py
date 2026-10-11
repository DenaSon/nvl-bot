#!/usr/bin/env python3
"""D1-D2A: read-only Core production host staging suitability audit.

NO shell, writes, unit modifications, NS creation, database updates, network
changes or SSH calls. Reads local state only and prints a redacted JSON report.
Designed for the existing NVL Core while production remains online.

For D1-D2B, the reviewed candidate is: stg1; 10.78.110.0/30 tunnel,
10.78.111.0/30 veth, local rule priority 1790, table 1790, tentative
standby UDP port 51842. This tool MUST NOT activate these resources.

The Core report cannot replace a separate read-only Standby Edge audit.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import sqlite3
import subprocess
from typing import Callable

EDGE_ID = "stg1"
STAGING_IFACE = "wg-nvl-stg1"
STAGING_NS = "nvl-egress-stg1"
STAGING_VETH = "vnh-stg1"
STAGING_PEER = "vnn-stg1"
STAGING_USER = "nvlstg1"
TUNNEL = ipaddress.ip_network("10.78.110.0/30")
VETH = ipaddress.ip_network("10.78.111.0/30")
ROUTE_TABLE = 1790
RULE_PRIORITY = 1790
STANDBY_UDP_PORT = 51842
PROTECTED_IFACES = frozenset({"wg0", "eth0"})
RUN_TIMEOUT = 8


class PreflightError(RuntimeError):
    pass


def _probe(args: tuple[str, ...]) -> tuple[int, str]:
    proc = subprocess.run(list(args), text=True, capture_output=True,
                          check=False, timeout=RUN_TIMEOUT)
    return proc.returncode, proc.stdout


def _json_probe(args: tuple[str, ...], probe: Callable) -> list[dict]:
    code, output = probe(args)
    if code != 0:
        raise PreflightError("PROBE_FAILED:" + " ".join(args[:3]))
    data = json.loads(output)
    if not isinstance(data, list):
        raise PreflightError("INVALID_PROBE_JSON")
    return data


def _db_state(path: Path) -> dict:
    """SQLite read-only URI; do not return account/host/credential details."""
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        return {"available": False}
    uri = path.as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=3) as conn:
        conn.execute("PRAGMA query_only=ON")
        names = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        result: dict = {"available": True,
                        "settings_table": "settings" in names,
                        "operations_table": "failover_operations" in names}
        if "settings" in names:
            row = conn.execute(
                "SELECT value FROM settings WHERE key='edge_egress_protected_mode'"
            ).fetchone()
            result["protected_mode"] = str(row[0]) if row else "0"
        if "failover_operations" in names:
            result["running_6g_operations"] = int(conn.execute(
                "SELECT count(*) FROM failover_operations WHERE status='RUNNING'"
            ).fetchone()[0])
        return result


def _network_conflicts(items: list[dict], issues: list[str]) -> None:
    for row in items:
        # Network already assigned to any interface or any routing table.
        for address in row.get("addr_info", []) or []:
            try:
                if address.get("family") == "inet":
                    host = ipaddress.ip_interface(
                        f"{address['local']}/{address['prefixlen']}").network
                    if host.overlaps(TUNNEL) or host.overlaps(VETH):
                        issues.append("ADDRESS_SUBNET_COLLISION")
            except (KeyError, ValueError, TypeError):
                issues.append("INVALID_ADDRESS_INVENTORY")


def evaluate_core(
    *, probe: Callable = _probe, db_reader: Callable = _db_state,
    username_lookup: Callable = pwd.getpwnam,
    db_path: Path = Path("/root/master_bot.db"),
) -> dict:
    """Offline/mockable read-only checks; never authorizes activation."""
    issues: list[str] = []
    warnings: list[str] = []
    observed: dict = {}
    tools = ("ip", "ss", "wg", "systemctl", "python3")
    missing = [cmd for cmd in tools if shutil.which(cmd) is None]
    if missing:
        issues.extend("TOOL_MISSING:" + x for x in missing)
        return _out(issues, warnings, {"missing_tools": missing})

    checks: dict[str, tuple[str, ...]] = {
        "interfaces": ("ip", "-j", "link", "show"),
        "addresses": ("ip", "-j", "-4", "addr", "show"),
        "routes": ("ip", "-j", "-4", "route", "show", "table", "all"),
        "rules": ("ip", "-4", "rule", "show"),
        "namespaces": ("ip", "netns", "list"),
        "udp_sockets": ("ss", "-H", "-lun"),
        "tcp_sockets": ("ss", "-H", "-ltn"),
        "wg_interfaces": ("wg", "show", "interfaces"),
        "bot_service": ("systemctl", "show", "nvlbot",
                        "-p", "ActiveState", "--no-pager"),
        "ssh_service": ("systemctl", "show", "ssh.service",
                        "-p", "ActiveState", "--no-pager"),
    }
    raw = {}
    for key, command in checks.items():
        try:
            code, stdout = probe(command)
            if code != 0:
                issues.append("PROBE_FAILED:" + key)
            else:
                raw[key] = stdout
        except (OSError, subprocess.TimeoutExpired, ValueError):
            issues.append("PROBE_FAILED:" + key)

    if any(k not in raw for k in checks):
        return _out(issues, warnings, observed)

    try:
        links = json.loads(raw["interfaces"])
        addrs = json.loads(raw["addresses"])
        routes = json.loads(raw["routes"])
        if not all(isinstance(x, list) for x in (links, addrs, routes)):
            raise ValueError("invalid network inventory")
    except (ValueError, TypeError):
        return _out(issues + ["INVALID_KERNEL_JSON"], warnings, observed)

    names = {r.get("ifname") for r in links if isinstance(r, dict)}
    # Interface/namespace labels are deliberately separate from C2 stages.
    for iface in (STAGING_IFACE, STAGING_VETH, STAGING_PEER):
        if iface in names:
            issues.append("STAGING_INTERFACE_OCCUPIED")
    namespaces = {line.split()[0] for line in raw["namespaces"].splitlines()
                  if line.strip()}
    if STAGING_NS in namespaces:
        issues.append("STAGING_NAMESPACE_OCCUPIED")

    _network_conflicts(addrs, issues)
    for route in routes:
        if not isinstance(route, dict):
            issues.append("INVALID_ROUTE_INVENTORY")
            continue
        if str(route.get("table", "main")) == str(ROUTE_TABLE):
            issues.append("STAGING_ROUTE_TABLE_OCCUPIED")
        dst = route.get("dst")
        if dst and dst != "default":
            try:
                prefix = ipaddress.ip_network(dst, strict=False)
                if isinstance(prefix, ipaddress.IPv4Network) and (
                    prefix.overlaps(TUNNEL) or prefix.overlaps(VETH)
                ):
                    issues.append("STAGING_ROUTE_SUBNET_COLLISION")
            except ValueError:
                issues.append("INVALID_ROUTE_PREFIX")

    rule_lines = raw["rules"].splitlines()
    for line in rule_lines:
        if re.match(r"^\s*" + str(RULE_PRIORITY) + r":", line):
            issues.append("STAGING_RULE_PRIORITY_OCCUPIED")
        if re.search(r"\blookup\s+" + str(ROUTE_TABLE) + r"(?:\s|$)", line):
            issues.append("STAGING_RULE_TABLE_REFERENCED")
    try:
        username_lookup(STAGING_USER)
        issues.append("STAGING_USERNAME_OCCUPIED")
    except KeyError:
        pass

    # Screen socket use without disclosing process names/IDs or service IPs.
    if re.search(rf":{STANDBY_UDP_PORT}(?=\s|$)", raw["udp_sockets"]):
        warnings.append("CORE_UDP_PORT_RESERVED_FOR_EDGE_USED_LOCALLY")
    if re.search(r":22282(?=\s|$)", raw["tcp_sockets"]):
        issues.append("STAGING_LOCAL_SSH_PORT_OCCUPIED")

    # These do not expose service details or baseline user traffic.
    observed["nvlbot_active"] = "ActiveState=active" in raw["bot_service"]
    observed["ssh_active"] = "ActiveState=active" in raw["ssh_service"]
    observed["wg0_present"] = "wg0" in raw["wg_interfaces"].split()
    observed["kernel_namespace_inventory"] = True
    if not observed["nvlbot_active"]:
        warnings.append("BOT_BASELINE_NOT_ACTIVE")
    if not observed["ssh_active"]:
        warnings.append("SSH_BASELINE_NOT_ACTIVE")
    if not observed["wg0_present"]:
        issues.append("PRODUCTION_WG0_BASELINE_MISSING")

    try:
        db = db_reader(db_path)
        observed["database"] = db
        if not db.get("available"):
            warnings.append("PRODUCTION_DB_NOT_READABLE")
        else:
            if db.get("protected_mode", "0") != "0":
                issues.append("GLOBAL_PROTECTED_MODE_NOT_OFF")
            if db.get("running_6g_operations", 0) != 0:
                issues.append("SHARED_6G_OPERATION_RUNNING")
    except (sqlite3.Error, OSError, ValueError):
        issues.append("DATABASE_READ_FAILED")

    return _out(issues, warnings, observed)


def _out(issues: list[str], warnings: list[str], observed: dict) -> dict:
    return {
        "phase": "D1-D2A",
        "mode": "READ_ONLY_PREFLIGHT",
        "candidate": {
            "edge_id": EDGE_ID,
            "core_namespace": STAGING_NS,
            "interface": STAGING_IFACE,
            "veth": STAGING_VETH,
            "test_username": STAGING_USER,
            "tunnel_cidr": str(TUNNEL),
            "veth_cidr": str(VETH),
            "rule_priority": RULE_PRIORITY,
            "route_table": ROUTE_TABLE,
            "standby_udp_port_tentative": STANDBY_UDP_PORT,
            "namespace_ssh_port_tentative": 22282,
        },
        "verdict": ("BLOCKED" if issues else "CORE_ONLY_CANDIDATE"),
        "issues": sorted(set(issues)),
        "warnings": sorted(set(warnings)),
        "observed": observed,
        "next_gate": "STANDBY_EDGE_PREFLIGHT_AND_OPERATOR_REVIEW",
        "activation_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=Path("/root/master_bot.db"))
    args = parser.parse_args()
    report = evaluate_core(db_path=args.db)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    # A WARN does not validate a live change. Explicit manual review needed.
    return 2 if report["verdict"] == "BLOCKED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
