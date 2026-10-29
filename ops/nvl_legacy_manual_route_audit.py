#!/usr/bin/env python3
"""Read-only production audit for the EXISTING Legacy manual Edge/IP workflow.

No Telegram WebApp, new HTTPS domain, Cloudzy purchase, feature flag or writes.
This is diagnostic evidence only, NOT a migration or DNS acceptance tool.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import ipaddress
import json
from pathlib import Path
import socket
import sqlite3
from urllib.parse import quote


def _table_exists(db, table):
    return bool(db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone())


def _ipv4(value):
    try:
        return str(ipaddress.IPv4Address(str(value or "").strip()))
    except ValueError:
        return None


def audit(db_path, *, resolve_dns=False, resolver=None):
    """Immutable observation of routing metadata; NEVER changes a live ledger."""
    path = Path(db_path).absolute()
    uri = "file:" + quote(str(path), safe="/") + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, timeout=5)) as db:
        if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("SQLITE_QUICK_CHECK_FAILED")
        settings = dict(db.execute(
            "SELECT key,value FROM settings WHERE key IN "
            "('hosts','dns_current_ip','public_domain','tls_domain','tls_passthrough')"
        ).fetchall())
        defaults = db.execute(
            "SELECT host,active,is_standby,service_port "
            "FROM host_pool WHERE is_default=1"
        ).fetchall()
        failures, warnings = [], []
        default = defaults[0] if len(defaults) == 1 else None
        if default is None:
            failures.append("DEFAULT_RELAY_NOT_UNIQUE")
        elif (_ipv4(default[0]) != default[0] or
              int(default[1] or 0) != 1 or
              int(default[2] or 0) != 0 or
              not 1 <= int(default[3] or 0) <= 65535):
            failures.append("DEFAULT_RELAY_NOT_ELIGIBLE")
        host = default[0] if default else None
        actual_dns = settings.get("dns_current_ip")
        if host and actual_dns != host:
            failures.append("CACHED_DNS_DEFAULT_MISMATCH")
        hosts = [s.strip() for s in (settings.get("hosts") or "").split(",") if s.strip()]
        if host and (not hosts or hosts[0] != host):
            failures.append("HOST_PICKER_DEFAULT_MISMATCH")
        if len(hosts) != len(set(hosts)):
            warnings.append("HOST_PICKER_DUPLICATE")
        counts = db.execute(
            "SELECT host, COUNT(*) FROM ssh_accounts "
            "WHERE service_type='ssh' AND status LIKE '%فعال%' "
            "AND status NOT LIKE '%غیر%' "
            "GROUP BY host ORDER BY host"
        ).fetchall()
        mapped = {h or "(unassigned)": count for h, count in counts}
        pending = []
        if _table_exists(db, "cloudzy_cz07_jobs"):
            pending = [
                {"id": row[0], "status": row[1], "target": row[2]}
                for row in db.execute(
                    "SELECT id,status,target FROM cloudzy_cz07_jobs "
                    "WHERE status NOT IN ('DONE','ABORTED','MOVED') "
                    "ORDER BY updated_at DESC LIMIT 10"
                ).fetchall()
            ]
            if pending:
                # A DIFFERENT historic job must never be represented as
                # successful or silently cleared by this audit.
                warnings.append("UNRESOLVED_MIGRATION_REVIEW_SEPARATELY")
        domains = []
        if resolve_dns:
            resolve = resolver or socket.getaddrinfo
            names = [settings.get("public_domain")]
            if settings.get("tls_passthrough") == "1":
                names.append(settings.get("tls_domain"))
            for name in dict.fromkeys(n for n in names if n):
                try:
                    addresses = sorted({
                        row[4][0] for row in resolve(
                            name, None, family=socket.AF_INET,
                            type=socket.SOCK_STREAM
                        )
                    })
                except (socket.gaierror, OSError):
                    addresses = []
                    warnings.append("PUBLIC_DNS_LOOKUP_UNAVAILABLE")
                if host and addresses and host not in addresses:
                    warnings.append("PUBLIC_DNS_DEFAULT_MISMATCH")
                domains.append({"name":name,"a_records":addresses})
        return {
            "mode":"READ_ONLY_LEGACY_MANUAL",
            "ready_metadata":not failures,
            "default_edge":host,
            "customer_port":int(default[3]) if default else None,
            "cached_dns":actual_dns,
            "picker_hosts":hosts,
            "active_ssh_by_host":mapped,
            "unresolved_jobs":pending,
            "public_dns":domains,
            "failures":sorted(set(failures)),
            "warnings":sorted(set(warnings)),
        }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="/root/master_bot.db")
    parser.add_argument(
        "--dns", action="store_true",
        help="Also resolve public DNS A records (informational, not Cloudflare API proof)"
    )
    args = parser.parse_args(argv)
    try:
        result = audit(args.db, resolve_dns=args.dns)
    except (OSError, sqlite3.Error, ValueError) as exc:
        print(json.dumps({"mode":"READ_ONLY_LEGACY_MANUAL",
                          "error":type(exc).__name__},
                         ensure_ascii=False))
        return 3
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["ready_metadata"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
