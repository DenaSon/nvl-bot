"""F4 production Core preflight (read-only): inventory, locks, PAM, services.

This command NEVER adds ip rules, writes SQLite, installs PAM, touches wg0,
restarts ssh/nvlbot, migrates a UID or promotes Edge to READY. A reported
preflight success would STILL NOT replace a disposable full-VM reboot and
real SSH/SOCKS + DNS/IPv6 packet proof.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from ipaddress import IPv4Address
import re
import os
from pathlib import Path
import pwd
import sqlite3
import subprocess

from edge_egress_f4_pam import inspect_pam_sshd, verify_installed_gate_digest


@dataclass(frozen=True)
class CorePreflight:
    safe_to_consider: bool
    blockers: tuple[str,...]
    customer_ready: bool = False


def examine_core(conn: sqlite3.Connection, *, username: str,
                 uid: int, source_ip: str, edge_id: str,
                 expected_edge_ip: str, pam_text: str,
                 sshd_effective: str, ssh_active: bool,
                 bot_active: bool, os_uid: int,
                 gate_digest_verified: bool = False) -> CorePreflight:
    errors=[]
    if username != "nvl0557" and not username.startswith("nvl"):
        errors.append("UNREVIEWED_USERNAME")
    if type(uid) is not int or type(os_uid) is not int or uid != os_uid:
        errors.append("OS_UID_MISMATCH")
    if not ssh_active or not bot_active:
        errors.append("PRODUCTION_SSH_OR_BOT_UNHEALTHY")
    pam=inspect_pam_sshd(pam_text,sshd_effective,protected_username=username)
    errors.extend(pam.issues)
    if not gate_digest_verified:
        errors.append("PAM_GATE_SHA256_OR_ROOT_OWNERSHIP_UNVERIFIED")
    try:
        required=("ssh_accounts","host_pool","settings",
                  "failover_operations","edge_egress_allocations",
                  "edge_egress_readiness","edge_egress_uid_runtime",
                  "edge_egress_uid_bindings")
        existing={row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
        missing=set(required)-existing
        if missing:
            errors.append("MISSING_REQUIRED_DB_TABLES")
        else:
            if conn.execute(
                "SELECT 1 FROM failover_operations WHERE status='RUNNING' LIMIT 1"
            ).fetchone():
                errors.append("6G_RECOVERY_OR_OPERATION_ACTIVE")
            account=conn.execute(
                "SELECT host,service_type,status FROM ssh_accounts "
                "WHERE username=?", (username,)
            ).fetchone()
            if (account is None or account[0] not in (source_ip,"",None)
                or account[1] != "ssh"
                or not isinstance(account[2],str)
                or account[2] != "🟢 فعال"):
                errors.append("CUSTOMER_INGRESS_OR_STATUS_MISMATCH")
            owner=conn.execute(
                "SELECT active,is_default FROM host_pool WHERE host=?",
                (source_ip,),
            ).fetchone()
            if owner!=(1,1):
                errors.append("SOURCE_NOT_ACTIVE_DEFAULT")
            dns=conn.execute(
                "SELECT value FROM settings WHERE key='dns_current_ip'"
            ).fetchone()
            if dns!=(source_ip,):
                errors.append("INGRESS_DNS_MISMATCH")
            protected=conn.execute(
                "SELECT 1 FROM edge_egress_uid_runtime "
                "WHERE username=? OR uid=? LIMIT 1", (username,uid)
            ).fetchone()
            if protected or conn.execute(
                "SELECT 1 FROM edge_egress_uid_bindings "
                "WHERE username=? OR uid=? LIMIT 1", (username,uid)
            ).fetchone():
                errors.append("EXISTING_PROTECTED_OR_HOLD_INTENT")
            allocation=conn.execute(
                "SELECT edge_public_ipv4,status FROM edge_egress_allocations "
                "WHERE edge_id=?", (edge_id,)
            ).fetchone()
            if allocation!=(expected_edge_ip,"STAGED"):
                errors.append("EXACT_STAGED_EDGE_ALLOCATION_REQUIRED")
            readiness=conn.execute(
                "SELECT edge_ipv4,state FROM edge_egress_readiness "
                "WHERE edge_id=?", (edge_id,)
            ).fetchone()
            if readiness is None or readiness[0]!=expected_edge_ip or (
                readiness[1] not in ("STAGED","VERIFIED_LAB")
            ):
                errors.append("EDGE_NOT_IN_F4_PREACCEPTANCE_STATE")
    except (sqlite3.Error,TypeError,IndexError):
        errors.append("DB_READ_EVIDENCE_UNAVAILABLE")
    return CorePreflight(not errors,tuple(dict.fromkeys(errors)))


def sshd_connection_spec(*, username: str, local_addr: str,
                         remote_addr: str, local_port: int) -> str:
    """Pin the real SSH listener/peer for Match LocalPort/Address checks.

    Core's public IP need not be the local socket address: wg0 ingress uses
    10.77.0.1:2252. Never silently fall back to a localhost-only Match.
    """
    if not isinstance(username, str) or re.fullmatch(
        r"[a-z_][a-z0-9_-]{0,31}", username
    ) is None or type(local_port) is not int or not 1 <= local_port <= 65535:
        raise ValueError("INVALID_SSH_CONNECTION_IDENTITY")
    try:
        local = str(IPv4Address(local_addr))
        remote = str(IPv4Address(remote_addr))
    except (ValueError, TypeError) as exc:
        raise ValueError("INVALID_SSH_CONNECTION_IPV4") from exc
    if local != local_addr or remote != remote_addr:
        raise ValueError("NON_CANONICAL_SSH_CONNECTION_IPV4")
    return (f"user={username},host=localhost,addr={remote},"
            f"laddr={local},lport={local_port}")


def main(argv=None):
    parser=argparse.ArgumentParser(description="NVL F4 Core READ-ONLY preflight")
    parser.add_argument("--db",default="/root/master_bot.db")
    parser.add_argument("--username",default="nvl0557")
    parser.add_argument("--uid",type=int,default=1644)
    parser.add_argument("--source-ip",required=True)
    parser.add_argument("--edge-id",required=True)
    parser.add_argument("--edge-ip",required=True)
    parser.add_argument("--reviewed-gate-sha256",required=True,
                        help="SHA256 of the independently reviewed PAM hook file")
    parser.add_argument("--ssh-local-addr",required=True,
                        help="Actual Core socket IP (e.g. wg0 10.77.0.1)")
    parser.add_argument("--ssh-remote-addr",required=True,
                        help="Core-observed peer address from ingress wg0")
    parser.add_argument("--ssh-local-port",required=True,type=int,
                        help="Actual Core SSHD local port; Match LocalPort needs lport")
    args=parser.parse_args(argv)
    blockers=[]
    try:
        if args.db!="/root/master_bot.db":
            raise ValueError("UNEXPECTED_PRODUCTION_DB_PATH")
        os_uid=pwd.getpwnam(args.username).pw_uid
        pam=Path("/etc/pam.d/sshd").read_text(encoding="utf-8")
        effective=subprocess.run(
            ["sshd","-T","-C",sshd_connection_spec(
                username=args.username,
                local_addr=args.ssh_local_addr,
                remote_addr=args.ssh_remote_addr,
                local_port=args.ssh_local_port,
            )],
            capture_output=True,text=True,timeout=8,check=False,
        )
        if effective.returncode:
            raise OSError("SSHD_EFFECTIVE_CONFIG_UNAVAILABLE")
        def active(name):
            result=subprocess.run(
                ["systemctl","is-active","--quiet",name],
                capture_output=True,text=True,timeout=8,check=False,
            )
            return result.returncode==0
        conn=sqlite3.connect(
            "file:/root/master_bot.db?mode=ro",uri=True,timeout=3
        )
        try:
            conn.execute("PRAGMA query_only=ON")
            result=examine_core(
                conn,username=args.username,uid=args.uid,
                source_ip=args.source_ip,edge_id=args.edge_id,
                expected_edge_ip=args.edge_ip,pam_text=pam,
                sshd_effective=effective.stdout,
                ssh_active=active("ssh"),bot_active=active("nvlbot"),
                os_uid=os_uid,
                gate_digest_verified=verify_installed_gate_digest(
                    args.reviewed_gate_sha256
                ),
            )
        finally:
            conn.close()
        blockers.extend(result.blockers)
    except (OSError,ValueError,sqlite3.Error,KeyError):
        blockers.append("HOST_EVIDENCE_NOT_AVAILABLE")
    print(json.dumps({
        "candidate":not blockers,
        "customer_ready":False,
        "blockers":blockers,
        "host_mutations":0,
    },sort_keys=True))
    return 0 if not blockers else 2


if __name__=="__main__":
    raise SystemExit(main())
