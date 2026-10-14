"""P3 host witness: root-only READ-ONLY live Core/UID readiness inspection.

Composes existing F2/H/PAM/F4 checks against the actual Core. This NEVER
mints F4, a P3 ticket, independent packet witness or permission to deploy.
No route, service, SSH, Cloudflare, DB, roster or PAM mutation exists here.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from hashlib import sha256
from ipaddress import IPv4Address
import json
import os
from pathlib import Path
import pwd
import re
import sqlite3
import stat
import subprocess
import time
from typing import Callable

from edge_egress_f3_readiness import admission_eligible, read_readiness
from edge_egress_f4_kernel_audit import inspect_uid_kernel
from edge_egress_f4_preflight import sshd_connection_spec
from edge_egress_uid_runtime_store import read_binding
from edge_egress_v1_admission import (
    PAM_LINE, check_account, checked_guard, inspect_pam, load_roster,
)
from edge_egress_v1_ingress import probe_ingress
from ops.k2_final_readiness import _trusted_db

V1_PAM_GATE = Path("/opt/nvl-egress/edge_egress_v1_admission.py")
CORE_DB = Path("/root/master_bot.db")
NAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
EDGE = re.compile(r"[a-z][a-z0-9_-]{1,23}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
MAX_V1_GATE = 131072


@dataclass(frozen=True)
class HostUIDWitness:
    local_preflight: bool
    blockers: tuple[str, ...]
    username: str
    edge_id: str
    f4_candidate_only: bool = True
    packet_proof: bool = False
    customer_ready: bool = False


def _public(value: object) -> bool:
    try:
        return isinstance(value, str) and str(IPv4Address(value)) == value and IPv4Address(value).is_global
    except (TypeError, ValueError):
        return False


def trusted_v1_gate_sha(expected: str, path: Path = V1_PAM_GATE) -> bool:
    """Attest the exact V1 PAM hook under root-controlled immutable pathname.

    No caller-provided module path is accepted, and symlinked parents fail.
    """
    if not isinstance(expected, str) or SHA.fullmatch(expected) is None or path != V1_PAM_GATE:
        return False
    try:
        for parent in (Path("/opt"), Path("/opt/nvl-egress")):
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                return False
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                or not 1 <= info.st_size <= MAX_V1_GATE):
            return False
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            check = os.fstat(fd)
            if (check.st_ino != info.st_ino or check.st_dev != info.st_dev
                    or check.st_uid != 0 or not stat.S_ISREG(check.st_mode)
                    or check.st_mode & 0o022 or not 1 <= check.st_size <= MAX_V1_GATE):
                return False
            with os.fdopen(os.dup(fd), "rb") as stream:
                return sha256(stream.read(MAX_V1_GATE + 1)).hexdigest() == expected
        finally:
            os.close(fd)
    except OSError:
        return False


def inspect_uid_host(
    db_conn: Callable, *, username: str, edge_id: str, ingress_source: str,
    expected_edge: str, pam_rhost: str, pam_text: str, sshd_effective: str,
    gate_digest_verified: bool, os_uid: Callable[[str], int],
    roster_loader: Callable = load_roster,
    guard_loader: Callable = checked_guard,
    ingress_probe: Callable = probe_ingress,
    kernel_check: Callable = inspect_uid_kernel,
    now: int | None = None,
) -> HostUIDWitness:
    """Observe existing live guard state; do not construct/approve F4 evidence."""
    failures: list[str] = []
    if (not isinstance(username, str) or NAME.fullmatch(username) is None
            or username == "root" or not isinstance(edge_id, str)
            or EDGE.fullmatch(edge_id) is None or not _public(ingress_source)
            or not _public(expected_edge) or not isinstance(pam_rhost, str)
            or not isinstance(gate_digest_verified, bool)):
        raise ValueError("INVALID_PINNED_HOST_IDENTITY")
    if now is None:
        now = int(time.time())
    if type(now) is not int or now <= 0:
        raise ValueError("INVALID_WITNESS_TIME")

    if not gate_digest_verified:
        failures.append("V1_ROOT_PAM_GATE_NOT_PINNED")
    if not inspect_pam(pam_text, sshd_effective):
        failures.append("LIVE_PAM_SSHD_CONTEXT_NOT_VERIFIED")
    try:
        os_identity = os_uid(username)
        if type(os_identity) is not int or not 1000 <= os_identity < 60000:
            failures.append("OS_UID_NOT_TRUSTED")
        members = roster_loader()
        if not isinstance(members, dict) or username not in members:
            raise ValueError("ROOT_ROSTER_MISSING")
        member = members[username]
        manifest = guard_loader(member)
        req = manifest.request
        with db_conn() as db:
            if db.execute(
                "SELECT 1 FROM failover_operations WHERE status='RUNNING' LIMIT 1"
            ).fetchone():
                failures.append("SHARED_6G_BUSY")
            user = db.execute(
                "SELECT host,service_type,status FROM ssh_accounts WHERE username=?",
                (username,),
            ).fetchone()
            if (user is None or user[0] != ingress_source or user[1] != "ssh"
                    or not isinstance(user[2], str) or "فعال" not in user[2]
                    or "غیر" in user[2]):
                failures.append("ACTIVE_SSH_INGRESS_NOT_PINNED")
            source = db.execute(
                "SELECT host FROM host_pool WHERE active=1 AND is_default=1"
            ).fetchall()
            if len(source) != 1 or source[0] != (ingress_source,):
                failures.append("SOURCE_EDGE_DEFAULT_NOT_PINNED")
            dns = db.execute(
                "SELECT value FROM settings WHERE key='dns_current_ip'"
            ).fetchone()
            if dns != (ingress_source,):
                failures.append("PUBLIC_DNS_SOURCE_NOT_PINNED")
            mode = db.execute(
                "SELECT value FROM settings WHERE key='edge_egress_protected_mode'"
            ).fetchone()
            if mode not in (("0",), ("1",)):
                failures.append("GLOBAL_PROTECTED_MODE_INVALID")
            row = read_binding(db, username)
            binding = db.execute(
                "SELECT uid,edge_id,edge_ipv4,status "
                "FROM edge_egress_uid_bindings WHERE username=?", (username,),
            ).fetchone()
            if (row is None or row.state != "PROTECTED" or row.uid != os_identity
                    or row.edge_id != edge_id or row.edge_ipv4 != expected_edge
                    or binding != (os_identity, edge_id, expected_edge, "PROTECTED")):
                failures.append("PROTECTED_UID_MAPPING_NOT_CURRENT")
            else:
                alloc = db.execute(
                    "SELECT edge_public_ipv4,core_public_ipv4,tunnel_network,"
                    "veth_network,route_table,edge_listen_port,edge_uplink,status "
                    "FROM edge_egress_allocations WHERE edge_id=?", (edge_id,),
                ).fetchone()
                spec = req.spec
                if (alloc is None or alloc != (
                    spec.edge_public_ipv4, spec.core_public_ipv4,
                    spec.tunnel_network, spec.veth_network, spec.route_table,
                    spec.edge_listen_port, spec.edge_uplink, "STAGED"
                ) or spec.edge_public_ipv4 != expected_edge
                        or member.uid != os_identity or req.uid != os_identity
                        or req.username != username or req.priority != row.priority
                        or req.spec.edge_id != edge_id
                        or manifest.dns_port != row.dns_port):
                    failures.append("ROOT_MANIFEST_F3_UID_ROUTE_MISMATCH")
                f4 = read_readiness(db, edge_id)
                if (f4 is None or f4.edge_ipv4 != expected_edge
                        or not admission_eligible(f4, now=now)):
                    failures.append("F4_CURRENT_ACCEPTANCE_REQUIRED")
                if not ingress_probe(row, pam_rhost):
                    failures.append("LIVE_WG0_INGRESS_PEER_UNVERIFIED")
                audited = kernel_check(manifest, expected_state="PROTECTED")
                if audited.locally_consistent is not True:
                    failures.append("LIVE_KERNEL_BOOT_DNS_UID_UNVERIFIED")
                # The existing V1 PAM decision must also permit THIS protected
                # identity, not merely report a syntactically installed hook.
                if not check_account(
                    db, username, os_identity, members,
                    guard_loader=guard_loader,
                    guard_probe=lambda _conn, _row: audited.locally_consistent is True,
                    ingress_probe=lambda _row: ingress_probe(_row, pam_rhost),
                ):
                    failures.append("V1_PAM_PROTECTED_ADMISSION_DENIED")
            # No active/runtime/mapping owner may silently conflict with UID.
            if db.execute(
                "SELECT 1 FROM edge_egress_uid_runtime "
                "WHERE uid=? AND username<>? LIMIT 1", (os_identity,username),
            ).fetchone() or db.execute(
                "SELECT 1 FROM edge_egress_uid_bindings "
                "WHERE uid=? AND username<>? LIMIT 1", (os_identity,username),
            ).fetchone():
                failures.append("NUMERIC_UID_OWNERSHIP_COLLISION")
            # An unrostered protected account can never be treated as Legacy.
            rt = db.execute(
                "SELECT username,uid FROM edge_egress_uid_runtime"
            ).fetchall()
            bm = db.execute(
                "SELECT username,uid FROM edge_egress_uid_bindings"
            ).fetchall()
            if any(name not in members or members[name].uid != uid
                   for name,uid in rt + bm):
                failures.append("UNROSTERED_PROTECTED_INTENT")
    except (OSError, sqlite3.Error, ValueError, KeyError, TypeError, AttributeError, IndexError) as exc:
        failures.append("HOST_EVIDENCE_UNAVAILABLE")
    return HostUIDWitness(
        not failures, tuple(dict.fromkeys(failures)), username, edge_id,
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="K2 P3 root-only Core READ-ONLY host UID preflight")
    parser.add_argument("--username", required=True)
    parser.add_argument("--edge-id", required=True)
    parser.add_argument("--ingress-source", required=True)
    parser.add_argument("--edge-ip", required=True)
    parser.add_argument("--pam-rhost", required=True, help="actual sshd-observed WireGuard peer address")
    parser.add_argument("--ssh-local-addr", required=True)
    parser.add_argument("--ssh-local-port", type=int, required=True)
    parser.add_argument("--reviewed-v1-gate-sha256", required=True)
    args = parser.parse_args(argv)
    result = None
    try:
        if os.geteuid() != 0:
            raise ValueError("ROOT_REQUIRED")
        # DB is always the fixed Core path, read-only; no operator-supplied file.
        _trusted_db(CORE_DB)
        context = sshd_connection_spec(
            username=args.username,local_addr=args.ssh_local_addr,
            remote_addr=args.pam_rhost,local_port=args.ssh_local_port,
        )
        effective = subprocess.run(
            ["sshd","-T","-C",context],capture_output=True,
            text=True,timeout=8,check=False,
        )
        if effective.returncode != 0:
            raise ValueError("SSHD_CONFIG_UNAVAILABLE")
        pam=Path("/etc/pam.d/sshd").read_text(encoding="utf-8")

        from contextlib import contextmanager
        @contextmanager
        def read_db():
            conn=sqlite3.connect(CORE_DB.as_uri()+"?mode=ro",uri=True,timeout=3)
            try:
                conn.execute("PRAGMA query_only=ON")
                yield conn
            finally:
                conn.close()
        result=inspect_uid_host(
            read_db, username=args.username, edge_id=args.edge_id,
            ingress_source=args.ingress_source, expected_edge=args.edge_ip,
            pam_rhost=args.pam_rhost, pam_text=pam,
            sshd_effective=effective.stdout,
            gate_digest_verified=trusted_v1_gate_sha(args.reviewed_v1_gate_sha256),
            os_uid=lambda name:pwd.getpwnam(name).pw_uid,
        )
    except (OSError,ValueError,sqlite3.Error,subprocess.TimeoutExpired):
        result=HostUIDWitness(False,("READ_ONLY_HOST_PREFLIGHT_UNAVAILABLE",),
                              str(args.username)[:32],str(args.edge_id)[:24])
    print(json.dumps({
        "status":"LOCAL_PASS" if result.local_preflight else "HOLD",
        "edge_id":result.edge_id,"blockers":list(result.blockers),
        "customer_ready":False,"independent_f4_candidate_only":True,
        "packet_no_core_leak_proven":False,"changes":False,
    },sort_keys=True))
    return 0 if result.local_preflight else 2


if __name__=="__main__":
    raise SystemExit(main())
