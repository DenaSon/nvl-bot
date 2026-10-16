"""F2: fail-closed *per-user* SSH/PAM account admission policy.

Read-only. No PAM/sshd installer is shipped here. A future operator-reviewed
account hook runs as root, with PAM_USER/PAM_TYPE; it must be present in every
supported SSH authentication path BEFORE a protected runtime intent is written.

This is independent from shared ssh.service systemd dependencies. It cannot
prove an already-authenticated session was disconnected and is NOT sufficient
for a production cutover without F4's real SSH/PAM/boot tests.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import os
import pwd
import re
import sqlite3
import subprocess
from typing import Callable

from edge_egress_uid_runtime_store import RuntimeBinding, read_binding
from edge_egress_f3_readiness import read_readiness, admission_eligible
from edge_egress_uid_boot import BootGuardApplier, BootGuardManifest
from edge_egress_uid_route_state import inspect_owned_routes
from ops.edge_egress_provision import EgressSpec

NAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
FIXED_DB = "/root/master_bot.db"


class AdmissionResult(str, Enum):
    ALLOW_LEGACY = "ALLOW_LEGACY"
    ALLOW_PROTECTED = "ALLOW_PROTECTED"
    DENY = "DENY"


@dataclass(frozen=True)
class AdmissionDecision:
    result: AdmissionResult
    reason: str

    @property
    def permitted(self) -> bool:
        return self.result != AdmissionResult.DENY


def decide_account(conn: sqlite3.Connection, username: str, actual_uid: int,
                   protected_guard_probe: Callable[[RuntimeBinding], bool],
                   *, scoped_busy_probe: Callable[[RuntimeBinding], bool] | None = None,
                   ) -> AdmissionDecision:
    """Fail closed for ANY ambiguous DB, mapping, kernel or shared-6G state."""
    denied = lambda reason: AdmissionDecision(AdmissionResult.DENY, reason)
    try:
        if not isinstance(username, str) or not NAME.fullmatch(username):
            return denied("INVALID_ACCOUNT_IDENTITY")
        if type(actual_uid) is not int or actual_uid < 0:
            return denied("INVALID_OS_UID")
        if not conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='edge_egress_uid_runtime'"
        ).fetchone():
            return denied("RUNTIME_MIGRATION_REQUIRED")
        row = read_binding(conn, username)
        if not conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='edge_egress_uid_bindings'"
        ).fetchone():
            return denied("PROTECTED_MAPPING_MIGRATION_REQUIRED")
        protected = conn.execute(
            "SELECT uid,edge_id,edge_ipv4,status "
            "FROM edge_egress_uid_bindings WHERE username=?", (username,),
        ).fetchone()
        if row is None:
            if protected:
                return denied("MAPPING_WITHOUT_RUNTIME")
            # A renamed/reused Unix identity must not become an unprotected
            # "legacy" login while another username owns the numeric UID.
            if conn.execute(
                "SELECT 1 FROM edge_egress_uid_runtime "
                "WHERE uid=? LIMIT 1", (actual_uid,),
            ).fetchone():
                return denied("UID_OWNED_BY_DIFFERENT_PROTECTED_USER")
            if conn.execute(
                "SELECT 1 FROM edge_egress_uid_bindings "
                "WHERE uid=? LIMIT 1", (actual_uid,),
            ).fetchone():
                return denied("UID_OWNED_BY_DIFFERENT_PROTECTED_MAPPING")
            setting = conn.execute(
                "SELECT value FROM settings WHERE key='edge_egress_protected_mode'"
            ).fetchone()
            if setting and setting[0] not in ("0",):
                return denied("GLOBAL_PROTECTED_MODE_WITHOUT_MAPPING")
            return AdmissionDecision(AdmissionResult.ALLOW_LEGACY, "NO_PROTECTED_INTENT")
        if row.uid != actual_uid:
            return denied("UID_IDENTITY_CHANGED")
        if row.state != "PROTECTED":
            return denied("PROTECTED_ACCOUNT_NOT_ROUTED")
        if protected != (row.uid, row.edge_id, row.edge_ipv4, "PROTECTED"):
            return denied("PROTECTED_MAPPING_NOT_COHERENT")
        busy = conn.execute(
            "SELECT 1 FROM failover_operations "
            "WHERE status='RUNNING' LIMIT 1"
        ).fetchone()
        if busy and (scoped_busy_probe is None or scoped_busy_probe(row) is not True):
            return denied("SHARED_6G_OPERATION_ACTIVE")
        if not protected_guard_probe(row):
            return denied("KERNEL_DNS_BOOT_GUARD_NOT_VERIFIED")
        return AdmissionDecision(AdmissionResult.ALLOW_PROTECTED, "GUARDED_EDGE_ROUTE")
    except (sqlite3.Error, OSError, ValueError, LookupError):
        return denied("ADMISSION_EVIDENCE_UNAVAILABLE")


def probe_local_guards(conn: sqlite3.Connection, row: RuntimeBinding) -> bool:
    """Recheck exact assigned Edge, UID kernel rules and running DNS service.

    DNS must be running and the Edge route must be the only alternate to the
    terminal blackhole. This does NOT prove Internet reachability right now.
    """
    allocation = conn.execute(
        "SELECT edge_public_ipv4,core_public_ipv4,tunnel_network,veth_network,"
        "route_table,edge_listen_port,edge_uplink,status "
        "FROM edge_egress_allocations WHERE edge_id=?", (row.edge_id,),
    ).fetchone()
    if not allocation or allocation[0] != row.edge_ipv4 or (
        allocation[4] != row.route_table or allocation[7] != "STAGED"
    ):
        return False
    # An Edge proven in a disposable lab is NOT a customer-admissible Edge.
    if not admission_eligible(read_readiness(conn, row.edge_id)):
        return False
    spec = EgressSpec(
        edge_id=row.edge_id, edge_public_ipv4=allocation[0],
        core_public_ipv4=allocation[1], tunnel_network=allocation[2],
        veth_network=allocation[3], route_table=allocation[4],
        edge_listen_port=allocation[5], edge_uplink=allocation[6],
    )
    from edge_egress_uid_policy import UIDPolicyRequest
    request = UIDPolicyRequest(
        spec, row.username, row.uid, priority=row.priority,
    )
    manifest = BootGuardManifest(request, "PROTECTED_BOOT_GUARD", row.dns_port,
                                 ingress_return=True, shared_edge=True)
    BootGuardApplier().verify(manifest)
    # Frozen/denied UID must never be admitted even though another UID on
    # the same Edge keeps the shared route attached.
    from edge_egress_uid_boot import uid_deny_present, _local_run
    if uid_deny_present(_local_run, row.uid):
        return False
    routes = subprocess.run(
        ["ip", "-4", "route", "show", "table", str(row.route_table)],
        capture_output=True, text=True, timeout=6, check=False,
    )
    if routes.returncode or not inspect_owned_routes(
        routes.stdout, next_hop=spec.ns_veth_ip,
        device=spec.veth_root, source=spec.root_veth_ip,
        allow_ingress_return=True,
    ).edge_attached:
        return False
    dns = subprocess.run(
        ["systemctl", "is-active", "--quiet",
         "nvl-egress-dns-" + row.username + ".service"],
        capture_output=True, text=True, timeout=6, check=False,
    )
    return dns.returncode == 0


def main() -> int:
    """PAM account hook candidate; installer intentionally excluded in F2."""
    if os.geteuid() != 0 or os.environ.get("PAM_TYPE") != "account":
        return 1
    username = os.environ.get("PAM_USER", "")
    if not NAME.fullmatch(username):
        return 1
    try:
        actual = pwd.getpwnam(username).pw_uid
        # Keep the primary root break-glass route independent from bot DB,
        # WireGuard and per-account DNS. No other UID gets this exception.
        # F4 must test out-of-band console and non-root admins separately.
        if username == "root" and actual == 0:
            return 0
        # Open the exact expected Core DB read-only. The path is not provided
        # by PAM/user input, preventing a user selecting a forged SQLite file.
        conn = sqlite3.connect("file:" + FIXED_DB + "?mode=ro", uri=True, timeout=2)
        try:
            conn.execute("PRAGMA query_only=ON")
            decision = decide_account(
                conn, username, actual,
                lambda binding: probe_local_guards(conn, binding),
            )
            return 0 if decision.permitted else 1
        finally:
            conn.close()
    except (sqlite3.Error, OSError, KeyError, ValueError):
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
