"""Read-only LAB closure inspector: never promotes F4 readiness.

Bound to the disposable Amsterdam Core, the real on-disk PAM, 6G journal,
F1-F3 allocation and terminal UID blackhole. Safe under an active root SSH
session. Does not try an external SSH login, touch PAM, issue a lease,
construct a customer, change WireGuard or reboot.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import sqlite3
import stat
import subprocess
import sys

from edge_egress_r1_lab_6g_bootstrap import lab_host_attested
from edge_egress_r1_lab_pam import PAM_ACCOUNT_LINE
from edge_egress_r1_lab_pam_runtime import verified_runtime_module
from edge_egress_uid_boot import BootGuardApplier, read_root_only_manifest
from edge_egress_uid_route_state import inspect_owned_routes

DB = Path("/root/master_bot.db")
PAM = Path("/etc/pam.d/sshd")
BACKUP = Path("/root/nvl-r1-pam-rollback/sshd.before")
WRAPPER = Path("/opt/nvl-egress/edge_egress_r1_lab_pam.py")
MANIFEST = Path("/etc/nvl-egress/protected/nvlr1test.json")
CORE = "107.189.16.36"
EDGE = "216.126.229.12"
USER = "nvlr1test"
UID = 1555


def owned_data(path: Path, *, max_size: int = 200000) -> bytes:
    meta = path.lstat()
    if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0
            or meta.st_mode & 0o022 or meta.st_size > max_size):
        raise ValueError("UNTRUSTED_FILE")
    return path.read_bytes()


def audit_db(conn) -> dict[str, object]:
    """No schema install or INSERT; never substitute guessed host/DNS rows."""
    checks: dict[str, object] = {}
    tables = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    )}
    required = {"failover_operations", "edge_egress_allocations",
                "edge_egress_readiness", "edge_egress_uid_runtime",
                "edge_egress_uid_bindings"}
    checks["real_6g_f1_f3_schema"] = required <= tables
    if not checks["real_6g_f1_f3_schema"]:
        return checks
    journal = conn.execute(
        "SELECT status,source_host,target_host,detail_json "
        "FROM failover_operations ORDER BY id DESC LIMIT 1"
    ).fetchone()
    checks["last_6g_staged_operation"] = bool(
        journal and journal[0:3] == ("SUCCEEDED", CORE, EDGE)
        and journal[3] and '"EGRESS_LAB_ALLOCATION"' in journal[3]
    )
    checks["no_active_6g_lock"] = not conn.execute(
        "SELECT 1 FROM failover_operations WHERE status='RUNNING' LIMIT 1"
    ).fetchone()
    allocation = conn.execute(
        "SELECT edge_public_ipv4,core_public_ipv4,status,route_table "
        "FROM edge_egress_allocations WHERE edge_id='lab1'"
    ).fetchone()
    checks["live_edge_registry_staged"] = (
        allocation == (EDGE, CORE, "STAGED", 1791)
    )
    readiness = conn.execute(
        "SELECT edge_ipv4,state FROM edge_egress_readiness "
        "WHERE edge_id='lab1'"
    ).fetchone()
    checks["edge_is_staged_not_ready"] = readiness == (EDGE, "STAGED")
    checks["protected_uid_mapping_absent"] = not conn.execute(
        "SELECT 1 FROM edge_egress_uid_bindings WHERE username=? OR uid=?",
        (USER, UID),
    ).fetchone() and not conn.execute(
        "SELECT 1 FROM edge_egress_uid_runtime WHERE username=? OR uid=?",
        (USER, UID),
    ).fetchone()
    checks["ingress_customer_schema_present"] = (
        {"ssh_accounts", "host_pool", "settings"} <= tables
    )
    # These are intentionally not invented by the LAB 6G bootstrap.
    # A truthful deployment must still bind an actual Core ingress/UID.
    return checks


def audit_pam() -> dict[str, bool]:
    """Compare installed first account rule to original exact backup bytes."""
    data = owned_data(PAM)
    original = owned_data(BACKUP)
    wrapper = owned_data(WRAPPER)
    lines = [" ".join(line.split()) for line in data.decode().splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    accounts = [line for line in lines if line.startswith("account ")]
    return {
        "pam_original_backup_exact": data == (
            (PAM_ACCOUNT_LINE + "\n").encode() + original
        ),
        "pam_first_account_rule": bool(
            accounts and accounts[0] == PAM_ACCOUNT_LINE
            and accounts.count(PAM_ACCOUNT_LINE) == 1
        ),
        "pam_wrapper_bytes_attested": bool(
            wrapper and verified_runtime_module()
        ),
    }


def run_check(*argv: str) -> tuple[int, str]:
    result = subprocess.run(
        list(argv), capture_output=True, text=True, timeout=8, check=False
    )
    return result.returncode, result.stdout.strip()


def audit_host() -> dict[str, bool]:
    """Observe existing deny-only routing. Never touch traffic or service."""
    checks: dict[str, bool] = {}
    checks["pinned_disposable_core"] = lab_host_attested()
    if not checks["pinned_disposable_core"]:
        return checks
    account = pwd.getpwnam(USER)
    checks["pilot_nologin"] = (account.pw_uid == UID and
                               account.pw_shell == "/usr/sbin/nologin")
    status, text = run_check("passwd", "-S", USER)
    checks["pilot_password_locked"] = status == 0 and bool(
        len(text.split()) > 1 and text.split()[1] == "L"
    )
    manifest = read_root_only_manifest(MANIFEST)
    req = manifest.request
    checks["pilot_manifest_fixed"] = bool(
        manifest.mode == "PROTECTED_BOOT_GUARD"
        and (req.username, req.uid, req.spec.edge_id,
             req.spec.route_table) == (USER, UID, "lab1", 1791)
        and (req.spec.core_public_ipv4,
             req.spec.edge_public_ipv4) == (CORE, EDGE)
    )
    if checks["pilot_manifest_fixed"]:
        BootGuardApplier().verify(manifest)
        checks["uid_boot_guard_active"] = True
        status, route = run_check(
            "ip", "-4", "route", "show", "table", "1791"
        )
        if status:
            raise ValueError("ROUTE_TABLE_UNAVAILABLE")
        inspected = inspect_owned_routes(
            route, next_hop=req.spec.ns_veth_ip,
            device=req.spec.veth_root, source=req.spec.root_veth_ip,
        )
        checks["uid_blackhole_only"] = (
            inspected.terminal_blackhole and not inspected.edge_attached
        )
    for label, action in (
        ("persistent_bootguard_active", "is-active"),
        ("persistent_bootguard_enabled", "is-enabled"),
    ):
        code, _ = run_check(
            "systemctl", action, "--quiet",
            "nvl-egress-lab1-guard.service"
        )
        checks[label] = code == 0
    code, ssh_config = run_check(
        "/usr/sbin/sshd", "-T", "-C",
        "user=nvlr1test,host=107.189.16.36,addr=107.189.16.36"
    )
    checks["sshd_usepam"] = code == 0 and (
        "usepam yes" in ssh_config.lower().splitlines()
    )
    checks.update(audit_pam())
    return checks


def collect() -> dict:
    checks: dict[str, object] = {}
    failures: list[str] = []
    # No caller-supplied parameters; never audit a Production IP or DB.
    if os.geteuid() != 0:
        failures.append("ROOT_REQUIRED")
    else:
        try:
            checks.update(audit_host())
        except Exception:
            failures.append("LIVE_HOST_EVIDENCE_UNAVAILABLE")
        try:
            info = DB.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or info.st_mode & 0o077):
                raise ValueError("LAB_DB_PERMISSIONS_UNSAFE")
            with sqlite3.connect(
                DB.absolute().as_uri() + "?mode=ro",
                uri=True, timeout=3
            ) as conn:
                conn.execute("PRAGMA query_only=ON")
                checks.update(audit_db(conn))
        except Exception:
            failures.append("LIVE_6G_DB_EVIDENCE_UNAVAILABLE")
    for key, ok in checks.items():
        if not ok and key != "ingress_customer_schema_present":
            failures.append(key.upper() + "_NOT_VERIFIED")
    if not checks.get("ingress_customer_schema_present"):
        failures.append("REAL_LAB_INGRESS_ACCOUNT_METADATA_MISSING")
    # A first canary is logically impossible to treat as F4 READY before
    # its SSH and failure proofs. NEVER insert READY or authorize login.
    failures.extend((
        "ISOLATED_FIRST_SSH_CANARY_NOT_ACCEPTED",
        "REAL_EDGE_OUTAGE_AND_REBOOT_NOT_ACCEPTED",
        "F4_READY_NOT_EVIDENCED",
    ))
    return {
        "environment": "disposable-r1-lab-core",
        "checks": checks,
        "blockers": list(dict.fromkeys(failures)),
        "host_mutations": 0,
        "protected_ssh_enabled": False,
        "customer_ready": False,
    }


def main() -> int:
    report = collect()
    print(json.dumps(report, sort_keys=True, ensure_ascii=False))
    return 0 if (report["checks"].get("pinned_disposable_core")
                 and report["checks"].get("pam_original_backup_exact")
                 and report["checks"].get("uid_blackhole_only")) else 2


if __name__ == "__main__":
    raise SystemExit(main())
