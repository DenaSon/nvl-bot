"""K2 Phase 2: read-only, fail-closed Legacy -> protected enrollment inventory.

A Legacy SSH account has no trusted per-UID route or protected binding. It
must first be enrolled on its CURRENT ingress Edge, under independently
accepted F4/PAM/BootGuard/packet proofs, before the existing all-protected
Edge-to-Edge cutover can run. This module performs no enrollment or release.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest
from ipaddress import IPv4Address
import json
import pwd
import re
import sqlite3
import time
from typing import Callable

from edge_egress_f3_readiness import admission_eligible, read_readiness


class LegacyEnrollmentHold(ValueError):
    pass


@dataclass(frozen=True)
class LegacyEnrollmentAudit:
    source_ip: str
    source_edge_id: str
    target_ip: str
    target_edge_id: str
    active_count: int
    protected_count: int
    legacy_users: tuple[tuple[str, int], ...]
    invalid_count: int
    blockers: tuple[str, ...]
    fingerprint: str

    @property
    def inventory_clear(self) -> bool:
        # Inventory is NOT a customer release or executable approval.
        return bool(self.legacy_users) and self.invalid_count == 0 and not self.blockers


def _ipv4(value: object) -> bool:
    try:
        ip = IPv4Address(value)
        return isinstance(value, str) and str(ip) == value and ip.is_global
    except (TypeError, ValueError):
        return False


def _digest(value: object) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def inspect_legacy_enrollment(
    db_conn: Callable, target_edge_id: str, *,
    os_uid: Callable[[str], int] = lambda name: pwd.getpwnam(name).pw_uid,
    now: int | None = None,
    authorized_operation: tuple[int, str, str] | None = None,
) -> LegacyEnrollmentAudit:
    """Identify exact Legacy UIDs without changing routing, DB, DNS or PAM.

    All active SSH accounts are audited, including other-Edge/unknown owners,
    and all existing protected runtime/binding rows are cross-checked. Source
    F3/F4 is mandatory: Legacy users must not be routed via a different Edge
    during a supposed same-ingress/same-egress conversion.
    """
    if not isinstance(target_edge_id, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{1,23}", target_edge_id):
        raise LegacyEnrollmentHold("INVALID_EDGE_ID")
    ts = int(time.time()) if now is None else now
    if type(ts) is not int or ts <= 0:
        raise LegacyEnrollmentHold("INVALID_REVIEW_TIME")

    blockers: list[str] = []
    legacy: list[tuple[str, int]] = []
    invalid = protected = 0
    source = source_eid = target = ""
    active: list[tuple[str, str, int | None]] = []
    source_f4 = target_f4 = ()
    allocations = runtime = bindings = ()
    try:
        with db_conn() as conn:
            defaults = conn.execute(
                "SELECT host FROM host_pool WHERE active=1 AND is_default=1"
            ).fetchall()
            if len(defaults) != 1 or not _ipv4(defaults[0][0]):
                raise LegacyEnrollmentHold("SOURCE_DEFAULT_NOT_UNIQUE")
            source = defaults[0][0]
            dns = conn.execute(
                "SELECT value FROM settings WHERE key='dns_current_ip'"
            ).fetchone()
            if dns != (source,):
                blockers.append("SOURCE_DNS_NOT_PINNED")
            # Historical 6G SQLite fixtures have only id/status columns.
            # Read extended journal columns ONLY for a running operation
            # explicitly bound to the source-enrollment worker.
            running_ids = conn.execute(
                "SELECT id FROM failover_operations WHERE status='RUNNING'"
            ).fetchall()
            if running_ids:
                authorized = False
                if len(running_ids) == 1 and authorized_operation is not None:
                    try:
                        operation_id, scope_hash, nonce_hash = authorized_operation
                        row = conn.execute(
                            "SELECT id,source_host,target_host,detail_json "
                            "FROM failover_operations WHERE id=? AND status='RUNNING'",
                            (running_ids[0][0],),
                        ).fetchone()
                        detail = json.loads(row[3])
                        authorized = (
                            type(operation_id) is int and operation_id > 0
                            and row[:3] == (operation_id, source, source)
                            and isinstance(detail, dict)
                            and detail.get("kind") == "K2_P3A"
                            and detail.get("action") == "UID_ENROLL_SOURCE"
                            and detail.get("phase") == "EGRESS_P3_EXECUTE_INTENT"
                            and isinstance(scope_hash, str) and len(scope_hash) == 64
                            and isinstance(nonce_hash, str) and len(nonce_hash) == 64
                            and compare_digest(detail.get("scope_digest", ""), scope_hash)
                            and compare_digest(detail.get("nonce_hash", ""), nonce_hash)
                        )
                    except (ValueError, TypeError):
                        authorized = False
                if not authorized:
                    blockers.append("SHARED_6G_BUSY")

            allocations = tuple(conn.execute(
                "SELECT edge_id,edge_public_ipv4,core_public_ipv4,status "
                "FROM edge_egress_allocations ORDER BY edge_id"
            ).fetchall())
            targets = [r for r in allocations if r[0] == target_edge_id]
            if len(targets) != 1 or targets[0][3] != "STAGED" or not _ipv4(targets[0][1]):
                raise LegacyEnrollmentHold("TARGET_F3_ALLOCATION_REQUIRED")
            target = targets[0][1]
            if target == source:
                raise LegacyEnrollmentHold("SOURCE_TARGET_SAME_EDGE")
            sources = [r for r in allocations
                       if r[1] == source and r[2] == targets[0][2] and r[3] == "STAGED"]
            if len(sources) != 1:
                blockers.append("SOURCE_F3_ALLOCATION_REQUIRED")
            else:
                source_eid = sources[0][0]
            if any(r[1] == target and r[0] != target_edge_id for r in allocations):
                blockers.append("TARGET_ALLOCATION_COLLISION")
            if any(r[1] == source and r[0] != source_eid for r in allocations):
                blockers.append("SOURCE_ALLOCATION_COLLISION")

            def _f4(eid: str, ip: str):
                if not eid:
                    return ()
                ready = read_readiness(conn, eid)
                if not admission_eligible(ready, now=ts) or ready.edge_ipv4 != ip:
                    return ()
                return (ready.witness, ready.probed_at, ready.expires_at,
                        ready.observed_ipv4)

            source_f4 = _f4(source_eid, source)
            target_f4 = _f4(target_edge_id, target)
            if not source_f4:
                blockers.append("SOURCE_F4_NOT_ACCEPTED")
            if not target_f4:
                blockers.append("TARGET_F4_NOT_ACCEPTED")

            rows = conn.execute(
                "SELECT username,host FROM ssh_accounts "
                "WHERE service_type='ssh' AND status LIKE '%فعال%' "
                "AND status NOT LIKE '%غیر%' ORDER BY username"
            ).fetchall()
            if not rows or len(rows) > 10000:
                blockers.append("ACTIVE_COHORT_EMPTY_OR_TOO_LARGE")

            runtime = tuple(conn.execute(
                "SELECT username,uid,edge_id,edge_ipv4,state "
                "FROM edge_egress_uid_runtime ORDER BY username"
            ).fetchall())
            bindings = tuple(conn.execute(
                "SELECT username,uid,edge_id,edge_ipv4,status "
                "FROM edge_egress_uid_bindings ORDER BY username"
            ).fetchall())
            by_runtime = {r[0]: r for r in runtime}
            by_binding = {r[0]: r for r in bindings}
            if len(by_runtime) != len(runtime) or len(by_binding) != len(bindings):
                blockers.append("DUPLICATE_PROTECTED_IDENTITY")
            active_names = set()
            seen_uids = set()
            for name, host in rows:
                uid = None
                if isinstance(name, str) and re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", name):
                    try:
                        uid = os_uid(name)
                    except (KeyError, OSError, ValueError, TypeError):
                        pass
                valid_uid = type(uid) is int and 1000 <= uid < 60000 and uid not in seen_uids
                if valid_uid:
                    seen_uids.add(uid)
                active.append((name, host, uid if valid_uid else None))
                rr, bb = by_runtime.get(name), by_binding.get(name)
                if name in active_names or not valid_uid or host != source:
                    invalid += 1
                    blockers.append("ACCOUNT_OS_UID_OR_SOURCE_UNVERIFIED")
                elif rr is None and bb is None:
                    legacy.append((name, uid))
                elif (rr is not None and bb is not None and source_eid
                      and rr == (name, uid, source_eid, source, "PROTECTED")
                      and bb == (name, uid, source_eid, source, "PROTECTED")):
                    protected += 1
                else:
                    invalid += 1
                    blockers.append("PARTIAL_OR_FOREIGN_PROTECTED_IDENTITY")
                active_names.add(name)
            if any(r[0] not in active_names for r in runtime + bindings):
                blockers.append("ORPHAN_PROTECTED_IDENTITY")
            if not legacy:
                blockers.append("NO_LEGACY_USER_TO_ENROLL")
    except LegacyEnrollmentHold:
        raise
    except (OSError, ValueError, TypeError, sqlite3.Error) as exc:
        raise LegacyEnrollmentHold("INVENTORY_EVIDENCE_UNAVAILABLE") from exc

    fingerprint = _digest((
        source, source_eid, target, target_edge_id, allocations,
        tuple(active), runtime, bindings, source_f4, target_f4,
        tuple(sorted(legacy)), protected, invalid, tuple(blockers),
    ))
    return LegacyEnrollmentAudit(
        source, source_eid, target, target_edge_id, len(active), protected,
        tuple(legacy), invalid, tuple(dict.fromkeys(blockers)), fingerprint,
    )


def legacy_enrollment_html(audit: LegacyEnrollmentAudit) -> str:
    """Short operator text; no usernames, UIDs, technical release flags."""
    lines = [
        "👥 <b>آماده‌سازی کاربران قدیمی</b>", "",
        f"کاربران فعال: <b>{audit.active_count}</b>",
        f"دارای خروجی محافظت‌شده: <b>{audit.protected_count}</b>",
        f"نیازمند انتقال امن: <b>{len(audit.legacy_users)}</b>",
    ]
    if audit.invalid_count:
        lines.append(f"حساب‌های نیازمند بررسی: <b>{audit.invalid_count}</b>")
    if audit.inventory_clear:
        lines.append("✅ هویت کاربران بررسی شد؛ اجرای انتقال هنوز فعال نیست.")
    else:
        lines.append("⛔ انتقال متوقف است؛ ابتدا ایمنی سرورها و حساب‌ها بررسی شود.")
    lines.append("حساب‌ها و مسیر اینترنت تغییری نکرده‌اند.")
    return "\n".join(lines)
