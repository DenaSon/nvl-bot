"""K2 Phase 2: read-only, SOURCE-scoped SSH customer cohort audit.

Host metadata alone is not protected routing proof. The output only describes
potential customers on the current Legacy default relay; it never stages,
selects, updates, or releases a UID. It is NOT an execution authorization.
"""
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address
import sqlite3
from typing import Callable


class CohortHold(ValueError):
    pass


@dataclass(frozen=True)
class SourceCohort:
    source_ip: str
    target_ip: str
    source_accounts: int
    other_edge_accounts: int
    already_target_accounts: int
    unknown_accounts: int
    active_total: int
    blockers: tuple[str, ...]

    @property
    def source_only(self) -> bool:
        return bool(self.source_ip and self.source_accounts > 0 and
                    not self.blockers)


def _public(value: str) -> bool:
    try:
        parsed = IPv4Address(value)
        return isinstance(value, str) and str(parsed) == value and parsed.is_global
    except (ValueError, TypeError):
        return False


def _table(conn, name: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (name,),
    ).fetchone() is not None


def read_source_cohort(db_conn: Callable, target_ip: str) -> SourceCohort:
    """Return exact source-only counts; OTHER Edge accounts are never included.

    A read-only snapshot is not a lease. The actual P3-A execution must redo
    every ownership and Unix UID check under the one existing 6G lock.
    """
    if not _public(target_ip):
        raise CohortHold("NONPUBLIC_TARGET_EDGE")
    blockers = []
    source = ""
    source_count = other_count = target_count = unknown = total = 0
    try:
        with db_conn() as conn:
            if not _table(conn, "host_pool") or not _table(conn, "ssh_accounts"):
                return SourceCohort(
                    "", target_ip, 0, 0, 0, 0, 0,
                    ("فهرست سرورها یا حساب‌ها کامل نیست",),
                )
            defaults = conn.execute(
                "SELECT host FROM host_pool WHERE active=1 AND is_default=1"
            ).fetchall()
            if len(defaults) != 1 or not _public(defaults[0][0]):
                blockers.append("رله مبدأ یکتا و معتبر نیست")
            else:
                source = defaults[0][0]
                if source == target_ip:
                    blockers.append("این سرور هم‌اکنون پیش‌فرض است")
            known = {str(row[0]) for row in conn.execute(
                "SELECT host FROM host_pool"
            ).fetchall()}
            rows = conn.execute(
                "SELECT username,host FROM ssh_accounts "
                "WHERE service_type='ssh' AND status='🟢 فعال'"
            ).fetchall()
            total = len(rows)
            if total > 10000:
                blockers.append("تعداد حساب‌ها نیازمند بررسی است")
            names = set()
            for username, host in rows:
                if (not isinstance(username, str) or not username
                        or username in names):
                    unknown += 1
                    continue
                names.add(username)
                if source and host == source:
                    source_count += 1
                elif host == target_ip:
                    target_count += 1
                elif _public(host) and host in known:
                    other_count += 1
                else:
                    unknown += 1
            if unknown:
                blockers.append("مالکیت برخی حساب‌ها مشخص نیست")
            if source and source_count == 0:
                blockers.append("کاربری روی رله مبدأ برای انتقال وجود ندارد")
            # A global DNS switch is a separate operation requiring proof that
            # shared hostnames won't redirect OTHER Edge customer ingress.
            if other_count:
                blockers.append("حساب‌های سرورهای دیگر از تغییر دامنه جدا نشده‌اند")
    except sqlite3.Error as exc:
        raise CohortHold("COHORT_DATABASE_UNAVAILABLE") from exc
    return SourceCohort(
        source, target_ip, source_count, other_count, target_count,
        unknown, total, tuple(dict.fromkeys(blockers)),
    )
