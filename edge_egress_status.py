"""Read-only NVL Edge Egress status for the admin's existing Edge screen.

No migrations, no SSH/WireGuard, no token/secret read, no DNS or account writes.
STAGED means config files only; it MUST NOT be presented as VPN-ready.
"""
from __future__ import annotations

from dataclasses import dataclass
from html import escape
from ipaddress import ip_address


@dataclass(frozen=True)
class EgressRow:
    edge_id: str
    edge_ipv4: str
    state: str


@dataclass(frozen=True)
class EgressStatus:
    protected_setting: str
    schema_installed: bool
    registrations: tuple[EgressRow, ...]
    registered_count: int


def read_egress_status(db_conn) -> EgressStatus:
    """Database reads only; callers can safely use asyncio.to_thread."""
    with db_conn() as conn:
        item = conn.execute(
            "SELECT value FROM settings WHERE key='edge_egress_protected_mode'"
        ).fetchone()
        mode = str(item[0]) if item else "0"
        present = conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name='edge_egress_allocations'"
        ).fetchone()
        if not present:
            return EgressStatus(mode, False, (), 0)
        rows = conn.execute(
            "SELECT edge_id,edge_public_ipv4,status "
            "FROM edge_egress_allocations ORDER BY created_at DESC,edge_id LIMIT 8"
        ).fetchall()
        count = conn.execute("SELECT COUNT(*) FROM edge_egress_allocations").fetchone()[0]
        return EgressStatus(mode, True, tuple(EgressRow(*x) for x in rows), count)


def render_egress_status_html(status: EgressStatus) -> str:
    """Static warnings are intentional; no READY/ACTIVE label is rendered."""
    if status.protected_setting == "0":
        policy = "خاموش (مسیر فعلی کاربران بدون تغییر)"
    elif status.protected_setting == "1":
        policy = "محافظت‌شده، اما موتور اجرای Production هنوز تکمیل نشده"
    else:
        policy = "نامعتبر — عملیات مدیریتی باید متوقف شود"
    lines = [
        "🛡️ <b>وضعیت Edge Egress Manager</b>",
        "",
        f"حالت: <b>{escape(policy)}</b>",
        "وضعیت انتشار: <b>آزمایشی / بدون فعال‌سازی کاربران</b>",
    ]
    if not status.schema_installed:
        lines.append("رجیستری Edge Egress: نصب نشده")
    else:
        lines.append(f"رجیستری: {status.registered_count} شناسه")
        for row in status.registrations:
            edge_id = escape(row.edge_id[:32])
            edge_ip = escape(row.edge_ipv4[:64])
            state = escape(row.state[:24])
            lines.append(f"• <code>{edge_id}</code> · <code>{edge_ip}</code> · {state}")
    lines.extend((
        "",
        "⚠️ RESERVED و STAGED به‌معنای سالم‌بودن WireGuard یا آماده‌بودن IP خروجی نیستند.",
        "تغییر دستی Edge و Failover محافظت‌شده تا تکمیل تست‌های عملیاتی غیرفعال می‌مانند.",
    ))
    return "\n".join(lines)
