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
    witness: str = ""
    observed_ipv4: str = ""
    expires_at: int | None = None


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
        readiness = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='edge_egress_readiness'"
        ).fetchone()
        if readiness:
            # LEFT JOIN prevents any lab evidence from overwriting canonical
            # stage-only allocation status or implying customer readiness.
            rows = conn.execute(
                "SELECT a.edge_id,a.edge_public_ipv4,a.status,"
                "COALESCE(r.witness,''),COALESCE(r.observed_ipv4,''),"
                "r.expires_at "
                "FROM edge_egress_allocations a LEFT JOIN "
                "edge_egress_readiness r ON r.edge_id=a.edge_id "
                "ORDER BY a.created_at DESC,a.edge_id LIMIT 8"
            ).fetchall()
            states = conn.execute(
                "SELECT edge_id,state FROM edge_egress_readiness"
            ).fetchall()
            by_edge = dict(states)
            rows = [
                (edge_id, ip, stage + " / " + by_edge.get(edge_id, "NO_EVIDENCE"),
                 witness, observed, expires)
                for edge_id, ip, stage, witness, observed, expires in rows
            ]
        else:
            rows = conn.execute(
                "SELECT edge_id,edge_public_ipv4,status "
                "FROM edge_egress_allocations "
                "ORDER BY created_at DESC,edge_id LIMIT 8"
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
            if row.witness:
                observed = escape(row.observed_ipv4[:64])
                lines.append(
                    f"  شاهد: {escape(row.witness[:40])} · IP: <code>{observed}</code>"
                )
    lines.extend((
        "",
        "⚠️ VERIFIED_LAB فقط شاهد IP تونل آزمایشی است؛ به‌معنای مجوز تخصیص کاربر نیست.",
        "برای تخصیص Production باید تأیید Reboot، PAM و بدون Leak در F4 ثبت شود.",
        "تغییر دستی Edge و Failover محافظت‌شده تا تکمیل تست‌های عملیاتی غیرفعال می‌مانند.",
    ))
    return "\n".join(lines)
