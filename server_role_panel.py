"""Legacy Core/Edge Telegram presentation and guarded inactive inventory deletion.

No network, SSH, DNS, WireGuard, account or failover operations live here.
Existing operational callbacks are deliberately reused without modification.
"""
from __future__ import annotations

from html import escape
from ipaddress import IPv4Address
from pathlib import Path

PAGE_SIZE = 7


def checked_ip(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("INVALID_HOST_IP")
    try:
        address = IPv4Address(value)
    except ValueError as exc:
        raise ValueError("INVALID_HOST_IP") from exc
    if str(address) != value or not address.is_global:
        raise ValueError("INVALID_HOST_IP")
    return value


def relay_selection(pool, core_ip: str, dns_ip: str):
    """Only a single, active, non-Core is_default row is the selected relay.

    DNS equality alone does not make a second row selected. A DB/DNS mismatch
    remains visible and never triggers a mutation or an inferred live route.
    """
    defaults = [r[0] for r in pool if r[7]]
    if len(defaults) > 1:
        return None, "⚠️ چند سرور در دیتابیس پیش‌فرض شده‌اند؛ وضعیت نیازمند بررسی است."
    if not defaults:
        return None, "⚠️ رله پیش‌فرض مشخص نیست؛ وضعیت DNS را بررسی کنید."
    selected = defaults[0]
    if selected == core_ip:
        return None, "⚠️ Core به‌عنوان پیش‌فرض ثبت شده؛ رله Edge مشخص نیست."
    row = next((r for r in pool if r[0] == selected), None)
    if row is None or not row[1]:
        return None, "⚠️ رله پیش‌فرض غیرفعال است؛ فعال‌بودن تأیید نمی‌شود."
    if dns_ip != selected:
        return selected, "⚠️ IP پیش‌فرض و IP ثبت‌شده برای دامنه متفاوت‌اند؛ اتصال واقعی تأیید نشده است."
    return selected, ""


def overview(core_ip: str, pool, dns_ip: str, page: int = 0):
    selected, warning = relay_selection(pool, core_ip, dns_ip)
    edges = [r for r in pool if r[0] != core_ip]
    edges.sort(key=lambda r: (r[0] != selected, not bool(r[1]), r[0]))
    page_count = max(1, (len(edges) + PAGE_SIZE - 1) // PAGE_SIZE)
    page = max(0, min(page if type(page) is int else 0, page_count - 1))
    active = sum(bool(r[1]) for r in edges)
    inactive = len(edges) - active
    lines = [
        "🖥 <b>مدیریت سرورهای Core / Edge</b>", "",
        f"🏠 Core: <code>{escape(core_ip)}</code>",
        f"🎯 رله منتخب: <code>{escape(selected)}</code>" if selected else "🎯 رله منتخب: <b>نامشخص</b>",
        f"🌐 IP دامنه (ثبت‌شده): <code>{escape(dns_ip or '—')}</code>",
        f"🟢 فعال: {active}  |  🔴 غیرفعال: {inactive}",
    ]
    if warning:
        lines.extend(("", warning))
    lines.extend(("", "برای مشاهده عملیات، IP سرور را انتخاب کنید."))
    buttons = [[("👑 Core · " + core_ip, "srv_view_" + core_ip)]]
    for row in edges[page * PAGE_SIZE:(page + 1) * PAGE_SIZE]:
        ip, is_active = row[0], bool(row[1])
        icon = "🎯" if ip == selected else ("🟢" if is_active else "🔴")
        label = "رله منتخب" if ip == selected else ("آماده" if is_active else "غیرفعال")
        buttons.append([(f"{icon} {ip} · {label}", "srv_view_" + ip)])
    nav = []
    if page > 0:
        nav.append(("◀️ قبلی", "srv_page_" + str(page - 1)))
    if page + 1 < page_count:
        nav.append(("بعدی ▶️", "srv_page_" + str(page + 1)))
    if nav:
        buttons.append(nav)
    if page_count > 1:
        lines.append(f"صفحه {page + 1} از {page_count}")
    buttons.extend([
        [("🔄 بروزرسانی", "srv_status")],
        [("🔙 تنظیمات سرور", "srv_menu_back")],
    ])
    return "\n".join(lines), buttons


def detail(core_ip: str, host: str, pool, dns_ip: str,
           service_port: int, admin_port: int, key_ok: bool | None = None):
    checked_ip(host)
    if host != core_ip and not any(r[0] == host for r in pool):
        raise ValueError("HOST_NOT_FOUND")
    row = next((r for r in pool if r[0] == host), None)
    selected, warning = relay_selection(pool, core_ip, dns_ip)
    core = host == core_ip
    active = bool(row[1]) if row else core
    status = ("👑 Core" if core else
              "🎯 رله منتخب" if host == selected else
              "🟢 آماده به کار" if active else "🔴 غیرفعال")
    lines = [
        "🖥 <b>جزئیات سرور</b>", "",
        f"🌐 IP: <code>{escape(host)}</code>",
        f"📌 وضعیت: <b>{status}</b>",
        f"🔌 Service: <code>{service_port}</code> | Admin: <code>{admin_port}</code>",
    ]
    if warning and (host == selected or host == dns_ip or core):
        lines.extend(("", warning))
    buttons = []
    if core:
        buttons.extend([
            [("📉 تنزل به Edge", "srv_demote_" + host)],
            [("⚡ بهینه‌سازی سرعت", "srv_optimize_" + host)],
        ])
    else:
        if active and host != selected:
            buttons.append([("🎯 تنظیم به عنوان رله فعال", "srv_mkactive_" + host)])
        buttons.extend([
            [("🚀 ارتقا به Core", "srv_promote_" + host),
             ("🔄 آپدیت Endpoint", "srv_update_ep_" + host)],
            [("⚡ بهینه‌سازی سرعت", "srv_optimize_" + host)],
        ])
        key_icon = "✅" if key_ok else "❌" if key_ok is False else "❔"
        buttons.append([(key_icon + " نصب دسترسی دائمی SSH", "srv_installkey_" + host)])
        if not active:
            buttons.append([("🗑 حذف از فهرست", "srv_del_" + host)])
    buttons.extend([
        [("🔄 بروزرسانی جزئیات", "srv_view_" + host)],
        [("🔙 فهرست سرورها", "srv_status")],
    ])
    return "\n".join(lines), buttons


def _table(conn, name: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (name,),
    ).fetchone() is not None


def _registry_blocker(host: str) -> str | None:
    """Fail closed if the host is still registered as protected ingress."""
    from edge_egress_v1_ingress import REGISTRY, load_registry
    if not Path(REGISTRY).exists():
        return None
    try:
        peers = load_registry()
    except (OSError, ValueError):
        return "رجیستری ورودی قابل اعتبارسنجی نیست؛ حذف متوقف شد."
    if any(peer.edge_ipv4 == host for peer in peers):
        return "این IP هنوز در رجیستری ورودی Edge ثبت شده است."
    return None


def _blocker(conn, host: str, core_ip: str) -> str | None:
    checked_ip(host)
    checked_ip(core_ip)
    if host == core_ip:
        return "حذف سرور Core مجاز نیست."
    row = conn.execute(
        "SELECT active, is_default FROM host_pool WHERE host=?", (host,)
    ).fetchone()
    if row is None:
        return "سرور در فهرست وجود ندارد یا قبلاً حذف شده است."
    if bool(row[0]):
        return "سرور هنوز فعال است؛ حذف فقط برای موارد غیرفعال مجاز است."
    if bool(row[1]):
        return "این سرور پیش‌فرض است؛ حذف مجاز نیست."
    settings = dict(conn.execute(
        "SELECT key, value FROM settings WHERE key IN ('hosts','dns_current_ip')"
    ).fetchall())
    if host == settings.get("dns_current_ip"):
        return "دامنه هنوز به این IP اشاره می‌کند."
    if host in [h.strip() for h in (settings.get("hosts") or "").split(",")]:
        return "این IP هنوز در تنظیمات سرویس‌دهی hosts وجود دارد."
    if conn.execute(
        "SELECT 1 FROM ssh_accounts WHERE host=? LIMIT 1", (host,)
    ).fetchone():
        return "حساب SSH به این IP متصل است."
    if _table(conn, "domains") and conn.execute(
        "SELECT 1 FROM domains WHERE host=? LIMIT 1", (host,)
    ).fetchone():
        return "یک دامنه به این سرور وابسته است."
    if _table(conn, "edge_egress_allocations") and conn.execute(
        "SELECT 1 FROM edge_egress_allocations WHERE edge_public_ipv4=? LIMIT 1",
        (host,),
    ).fetchone():
        return "برای این IP تخصیص محافظت‌شده ثبت شده است."
    if _table(conn, "failover_operations") and conn.execute(
        "SELECT 1 FROM failover_operations WHERE finished_at IS NULL "
        "AND (source_host=? OR target_host=?) LIMIT 1", (host, host)
    ).fetchone():
        return "عملیات Failover ناتمام به این IP وابسته است."
    if _table(conn, "filter_incidents") and conn.execute(
        "SELECT 1 FROM filter_incidents WHERE closed_at IS NULL "
        "AND (source_host=? OR target_host=?) LIMIT 1", (host, host)
    ).fetchone():
        return "رخداد بازِ پایش به این IP وابسته است."
    return _registry_blocker(host)


def deletion_preview(db_conn, host: str, core_ip: str, guard=None):
    try:
        with db_conn() as conn:
            if guard:
                guard(conn)
            reason = _blocker(conn, host, core_ip)
            return not bool(reason), reason or "این IP غیرفعال و فاقد وابستگی شناخته‌شده است."
    except (ValueError, RuntimeError, Exception):
        return False, "بررسی ایمنی حذف ناموفق بود؛ هیچ تغییری انجام نشد."


def delete_inactive(db_conn, host: str, core_ip: str, guard=None):
    """Metadata-only, atomic recheck; never remove a VPS or any network state."""
    try:
        with db_conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if guard:
                guard(conn)
            reason = _blocker(conn, host, core_ip)
            if reason:
                return False, reason
            changed = conn.execute(
                "DELETE FROM host_pool WHERE host=? AND active=0 "
                "AND COALESCE(is_default, 0)=0",
                (host,),
            ).rowcount
            if changed != 1:
                raise RuntimeError("HOST_DELETE_RACE")
            return True, "رکورد مدیریتی IP از فهرست حذف شد؛ تنظیمات سرور تغییر نکرد."
    except Exception:
        return False, "حذف ایمن انجام نشد؛ وضعیت سرور را دوباره بررسی کنید."
