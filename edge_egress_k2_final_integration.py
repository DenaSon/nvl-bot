"""K2 final integration: read-only traffic-route readiness in the existing Telegram Edge panel.

This is deliberately NOT the migration executor. The legacy bulk-host/DNS writer
never establishes per-UID Egress. No UI path in this module writes host, routes,
Cloudflare, F4 READY, UID mappings or the shared 6G journal.
"""
from __future__ import annotations

from dataclasses import dataclass
from html import escape
from ipaddress import IPv4Address
from typing import Callable

from edge_egress_v1_console import edge_id_checked
from edge_egress_k2_source_cohort import read_source_cohort, CohortHold

K2_TRANSFER_EXECUTOR_RELEASED = False


@dataclass(frozen=True)
class TransferPreview:
    edge_id: str
    edge_ip: str
    ssh_accounts: int
    blockers: tuple[str, ...]
    can_probe: bool
    source_host: str = ""
    other_edge_accounts: int = 0
    already_target_accounts: int = 0
    unknown_accounts: int = 0
    active_total: int = 0

    @property
    def can_execute(self) -> bool:
        # Only a separately audited root worker may change this contract.
        return not self.blockers and K2_TRANSFER_EXECUTOR_RELEASED


def _table(conn, name: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def read_transfer_preview(db_conn: Callable, card, transport) -> TransferPreview:
    """Observe one Edge and aggregate count without persisting or assigning anything."""
    eid = edge_id_checked(card.edge_id)
    try:
        ip = IPv4Address(card.ip)
    except (TypeError, ValueError) as exc:
        raise ValueError("EDGE_IP_NOT_VERIFIED") from exc
    if not ip.is_global or str(ip) != card.ip:
        raise ValueError("EDGE_IP_NOT_VERIFIED")

    reasons = []
    if not card.ingress_verified or not card.pool_active:
        reasons.append("اتصال ورودی تأیید نشده")
    if card.allocation != "STAGED" or not card.stage_pin:
        reasons.append("آماده‌سازی خروجی ثبت و تأیید نشده")
    if getattr(transport, "state", None) != "UP":
        reasons.append("تونل خروجی آماده نیست")
    if not card.f4_valid:
        reasons.append("آزمون مستقل خروجی تأیید نشده")

    count = other = already_target = unknown = total = 0
    source = ""
    try:
        cohort = read_source_cohort(db_conn, str(ip))
        count, source = cohort.source_accounts, cohort.source_ip
        other, already_target = cohort.other_edge_accounts, cohort.already_target_accounts
        unknown, total = cohort.unknown_accounts, cohort.active_total
        reasons.extend(cohort.blockers)
    except CohortHold:
        reasons.append("مالکیت حساب‌های مبدأ قابل تأیید نیست")
    with db_conn() as conn:
        if not _table(conn, "settings") or not _table(conn, "ssh_accounts"):
            reasons.append("اطلاعات حساب‌ها کامل نیست")
        else:
            mode = conn.execute(
                "SELECT value FROM settings WHERE key='edge_egress_protected_mode'"
            ).fetchone()
            if mode != ("1",):
                reasons.append("محافظت کاربران فعال یا تأیید نشده")
        if not _table(conn, "failover_operations"):
            reasons.append("کنترل انتقال در دسترس نیست")
        elif conn.execute(
            "SELECT 1 FROM failover_operations WHERE status='RUNNING' LIMIT 1"
        ).fetchone():
            reasons.append("عملیات انتقال دیگری در جریان است")

    # F4 DB status and stage/transport observation cannot replace independent
    # Linux/PAM/Boot/packet evidence or privileged worker acceptance.
    if not K2_TRANSFER_EXECUTOR_RELEASED:
        reasons.append("انتقال امن هنوز برای اجرا آزاد نشده")

    return TransferPreview(
        eid, str(ip), count, tuple(dict.fromkeys(reasons)), bool(card.can_probe),
        source, other, already_target, unknown, total,
    )


def transfer_preview_html(preview: TransferPreview) -> str:
    body = [
        "👥 <b>مسیر ترافیک کاربران</b>", "",
        "سرور: <code>" + escape(preview.edge_id, quote=True) + "</code>",
        "IP مقصد: <code>" + escape(preview.edge_ip, quote=True) + "</code>",
        f"رله مبدأ: <code>{escape(preview.source_host or '—', quote=True)}</code>",
        f"کاربران مبدأ: <b>{preview.ssh_accounts}</b>",
        f"کاربران سایر سرورها (بدون تغییر): <b>{preview.other_edge_accounts}</b>",
        f"کاربران روی مقصد: <b>{preview.already_target_accounts}</b>",
        *(('⚠️ حساب‌های بدون مالک مشخص: <b>' + str(preview.unknown_accounts) + '</b>',)
          if preview.unknown_accounts else ()),
        "",
    ]
    if preview.can_execute:
        body.append("✅ آماده تأیید انتقال محافظت‌شده")
    else:
        body.append("⛔ <b>تغییر مسیر فعلاً متوقف است.</b>")
        body.extend("• " + escape(x, quote=True) for x in preview.blockers)
        body.extend(("", "حساب‌ها روی Core می‌مانند؛ تغییر IP اتصال بدون مسیر خروجی محافظت‌شده کافی نیست."))
    return "\n".join(body)


def transfer_preview_buttons(preview: TransferPreview) -> list[list[tuple[str, str]]]:
    eid = edge_id_checked(preview.edge_id)
    result = [
        [("👤 بررسی یک کاربر", f"hpeg_user_{eid}"),
         ("🔄 بررسی دوباره", f"hpeg_transfer_{eid}")],
    ]
    if preview.can_probe:
        result.append([("🌍 تست IP خروجی", f"hpeg_probe_{eid}")])
    result.append([("◀️ جزئیات سرور", f"hpeg_edge_{eid}")])
    # No bulk/execute callback until the actual privileged cohort executor is accepted.
    return result
