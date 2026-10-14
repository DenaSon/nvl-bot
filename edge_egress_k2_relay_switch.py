"""K2 relay selection presentation: preserve exact Legacy traffic semantics.

Legacy 'make default' changes host_pool / invoice-host selection; an optional
second confirmation changes ssh_accounts.host and public Cloudflare ingress.
Neither moves Linux accounts nor establishes protected outgoing SSH/SOCKS IP.

This source-only review NEVER calls those legacy mutators. In protected
operation the same 6G guarded data-plane and P3-D ingress handoff must be
accepted before any global default/DNS traffic change can be released.
"""
from __future__ import annotations

from dataclasses import dataclass
from html import escape
from ipaddress import IPv4Address

from edge_egress_v1_console import edge_id_checked


@dataclass(frozen=True)
class RelayTrafficReview:
    edge_id: str
    edge_ip: str
    current_default: str
    current_dns: str
    active_ssh_accounts: int
    destination_is_default: bool
    blockers: tuple[str, ...]
    execution_available: bool = False


def review_relay_traffic(board, card, transfer_preview) -> RelayTrafficReview:
    """A pure legacy-compatible route-intent review; never executes writes."""
    eid = edge_id_checked(card.edge_id)
    target = str(IPv4Address(card.ip))
    if target != card.ip or not IPv4Address(target).is_global:
        raise ValueError("EDGE_PUBLIC_IP_NOT_CANONICAL")
    if transfer_preview.edge_id != eid or transfer_preview.edge_ip != target:
        raise ValueError("K2_TRANSFER_PREVIEW_EDGE_DRIFT")
    default = str(board.default_ip or "")
    dns = str(board.dns_ip or "")
    blockers = list(transfer_preview.blockers)
    if not card.pool_active or not card.ingress_verified:
        blockers.append("رله ورودی فعال و تأییدشده نیست")
    if default != dns:
        blockers.append("رله پیش‌فرض و DNS فعلی همخوان نیستند")
    # Do not infer real packet ownership from selection in host_pool.
    blockers.append("تغییر رله فقط پس از تأیید واقعی مسیر خروجی مجاز است")
    return RelayTrafficReview(
        eid, target, default, dns, transfer_preview.ssh_accounts,
        default == target, tuple(dict.fromkeys(blockers)), False,
    )


def relay_traffic_html(review: RelayTrafficReview) -> str:
    if review.execution_available:
        raise ValueError("UNREVIEWED_RELAY_EXECUTION_MUST_NOT_BE_RENDERED")
    title = "🔀 <b>تغییر مسیر ترافیک</b>"
    lines = [
        title, "",
        "رله فعلی: <code>" + escape(review.current_default or "—") + "</code>",
        "رله انتخابی: <code>" + escape(review.edge_ip) + "</code>",
        "دامنه فعلی: <code>" + escape(review.current_dns or "—") + "</code>",
        f"حساب‌های SSH فعال: <b>{review.active_ssh_accounts}</b>",
        "",
        "همه حساب‌ها روی Core باقی می‌مانند؛ فقط مسیر اتصال و خروجی تغییر می‌کند.",
        "در مسیر قبلی، پیش‌فرض/هاست حساب و DNS تغییر می‌کرد؛ "
        "IP خروجی از Core مستقل نبود.",
        "",
        "⛔ <b>سوییچ ترافیک فعلاً انجام نمی‌شود.</b>",
        "اول باید خروجی اینترنت کاربران از خود Edge اثبات شود.",
    ]
    return "\n".join(lines)


def relay_traffic_buttons(review: RelayTrafficReview):
    eid = edge_id_checked(review.edge_id)
    return [
        [("👥 بررسی ترافیک کاربران", f"hpeg_transfer_{eid}"),
         ("🔎 بررسی اتصال", f"hpeg_health_{eid}")],
        [("◀️ جزئیات سرور", f"hpeg_edge_{eid}")],
    ]
