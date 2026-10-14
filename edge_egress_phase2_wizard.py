"""Phase 2 final: presentation and opt-in contract for the EXISTING Edge wizard.

A selected Telegram entrypoint enables Stage-only Egress for ONE new Edge
installation. This module never executes provisioning, changes settings,
routes customers, makes an Edge default or declares F4 READY.
"""
from __future__ import annotations

from html import escape
from ipaddress import IPv4Address

from edge_egress_v1_console import edge_id_checked, EgressConsoleHold


def new_edge_prompt(*, integrated: bool) -> str:
    if type(integrated) is not bool:
        raise EgressConsoleHold("INVALID_EDGE_WIZARD_FLOW")
    if integrated:
        return (
            "🚀 <b>افزودن Edge — Ingress + Egress</b>\n\n"
            "از همان Wizard نصب Edge استفاده می‌کنیم؛ بعد از راه‌اندازی "
            "WireGuard ورودی، برای همین سرور Stage اختصاصی Egress "
            "نیز آماده می‌شود.\n\n"
            "✅ فعلاً فقط نصب ورودی و ساخت Stage خروجی انجام می‌شود.\n"
            "🔒 فعال‌سازی رله پیش‌فرض، اتصال کاربران، DNS و "
            "انتشار F4 READY انجام نمی‌شود.\n"
            "⚠️ سرور باید <b>جدید و خام</b> باشد؛ اگر قبلاً ثبت شده، "
            "از «جزئیات Edge» برای بررسی استفاده کنید.\n\n"
            "۱) IP عمومی VPS جدید را ارسال کنید:"
        )
    return (
        "🚀 <b>افزودن Edge ورودی (Legacy)</b>\n\n"
        "VPS جدید با WireGuard به Core متصل و در استخر ورودی ثبت می‌شود.\n"
        "این مسیر به‌تنهایی Egress امن یا خروج کاربران از Edge را اثبات نمی‌کند.\n\n"
        "۱) IP عمومی VPS جدید را ارسال کنید:"
    )


def staged_edge_result(edge_ip: str, result: dict) -> tuple[str, str]:
    """Only a real Stage-only outcome may reveal next read-only actions."""
    try:
        ip = IPv4Address(edge_ip)
    except (TypeError, ValueError) as exc:
        raise EgressConsoleHold("INVALID_NEW_EDGE_IP") from exc
    if not ip.is_global or str(ip) != edge_ip or not isinstance(result, dict):
        raise EgressConsoleHold("INVALID_NEW_EDGE_STAGE_OUTCOME")
    stage = result.get("egress_v1")
    if not isinstance(stage, dict) or stage.get("egress_state") != "STAGED_NOT_READY":
        raise EgressConsoleHold("INCOMPLETE_NEW_EDGE_STAGE_HOLD")
    eid = edge_id_checked(stage.get("edge_id"))
    if stage.get("ingress_ipv4") != result.get("edge_wg_ip"):
        raise EgressConsoleHold("INGRESS_STAGE_IDENTITY_MISMATCH")
    # The returned paths are intentionally not displayed: a user does not
    # need filesystem internals, password, keys, or root-owned stage content.
    body = (
        "📦 <b>Edge جدید — مراحل نصب و آماده‌سازی</b>\n\n"
        f"🌍 IP: <code>{escape(edge_ip)}</code>\n"
        f"🖥 شناسه: <code>{escape(eid)}</code>\n"
        "✅ ۱/۳ — Ingress: اتصال WireGuard ثبت شد؛ هنوز وارد استخر فعال مشتریان نشده.\n"
        "✅ ۲/۳ — Egress: Stage اختصاصی ساخته شد؛ هنوز فعال/تأیید نشده.\n"
        "⏳ ۳/۳ — بررسی و پذیرش امنیتی: <b>HOLD</b>\n\n"
        "ℹ️ عضویت فعال در استخر برای پایش ورودی است؛ "
        "به‌معنی رله پیش‌فرض، Egress کاربران یا F4 READY نیست.\n"
        "🔒 برای آماده‌سازی Production، "
        "ابتدا بررسی Stage، Fail-Closed و تست‌های Core لازم است.\n"
        "⚠️ اگر سرور دیگری را اضافه می‌کنید، "
        "از این اطلاعات برای راه‌اندازی مجدد همین Edge استفاده نکنید."
    )
    return body, eid
