"""DenaProbe administrator telemetry dashboard for the existing NVLBot.

Read-only SQLite metrics; private-chat active admins only. No collector API,
HMAC keys, raw payloads, autonomous alerts, or SSH/GOST/DNS actions.
"""
from __future__ import annotations

import asyncio
import html
import logging
import os
import sqlite3
from pathlib import Path

from denaprobe_ingest.metrics import build_report

LOG = logging.getLogger(__name__)
DEFAULT_DEVICE = "dp-mci-01"
CALLBACKS = frozenset(("apps_dpt_24", "apps_dpt_168"))


def authorized(*, role: str | None, actor: int | None, chat: int | None,
               is_private: bool, active_admin_ids) -> bool:
    return (role == "admin" and type(actor) is int and type(chat) is int
            and actor > 0 and actor == chat and is_private
            and actor in set(active_admin_ids))


def _format_ms(field: dict) -> str:
    p50, p95 = field["p50_ms"], field["p95_ms"]
    if p50 is None:
        return "—"
    return f"{p50:,} / {p95:,} ms"


def render(report: dict) -> str:
    device = html.escape(report["device_id"])
    events = report["events"]
    live = report["live"]
    ssh = report["ssh"]
    https = report["https"]
    truncated = "\n⚠️ حجم داده به سقف گزارش رسیده؛ نتایج جزئی هستند." if report["truncated"] else ""
    gap = "بله" if live["monitoring_gap"] else "خیر"
    return (
        f"📡 <b>DenaProbe | کیفیت پایش</b>\n"
        f"━━━━━━━━━━━━━━\n"
        f"برد: <code>{device}</code> · بازه: {report['window_hours']} ساعت\n"
        f"\n"
        f"🛰 <b>دریافت و پیوستگی</b>\n"
        f"• ثبت‌شده: <b>{events['stored']:,}</b> رویداد\n"
        f"• شکاف مشاهده‌شده Sequence: <b>{events['observed_missing_sequences']:,}</b>\n"
        f"• تاریخچه-only: {events['history_only']:,} · کد ناشناخته: {events['unknown_codes']:,}\n"
        f"• سن ارسال P50/P95: {_format_ms(report['sender_age'])}\n"
        f"\n"
        f"🔐 <b>SSH Transport</b>\n"
        f"• PASS: <b>{ssh['pass']:,}</b> · نتیجه مسیر غیرموفق: {ssh['path_nonpass']:,}\n"
        f"• خطای محلی: {ssh['local']:,} · اعتماد/کلید: {ssh['trust']:,}\n"
        f"• DNS P50/P95: {_format_ms(ssh['dns'])}\n"
        f"• Transport P50/P95: {_format_ms(ssh['transport'])}\n"
        f"• Service Accept P50/P95: {_format_ms(ssh['service_accept'])}\n"
        f"\n"
        f"🌐 <b>HTTPS مستقل</b>\n"
        f"• PASS: {https['pass']:,} · SLOW: {https['slow']:,}\n"
        f"• نامشخص/محلی: {https['unmeasurable']:,} · سایر خطاها: {https['other']:,}\n"
        f"• Body P50/P95: {_format_ms(https['body_transfer'])}\n"
        f"\n"
        f"🧭 <b>وضعیت زنده</b>\n"
        f"• SSH: {live['ssh_sequence'] or '—'} ({live['ssh_freshness']})\n"
        f"• HTTPS: {live['https_sequence'] or '—'} ({live['https_freshness']})\n"
        f"• تحویل: {live['delivery_freshness']} · شکاف پایش: {gap}\n"
        f"\n"
        f"ℹ️ سن ارسال، زمان صف‌شدن نزد برد است؛ نه RTT شبکه. "
        f"شکاف Sequence و سکوت دستگاه به‌تنهایی اثبات قطعی SSH یا فیلترینگ نیست."
        f"{truncated}"
    )


async def handle_dashboard(query, *, data: str, role: str | None,
                           actor: int | None, chat: int | None,
                           is_private: bool, active_admin_ids):
    """Handle only fixed callbacks, never trust stored role alone."""
    if data not in CALLBACKS:
        return False
    if not authorized(role=role, actor=actor, chat=chat,
                      is_private=is_private, active_admin_ids=active_admin_ids):
        await query.message.reply_text("⛔️ این گزارش فقط در گفت‌وگوی خصوصی مدیر فعال است.")
        return True
    # Never accept a callback-supplied path/device ID. Operators configure
    # the private DB path and device ID outside Telegram.
    hours = 168 if data == "apps_dpt_168" else 24
    device = os.environ.get("DENAPROBE_DASHBOARD_DEVICE_ID", DEFAULT_DEVICE)
    db = Path(os.environ.get("DENAPROBE_TELEMETRY_DB",
                             "/var/lib/denaprobe/telemetry.sqlite3"))
    try:
        report = await asyncio.to_thread(build_report, db, device, hours)
    except (OSError, ValueError, sqlite3.Error):
        LOG.warning("DenaProbe read-only dashboard unavailable", exc_info=True)
        content = ("📡 <b>DenaProbe</b>\n"
                   "⚠️ گزارش فعلاً در دسترس نیست. اتصال و مجوز خواندن دیتابیس را بررسی کنید.")
    else:
        content = render(report)
    from telegram import InlineKeyboardButton, InlineKeyboardMarkup
    from telegram.error import BadRequest
    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("۲۴ ساعت", callback_data="apps_dpt_24"),
         InlineKeyboardButton("۷ روز", callback_data="apps_dpt_168")],
        [InlineKeyboardButton("🔄 بروزرسانی", callback_data=data)],
        [InlineKeyboardButton("↩️ برنامه‌ها", callback_data="apps_home")],
    ])
    try:
        await query.edit_message_text(
            content, parse_mode="HTML", reply_markup=keyboard)
    except BadRequest as exc:
        # Two immediate refresh taps can produce identical text/markup.
        if "Message is not modified" not in str(exc):
            raise
    return True
