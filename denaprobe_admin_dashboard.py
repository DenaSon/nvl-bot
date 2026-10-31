"""Read-only, private-admin DenaProbe telemetry dashboard for NVLBot.

UX labels describe *measurement confidence*, never declare censorship, a VPN
health verdict, or an outage based solely on missing/old telemetry.
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
REPORT_24 = "apps_dpt_24"
REPORT_168 = "apps_dpt_168"
GUIDE_24 = "apps_dpt_help_24"
GUIDE_168 = "apps_dpt_help_168"
CALLBACKS = frozenset((REPORT_24, REPORT_168, GUIDE_24, GUIDE_168))
GUIDE_CALLBACKS = frozenset((GUIDE_24, GUIDE_168))


def authorized(*, role: str | None, actor: int | None, chat: int | None,
               is_private: bool, active_admin_ids) -> bool:
    return (role == "admin" and type(actor) is int and type(chat) is int
            and actor > 0 and actor == chat and is_private
            and actor in set(active_admin_ids))


def _format_duration(ms: int | None) -> str:
    """Human units. Avoid printing 92,584ms without context."""
    if ms is None:
        return "—"
    if ms < 1000:
        return f"{ms:,}ms"
    if ms < 10000:
        return f"{ms / 1000:.2f}s"
    return f"{ms / 1000:.1f}s"


def _p(field: dict) -> str:
    """Nearest-rank P50/P95; show denominator to avoid spurious precision."""
    if field["count"] == 0:
        return "<code>—</code> (نمونه ندارد)"
    return (f"<code>{_format_duration(field['p50_ms'])} / "
            f"{_format_duration(field['p95_ms'])}</code> "
            f"(n={field['count']:,})")


def _freshness(value: str) -> str:
    return {
        "FRESH": "🟢 تازه",
        "STALE": "🟠 قدیمی",
        "NOT_TESTED": "⚪ ثبت‌نشده",
        "CLOCK_ANOMALY": "🟠 اختلاف زمان",
    }.get(value, "⚪ نامشخص")


def _coverage_status(live: dict) -> str:
    """Only data quality/continuity, not SSH availability."""
    if live["delivery_freshness"] != "FRESH":
        return "⚪ <b>دریافت داده تازه تأیید نشده</b>"
    if live["ssh_freshness"] != "FRESH":
        return "🟠 <b>نمونه تازه SSH در دسترس نیست</b>"
    if live["monitoring_gap"] != 0:
        return "🟠 <b>پیوستگی نمونه‌های SSH تأیید نشده</b>"
    return "🟢 <b>داده SSH تازه و پیوسته است</b>"


def _sequence(number: int | None) -> str:
    return f"<code>#{number}</code>" if number is not None else "—"


def render(report: dict) -> str:
    """Compact RTL-friendly page: separated values and inline short glossary."""
    device = html.escape(report["device_id"])
    events, live, ssh = report["events"], report["live"], report["ssh"]
    https = report["https"]
    history = events["history_only"]
    usable_ssh = sum(ssh[key] for key in ("pass", "path_nonpass", "local", "trust", "unknown"))
    window = ("۲۴ ساعت" if report["window_hours"] == 24 else "۷ روز")
    truncated = ("\n⚠️ این گزارش به سقف نمونه‌ها رسیده و ممکن است ناقص باشد."
                 if report["truncated"] else "")
    unknown = (f"\n• کدهای ناشناخته: <b>{events['unknown_codes']:,}</b>"
               if events["unknown_codes"] else "")
    history_note = ("⚠️ بعضی گزارش‌ها برای وضعیت زنده قابل‌استفاده نبوده‌اند.\n"
                    if history else "")
    return (
        "📡 <b>DenaProbe | کیفیت پایش</b>\n"
        f"برد: <code>{device}</code>\n"
        f"بازه بررسی: <b>{window} گذشته</b>\n\n"
        "🧭 <b>ارزیابی وضعیت داده‌ها</b>\n"
        f"{_coverage_status(live)}\n"
        f"• دریافت از برد: {_freshness(live['delivery_freshness'])}\n"
        f"• آخرین SSH: {_sequence(live['ssh_sequence'])} · {_freshness(live['ssh_freshness'])}\n"
        f"• آخرین HTTPS: {_sequence(live['https_sequence'])} · {_freshness(live['https_freshness'])}\n"
        f"• شکاف پایش زنده: <b>{'وجود دارد' if live['monitoring_gap'] else 'ندارد'}</b>\n\n"
        "📥 <b>کیفیت دریافت گزارش‌ها</b>\n"
        f"• رویداد ثبت‌شده: <b>{events['stored']:,}</b>\n"
        f"• شکاف شماره‌های ثبت‌شده: <b>{events['observed_missing_sequences']:,}</b>\n"
        f"• رویداد تاریخی (غیرزنده): <b>{history:,}</b>\n"
        f"• سن ارسال P50 / P95: {_p(report['sender_age'])}"
        f"{unknown}\n"
        f"{history_note}\n"
        "🔐 <b>کیفیت SSH (نمونه‌های معتبر)</b>\n"
        f"• موفق: <b>{ssh['pass']:,}</b> از <b>{usable_ssh:,}</b> نمونه\n"
        f"• نتیجه ناموفق مسیر: <b>{ssh['path_nonpass']:,}</b>\n"
        f"• خطای محلی: {ssh['local']:,} · خطای اعتماد: {ssh['trust']:,}\n"
        "• زمان‌های زیر: <b>P50 / P95</b>\n"
        f"  DNS: {_p(ssh['dns'])}\n"
        f"  SSH Transport: {_p(ssh['transport'])}\n"
        f"  Service Accept: {_p(ssh['service_accept'])}\n\n"
        "🌐 <b>HTTPS عمومی (مستقل از SSH)</b>\n"
        f"• موفق: <b>{https['pass']:,}</b> · کند: <b>{https['slow']:,}</b>\n"
        f"• غیرقابل‌اندازه‌گیری: {https['unmeasurable']:,} · سایر: {https['other']:,}\n"
        f"• دریافت بدنه P50 / P95: {_p(https['body_transfer'])}\n\n"
        "📖 <b>راهنمای سریع تفسیر</b>\n"
        "• <b>تازه</b>: اخیراً ثبت شده؛ الزاماً به معنی اتصال سالم نیست.\n"
        "• <b>P50 / P95</b>: میانه / مقدار ۹۵٪ نمونه‌ها.\n"
        "• <b>سن ارسال</b>: فاصله اندازه‌گیری تا ارسال از برد؛ نه پینگ.\n"
        "• <b>تاریخی</b>: ذخیره شده، اما وضعیت زنده را تغییر نداده.\n"
        "• <b>شکاف</b>: فاصله شماره‌های دریافتی؛ نه اثبات گم‌شدن بسته شبکه.\n"
        "برای توضیح هر شاخص، «راهنمای کامل» را باز کنید."
        f"{truncated}"
    )


def render_guide() -> str:
    """Static definitions. This view never queries SQLite."""
    return (
        "📖 <b>راهنمای تفسیر شاخص‌های DenaProbe</b>\n\n"
        "🧭 <b>وضعیت زنده</b>\n"
        "• <b>دریافت از برد</b>: تازگی آخرین رویداد ثبت‌شده روی سرور "
        "(سیاست اولیه: ۱۸۰ ثانیه).\n"
        "• <b>SSH تازه</b>: زمان دریافت آخرین نمونه معتبر SSH حداکثر "
        "۹۰ ثانیه قبل باشد.\n"
        "• <b>HTTPS تازه</b>: زمان دریافت آخرین نمونه HTTPS حداکثر "
        "۳۶۰ ثانیه قبل باشد.\n"
        "• <b>شکاف پایش زنده</b>: نبود پیوستگی تأییدشده بین دو مشاهده "
        "متوالی و تازه SSH. با شکاف کل تاریخچه متفاوت است.\n"
        "• <b>شماره #</b>: شناسه ترتیبی رویداد در همان نوبت روشن‌شدن برد؛ "
        "مقیاس زمان یا تعداد قطعی نیست.\n\n"
        "📥 <b>دریافت و اطمینان داده</b>\n"
        "• <b>رویداد ثبت‌شده</b>: مجموع پیام‌های ذخیره‌شده، شامل "
        "روشن‌شدن، وضعیت محلی و نتیجه SSH.\n"
        "• <b>شکاف شماره‌ها</b>: شماره‌های غایب بین دو رویداد ذخیره‌شده "
        "از یک Boot در بازه انتخابی؛ لزوماً Packet Loss نیست.\n"
        "• <b>تاریخی / History Only</b>: رویداد ذخیره‌شده‌ای که "
        "به‌علت شرایطی مثل تأخیر یا ترتیب، وارد وضعیت زنده نشده است.\n"
        "• <b>سن ارسال</b>: زمان سپری‌شده روی برد از اندازه‌گیری تا "
        "اقدام به ارسال؛ زمان کامل شبکه/سرور یا RTT نیست.\n"
        "• <b>کد ناشناخته</b>: وضعیت عددی‌ای که Collector نمی‌شناسد؛ "
        "به معنی اختلال مسیر نیست.\n\n"
        "📊 <b>روش خواندن زمان‌ها</b>\n"
        "• <b>P50</b>: میانه؛ تقریباً نصف نمونه‌ها در این زمان یا کمترند.\n"
        "• <b>P95</b>: تقریباً ۹۵٪ نمونه‌ها در این زمان یا کمترند؛ "
        "جهش‌های نادر را بهتر از میانگین نشان می‌دهد.\n"
        "• <b>n</b>: تعداد نمونه‌های مبنای همان شاخص. "
        "با n کم، تفسیر P95 باید محتاطانه باشد.\n\n"
        "🔐 <b>SSH</b>\n"
        "• <b>موفق</b>: دریافت SERVICE_ACCEPT پس از Transport و "
        "بررسی کلید میزبان؛ ورود کاربر یا VPN آزمایش نشده.\n"
        "• <b>ناموفق مسیر</b>: نتیجه شبکه/SSH در طبقه خطا؛ "
        "به‌تنهایی دلیل فیلترینگ نیست.\n"
        "• <b>خطای محلی</b>: خود برد یا شرایط تست مانع اندازه‌گیری بوده.\n"
        "• <b>خطای اعتماد</b>: بررسی هویت/کلید میزبان یا اعتبارسنجی ناموفق.\n"
        "• <b>DNS</b>: مدت تبدیل نام مقصد به IP.\n"
        "• <b>Transport</b>: مدت پیشروی تبادل SSH و برقراری Transport.\n"
        "• <b>Service Accept</b>: زمان دریافت پذیرش سرویس پس از Transport.\n\n"
        "🌐 <b>HTTPS مستقل</b>\n"
        "• آزمایش دانلود از مقصد عمومی Cloudflare از مسیر مستقیم هات‌اسپات "
        "است؛ مسیر VPN یا احراز هویت SSH را اندازه نمی‌گیرد.\n"
        "• <b>موفق</b>: آزمایش HTTPS کامل؛ <b>کند</b>: دریافت بدنه "
        "از آستانه نمونه عبور کرده، نه الزاماً کندی کل اینترنت.\n"
        "• <b>غیرقابل‌اندازه‌گیری</b>: مانند آماده‌نبودن ساعت دستگاه.\n"
        "• <b>دریافت بدنه</b>: مدت انتقال بدنه نمونه HTTPS؛ "
        "معادل سرعت واقعی کل اینترنت نیست.\n\n"
        "⚠️ <b>نکته:</b> سکوت دستگاه یا قدیمی‌شدن داده‌ها، "
        "خودش اثبات قطعی SSH یا فیلترینگ نیست."
    )


def _keyboard(data: str, *, guide: bool):
    from telegram import InlineKeyboardButton, InlineKeyboardMarkup
    hours = 168 if data.endswith("168") else 24
    back = REPORT_168 if hours == 168 else REPORT_24
    if guide:
        rows = [
            [InlineKeyboardButton("↩️ بازگشت به گزارش", callback_data=back)],
            [InlineKeyboardButton("🧩 برنامه‌ها", callback_data="apps_home")],
        ]
    else:
        help_callback = GUIDE_168 if hours == 168 else GUIDE_24
        rows = [
            [InlineKeyboardButton("۲۴ ساعت", callback_data=REPORT_24),
             InlineKeyboardButton("۷ روز", callback_data=REPORT_168)],
            [InlineKeyboardButton("📖 راهنمای کامل شاخص‌ها", callback_data=help_callback)],
            [InlineKeyboardButton("🔄 بروزرسانی", callback_data=data)],
            [InlineKeyboardButton("↩️ برنامه‌ها", callback_data="apps_home")],
        ]
    return InlineKeyboardMarkup(rows)


async def handle_dashboard(query, *, data: str, role: str | None,
                           actor: int | None, chat: int | None,
                           is_private: bool, active_admin_ids):
    """Route fixed callbacks; check current role/private-admin on every entry."""
    if data not in CALLBACKS:
        return False
    if not authorized(role=role, actor=actor, chat=chat,
                      is_private=is_private, active_admin_ids=active_admin_ids):
        await query.message.reply_text("⛔️ این گزارش فقط در گفت‌وگوی خصوصی مدیر فعال است.")
        return True
    guide = data in GUIDE_CALLBACKS
    if guide:
        content = render_guide()
    else:
        hours = 168 if data == REPORT_168 else 24
        device = os.environ.get("DENAPROBE_DASHBOARD_DEVICE_ID", DEFAULT_DEVICE)
        db = Path(os.environ.get("DENAPROBE_TELEMETRY_DB",
                                 "/var/lib/denaprobe/telemetry.sqlite3"))
        try:
            report = await asyncio.to_thread(build_report, db, device, hours)
        except (OSError, ValueError, sqlite3.Error):
            LOG.warning("DenaProbe read-only dashboard unavailable", exc_info=True)
            content = ("📡 <b>DenaProbe</b>\n"
                       "⚠️ گزارش فعلاً در دسترس نیست. "
                       "اتصال و مجوز خواندن دیتابیس را بررسی کنید.")
        else:
            content = render(report)

    from telegram.error import BadRequest
    try:
        await query.edit_message_text(
            content, parse_mode="HTML", reply_markup=_keyboard(data, guide=guide))
    except BadRequest as exc:
        if "Message is not modified" not in str(exc):
            raise
    return True
