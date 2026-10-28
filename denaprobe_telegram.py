"""Read-only NVL Telegram admin surface for the isolated DenaProbe database."""
from __future__ import annotations

import asyncio
import html
import os
import time
from datetime import datetime, timezone

from telegram import InlineKeyboardButton, InlineKeyboardMarkup

from denaprobe_store import latest_reports

STALE_AFTER_S = 180
DEFAULT_DB = "/var/lib/nvl-denaprobe/telemetry.sqlite3"


def _is_authorized(update, context, active_admin_ids) -> bool:
    actor = getattr(update.effective_user, "id", None)
    chat = update.effective_chat
    return bool(
        actor is not None
        and chat is not None
        and getattr(chat, "type", "") == "private"
        and chat.id == actor
        and bool(context.user_data.get("logged_in"))
        and context.user_data.get("role") == "admin"
        and actor in active_admin_ids
    )


def render_dashboard(rows: list[dict], *, now: int | None = None) -> str:
    now = int(time.time()) if now is None else now
    parts = [
        "📡 <b>DenaProbe | پایش شبکه</b>",
        "━━━━━━━━━━━━━━",
        "<i>گزارش‌های ESP32؛ نه تست کامل NPV یا رأی فیلترینگ.</i>",
    ]
    if not rows:
        parts.append("\n⚪ هنوز گزارشی از دستگاه دریافت نشده است.")
    for row in rows[:10]:
        age = max(0, now - int(row["received_at"]))
        age_text = f"{age // 60} دقیقه" if age >= 60 else f"{age} ثانیه"
        stage = str(row["stage"])
        if age > STALE_AFTER_S:
            icon = "⚪"
            message = "گزارش قدیمی؛ ارتباط دستگاه نامشخص"
        elif stage == "SSH_ID_PASS":
            icon = "🟢"
            message = "DNS/TCP/SSH Banner موفق"
        elif row["control_ok"] == 1:
            icon = "🟠"
            message = "Edge ناموفق؛ کنترل TCP عمومی موفق"
        else:
            icon = "🟡"
            message = "اختلال یا نتیجه نامشخص"
        passed = lambda key: "✓" if row[key] == 1 else ("✗" if row[key] == 0 else "—")
        parts.extend([
            "",
            f"{icon} <b>{html.escape(str(row['device_id']))}</b> | {html.escape(message)}",
            f"شبکه اعلام‌شده: <b>{html.escape(str(row['carrier_declared']))}</b> (تأیید مستقل نشده)",
            f"Edge: <code>{html.escape(str(row['edge_host']))}</code>:{int(row['edge_port'])}",
            f"DNS {passed('dns_ok')} | TCP {passed('tcp_ok')} | SSH-ID {passed('ssh_id_ok')}",
            f"زمان‌ها: DNS {row['dns_ms'] if row['dns_ms'] is not None else '—'} / "
            f"TCP {row['tcp_ms'] if row['tcp_ms'] is not None else '—'} / "
            f"SSH {row['ssh_id_ms'] if row['ssh_id_ms'] is not None else '—'} ms",
            f"RSSI: {int(row['wifi_rssi_dbm'])} dBm | آخرین دریافت: {age_text} قبل",
            f"ثبت سرور (UTC): {datetime.fromtimestamp(int(row['received_at']), timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}",
        ])
    parts.extend([
        "",
        "⚠️ <i>دریافت SSH Banner، سلامت احراز هویت و انتقال واقعی VPN را اثبات نمی‌کند.</i>",
        "اطلاعات فقط خواندنی است؛ روی DNS، Edge یا Failover اثری ندارد.",
    ])
    return "\n".join(parts)


def dashboard_markup() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🔄 بروزرسانی گزارش", callback_data="apps_denaprobe_refresh")],
        [InlineKeyboardButton("↩️ برنامه‌ها", callback_data="apps_home")],
    ])


async def _show(update, context, active_admin_ids) -> None:
    if not _is_authorized(update, context, active_admin_ids):
        if update.callback_query:
            await update.callback_query.answer("دسترسی غیرمجاز.", show_alert=True)
        elif update.message:
            await update.message.reply_text("⛔️ دسترسی این بخش فقط برای مدیر واردشده مجاز است.")
        return
    try:
        rows = await asyncio.to_thread(
            latest_reports, os.environ.get("DENAPROBE_DB_PATH", DEFAULT_DB),
        )
        text = render_dashboard(rows)
    except Exception:
        text = "⚪ گزارش DenaProbe فعلاً قابل دریافت نیست؛ وضعیت شبکه نامشخص است."
    if update.callback_query:
        await update.callback_query.answer()
        try:
            await update.callback_query.edit_message_text(
                text, parse_mode="HTML", reply_markup=dashboard_markup(),
            )
        except Exception as exc:
            if "Message is not modified" not in str(exc):
                raise
    else:
        await update.message.reply_text(
            text, parse_mode="HTML", reply_markup=dashboard_markup(),
        )


async def denaprobe_command(update, context, *, active_admin_ids) -> None:
    await _show(update, context, active_admin_ids)


async def denaprobe_callback(update, context, *, active_admin_ids) -> None:
    await _show(update, context, active_admin_ids)
