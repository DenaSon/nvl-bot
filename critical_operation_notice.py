"""Super-admin-only notifications for rare, critical customer-route outcomes.

No Cloudflare, host, database or network mutation occurs in this module.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
import uuid
from html import escape
from typing import Optional


EVENTS = {
    "ROUTE_CHANGED": (
        "تغییر مسیر سرویس", "موفق", "مسیر دسترسی به مقصد جایگزین منتقل شد."
    ),
    "ROUTE_CHANGE_FAILED": (
        "تغییر مسیر سرویس", "ناموفق", "تغییر مسیر تأیید نشد؛ بررسی وضعیت سرویس ضروری است."
    ),
    "ROUTE_CHANGE_BLOCKED": (
        "حفاظت مسیر سرویس", "متوقف شد", "مسیر جایگزین تأیید نشد؛ عملیات حفاظتی متوقف شد."
    ),
}

_COOLDOWNS = {"ROUTE_CHANGE_FAILED": 900, "ROUTE_CHANGE_BLOCKED": 3600}
_STATE_KEY = "_nvl_critical_notice_sent_at"


def _recipients(primary: int, extra: Optional[str] = None) -> tuple[int, ...]:
    """Explicit super-admin IDs only; never use all-admin/accountant lists."""
    ids = set()
    try:
        value = int(primary)
        if value > 0:
            ids.add(value)
    except (TypeError, ValueError):
        pass
    if extra is None:
        extra = os.environ.get("NVL_CRITICAL_SUPERADMIN_IDS", "")
    for raw in extra.split(","):
        try:
            value = int(raw.strip())
            if value > 0:
                ids.add(value)
        except ValueError:
            continue
    return tuple(sorted(ids))


def format_critical_notice(event: str, reference: str) -> str:
    """User-facing operational report, without implementation details/IPs."""
    if event not in EVENTS:
        raise ValueError("Unknown critical operation event")
    operation, outcome, summary = EVENTS[event]
    return (
        "🚨 <b>NVL | گزارش عملیات مهم</b>\n\n"
        f"<b>عملیات:</b> {operation}\n"
        f"<b>وضعیت:</b> {outcome}\n"
        f"<b>گزارش:</b> {summary}\n"
        f"<b>شناسه پیگیری:</b> <code>{escape(reference)}</code>"
    )


async def send_critical_notice(
    app,
    *,
    event: str,
    primary_super_admin_id: int,
    dedupe_key: str = "",
    operation_ref: Optional[str] = None,
    logger: Optional[logging.Logger] = None,
    now: Optional[float] = None,
) -> Optional[str]:
    """Best-effort notice. Telegram failure cannot fail/undo an operation."""
    log = logger or logging.getLogger(__name__)
    if event not in EVENTS:
        raise ValueError("Unknown critical operation event")
    reference = operation_ref or ("NVL-" + uuid.uuid4().hex[:16].upper())
    if app is None:
        log.warning("NVL_CRITICAL_NOTICE skipped event=%s ref=%s reason=APP_MISSING",
                    event, reference)
        return None

    clock = time.monotonic() if now is None else now
    try:
        state = app.bot_data.setdefault(_STATE_KEY, {})
    except Exception:
        state = {}
    cooldown = _COOLDOWNS.get(event, 0)
    fingerprint = (event, dedupe_key)
    previous = state.get(fingerprint)
    if cooldown and previous is not None and 0 <= clock - previous < cooldown:
        log.info("NVL_CRITICAL_NOTICE throttled event=%s key=%s", event, dedupe_key)
        return None

    targets = _recipients(primary_super_admin_id)
    if not targets:
        log.error("NVL_CRITICAL_NOTICE skipped event=%s ref=%s reason=NO_SUPERADMIN", event, reference)
        return None
    text = format_critical_notice(event, reference)
    delivered = 0
    for chat_id in targets:
        try:
            await asyncio.wait_for(
                app.bot.send_message(chat_id=chat_id, text=text, parse_mode="HTML"),
                timeout=3.0,
            )
            delivered += 1
        except Exception as exc:
            log.warning("NVL_CRITICAL_NOTICE delivery_failed event=%s ref=%s recipient=%s exception=%s",
                        event, reference, chat_id, type(exc).__name__)
    if delivered and cooldown:
        state[fingerprint] = clock
    log.warning("NVL_CRITICAL_NOTICE event=%s ref=%s delivered=%s/%s",
                event, reference, delivered, len(targets))
    return reference if delivered else None
