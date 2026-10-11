"""F3: administrator-only, bounded *read-only* UID-to-Edge assignment preview.

The bot never creates BLOCKED intents, activates a tunnel, touches host_pool,
changes SSH accounts or routes traffic from this screen. Evidence-only.
"""
from __future__ import annotations

from html import escape
import re
import sqlite3

from edge_egress_f3_readiness import assignment_preview, ReadinessUnsafe

_NAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_EDGE = re.compile(r"^[a-z][a-z0-9]{0,6}$")


def render_assignment_preview(db_conn, value: str) -> str:
    """Parse '<username> <edge_id>' and return safe Persian HTML."""
    if not isinstance(value, str) or len(value) > 120:
        return "⛔️ ورودی نامعتبر است. نمونه: <code>nvl0557 fra1</code>"
    tokens = value.strip().split()
    if len(tokens) != 2 or not _NAME.fullmatch(tokens[0]) or (
        not _EDGE.fullmatch(tokens[1])
    ):
        return "⛔️ فرمت نامعتبر. نمونه: <code>nvl0557 fra1</code>"
    user, edge_id = tokens
    try:
        with db_conn() as conn:
            result = assignment_preview(conn, user, edge_id)
    except (sqlite3.Error, ReadinessUnsafe):
        result = {"eligible": False, "reason": "EVIDENCE_UNAVAILABLE"}
    reason = escape(result["reason"][:80])
    return (
        "🛡️ <b>پیش‌نمایش تخصیص Egress</b>\n\n"
        f"کاربر: <code>{escape(user)}</code>\n"
        f"Edge: <code>{escape(edge_id)}</code>\n"
        f"وضعیت: ⛔️ تخصیص غیرفعال\n"
        f"دلیل: <code>{reason}</code>\n\n"
        "این یک بررسی Read-only است؛ هیچ تنظیم، حساب یا Route تغییر نکرد. "
        "تخصیص واقعی تنها بعد از پذیرش F4 و تحت قفل 6G مجاز خواهد بود."
    )
