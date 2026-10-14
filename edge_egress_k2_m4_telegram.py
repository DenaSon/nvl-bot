"""K2 M4 Telegram operator presentation — functional UI, no kernel mutations.

All callbacks use the EXISTING hpeg_* handler, never a second bot.
Short Persian labels, <=2 columns, no development vocabulary in visible text.
A separate final UI/UX polish milestone is required after operational M7.
"""
from __future__ import annotations

from html import escape
import re
from typing import Iterable

from edge_egress_k2_migration_inventory import (
    MigrationInventory, MigrationInventoryHold, select_migration,
)
from edge_egress_k2_m3_waves import MigrationWavePlan, build_wave_plan

MAX_INPUT_UIDS = 10
_NAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
_EDGE = re.compile(r"[a-z][a-z0-9_-]{1,23}\Z")
CALLBACK_PREFIX = "hpeg_m4_"
ACTIONS = frozenset(("home","single","batch","refresh","cancel","recheck"))


class M4UIHold(ValueError):
    pass


def parse_callback(data: str) -> tuple[str, str]:
    if not isinstance(data,str) or not data.startswith(CALLBACK_PREFIX):
        raise M4UIHold("CALLBACK_NOT_M4")
    command=data[len(CALLBACK_PREFIX):]
    if "_" not in command:
        raise M4UIHold("CALLBACK_INCOMPLETE")
    action,edge_id=command.split("_",1)
    if action not in ACTIONS or not _EDGE.fullmatch(edge_id):
        raise M4UIHold("CALLBACK_UNTRUSTED")
    if len(data.encode("utf-8"))>64:
        raise M4UIHold("TELEGRAM_CALLBACK_TOO_LONG")
    return action,edge_id


def select_input(mode: str, text: str, edge_id: str):
    """Strict one-shot operator input. No wildcard, no selecting all users."""
    if not isinstance(text,str) or len(text)>380:
        raise M4UIHold("INPUT_TOO_LONG")
    if not isinstance(edge_id,str) or not _EDGE.fullmatch(edge_id):
        raise M4UIHold("TARGET_INVALID")
    if mode not in ("SINGLE","BATCH"):
        raise M4UIHold("MODE_INVALID")
    names=[part.strip() for part in re.split(r"[,،\s]+",text.strip()) if part.strip()]
    if not names or len(names)>MAX_INPUT_UIDS or (
        mode=="SINGLE" and len(names)!=1
    ) or len(set(names))!=len(names) or any(
        not _NAME.fullmatch(name) for name in names
    ):
        raise M4UIHold("USERS_INVALID_OR_DUPLICATED")
    return select_migration(mode,tuple(names),edge_id)


def _safe(value: object, limit: int = 52) -> str:
    return escape(str(value or "—")[:limit],quote=True)


def _button_rows(*rows: tuple[tuple[str,str], ...]) -> list[list[tuple[str,str]]]:
    return [list(row) for row in rows if row]


def home_html(edge_id: str) -> str:
    if not _EDGE.fullmatch(edge_id):
        raise M4UIHold("EDGE_INVALID")
    return ("👥 <b>انتقال کاربران</b>\n\n"
            f"سرور مقصد: <code>{_safe(edge_id)}</code>\n"
            "انتقال تکی یا گروهی را انتخاب کنید.\n\n"
            "هر گروه حداکثر ۱۰ کاربر دارد. "
            "حساب‌های دیگر بدون تغییر می‌مانند.")


def home_buttons(edge_id: str):
    if not _EDGE.fullmatch(edge_id):
        raise M4UIHold("EDGE_INVALID")
    return _button_rows(
        (("👤 انتقال تکی",f"hpeg_m4_single_{edge_id}"),
         ("👥 انتقال گروهی",f"hpeg_m4_batch_{edge_id}")),
        (("◀️ سرور",f"hpeg_edge_{edge_id}"),)
    )


def prompt_html(edge_id: str, mode: str):
    if not _EDGE.fullmatch(edge_id) or mode not in ("SINGLE","BATCH"):
        raise M4UIHold("PROMPT_INVALID")
    if mode=="SINGLE":
        text=("👤 <b>انتقال یک کاربر</b>\n\n"
              "نام کاربری را بفرستید.\n"
              "مثال: <code>nvl0555</code>")
    else:
        text=("👥 <b>انتقال گروهی</b>\n\n"
              "نام‌های کاربری را با ویرگول جدا کنید.\n"
              "حداکثر ۱۰ حساب در هر مرحله.\n"
              "مثال: <code>nvl0555, nvl0557</code>")
    return text+f"\n\nمقصد: <code>{_safe(edge_id)}</code>"


def cancel_buttons(edge_id: str):
    if not _EDGE.fullmatch(edge_id):
        raise M4UIHold("EDGE_INVALID")
    return _button_rows((("❌ انصراف",f"hpeg_m4_cancel_{edge_id}"),))


def preview_html(inventory: MigrationInventory) -> str:
    if not isinstance(inventory,MigrationInventory):
        raise M4UIHold("PREVIEW_UNAVAILABLE")
    plan=build_wave_plan(inventory,wave_size=MAX_INPUT_UIDS)
    chosen=tuple(plan.members)
    total=len(chosen)
    held=total-plan.ready_count
    title="یک کاربر" if inventory.selection.mode=="SINGLE" else "گروه کاربران"
    lines=[
        "🔎 <b>بررسی انتقال</b>","",
        f"انتخاب: <b>{title}</b>",
        f"سرور مقصد: <code>{_safe(inventory.selection.target_edge_id)}</code>",
        f"آماده بررسی: <b>{plan.ready_count}</b>",
        f"نیازمند بررسی: <b>{held}</b>","",
    ]
    for member in chosen:
        sign="✅" if member.selectable and not plan.global_blockers else "⛔️"
        lines.append(f"{sign} <code>{_safe(member.username)}</code> — "+
                     ("آماده بررسی" if sign=="✅" else "نیازمند بررسی"))
    lines.append("")
    lines.append(
        "⛔️ اجرای انتقال در این نسخه غیرفعال است؛ "
        "تا تأیید نهایی مسیر، هیچ حسابی تغییر نمی‌کند."
    )
    # Do not expose internal 6G/PAM/F4 gate names to end users or Telegram.
    return "\n".join(lines)


def preview_buttons(edge_id: str):
    if not _EDGE.fullmatch(edge_id):
        raise M4UIHold("EDGE_INVALID")
    return _button_rows(
        (("🔄 بررسی دوباره",f"hpeg_m4_refresh_{edge_id}"),),
        (("👥 انتخاب جدید",f"hpeg_m4_home_{edge_id}"),
         ("◀️ سرور",f"hpeg_edge_{edge_id}")),
    )


def failure_html() -> str:
    return ("⛔️ <b>بررسی کامل نشد</b>\n\n"
            "اطلاعات فعلی برای انتقال ایمن کافی نیست. "
            "هیچ تغییری در حساب‌ها انجام نشده است.")


def blocked_html() -> str:
    return ("🔒 <b>انتقال هنوز فعال نیست</b>\n\n"
            "برای حفاظت از حساب‌های فعال، "
            "اجرای انتقال تا تأیید کامل زیرساخت غیرفعال می‌ماند.")
