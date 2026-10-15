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
from edge_egress_k2_m3_waves import (
    MigrationWavePlan, build_wave_plan, m4_same_ingress_reviewed,
    m4_cross_edge_single_reviewed,
)
import edge_egress_k2_m4_root_portal as _root_portal

MAX_INPUT_UIDS = 10
_NAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
_EDGE = re.compile(r"[a-z][a-z0-9_-]{1,23}\Z")
CALLBACK_PREFIX = "hpeg_m4_"
ACTIONS = frozenset(("home","single","batch","refresh","cancel","status","prepare","confirm","abort"))


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


def _root_can_review(plan: MigrationWavePlan) -> bool:
    # Mirror original root PREPARE eligibility, never infer a release
    # from a user-facing preview or a generic "ready" flag.
    return m4_same_ingress_reviewed(plan) or (
        _root_portal.M4_CROSS_EDGE_SINGLE_ENABLED
        and m4_cross_edge_single_reviewed(plan)
    )


def _operator_runtime_released(plan: MigrationWavePlan) -> bool:
    """Presentation gating only: never offer CONFIRM for a code-only preview.

    This does NOT authorize execution. Root IPC and the original 6G/P3
    repeat all their independent checks. In the legacy root bot (UID 0),
    no PREPARE button is offered even if someone toggles a subset of flags.
    """
    import os
    from edge_egress_k2_m43_client import M43_TELEGRAM_EXECUTION_ENABLED
    from edge_egress_k2_m4_ipc import M4_UNIX_IPC_ENABLED
    from edge_egress_k2_m4_root_worker import M4_ROOT_WORKER_ENABLED
    from ops.k2_m4_root_daemon import M4A_ROOT_DAEMON_RELEASED
    from edge_egress_k2_a_root_assembly import M4A_ROOT_ASSEMBLY_ENABLED
    from edge_egress_k2_a_host_factory import (
        M4A_REAL_HOST_FACTORY_ENABLED, M4A_CROSS_EDGE_FACTORY_ENABLED,
    )
    from edge_egress_k2_a3_host_plans import (
        A3_ROOT_OWNED_PLAN_SOURCE_ENABLED, A3_ROOT_SNAPSHOT_BINDING_ENABLED,
        A3_ROOT_CROSS_EDGE_PLAN_ENABLED, A3_ROOT_CROSS_EDGE_SNAPSHOT_ENABLED,
    )
    from edge_egress_k2_m42_bindings import (
        M42_LIVE_BINDINGS_ENABLED, M42_CROSS_EDGE_LEGACY_SINGLE_ENABLED,
    )
    from edge_egress_k2_m4_root_portal import M4_ROOT_PORTAL_ENABLED
    from edge_egress_k2_m3_waves import (
        M3_WAVE_EXECUTION_ENABLED, M3_CROSS_EDGE_LEGACY_SINGLE_ENABLED,
    )
    from edge_egress_p3_executor import P3_CROSS_EDGE_LEGACY_UID_ATTACH_ENABLED
    from edge_egress_k2_m4_bootstrap import M42_CROSS_EDGE_DEFERRED_ENABLED
    from edge_egress_k2_m4_cross_edge_port import (
        M4_CROSS_EDGE_UID_PORT_ENABLED, CROSS_EDGE_PAM_SAFETY_ENABLED,
    )
    from edge_egress_uid_runtime_store import K2_CROSS_EDGE_RUNTIME_STORE_ENABLED
    from edge_egress_k2_uid_ingress_egress import K2_M4_POLICY_STAGE_ENABLED
    if (os.geteuid() == 0 or not _root_can_review(plan)
        or not all((
            M43_TELEGRAM_EXECUTION_ENABLED, M4_UNIX_IPC_ENABLED,
            M4_ROOT_WORKER_ENABLED, M4A_ROOT_DAEMON_RELEASED,
            M4A_ROOT_ASSEMBLY_ENABLED, M4A_REAL_HOST_FACTORY_ENABLED,
            A3_ROOT_OWNED_PLAN_SOURCE_ENABLED, A3_ROOT_SNAPSHOT_BINDING_ENABLED,
            M42_LIVE_BINDINGS_ENABLED, M4_ROOT_PORTAL_ENABLED,
            M3_WAVE_EXECUTION_ENABLED,
        ))):
        return False
    if m4_cross_edge_single_reviewed(plan):
        return all((
            M3_CROSS_EDGE_LEGACY_SINGLE_ENABLED,
            _root_portal.M4_CROSS_EDGE_SINGLE_ENABLED,
            M42_CROSS_EDGE_LEGACY_SINGLE_ENABLED,
            M4A_CROSS_EDGE_FACTORY_ENABLED,
            A3_ROOT_CROSS_EDGE_PLAN_ENABLED,
            A3_ROOT_CROSS_EDGE_SNAPSHOT_ENABLED,
            P3_CROSS_EDGE_LEGACY_UID_ATTACH_ENABLED,
            M42_CROSS_EDGE_DEFERRED_ENABLED,
            M4_CROSS_EDGE_UID_PORT_ENABLED,
            CROSS_EDGE_PAM_SAFETY_ENABLED,
            K2_CROSS_EDGE_RUNTIME_STORE_ENABLED,
            K2_M4_POLICY_STAGE_ENABLED,
        ))
    return True


def preview_html(inventory: MigrationInventory) -> str:
    if not isinstance(inventory,MigrationInventory):
        raise M4UIHold("PREVIEW_UNAVAILABLE")
    plan=build_wave_plan(inventory,wave_size=MAX_INPUT_UIDS)
    chosen=tuple(plan.members)
    total=len(chosen)
    # Match the same explicit single-only gate as privileged M4 PREPARE.
    can_stage=_root_can_review(plan)
    ready=sum(
        m.selectable and not plan.global_blockers
        and (m.source_edge_id==m.target_edge_id
             and m.source_ipv4==m.target_ipv4 or (
                 _root_portal.M4_CROSS_EDGE_SINGLE_ENABLED
                 and m.source_edge_id!=m.target_edge_id
                 and m.source_ipv4!=m.target_ipv4
                 and inventory.selection.mode=="SINGLE"
                 and len(chosen)==1
             ))
        for m in chosen
    )
    held=total-ready
    title="یک کاربر" if inventory.selection.mode=="SINGLE" else "گروه کاربران"
    lines=[
        "🔎 <b>بررسی انتقال</b>","",
        f"انتخاب: <b>{title}</b>",
        f"سرور مقصد: <code>{_safe(inventory.selection.target_edge_id)}</code>",
        f"آماده بررسی: <b>{ready}</b>",
        f"نیازمند بررسی: <b>{held}</b>","",
    ]
    for member in chosen:
        sign="✅" if member.selectable and can_stage else "⛔️"
        lines.append(f"{sign} <code>{_safe(member.username)}</code> — "+
                     ("آماده بررسی" if sign=="✅" else "نیازمند بررسی"))
    lines.append("")
    lines.append(
        ("⛔️ مسیر این حساب‌ها هنوز آماده انتقال نیست. "
         "ابتدا وضعیت سرور ورودی بررسی شود."
         if not can_stage else
         "⛔️ اجرای انتقال در این نسخه غیرفعال است؛ "
         "تا تأیید نهایی مسیر، هیچ حسابی تغییر نمی‌کند.")
    )
    # Do not expose internal 6G/PAM/F4 gate names to end users or Telegram.
    return "\n".join(lines)


def preview_buttons(edge_id: str, *,
                    inventory: MigrationInventory | None = None):
    if not _EDGE.fullmatch(edge_id):
        raise M4UIHold("EDGE_INVALID")
    # Default deny: status and post-confirmation views cannot reuse an
    # earlier preview to mint an actionable approval. A fresh, exact M1
    # inventory is required to display the PREPARE button at all.
    reviewed=False
    if inventory is not None:
        if (not isinstance(inventory,MigrationInventory)
            or inventory.selection.target_edge_id != edge_id):
            raise M4UIHold("PREVIEW_SELECTION_INVALID")
        plan=build_wave_plan(inventory,wave_size=MAX_INPUT_UIDS)
        reviewed=_operator_runtime_released(plan)
    return _button_rows(
        (("🔐 درخواست تأیید",f"hpeg_m4_prepare_{edge_id}"),)
        if reviewed else (),
        (("🔄 بررسی دوباره",f"hpeg_m4_refresh_{edge_id}"),
         ("📋 وضعیت",f"hpeg_m4_status_{edge_id}")),
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
