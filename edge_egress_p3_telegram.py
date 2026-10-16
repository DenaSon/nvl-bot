"""K2 P3-F: concise Persian Telegram presentation for the existing Edge panel.

Pure display / read-only discovery only. Business gates, tickets, permission
checks, and removal remain in their established modules and bot callbacks.
No privileged worker, protected release, remote API, or shell is registered.
"""
from __future__ import annotations

from html import escape
from pathlib import Path
import re
import stat

from edge_egress_v1_console import edge_id_checked

P3F_LIVE_EXECUTION_ENABLED = False
UI_EDGE_MAX = 8


def _safe(value: object, limit: int = 70) -> str:
    return escape(str(value or "—")[:limit], quote=True)


def _state(card) -> str:
    if card.allocation == "IDENTITY_CONFLICT" or not card.ingress_verified:
        return "⛔ نیاز به بررسی"
    if card.f4_valid and card.pool_active:
        return "✅ بررسی‌شده"
    if card.pool_active or card.allocation == "STAGED":
        return "🟡 در انتظار بررسی"
    return "⚪️ غیرفعال"


def dashboard_html(board, *, active_edge: str = "") -> str:
    if not board.registry_trusted:
        note = "⚠️ اطلاعات برخی سرورها در دسترس نیست."
    else:
        note = "برای مدیریت، یک سرور را انتخاب کنید."
    return "\n".join((
        "🌐 <b>مدیریت خروجی کاربران</b>", "",
        f"⭐ خروجی فعال: <code>{_safe(active_edge)}</code>",
        f"🖥 تعداد سرورها: <b>{board.total}</b>",
        "",
        "💡 با تغییر خروجی، حساب روی سرور مرکزی می‌ماند و IP اینترنت کاربر از سرور انتخابی خواهد بود.",
        "",
        note,
    ))


def dashboard_buttons(board) -> list[list[tuple[str,str]]]:
    # The existing paged dashboard remains the only discovery authority.
    buttons: list[list[tuple[str,str]]] = []
    items = []
    for card in board.cards:
        eid = edge_id_checked(card.edge_id)
        icon = "✅" if card.f4_valid else "🟡" if card.ingress_verified else "⛔"
        items.append((f"{icon} {eid}",f"hpeg_edge_{eid}"))
    for pos in range(0,len(items),2):
        buttons.append(items[pos:pos+2])
    page_row = []
    if board.page:
        page_row.append(("◀️ قبلی",f"hpeg_page_{board.page-1}"))
    if (board.page+1)*UI_EDGE_MAX < board.total:
        page_row.append(("بعدی ▶️",f"hpeg_page_{board.page+1}"))
    if page_row:
        buttons.append(page_row)
    buttons.extend((
        [("➕ افزودن Edge","hpeg_wizard"),("❔ راهنما","hpeg_steps")],
        [("🔄 بروزرسانی",f"hpeg_page_{board.page}"),("🧹 منابع باقی‌مانده","hpeg_orphans")],
        [("↩️ برنامه‌ها","apps_home")],
    ))
    return buttons


def edge_html(card, *, active_edge: str = "") -> str:
    return "\n".join((
        f"🖥 <b>سرور {_safe(card.edge_id)}</b>", "",
        f"🌐 نشانی: <code>{_safe(card.ip)}</code>",
        f"📡 وضعیت: {_state(card)}",
        "📥 ورودی: " + ("✅ فعال" if card.ingress_verified and card.pool_active
                     else "🟡 ثبت‌شده؛ در انتظار فعال‌سازی" if card.ingress_verified
                     else "⚪️ نیازمند بررسی"),
        "📤 خروجی: " + ("✅ بررسی‌شده" if card.f4_valid else "🟡 تأییدنشده"),
        "⭐ خروجی فعال: " + ("بله" if active_edge == card.edge_id else "خیر"),
        "",
        "💡 افزودن سرور به‌تنهایی خروجی کاربران را تغییر نمی‌دهد؛ ابتدا کاربران را انتخاب و انتقال را تأیید کنید.",
    ))


def detail_buttons(card, current: str = "") -> list[list[tuple[str,str]]]:
    eid=edge_id_checked(card.edge_id)
    connection=[("🔎 بررسی اتصال",f"hpeg_health_{eid}")]
    if card.can_probe:
        connection.append(("🌍 تست IP خروجی",f"hpeg_probe_{eid}"))
    elif (not card.pool_active and card.ingress_verified
          and card.allocation=="STAGED" and card.stage_pin):
        # Isolated candidates deliberately never join the legacy host pool.
        # Reuse P1's independent pinned/two-sided read-only probe; do not
        # loosen the legacy console's pool-active safety gate.
        connection=[("🌍 تست اتصال و IP",f"hpeg_p1_probe_{eid}")]
    return [
        [("👥 انتقال کاربران",f"hpeg_m4_home_{eid}"),
         ("⭐ انتخاب خروجی فعال",f"hpeg_relay_{eid}")],
        connection,
        [("⚙️ جزئیات و نگهداری",f"hpeg_more_{eid}"),
         ("🔄 بروزرسانی",f"hpeg_edge_{eid}")],
        [("↩️ مدیریت خروجی","hpeg_status")],
    ]


def maintenance_buttons(card):
    eid=edge_id_checked(card.edge_id)
    return [
        [("👤 بررسی حساب",f"hpeg_user_{eid}"),
         ("📦 اطلاعات اتصال",f"hpeg_stage_{eid}")],
        [("📤 آماده‌سازی اتصال",f"hpeg_p1_open_{eid}"),
         ("🌍 تست اتصال خروجی",f"hpeg_p1_probe_{eid}")],
        [("🧭 وضعیت سرور",f"hpeg_actions_{eid}"),
         ("🧪 بررسی سلامت",f"hpeg_lab_{eid}")],
        [("🗑 حذف سرور",f"hpeg_retire_open_{eid}"),
         ("🧹 منابع باقی‌مانده","hpeg_orphans")],
        [("◀️ سرور",f"hpeg_edge_{eid}")],
    ]


def transport_html(card, status) -> str:
    meaning={
        "UP":"✅ برقرار",
        "ABSENT":"⚪️ متصل نیست",
        "POOL_INACTIVE":"⚪️ سرور غیرفعال است",
    }
    state=meaning.get(status.state,"🟡 نیاز به بررسی")
    return f"🔎 <b>وضعیت اتصال</b>\n\nسرور: <code>{_safe(card.edge_id)}</code>\nوضعیت: {state}"


def stage_html(card, proof) -> str:
    states={"PINNED":"✅ ثبت و بررسی‌شده",
            "LOCAL_UNATTESTED":"🟡 نیاز به بررسی",
            "PIN_MISMATCH":"⛔ اطلاعات اتصال ناسازگار است"}
    return (f"📦 <b>اطلاعات اتصال</b>\n\n"
            f"سرور: <code>{_safe(card.edge_id)}</code>\n"
            f"وضعیت: {states.get(proof.stage_state,'🟡 نامشخص')}")


def actions_html(card,status) -> str:
    reasons=[]
    if not card.ingress_verified or not card.pool_active:
        reasons.append("اتصال ورودی")
    if card.allocation != "STAGED" or not card.stage_pin:
        reasons.append("آماده‌سازی خروجی")
    if status.state != "UP" or not card.f4_valid:
        reasons.append("بررسی سلامت")
    return "\n".join((
        "🧭 <b>وضعیت سرور</b>", "",
        f"سرور: <code>{_safe(card.edge_id)}</code>",
        "وضعیت: " + ("✅ بررسی‌شده" if not reasons else "🟡 نیاز به بررسی"),
        *(("\nموارد قابل بررسی: "+ "، ".join(reasons),) if reasons else ()),
        "\nبرای انتقال کاربران، از صفحهٔ سرور اقدام کنید.",
    ))


def review_html(review) -> str:
    title={"EDGE_PREPARE":"آماده‌سازی سرور",
           "UID_ATTACH":"اتصال کاربر",
           "UID_FREEZE":"توقف دسترسی کاربر"}.get(review.action,"بررسی درخواست")
    body=[f"📋 <b>{title}</b>","",
          f"سرور: <code>{_safe(review.edge_id)}</code>"]
    if review.username:
        body.append(f"کاربر: <code>{_safe(review.username)}</code>")
    body.extend(("","🟡 امکان انجام این درخواست هنوز تأیید نشده.",
                 "این بررسی تغییری ایجاد نمی‌کند."))
    return "\n".join(body)


def retire_html(plan) -> str:
    body=["🗑 <b>حذف سرور</b>","",
          f"سرور: <code>{_safe(plan.edge_id)}</code>",
          f"نشانی: <code>{_safe(plan.edge_ipv4)}</code>",""]
    if plan.allowed:
        body.extend(("✅ امکان حذف از فهرست وجود دارد.",
                     "این کار خود سرور را خاموش نمی‌کند.",
                     "برای ادامه، حذف را تأیید کنید."))
    else:
        body.extend(("⛔ فعلاً امکان حذف وجود ندارد.",
                     "ابتدا اتصال‌ها و وابستگی‌های سرور بررسی شوند."))
    return "\n".join(body)


def steps_html() -> str:
    return ("❔ <b>راهنمای مدیریت خروجی</b>\n\n"
            "۱. Edge جدید را اضافه و اتصال آن را بررسی کنید.\n"
            "۲. سرور را باز کنید و «انتقال کاربران» را بزنید.\n"
            "۳. یک کاربر، یک گروه یا همهٔ کاربران واجد شرایط را انتخاب کنید.\n"
            "۴. نتیجهٔ بررسی را بخوانید و انتقال را تأیید کنید.\n\n"
            "💡 «خروجی فعال» پس از تأیید مسیر همهٔ حساب‌های فعال ثبت می‌شود. "
            "کاربرانی که اتصال فعال دارند، فعلاً منتقل نمی‌شوند.\n\n"
            "حساب و نام کاربری روی سرور مرکزی می‌ماند؛ IP اینترنت از Edge خارج می‌شود. "
            "این انتخاب کاربران جدید آینده را خودکار منتقل نمی‌کند.")


def user_prompt_html(edge_id: str) -> str:
    return (f"👤 <b>بررسی کاربر</b>\n\n"
            f"سرور: <code>{_safe(edge_id_checked(edge_id))}</code>\n"
            "نام کاربری SSH را ارسال کنید.\n"
            "مثال: <code>nvl0557</code>\n\n"
            "برای انصراف، «لغو» را بفرستید.")


def user_result_html(edge_id: str, username: str) -> str:
    return (f"👤 <b>بررسی کاربر</b>\n\n"
            f"کاربر: <code>{_safe(username)}</code>\n"
            f"سرور: <code>{_safe(edge_id)}</code>\n\n"
            "برای ادامه، یکی از گزینه‌های زیر را انتخاب کنید.\n"
            "هیچ تغییری در حساب ایجاد نشده است.")


def orphan_html(*, stage_root: Path=Path("/root/nvl-egress-v1"),
                max_items: int=8) -> str:
    """Read-only, conservative stage-directory inventory, NOT proof of orphanage.

    No stage digest is minted and no runtime deletion may follow this view.
    """
    try:
        info=stage_root.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=0
                or info.st_mode & 0o077):
            raise OSError("untrusted root")
        candidates=[]
        for item in stage_root.iterdir():
            if not re.fullmatch(r"core-[a-z][a-z0-9_-]{1,23}",item.name):
                continue
            child=item.lstat()
            if (not stat.S_ISDIR(child.st_mode) or child.st_uid!=0
                    or child.st_mode & 0o077):
                raise OSError("untrusted entry")
            candidates.append(item.name[5:])
        candidates.sort()
        if len(candidates)>max_items:
            candidates=candidates[:max_items]
        detail=("\n".join(f"• <code>{_safe(x)}</code> · نیازمند بررسی"
                          for x in candidates) if candidates else
                "موردی برای بررسی در فهرست محلی پیدا نشد.")
    except (OSError, ValueError):
        detail="وضعیت منابع قدیمی قابل بررسی نیست."
    return ("🧹 <b>پاکسازی سرورها</b>\n\n"+detail+
            "\n\nحذف منابع باقی‌مانده فقط پس از بررسی ایمنی انجام می‌شود.")


def wizard_prompt(*, integrated: bool) -> str:
    if type(integrated) is not bool:
        raise ValueError("INVALID_EDGE_WIZARD_MODE")
    return ("➕ <b>افزودن سرور</b>\n\n"
            "نشانی IP عمومی سرور جدید را ارسال کنید.\n"
            "سرور باید تازه و آماده راه‌اندازی باشد.\n\n"
            "💡 در سه گام IP، رمز و پورت اتصال کاربران را می‌گیریم. "
            "بعد از ارسال پورت، نصب شروع می‌شود. برای انصراف «لغو» را بفرستید.")


def wizard_result(edge_ip: str, result: dict) -> tuple[str,str]:
    # Preserve the strict existing onboarding identity and outcome validator;
    # change only the human-facing text, never the release state.
    from edge_egress_phase2_wizard import staged_edge_result
    _detail,eid=staged_edge_result(edge_ip,result)
    return (
        "✅ <b>سرور اضافه شد</b>\n\n"
        f"شناسه: <code>{_safe(eid)}</code>\n"
        f"نشانی: <code>{_safe(edge_ip)}</code>\n\n"
        "📦 آماده‌سازی اولیه ثبت شد. مسیر خروجی کاربران هنوز فعال نیست.\n"
        "برای ادامه، صفحهٔ سرور را باز کنید و وضعیت اتصال را ببینید.",
        eid,
    )


def probe_html(result) -> str:
    state="✅ نشانی خروجی درست است" if result.matches else "⛔ نشانی خروجی متفاوت است"
    return ("🌍 <b>تست IP خروجی</b>\n\n"
            f"مورد انتظار: <code>{_safe(result.expected_ip)}</code>\n"
            f"مشاهده‌شده: <code>{_safe(result.observed_ip)}</code>\n\n"
            f"{state}")
