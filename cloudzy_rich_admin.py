"""Phase 7 source-only Rich Messages read model and renderer for trusted admins.

No Telegram handler, callback registration, provider write, DNS write, account
mutation, or background worker is installed by importing this module.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
import sqlite3

OP_ID = re.compile(r"[a-f0-9]{16,64}\Z")
CODE = re.compile(r"[A-Z][A-Z0-9_]{0,89}\Z")
KINDS = ("CZ07", "UO")
STAGES = (
    "تأیید درخواست و هزینه",
    "تأیید هویت سرور Cloudzy",
    "نصب Edge و بررسی WireGuard",
    "آماده‌سازی Standby",
    "بازبینی آمادگی تغییر مسیر",
    "تغییر محافظت‌شده DNS و Default",
    "انتقال حساب‌های SSH",
    "تأیید ساخت، تمدید و اتصال",
)
UO_STEP = {
    "PREFLIGHT": 0, "PURCHASE": 0, "PROVIDER_WAIT": 1,
    "SSH_IDENTITY": 1, "EDGE_INSTALL": 2, "STANDBY": 3,
    "CLIENT_E2E": 4, "DNS_CUTOVER": 5,
    "CUSTOMER_MIGRATION": 6, "FINAL_VERIFY": 7,
}
STATE_LABELS = {
    "PLANNED": "برنامه‌ریزی‌شده", "RUNNING": "در حال اجرا",
    "WAITING_EXTERNAL": "در انتظار پاسخ زیرساخت",
    "NEEDS_ATTESTATION": "در انتظار تأیید شواهد",
    "RETRYABLE": "قابل پیگیری",
    "RECONCILE_REQUIRED": "نیازمند تطبیق وضعیت",
    "CANCELLATION_REQUESTED": "درخواست توقف ثبت شده",
    "PAUSED_SAFE": "متوقف‌شده در نقطه امن",
    "COMPLETED": "تکمیل و تأییدشده",
    "CANCELLED_SAFE": "لغو امن", "NEEDS_OPERATOR": "نیازمند بررسی مدیر",
    "QUEUED": "در صف انتقال", "ROUTING": "در حال تغییر مسیر",
    "MIGRATING": "در حال انتقال حساب‌ها",
    "VERIFYING": "انتقال انجام شده؛ پذیرش نهایی باز است",
    "DONE": "تکمیل و تأییدشده", "HOLD": "متوقف برای بررسی",
    "ABORTED": "لغوشده",
}

CZ07_STEP = {
    "QUEUED": 4, "ROUTING": 5, "MIGRATING": 6, "PAUSED_SAFE": 6,
    "VERIFYING": 7, "DONE": 7, "HOLD": 6, "ABORTED": 5,
}

# Typed action policy. Each error is explained but NEVER authorizes an effect.
ERRORS = {
    "LEGACY_HOSTS_ORDER_MISMATCH": (
        "ناسازگاری فهرست مسیرهای مشتری", "مسیر پیش‌فرض با فهرست Hostها یکسان نیست.",
        "READ_DIAGNOSE"),
    "DEFAULT_CUSTOMER_RELAY_NOT_ELIGIBLE": (
        "مسیر پیش‌فرض معتبر نیست", "Relay پیش‌فرض شرایط ارائه حساب SSH را ندارد.",
        "READ_DIAGNOSE"),
    "CLOUDZY_PROVIDER_UNAVAILABLE": (
        "دسترسی موقت به Cloudzy برقرار نشد", "نتیجه درخواست ارائه‌دهنده مشخص نیست.",
        "RECONCILE_FIRST"),
    "CREATE_RESULT_UNCERTAIN": (
        "نتیجه خرید سرور نامشخص است", "پیش از هر خرید دیگر، شناسه سفارش قبلی بررسی شود.",
        "RECONCILE_FIRST"),
    "PROVIDER_RESULT_UNCERTAIN": (
        "نتیجه عملیات ارائه‌دهنده نامشخص است", "تکرار عملیات خارجی بدون بررسی ممنوع است.",
        "RECONCILE_FIRST"),
    "DNS_OR_DEFAULT_UNCERTAIN_LOCK_HELD": (
        "نتیجه تغییر DNS قطعی نیست", "قفل محافظ باید تا بررسی واقعی حفظ شود.",
        "RECONCILE_FIRST"),
    "SHARED_6G_BUSY": (
        "عملیات شبکه دیگری در جریان است", "مالک قفل 6G و Journal بررسی شوند.",
        "READ_DIAGNOSE"),
    "CANCEL_REQUESTED": (
        "توقف درخواست شده است", "عملیات پس از Batch جاری در مرز امن متوقف می‌شود.",
        "WAIT"),
    "AWAITING_BUSINESS_E2E": (
        "انتقال حساب‌ها ثبت شد؛ پذیرش نهایی باز است",
        "ثبت تغییر Host به‌تنهایی موفقیت سرویس نیست؛ شواهد مستقل ساخت، تمدید و اتصال مشتری باید بررسی شوند.",
        "VERIFY_EVIDENCE"),
    "CZ06_STANDBY_READY_AWAITING_CLIENT_E2E": (
        "سرور و Standby آماده‌اند",
        "آماده‌بودن زیرساخت تأیید شده؛ قبل از تغییر مسیر باید شواهد مستقل اتصال وجود داشته باشد.",
        "VERIFY_EVIDENCE"),
    "CZ07_BUSINESS_E2E_REQUIRED": (
        "انتقال کامل؛ تأیید سرویس باقی است",
        "ساخت و تمدید حساب و اتصال مشتری باید با شواهد مستقل تأیید شوند.",
        "VERIFY_EVIDENCE"),
    "HOST_KEY_CHANGED": (
        "هویت SSH سرور تغییر کرده است",
        "اثر انگشت SSH باید از مسیر مستقل تأیید شود.", "SECURITY_HOLD"),
    "CLOUDZY_HTTP_429": (
        "محدودیت درخواست Cloudzy",
        "فقط بازخوانی محدود و دارای Backoff مجاز است.", "READ_RETRY"),
    "TELEGRAM_DELIVERY_TIMEOUT": (
        "نمایش وضعیت در تلگرام ناموفق بود",
        "وضعیت عملیات اصلی تغییر نکرده است.", "DELIVERY_ONLY"),
}


class RichViewHold(ValueError):
    """No privileged data or side effect is returned on denial."""


@dataclass(frozen=True)
class OperationView:
    kind: str
    operation_id: str
    actor: int
    chat: int
    version: int
    stage: int
    state: str
    code: str
    source: str = "—"
    target: str = "—"
    moved: int | None = None
    total: int | None = None
    accepted_steps: tuple[int, ...] = ()


def _safe_code(value):
    raw = str(value or "").upper()
    return raw if CODE.fullmatch(raw) else "UNSPECIFIED"


def _safe_ip(value):
    try:
        ip = ipaddress.ip_address(str(value))
        return str(ip) if ip.version == 4 else "—"
    except ValueError:
        return "—"


def _table_exists(db, name):
    return bool(db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone())


def _identity(kind, operation_id, actor, chat):
    if (kind not in KINDS or not isinstance(operation_id, str)
            or not OP_ID.fullmatch(operation_id)
            or type(actor) is not int or actor <= 0
            or type(chat) is not int):
        raise RichViewHold("INVALID_OPERATION_IDENTITY")


def read_operation(db: sqlite3.Connection, *, kind, operation_id, actor, chat):
    """SELECT-only, owner-bound projection; no lazy CREATE, migrations or writes."""
    _identity(kind, operation_id, actor, chat)
    if kind == "CZ07":
        if not _table_exists(db, "cloudzy_cz07_jobs"):
            raise RichViewHold("CZ07_JOURNAL_UNAVAILABLE")
        record = db.execute(
            "SELECT actor,chat,status,code,source,target,moved,total "
            "FROM cloudzy_cz07_jobs WHERE id=?", (operation_id,)
        ).fetchone()
        if record is None or record[0:2] != (actor, chat):
            raise RichViewHold("OPERATION_OWNER_MISMATCH")
        status, code, source, target, moved, total = record[2:]
        # Version is derived solely from the durable event sequence.
        if not _table_exists(db, "cloudzy_cz07_events"):
            raise RichViewHold("CZ07_EVENTS_UNAVAILABLE")
        version = int(db.execute(
            "SELECT COALESCE(MAX(seq),0) FROM cloudzy_cz07_events WHERE job_id=?",
            (operation_id,)
        ).fetchone()[0])
        state = str(status or "UNKNOWN").upper()
        return OperationView(
            kind, operation_id, actor, chat, version,
            CZ07_STEP.get(state, 0), state, _safe_code(code),
            _safe_ip(source), _safe_ip(target),
            int(moved), int(total))
    if not _table_exists(db, "cloudzy_uo_operations"):
        raise RichViewHold("UO_JOURNAL_UNAVAILABLE")
    record = db.execute(
        "SELECT actor,chat,step,state,code,version FROM cloudzy_uo_operations "
        "WHERE id=?", (operation_id,)
    ).fetchone()
    if record is None or record[0:2] != (actor, chat):
        raise RichViewHold("OPERATION_OWNER_MISMATCH")
    stage, state, code, version = record[2:]
    return OperationView(
        kind, operation_id, actor, chat, int(version or 0),
        UO_STEP.get(str(stage or "").upper(), 0),
        str(state or "UNKNOWN").upper(), _safe_code(code))


def issue(code):
    return ERRORS.get(
        _safe_code(code),
        ("نیازمند بررسی", "علت دقیق در Journal اصلی بررسی شود؛ "
         "هیچ عملیات خارجی را بدون مدرک تکرار نکنید.", "RECONCILE_FIRST"),
    )


def _callback(view, action):
    # Read-only buttons; the caller must still repeat authenticated projection.
    if action not in ("r", "d"):
        raise RichViewHold("MUTATION_CALLBACK_NOT_AVAILABLE")
    data = f"u7:{action}:{view.kind.lower()}:{view.operation_id}"
    if len(data.encode("utf-8")) > 64:
        raise RichViewHold("CALLBACK_TOO_LONG")
    return data


def parse_callback(data):
    if not isinstance(data, str):
        raise RichViewHold("CALLBACK_INVALID")
    match = re.fullmatch(r"u7:([rd]):(cz07|uo):([a-f0-9]{16,64})", data)
    if not match or len(data.encode("utf-8")) > 64:
        raise RichViewHold("CALLBACK_INVALID")
    action, kind, ref = match.groups()
    return ("CZ07" if kind == "cz07" else "UO", ref, action)


def _progress(view):
    if view.moved is None or view.total is None:
        return "— (آمار تأیید نشده)"
    if not (0 <= view.moved <= view.total):
        return "— (مغایرت شمارش)"
    return f"{view.moved}/{view.total}"


def render_card(view: OperationView, *, details=False, refresh_stamp=None):
    """Bot API 10.3 InputRichMessage, blocks-only. Never HTML fallback."""
    _identity(view.kind, view.operation_id, view.actor, view.chat)
    if type(view.stage) is not int or view.stage not in range(8):
        raise RichViewHold("INVALID_STAGE")
    if type(view.version) is not int or view.version < 0:
        raise RichViewHold("INVALID_EVENT_VERSION")
    if refresh_stamp is not None and (not isinstance(refresh_stamp, str)
            or not re.fullmatch(r"[a-f0-9]{8}", refresh_stamp)):
        raise RichViewHold("INVALID_REFRESH_REFERENCE")
    title, explanation, policy = issue(view.code)
    if view.code in ("", "UNSPECIFIED"):
        title, explanation, policy = ("وضعیت در Journal ثبت شده است",
                                       "وضعیت فعلی تنها از رکورد عملیات خوانده شده است.",
                                       "READ_DIAGNOSE")
    timeline = []
    accepted = set(view.accepted_steps)
    if not accepted.issubset(set(range(8))):
        raise RichViewHold("INVALID_ACCEPTED_MILESTONES")
    for index, label in enumerate(STAGES):
        # Never infer a checkmark simply from the current step number.
        icon = "✅" if index in accepted else ("🔹" if index == view.stage else "▫️")
        timeline.append({"type": "paragraph", "text": f"{icon} {label}"})
    blocks = [
        {"type": "heading", "size": 3, "text": "📊 مرکز عملیات Edge"},
        {"type": "paragraph", "text": [
            {"type": "bold", "text": "وضعیت: "},
            STATE_LABELS.get(view.state, "نیازمند بررسی")]},
        {"type": "table", "is_compact": True,
         "cells": [
             [{"text": "شناسه"}, {"text": view.operation_id[:12]}],
             [{"text": "مرحله"}, {"text": f"{view.stage + 1} / 8"}],
             [{"text": "مبدأ"}, {"text": view.source}],
             [{"text": "مقصد"}, {"text": view.target}],
             [{"text": "انتقال حساب"}, {"text": _progress(view)}],
         ]},
        {"type": "divider"},
        {"type": "heading", "size": 5, "text": "وضعیت مراحل"},
        *timeline,
        {"type": "details", "summary": "🔎 جزئیات فنی و اقدام مجاز",
         "is_open": bool(details), "blocks": [
             {"type": "paragraph", "text": f"کد: {view.code}"},
             {"type": "paragraph", "text": f"توضیح: {title}"},
             {"type": "paragraph", "text": explanation},
             {"type": "paragraph", "text": f"راهبرد: {policy}"},
             {"type": "paragraph", "text": f"نسخه Journal: {view.version}"},
             {"type": "paragraph", "text": f"وضعیت سیستمی: {view.state[:36]}"},
             *([{"type": "paragraph", "text": f"شناسه بازبینی: {refresh_stamp}"}]
               if refresh_stamp else []),
         ]},
        {"type": "buttons", "align": "right", "buttons": [
            {"text": "🔄 تازه‌سازی", "style": "primary",
             "callback_data": _callback(view, "r")},
            {"text": "🔎 جزئیات فنی", "callback_data": _callback(view, "d")},
        ]},
    ]
    if view.state in ("VERIFYING", "RECONCILE_REQUIRED", "HOLD", "PAUSED_SAFE"):
        blocks.insert(1, {"type": "paragraph", "text": [
            {"type": "bold", "text": "⚠️ عملیات هنوز پذیرفته نشده است"}
        ]})
    return {"blocks": blocks, "is_rtl": True, "skip_entity_detection": True}
