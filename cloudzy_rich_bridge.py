"""Phase 7 read-only Rich UI bridge for authenticated NVL Telegram admins.

Directly available to currently authenticated, active admin sessions in
private chats. Never executes infrastructure actions or migration workers.
"""
from __future__ import annotations

import logging
import sqlite3

from cloudzy_rich_admin import RichViewHold, parse_callback, OP_ID
from cloudzy_rich_transport import (
    DurableRichDelivery, RichBotAPI, RichDeliveryHold,
)

log = logging.getLogger(__name__)
ENTRY = "apps_cz_rich_home"
ENTRY_MIGRATION = "apps_cz_rich_migration"
PREFIX = "u7:"


def can_view(*, role, actor, chat, is_private, active_admin_ids):
    """Only active NVL admins, in their own private chat, may access Rich UI.

    The caller must additionally enforce the existing authenticated session.
    The active IDs are reloaded from NVL's admin registry, not historical
    Telegram IDs or an environment Feature Flag.
    """
    if (role != "admin" or type(actor) is not int or type(chat) is not int
            or actor <= 0 or actor != chat or is_private is not True):
        return False
    return isinstance(active_admin_ids, (frozenset, set, tuple)) and actor in active_admin_ids


def _table_exists(db, name):
    return bool(db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone())


def latest_owned_operation(db: sqlite3.Connection, *, actor, chat,
                           only_kind=None):
    """SELECT-only; absent tables, invalid IDs and other owners stay invisible."""
    if type(actor) is not int or type(chat) is not int or actor != chat:
        raise RichViewHold("OPERATOR_IDENTITY_INVALID")
    if only_kind not in (None, "CZ07"):
        raise RichViewHold("OPERATION_KIND_INVALID")
    hits = []
    if _table_exists(db, "cloudzy_cz07_jobs"):
        for job_id, ts in db.execute(
                "SELECT id,started_at FROM cloudzy_cz07_jobs "
                "WHERE actor=? AND chat=? ORDER BY started_at DESC,id DESC LIMIT 3",
                (actor, chat)).fetchall():
            if isinstance(job_id, str) and OP_ID.fullmatch(job_id):
                hits.append((int(ts or 0), "CZ07", job_id))
    if only_kind is None and _table_exists(db, "cloudzy_uo_operations"):
        for op_id, ts in db.execute(
                "SELECT id,updated_at FROM cloudzy_uo_operations "
                "WHERE actor=? AND chat=? ORDER BY updated_at DESC,id DESC LIMIT 3",
                (actor, chat)).fetchall():
            if isinstance(op_id, str) and OP_ID.fullmatch(op_id):
                hits.append((int(ts or 0), "UO", op_id))
    if not hits:
        return None
    _ts, kind, reference = max(hits)
    return kind, reference


def assert_original_card(db, *, kind, operation_id, actor, chat, message_id):
    """A read-only rich callback must refer to this admin's acknowledged card."""
    if type(message_id) is not int or message_id <= 0:
        raise RichViewHold("RICH_CALLBACK_ORIGIN_INVALID")
    if not _table_exists(db, "cloudzy_rich_message_pointers"):
        raise RichViewHold("RICH_CARD_NOT_ACKNOWLEDGED")
    row = db.execute(
        "SELECT actor,message_id FROM cloudzy_rich_message_pointers "
        "WHERE kind=? AND operation_id=? AND chat=?",
        (kind, operation_id, chat)
    ).fetchone()
    if row is None or row != (actor, message_id):
        raise RichViewHold("RICH_CARD_NOT_ACKNOWLEDGED")


_PUBLIC_FAILURES = {
    "PRIOR_TELEGRAM_DELIVERY_UNCERTAIN":
        "⚠️ نتیجه ارسال قبلی مشخص نیست. برای جلوگیری از پیام تکراری، "
        "ارسال دوباره متوقف شده؛ وضعیت Outbox را بررسی کنید.",
    "TELEGRAM_MESSAGE_UNAVAILABLE":
        "⚠️ تلگرام پیام Rich را نپذیرفت. کد: TELEGRAM_MESSAGE_UNAVAILABLE",
    "TELEGRAM_DELIVERY_UNCERTAIN":
        "⚠️ پاسخ تلگرام نامشخص است. وضعیت ارسال را در Outbox بررسی کنید.",
    "RICH_CARD_NOT_ACKNOWLEDGED":
        "⚠️ این کارت قدیمی است؛ مرکز عملیات Edge را دوباره از منوی برنامه‌ها باز کنید.",
    "RICH_CALLBACK_ORIGIN_INVALID":
        "⚠️ مبدأ دکمه تأیید نشد. داشبورد را دوباره از منو باز کنید.",
    "RENDER_SNAPSHOT_STALE":
        "⚠️ وضعیت عملیات تغییر کرده است. داشبورد را دوباره باز کنید.",
}


async def _admin_feedback(context, *, actor, chat, is_private, text):
    """Visible diagnostics in the operator's private chat, never in groups.

    This is a plain informational error notice, NOT an HTML Rich-card fallback
    or a replay of the original Telegram delivery intent.
    """
    if is_private is not True or type(actor) is not int or actor != chat:
        return
    try:
        await context.bot.send_message(
            chat_id=chat, text=text, disable_notification=True)
    except Exception:
        # Errors in user feedback cannot change a business operation.
        log.warning("Phase7 Rich feedback delivery unavailable")


def _error_message(code):
    return _PUBLIC_FAILURES.get(
        code, "⚠️ کارت وضعیت عملیات نمایش داده نشد. "
        "خطای ایمن در لاگ Phase7 ثبت شده است؛ عملیات زیرساخت تغییر نکرده."
    )


def empty_card():
    """No account or Cloudzy credentials exposed in this safe neutral card."""
    return {
        "blocks": [
            {"type": "heading", "size": 3, "text": "📊 مرکز عملیات Edge"},
            {"type": "paragraph", "text": (
                "فعلاً پرونده‌ای متعلق به این مدیر در Journal جدید ثبت نشده است."
            )},
            {"type": "paragraph", "text": (
                "برای مشاهده سایر عملیات، از فهرست قدیمی Cloudzy استفاده کنید. "
                "این صفحه صرفاً برای مشاهده است."
            )},
        ],
        "is_rtl": True, "skip_entity_detection": True,
    }


async def handle_rich_admin_callback(
        *, data, query, context, db_factory,
        role, actor, chat, is_private, active_admin_ids,
        api_factory=RichBotAPI):
    """Direct, admin-authenticated read-only callback; no HTML fallback.

    The central PTB handler has already acknowledged the Telegram callback.
    Failures stay within Rich UI; they never change the underlying operations.
    """
    if not isinstance(data, str) or not (
            data in (ENTRY, ENTRY_MIGRATION) or data.startswith(PREFIX)):
        return "NOT_OURS"
    if not can_view(role=role, actor=actor, chat=chat,
                    is_private=is_private, active_admin_ids=active_admin_ids):
        log.warning("Phase7 Rich access rejected: role/active-admin/private guard")
        await _admin_feedback(
            context, actor=actor, chat=chat, is_private=is_private,
            text="⛔️ دسترسی به مرکز عملیات Edge در این نشست تأیید نشد.")
        return "DENIED"
    try:
        with db_factory() as db:
            if data in (ENTRY, ENTRY_MIGRATION):
                target = latest_owned_operation(
                    db, actor=actor, chat=chat,
                    only_kind="CZ07" if data == ENTRY_MIGRATION else None)
                if target is None:
                    # The no-op empty-state card is send-only; no business
                    # identity, timer, or action callback is created.
                    api = api_factory(context.bot.token)
                    await api.send(chat_id=chat, rich_message=empty_card())
                    return "EMPTY"
                kind, reference = target
                details = False
            else:
                kind, reference, action = parse_callback(data)
                details = action == "d"
                message = getattr(query, "message", None)
                assert_original_card(
                    db, kind=kind, operation_id=reference, actor=actor,
                    chat=chat, message_id=getattr(message, "message_id", None))
        api = api_factory(context.bot.token)
        delivery = DurableRichDelivery(db_conn=db_factory, api=api)
        result = await delivery.render_once(
            kind=kind, operation_id=reference, actor=actor, chat=chat,
            details=details,
            fresh=data in (ENTRY, ENTRY_MIGRATION),
            refresh=data not in (ENTRY, ENTRY_MIGRATION),
        )
        return result
    except (RichViewHold, RichDeliveryHold, sqlite3.Error, ValueError) as exc:
        code = str(exc) if isinstance(exc, (RichViewHold, RichDeliveryHold)) \
            else "RICH_DATABASE_UNAVAILABLE"
        # Never log user content, raw provider details, URLs, chat ids or token.
        log.warning("Phase7 Rich UI held: code=%s", code[:90])
        await _admin_feedback(
            context, actor=actor, chat=chat, is_private=is_private,
            text=_error_message(code))
        return "HOLD"
    except Exception:
        log.exception("Phase7 Rich UI unexpected error (no business effects)")
        await _admin_feedback(
            context, actor=actor, chat=chat, is_private=is_private,
            text=_error_message("RICH_UNEXPECTED_ERROR"))
        return "HOLD"
