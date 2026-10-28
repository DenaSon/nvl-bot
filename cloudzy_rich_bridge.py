"""Phase 7 read-only Rich UI bridge for authenticated NVL Telegram admins.

Source admission is deliberately OFF by default. This never executes
Cloudzy/Cloudflare, CZ07 mutating callbacks, SSH writes, or migration workers.
"""
from __future__ import annotations

import logging
import os
import sqlite3

from cloudzy_rich_admin import RichViewHold, parse_callback, OP_ID
from cloudzy_rich_transport import (
    DurableRichDelivery, RichBotAPI, RichDeliveryHold,
)

log = logging.getLogger(__name__)
ENTRY = "apps_cz_rich_home"
PREFIX = "u7:"


def rich_enabled(env=None):
    source = os.environ if env is None else env
    return source.get("NVL_CLOUDZY_RICH_UI_ENABLED", "0") == "1"


def configured_admin_ids(env=None):
    """Explicitly allowlist 1–3 admins; never infer authorization from history."""
    source = os.environ if env is None else env
    raw = source.get("NVL_CLOUDZY_RICH_ADMIN_IDS", "")
    values = [value.strip() for value in raw.split(",")]
    if not values or len(values) > 3 or any(
            not value.isascii() or not value.isdigit() or int(value) <= 0
            for value in values):
        return frozenset()
    ids = frozenset(int(value) for value in values)
    return ids if len(ids) == len(values) else frozenset()


def can_view(*, role, actor, chat, is_private, env=None):
    """Bot auth and exact private-chat/owner/allowlist checks are cumulative."""
    if not rich_enabled(env):
        return False
    if (role != "admin" or type(actor) is not int or type(chat) is not int
            or actor <= 0 or actor != chat or is_private is not True):
        return False
    return actor in configured_admin_ids(env)


def _table_exists(db, name):
    return bool(db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone())


def latest_owned_operation(db: sqlite3.Connection, *, actor, chat):
    """SELECT-only; absent tables, invalid IDs and other owners stay invisible."""
    if type(actor) is not int or type(chat) is not int or actor != chat:
        raise RichViewHold("OPERATOR_IDENTITY_INVALID")
    hits = []
    if _table_exists(db, "cloudzy_cz07_jobs"):
        for job_id, ts in db.execute(
                "SELECT id,started_at FROM cloudzy_cz07_jobs "
                "WHERE actor=? AND chat=? ORDER BY started_at DESC,id DESC LIMIT 3",
                (actor, chat)).fetchall():
            if isinstance(job_id, str) and OP_ID.fullmatch(job_id):
                hits.append((int(ts or 0), "CZ07", job_id))
    if _table_exists(db, "cloudzy_uo_operations"):
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


def empty_card():
    """No account or Cloudzy credentials exposed in this safe neutral card."""
    return {
        "blocks": [
            {"type": "heading", "size": 3, "text": "☁️ داشبورد Unified Edge"},
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
        role, actor, chat, is_private, api_factory=RichBotAPI, env=None):
    """Opt-in read-only callback; no mutation API or HTML fallback.

    The central PTB handler has already acknowledged the Telegram callback.
    Failures stay within Rich UI; they never change the underlying operations.
    """
    if not isinstance(data, str) or not (
            data == ENTRY or data.startswith(PREFIX)):
        return "NOT_OURS"
    if not can_view(role=role, actor=actor, chat=chat,
                    is_private=is_private, env=env):
        log.warning("Phase7 Rich access rejected: role/allowlist/private guard")
        return "DENIED"
    try:
        with db_factory() as db:
            if data == ENTRY:
                target = latest_owned_operation(db, actor=actor, chat=chat)
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
        return await delivery.render_once(
            kind=kind, operation_id=reference, actor=actor, chat=chat,
            details=details,
        )
    except (RichViewHold, RichDeliveryHold, sqlite3.Error, ValueError) as exc:
        code = str(exc) if isinstance(exc, (RichViewHold, RichDeliveryHold)) \
            else "RICH_DATABASE_UNAVAILABLE"
        # Never log user content, raw provider details, URLs, chat ids or token.
        log.warning("Phase7 Rich UI held: code=%s", code[:90])
        return "HOLD"
    except Exception:
        log.exception("Phase7 Rich UI unexpected error (no business effects)")
        return "HOLD"
