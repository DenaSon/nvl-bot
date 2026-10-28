"""Phase 7 Rich-only transport and durable delivery intent.

Explicit API; NO bot handler, global timer, startup task, or HTML fallback.
Raw Bot API transport avoids PTB 22.8 private interfaces. Callers pass a
verified PTB bot.token, authorized DB connection and an approved operation.
"""
from __future__ import annotations

import asyncio
import json
import secrets
import sqlite3
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from cloudzy_rich_admin import (
    RichViewHold, read_operation, render_card,
)


class RichDeliveryHold(RuntimeError):
    """A stable, sanitized delivery code, never a raw token-bearing URL."""


class RichBotAPI:
    """Narrow async Bot API adapter, with injected request for offline tests."""

    def __init__(self, bot_token, *, transport=None):
        if not isinstance(bot_token, str) or not bot_token or any(
                character.isspace() for character in bot_token):
            raise RichDeliveryHold("BOT_TOKEN_UNAVAILABLE")
        self._token = bot_token
        self._transport = transport or self._post

    def _post(self, method, data):
        url = "https://api.telegram.org/bot" + self._token + "/" + method
        body = json.dumps(data, ensure_ascii=False,
                          separators=(",", ":")).encode("utf-8")
        try:
            with urlopen(Request(
                    url, data=body, method="POST",
                    headers={"Content-Type": "application/json"}), timeout=15
            ) as response:
                result = json.load(response)
        except HTTPError as exc:
            # Do not expose URLs, response body or the bot token in logs.
            if exc.code == 429:
                raise RichDeliveryHold("TELEGRAM_RATE_LIMITED") from None
            if exc.code in (400, 403, 404):
                raise RichDeliveryHold("TELEGRAM_MESSAGE_UNAVAILABLE") from None
            raise RichDeliveryHold("TELEGRAM_HTTP_UNCERTAIN") from None
        except (URLError, TimeoutError, OSError, ValueError):
            raise RichDeliveryHold("TELEGRAM_DELIVERY_UNCERTAIN") from None
        if not isinstance(result, dict):
            raise RichDeliveryHold("TELEGRAM_RESPONSE_UNVERIFIED")
        if result.get("ok") is not True:
            raise RichDeliveryHold("TELEGRAM_RESPONSE_UNVERIFIED")
        return result["result"]

    async def send(self, *, chat_id, rich_message):
        result = await asyncio.to_thread(
            self._transport, "sendRichMessage", {
                "chat_id": chat_id,
                "rich_message": rich_message,
                "protect_content": True,
            }
        )
        if not isinstance(result, dict) or type(result.get("message_id")) is not int:
            raise RichDeliveryHold("TELEGRAM_SEND_RECEIPT_UNVERIFIED")
        return result["message_id"]

    async def edit(self, *, chat_id, message_id, rich_message):
        result = await asyncio.to_thread(
            self._transport, "editMessageText", {
                "chat_id": chat_id, "message_id": message_id,
                "rich_message": rich_message,
            }
        )
        # For chat-id edits Telegram returns a Message; no inline edit is used.
        if not isinstance(result, dict) or result.get("message_id") != message_id:
            raise RichDeliveryHold("TELEGRAM_EDIT_RECEIPT_UNVERIFIED")
        return True


class DurableRichDelivery:
    """One card per (kind, operation, admin chat), with fail-closed outbox."""

    def __init__(self, *, db_conn, api, now=time.time):
        self.db = db_conn
        self.api = api
        self.now = now

    @staticmethod
    def initialize(db):
        """Explicit additive schema, NEVER called on bot module import."""
        db.execute("""CREATE TABLE IF NOT EXISTS cloudzy_rich_message_pointers (
            kind TEXT NOT NULL, operation_id TEXT NOT NULL,
            actor INTEGER NOT NULL, chat INTEGER NOT NULL,
            message_id INTEGER NOT NULL, delivered_version INTEGER NOT NULL,
            details INTEGER NOT NULL, updated_at INTEGER NOT NULL,
            PRIMARY KEY(kind,operation_id,chat)
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS cloudzy_rich_delivery_outbox (
            attempt TEXT PRIMARY KEY, kind TEXT NOT NULL,
            operation_id TEXT NOT NULL, actor INTEGER NOT NULL,
            chat INTEGER NOT NULL, version INTEGER NOT NULL,
            details INTEGER NOT NULL, method TEXT NOT NULL,
            status TEXT NOT NULL, reason TEXT NOT NULL,
            message_id INTEGER, created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        )""")
        db.execute("""CREATE INDEX IF NOT EXISTS cloudzy_rich_pending_delivery
            ON cloudzy_rich_delivery_outbox
            (kind,operation_id,chat,status)""")

    def pending(self, *, kind, operation_id, chat):
        with self.db() as db:
            if db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='cloudzy_rich_delivery_outbox'"
            ).fetchone() is None:
                return ()
            return tuple(db.execute(
                "SELECT attempt,status,reason,version FROM "
                "cloudzy_rich_delivery_outbox WHERE kind=? AND "
                "operation_id=? AND chat=? AND status != 'SENT' "
                "ORDER BY created_at,attempt",
                (kind, operation_id, chat)
            ).fetchall())

    def _intent(self, view, *, details, fresh=False, refresh=False):
        """Commit journal intent BEFORE attempting Telegram network effects."""
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            self.initialize(db)
            # Re-evaluate owner/version against authoritative source under lock.
            live = read_operation(
                db, kind=view.kind, operation_id=view.operation_id,
                actor=view.actor, chat=view.chat)
            if live.version != view.version or live.state != view.state:
                raise RichViewHold("RENDER_SNAPSHOT_STALE")
            pointer = db.execute(
                "SELECT message_id,delivered_version,details FROM "
                "cloudzy_rich_message_pointers WHERE kind=? "
                "AND operation_id=? AND chat=?",
                (view.kind, view.operation_id, view.chat)
            ).fetchone()
            if db.execute(
                "SELECT 1 FROM cloudzy_rich_delivery_outbox WHERE kind=? "
                "AND operation_id=? AND chat=? AND status != 'SENT' LIMIT 1",
                (view.kind, view.operation_id, view.chat)
            ).fetchone():
                raise RichDeliveryHold("PRIOR_TELEGRAM_DELIVERY_UNCERTAIN")
            if pointer and int(pointer[1]) > view.version:
                return None  # Never overwrite a newer acknowledged snapshot.
            if (pointer and not (fresh or refresh)
                    and int(pointer[1]) == view.version
                    and bool(pointer[2]) == details):
                return None
            # A pointer can be edited after an event update; no silent resend
            # after missing/deleted Telegram message or prior ambiguous request.
            method = "SEND" if fresh or not pointer else "EDIT"
            message_id = int(pointer[0]) if pointer else None
            attempt = secrets.token_hex(16)
            db.execute(
                "INSERT INTO cloudzy_rich_delivery_outbox "
                "(attempt,kind,operation_id,actor,chat,version,details,method,"
                "status,reason,message_id,created_at,updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (attempt, view.kind, view.operation_id, view.actor, view.chat,
                 view.version, int(details), method, "INTENT", "PENDING",
                 message_id, int(self.now()), int(self.now()))
            )
            return attempt, method, message_id

    def _mark_uncertain(self, attempt, reason):
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "UPDATE cloudzy_rich_delivery_outbox SET status='UNCERTAIN',"
                "reason=?,updated_at=? WHERE attempt=? AND status='INTENT'",
                (reason, int(self.now()), attempt)
            )

    def _ack(self, view, *, details, attempt, message_id):
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            intent = db.execute(
                "SELECT status FROM cloudzy_rich_delivery_outbox "
                "WHERE attempt=?", (attempt,)
            ).fetchone()
            if intent != ("INTENT",):
                raise RichDeliveryHold("DELIVERY_INTENT_STALE")
            # A newer event may have occurred while Telegram was responding.
            # We acknowledge ONLY the rendered version; next refresh can update.
            db.execute(
                "INSERT INTO cloudzy_rich_message_pointers "
                "(kind,operation_id,actor,chat,message_id,delivered_version,"
                "details,updated_at) VALUES (?,?,?,?,?,?,?,?) "
                "ON CONFLICT(kind,operation_id,chat) DO UPDATE SET "
                "message_id=excluded.message_id,"
                "delivered_version=excluded.delivered_version,"
                "details=excluded.details,updated_at=excluded.updated_at",
                (view.kind, view.operation_id, view.actor, view.chat,
                 message_id, view.version, int(details), int(self.now()))
            )
            if db.execute(
                "UPDATE cloudzy_rich_delivery_outbox SET status='SENT',"
                "reason='ACKNOWLEDGED',message_id=?,updated_at=? "
                "WHERE attempt=? AND status='INTENT'",
                (message_id, int(self.now()), attempt)
            ).rowcount != 1:
                raise RichDeliveryHold("DELIVERY_ACK_CAS_FAILED")

    async def render_once(self, *, kind, operation_id, actor, chat,
                          details=False, fresh=False, refresh=False):
        """Explicit authorized rich send/edit; NEVER executes business actions.

        Recoverable Telegram ambiguity holds just this delivery, not CZ07/UO.
        """
        with self.db() as db:
            view = read_operation(db, kind=kind, operation_id=operation_id,
                                  actor=actor, chat=chat)
        # Render and validate before committing a delivery intent. A malformed
        # card must NEVER leave an unfulfillable INTENT in the durable outbox.
        # Unique reference prevents identical-content edits on repeated clicks.
        message = render_card(
            view, details=details,
            refresh_stamp=secrets.token_hex(4) if (fresh or refresh) else None)
        intent = self._intent(view, details=details,
                              fresh=fresh, refresh=refresh)
        if intent is None:
            return "UNCHANGED"
        attempt, method, message_id = intent
        try:
            if method == "EDIT":
                await self.api.edit(chat_id=chat, message_id=message_id,
                                    rich_message=message)
            else:
                message_id = await self.api.send(chat_id=chat,
                                                rich_message=message)
            self._ack(view, details=details, attempt=attempt,
                      message_id=message_id)
        except Exception as exc:
            # Do not replace/duplicate a possibly already delivered message.
            code = str(exc) if isinstance(exc, RichDeliveryHold) else \
                "TELEGRAM_DELIVERY_UNCERTAIN"
            self._mark_uncertain(attempt, code)
            raise RichDeliveryHold(code) from None
        return "SENT"
