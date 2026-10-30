"""Simple, safe Telegram HTML + InlineKeyboard screens for manual Edge flows.

No Rich edit pointer or rich-message delivery. Each screen is an ordinary
Telegram message, so stale/previous inline cards cannot lock navigation.
All callbacks and WebApp URL constraints use the existing audited validator.
"""
from __future__ import annotations

from telegram import InlineKeyboardButton, InlineKeyboardMarkup

from manual_edge_rich import render_manual_card


class ManualHtmlDelivery:
    def __init__(self, bot):
        if not callable(getattr(bot, "send_message", None)):
            raise ValueError("TELEGRAM_BOT_REQUIRED")
        self.bot = bot

    @staticmethod
    def _keyboard(text, rows):
        # Validate markup, callback prefixes/64-byte limit, HTTPS-only WebApp,
        # label lengths and row count before exposing any Telegram controls.
        render_manual_card(text, rows)
        keyboard = []
        for group in rows:
            buttons = []
            for label, action in group:
                if isinstance(action, str):
                    buttons.append(InlineKeyboardButton(label, callback_data=action))
                else:
                    buttons.append(InlineKeyboardButton(
                        label, web_app=action["web_app"]))
            keyboard.append(buttons)
        return InlineKeyboardMarkup(keyboard) if keyboard else None

    async def send(self, *, chat, text, rows):
        if type(chat) is not int or chat <= 0:
            raise ValueError("TELEGRAM_CHAT_INVALID")
        keyboard = self._keyboard(text, rows)
        # Never retry an uncertain send: stateful actions must not be replayed.
        message = await self.bot.send_message(
            chat_id=chat,
            text=text,
            parse_mode="HTML",
            reply_markup=keyboard,
            disable_web_page_preview=True,
            protect_content=True,
        )
        mid = getattr(message, "message_id", None)
        if type(mid) is not int or mid <= 0:
            raise ValueError("TELEGRAM_SEND_RECEIPT_UNVERIFIED")
        return mid

    async def show(self, *, chat, context, text, rows):
        if not hasattr(context, "user_data"):
            raise ValueError("TELEGRAM_CONTEXT_INVALID")
        return await self.send(chat=chat, text=text, rows=rows)
