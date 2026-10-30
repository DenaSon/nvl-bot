"""Simple Telegram HTML + inline buttons for manual Edge administration.

Send-only navigation: no Rich-card edits or shared Telegram message pointer.
Transport uses the existing guarded raw Bot API client; no PTB dependency.
"""
from __future__ import annotations

import asyncio

from cloudzy_rich_transport import RichBotAPI, RichDeliveryHold
from manual_edge_rich import render_manual_card


class ManualHtmlBotAPI(RichBotAPI):
    """Narrow standard Bot API adapter, with injectable offline transport."""

    async def send_html(self, *, chat_id, text, keyboard):
        body={
            "chat_id":chat_id,
            "text":text,
            "parse_mode":"HTML",
            "protect_content":True,
            "link_preview_options":{"is_disabled":True},
        }
        if keyboard is not None:
            body["reply_markup"]=keyboard
        result=await asyncio.to_thread(self._transport,"sendMessage",body)
        if (not isinstance(result,dict)
                or type(result.get("message_id")) is not int
                or result["message_id"] <= 0):
            raise RichDeliveryHold("TELEGRAM_SEND_RECEIPT_UNVERIFIED")
        return result["message_id"]


class ManualHtmlDelivery:
    def __init__(self, bot, *, api_factory=ManualHtmlBotAPI):
        token=getattr(bot,"token",None)
        self.api=api_factory(token)

    @staticmethod
    def _keyboard(text, rows):
        # Strict, existing allowlist: callback scopes / 64 byte maximum,
        # authorized HTTPS WebApp path, screen contents and row bounds.
        render_manual_card(text, rows)
        if len(text)>4096:
            raise RichDeliveryHold("TELEGRAM_MESSAGE_TOO_LONG")
        keyboard=[]
        for group in rows:
            buttons=[]
            for label, action in group:
                if isinstance(action,str):
                    buttons.append({"text":label,"callback_data":action})
                else:
                    buttons.append({"text":label,"web_app":{
                        "url":action["web_app"]["url"]}})
            keyboard.append(buttons)
        return {"inline_keyboard":keyboard} if keyboard else None

    async def send(self, *, chat, text, rows):
        if type(chat) is not int or chat <= 0:
            raise RichDeliveryHold("TELEGRAM_CHAT_INVALID")
        keyboard=self._keyboard(text,rows)
        # No retry after uncertain delivery. No business action is replayed.
        return await self.api.send_html(
            chat_id=chat,text=text,keyboard=keyboard)

    async def show(self, *, chat, context, text, rows):
        if not hasattr(context,"user_data"):
            raise RichDeliveryHold("TELEGRAM_CONTEXT_INVALID")
        return await self.send(chat=chat,text=text,rows=rows)
