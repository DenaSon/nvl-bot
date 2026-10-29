"""Rich-only Telegram screens for manual Edge wizard (Bot API 10.3).

All action screens are InputRichMessage blocks and RichMessageButton rows.
The HTTPS credential intake remains a separate, explicitly authorized Web App.
Never downgrade to parse_mode=HTML or legacy inline-keyboard messages.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urlsplit

from cloudzy_rich_transport import RichBotAPI, RichDeliveryHold


class ManualRichHold(RuntimeError):
    pass


class _VisibleText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []

    def handle_data(self, text):
        self.parts.append(text)

    def handle_starttag(self, tag, attrs):
        if tag in ("br", "p", "h3", "h4", "h5"):
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("p", "h3", "h4", "h5"):
            self.parts.append("\n")


def _readable(source):
    if not isinstance(source, str) or len(source) > 4500:
        raise ManualRichHold("RICH_SCREEN_INVALID")
    parser = _VisibleText()
    try:
        parser.feed(source)
        parser.close()
    except ValueError as exc:
        raise ManualRichHold("RICH_SCREEN_INVALID") from exc
    plain = "".join(parser.parts).strip()
    if not plain or "<" in plain or ">" in plain or "\x00" in plain:
        raise ManualRichHold("RICH_SCREEN_INVALID")
    return [v.strip() for v in re.split(r"\n+", plain) if v.strip()]


def render_manual_card(text, rows):
    """Strict native Rich blocks; preserves existing callback permissions."""
    lines = _readable(text)
    if not lines or len(lines) > 32:
        raise ManualRichHold("RICH_SCREEN_INVALID")
    if not isinstance(rows, (list, tuple)) or len(rows) > 12:
        raise ManualRichHold("RICH_ACTION_INVALID")
    blocks = [{"type": "heading", "size": 3, "text": lines[0]}]
    for line in lines[1:]:
        if len(line) > 500:
            raise ManualRichHold("RICH_SCREEN_INVALID")
        blocks.append({"type": "paragraph", "text": line})
    if len(lines) == 1:
        blocks.append({"type": "paragraph", "text": "وضعیت و اقدام بعدی را انتخاب کنید."})
    for group in rows:
        if not 1 <= len(group) <= 8:
            raise ManualRichHold("RICH_ACTION_INVALID")
        buttons = []
        for item in group:
            if not isinstance(item, tuple) or len(item) != 2:
                raise ManualRichHold("RICH_ACTION_INVALID")
            label, action = item
            if not isinstance(label, str) or not 1 <= len(label) <= 70:
                raise ManualRichHold("RICH_ACTION_INVALID")
            if isinstance(action, str):
                if (not action.startswith(("apps_edge_manual_", "apps_cz_",
                                           "apps_cz7_", "apps_home"))
                        or not 1 <= len(action.encode("utf-8")) <= 64):
                    raise ManualRichHold("RICH_ACTION_INVALID")
                button = {"text": label, "callback_data": action}
            elif isinstance(action, dict) and set(action) == {"web_app"}:
                web = action["web_app"]
                url = web.get("url") if isinstance(web, dict) else None
                parsed = urlsplit(url) if isinstance(url, str) else None
                if (not parsed or parsed.scheme != "https" or not parsed.netloc
                        or parsed.username or parsed.password or parsed.fragment
                        or not parsed.path.endswith("/manual-edge/form")):
                    raise ManualRichHold("RICH_WEBAPP_INVALID")
                button = {"text": label, "web_app": {"url": url}}
            else:
                raise ManualRichHold("RICH_ACTION_INVALID")
            if "لغو" in label or "انصراف" in label:
                button["style"] = "danger"
            elif label.startswith(("✅", "➕", "📝", "🔐", "🔁")):
                button["style"] = "primary"
            buttons.append(button)
        blocks.append({"type": "buttons", "align": "right", "buttons": buttons})
    return {"blocks": blocks, "is_rtl": True, "skip_entity_detection": True}


class ManualRichDelivery:
    """One Rich message per admin session. No HTML/inline reply fallback.

    If an edit is uncertain, the UI returns an explicit delivery error; it
    does not replay an effect or send another uncertain duplicate.
    """

    def __init__(self, token, *, api_factory=RichBotAPI):
        self.api = api_factory(token)

    async def show(self, *, chat, context, text, rows):
        if type(chat) is not int or not hasattr(context, "user_data"):
            raise ManualRichHold("RICH_OPERATOR_UNAVAILABLE")
        card = render_manual_card(text, rows)
        pointer = context.user_data.get("manual_edge_rich_pointer")
        if type(pointer) is int and pointer > 0:
            await self.api.edit(chat_id=chat, message_id=pointer, rich_message=card)
            return pointer
        mid = await self.api.send(chat_id=chat, rich_message=card)
        if type(mid) is not int or mid <= 0:
            raise RichDeliveryHold("TELEGRAM_SEND_RECEIPT_UNVERIFIED")
        context.user_data["manual_edge_rich_pointer"] = mid
        return mid
