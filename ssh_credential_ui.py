"""Presentation-only helpers for NVL SSH credentials and Napsternet QR delivery.

No credentials or QR payloads are written to disk or sent to third-party services.
"""
import io
from html import escape

import qrcode
from telegram import CopyTextButton, InlineKeyboardButton


def credential_fields_text(host: str, username: str, password: str, port) -> str:
    """Keep visible credentials available as selectable text alongside copy buttons."""
    return (
        f"🌐 <b>سرور:</b> <code>{escape(str(host))}</code>\n"
        f"👤 <b>نام کاربری:</b> <code>{escape(str(username))}</code>\n"
        f"🔑 <b>رمز عبور:</b> <code>{escape(str(password))}</code>\n"
        f"🔌 <b>پورت:</b> <code>{escape(str(port))}</code>"
    )


def _copy_button(label: str, value) -> InlineKeyboardButton | None:
    """Telegram CopyTextButton supports only 1–256 characters."""
    value = str(value) if value is not None else ""
    if not 1 <= len(value) <= 256:
        return None
    return InlineKeyboardButton(label, copy_text=CopyTextButton(text=value))


def ssh_connection_action_rows(
    username: str,
    password: str,
    host: str,
    port,
    *,
    qr_callback: str,
    text_callback: str,
) -> list[list[InlineKeyboardButton]]:
    """Two link actions and copyable individual fields; never attempt a 512-char copy."""
    rows = [
        [
            InlineKeyboardButton("📱 نمایش QR اتصال", callback_data=qr_callback),
            InlineKeyboardButton("🔗 لینک متنی", callback_data=text_callback),
        ]
    ]
    for items in (
        [("👤 کپی نام کاربری", username), ("🔑 کپی رمز", password)],
        [("🌐 کپی سرور", host), ("🔌 کپی پورت", port)],
    ):
        buttons = [button for label, value in items if (button := _copy_button(label, value))]
        if buttons:
            rows.append(buttons)
    return rows


def napsternet_qr_png(link: str) -> io.BytesIO:
    """Encode the exact full npvt-ssh URI, including its scheme, in an in-memory PNG."""
    if not link.startswith("npvt-ssh://"):
        raise ValueError("Expected npvt-ssh URI")
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=4,
    )
    qr.add_data(link, optimize=0)
    qr.make(fit=True)
    buffer = io.BytesIO()
    qr.make_image(fill_color="black", back_color="white").save(buffer, format="PNG")
    buffer.name = "nvl-ssh-connection.png"
    buffer.seek(0)
    return buffer
