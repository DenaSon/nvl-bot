"""Customer-facing routing constants for NVL Direct Market V1.

This module is intentionally Telegram-agnostic.  Phase 2 only establishes
customer identity and the storefront home; money/provisioning actions remain
disabled until their dedicated phases.
"""

from __future__ import annotations

ROLE_CUSTOMER = "customer"

BUTTON_BUY = "🛒 خرید اشتراک"
BUTTON_SERVICES = "📦 سرویس‌های من"
BUTTON_WALLET = "💰 کیف پول"
BUTTON_TRANSACTIONS = "🧾 تراکنش‌ها"
BUTTON_AGENT_LOGIN = "👨‍💼 ورود نماینده"

CUSTOMER_HOME_KEYBOARD = (
    (BUTTON_BUY, BUTTON_SERVICES),
    (BUTTON_WALLET, BUTTON_TRANSACTIONS),
    (BUTTON_AGENT_LOGIN,),
)

CUSTOMER_PLACEHOLDER_LABELS = frozenset(
    {BUTTON_BUY, BUTTON_SERVICES}
)
CUSTOMER_MENU_LABELS = frozenset(
    {
        BUTTON_BUY,
        BUTTON_SERVICES,
        BUTTON_WALLET,
        BUTTON_TRANSACTIONS,
        BUTTON_AGENT_LOGIN,
    }
)

LEGACY_PORTAL_ROLES = frozenset({"admin", "agent", "accountant"})

CUSTOMER_HOME_TEXT = (
    "🛍 بازار NeVeL\n"
    "━━━━━━━━━━━━━━\n"
    "خرید و مدیریت سرویس‌های شخصی از این بخش انجام می‌شود."
)

CUSTOMER_USE_MENU_TEXT = "لطفاً یکی از گزینه‌های منوی بازار را انتخاب کنید."


def should_open_customer_market(
    *,
    direct_market_enabled: bool,
    is_private_chat: bool,
    authenticated_role: str | None,
) -> bool:
    """Return True only when /start may enter the customer storefront.

    Existing authenticated Admin/Agent/Accountant sessions always keep their
    legacy portal precedence. Customer UI is private-chat only and controlled
    by the master Direct Market feature flag.
    """
    if not direct_market_enabled or not is_private_chat:
        return False
    return authenticated_role not in LEGACY_PORTAL_ROLES


def phase2_placeholder_text(label: str) -> str:
    if label == BUTTON_BUY:
        return (
            "🛒 بخش خرید مستقیم در حال آماده‌سازی است.\n\n"
            "در نسخه فعلی هیچ سفارش یا کسر وجهی از این مسیر انجام نمی‌شود."
        )
    if label == BUTTON_SERVICES:
        return (
            "📦 بخش «سرویس‌های من» پس از فعال‌شدن خرید مستقیم در دسترس قرار می‌گیرد."
        )
    if label == BUTTON_WALLET:
        return (
            "💰 کیف پول مشتری در فاز بعدی فعال می‌شود.\n\n"
            "در حال حاضر از این بخش هیچ شارژ یا برداشت مالی انجام نمی‌شود."
        )
    if label == BUTTON_TRANSACTIONS:
        return (
            "🧾 تاریخچه تراکنش‌های مشتری همراه با کیف پول فعال خواهد شد."
        )
    return CUSTOMER_USE_MENU_TEXT
