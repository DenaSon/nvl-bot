"""Presentation-only Persian UX for Cloudzy / Quick Relay Phase 1.

No Cloudzy API calls, SQL mutations, or transition decisions belong here.
State and action eligibility must come from the existing durable journals.
"""
from __future__ import annotations

from html import escape


RECEIPT_TITLES = {
    "CREATING": "در حال ثبت خرید VPS",
    "CREATE_UNCERTAIN": "نتیجه خرید VPS نامشخص است",
    "CREATED": "VPS خریداری شده است",
    "WAITING": "در انتظار آماده‌شدن VPS",
    "HOLD_WAIT": "آماده‌سازی VPS متوقف شده است",
    "HOLD_IP": "IP سرور هنوز تأیید نشده است",
    "HOLD_SSH": "دسترسی SSH هنوز تأیید نشده است",
    "HOSTKEY_PENDING": "منتظر تأیید اثرانگشت SSH",
    "PROVISIONING": "در حال نصب Edge",
    "HOLD_PROVISION": "نصب Edge نیازمند بررسی است",
    "HOLD_PREFLIGHT": "بررسی امنیتی پیش از نصب متوقف شده است",
    "HOLD_PROVIDER": "پاسخ سرویس‌دهنده نیازمند بررسی است",
    "HOLD_UNKNOWN": "نتیجه عملیات نامشخص است",
    "EDGE_READY": "نصب Edge تأیید شده است",
    "CANCELLED": "پرونده عملیات بسته شده است",
    "REJECTED": "درخواست رد شده است",
}

HOLD_DESCRIPTIONS = {
    "EDGE_APT_LOCK_BUSY": (
        "APT روی VPS مشغول بوده و آماده‌سازی بسته‌ها متوقف شده است.",
        "خرید یا نصب را تکرار نکنید؛ وضعیت همان VPS و آثار نصب باید بررسی شود.",
    ),
    "PARTIAL_OR_UNVERIFIED_LEGACY_INSTALL": (
        "تکمیل نصب Legacy یا سلامت WireGuard تأیید نشده است.",
        "ممکن است بخشی از نصب انجام شده باشد؛ از اجرای دوباره خودداری کنید.",
    ),
    "PROVIDER_OR_IP_NOT_READY": (
        "VPS ساخته شده اما آمادگی یا IP آن هنوز قطعی نیست.",
        "وضعیت همان VPS را بدون خرید مجدد بررسی کنید.",
    ),
    "CREATE_RESULT_UNCERTAIN": (
        "نتیجه درخواست خرید از سرویس‌دهنده قطعی نیست.",
        "ابتدا وجود VPS را بررسی کنید؛ سفارش تازه ثبت نکنید.",
    ),
    "CLOUDZY_IP_ALREADY_REGISTERED": (
        "این IP قبلاً در فهرست سرورها ثبت شده است.",
        "هویت VPS و رکورد موجود را بررسی کنید؛ نصب تکراری انجام ندهید.",
    ),
    "OPERATOR_CANCELLED": (
        "پرونده عملیات به درخواست مدیر بسته شده است.",
        "لغو پرونده VPS را حذف نمی‌کند و هزینه آن ممکن است ادامه داشته باشد.",
    ),
}

CZ07_ISSUES = {
    "NO_CZ06_RUN": (
        "هیچ سابقه معتبر Quick Relay خودکار برای انتقال یافت نشد.",
        "اگر Edge را دستی ساخته‌اید، از مدیریت Standby و مسیر کنترل‌شده CZ-04B استفاده کنید.",
    ),
    "CZ06_STANDBY_PENDING": (
        "نصب Edge انجام شده، اما تأیید Standby هنوز کامل نیست.",
        "از «وضعیت عملیات» ادامه امن Standby را بررسی کنید؛ نصب مجدد نکنید.",
    ),
    "CZ06_HOLD": (
        "آماده‌سازی خودکار Standby با توقف امن روبه‌رو شده است.",
        "جزئیات عملیات و مسیر کنترل‌شده Standby را بررسی کنید.",
    ),
    "CZ06_CANCELLED": (
        "آخرین پرونده Quick Relay لغو شده است.",
        "برای VPS موجود ابتدا فهرست Edgeها را بررسی کنید؛ خرید مجدد الزاماً لازم نیست.",
    ),
    "CZ06_NOT_READY": (
        "آخرین فرایند Quick Relay هنوز به آمادگی Standby نرسیده است.",
        "وضعیت مراحل قبلی را بررسی کنید.",
    ),
    "EDGE_NOT_VERIFIED": (
        "پذیرش نهایی نصب Edge هنوز تأیید نشده است.",
        "ابتدا نتیجه نصب را از پرونده فعلی بررسی کنید.",
    ),
    "HOST_NOT_REGISTERED": (
        "رکورد معتبر و منطبق با VPS در فهرست Edgeها یافت نشد.",
        "هویت VPS و ثبت Edge را بررسی کنید؛ تغییری در مسیر کاربران ندهید.",
    ),
    "PROVIDER_MISMATCH": (
        "مالکیت Cloudzy در رکورد Edge با پرونده عملیات یکسان نیست.",
        "از هرگونه تغییر مسیر خودداری کنید و سوابق VPS را بررسی کنید.",
    ),
    "STANDBY_NOT_READY": (
        "Edge هنوز به‌صورت Standby فعال و تأیید نشده است.",
        "آماده‌سازی Standby یا مدیریت دستی Edge را بررسی کنید.",
    ),
    "STANDBY_ALREADY_DEFAULT": (
        "این Edge از قبل نقش پیش‌فرض دارد و مقصد Standby نیست.",
        "Journal انتقال قبلی و وضعیت مسیر را بررسی کنید.",
    ),
}


def receipt_title(status):
    return RECEIPT_TITLES.get(str(status or ""), "وضعیت عملیات نیازمند بررسی است")


def receipt_result(receipt, run=None):
    state = str(receipt.get("status") or "")
    stage = str((run or {}).get("stage") or "")
    reason = str(receipt.get("hold_reason") or "")
    if state == "EDGE_READY":
        if stage == "READY":
            return "✅ نصب Edge و آماده‌سازی Standby تأیید شده‌اند. برای انتقال، پیش‌نیازهای CZ-07 جداگانه بررسی می‌شوند."
        if run:
            return "✅ نصب Edge تأیید شده است؛ آماده‌سازی Standby هنوز تأیید نهایی ندارد."
        return "✅ نصب Edge تأیید شده است؛ این پرونده مسیر دستی دارد و سابقه READY خودکار CZ-06 نیست."
    if state == "CANCELLED":
        return "ℹ️ پرونده بسته شده است؛ VPS خودکار حذف نشده و ممکن است همچنان هزینه داشته باشد."
    if state in ("CREATING", "CREATED", "WAITING", "PROVISIONING"):
        return "⏳ عملیات هنوز نتیجه نهایی ندارد. خرید و نصب را تکرار نکنید."
    if state == "HOSTKEY_PENDING":
        return "🔐 نصب تا تأیید مستقل اثرانگشت SSH انجام نخواهد شد."
    if state == "CREATE_UNCERTAIN" or state.startswith("HOLD"):
        description, action = HOLD_DESCRIPTIONS.get(reason, (
            "این مرحله با توقف امن یا نتیجه نامشخص ثبت شده است.",
            "قبل از اقدام دوباره، وضعیت و Journal فعلی را بررسی کنید.",
        ))
        return "⚠️ " + description + "\n↪️ " + action
    return "ℹ️ وضعیت همین پرونده را پیش از هر اقدام بعدی بررسی کنید."


def technical_receipt(receipt, run=None):
    """Detail screen for the same recorded operation; never show tokens or keys."""
    rid = escape(str(receipt.get("id") or "")[:32])
    state = escape(str(receipt.get("status") or "")[:80])
    reason = escape(str(receipt.get("hold_reason") or "—")[:90])
    provider = escape(str(receipt.get("provider_server_id") or "—")[:100])
    stage = escape(str((run or {}).get("stage") or "—")[:50])
    detail = escape(str((run or {}).get("detail_code") or "—")[:90])
    return (
        "🔎 <b>جزئیات فنی عملیات Cloudzy</b>\n\n"
        f"شناسه: <code>{rid}</code>\n"
        f"Receipt: <code>{state}</code>\n"
        f"CZ-06: <code>{stage}</code>\n"
        f"علت توقف: <code>{reason}</code>\n"
        f"کد مرحله: <code>{detail}</code>\n"
        f"VPS ID: <code>{provider}</code>\n\n"
        "🛡 این صفحه فقط اطلاعات ثبت‌شده را نشان می‌دهد و هیچ عملیاتی اجرا نمی‌کند."
    )


def cz07_issue(code):
    return CZ07_ISSUES.get(str(code), (
        "پیش‌نیاز انتقال خودکار قابل تأیید نیست.",
        "وضعیت Quick Relay، Standby و Journal را بررسی کنید.",
    ))
