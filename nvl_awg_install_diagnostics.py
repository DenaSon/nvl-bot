"""Safe, operator-visible diagnostics for the AWG new-Edge install.

Only fixed stage labels and validated symbolic codes may reach Telegram or
SQLite. Never forward stderr, exception strings, credentials or AWG key data.
"""
from __future__ import annotations

import re
import sqlite3
import subprocess

STAGES = {
    "WIZARD_PREFLIGHT": "بررسی اولیه ویزارد",
    "CORE_PREFLIGHT": "بررسی آمادگی Core و دیتابیس",
    "SSH_CONNECT": "احراز هویت SSH سرور جدید",
    "EDGE_PRECHECK": "بررسی خالی‌بودن VPS و نصب کلید مدیریت",
    "EDGE_STAGING": "انتقال امن فایل‌های نصب",
    "EDGE_INSTALL": "نصب AWG و تنظیم قوانین شبکه روی VPS",
    "CORE_PEER": "ثبت Peer جدید در Core",
    "CORE_PATH": "بررسی اتصال تونل Core به Edge",
    "EDGE_NAT": "بررسی NAT و پایداری سرویس‌های Edge",
    "DB_REGISTER": "ثبت نهایی Edge در دیتابیس",
    "WIZARD_POSTCHECK": "آزمون نهایی هویت و اتصال",
    "UNKNOWN": "مرحله نامشخص",
}
CAUSES = {
    "SSH_AUTH_FAILED": "رمز یا روش احراز هویت SSH پذیرفته نشد.",
    "SSH_CONNECTION_FAILED": "اتصال مدیریتی SSH برقرار نشد.",
    "SSH_HOST_KEY_CHANGED": "کلید هویت SSH سرور تغییر کرده است.",
    "EDGE_REMOTE_COMMAND_FAILED": "اجرای دستور روی سرور جدید ناموفق بود.",
    "EDGE_REMOTE_COMMAND_TIMEOUT": "دستور سرور جدید در زمان مجاز کامل نشد.",
    "EDGE_INSTALL_TIMEOUT": "نصب روی VPS در بازه مجاز تمام نشد.",
    "EDGE_AWG_INSTALL_UNVERIFIED": "نصب‌کننده پایان موفق را تأیید نکرد.",
    "AWG_NAT_PERSISTENCE_UNVERIFIED": "قوانین شبکه یا ماندگاری آن‌ها تأیید نشد.",
    "EDGE_POOL_ALREADY_REGISTERED": "سرور از قبل در فهرست Edge ثبت شده است.",
    "AWG_BINDING_COLLISION": "آدرس تونل یا هویت Peer تکراری است.",
    "CORE_FILE_MISSING_OR_NOT_PRIVATE": "فایل تنظیمات Core وجود ندارد یا دسترسی ایمن ندارد.",
    "AWG_INSTALLER_NOT_DEPLOYED": "نصب‌کننده AWG روی Core مستقر نیست.",
    "EDGE_INSTALL_ROOT_REQUIRED": "نصب‌کننده روی VPS با دسترسی Root اجرا نشده است.",
    "EDGE_INSTALL_EXISTING_AWG_CONFIG": "روی VPS از قبل تنظیمات AWG وجود دارد.",
    "EDGE_INSTALL_EXISTING_AWG_LINK": "رابط AWG از قبل روی VPS وجود دارد.",
    "EDGE_INSTALL_EXISTING_WG_LINK": "رابط WireGuard از قبل روی VPS وجود دارد.",
    "EDGE_INSTALL_EXISTING_WG_OR_AWG_TUNNEL": "روی VPS تونل دیگری از قبل فعال است.",
    "EDGE_INSTALL_CUSTOMER_PORT_ALREADY_LISTENING": "پورت مشتری از قبل توسط سرویسی اشغال شده است.",
    "EDGE_INSTALL_CUSTOMER_PORT_EXISTING_NAT": "برای پورت مشتری از قبل قانون NAT وجود دارد.",
    "EDGE_INSTALL_AWG_31_MODULE_REQUIRED": "ماژول AWG 3.1 نصب یا شناسایی نشد.",
    "EDGE_INSTALL_AWG_31_TOOLS_REQUIRED": "ابزار AWG 3.1 نصب یا شناسایی نشد.",
    "EDGE_INSTALL_UBUNTU_2404_REQUIRED": "سیستم‌عامل VPS باید Ubuntu 24.04 باشد.",
    "EDGE_INSTALL_STAGED_CONFIG_NOT_PRIVATE": "مجوز فایل موقت AWG روی VPS ایمن نیست.",
    "EDGE_INSTALL_STAGED_CONFIG_MISSING": "فایل موقت AWG روی VPS یافت نشد.",
    "LOCAL_COMMAND_FAILED": "دستور محلی در Core ناموفق بود.",
    "COMMAND_TIMEOUT": "یک فرمان محلی در زمان مجاز تمام نشد.",
    "DATABASE_OPERATION_FAILED": "ثبت یا بررسی اطلاعات SQLite ناموفق بود.",
    "UNEXPECTED_FAILURE": "خطای پیش‌بینی‌نشده رخ داد؛ کد و مرحله برای بررسی ثبت شده‌اند.",
    "AWG_INSTALLER_NOT_CONFIGURED": "تابع نصب AWG در برنامه پیکربندی نشده است.",
    "EDGE_POSTCHECK_FAILED": "بررسی نهایی اتصال Edge موفق نشد.",
    "HOST_KEY_CHANGED_AFTER_INSTALL": "کلید SSH سرور بعد از نصب تغییر کرده است.",
    "LEGACY_INSTALL_OR_TUNNEL_FAILED": "نصب یا اتصال Edge تأیید نشد.",
    "UBUNTU24_ROOT_REQUIRED": "ورود Root یا نسخه Ubuntu 24.04 تأیید نشد.",
    "AWG_CORE_NOT_READY": "پیش‌نیازهای AWG روی Core آماده نیست.",
    "MANUAL_HOST_POOL_MISMATCH": "ثبت سرور در دیتابیس با وضعیت نصب سازگار نیست.",
    "CORE_WG_INSTALL_BUSY": "نصب دیگری در حال اجراست.",
    "CORE_WG_INSTALL_LEASE_BUSY": "پرونده نصب دیگری هنوز فعال است.",
}
# These shell failure codes are emitted by our root-owned one-time installer;
# never accept arbitrary remote stderr or a token with non-symbolic content.
SHELL_HOLDS = frozenset((
    "ROOT_REQUIRED", "EXPECT_SIX_PUBLIC_ARGS", "STAGED_CONFIG_MISSING",
    "STAGED_CONFIG_NOT_PRIVATE", "EXISTING_AWG_CONFIG",
    "EXISTING_AWG_LINK", "EXISTING_WG_LINK", "EXISTING_WG_OR_AWG_TUNNEL",
    "SERVICE_PORT_COLLISION", "ADMIN_PORT_COLLISION", "UBUNTU_REQUIRED",
    "UBUNTU_2404_REQUIRED", "WAN_UNVERIFIED",
    "CUSTOMER_PORT_ALREADY_LISTENING", "CUSTOMER_PORT_EXISTING_NAT",
    "AWG_TOOLS_MISSING", "AWG_31_MODULE_REQUIRED", "AWG_31_TOOLS_REQUIRED",
    "AWG_INTERFACE_NOT_READY",
))
PROGRESS = frozenset(("START", "BASE_PACKAGES", "PPA_ENABLED",
                      "AWG_PACKAGES", "AWG_SERVICE", "NAT_PERSISTED"))
_DIAG = re.compile(r"\AAWG:([A-Z_]{3,24}):([A-Z][A-Z0-9_]{2,52})\Z")


def validated(stage: str, code: str) -> tuple[str, str]:
    """Canonical, bounded, non-secret receipt values."""
    if stage not in STAGES:
        stage = "UNKNOWN"
    if not isinstance(code, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{2,52}", code):
        code = "UNEXPECTED_FAILURE"
    return stage, code


def receipt(stage: str, code: str) -> str:
    stage, code = validated(stage, code)
    return f"AWG:{stage}:{code}"


def classify(exc: Exception) -> str:
    """Do not leak raw third-party exception text into the UI or journal."""
    if type(exc).__name__ == "AuthenticationException":
        return "SSH_AUTH_FAILED"
    if type(exc).__name__ in (
        "NoValidConnectionsError", "SSHException", "ConnectionRefusedError",
        "ConnectionResetError", "TimeoutError", "OSError",
    ):
        return "SSH_CONNECTION_FAILED"
    if isinstance(exc, subprocess.TimeoutExpired):
        return "COMMAND_TIMEOUT"
    if isinstance(exc, subprocess.CalledProcessError):
        return "LOCAL_COMMAND_FAILED"
    if isinstance(exc, (sqlite3.Error,)):
        return "DATABASE_OPERATION_FAILED"
    if type(exc).__name__ in ("AWGProvisionHold", "AWGPlanHold",
                              "LegacyWGLeaseHold", "ManualEdgeHold",
                              "ManualWizardHold"):
        code = str(exc)
        if isinstance(code, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{2,52}", code):
            return code
    return "UNEXPECTED_FAILURE"


def describe(value: str, op_id: str) -> str:
    """Return an HTML-escaped-by-construction explanation for a private admin chat."""
    match = _DIAG.fullmatch(value or "")
    if not match:
        return ""
    stage, code = validated(*match.groups())
    # Symbolic tokens have no HTML metacharacters. No exception text is used.
    cause = CAUSES.get(code, "این مرحله با خطای فنی ثبت‌شده متوقف شد؛ نصب را تکرار نکنید.")
    if code.startswith("EDGE_INSTALL_AFTER_"):
        prior = code.removeprefix("EDGE_INSTALL_AFTER_")
        cause = "نصب روی VPS پس از مرحله " + {
            "START": "شروع نصب", "BASE_PACKAGES": "بسته‌های پایه",
            "PPA_ENABLED": "افزودن مخزن AWG",
            "AWG_PACKAGES": "نصب بسته‌های AWG",
            "AWG_SERVICE": "راه‌اندازی سرویس AWG",
            "NAT_PERSISTED": "ثبت قوانین NAT",
        }.get(prior, "نامشخص") + " متوقف شد."
    return (
        "⛔️ <b>نصب AWG متوقف شد.</b>\n\n"
        f"📍 مرحله: <b>{STAGES[stage]}</b>\n"
        f"🔎 علت: {cause}\n"
        f"🧩 کد فنی: <code>{code}</code>\n"
        f"📋 شناسه پرونده: <code>{op_id}</code>\n\n"
        "⚠️ ممکن است بخشی از نصب روی VPS انجام شده باشد. "
        "همین نصب را دوباره آغاز نکنید؛ از وضعیت سرور برای بازیابی استفاده کنید."
    )
