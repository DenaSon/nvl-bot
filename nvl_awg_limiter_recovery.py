"""Operator-initiated, narrowly scoped AWG limiter recovery.

A stale Limiter process may block independent witness attestations after a
trusted code deploy. The Telegram bot must never mint witness markers, alter
DNS/routes/firewall, or bypass cutover proof. Only the exact known stale-image
condition is eligible for a confirmed restart of ssh-limiter.service.
"""
from __future__ import annotations

import os
import sqlite3
import subprocess

from nvl_awg_limiter_witness import (
    LimiterWitnessHold, _approved_source, _live_service_matches_script,
)
from nvl_awg_target import core_limiter_canary_ready
from nvl_tunnel_backend import lookup_binding

RESTARTABLE = "LIMITER_SOURCE_CHANGED_AFTER_START"
TEXT = {
    "READY": "گیت Limiter معتبر است؛ انتقال را از مسیر استاندارد انجام دهید.",
    RESTARTABLE: "فایل Limiter تأیید شده، اما پردازش فعال از قبل از آخرین تغییر فایل اجرا شده است. راه‌اندازی مجدد کنترل‌شده قابل انجام است.",
    "WITNESS_PENDING": "تأییدیه مستقل این Edge موجود یا تازه نیست. لاگ nvl-awg-witness-refresh را بررسی کنید؛ این وضعیت مجوز دورزدن گیت نیست.",
    "RUNNING_LIMITER_SOURCE_MISMATCH": "فایل Limiter با نسخه تأییدشده تطابق ندارد؛ اصلاح نسخه باید خارج از بات و پس از بازبینی انجام شود.",
    "PROMOTER_LIMITER_TEMPLATE_MISSING": "قالب مرجع Limiter در اسکریپت استقرار پیدا نشد.",
    "RUNTIME_FILE_UNAVAILABLE": "یکی از فایل‌های مرجع Limiter موجود نیست.",
    "RUNTIME_FILE_UNTRUSTED": "مجوز یا مالکیت فایل مرجع Limiter معتبر نیست.",
    "LIMITER_SERVICE_NOT_ACTIVE": "سرویس ssh-limiter فعال نیست؛ وضعیت سرویس را در Core بررسی کنید.",
    "LIMITER_PROCESS_IMAGE_MISMATCH": "فرمان پردازش Limiter با نسخه مورد انتظار تفاوت دارد؛ بازیابی خودکار مجاز نیست.",
    "LIMITER_SOURCE_CHANGED_AFTER_START": "کد Limiter پس از شروع پردازش تغییر کرده است؛ ترمیم با تأیید مدیر امکان‌پذیر است.",
    "LIMITER_PROCESS_UNVERIFIED": "هویت پردازش Limiter قابل تأیید نیست؛ بازبینی دستی لازم است.",
    "RUNTIME_COMMAND_UNVERIFIED": "اطلاعات زنده سرویس Limiter به شکل معتبر دریافت نشد.",
    "BINDING_NOT_READY": "Binding تأییدشده AWG برای این Edge پیدا نشد.",
    "RECOVERY_CHECK_FAILED": "بررسی وضعیت Limiter موفق نبود؛ گزارش فنی Core را بررسی کنید.",
}


class LimiterRecoveryHold(RuntimeError):
    pass


def _safe_code(exc: Exception) -> str:
    if isinstance(exc, LimiterWitnessHold) and str(exc) in TEXT:
        return str(exc)
    return "RECOVERY_CHECK_FAILED"


def limiter_status(host: str, *, db_path="/root/master_bot.db") -> str:
    """Read-only: identify the first failing security guard for this Edge."""
    try:
        with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=3) as db:
            binding = lookup_binding(db, host)
        if binding is None or binding.backend != "amneziawg":
            return "BINDING_NOT_READY"
    except (sqlite3.Error, ValueError, OSError):
        return "BINDING_NOT_READY"

    try:
        trusted = _approved_source()
        _live_service_matches_script(trusted)
    except Exception as exc:
        return _safe_code(exc)
    try:
        return ("READY" if core_limiter_canary_ready(binding.edge_tunnel_ip)
                else "WITNESS_PENDING")
    except Exception:
        return "RECOVERY_CHECK_FAILED"


def repair_stale_limiter(host: str, *, runner=subprocess.run,
                         root_check=os.geteuid) -> str:
    """Restart ONLY an already-trusted but stale Limiter process.

    No call to the privileged witness or marker writer. The independent
    systemd timer must independently attest every Edge after this restart.
    """
    if root_check() != 0:
        raise LimiterRecoveryHold("RECOVERY_ROOT_REQUIRED")
    # Recheck immediately before mutation; never restart arbitrary states.
    if limiter_status(host) != RESTARTABLE:
        raise LimiterRecoveryHold("RECOVERY_STATE_CHANGED")
    try:
        result = runner(
            ["systemctl", "restart", "ssh-limiter.service"],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise LimiterRecoveryHold("LIMITER_RESTART_FAILED") from None
    if result.returncode != 0:
        raise LimiterRecoveryHold("LIMITER_RESTART_FAILED")
    observed = limiter_status(host)
    if observed not in ("READY", "WITNESS_PENDING"):
        raise LimiterRecoveryHold("LIMITER_RESTART_NOT_VERIFIED")
    return observed
