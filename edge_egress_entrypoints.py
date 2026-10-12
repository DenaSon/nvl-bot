"""D1-C2B: one safety boundary for legacy manual Edge-management entry points.

This module deliberately DOES NOT activate an Edge or route traffic. Telegram
callback/text handlers consult it *before* any DB, SSH, WG or DNS mutation.
In protected mode the existing manual routes are blocked until their adapters
can call the same Phase-6G-locked protected handoff coordinator as 6G/6H.

The legacy unprotected behavior stays the same with the default setting "0".
Unknown settings fail closed. Classifiers match exact prefixes with careful
prefix precedence; generic menus and read-only checks are not blocked.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from edge_egress_lifecycle import (
    PROTECTED_SETTING_DEFAULT, PROTECTED_SETTING_KEY,
    UNKNOWN_MODE,
    _mode,
)


class EdgeOperation(str, Enum):
    REGISTER = "register_edge"
    ACTIVATE = "activate_edge"
    ASSIGN = "assign_existing_accounts"
    DEFAULT = "change_default_edge"
    BLOCK = "block_edge"
    UNBLOCK = "unblock_edge"
    DELETE = "delete_edge"
    STANDBY = "set_edge_standby"
    DNS = "edge_dns_change"
    CORE_MIGRATION = "core_edge_role_migration"


# This list only covers legacy management paths; monitor/UI callbacks are
# intentionally excluded. Add new mutating callback names here with tests.
_EXACT_CALLBACKS: dict[str, EdgeOperation] = {
    "hp_add": EdgeOperation.REGISTER,
    "hp_addedge": EdgeOperation.REGISTER,
    "srv_wiz_promote_start": EdgeOperation.CORE_MIGRATION,
    "srv_run_promote": EdgeOperation.CORE_MIGRATION,
    "srv_run_demote": EdgeOperation.CORE_MIGRATION,
}
_PREFIX_CALLBACKS: tuple[tuple[str, EdgeOperation], ...] = (
    ("hpdefmig_yes_", EdgeOperation.ASSIGN),
    ("hpdef_migrate_", EdgeOperation.ASSIGN),
    ("hpdef_", EdgeOperation.DEFAULT),
    ("srv_mkactive_", EdgeOperation.ACTIVATE),
    ("hpblk_", EdgeOperation.BLOCK),
    ("hpact_", EdgeOperation.UNBLOCK),
    ("hpdelyes_", EdgeOperation.DELETE),
    ("hpdelconfirm_", EdgeOperation.DELETE),
    ("hpstandby_", EdgeOperation.STANDBY),
)

_TEXT_STATES: dict[str, EdgeOperation] = {
    "HOSTS_INPUT": EdgeOperation.REGISTER,
    "HOSTS_APPEND_INPUT": EdgeOperation.REGISTER,
    "HOSTPOOL_ADD_INPUT": EdgeOperation.REGISTER,
    "EDGE_NEW_IP": EdgeOperation.REGISTER,
    "EDGE_NEW_ROOTPASS": EdgeOperation.REGISTER,
    "EDGE_NEW_PORT": EdgeOperation.REGISTER,
    # Promotion/demotion are not Relay handoffs: require separate reconciliation.
    "SRV_PROMOTE_PORT_INPUT": EdgeOperation.CORE_MIGRATION,
    "SRV_PROMOTE_GOST_PORTS": EdgeOperation.CORE_MIGRATION,
    "SRV_PROMOTE_PASS_INPUT": EdgeOperation.CORE_MIGRATION,
}
_EXACT_TEXT_COMMANDS = {
    "tlstoedge": EdgeOperation.DNS,
}


@dataclass(frozen=True)
class EdgeManagementGate:
    action: EdgeOperation
    allowed: bool
    reason: str
    protected_mode: bool


LEGACY_MANUAL_UNSAFE = "EGRESS_PROTECTED_MANUAL_EDGE_WORKFLOW_UNAVAILABLE"
UNAUTHORIZED = "EDGE_MANAGEMENT_ADMIN_REQUIRED"


def classify_edge_callback(data: Optional[str]) -> Optional[EdgeOperation]:
    if not isinstance(data, str):
        return None
    if data in _EXACT_CALLBACKS:
        return _EXACT_CALLBACKS[data]
    for prefix, kind in _PREFIX_CALLBACKS:
        if data.startswith(prefix):
            # Do not reinterpret a missing host suffix as a less-specific
            # command (e.g. hpdef_migrate_ must not become hpdef_).
            return kind if data[len(prefix):] else None
    return None


def classify_edge_text(state: Optional[str], text: Optional[str]) -> Optional[EdgeOperation]:
    if isinstance(state, str) and state in _TEXT_STATES:
        return _TEXT_STATES[state]
    if isinstance(text, str):
        return _EXACT_TEXT_COMMANDS.get(text.strip())
    return None


def evaluate_manual_edge_gate(
    action: EdgeOperation,
    protected_setting: Optional[str],
    *,
    role: str,
) -> EdgeManagementGate:
    """Pure, conservative guard for the STILL-LEGACY manual entry points.

    Setting 0: keep legacy admin behavior. Setting 1: reject rather than
    pretending ingress-only Edge is ready for protected customer Egress.
    This is NOT a protected-operation executor.
    """
    if not isinstance(action, EdgeOperation):
        raise ValueError("Unknown manual Edge action")
    if role != "admin":
        return EdgeManagementGate(action, False, UNAUTHORIZED, False)
    state = _mode(protected_setting)
    if state == "0":
        return EdgeManagementGate(action, True, "LEGACY_UNPROTECTED_MODE", False)
    if state == "invalid":
        return EdgeManagementGate(action, False, UNKNOWN_MODE, True)
    return EdgeManagementGate(action, False, LEGACY_MANUAL_UNSAFE, True)


def edge_guard_message(reason: str) -> str:
    """Static administrator message. Never interpolates user input or secrets."""
    if reason == UNAUTHORIZED:
        return "⛔️ مدیریت Edge فقط برای مدیر مجاز است."
    if reason == UNKNOWN_MODE:
        return "⛔️ تنظیم حالت محافظت Egress نامعتبر است؛ عملیات انجام نشد."
    if isinstance(reason, str) and reason.startswith("EGRESS_J_"):
        messages = {
            "EGRESS_J_SCHEMA_MISSING": "مهاجرت دیتابیس Egress هنوز کامل نشده است.",
            "EGRESS_J_TARGET_INGRESS_UNVERIFIED": "Edge مقصد به عنوان ورودی معتبر ثبت نشده است.",
            "EGRESS_J_TARGET_NOT_F4_READY": "خروجی واقعی Edge مقصد هنوز گواهی READY معتبر ندارد.",
            "EGRESS_J_MAPPING_UNCERTAIN": "نگاشت حساب‌های محافظت‌شده مبهم یا در وضعیت انتقال است.",
            "EGRESS_J_PINNED_UIDS_REQUIRE_DRAIN_REBIND":
                "حساب‌های محافظت‌شده هنوز به Edge قبلی متصل‌اند؛ انتقال بدون Drain و Rebind ممنوع است.",
            "EGRESS_J_PROTECTED_6G_HANDOFF_NOT_RELEASED":
                "تأیید نهایی اجرای انتقال محافظت‌شده در 6G هنوز انجام نشده است.",
        }
        return ("⛔️ سوییچ Edge در حالت محافظت‌شده انجام نشد. "
                + messages.get(reason, "شواهد محافظت Egress کامل نیست.") 
                + " هیچ مسیر یا حسابی تغییر نکرد.")
    if reason == LEGACY_MANUAL_UNSAFE:
        return (
            "⛔️ این مسیر قدیمی مدیریت Edge هنوز به Egress Manager متصل نیست. "
            "برای جلوگیری از قطع کاربران یا خروج از IP سرور Core، عملیات انجام نشد. "
            "تا قبل از تکمیل Provisioning، Health Check و Failover مشترک، "
            "حالت محافظت‌شده را روی Production فعال نکنید."
        )
    return "⛔️ عملیات مدیریت Edge مجاز نیست."
