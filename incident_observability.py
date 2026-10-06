"""V119-B pure incident-observability policy helpers.

No SQLite, Telegram, network or failover side effects live here. Runtime code uses
these helpers to normalize incident states/reasons and decide when an operator
notification is meaningful.
"""

from __future__ import annotations

from dataclasses import dataclass


INCIDENT_STATE_SUSPECTED = "SUSPECTED"
INCIDENT_STATE_CONFIRMING = "CONFIRMING"
INCIDENT_STATE_FILTER_CONFIRMED = "FILTER_CONFIRMED"
INCIDENT_STATE_FAILOVER_BLOCKED = "FAILOVER_BLOCKED"
INCIDENT_STATE_FAILOVER_STARTED = "FAILOVER_STARTED"
INCIDENT_STATE_FAILOVER_SUCCEEDED = "FAILOVER_SUCCEEDED"
INCIDENT_STATE_FAILOVER_FAILED = "FAILOVER_FAILED"
INCIDENT_STATE_EVIDENCE_DEGRADED = "EVIDENCE_DEGRADED"
INCIDENT_STATE_RECOVERED = "RECOVERED"

REASON_REGIONAL_SUSPECTED = "REGIONAL_SUSPECTED"
REASON_CONFIRMATION_PENDING = "CONFIRMATION_PENDING"
REASON_FILTER_CONFIRMED = "FILTER_CONFIRMED"
REASON_NO_DEFAULT_EDGE = "NO_DEFAULT_EDGE"
REASON_AUTO_DISABLED = "AUTO_DISABLED"
REASON_PROVIDER_ERROR = "PROVIDER_ERROR"
REASON_PROVIDER_LIMITED = "PROVIDER_LIMITED"
REASON_NO_STANDBY = "NO_STANDBY"
REASON_NO_SAFE_STANDBY = "NO_SAFE_STANDBY"
REASON_SWITCH_COOLDOWN = "SWITCH_COOLDOWN"
REASON_ATTEMPT_COOLDOWN = "ATTEMPT_COOLDOWN"
REASON_PREFLIGHT_FAILED = "PREFLIGHT_FAILED"
REASON_FAILOVER_BUSY = "FAILOVER_BUSY"
REASON_FAILOVER_EXCEPTION = "FAILOVER_EXCEPTION"
REASON_ROLLBACK_FAILED = "ROLLBACK_FAILED"
REASON_FAILOVER_SUCCEEDED = "FAILOVER_SUCCEEDED"
REASON_FILTER_RECOVERED = "FILTER_RECOVERED"
REASON_EVIDENCE_DEGRADED = "EVIDENCE_DEGRADED"
REASON_FAILOVER_BLOCKED = "FAILOVER_BLOCKED"
REASON_FAILOVER_STARTED = "FAILOVER_STARTED"
REASON_DIFFERENTIAL_NOT_CONFIRMED = "DIFFERENTIAL_NOT_CONFIRMED"
REASON_DIFFERENTIAL_STALE = "DIFFERENTIAL_STALE"
REASON_WIDESPREAD_NETWORK_OUTAGE = "WIDESPREAD_NETWORK_OUTAGE"

_AUTO_REASON_MAP = {
    "AUTO_DISABLED": REASON_AUTO_DISABLED,
    "PROVIDER_NOT_OK": REASON_PROVIDER_ERROR,
    "NO_SAFE_STANDBY": REASON_NO_SAFE_STANDBY,
    "SWITCH_COOLDOWN_ACTIVE": REASON_SWITCH_COOLDOWN,
    "ATTEMPT_COOLDOWN_ACTIVE": REASON_ATTEMPT_COOLDOWN,
    "DIFFERENTIAL_NOT_CONFIRMED": REASON_DIFFERENTIAL_NOT_CONFIRMED,
    "DIFFERENTIAL_STALE": REASON_DIFFERENTIAL_STALE,
    "WIDESPREAD_NETWORK_OUTAGE": REASON_WIDESPREAD_NETWORK_OUTAGE,
}

_FAILOVER_RESULT_REASON_MAP = {
    "PREFLIGHT_FAILED": REASON_PREFLIGHT_FAILED,
    "FAILOVER_BUSY": REASON_FAILOVER_BUSY,
    "FAILOVER_EXCEPTION": REASON_FAILOVER_EXCEPTION,
    "ROLLBACK_FAILED": REASON_ROLLBACK_FAILED,
    "FINAL_DNS_FAILED_CORE_RESTORE_FAILED": REASON_FAILOVER_EXCEPTION,
    "FINAL_DNS_FAILED_ROLLED_BACK": REASON_FAILOVER_EXCEPTION,
}


@dataclass(frozen=True)
class IncidentClassification:
    state: str
    reason: str
    actionable: bool


def classify_filter_incident(
    *,
    filter_state: str,
    confidence: str,
    failure_streak: int,
    confirm_threshold: int,
) -> IncidentClassification | None:
    state = str(filter_state or "").upper()
    confidence = str(confidence or "").upper()
    streak = max(0, int(failure_streak or 0))
    threshold = max(1, int(confirm_threshold or 1))

    if state == "POSSIBLE":
        return IncidentClassification(
            INCIDENT_STATE_SUSPECTED,
            REASON_REGIONAL_SUSPECTED,
            False,
        )
    if state == "LIKELY":
        if confidence == "HIGH" and streak >= threshold:
            return IncidentClassification(
                INCIDENT_STATE_FILTER_CONFIRMED,
                REASON_FILTER_CONFIRMED,
                True,
            )
        return IncidentClassification(
            INCIDENT_STATE_CONFIRMING,
            REASON_CONFIRMATION_PENDING,
            False,
        )
    if state == "UNKNOWN":
        return IncidentClassification(
            INCIDENT_STATE_EVIDENCE_DEGRADED,
            REASON_EVIDENCE_DEGRADED,
            False,
        )
    return None


def normalize_auto_block_reason(
    decision_reason: str,
    *,
    configured_standby_count: int = 0,
    safe_standby_count: int = 0,
) -> str:
    raw = str(decision_reason or "").upper()
    if raw == "NO_SAFE_STANDBY":
        if int(configured_standby_count or 0) <= 0:
            return REASON_NO_STANDBY
        if int(safe_standby_count or 0) <= 0:
            return REASON_NO_SAFE_STANDBY
    return _AUTO_REASON_MAP.get(raw, raw or REASON_FAILOVER_BLOCKED)


def normalize_failover_result_reason(reason: str) -> str:
    raw = str(reason or "").upper()
    return _FAILOVER_RESULT_REASON_MAP.get(raw, raw or REASON_FAILOVER_EXCEPTION)


def should_notify_incident(
    *,
    previous_state: str | None,
    previous_reason: str | None,
    new_state: str,
    new_reason: str,
) -> bool:
    """Notify only for a meaningful incident state/reason transition."""
    return (
        str(previous_state or "") != str(new_state or "")
        or str(previous_reason or "") != str(new_reason or "")
    )


def reason_label_fa(reason: str) -> str:
    labels = {
        REASON_REGIONAL_SUSPECTED: "اختلال منطقه‌ای مشکوک شناسایی شد",
        REASON_CONFIRMATION_PENDING: "بررسی تکمیلی برای تأیید اختلال در حال انجام است",
        REASON_FILTER_CONFIRMED: "اختلال منطقه‌ای با اطمینان بالا تأیید شد",
        REASON_NO_DEFAULT_EDGE: "سرور اصلی تعریف نشده است",
        REASON_AUTO_DISABLED: "انتقال خودکار غیرفعال است",
        REASON_PROVIDER_ERROR: "سرویس بررسی منطقه‌ای در دسترس نیست",
        REASON_PROVIDER_LIMITED: "سرویس بررسی منطقه‌ای موقتاً محدود شده است",
        REASON_NO_STANDBY: "هیچ سرور جایگزینی تعریف نشده است",
        REASON_NO_SAFE_STANDBY: "هیچ سرور جایگزین آماده و ایمنی در دسترس نیست",
        REASON_SWITCH_COOLDOWN: "زمان ایمنی پس از آخرین انتقال هنوز تمام نشده است",
        REASON_ATTEMPT_COOLDOWN: "فاصلهٔ ایمنی تا تلاش بعدی هنوز تمام نشده است",
        REASON_PREFLIGHT_FAILED: "بررسی‌های ایمنی پیش از انتقال تأیید نشد",
        REASON_FAILOVER_BUSY: "یک انتقال دیگر در حال اجراست",
        REASON_FAILOVER_EXCEPTION: "انتقال به‌دلیل خطای اجرایی متوقف شد",
        REASON_ROLLBACK_FAILED: "بازگردانی کامل نشد",
        REASON_FAILOVER_STARTED: "انتقال امن شروع شد",
        REASON_FAILOVER_SUCCEEDED: "انتقال با موفقیت کامل شد",
        REASON_FILTER_RECOVERED: "دسترسی منطقه‌ای بازیابی شد",
        REASON_EVIDENCE_DEGRADED: "اطلاعات فعلی برای تصمیم قطعی کافی نیست",
        REASON_DIFFERENTIAL_NOT_CONFIRMED: "تأیید مقایسه‌ای کافی برای انتقال خودکار وجود ندارد",
        REASON_DIFFERENTIAL_STALE: "تأیید مقایسه‌ای قدیمی شده و باید دوباره بررسی شود",
        REASON_WIDESPREAD_NETWORK_OUTAGE: "اختلال گسترده اینترنت شناسایی شده و انتقال خودکار موقتاً متوقف است",
    }
    return labels.get(str(reason or ""), "علت نامشخص")


def standby_failure_label_fa(reason: str) -> str:
    raw = str(reason or "")
    if raw.startswith("LOCAL_EVIDENCE_STALE:"):
        return "اطلاعات سلامت محلی قدیمی است"
    labels = {
        "INACTIVE": "سرور غیرفعال است",
        "SERVICE_NOT_OK": "سرویس کاربران آماده نیست",
        "ADMIN_NOT_OK": "دسترسی مدیریتی آماده نیست",
        "WG_NOT_OK": "ارتباط WireGuard آماده نیست",
        "CORE_PATH_NOT_OK": "مسیر ارتباط با هسته آماده نیست",
        "EXTERNAL_NOT_OK": "دسترسی بیرونی سرویس تأیید نشده است",
        "FILTER_NOT_CLEAR": "وضعیت دسترسی منطقه‌ای سرور شفاف نیست",
        "REGIONAL_EVIDENCE_STALE": "نتیجهٔ بررسی منطقه‌ای قدیمی است",
    }
    return labels.get(raw, "شرایط ایمنی کامل نیست")


def standby_safety_failures(health) -> tuple[str, ...]:
    """Explain why one configured Standby is not an automatic safe candidate."""
    health = health or {}
    failures = []
    if str(health.get("filter_state") or "").upper() != "CLEAR":
        failures.append("FILTER_NOT_CLEAR")
    for key, code in (
        ("service_ok", "SERVICE_NOT_OK"),
        ("admin_ok", "ADMIN_NOT_OK"),
        ("wg_peer_ok", "WG_NOT_OK"),
        ("core_path_ok", "CORE_PATH_NOT_OK"),
        ("external_service_ok", "EXTERNAL_NOT_OK"),
    ):
        if health.get(key) is not True:
            failures.append(code)
    return tuple(failures)

def is_terminal_state(state: str) -> bool:
    return str(state or "") in {
        INCIDENT_STATE_FAILOVER_SUCCEEDED,
        INCIDENT_STATE_RECOVERED,
    }
