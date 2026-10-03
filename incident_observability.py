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

_AUTO_REASON_MAP = {
    "AUTO_DISABLED": REASON_AUTO_DISABLED,
    "PROVIDER_NOT_OK": REASON_PROVIDER_ERROR,
    "NO_SAFE_STANDBY": REASON_NO_SAFE_STANDBY,
    "SWITCH_COOLDOWN_ACTIVE": REASON_SWITCH_COOLDOWN,
    "ATTEMPT_COOLDOWN_ACTIVE": REASON_ATTEMPT_COOLDOWN,
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
        REASON_CONFIRMATION_PENDING: "منتظر تأیید سریع فیلترینگ",
        REASON_FILTER_CONFIRMED: "فیلترینگ با اطمینان بالا تأیید شد",
        REASON_NO_DEFAULT_EDGE: "Default Edge تعریف نشده است",
        REASON_AUTO_DISABLED: "Auto Failover غیرفعال است",
        REASON_PROVIDER_ERROR: "Regional Provider در دسترس نیست",
        REASON_PROVIDER_LIMITED: "Regional Provider موقتاً Rate Limited شده است",
        REASON_NO_STANDBY: "هیچ Standby تعریف نشده است",
        REASON_NO_SAFE_STANDBY: "Standby وجود دارد اما هیچ‌کدام Safety Gate را پاس نکرده‌اند",
        REASON_SWITCH_COOLDOWN: "Switch cooldown هنوز فعال است",
        REASON_ATTEMPT_COOLDOWN: "Attempt cooldown هنوز فعال است",
        REASON_PREFLIGHT_FAILED: "Preflight امن Failover رد شد",
        REASON_FAILOVER_BUSY: "یک Failover دیگر در حال اجراست",
        REASON_FAILOVER_EXCEPTION: "Failover با خطای اجرایی متوقف شد",
        REASON_ROLLBACK_FAILED: "Rollback کامل نشد",
        REASON_FAILOVER_STARTED: "Failover امن شروع شد",
        REASON_FAILOVER_SUCCEEDED: "Failover با موفقیت کامل شد",
        REASON_FILTER_RECOVERED: "دسترسی منطقه‌ای بازیابی شد",
        REASON_EVIDENCE_DEGRADED: "Evidence منطقه‌ای برای تصمیم قطعی کافی نیست",
    }
    return labels.get(str(reason or ""), str(reason or "UNKNOWN"))



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
