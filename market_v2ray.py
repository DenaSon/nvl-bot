"""Direct Market V2Ray/Marzban plan-to-runtime mapping.

This module is deliberately Telegram- and database-agnostic. It converts the
immutable Order snapshot into the exact Marzban create contract and verifies
the authoritative GET payload before Commerce is allowed to capture funds.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

SERVICE_V2RAY = "v2ray"
SERVICE_V2RAY_VOL = "v2ray_vol"
SUPPORTED_SERVICE_TYPES = frozenset({SERVICE_V2RAY, SERVICE_V2RAY_VOL})
GIB = 1024 ** 3


@dataclass(frozen=True)
class ProvisioningSpec:
    service_type: str
    duration_days: int | None
    data_limit_gb: int | None
    data_limit_bytes: int
    users_limit: int
    local_users_limit: int
    expire_timestamp: int
    local_expire_date: str
    reset_strategy: str
    note_marker: str


def _positive_int(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a positive integer")
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be a positive integer") from exc
    if number <= 0:
        raise ValueError(f"{field} must be a positive integer")
    return number


def build_provisioning_spec(
    order: dict,
    *,
    now: datetime | None = None,
) -> ProvisioningSpec:
    service_type = str(order.get("service_type") or "").strip()
    if service_type not in SUPPORTED_SERVICE_TYPES:
        raise ValueError("unsupported Direct Market V2Ray service type")

    order_id = _positive_int(order.get("id"), "order id")
    customer_id = _positive_int(order.get("customer_id"), "customer id")
    users_limit = _positive_int(order.get("users_limit"), "users_limit")
    now = now or datetime.now()

    duration_raw = order.get("duration_days")
    duration_days = None if duration_raw is None else _positive_int(
        duration_raw, "duration_days"
    )
    data_raw = order.get("data_limit_gb")
    data_limit_gb = None if data_raw is None else _positive_int(
        data_raw, "data_limit_gb"
    )

    marker = f"NVL_MARKET_ORDER:{order_id};CUSTOMER:{customer_id}"

    if service_type == SERVICE_V2RAY:
        if duration_days is None:
            raise ValueError("timed V2Ray orders require duration_days")
        expire_at = now + timedelta(days=duration_days)
        data_limit_bytes = (data_limit_gb or 0) * GIB
        # Legacy timed V2Ray uses a daily reset when a cap is configured.
        # A NULL data_limit_gb explicitly means unlimited data.
        reset_strategy = "day" if data_limit_gb else "no_reset"
        note_marker = marker + f";IP_LIMIT:{users_limit}"
        local_users_limit = users_limit
    else:
        if data_limit_gb is None:
            raise ValueError("volume V2Ray orders require data_limit_gb")
        expire_at = now + timedelta(days=duration_days) if duration_days else None
        data_limit_bytes = data_limit_gb * GIB
        reset_strategy = "no_reset"
        note_marker = marker
        # Existing NVL semantics use users_limit=0 locally for volumetric plans,
        # which is rendered as unlimited-user access.
        local_users_limit = 0

    return ProvisioningSpec(
        service_type=service_type,
        duration_days=duration_days,
        data_limit_gb=data_limit_gb,
        data_limit_bytes=data_limit_bytes,
        users_limit=users_limit,
        local_users_limit=local_users_limit,
        expire_timestamp=int(expire_at.timestamp()) if expire_at else 0,
        local_expire_date=expire_at.strftime("%Y-%m-%d") if expire_at else "نامحدود",
        reset_strategy=reset_strategy,
        note_marker=note_marker,
    )


def verify_remote_user(
    payload: Any,
    *,
    username: str,
    spec: ProvisioningSpec,
) -> tuple[bool, str]:
    if not isinstance(payload, dict):
        return False, "Marzban verification payload is not an object"
    if str(payload.get("username") or "") != str(username):
        return False, "Marzban username mismatch"
    if str(payload.get("status") or "").lower() != "active":
        return False, "Marzban user is not active"

    try:
        remote_limit = int(payload.get("data_limit") or 0)
    except (TypeError, ValueError):
        return False, "Marzban data_limit is invalid"
    if remote_limit != int(spec.data_limit_bytes):
        return False, "Marzban data_limit mismatch"

    try:
        remote_expire = int(payload.get("expire") or 0)
    except (TypeError, ValueError):
        return False, "Marzban expire is invalid"
    if remote_expire != int(spec.expire_timestamp):
        return False, "Marzban expire mismatch"

    reset_value = payload.get("data_limit_reset_strategy")
    if reset_value not in (None, ""):
        if str(reset_value).strip().lower() != spec.reset_strategy:
            return False, "Marzban reset strategy mismatch"

    note = str(payload.get("note") or "")
    if spec.note_marker not in note:
        return False, "Marzban ownership marker mismatch"

    return True, "ok"


def classify_create_failure(payload: Any) -> str:
    """Return collision, uncertain, or definite for a failed create call."""
    if isinstance(payload, dict) and bool(payload.get("created")):
        return "uncertain"
    text = str(payload or "").lower()
    if "already exists" in text or "already_exist" in text:
        return "collision"
    if any(
        marker in text
        for marker in (
            "network error",
            "timeout",
            "timed out",
            "connection reset",
            "connection aborted",
            "server disconnected",
        )
    ):
        return "uncertain"
    return "definite"


def is_remote_not_found(payload: Any) -> bool:
    text = str(payload or "").lower()
    return any(
        marker in text
        for marker in (
            "404",
            "not found",
            "does not exist",
            "user not found",
        )
    )
