"""Side-effect-free SSH deletion refund math.

NVL agent base_price is *monthly per allowed user*, not a prepaid total for
arbitrary account lifetime. Never divide the monthly amount by account age.
Historical paid-price reconciliation remains a separate finance audit concern.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP


@dataclass(frozen=True)
class SSHRefund:
    amount: int
    days: int
    reason: str


def _day(value) -> date:
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value)[:10])


def calculate_ssh_refund(
    *,
    monthly_price,
    users_limit,
    expire_date,
    creation_date,
    hold_active=False,
    hold_duration_days=None,
    today=None,
) -> SSHRefund:
    """Return a non-negative whole-toman refund for an existing SSH account.

    A waiting/hidden-hold account receives its *purchased* days rather than
    the temporary Linux hold expiry. For old rows without hold_duration_days,
    preserve the legacy one-month fallback and explicitly label it.
    """
    try:
        monthly = Decimal(str(monthly_price).replace(",", "").strip())
        users = int(users_limit)
        if not monthly.is_finite() or monthly <= 0 or users <= 0:
            return SSHRefund(0, 0, "INVALID_PRICE_OR_USER_LIMIT")

        if hold_active:
            fallback = hold_duration_days is None or str(hold_duration_days).strip() == ""
            days = 30 if fallback else int(hold_duration_days)
            if not 1 <= days <= 3650:
                return SSHRefund(0, 0, "INVALID_HOLD_DURATION")
            reason = "HOLD_LEGACY_30_DAY_FALLBACK" if fallback else "HOLD_UNUSED"
        else:
            created = _day(creation_date)
            expiry = _day(expire_date)
            now = _day(today) if today is not None else date.today()
            if expiry <= created:
                return SSHRefund(0, 0, "INVALID_ACCOUNT_DATES")
            days = max(0, (expiry - now).days)
            if not days:
                return SSHRefund(0, 0, "EXPIRED")
            reason = "UNUSED_DAYS"

        money = (monthly * Decimal(users) * Decimal(days) / Decimal(30)).quantize(
            Decimal("1"), rounding=ROUND_HALF_UP
        )
        return SSHRefund(int(money), days, reason)
    except (TypeError, ValueError, OverflowError, InvalidOperation):
        return SSHRefund(0, 0, "INVALID_REFUND_INPUT")
