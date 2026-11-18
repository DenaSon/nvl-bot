"""Time-based subscription refund calculations for NVL."""
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP


class RefundCalculationError(ValueError):
    """Raised when a safe, defensible refund amount cannot be calculated."""


def calculate_time_based_refund(
    base_price,
    users_limit,
    *,
    remaining_days=None,
    hold_active=False,
    hold_duration_days=None,
):
    """Calculate a refund from a per-user, per-30-day price.

    A Hidden Hold has not consumed the purchased service period, so it refunds
    the full recorded plan duration. A normal account refunds only its remaining
    days. The number of permitted users is always included.
    """
    try:
        price = Decimal(str(base_price))
        users = Decimal(str(users_limit))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise RefundCalculationError("قیمت پایه یا تعداد کاربران معتبر نیست.") from exc

    if not price.is_finite() or price <= 0:
        raise RefundCalculationError("قیمت پایه نماینده معتبر نیست.")
    if not users.is_finite() or users <= 0:
        raise RefundCalculationError("تعداد کاربران مجاز معتبر نیست.")

    if hold_active:
        try:
            days = Decimal(str(hold_duration_days))
        except (InvalidOperation, TypeError, ValueError) as exc:
            raise RefundCalculationError("مدت پلن Hidden Hold ثبت نشده است.") from exc
        if not days.is_finite() or days <= 0:
            raise RefundCalculationError("مدت پلن Hidden Hold ثبت نشده است.")
    else:
        try:
            days = Decimal(str(remaining_days))
        except (InvalidOperation, TypeError, ValueError) as exc:
            raise RefundCalculationError("روزهای باقی‌مانده معتبر نیست.") from exc
        if not days.is_finite():
            raise RefundCalculationError("روزهای باقی‌مانده معتبر نیست.")
        days = max(Decimal("0"), days)

    if days <= 0:
        return Decimal("0")

    amount = price * users * days / Decimal("30")
    return amount.quantize(Decimal("1"), rounding=ROUND_HALF_UP)
