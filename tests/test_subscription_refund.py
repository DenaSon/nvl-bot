from decimal import Decimal

import pytest

from subscription_refund import (
    RefundCalculationError,
    calculate_time_based_refund,
)


def test_two_user_three_month_plan_refunds_remaining_month_correctly():
    assert calculate_time_based_refund(
        "160000", 2, remaining_days=30
    ) == Decimal("320000")


def test_two_user_three_month_plan_full_remaining_period():
    assert calculate_time_based_refund(
        "160000", 2, remaining_days=90
    ) == Decimal("960000")


def test_hidden_hold_refunds_full_purchased_duration_for_two_users():
    assert calculate_time_based_refund(
        "160000", 2, hold_active=True, hold_duration_days=90
    ) == Decimal("960000")


def test_single_user_partial_month_refund():
    assert calculate_time_based_refund(
        "160000", 1, remaining_days=15
    ) == Decimal("80000")


def test_expired_account_has_no_time_refund():
    assert calculate_time_based_refund(
        "160000", 2, remaining_days=-2
    ) == Decimal("0")


def test_hidden_hold_without_plan_duration_fails_closed():
    with pytest.raises(RefundCalculationError):
        calculate_time_based_refund(
            "160000", 2, hold_active=True, hold_duration_days=None
        )
