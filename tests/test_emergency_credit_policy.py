from emergency_credit_policy import (
    EMERGENCY_CREDIT_ENABLED,
    emergency_approval_active,
    is_emergency_credit_callback,
    is_emergency_credit_enabled,
)


def test_emergency_credit_is_disabled_and_stale_approval_is_ignored():
    assert EMERGENCY_CREDIT_ENABLED is False
    assert is_emergency_credit_enabled() is False
    assert emergency_approval_active(True) is False


def test_every_legacy_emergency_confirmation_callback_is_blocked():
    callbacks = {
        "uinc_emergency_yes",
        "buy_emergency_yes",
        "v2rn_emergency_yes",
        "v2addvol_emergency_yes",
        "v2_vol_buy_emergency_yes",
        "v2_buy_emergency_yes",
        "rnyes_emergency",
    }
    assert all(is_emergency_credit_callback(item) for item in callbacks)
    assert not is_emergency_credit_callback("v2rnyes")
    assert not is_emergency_credit_callback("buy_confirm")
