"""Emergency-credit kill switch for NVL.

New emergency borrowing is intentionally disabled. Historical emergency balances
remain in the ledger and may still be repaid from legitimate wallet credits.
"""

EMERGENCY_CREDIT_ENABLED = False

EMERGENCY_CREDIT_CALLBACKS = frozenset({
    "uinc_emergency_yes",
    "buy_emergency_yes",
    "v2rn_emergency_yes",
    "v2addvol_emergency_yes",
    "v2_vol_buy_emergency_yes",
    "v2_buy_emergency_yes",
    "rnyes_emergency",
})


def is_emergency_credit_enabled() -> bool:
    return EMERGENCY_CREDIT_ENABLED


def emergency_approval_active(value) -> bool:
    """Old Telegram callback state must never authorize borrowing while disabled."""
    return bool(EMERGENCY_CREDIT_ENABLED and value)


def is_emergency_credit_callback(callback_data) -> bool:
    return isinstance(callback_data, str) and callback_data in EMERGENCY_CREDIT_CALLBACKS
