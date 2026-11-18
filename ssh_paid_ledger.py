"""Verified per-SSH-account wallet journal and conservative refund exposure model.

Historical activity_log rows are NOT proof of settlement. No retroactive migration
or automatic wallet reconciliation. New verified purchases and all account edits
must pass through the same SQLite transaction as wallet accounting.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from uuid import uuid4

import nvl_daily_business


class SSHFinanceHold(RuntimeError):
    """Manual accounting review is required before an irreversible action."""


@dataclass(frozen=True)
class PaidRefund:
    amount: int
    days: int
    reason: str


def _day(value):
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value)[:10])


def _amount(value):
    try:
        money = Decimal(str(value).replace(",", "").strip())
    except (InvalidOperation, ValueError, TypeError):
        raise SSHFinanceHold("INVALID_PAID_AMOUNT") from None
    if not money.is_finite() or money < 0:
        raise SSHFinanceHold("INVALID_PAID_AMOUNT")
    return money


def _exists(conn, table):
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone() is not None


def install_schema(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS ssh_paid_accounts (
        username TEXT PRIMARY KEY,
        agent_id INTEGER NOT NULL,
        created_on TEXT NOT NULL,
        expected_expiry TEXT NOT NULL,
        expected_users INTEGER NOT NULL,
        verified INTEGER NOT NULL CHECK(verified IN (0,1)),
        closed INTEGER NOT NULL DEFAULT 0 CHECK(closed IN (0,1))
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS ssh_paid_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_key TEXT NOT NULL UNIQUE,
        username TEXT NOT NULL,
        agent_id INTEGER NOT NULL,
        kind TEXT NOT NULL CHECK(kind IN (
            'PURCHASE','EXTEND','SEAT_INCREASE','TIME_REDUCE',
            'ADMIN_ADJUST','DELETE_REFUND','DELETE_ZERO'
        )),
        amount_toman TEXT NOT NULL,
        period_from TEXT,
        period_to TEXT,
        old_expiry TEXT,
        new_expiry TEXT,
        old_users INTEGER,
        new_users INTEGER,
        created_at_utc TEXT NOT NULL
    )""")
    conn.execute("""CREATE INDEX IF NOT EXISTS idx_ssh_paid_events_account
                    ON ssh_paid_events(username,id)""")


def _account(conn, username):
    if not _exists(conn, "ssh_paid_accounts"):
        return None
    return conn.execute(
        "SELECT agent_id,created_on,expected_expiry,expected_users,verified,closed "
        "FROM ssh_paid_accounts WHERE username=?", (username,)
    ).fetchone()


def _append(conn, username, agent, kind, amount, *,
            from_day=None, to_day=None, old_expiry=None, new_expiry=None,
            old_users=None, new_users=None):
    conn.execute(
        "INSERT INTO ssh_paid_events "
        "(event_key,username,agent_id,kind,amount_toman,period_from,period_to,"
        "old_expiry,new_expiry,old_users,new_users,created_at_utc)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            uuid4().hex, username, agent, kind, str(_amount(amount)),
            str(from_day) if from_day is not None else None,
            str(to_day) if to_day is not None else None,
            old_expiry, new_expiry, old_users, new_users,
            datetime.now(timezone.utc).isoformat(),
        )
    )


def _live(conn, username):
    return conn.execute(
        "SELECT agent_id,creation_date,expire_date,users_limit,status,hold_active,"
        "hold_duration_days,service_type FROM ssh_accounts WHERE username=?",
        (username,)
    ).fetchone()


def _matches_live(live, agent, created, expiry, users):
    return (
        live is not None and live[7] == "ssh"
        and live[0] == agent and live[1] == created
        and live[2] == expiry and live[3] == users
    )


def _prove(conn, username, agent, created, expiry, users):
    state = _account(conn, username)
    if state is None or not state[4] or state[5]:
        raise SSHFinanceHold("HISTORICAL_PAYMENT_UNVERIFIED")
    if (state[0], state[1], state[2], state[3]) != (
        agent, created, expiry, users
    ):
        raise SSHFinanceHold("PAID_ACCOUNT_SNAPSHOT_MISMATCH")
    return state


def _paid_quote(conn, username, agent, created, expiry, users, *,
                today=None, hold=False):
    """Exact unused share of verified debit intervals; no current-tariff guess.

    Time reductions shorten the entitlement horizon and return the clipped
    portion once. A seat increase adds its own paid interval. Seat decreases
    require manual accounting review rather than a guessed proportional credit.
    """
    _prove(conn, username, agent, created, expiry, users)
    now = _day(today) if today is not None else date.today()
    end = _day(expiry)
    if not _exists(conn, "ssh_paid_events"):
        raise SSHFinanceHold("PAID_EVENTS_MISSING")
    entries = conn.execute(
        "SELECT kind,amount_toman,period_from,period_to "
        "FROM ssh_paid_events WHERE username=? AND agent_id=? ORDER BY id",
        (username, agent)
    ).fetchall()
    lots = [row for row in entries if row[0] in
            ("PURCHASE", "EXTEND", "SEAT_INCREASE")]
    if not lots or lots[0][0] != "PURCHASE":
        raise SSHFinanceHold("PAID_PURCHASE_MISSING")
    paid = Decimal("0")
    credited = Decimal("0")
    unearned = Decimal("0")
    for kind, value, start_text, stop_text in entries:
        amount = _amount(value)
        if kind in ("PURCHASE", "EXTEND", "SEAT_INCREASE"):
            paid += amount
            if start_text is None or stop_text is None:
                raise SSHFinanceHold("INVALID_PAID_INTERVAL")
            start, stop = _day(start_text), _day(stop_text)
            length = (stop - start).days
            if length <= 0:
                raise SSHFinanceHold("INVALID_PAID_INTERVAL")
            if hold:
                # An unused Hidden Hold has not started consuming paid time.
                days = max(0, (min(stop,end)-start).days)
            else:
                days = max(0, (min(stop,end)-max(start,now)).days)
            unearned += amount * Decimal(days) / Decimal(length)
        elif kind in ("TIME_REDUCE", "DELETE_REFUND"):
            credited += amount
        elif kind == "ADMIN_ADJUST":
            raise SSHFinanceHold("MANUAL_PAID_ACCOUNT_ADJUSTMENT")
        elif kind == "DELETE_ZERO":
            raise SSHFinanceHold("ACCOUNT_ALREADY_CLOSED")
        else:
            raise SSHFinanceHold("UNKNOWN_PAID_EVENT")
    if paid < credited:
        raise SSHFinanceHold("PAID_CREDITS_EXCEED_CHARGES")
    # Every auto-credit must be at most the still-unrefunded paid principal.
    amount = min(unearned, paid - credited).quantize(
        Decimal("1"), rounding=ROUND_HALF_UP
    )
    days = max(0, (end - now).days)
    if hold:
        days = max(0, (end - _day(created)).days)
    return PaidRefund(int(amount), days, "PAID_UNUSED" if amount else "PAID_EXPIRED")


def preview_delete(conn, username, *, agent, created, expiry, users,
                   hold=False, today=None):
    """Read-only, fail-closed refund quote for a verified account.

    Expired legacy accounts can be removed for ZERO credit. All other legacy
    accounts require manual reconciliation BEFORE Linux userdel.
    """
    now = _day(today) if today is not None else date.today()
    if not agent:
        return PaidRefund(0, 0, "DIRECT_ADMIN")
    if not hold and _day(expiry) <= now:
        return PaidRefund(0, 0, "EXPIRED_ZERO")
    return _paid_quote(
        conn, username, agent, created, expiry, users, today=now, hold=hold,
    )


def _charge(conn, agent, money):
    balance_row = conn.execute(
        "SELECT balance FROM agents WHERE id=?", (agent,)
    ).fetchone()
    if balance_row is None or _amount(balance_row[0]) < money:
        raise SSHFinanceHold("INSUFFICIENT_WALLET_FOR_PAID_ACCOUNT")
    if money > 0:
        nvl_daily_business.charge_purchase(conn, agent, float(money))


def create_paid_purchase(conn, *, username, agent, amount,
                         created, expiry, users):
    """Use INSIDE with db_conn() after successful Linux provisioning."""
    conn.execute("BEGIN IMMEDIATE")
    install_schema(conn)
    live = _live(conn, username)
    if not _matches_live(live, agent, created, expiry, users):
        raise SSHFinanceHold("PAID_PURCHASE_SNAPSHOT_CHANGED")
    if not isinstance(agent, int) or agent <= 0 or users <= 0:
        raise SSHFinanceHold("INVALID_PAID_OWNER_OR_SEATS")
    if _account(conn, username) is not None:
        raise SSHFinanceHold("PAID_ACCOUNT_ALREADY_EXISTS")
    if _day(expiry) <= _day(created):
        raise SSHFinanceHold("INVALID_PAID_INTERVAL")
    cost = _amount(amount)
    _charge(conn, agent, cost)
    conn.execute(
        "INSERT INTO ssh_paid_accounts "
        "(username,agent_id,created_on,expected_expiry,expected_users,verified)"
        " VALUES(?,?,?,?,?,1)",
        (username, agent, created, expiry, users),
    )
    _append(conn, username, agent, "PURCHASE", cost, from_day=created,
            to_day=expiry, new_expiry=expiry, new_users=users)
    return cost


def apply_paid_change(conn, *, username, agent, expected_created,
                      expected_expiry, expected_users, expected_status,
                      new_expiry, new_users, kind, amount=0, today=None,
                      repay_emergency=None, mutate=None):
    """Atomically change SSH DB state, per-account journal and wallet.

    External Linux expiry/user-limit updates, if any, must be rolled back by
    caller if this transaction fails. No optimistic historical refund.
    """
    if kind not in ("EXTEND", "SEAT_INCREASE", "TIME_REDUCE",
                    "SEAT_DECREASE", "ADMIN_ADJUST"):
        raise SSHFinanceHold("UNKNOWN_SSH_ACCOUNT_CHANGE")
    now = _day(today) if today is not None else date.today()
    conn.execute("BEGIN IMMEDIATE")
    install_schema(conn)
    live = _live(conn, username)
    if (not _matches_live(live, agent, expected_created, expected_expiry, expected_users)
            or live[4] != expected_status):
        raise SSHFinanceHold("PAID_CHANGE_SNAPSHOT_CHANGED")
    if _day(new_expiry) < now and kind != "ADMIN_ADJUST":
        raise SSHFinanceHold("INVALID_NEW_EXPIRY")
    if new_users <= 0:
        raise SSHFinanceHold("INVALID_NEW_SEATS")
    state = _account(conn, username)
    if state is not None and state[5]:
        raise SSHFinanceHold("PAID_ACCOUNT_ALREADY_CLOSED")
    verified = bool(state and state[4])
    if verified:
        _prove(conn, username, agent, expected_created,
               expected_expiry, expected_users)
    if kind == "SEAT_DECREASE":
        raise SSHFinanceHold("MANUAL_SEAT_REDUCTION_REQUIRED")

    cost = _amount(amount)
    refunded = Decimal("0")
    if kind in ("EXTEND", "SEAT_INCREASE"):
        if agent <= 0:
            raise SSHFinanceHold("INVALID_PAID_AGENT")
        if kind == "EXTEND" and (
            new_users != expected_users or _day(new_expiry) <= _day(expected_expiry)
        ):
            # An expired subscription can be renewed from today.
            if new_users != expected_users or _day(new_expiry) <= max(now, _day(expected_expiry)):
                raise SSHFinanceHold("INVALID_PAID_EXTENSION")
        if kind == "SEAT_INCREASE" and (
            new_expiry != expected_expiry or new_users <= expected_users
        ):
            raise SSHFinanceHold("INVALID_PAID_SEAT_INCREASE")
        _charge(conn, agent, cost)
    elif kind == "TIME_REDUCE":
        if not verified:
            raise SSHFinanceHold("HISTORICAL_PAYMENT_UNVERIFIED")
        if new_users != expected_users or _day(new_expiry) >= _day(expected_expiry):
            raise SSHFinanceHold("INVALID_PAID_REDUCTION")
        old_quote = _paid_quote(conn, username, agent, expected_created,
                                expected_expiry, expected_users, today=now)
        # Partial interval removal is valued using the ACTUAL amount paid,
        # never the new agent tariff.
        # Compute the interval that is no longer entitled without changing
        # the durable snapshot until the transaction commits.
        old_lots = conn.execute(
            "SELECT amount_toman,period_from,period_to FROM ssh_paid_events "
            "WHERE username=? AND kind IN('PURCHASE','EXTEND','SEAT_INCREASE')",
            (username,),
        ).fetchall()
        cut = Decimal("0")
        for raw, start_text, stop_text in old_lots:
            start, stop = _day(start_text), _day(stop_text)
            length = (stop-start).days
            if length <= 0:
                raise SSHFinanceHold("INVALID_PAID_INTERVAL")
            a = max(start, now, _day(new_expiry))
            b = min(stop, _day(expected_expiry))
            if b > a:
                cut += _amount(raw) * Decimal((b-a).days) / Decimal(length)
        refunded = min(
            cut.quantize(Decimal("1"), rounding=ROUND_HALF_UP),
            Decimal(old_quote.amount),
        )
        if refunded < 0:
            raise SSHFinanceHold("NEGATIVE_REFUND")
        if refunded > 0:
            nvl_daily_business.refund_purchase(conn, agent, float(refunded))
            if repay_emergency is not None:
                repay_emergency(conn, agent, float(refunded))
    elif kind == "ADMIN_ADJUST":
        refunded = Decimal("0")
    else:
        raise SSHFinanceHold("UNKNOWN_SSH_ACCOUNT_CHANGE")

    if mutate is None:
        cursor = conn.execute(
            "UPDATE ssh_accounts SET expire_date=?, users_limit=?, hold_active=0 "
            "WHERE username=? AND agent_id=? AND expire_date=? "
            "AND users_limit=? AND status=? AND service_type='ssh'",
            (new_expiry, new_users, username, agent, expected_expiry,
             expected_users, expected_status),
        )
        if cursor.rowcount != 1:
            raise SSHFinanceHold("PAID_ACCOUNT_UPDATE_CAS_FAILED")
    else:
        mutate(conn)
    changed = _live(conn, username)
    if not _matches_live(changed, agent, expected_created, new_expiry, new_users):
        raise SSHFinanceHold("PAID_ACCOUNT_POST_UPDATE_MISMATCH")

    if state is None:
        conn.execute(
            "INSERT INTO ssh_paid_accounts "
            "(username,agent_id,created_on,expected_expiry,expected_users,verified)"
            " VALUES(?,?,?,?,?,0)",
            (username, agent, expected_created, new_expiry, new_users),
        )
    else:
        conn.execute(
            "UPDATE ssh_paid_accounts SET expected_expiry=?, expected_users=?,"
            " verified=? WHERE username=?",
            (new_expiry, new_users, 0 if kind == "ADMIN_ADJUST" else int(verified),
             username),
        )
    if kind == "EXTEND":
        period_start = max(_day(expected_expiry), now)
        event_kind = "EXTEND"
        event_amount = cost
        period_end = _day(new_expiry)
    elif kind == "SEAT_INCREASE":
        period_start = now
        period_end = _day(expected_expiry)
        event_kind = kind
        event_amount = cost
    elif kind == "TIME_REDUCE":
        period_start = period_end = None
        event_kind = kind
        event_amount = refunded
    else:
        period_start = period_end = None
        event_kind = kind
        event_amount = Decimal("0")
    if period_start is not None and period_end <= period_start:
        raise SSHFinanceHold("INVALID_NEW_PAID_INTERVAL")
    _append(conn, username, agent, event_kind, event_amount,
            from_day=period_start, to_day=period_end,
            old_expiry=expected_expiry, new_expiry=new_expiry,
            old_users=expected_users, new_users=new_users)
    return float(refunded if kind == "TIME_REDUCE" else cost)


def close_paid_account(conn, *, username, agent, amount):
    """Append immutable settlement outcome and mark proved account closed.

    Must run inside the SAME SQLite transaction as DELETE and wallet credit.
    Legacy expired accounts (zero credit) have no verified account to close.
    """
    state = _account(conn, username)
    if state is None:
        if _amount(amount) != 0:
            raise SSHFinanceHold("UNVERIFIED_ACCOUNT_CANNOT_BE_CREDITED")
        return
    if state[5] or state[0] != agent:
        raise SSHFinanceHold("PAID_ACCOUNT_ALREADY_CLOSED_OR_OWNER_CHANGED")
    if conn.execute(
        "UPDATE ssh_paid_accounts SET closed=1 WHERE username=? "
        "AND agent_id=? AND closed=0", (username, agent)
    ).rowcount != 1:
        raise SSHFinanceHold("PAID_ACCOUNT_CLOSE_CAS_FAILED")
    _append(conn, username, agent,
            "DELETE_REFUND" if _amount(amount) > 0 else "DELETE_ZERO",
            amount, old_expiry=state[2], old_users=state[3])
