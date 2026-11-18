"""Atomic SQLite settlement after a confirmed Core SSH account deletion.

This does NOT execute Linux userdel. The caller must confirm that external
side effect first, then run this function in a managed SQLite connection.
"""
from __future__ import annotations

from decimal import Decimal
import nvl_daily_business
from ssh_refund_policy import SSHRefund, calculate_ssh_refund


class SSHDeleteSettlementHold(RuntimeError):
    pass


def preflight_ssh_delete(
    conn, *, username, expected_agent_id, expected_expiry,
    expected_created, expected_users, expected_status, today=None,
):
    """Check type, ownership, snapshot and refund data before Linux userdel.

    Read-only; settlement validates again under BEGIN IMMEDIATE because
    Linux user deletion and SQLite cannot form one distributed transaction.
    """
    row = conn.execute(
        "SELECT a.agent_id, a.expire_date, a.creation_date, a.users_limit, "
        "a.status, a.hold_active, a.hold_duration_days, ag.base_price, "
        "a.service_type FROM ssh_accounts a "
        "LEFT JOIN agents ag ON ag.id=a.agent_id WHERE a.username=?",
        (username,),
    ).fetchone()
    if not row:
        raise SSHDeleteSettlementHold("ACCOUNT_ALREADY_DELETED")
    agent, expiry, created, users, status, hold, held_days, monthly_price, service_type = row
    if (
        agent != expected_agent_id
        or expiry != expected_expiry
        or created != expected_created
        or users != expected_users
        or status != expected_status
        or service_type != "ssh"
    ):
        raise SSHDeleteSettlementHold("ACCOUNT_SNAPSHOT_CHANGED")

    if agent:
        refund = calculate_ssh_refund(
            monthly_price=monthly_price,
            users_limit=users,
            expire_date=expiry,
            creation_date=created,
            hold_active=hold,
            hold_duration_days=held_days,
            today=today,
        )
        if refund.reason.startswith("INVALID_"):
            raise SSHDeleteSettlementHold(refund.reason)
    else:
        refund = SSHRefund(0, 0, "DIRECT_ADMIN")
    return agent, refund


def finalize_ssh_delete(
    conn,
    *,
    username,
    expected_agent_id,
    expected_expiry,
    expected_created,
    expected_users,
    expected_status,
    repay_emergency,
    today=None,
):
    """Consume one existing SSH account exactly once, with its wallet refund.

    The SELECT, DELETE, PURCHASE_REFUND event, wallet credit and old emergency
    debt repayment are committed together by the caller's connection context.
    BEGIN IMMEDIATE serializes simultaneous confirmation callbacks.
    """
    conn.execute("BEGIN IMMEDIATE")
    agent, refund = preflight_ssh_delete(
        conn, username=username, expected_agent_id=expected_agent_id,
        expected_expiry=expected_expiry, expected_created=expected_created,
        expected_users=expected_users, expected_status=expected_status,
        today=today,
    )

    removed = conn.execute(
        "DELETE FROM ssh_accounts WHERE username=? AND service_type='ssh'",
        (username,),
    ).rowcount
    if removed != 1:
        raise SSHDeleteSettlementHold("ACCOUNT_DELETE_CAS_FAILED")

    repaid = 0
    if agent and refund.amount > 0:
        used = conn.execute(
            "SELECT emergency_used FROM agents WHERE id=?", (agent,),
        ).fetchone()
        if used is None:
            raise SSHDeleteSettlementHold("OWNER_AGENT_MISSING")
        nvl_daily_business.refund_purchase(conn, agent, refund.amount)
        repaid = min(Decimal(str(used[0] or 0)), Decimal(refund.amount))
        repay_emergency(conn, agent, refund.amount)
    return refund.amount if agent else 0, int(repaid), refund.reason, refund.days
