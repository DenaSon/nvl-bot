"""Read-only expiry listing for an NVL reseller.

Never calls Marzban, changes accounts or touches the reseller wallet.
The agent_id predicate is applied by SQLite, not to a post-query Python list.
"""
from __future__ import annotations

from datetime import date, timedelta


ALLOWED_WINDOWS = (1, 3, 7)
PAGE_SIZE = 10


def list_expiring_accounts(conn, agent_id: int, *, days: int = 3,
                           page: int = 0, today: date | None = None):
    """Return (matching_count, page_rows) for this agent's active timed accounts.

    Rows are (username, service_type, customer_name, expire_date).
    Today's expiry is included. Expired, on-hold and time-unlimited users are
    excluded. Date values are canonical ISO dates (YYYY-MM-DD).
    """
    try:
        owner = int(agent_id)
        days = int(days)
        page = int(page)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid reseller expiry parameters") from exc
    if owner <= 0 or days not in ALLOWED_WINDOWS or page < 0:
        raise ValueError("invalid reseller expiry parameters")
    start = today or date.today()
    if not isinstance(start, date):
        raise ValueError("today must be a date")
    end = start + timedelta(days=days)
    predicate = (
        "agent_id = ? AND service_type IN ('ssh', 'v2ray') "
        "AND status = '🟢 فعال' AND COALESCE(hold_active, 0) = 0 "
        "AND expire_date BETWEEN ? AND ? "
        "AND length(expire_date) = 10 "
    )
    params = (owner, start.isoformat(), end.isoformat())
    count = conn.execute(
        "SELECT COUNT(*) FROM ssh_accounts WHERE " + predicate, params
    ).fetchone()[0]
    rows = conn.execute(
        "SELECT username, service_type, customer_name, expire_date "
        "FROM ssh_accounts WHERE " + predicate
        + "ORDER BY expire_date ASC, username ASC LIMIT ? OFFSET ?",
        (*params, PAGE_SIZE, page * PAGE_SIZE),
    ).fetchall()
    return int(count), rows
