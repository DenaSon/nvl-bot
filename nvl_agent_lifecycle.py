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


def list_expired_accounts(conn, agent_id: int, *, page: int = 0,
                          today: date | None = None):
    """Return recently expired first, regardless of the disabled-status label.

    Never includes on-hold or time-unlimited accounts; the date predicate is
    read-only and uses the owning reseller's agent_id in SQL.
    """
    try:
        owner, page = int(agent_id), int(page)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid reseller expiry parameters") from exc
    if owner <= 0 or page < 0:
        raise ValueError("invalid reseller expiry parameters")
    cutoff = (today or date.today()).isoformat()
    predicate = (
        "agent_id=? AND service_type IN ('ssh','v2ray') "
        "AND status != '⏳ درحال ساخت' AND COALESCE(hold_active,0)=0 "
        "AND expire_date < ? AND length(expire_date)=10 "
        "AND date(expire_date, '+0 days')=expire_date "
    )
    args = (owner, cutoff)
    count = conn.execute(
        "SELECT COUNT(*) FROM ssh_accounts WHERE " + predicate, args
    ).fetchone()[0]
    rows = conn.execute(
        "SELECT username, service_type, customer_name, expire_date "
        "FROM ssh_accounts WHERE " + predicate
        + "ORDER BY expire_date DESC, username ASC LIMIT ? OFFSET ?",
        (*args, PAGE_SIZE, page * PAGE_SIZE),
    ).fetchall()
    return int(count), rows


def select_low_volume_accounts(local_rows, remote_users, *, threshold_pct=10):
    """Intersect API usage with locally owned V2Ray-volume users only.

    local_rows: (username, customer_name, status) already scoped by SQL.
    Return (username, customer_name, remaining_bytes, total_bytes) with <=10%
    remaining, lowest remaining fraction first. No mutation or network access.
    """
    if not 0 < threshold_pct <= 100:
        raise ValueError("invalid low-volume threshold")
    if not isinstance(remote_users, list):
        raise ValueError("incomplete Marzban users response")
    local = {
        str(row[0]): (row[1], str(row[2]))
        for row in local_rows
        if len(row) >= 3 and row[0]
        and str(row[2]) in ("🟢 فعال", "🔴 غیرفعال")
    }
    selected = {}
    for remote in remote_users:
        if not isinstance(remote, dict):
            continue
        username = str(remote.get("username") or "")
        remote_status = remote.get("status")
        if username not in local or remote_status not in ("active", "limited"):
            continue
        customer, local_status = local[username]
        # A manually disabled user must not look like an active renewal
        # candidate; a traffic-limited Marzban user is a valid 0GB case.
        if local_status != "🟢 فعال" and remote_status != "limited":
            continue
        try:
            limit = int(remote.get("data_limit"))
            used = int(remote.get("used_traffic"))
        except (ValueError, TypeError):
            continue
        if limit <= 0 or used < 0:
            continue
        remaining = max(0, limit - used)
        if remaining * 100 <= limit * threshold_pct:
            selected[username] = (username, customer, remaining, limit)
    return sorted(selected.values(), key=lambda x: (x[2] / x[3], x[0]))


def renewal_reminder(username: str, expire_date: str, *, today: date | None = None):
    """Copyable text; caller is responsible for delivering it manually."""
    try:
        parsed = date.fromisoformat(str(expire_date))
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid expiry date") from exc
    remaining = (parsed - (today or date.today())).days
    if remaining < 0:
        line = "مدت اشتراک شما به پایان رسیده است."
    elif remaining == 0:
        line = "اشتراک شما امروز به پایان می‌رسد."
    else:
        line = f"فقط {remaining} روز تا پایان اشتراک شما باقی مانده است."
    return (
        "سلام، وقت بخیر 🌿\n"
        + line + "\n"
        + f"شناسه اشتراک: {username}\n"
        + "برای تمدید، لطفاً پیام دهید تا راهنمایی‌تان کنیم."
    )
