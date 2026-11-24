"""Read-only, anonymized NVL SSH refund audit (NO wallet writes).

Usage:
  python3 -B ops/nvl_ssh_refund_audit.py --db /root/master_bot.db

Lists aggregate exposure of the old denominator error and flags mismatched
recorded extension rates. Activity history is incomplete for some old accounts;
never interpret this report as approval to credit historical wallets.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
import json
from pathlib import Path
import re
import sqlite3
import sys
from urllib.parse import quote
from zoneinfo import ZoneInfo

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ssh_refund_policy import calculate_ssh_refund

TEHRAN = ZoneInfo("Asia/Tehran")
DAYS = re.compile(r"([0-9]+)\s*روز")


def audit(conn, *, today=None):
    now = today or datetime.now(TEHRAN).date()
    conn.row_factory = sqlite3.Row
    has_history = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='activity_log'"
    ).fetchone() is not None
    records = conn.execute(
        "SELECT a.username, a.creation_date, a.expire_date, a.hold_active,"
        "a.hold_duration_days, a.users_limit, ag.base_price "
        "FROM ssh_accounts a LEFT JOIN agents ag ON ag.id=a.agent_id "
        "WHERE a.service_type='ssh' AND a.users_limit >= 2"
    ).fetchall()
    counts = Counter()
    sum_before = sum_after = 0
    examples = []
    for row in records:
        counts["accounts"] += 1
        result = calculate_ssh_refund(
            monthly_price=row["base_price"], users_limit=row["users_limit"],
            expire_date=row["expire_date"], creation_date=row["creation_date"],
            hold_active=row["hold_active"],
            hold_duration_days=row["hold_duration_days"], today=now,
        )
        if result.reason.startswith("INVALID_"):
            counts["invalid_data"] += 1
            continue
        if row["hold_active"]:
            counts["hidden_hold"] += 1
        if result.reason == "HOLD_LEGACY_30_DAY_FALLBACK":
            counts["hold_legacy_fallback"] += 1
        if result.reason == "EXPIRED":
            counts["expired"] += 1
        try:
            monthly = Decimal(str(row["base_price"]).replace(",", ""))
            users = int(row["users_limit"])
            if row["hold_active"]:
                old = monthly * users
            else:
                total_days = (
                    date.fromisoformat(row["expire_date"][:10])
                    - date.fromisoformat(row["creation_date"][:10])
                ).days
                remaining = max(0, (
                    date.fromisoformat(row["expire_date"][:10]) - now
                ).days)
                old = (monthly * users * Decimal(remaining) / Decimal(total_days)
                       if total_days > 0 else Decimal(0))
            legacy_amount = int(round(old))
        except (InvalidOperation, ValueError, TypeError, ZeroDivisionError):
            counts["legacy_invalid"] += 1
            continue
        sum_before += legacy_amount
        sum_after += result.amount
        if legacy_amount != result.amount:
            counts["different_refunds"] += 1
            if len(examples) < 8:
                examples.append({
                    "sample": "S" + str(len(examples) + 1),
                    "users_limit": users,
                    "hold": bool(row["hold_active"]),
                    "old_toman": legacy_amount,
                    "new_toman": result.amount,
                    "difference_toman": result.amount - legacy_amount,
                })
        if has_history:
            history = conn.execute(
                "SELECT details,cost FROM activity_log WHERE username=? "
                "AND service_type='ssh' AND action='extend' AND cost>0",
                (row["username"],),
            ).fetchall()
            if not history:
                counts["extension_history_missing"] += 1
            else:
                counts["with_extension_history"] += 1
                for event in history:
                    match = DAYS.search(str(event["details"] or ""))
                    if not match:
                        continue
                    days = int(match.group(1))
                    if not days:
                        continue
                    try:
                        actual_unit = Decimal(str(event["cost"])) * 30 / (
                            Decimal(days) * Decimal(users))
                        if abs(actual_unit - monthly) > Decimal("0.5"):
                            counts["recorded_extension_rate_mismatch_events"] += 1
                    except (InvalidOperation, ZeroDivisionError):
                        counts["unparseable_extension_event"] += 1
    return {
        "mode": "READ_ONLY_ANONYMIZED_SSH_REFUND_AUDIT",
        "date_tehran": now.isoformat(),
        "activity_log_available": has_history,
        "counts": dict(sorted(counts.items())),
        "legacy_quote_total_toman": sum_before,
        "corrected_quote_total_toman": sum_after,
        "difference_total_toman": sum_after - sum_before,
        "anonymous_examples": examples,
        "warning": (
            "Prices from current agent settings are NOT proof of historical "
            "payments; incomplete activity history is not an invoice ledger. "
            "This report never changes accounts or balances."
        ),
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="/root/master_bot.db")
    args = parser.parse_args(argv)
    path = Path(args.db).resolve(strict=True)
    uri = "file:" + quote(str(path), safe="/") + "?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=3) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA busy_timeout=3000")
        report = audit(db)
        report["quick_check"] = db.execute("PRAGMA quick_check").fetchone()[0]
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
