#!/usr/bin/env python3
"""NVL finance data-quality probe, read-only, non-PII aggregated JSON.

Usage:
  python3 -B ops/nvl_finance_readonly_audit.py --db /root/master_bot.db --accounting /root/accounting.db

Uses SQLite mode=ro and query_only. No CREATE/INSERT/UPDATE/DELETE/ATTACH/PRAGMA journal_mode.
Runs independently from the bot and never imports bot code.
"""
import argparse
import collections
import datetime as dt
import json
import re
import sqlite3
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path
from urllib.parse import quote

CORE = {
    "agents": {"id", "balance", "withdrawable_balance", "emergency_used", "referral_income", "cashback_income"},
    "receipts": {"id", "agent_id", "amount", "status", "created_at", "card_owner_agent_id"},
    "activity_log": {"id", "agent_id", "action", "service_type", "cost", "created_at"},
    "withdrawal_requests": {"id", "agent_id", "amount", "status", "created_at", "done_at"},
}
FINANCE = {"finance_logs": {"id", "date", "agent_name", "action_type", "amount", "details"}}
CREDIT_ACTION = "واریز بانکی (تایید شده)"
RECEIPT_ID_RE = re.compile(r"شناسه\s+رسید\s*[:：]\s*(\d+)")


def readonly(path):
    path = Path(path).expanduser().resolve(strict=True)
    uri = "file:" + quote(str(path), safe="/") + "?mode=ro"
    con = sqlite3.connect(uri, uri=True, timeout=3)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA query_only=ON")
    con.execute("PRAGMA busy_timeout=3000")
    return con


def schema(con, spec):
    result = {}
    for table, required in spec.items():
        exists = bool(con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone())
        cols = {row[1] for row in con.execute(f"PRAGMA table_info({table})")} if exists else set()
        result[table] = {"present": exists, "missing_columns": sorted(required - cols)}
    return result


def valid_table(sch, name):
    return sch.get(name, {}).get("present", False) and not sch[name]["missing_columns"]


def amount(x):
    try:
        a = Decimal(str(x))
        return a if a.is_finite() else None
    except (InvalidOperation, TypeError, ValueError):
        return None


def display_amount(x):
    if x is None:
        return None
    return format(x.quantize(Decimal("0.01")), "f")


def date_quality(con, table, column):
    data = con.execute(f'SELECT "{column}" FROM "{table}"')
    missing = invalid = total = 0
    min_stamp = max_stamp = None
    for (value,) in data:
        total += 1
        if not value:
            missing += 1
            continue
        try:
            stamp = dt.datetime.fromisoformat(str(value))
        except (ValueError, TypeError):
            invalid += 1
            continue
        stamp = stamp.isoformat(sep=" ")
        min_stamp = min(stamp, min_stamp) if min_stamp else stamp
        max_stamp = max(stamp, max_stamp) if max_stamp else stamp
    return {"total": total, "missing": missing, "invalid": invalid, "earliest_raw": min_stamp, "latest_raw": max_stamp,
            "timezone_note": "Stored timestamps are not normalized across sources; raw values are not necessarily in the same timezone."}


def groups(con, table, cols):
    sql = f'SELECT {", ".join(cols)}, COUNT(*) AS n FROM "{table}" GROUP BY {", ".join(cols)} ORDER BY n DESC'
    return [{**{cols[i]: row[i] for i in range(len(cols))}, "count": row[-1]} for row in con.execute(sql)]


def audit(master, financial):
    out = {
        "audit_mode": "READ_ONLY_SOURCE_DATA_QUALITY",
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "caveats": [
            "No writes or migrations were performed.",
            "These are data-quality checks, NOT audited bank cashflow, profit, P&L or a complete ledger.",
            "Source DBs do not form a synchronized cross-database transaction snapshot.",
            "Date ranges must not be aggregated until source-specific timezone mapping is verified.",
            "Manual deductions, some refunds, wallet transfers and bulk sales may lack financial event rows by design.",
            "A receipt's submitted amount and the credited amount can differ in current bot code; matching cannot certify paid amount.",
        ],
        "schema": {"master": schema(master, CORE), "accounting": schema(financial, FINANCE) if financial else None},
    }
    s = out["schema"]["master"]
    if valid_table(s, "agents"):
        rows = master.execute("SELECT id, balance, withdrawable_balance, emergency_used, referral_income, cashback_income FROM agents").fetchall()
        totals = {}
        bad = {}
        for key in ("balance", "withdrawable_balance", "emergency_used", "referral_income", "cashback_income"):
            vals = [amount(r[key]) for r in rows]
            totals[key] = display_amount(sum((v for v in vals if v is not None), Decimal(0)))
            bad[key] = sum(v is None for v in vals)
        out["agent_current_snapshot"] = {"count": len(rows), "raw_sums_toman": totals, "invalid_amount_rows": bad,
            "warning": "Current stock balances, NOT movements in a chosen period. Missing or deleted agents are not represented."}
        agent_ids = {r["id"] for r in rows}
    else:
        agent_ids = set()
    receipt_rows = []
    if valid_table(s, "receipts"):
        receipt_rows = master.execute("SELECT id, agent_id, amount, status, created_at, card_owner_agent_id FROM receipts").fetchall()
        rstatus = collections.Counter(r["status"] if r["status"] is not None else "NULL" for r in receipt_rows)
        out["receipts"] = {
            "status_counts": dict(sorted(rstatus.items())),
            "invalid_or_nonpositive_amounts": sum((v is None or v <= 0) for v in map(lambda r: amount(r["amount"]), receipt_rows)),
            "missing_or_deleted_agent": sum(r["agent_id"] not in agent_ids for r in receipt_rows) if agent_ids else None,
            "missing_card_owner_when_set": sum(r["card_owner_agent_id"] not in agent_ids for r in receipt_rows if r["card_owner_agent_id"] is not None) if agent_ids else None,
            "approved_with_delegate_card": sum(r["status"] == "approved" and r["card_owner_agent_id"] is not None for r in receipt_rows),
            "date_quality": date_quality(master, "receipts", "created_at"),
            "warning": "created_at is receipt SUBMISSION, not approval time. No approved_at in the known schema.",
        }
    if valid_table(s, "activity_log"):
        out["activity_log"] = {"by_action_service": groups(master, "activity_log", ["action", "service_type"]),
            "date_quality": date_quality(master, "activity_log", "created_at"),
            "warning": "Not all charge/refund/bulk paths log an activity row; cost=0 for direct admin sales."}
    if valid_table(s, "withdrawal_requests"):
        out["withdrawals"] = {"by_status": groups(master, "withdrawal_requests", ["status"]),
            "done_missing_done_at": master.execute("SELECT COUNT(*) FROM withdrawal_requests WHERE status='done' AND (done_at IS NULL OR done_at='')").fetchone()[0],
            "created_at_quality": date_quality(master, "withdrawal_requests", "created_at"),
            "done_at_quality": date_quality(master, "withdrawal_requests", "done_at"),
            "warning": "done means marked done in bot, not independently verified bank settlement. Cancelled requests have no cancelled_at."}
    if financial and valid_table(out["schema"]["accounting"], "finance_logs"):
        frows = financial.execute("SELECT action_type, amount, details FROM finance_logs").fetchall()
        out["finance_logs"] = {"by_action": groups(financial, "finance_logs", ["action_type"]),
            "date_quality": date_quality(financial, "finance_logs", "date"),
            "invalid_amount_count": sum(amount(r["amount"]) is None for r in frows),
            "warning": "Agent identified by mutable name, not agent_id. Some writes may fail silently."}
        ids_in_finance = collections.defaultdict(list)
        without_id = 0
        for f in frows:
            if f["action_type"] != CREDIT_ACTION:
                continue
            match = RECEIPT_ID_RE.search(str(f["details"] or ""))
            if not match:
                without_id += 1
            else:
                ids_in_finance[int(match.group(1))].append(amount(f["amount"]))
        if receipt_rows:
            receipt_by_id = {r["id"]: r for r in receipt_rows}
            approved = [r for r in receipt_rows if r["status"] == "approved"]
            out["receipt_finance_reconciliation"] = {
                "approved_receipts": len(approved),
                "bank_approval_log_rows": sum(len(v) for v in ids_in_finance.values()) + without_id,
                "bank_approval_logs_without_receipt_id": without_id,
                "approved_receipts_without_bank_approval_log": sum(r["id"] not in ids_in_finance for r in approved),
                "approved_receipts_with_multiple_bank_approval_logs": sum(len(ids_in_finance.get(r["id"], [])) > 1 for r in approved),
                "approved_receipts_with_mismatched_logged_amount": sum(
                    any(v is not None and amount(r["amount"]) is not None and v != amount(r["amount"])
                        for v in ids_in_finance.get(r["id"], [])) for r in approved),
                "bank_approval_logs_for_unknown_receipts": sum(len(v) for rid, v in ids_in_finance.items() if rid not in receipt_by_id),
                "bank_approval_logs_for_nonapproved_receipts": sum(len(v) for rid, v in ids_in_finance.items()
                    if rid in receipt_by_id and receipt_by_id[rid]["status"] != "approved"),
                "warning": "No row-level correlation key for all finance operations; log failure and in-flight events can affect counts. No external bank statement validation.",
            }
    else:
        out["finance_logs"] = {"available": False, "warning": "No readable accounting database or finance_logs table."}
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True, help="Existing master_bot.db path")
    parser.add_argument("--accounting", required=True, help="Existing accounting.db path")
    args = parser.parse_args()
    try:
        with readonly(args.db) as master:
            try:
                f = readonly(args.accounting)
            except (OSError, sqlite3.Error) as e:
                f = None
                print(f"WARNING: accounting DB unavailable: {type(e).__name__}", file=sys.stderr)
            try:
                print(json.dumps(audit(master, f), ensure_ascii=False, indent=2, default=str))
            finally:
                if f:
                    f.close()
    except (OSError, sqlite3.Error) as exc:
        print(f"ERROR: Could not complete read-only audit ({type(exc).__name__}: {exc})", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
