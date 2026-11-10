"""NVL Super Admin accounting V1 — isolated, read-only operational report.

No bot imports, writes, migration, journal-mode changes, cross-DB joins or payouts.
A report is a snapshot of *recorded* operations, never a bank reconciliation/P&L.
The real bot's callback must enforce Super Admin identity and feature flag.
"""
from __future__ import annotations

from contextlib import closing
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from html import escape
from pathlib import Path
import sqlite3
from urllib.parse import quote
from zoneinfo import ZoneInfo


TEHRAN = ZoneInfo("Asia/Tehran")
PERIOD_DAYS = {"all": None, "7d": 7, "30d": 30}
PERIOD_LABELS = {
    "all": "از ابتدای داده‌های موجود",
    "7d": "۷ روز اخیر (شناور)",
    "30d": "۳۰ روز اخیر (شناور)",
}
REQUIRED_MASTER = {
    "agents": ("balance", "withdrawable_balance", "emergency_used"),
    "receipts": ("status", "amount", "created_at", "card_owner_agent_id"),
    "activity_log": ("action", "service_type", "cost", "agent_id", "created_at"),
    "withdrawal_requests": ("status", "amount", "created_at", "done_at"),
}
REQUIRED_ACCOUNTING = {
    "finance_logs": ("action_type", "amount", "date"),
}
SERVICE_LABELS = (("ssh", "SSH"), ("v2ray", "V2Ray زمانی"), ("v2ray_vol", "V2Ray حجمی"))
ACTION_LABELS = (("create", "ساخت"), ("extend", "تمدید/افزایش حجم"))


class ReportUnavailable(RuntimeError):
    """No unverified zero or partial report when a required source is missing."""


def is_superadmin_request(*, role: str | None, chat_id: int | None,
                          user_id: int | None, superadmin_id: int) -> bool:
    """Authorize by actual Telegram user AND private chat, not session role alone."""
    return (
        role == "admin"
        and user_id == superadmin_id
        and chat_id == superadmin_id
    )


def _readonly_connection(path: str) -> sqlite3.Connection:
    try:
        resolved = Path(path).expanduser().resolve(strict=True)
        if not resolved.is_file():
            raise ReportUnavailable("NOT_A_FILE")
        uri = "file:" + quote(str(resolved), safe="/") + "?mode=ro"
        con = sqlite3.connect(uri, uri=True, timeout=3)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA query_only=ON")
        con.execute("PRAGMA busy_timeout=3000")
        return con
    except (OSError, sqlite3.Error) as exc:
        raise ReportUnavailable("DATABASE_UNAVAILABLE") from exc


def _require_schema(con: sqlite3.Connection, required: dict) -> None:
    for table, columns in required.items():
        actual = {row["name"] for row in con.execute(f'PRAGMA table_info("{table}")')}
        if not set(columns).issubset(actual):
            raise ReportUnavailable("SCHEMA_INCOMPLETE")


def _as_decimal(value) -> Decimal:
    try:
        d = Decimal(str(value if value is not None else 0))
        if not d.is_finite():
            raise InvalidOperation()
        return d
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise ReportUnavailable("INVALID_AMOUNT") from exc


def _money(value) -> str:
    # Monetary amounts in the legacy DB are SQLite REAL. Format only at the
    # presentation boundary without truncating fractional historical balances.
    d = _as_decimal(value).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    if d == d.to_integral_value():
        return f"{d:,.0f}"
    return f"{d:,.2f}"


def _utc_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    return value.astimezone(TEHRAN)


def _window(column: str, start: datetime | None, end: datetime,
            tz: timezone | ZoneInfo) -> tuple[str, tuple]:
    if start is None:
        return "", ()
    # Column name is always a fixed literal supplied by this module.
    return (
        f' WHERE "{column}" >= ? AND "{column}" < ?',
        (start.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S"),
         end.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S")),
    )


def _group_amounts(con: sqlite3.Connection, sql: str, params: tuple):
    return con.execute(sql, params).fetchall()


def build_report_data(
    master_db: str,
    accounting_db: str,
    period: str,
    *,
    now: datetime | None = None,
    legacy_server_tz: timezone | ZoneInfo = timezone.utc,
) -> dict:
    """Return a read-only snapshot. All financial flows have explicit source labels.

    activity_log timestamps: UTC (508/508 correlated events in Core audit).
    finance_logs timestamps: Asia/Tehran.
    receipts/withdrawals: datetime.now() from bot host, default Core server UTC.
    The legacy server timezone must be verified on a non-UTC installation.
    """
    if period not in PERIOD_DAYS:
        raise ValueError("Unsupported report period")
    now_ir = _utc_aware(now or datetime.now(TEHRAN))
    start = now_ir - timedelta(days=PERIOD_DAYS[period]) if PERIOD_DAYS[period] else None

    with closing(_readonly_connection(master_db)) as main, \
         closing(_readonly_connection(accounting_db)) as fin:
        try:
            _require_schema(main, REQUIRED_MASTER)
            _require_schema(fin, REQUIRED_ACCOUNTING)

            # Read-only transactions keep each source internally consistent.
            # They cannot make TWO independent SQLite files atomic together.
            main.execute("BEGIN")
            fin.execute("BEGIN")

            agent = main.execute("""
                SELECT COUNT(*) AS count,
                  COALESCE(SUM(COALESCE(balance, 0)), 0) AS wallet,
                  COALESCE(SUM(COALESCE(withdrawable_balance, 0)), 0) AS withdrawable,
                  COALESCE(SUM(COALESCE(emergency_used, 0)), 0) AS emergency
                FROM agents
            """).fetchone()

            wr, rp = _window("created_at", start, now_ir, legacy_server_tz)
            receipt_rows = _group_amounts(main, """
                SELECT status,
                  CASE WHEN card_owner_agent_id IS NULL
                       THEN 'unmarked' ELSE 'delegate' END AS card_group,
                  COUNT(*) AS n, COALESCE(SUM(amount), 0) AS amount
                FROM receipts
            """ + wr + " GROUP BY status, card_group", rp)

            receipts = {"approved": {"delegate": [0, Decimal(0)],
                                     "unmarked": [0, Decimal(0)]},
                        "pending": 0, "rejected": 0, "other": 0}
            for row in receipt_rows:
                state = row["status"]
                n = int(row["n"])
                if state == "approved":
                    bucket = row["card_group"]
                    receipts["approved"][bucket][0] += n
                    receipts["approved"][bucket][1] += _as_decimal(row["amount"])
                elif state in ("pending", "rejected"):
                    receipts[state] += n
                else:
                    receipts["other"] += n

            wa, ap = _window("created_at", start, now_ir, timezone.utc)
            activity_rows = _group_amounts(main, """
                SELECT action, service_type, COUNT(*) AS n,
                  COALESCE(SUM(CASE WHEN agent_id IS NOT NULL AND agent_id <> 0
                    THEN COALESCE(cost, 0) ELSE 0 END), 0) AS agent_cost
                FROM activity_log
            """ + wa + " GROUP BY action, service_type", ap)
            activity = {}
            for row in activity_rows:
                activity[(row["action"], row["service_type"])] = (
                    int(row["n"]), _as_decimal(row["agent_cost"]))
            reductions = sum(
                v[0] for (action, _service), v in activity.items()
                if action == "reduce"
            )

            wq, wp = _window("created_at", start, now_ir, legacy_server_tz)
            withdrawal_rows = _group_amounts(main, """
                SELECT status, COUNT(*) AS n,
                    COALESCE(SUM(amount), 0) AS amount
                FROM withdrawal_requests
            """ + wq + " GROUP BY status", wp)
            requested_count = sum(int(r["n"]) for r in withdrawal_rows)
            requested_amount = sum((_as_decimal(r["amount"]) for r in withdrawal_rows), Decimal(0))

            wd, wdp = _window("done_at", start, now_ir, legacy_server_tz)
            completed = main.execute("""
                SELECT COUNT(*) AS n, COALESCE(SUM(amount), 0) AS amount
                FROM withdrawal_requests
            """ + (wd + " AND status='done'" if wd else " WHERE status='done'"), wdp).fetchone()

            current_pending = main.execute("""
                SELECT COUNT(*) AS n, COALESCE(SUM(amount), 0) AS amount
                FROM withdrawal_requests WHERE status='pending'
            """).fetchone()

            wf, fp = _window("date", start, now_ir, TEHRAN)
            fm = fin.execute("""
                SELECT COUNT(*) AS n, COALESCE(SUM(amount), 0) AS amount
                FROM finance_logs
            """ + (wf + " AND action_type=?" if wf else " WHERE action_type=?"),
                fp + ("شارژ دستی",)).fetchone()
            first_finance_date = fin.execute(
                "SELECT MIN(date) FROM finance_logs").fetchone()[0]
            first_activity_date = main.execute(
                "SELECT MIN(created_at) FROM activity_log").fetchone()[0]

            return {
                "period": period,
                "label": PERIOD_LABELS[period],
                "generated_at_ir": now_ir.strftime("%Y-%m-%d %H:%M"),
                "since_ir": start.strftime("%Y-%m-%d %H:%M") if start else None,
                "agents": {
                    "count": int(agent["count"]),
                    "wallet": _as_decimal(agent["wallet"]),
                    "withdrawable": _as_decimal(agent["withdrawable"]),
                    "emergency": _as_decimal(agent["emergency"]),
                },
                "receipts": receipts,
                "activity": activity,
                "reductions": reductions,
                "manual_topups": (int(fm["n"]), _as_decimal(fm["amount"])),
                "withdrawals": {
                    "requested": (requested_count, requested_amount),
                    "completed": (int(completed["n"]), _as_decimal(completed["amount"])),
                    "pending_now": (int(current_pending["n"]), _as_decimal(current_pending["amount"])),
                },
                "source_start": {
                    "finance_logs": first_finance_date,
                    "activity_log": first_activity_date,
                },
            }
        except sqlite3.Error as exc:
            raise ReportUnavailable("QUERY_FAILED") from exc


def render_report(data: dict) -> str:
    """Text-only Telegram HTML. No charts, no untrusted names or account details."""
    receipts = data["receipts"]
    known = receipts["approved"]["delegate"]
    unmarked = receipts["approved"]["unmarked"]
    total_count = known[0] + unmarked[0]
    total_amount = known[1] + unmarked[1]
    activity = data["activity"]
    withdrawals = data["withdrawals"]
    agents = data["agents"]
    rows = [
        "💰 <b>گزارش حسابداری NVL | نسخه ۱</b>",
        f"🗓 <b>{escape(data['label'])}</b>",
        f"🕒 زمان گزارش (ایران): {data['generated_at_ir']}",
    ]
    if data["since_ir"]:
        rows.append(f"از {data['since_ir']} تا {data['generated_at_ir']} (ایران)")
    rows += [
        "",
        "🧾 <b>رسیدهای ارسال‌شده در بازه (وضعیت فعلی)</b>",
        f"✅ تأییدشده: {total_count:,} | {_money(total_amount)} تومان",
        f"• کارت اختصاصی نمایندگان: {known[0]:,} | {_money(known[1])}",
        f"• بدون کارت نماینده ثبت‌شده: {unmarked[0]:,} | {_money(unmarked[1])}",
        f"⏳ در انتظار: {receipts['pending']:,} | ردشده: {receipts['rejected']:,}",
    ]
    if receipts["other"]:
        rows.append(f"سایر وضعیت‌ها: {receipts['other']:,}")

    rows += ["", "🛒 <b>عملیات سرویس ثبت‌شده</b>"]
    for service, service_label in SERVICE_LABELS:
        for action, action_label in ACTION_LABELS:
            n, charged = activity.get((action, service), (0, Decimal(0)))
            rows.append(
                f"• {service_label} / {action_label}: {n:,} | "
                f"کسر ثبت‌شده نمایندگان {_money(charged)}"
            )
    rows.append(f"↩️ کاهش زمان ثبت‌شده: {data['reductions']:,} عملیات")

    mt_count, mt_total = data["manual_topups"]
    rows += [
        "",
        "💳 <b>سایر گردش‌های ثبت‌شده</b>",
        f"• شارژ دستی در لاگ مالی: {mt_count:,} | {_money(mt_total)} تومان",
        f"• درخواست برداشت ثبت‌شده: {withdrawals['requested'][0]:,} | "
        f"{_money(withdrawals['requested'][1])}",
        f"• برداشت علامت‌خورده به‌عنوان انجام‌شده: "
        f"{withdrawals['completed'][0]:,} | {_money(withdrawals['completed'][1])}",
        "",
        "💼 <b>مانده فعلی نمایندگان (مستقل از بازه)</b>",
        f"👥 نمایندگان موجود: {agents['count']:,}",
        f"• کیف پول: {_money(agents['wallet'])} تومان",
        f"• قابل‌برداشت: {_money(agents['withdrawable'])} تومان",
        f"• اعتبار اضطراری مصرف‌شده: {_money(agents['emergency'])} تومان",
        f"• درخواست برداشت در انتظار (فعلی): {withdrawals['pending_now'][0]:,} | "
        f"{_money(withdrawals['pending_now'][1])}",
        "",
        "ℹ️ <b>محدودیت:</b> ارقام، سوابق ثبت‌شده‌اند؛ "
        "رسیدهای تأییدشده بر اساس تاریخ ارسال فیلتر شده‌اند، "
        "نه تاریخ تأیید. مبلغ فروش شامل مسیرهای فاقد لاگ و فروش مستقیم ادمین نیست. "
        "شارژ دستی قبل از آغاز تاریخچه finance_logs ممکن است موجود نباشد. "
        "«انجام‌شده» در برداشت، تأیید بانکی مستقل نیست. "
        "این گزارش درآمد نقدی یا سود خالص شرکت نیست.",
    ]
    text = "\n".join(rows)
    if len(text) > 3900:
        raise ReportUnavailable("TELEGRAM_MESSAGE_TOO_LONG")
    return text


def build_report_text(master_db: str, accounting_db: str, period: str,
                      *, now: datetime | None = None,
                      legacy_server_tz: timezone | ZoneInfo = timezone.utc) -> str:
    return render_report(build_report_data(
        master_db, accounting_db, period, now=now,
        legacy_server_tz=legacy_server_tz))
