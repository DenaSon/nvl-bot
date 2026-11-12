"""NVL Daily Business Report: immutable wallet/cash event ledger and Telegram digest.

Only transactions occurring AFTER installation are known. Never infer cash inflow
from wallet spending, or direct-admin credit from an actual bank transfer.
Every financial event is inserted in the SAME SQLite transaction as its source.
No Telegram APIs, network I/O, or existing balance/pricing policies here.
"""
from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal
from html import escape
import sqlite3
import uuid
from zoneinfo import ZoneInfo

TEHRAN = ZoneInfo("Asia/Tehran")
UTC = timezone.utc
TYPES = frozenset({
    "AGENT_CREATED", "BANK_TOPUP", "MANUAL_TOPUP",
    "PURCHASE", "PURCHASE_REFUND",
})


def _utc(value=None):
    if value is None:
        return datetime.now(UTC)
    if value.tzinfo is None:
        raise ValueError("timezone-aware datetime required")
    return value.astimezone(UTC)


def _ts(value=None):
    return _utc(value).isoformat(timespec="microseconds")


def install_schema(conn: sqlite3.Connection, *, now=None):
    """Idempotent schema; ledger starts NOW, never guesses historic activity."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS nvl_business_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          event_key TEXT NOT NULL UNIQUE,
          kind TEXT NOT NULL,
          agent_id INTEGER,
          amount_toman REAL NOT NULL DEFAULT 0,
          card_owner_agent_id INTEGER,
          occurred_at_utc TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_nvl_business_events_time
        ON nvl_business_events (occurred_at_utc, kind)
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS nvl_business_metadata (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS nvl_business_report_deliveries (
          report_day TEXT PRIMARY KEY,
          status TEXT NOT NULL,
          claimed_at_utc TEXT NOT NULL,
          completed_at_utc TEXT,
          telegram_message_id INTEGER,
          error_kind TEXT
        )
    """)
    conn.execute(
        "INSERT OR IGNORE INTO nvl_business_metadata(key,value) "
        "VALUES('started_at_utc',?)", (_ts(now),)
    )


def record_event(conn, *, kind, agent_id=None, amount=0,
                 source_key=None, card_owner_agent_id=None, now=None):
    if kind not in TYPES:
        raise ValueError("unknown business event")
    value = Decimal(str(amount))
    if not value.is_finite() or value < 0:
        raise ValueError("invalid business amount")
    key = source_key or f"{kind}:{uuid.uuid4().hex}"
    return conn.execute(
        "INSERT OR IGNORE INTO nvl_business_events"
        "(event_key,kind,agent_id,amount_toman,card_owner_agent_id,occurred_at_utc)"
        " VALUES(?,?,?,?,?,?)",
        (key, kind, agent_id, float(value), card_owner_agent_id, _ts(now)),
    ).rowcount


def charge_purchase(conn, agent_id, amount):
    """Use at existing wallet debit sites; debit and ledger are atomic."""
    if conn.execute(
        "UPDATE agents SET balance = balance - ? WHERE id=?",
        (amount, agent_id),
    ).rowcount != 1:
        raise ValueError("agent not found for purchase")
    if Decimal(str(amount)) > 0:
        record_event(conn, kind="PURCHASE", agent_id=agent_id, amount=amount)


def refund_purchase(conn, agent_id, amount):
    """Use at existing wallet refund sites, preserving refund accounting."""
    if conn.execute(
        "UPDATE agents SET balance = balance + ? WHERE id=?",
        (amount, agent_id),
    ).rowcount != 1:
        raise ValueError("agent not found for refund")
    if Decimal(str(amount)) > 0:
        record_event(conn, kind="PURCHASE_REFUND", agent_id=agent_id, amount=amount)


def _bounds(day):
    chosen = date.fromisoformat(str(day))
    start = datetime.combine(chosen, time.min, tzinfo=TEHRAN).astimezone(UTC)
    stop = datetime.combine(chosen + timedelta(days=1), time.min,
                            tzinfo=TEHRAN).astimezone(UTC)
    return start, stop


def _money(value):
    return f"{int(Decimal(str(value)).quantize(Decimal('1'))):,}"


def summarize(conn, day, *, now=None):
    """Precisely ONE Tehran calendar day, or today's elapsed period for preview."""
    start, stop = _bounds(day)
    cutoff = min(stop, _utc(now)) if now is not None else stop
    raw = conn.execute(
        "SELECT kind,agent_id,amount_toman,card_owner_agent_id "
        "FROM nvl_business_events WHERE occurred_at_utc>=? AND occurred_at_utc<?",
        (_ts(start), _ts(cutoff)),
    ).fetchall()
    total = {key: Decimal("0") for key in TYPES}
    counts = {key: 0 for key in TYPES}
    buyers, topuppers = set(), set()
    central_bank = partner_bank = Decimal("0")
    for kind, agent_id, amount, card_owner in raw:
        value = Decimal(str(amount))
        total[kind] += value
        counts[kind] += 1
        if kind == "PURCHASE" and agent_id:
            buyers.add(agent_id)
        if kind in ("BANK_TOPUP", "MANUAL_TOPUP") and agent_id:
            topuppers.add(agent_id)
        if kind == "BANK_TOPUP":
            if card_owner is None:
                central_bank += value
            else:
                partner_bank += value
    started = conn.execute(
        "SELECT value FROM nvl_business_metadata WHERE key='started_at_utc'"
    ).fetchone()
    if started is None:
        raise RuntimeError("business ledger is not installed")
    started_at = datetime.fromisoformat(started[0])
    return {
        "day": str(day), "start_utc": start, "started_at_utc": started_at,
        "partial": started_at > start, "counts": counts,
        "totals": total, "buyers": len(buyers),
        "topuppers": len(topuppers), "central_bank": central_bank,
        "partner_bank": partner_bank,
        "wallet_topups": total["BANK_TOPUP"] + total["MANUAL_TOPUP"],
        "net_purchases": total["PURCHASE"] - total["PURCHASE_REFUND"],
    }


def render_report(summary, *, previous=None, label=None, preview=False):
    day = escape(label or summary["day"])
    tag = "تا این لحظه" if preview else "روز بسته‌شده"
    partial = (
        "⚠️ <b>داده‌های ناقص:</b> ثبت مالی از میانه این روز شروع شده است.\n"
        if summary["partial"] else ""
    )
    counts, totals = summary["counts"], summary["totals"]
    rows = [
        "📊 <b>NVL | گزارش عملکرد روزانه</b>",
        f"📅 {day} | {tag} | Asia/Tehran",
        "🕛 بازه: ۰۰:۰۰ تا ۲۴:۰۰" if not preview else "🕛 بازه: امروز تا زمان درخواست",
        "",
        partial.rstrip(),
        "👥 <b>نمایندگان</b>",
        f"• نماینده جدید: <b>{counts['AGENT_CREATED']:,}</b>",
        f"• نماینده خریدار: <b>{summary['buyers']:,}</b>",
        f"• نماینده شارژکننده: <b>{summary['topuppers']:,}</b>",
        "",
        "🛒 <b>خرید با اعتبار کیف پول</b>",
        f"• تعداد عملیات خرید/تمدید: <b>{counts['PURCHASE']:,}</b>",
        f"• مبلغ ناخالص خرید: <b>{_money(totals['PURCHASE'])}</b> تومان",
        f"• بازگشت اعتبار خرید: <b>{_money(totals['PURCHASE_REFUND'])}</b> تومان",
        f"• خالص مصرف اعتبار: <b>{_money(summary['net_purchases'])}</b> تومان",
        "",
        "💳 <b>افزایش اعتبار نمایندگان</b>",
        f"• واریزی بانکی تأییدشده: <b>{_money(totals['BANK_TOPUP'])}</b> تومان",
        f"• شارژ دستی مدیر (غیرنقدی/نامشخص): <b>{_money(totals['MANUAL_TOPUP'])}</b> تومان",
        f"• مجموع شارژ کیف پول: <b>{_money(summary['wallet_topups'])}</b> تومان",
        "",
        "🏦 <b>تفکیک وجوه بانکی</b>",
        f"• حساب مرکزی NVL: <b>{_money(summary['central_bank'])}</b> تومان",
        f"• کارت اختصاصی نمایندگان: <b>{_money(summary['partner_bank'])}</b> تومان",
        "• خرید از کیف پول، دوباره به ورودی پول اضافه نشده است.",
    ]
    if previous is not None and not preview and not summary["partial"]:
        last = previous["net_purchases"]
        if not previous["partial"]:
            delta = summary["net_purchases"] - last
            direction = "⬆️" if delta > 0 else ("⬇️" if delta < 0 else "➡️")
            percent = (
                f"{abs(delta / last * 100):.1f}٪"
                if last != 0 else ("جدید" if delta else "بدون تغییر")
            )
            rows.extend(["", f"📈 تغییر خالص خرید نسبت به دیروز: {direction} {percent}"])
    rows.extend(["", "ℹ️ مبالغ فروش مستقیم مدیر بدون ثبت دریافت وجه، در گردش کیف پول نمایندگان منظور نشده‌اند."])
    return "\n".join(rows).replace("\n\n\n", "\n\n")


def claim_due_day(conn, *, now=None, send_time="00:05", max_backlog=7):
    """Claim oldest unsent closed calendar day. INTENT means no auto resend."""
    clock = _utc(now)
    hh, mm = map(int, send_time.split(":"))
    if not 0 <= hh <= 23 or not 0 <= mm <= 59:
        raise ValueError("invalid report time")
    local = clock.astimezone(TEHRAN)
    if local.time() < time(hour=hh, minute=mm):
        return None
    yesterday = local.date() - timedelta(days=1)
    started = conn.execute(
        "SELECT value FROM nvl_business_metadata WHERE key='started_at_utc'"
    ).fetchone()
    if not started:
        return None
    first_day = datetime.fromisoformat(started[0]).astimezone(TEHRAN).date()
    first = max(first_day, yesterday - timedelta(days=max(1, max_backlog) - 1))
    for offset in range((yesterday - first).days + 1):
        day = (first + timedelta(days=offset)).isoformat()
        claimed = conn.execute(
            "INSERT OR IGNORE INTO nvl_business_report_deliveries"
            "(report_day,status,claimed_at_utc) VALUES(?,'INTENT',?)",
            (day, _ts(clock)),
        ).rowcount
        if claimed:
            return day
    return None


def finish_delivery(conn, day, *, message_id=None, error_kind=None, now=None):
    status = "SENT" if message_id is not None else "UNCERTAIN"
    conn.execute(
        "UPDATE nvl_business_report_deliveries SET "
        "status=?,completed_at_utc=?,telegram_message_id=?,error_kind=? "
        "WHERE report_day=? AND status='INTENT'",
        (status, _ts(now), message_id, error_kind, day),
    )
