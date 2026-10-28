"""Cloudzy purchase safety policy (P3): pure classification and read-only proof.

No paid POST, deletes, SSH installation, DNS writes or Telegram rendering.
The current CZ03 receipt/idempotency key stays the charged source of truth.
"""
from __future__ import annotations

from dataclasses import dataclass
import argparse
import os
import re
import sqlite3
from pathlib import Path
from urllib.parse import quote

from cloudzy_cz05_catalog import CatalogHold
from cloudzy_service import CloudzyAPIError, CloudzyError, CloudzyUncertainError


@dataclass(frozen=True)
class PurchaseIssue:
    code: str
    title_fa: str
    next_action_fa: str
    retry_class: str


_CATALOG = {
    "AVAILABILITY_STALE": "موجودی Cloudzy به‌روز نیست",
    "PLAN_STOCK_OR_HOURLY_PRICE_CHANGED": "موجودی یا قیمت ساعتی پلن تغییر کرده است",
    "AVAILABILITY_TIMESTAMP_MISSING": "زمان تأیید موجودی مشخص نیست",
    "AVAILABILITY_TIMESTAMP_INVALID": "زمان تأیید موجودی معتبر نیست",
    "AVAILABILITY_REGION_MISMATCH": "منطقه موجودی با انتخاب شما یکسان نیست",
    "AVAILABILITY_PLANS_MISSING": "فهرست موجودی منطقه کامل نیست",
    "AVAILABILITY_DUPLICATE_PLAN": "اطلاعات موجودی یک پلن متناقض است",
    "CATALOG_REGION_OR_CYCLE_INVALID": "منطقه یا دوره قیمت کاتالوگ معتبر نیست",
    "HOURLY_ONLY": "فقط خرید ساعتی در این روند مجاز است",
}
_SAFE_CATALOG_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,79}\Z")
_SAFE_HOSTNAME = re.compile(r"nvl-edge-[0-9a-f]{12}\Z")
_SAFE_SERVER_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")


class PurchaseHold(RuntimeError):
    """Inspect existing receipt/provider rather than replaying paid calls."""


def classify_preflight(exc: Exception) -> PurchaseIssue:
    """GET failures are NEVER mislabelled as definitive price/stock results."""
    if isinstance(exc, CatalogHold):
        raw = str(exc)
        code = raw if _SAFE_CATALOG_CODE.fullmatch(raw) else "CATALOG_UNCLASSIFIED"
        return PurchaseIssue(
            code if code in _CATALOG else "CZ05_STOCK_OR_PRICE_UNVERIFIED",
            _CATALOG.get(code, "قیمت یا موجودی سرور قابل تأیید نیست"),
            "پس از تازه‌سازی قیمت و موجودی، انتخاب را مجدداً بررسی کنید؛ خریدی ارسال نشده است.",
            "NEW_PREFLIGHT_ONLY")
    if isinstance(exc, CloudzyAPIError):
        status = exc.status
        if status in (401, 403):
            title = "دسترسی حساب Cloudzy معتبر نیست"
            action = "توکن، دسترسی و مجوز API را بررسی کنید؛ خرید جدیدی انجام نشده است."
        elif status == 429:
            title = "Cloudzy درخواست‌های خواندنی را موقتاً محدود کرده است"
            action = "پس از مهلت مجاز ارائه‌دهنده فقط خواندن قیمت/موجودی را تکرار کنید."
        elif status >= 500:
            title = "پاسخ بررسی Cloudzy در دسترس نیست"
            action = "فقط استعلام GET را بعداً تکرار کنید؛ هیچ سفارشی ثبت نشده است."
        else:
            title = "Cloudzy استعلام اولیه را نپذیرفت"
            action = "درخواست استعلام یا تنظیمات حساب را بررسی کنید؛ خریدی ارسال نشده است."
        return PurchaseIssue(
            "CLOUDZY_PREFLIGHT_HTTP_" + str(status), title, action,
            "READ_RETRY_OR_OPERATOR")
    if isinstance(exc, CloudzyError):
        return PurchaseIssue(
            "CLOUDZY_PREFLIGHT_READ_FAILED",
            "بررسی قیمت و موجودی Cloudzy ناموفق بود",
            "اتصال API را بررسی کنید؛ فقط استعلام خواندنی قابل تکرار است.",
            "READ_RETRY")
    return PurchaseIssue(
        "CZ05_PREFLIGHT_UNEXPECTED",
        "بررسی مقدماتی خرید با خطای نامشخص روبه‌رو شد",
        "جزئیات محرمانه را در پیام نمایش ندهید؛ لاگ فنی را بررسی کنید.",
        "OPERATOR_REVIEW")


def classify_create(exc: Exception) -> PurchaseIssue:
    """After paid POST: uncertain ALWAYS holds same order/idempotency key."""
    if isinstance(exc, CloudzyUncertainError):
        return PurchaseIssue(
            "CREATE_RESULT_UNCERTAIN",
            "نتیجه ثبت خرید در Cloudzy مشخص نیست",
            "فقط همان hostname و شناسه سفارش قبلی را در فهرست VPSها بررسی کنید؛ POST جدید ممنوع است.",
            "RECONCILE_FIRST")
    if isinstance(exc, CloudzyAPIError):
        if exc.status in (401, 403):
            title = "Cloudzy دسترسی ثبت سفارش را رد کرد"
        elif exc.status == 429:
            title = "Cloudzy محدودیت تعداد درخواست را اعلام کرد"
        elif exc.status == 402:
            title = "Cloudzy به دلیل وضعیت پرداخت سفارش را رد کرد"
        else:
            title = "Cloudzy سفارش را رد کرد"
        return PurchaseIssue(
            "CLOUDZY_CREATE_HTTP_" + str(exc.status), title,
            "ابتدا علت رد سفارش را بررسی کنید؛ دکمه خرید قبلی را تکرار نکنید.",
            "DEFINITE_REJECTION")
    return PurchaseIssue(
        "CREATE_OR_RECEIPT_FAILED",
        "نتیجه خرید یا ثبت رسید آن قطعی نیست",
        "سابقه همان سفارش و موجودی Cloudzy باید قبل از هر خرید تازه تطبیق داده شود.",
        "RECONCILE_FIRST")


def require_base_hourly_ceiling(price_cents: int, ceiling: str | None) -> None:
    """Optional owner-configured **base** hourly limit, not a final price quote.

    Extra IPv4 charges cannot be certified by /pricing/catalog. Do not claim
    this cap guarantees the provider's total charge.
    """
    if type(price_cents) is not int or price_cents <= 0:
        raise PurchaseHold("INVALID_APPROVED_BASE_PRICE")
    if ceiling is None or ceiling == "":
        return
    if not isinstance(ceiling, str) or not re.fullmatch(r"[0-9]{1,7}", ceiling):
        raise PurchaseHold("BASE_HOURLY_CEILING_CONFIG_INVALID")
    limit = int(ceiling)
    if limit <= 0 or price_cents > limit:
        raise PurchaseHold("BASE_HOURLY_CEILING_EXCEEDED")


def _unwrap(record):
    if not isinstance(record, dict):
        return {}
    nested = record.get("data")
    if isinstance(nested, dict):
        record = nested
    for key in ("service", "server"):
        if isinstance(record.get(key), dict):
            return record[key]
    return record


def exact_existing_server(servers, *, hostname: str, provider_id: str | None = None):
    """Pure read-only proof of a unique, exact hostname and provider identity.

    A missing/duplicate/mismatched result is HOLD, never proof that no VPS
    was purchased. Never fall back to IP alone (IP reuse/recycling).
    """
    if not isinstance(hostname, str) or not _SAFE_HOSTNAME.fullmatch(hostname):
        raise PurchaseHold("INVALID_OPERATION_HOSTNAME")
    if provider_id is not None and (
            not isinstance(provider_id, str) or not _SAFE_SERVER_ID.fullmatch(provider_id)):
        raise PurchaseHold("INVALID_PROVIDER_ID")
    if not isinstance(servers, list):
        raise PurchaseHold("PROVIDER_INVENTORY_UNVERIFIED")
    candidates = []
    for raw in servers:
        obj = _unwrap(raw)
        if str(obj.get("hostname") or obj.get("name") or "") == hostname:
            candidates.append(obj)
    if not candidates:
        raise PurchaseHold("PROVIDER_CREATION_UNPROVEN")
    if len(candidates) != 1:
        raise PurchaseHold("PROVIDER_HOSTNAME_AMBIGUOUS")
    chosen = candidates[0]
    sid = str(chosen.get("id") or chosen.get("uuid") or chosen.get("serviceId") or "")
    if not _SAFE_SERVER_ID.fullmatch(sid):
        raise PurchaseHold("PROVIDER_ID_UNVERIFIED")
    if provider_id is not None and sid != provider_id:
        raise PurchaseHold("PROVIDER_ID_CHANGED")
    return sid


def _open_readonly(path: str):
    dbfile = Path(path).expanduser().resolve(strict=True)
    uri = "file:" + quote(str(dbfile), safe="/") + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.execute("PRAGMA query_only=ON")
    return conn


def inspect_receipt(db: sqlite3.Connection, opid: str | None = None):
    """SELECT-only metadata, does not disclose billing keys / SSH materials."""
    if opid is not None and not re.fullmatch(r"[0-9a-f]{32}", opid):
        raise PurchaseHold("INVALID_OPERATION_ID")
    if not db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='cloudzy_edge_operations'"
    ).fetchone():
        return None
    columns = "id,status,hostname,provider_server_id,region,plan_id,billing_cycle,price_cents,hold_reason"
    if opid is not None:
        row = db.execute(
            f"SELECT {columns} FROM cloudzy_edge_operations WHERE id=?", (opid,)
        ).fetchone()
    else:
        row = db.execute(
            f"SELECT {columns} FROM cloudzy_edge_operations ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
    return dict(zip(columns.split(","), row)) if row else None


def main(argv=None):
    """Safe Core smoke: reads real DB, optional provider GET, **never a POST**."""
    parser = argparse.ArgumentParser(description="Cloudzy P3 safe read-only purchase audit")
    parser.add_argument("--db", default="/root/master_bot.db")
    parser.add_argument("--operation", help="Exact existing CZ03 id, else latest")
    parser.add_argument("--live-read", action="store_true",
                        help="Use CLOUDZY_TOKEN from current environment for GET /services only")
    args = parser.parse_args(argv)
    try:
        with _open_readonly(args.db) as db:
            rec = inspect_receipt(db, args.operation)
    except (OSError, sqlite3.Error, PurchaseHold) as exc:
        print("⛔ اطلاعات دفتر سفارش خواندنی نیست؛ بدون تغییر باقی ماند.")
        return 2
    print("✅ پایش P3 تنها خواندنی است؛ هیچ سفارش یا تغییر مسیری اجرا نمی‌شود.")
    if rec is None:
        print("ℹ️ پرونده Cloudzy برای بررسی محلی پیدا نشد.")
        return 0
    print("پرونده:", rec["id"][:16], "وضعیت:", rec["status"],
          "منطقه:", rec["region"], "پایه سنت/ساعت:", rec["price_cents"])
    print("⚠️ قیمت پایه، سقف مبلغ نهایی Cloudzy شامل افزونه‌ها نیست.")
    if not args.live_read:
        print("CLOUDZY_LIVE_READ=SKIPPED")
        return 0
    if not os.environ.get("CLOUDZY_TOKEN"):
        print("CLOUDZY_LIVE_READ=NO_TOKEN_IN_ENV")
        return 2
    from cloudzy_service import CloudzyService
    try:
        inventory = CloudzyService().list_servers()
        if isinstance(inventory, list):
            items = inventory
        elif isinstance(inventory, dict):
            data = inventory.get("data", inventory)
            items = data if isinstance(data, list) else (
                next((data[k] for k in ("items", "services", "servers")
                      if isinstance(data, dict) and isinstance(data.get(k), list)), None)
            )
        else:
            items = None
        if not isinstance(items, list):
            raise PurchaseHold("PROVIDER_INVENTORY_UNVERIFIED")
        print("CLOUDZY_LIST_SERVERS=PASS", "تعداد:", len(items))
        try:
            sid = exact_existing_server(
                items, hostname=rec["hostname"],
                provider_id=rec["provider_server_id"])
        except PurchaseHold as exc:
            # SAFE code only, never raw provider data; absence is not proof of failed charge.
            print("EXACT_PURCHASE_RECONCILE=HOLD", str(exc))
            return 1
        else:
            print("EXACT_PURCHASE_RECONCILE=MATCH", "شناسه VPS:", sid[:16])
            return 0
    except (CloudzyError, PurchaseHold):
        print("CLOUDZY_LIVE_READ=UNVERIFIED (provider GET failed)")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
