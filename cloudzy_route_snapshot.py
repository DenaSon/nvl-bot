"""Read-only routing snapshot for the *existing* Cloudzy/Legacy Edge panel.

Phase 1: observations and Persian diagnostics only. Never mutates database
rows, DNS, Cloudzy, a worker/lease, or account ownership. Callers may supply
a connection held in a read transaction for cross-table consistency.
The Rich Message adapter and callback integration belong to a later phase.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import argparse
import sqlite3
from urllib.parse import quote


# Exact deployed Legacy/CZ04B active-account predicate (not an approximation).
_ACTIVE_SSH = "service_type='ssh' AND status LIKE '%فعال%' AND status NOT LIKE '%غیر%'"
_SETTING_KEYS = ("hosts", "dns_current_ip", "core_wg_public_ip")
_SEVERITY = {"ERROR": 0, "WARNING": 1}


@dataclass(frozen=True)
class RouteIssue:
    code: str
    severity: str
    title_fa: str
    reason_fa: str
    action_fa: str


@dataclass(frozen=True)
class RelayRow:
    host: str
    active: bool
    is_default: bool
    is_standby: bool
    provider: str
    provider_instance_id: str


@dataclass(frozen=True)
class RouteSnapshot:
    core_ip: str
    cached_dns_ip: str
    legacy_hosts: tuple[str, ...]
    inventory: tuple[RelayRow, ...]
    eligible_candidates: tuple[str, ...]
    active_assignments: tuple[tuple[str, int], ...]
    default_hosts: tuple[str, ...]
    sale_gate_code: str
    issues: tuple[RouteIssue, ...]
    # Cloudflare live records/Provider/SSH health are deliberately NOT probed.
    live_dns_verified: bool = False

    @property
    def consistent(self) -> bool:
        return not any(i.severity == "ERROR" for i in self.issues)


def _issue(code: str, severity: str, title: str, reason: str, action: str) -> RouteIssue:
    return RouteIssue(code, severity, title, reason, action)


def inspect_route(db: sqlite3.Connection) -> RouteSnapshot:
    """SELECT-only on existing tables; never executes CREATE/UPDATE/PRAGMA.

    When invoked by an application, obtain a consistent SQLite read transaction
    before calling this function. This diagnostic is not a health/route authority
    and must not be used to authorize a cutover or customer sale.
    """
    rows = dict(db.execute(
        "SELECT key,value FROM settings WHERE key IN (?,?,?)", _SETTING_KEYS
    ).fetchall())
    core = str(rows.get("core_wg_public_ip") or "").strip()
    cached_dns = str(rows.get("dns_current_ip") or "").strip()
    legacy = tuple(
        part.strip() for part in str(rows.get("hosts") or "").split(",")
        if part.strip()
    )
    pool = tuple(
        RelayRow(
            host=str(host or "").strip(),
            active=bool(active),
            is_default=bool(default),
            is_standby=bool(standby),
            provider=str(provider or ""),
            provider_instance_id=str(instance or ""),
        )
        for host, active, default, standby, provider, instance in
        db.execute(
            "SELECT host,active,is_default,is_standby,provider,provider_instance_id "
            "FROM host_pool ORDER BY host"
        ).fetchall()
    )
    assignment_rows = db.execute(
        "SELECT COALESCE(NULLIF(TRIM(host),''),'<EMPTY>'),COUNT(*) "
        "FROM ssh_accounts WHERE " + _ACTIVE_SSH +
        " GROUP BY COALESCE(NULLIF(TRIM(host),''),'<EMPTY>') "
        "ORDER BY COUNT(*) DESC,1"
    ).fetchall()
    assignments = tuple((str(host), int(count)) for host, count in assignment_rows)
    defaults = tuple(x.host for x in pool if x.is_default)
    eligible = tuple(
        x.host for x in pool if core and x.host and x.host != core
        and x.active and not x.is_standby
    )
    by_host = {x.host: x for x in pool}
    issues: list[RouteIssue] = []

    if not core:
        issues.append(_issue(
            "CORE_PUBLIC_IP_UNVERIFIED", "ERROR",
            "هویت IP اصلی Core مشخص نیست",
            "تنظیم core_wg_public_ip خالی یا تعریف‌نشده است.",
            "هویت Core را فقط با بررسی تنظیمات و زیرساخت معتبر تأیید کنید."
        ))
    if len(defaults) != 1:
        issues.append(_issue(
            "DEFAULT_CUSTOMER_RELAY_AMBIGUOUS", "ERROR",
            "Relay پیش‌فرض یکتا نیست",
            f"تعداد رکوردهای پیش‌فرض در host_pool: {len(defaults)}.",
            "پیش از هر تغییر مسیر، رکوردهای Default و تاریخچه انتقال بررسی شوند."
        ))
        sale_gate = "DEFAULT_CUSTOMER_RELAY_AMBIGUOUS"
    else:
        default = by_host[defaults[0]]
        if not default.host or default.host == core or not default.active or default.is_standby:
            issues.append(_issue(
                "DEFAULT_CUSTOMER_RELAY_NOT_ELIGIBLE", "ERROR",
                "Relay پیش‌فرض برای مشتری مجاز نیست",
                "پیش‌فرض غیرفعال، Standby، بدون IP یا برابر خود Core است.",
                "نقش و سلامت Relay و تغییرات دستی اخیر بررسی شوند؛ اصلاح خودکار ممنوع است."
            ))
            sale_gate = "DEFAULT_CUSTOMER_RELAY_NOT_ELIGIBLE"
        else:
            sale_gate = "PASS"

        if not legacy or legacy[0] != default.host:
            issues.append(_issue(
                "LEGACY_HOSTS_ORDER_MISMATCH", "ERROR",
                "ترتیب مسیرهای Legacy با پیش‌فرض هماهنگ نیست",
                f"Default={default.host}؛ اولین Host={legacy[0] if legacy else '—'}.",
                "ترتیب ثبت مسیرها و آخرین تغییر دستی/CZ-07 را بررسی کنید؛ این گزارش تغییری نمی‌دهد."
            ))
            if sale_gate == "PASS":
                sale_gate = "DEFAULT_CUSTOMER_RELAY_ROUTE_MISMATCH"
        if cached_dns != default.host:
            issues.append(_issue(
                "CACHED_DNS_DEFAULT_MISMATCH", "ERROR",
                "DNS ثبت‌شده با Relay پیش‌فرض یکسان نیست",
                f"Default={default.host}؛ Cached DNS={cached_dns or '—'}.",
                "DNS زنده Cloudflare و Journal تغییر مسیر را مستقل بررسی کنید."
            ))
            if sale_gate == "PASS":
                sale_gate = "DEFAULT_CUSTOMER_RELAY_ROUTE_MISMATCH"

    if not core:
        # Mirrors the first precondition of _default_customer_relay_checked.
        sale_gate = "CORE_PUBLIC_IP_UNVERIFIED"

    if not legacy:
        issues.append(_issue(
            "LEGACY_HOSTS_EMPTY", "ERROR",
            "فهرست مسیرهای Legacy خالی است",
            "settings.hosts هیچ Host معتبری ندارد.",
            "فهرست و منبع تولید آن را بررسی کنید؛ بازسازی خودکار در این فاز وجود ندارد."
        ))
    if len(legacy) != len(set(legacy)):
        issues.append(_issue(
            "LEGACY_HOSTS_DUPLICATED", "WARNING",
            "یک Host بیش از یک بار ثبت شده است",
            "settings.hosts شامل IP تکراری است.",
            "قبل از تغییر مسیر، فهرست Legacy و سوابق آن بررسی شوند."
        ))

    standby_in_hosts = sorted({h for h in legacy if h in by_host and by_host[h].is_standby})
    if standby_in_hosts:
        issues.append(_issue(
            "STANDBY_IN_LEGACY_HOSTS", "WARNING",
            "آدرس Standby در فهرست Legacy قرار دارد",
            "Hostهای Standby در settings.hosts: " + ", ".join(standby_in_hosts),
            "Inventory را از مسیرهای قابل عرضه به مشتری جدا کنید."
        ))
    if core and core in legacy:
        issues.append(_issue(
            "CORE_IN_LEGACY_HOSTS", "WARNING",
            "IP خود Core در فهرست مسیرهای Legacy است",
            "این فهرست به‌تنهایی فهرست Relayهای مجاز برای فروش نیست.",
            "Core و Edgeهای فروش را با نقش‌های مستقل مدل‌سازی کنید."
        ))
    unknown_in_hosts = sorted({h for h in legacy if h not in by_host})
    if unknown_in_hosts:
        issues.append(_issue(
            "LEGACY_HOST_NOT_IN_POOL", "WARNING",
            "Host ثبت‌شده در Inventory یافت نشد",
            "Hostهای فاقد رکورد: " + ", ".join(unknown_in_hosts),
            "هویت و سابقه Hostها را بدون حذف یا تغییر خودکار بررسی کنید."
        ))

    misplaced = [(host, count) for host, count in assignments
                 if host == "<EMPTY>" or host not in by_host
                 or (len(defaults) == 1 and host != defaults[0])]
    if misplaced:
        detail = ", ".join(f"{host}: {count}" for host, count in misplaced)
        issues.append(_issue(
            "ACTIVE_SSH_ASSIGNMENT_DRIFT", "ERROR",
            "برخی کاربران فعال روی مسیر پیش‌فرض ثبت نشده‌اند",
            "تعداد اکانت‌های فعال بر اساس Host: " + detail,
            "وضعیت کاربران و Journal انتقال را بررسی کنید؛ حساب‌ها را خودکار جابه‌جا نکنید."
        ))

    issues.sort(key=lambda i: (_SEVERITY[i.severity], i.code))
    return RouteSnapshot(
        core_ip=core, cached_dns_ip=cached_dns,
        legacy_hosts=legacy, inventory=pool,
        eligible_candidates=eligible,
        active_assignments=assignments, default_hosts=defaults,
        sale_gate_code=sale_gate, issues=tuple(issues)
    )


def format_route_report(snapshot: RouteSnapshot) -> str:
    """Plain Persian diagnostic for CLI/a future Rich Message presenter.

    This is *not* a second HTML fallback UI. Rendering/escaping for Telegram
    must occur in the later dedicated Rich Message layer.
    """
    lines = [
        "🩺 ارزیابی مسیرهای NVL | فاز ۱ (فقط خواندنی)",
        "نتیجه: " + ("ناسازگاری حیاتی مشاهده نشد" if snapshot.consistent else
                      "ناسازگاری نیازمند بررسی"),
        "پیش‌فرض: " + (", ".join(snapshot.default_hosts) or "نامشخص"),
        "DNS ذخیره‌شده: " + (snapshot.cached_dns_ip or "نامشخص"),
        "اولین Host: " + (snapshot.legacy_hosts[0] if snapshot.legacy_hosts else "نامشخص"),
        "Core: " + (snapshot.core_ip or "نامشخص"),
        "Relayهای بالقوه (بدون تأیید سلامت): " +
        (", ".join(snapshot.eligible_candidates) or "هیچ"),
        "کاربران SSH فعال: " +
        (", ".join(f"{host} = {count}" for host, count in snapshot.active_assignments)
         or "هیچ"),
        "کد پیش‌بینی‌شده گیت فروش: " + snapshot.sale_gate_code,
        "⚠️ DNS زنده Cloudflare، SSH و Provider در این گزارش آزموده نشده‌اند.",
    ]
    if not snapshot.issues:
        lines.append("✅ ناسازگاری محلی در قواعد بررسی‌شده مشاهده نشد.")
    else:
        for item in snapshot.issues:
            lines += [
                "",
                ("⛔" if item.severity == "ERROR" else "⚠️") + " " + item.title_fa,
                "علت: " + item.reason_fa,
                "راهنما: " + item.action_fa,
                "کد فنی: " + item.code,
            ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only NVL route diagnosis")
    parser.add_argument("--db", default="/root/master_bot.db",
                        help="Existing SQLite database; must already exist")
    args = parser.parse_args(argv)
    path = Path(args.db).expanduser().resolve(strict=True)
    uri = "file:" + quote(str(path), safe="/") + "?mode=ro"
    with sqlite3.connect(uri, uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")  # Consistent read snapshot, no data mutation.
        try:
            report = inspect_route(db)
            print(format_route_report(report))
        except sqlite3.OperationalError:
            print("⛔ ساختار داده برای ارزیابی مسیر در دسترس نیست؛ فقط Schema را بررسی کنید.")
            return 2
    return 0 if report.consistent else 1


if __name__ == "__main__":
    raise SystemExit(main())
