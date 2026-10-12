"""K2 Phase 2 — read-only Telegram admin view over existing Edge host pool.

This module never creates a transport, stages keys, mutates DNS/routes/UIDs,
installs PAM/systemd, or promotes a readiness witness to F4 READY.
It merges trusted H ingress identity, host_pool role and existing F3/F4 data
without confusing default ingress, public DNS and individual user egress.
"""
from __future__ import annotations

from dataclasses import dataclass
from html import escape
from ipaddress import IPv4Address
from pathlib import Path
import os
import sqlite3
import time
from typing import Callable

from edge_egress_f3_readiness import admission_eligible, read_readiness
from edge_egress_v1_console import EgressConsoleHold, edge_id_checked
from edge_egress_v1_ingress import IngressHold, load_registry

MAX_EDGES = 8


@dataclass(frozen=True)
class EdgeCard:
    edge_id: str
    ip: str
    ingress_verified: bool
    pool_active: bool
    pool_default: bool
    dns_target: bool
    allocation: str
    f4_state: str
    f4_valid: bool
    witness: str
    observed_ip: str
    evidence_at: int | None
    expires_at: int | None
    stage_pin: str | None

    @property
    def can_probe(self) -> bool:
        # A namespace IP test is never a substitute for F4 acceptance.
        return (self.ingress_verified and self.pool_active
                and self.allocation != "NOT_STAGED"
                and self.stage_pin is not None)


@dataclass(frozen=True)
class Dashboard:
    cards: tuple[EdgeCard, ...]
    total: int
    registry_trusted: bool
    default_ip: str
    dns_ip: str
    protected_mode: str


@dataclass(frozen=True)
class TransportCheck:
    state: str
    # No timestamped last good proof is written to disk.
    checked_at: int


def _setting(conn, name: str, default: str = "") -> str:
    value = conn.execute(
        "SELECT value FROM settings WHERE key=?", (name,)
    ).fetchone()
    return str(value[0]) if value and value[0] is not None else default


def _table(conn, name: str) -> bool:
    return bool(conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (name,),
    ).fetchone())


def _global_ip(value: str) -> bool:
    try:
        p = IPv4Address(value)
        return str(p) == value and p.is_global
    except (ValueError, TypeError):
        return False


def read_dashboard(db_conn: Callable, *,
                   ingress_loader: Callable = load_registry,
                   now: int | None = None) -> Dashboard:
    """Read-only. Include registered ingress-only e7 even without allocation."""
    clock = int(time.time()) if now is None else now
    if type(clock) is not int or clock < 1:
        raise EgressConsoleHold("INVALID_CLOCK")
    try:
        peers = ingress_loader()
        trusted = True
    except (IngressHold, OSError, ValueError):
        # Still show DB-staged allocations, but never label ingress verified.
        peers, trusted = (), False
    try:
        with db_conn() as conn:
            pool = {
                row[0]: (bool(row[1]), bool(row[2]))
                for row in conn.execute(
                    "SELECT host,active,is_default FROM host_pool"
                ).fetchall()
            }
            default = next(
                (host for host, flags in pool.items() if flags[1]), ""
            )
            dns = _setting(conn, "dns_current_ip")
            mode = _setting(conn, "edge_egress_protected_mode", "0")
            allocations = {}
            if _table(conn, "edge_egress_allocations"):
                allocations = {
                    row[0]: (row[1], row[2])
                    for row in conn.execute(
                        "SELECT edge_id,edge_public_ipv4,status "
                        "FROM edge_egress_allocations"
                    ).fetchall()
                }
            rows = {}
            if trusted:
                for p in peers:
                    edge_id_checked(p.edge_id)
                    if not _global_ip(p.edge_ipv4):
                        raise EgressConsoleHold("INVALID_REGISTRY_IPV4")
                    rows[p.edge_id] = (p.edge_ipv4, True)
            for edge_id, (ip, _) in allocations.items():
                try:
                    edge_id_checked(edge_id)
                    valid = _global_ip(ip)
                except EgressConsoleHold:
                    valid = False
                if not valid:
                    continue
                if edge_id in rows:
                    if rows[edge_id][0] != ip:
                        # Same identity with contradictory public IP: no
                        # green ingress status or transport operations.
                        rows[edge_id] = (ip, False)
                else:
                    rows[edge_id] = (ip, False)

            cards = []
            has_readiness = _table(conn, "edge_egress_readiness")
            for edge_id, (ip, ingress) in rows.items():
                active, is_default = pool.get(ip, (False, False))
                recorded = allocations.get(edge_id)
                allocation = (
                    recorded[1] if recorded and recorded[0] == ip
                    else "IDENTITY_CONFLICT" if recorded else "NOT_STAGED"
                )
                read = read_readiness(conn, edge_id) if has_readiness else None
                coherent = bool(read and read.edge_ipv4 == ip)
                stage_pin = _setting(
                    conn, "edge_egress_v1_stage_sha256_" + edge_id,
                )
                pin = stage_pin if (
                    len(stage_pin) == 64
                    and all(c in "0123456789abcdef" for c in stage_pin)
                ) else None
                cards.append(EdgeCard(
                    edge_id=edge_id, ip=ip,
                    ingress_verified=ingress, pool_active=active,
                    pool_default=is_default, dns_target=(dns == ip),
                    allocation=allocation,
                    f4_state=read.state if coherent else "NO_EVIDENCE",
                    f4_valid=bool(
                        coherent and admission_eligible(read, now=clock)
                        and allocation not in ("NOT_STAGED", "IDENTITY_CONFLICT")
                        and ingress and active
                    ),
                    witness=read.witness or "" if coherent else "",
                    observed_ip=read.observed_ipv4 or "" if coherent else "",
                    evidence_at=read.probed_at if coherent else None,
                    expires_at=read.expires_at if coherent else None,
                    stage_pin=pin,
                ))
        cards.sort(key=lambda c: (
            not c.pool_active, not c.pool_default, c.edge_id,
        ))
        return Dashboard(
            cards=tuple(cards[:MAX_EDGES]), total=len(cards),
            registry_trusted=trusted, default_ip=default, dns_ip=dns,
            protected_mode=mode,
        )
    except sqlite3.Error as exc:
        raise EgressConsoleHold("DASHBOARD_DATABASE_UNAVAILABLE") from exc


def get_card(dashboard: Dashboard, edge_id: str) -> EdgeCard:
    edge_id_checked(edge_id)
    for card in dashboard.cards:
        if card.edge_id == edge_id:
            return card
    raise EgressConsoleHold("EDGE_NOT_IN_CURRENT_PAGE")


def transport_check(card: EdgeCard, *, geteuid=os.geteuid,
                    now: Callable = time.time) -> TransportCheck:
    """Bounded pinned observation only, no ensure()/up.sh()/down.sh()."""
    checked = int(now())
    if not card.ingress_verified:
        return TransportCheck("INGRESS_UNVERIFIED", checked)
    if not card.pool_active:
        return TransportCheck("POOL_INACTIVE", checked)
    if card.allocation in ("NOT_STAGED", "IDENTITY_CONFLICT"):
        return TransportCheck("ALLOCATION_NOT_READY", checked)
    if not card.stage_pin:
        return TransportCheck("STAGE_PIN_REQUIRED", checked)
    if geteuid() != 0:
        return TransportCheck("ROOT_INSPECTION_REQUIRED", checked)
    from ops.edge_egress_v1_transport import pinned, observe, EgressHold
    try:
        path = Path("/root/nvl-egress-v1") / ("core-" + card.edge_id)
        spec, peer = pinned(path, "core", card.stage_pin)
        if spec.edge_id != card.edge_id or spec.edge_public_ipv4 != card.ip:
            return TransportCheck("STAGE_IDENTITY_MISMATCH", checked)
        return TransportCheck(observe(spec, "core", peer), checked)
    except (EgressHold, OSError, ValueError):
        return TransportCheck("HOLD", checked)


def _name(value: str) -> str:
    return escape(value[:100])


def _f4(card: EdgeCard) -> str:
    if card.f4_state in ("HOLD", "REVOKED"):
        return "⛔ " + _name(card.f4_state)
    if card.f4_valid:
        return "✅ F4 معتبر (فقط شاهد؛ نه مجوز سوییچ)"
    if card.f4_state == "READY":
        return "⏳ READY منقضی / نامعتبر"
    if card.f4_state == "VERIFIED_LAB":
        return "🧪 آزمایشگاهی؛ پذیرش Production ندارد"
    return "⏳ " + _name(card.f4_state)


def dashboard_html(board: Dashboard) -> str:
    lines = ["🛡 <b>مرکز کنترل Egress</b>", "",
             "📡 <b>وضعیت رله ورودی</b>",
             f"⭐ پیش‌فرض: <code>{_name(board.default_ip or '—')}</code>",
             f"🌐 مقصد DNS: <code>{_name(board.dns_ip or '—')}</code>"]
    if board.default_ip != board.dns_ip:
        lines.append("⚠️ پیش‌فرض استخر و مقصد DNS یکسان نیستند.")
    lines.append(
        "🔐 حالت محافظت: " +
        ("خاموش" if board.protected_mode == "0"
         else "فعال (نیازمند تأیید زنده)" if board.protected_mode == "1"
         else "HOLD — مقدار نامعتبر")
    )
    lines.extend(("", "🖥 <b>Edgeها</b>"))
    if not board.registry_trusted:
        lines.append("⚠️ رجیستری هویت wg0 در دسترس/قابل اعتماد نیست.")
    for card in board.cards:
        tag = ("⛔" if card.allocation == "IDENTITY_CONFLICT"
               else "✅" if card.f4_valid else "⏳")
        state = ("INGRESS_ONLY" if card.allocation == "NOT_STAGED"
                 else card.allocation[:20])
        lines.append(
            f"{tag} <code>{_name(card.edge_id)}</code> · "
            f"<code>{_name(card.ip)}</code> · {_name(state)}"
        )
    if not board.cards:
        lines.append("Edge ثبت‌شده یا تخصیص‌یافته‌ای یافت نشد.")
    if board.total > len(board.cards):
        lines.append("صفحه نخست؛ سایر Edgeها محفوظ‌اند.")
    lines.append(
        "\n🔒 انتقال کاربر، نصب PAM و تغییر رله عمومی تا پذیرش "
        "فاز اول غیرفعال‌اند."
    )
    return "\n".join(lines)


def detail_html(card: EdgeCard) -> str:
    ingress = (
        "✅ هویت ثبت‌شده؛ آنلاین‌بودن بررسی نشده"
        if card.ingress_verified and card.pool_active else
        "⏳ ثبت‌شده ولی غیرفعال" if card.ingress_verified else
        "⛔ هویت wg0 تأیید نشده"
    )
    return "\n".join((
        "🛡 <b>جزئیات Edge / Egress</b>", "",
        f"🖥 Edge: <code>{_name(card.edge_id)}</code>",
        f"🌍 IP: <code>{_name(card.ip)}</code>", "",
        "📥 <b>Ingress</b>: " + ingress,
        "⭐ پیش‌فرض ورودی: " + ("بله" if card.pool_default else "خیر"),
        "🌐 مقصد DNS: " + ("بله" if card.dns_target else "خیر"),
        "📤 <b>Egress</b>: " + _name(card.allocation),
        "🔏 Pin مستقل Stage: " + (
            "✅ ثبت شده" if card.stage_pin else "⏳ ثبت نشده"
        ),
        "🧾 F4: " + _f4(card),
        f"🔎 آخرین IP ثبت‌شده: <code>{_name(card.observed_ip or '—')}</code>",
        f"🕒 زمان شاهد (UTC Unix): <code>{card.evidence_at or '—'}</code>",
        "🧯 Fail-Closed: ⏳ اثبات عملی ثبت نشده",
        "🗝 PAM / Boot: ⏳ پذیرش عملی ثبت نشده",
        "🧬 DNS / IPv6: ⏳ تست نشت ثبت نشده",
        "",
        "🔒 تغییر مسیر و فعال‌سازی از این صفحه انجام نمی‌شود.",
    ))


def health_html(card: EdgeCard, status: TransportCheck) -> str:
    states = {
        "UP": "✅ UP — فقط تونل اختصاصی",
        "ABSENT": "⏳ اینترفیس اختصاصی حاضر نیست",
        "STAGE_PIN_REQUIRED": "⏳ SHA تأیید مستقل ندارد",
        "ALLOCATION_NOT_READY": "⏳ Allocation / Stage ثبت‌نشده",
        "INGRESS_UNVERIFIED": "⛔ رجیستری ورود تأیید نشده",
        "POOL_INACTIVE": "⏳ Edge در استخر غیرفعال است",
        "ROOT_INSPECTION_REQUIRED": "⛔ دسترسی ریشه برای بررسی لازم است",
        "STAGE_IDENTITY_MISMATCH": "⛔ Stage متعلق به این Edge نیست",
        "HOLD": "⛔ وضعیت تونل نامطمئن است",
    }
    current = states.get(status.state, "⛔ نامعلوم")
    return "\n".join((
        f"🔎 <b>سلامت Egress / {_name(card.edge_id)}</b>", "",
        f"📤 تونل: {current}",
        f"🕒 بررسی در (UTC Unix): <code>{status.checked_at}</code>",
        "🔐 نتیجه F4: " + _f4(card),
        "",
        "⚠️ این فقط بازرسی خواندنی محلی است؛ "
        "نه تست IP کلاینت، نه تست Fail-Closed و نه مجوز انتقال.",
    ))


def actions_html(card: EdgeCard, status: TransportCheck) -> str:
    """Read-only preview of safety gates. No activation execution endpoint."""
    reasons = []
    if not card.ingress_verified or not card.pool_active:
        reasons.append("هویت و فعالیت Ingress")
    if card.allocation in ("NOT_STAGED", "IDENTITY_CONFLICT"):
        reasons.append("تخصیص و Stage معتبر")
    if not card.stage_pin:
        reasons.append("Pin مستقل SHA256")
    if status.state != "UP":
        reasons.append("تونل اختصاصی سالم")
    if not card.f4_valid:
        reasons.append("شاهد مستقل F4 و عدم نشت")
    # Even exact F4 DB status cannot unfreeze users without PAM/rescue/6G.
    reasons.append("پذیرش PAM/Boot و عملیات 6G تحت قفل")
    return "\n".join((
        f"🧭 <b>آماده‌سازی {_name(card.edge_id)}</b>", "",
        f"📍 مقصد: <code>{_name(card.ip)}</code>",
        "🔒 فعال‌سازی و انتقال کاربران: <b>HOLD</b>",
        "",
        "پیش‌نیازهای باز:",
        *("• " + _name(x) for x in reasons),
        "",
        "این صفحه فقط وضعیت را نشان می‌دهد؛ "
        "هیچ عملیات نصب، تغییر IP/DNS یا UID اجرا نمی‌شود.",
    ))
