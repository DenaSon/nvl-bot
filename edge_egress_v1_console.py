"""K2 Telegram Edge Egress console: evidence-only and an opt-in live IP probe.

No migrations, 6G operations, user movement, PAM/systemd writes, changes to
wg0, Core main route, Cloudflare DNS or protected failover activation.
A *live* probe requires a separately operator-attested Stage SHA256 pin, an
already-running dedicated Core transport, and an existing DB allocation.
It NEVER starts a namespace/tunnel. Lack of proof is HOLD, not READY.
"""
from __future__ import annotations

from dataclasses import dataclass
from html import escape
from ipaddress import IPv4Address
from pathlib import Path
import os
import re
import sqlite3
import subprocess

from edge_egress_status import EgressStatus
from edge_egress_f3_readiness import read_readiness, admission_eligible

EDGE_ID = re.compile(r"^[a-z][a-z0-9_-]{1,23}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class EgressConsoleHold(ValueError):
    pass


@dataclass(frozen=True)
class EdgeDetail:
    edge_id: str
    edge_ipv4: str
    allocation: str
    readiness: str
    ready_for_protected: bool
    observed_ip: str
    witness: str
    stage_pin_present: bool


@dataclass(frozen=True)
class LiveIPResult:
    observed_ip: str
    expected_ip: str
    matches: bool


def edge_id_checked(value: str) -> str:
    if not isinstance(value, str) or EDGE_ID.fullmatch(value) is None:
        raise EgressConsoleHold("INVALID_EDGE_ID")
    return value


def read_edge_detail(db_conn, edge_id: str) -> EdgeDetail | None:
    edge_id_checked(edge_id)
    try:
        with db_conn() as conn:
            allocation = conn.execute(
                "SELECT edge_public_ipv4,status FROM edge_egress_allocations "
                "WHERE edge_id=?", (edge_id,),
            ).fetchone()
            if allocation is None:
                return None
            row = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='edge_egress_readiness'"
            ).fetchone()
            ready = read_readiness(conn, edge_id) if row else None
            pin = conn.execute(
                "SELECT value FROM settings WHERE key=?",
                ("edge_egress_v1_stage_sha256_" + edge_id,),
            ).fetchone()
            return EdgeDetail(
                edge_id=edge_id, edge_ipv4=allocation[0],
                allocation=allocation[1],
                readiness=ready.state if ready else "NO_EVIDENCE",
                ready_for_protected=bool(
                    ready and ready.edge_ipv4 == allocation[0]
                    and admission_eligible(ready)
                ),
                observed_ip=ready.observed_ipv4 or "" if ready else "",
                witness=ready.witness or "" if ready else "",
                stage_pin_present=bool(pin and isinstance(pin[0], str)
                                       and HEX64.fullmatch(pin[0])),
            )
    except sqlite3.Error as exc:
        raise EgressConsoleHold("EDGE_READINESS_UNAVAILABLE") from exc


def overview_html(status: EgressStatus) -> str:
    mode = ("خاموش" if status.protected_setting == "0"
            else "محافظت‌شده" if status.protected_setting == "1"
            else "نامعتبر / HOLD")
    lines = ["🛡 <b>مدیریت Egress</b>", "",
             f"حالت محافظت: <b>{mode}</b>",
             "فعال‌سازی کاربران و Failover محافظت‌شده: <b>🔒 بسته تا تأیید K2</b>"]
    if not status.schema_installed:
        lines.append("\n⛔ رجیستری Egress هنوز نصب نشده است.")
    elif not status.registrations:
        lines.append("\nEdge ثبت‌شده برای Egress وجود ندارد.")
    else:
        lines.append(f"\nEdgeهای ثبت‌شده: {status.registered_count}")
        for edge in status.registrations:
            lines.append(
                f"• <code>{escape(edge.edge_id[:24])}</code> · "
                f"<code>{escape(edge.edge_ipv4[:50])}</code> · "
                f"{escape(edge.state[:48])}"
            )
        if status.registered_count > len(status.registrations):
            lines.append("نمایش ۸ مورد اخیر؛ سایر موارد در پایگاه داده محفوظ‌اند.")
    lines.append("\nStage یا شاهد آزمایشگاهی به معنی READY بودن نیست.")
    return "\n".join(lines)


def detail_html(item: EdgeDetail) -> str:
    evidence = "✅ معتبر" if item.ready_for_protected else "⛔ تأیید نشده"
    return (
        "🛡 <b>جزئیات Egress</b>\n\n"
        f"Edge: <code>{escape(item.edge_id)}</code>\n"
        f"IP مقصد: <code>{escape(item.edge_ipv4)}</code>\n"
        f"Allocation: <code>{escape(item.allocation[:40])}</code>\n"
        f"Readiness: <code>{escape(item.readiness[:40])}</code>\n"
        f"شاهد F4: {evidence}\n"
        f"IP مشاهده‌شده: <code>{escape(item.observed_ip or '—')}</code>\n"
        f"نوع شاهد: <code>{escape(item.witness[:48] or '—')}</code>\n"
        f"Stage Pin: {'✅ ثبت شده' if item.stage_pin_present else '⛔ ثبت نشده'}\n\n"
        "🔒 فعال‌سازی، نصب PAM و انتقال کاربر تا پذیرش K2 غیرفعال‌اند."
    )


def instructions_html() -> str:
    return (
        "🧭 <b>مراحل راه‌اندازی Egress</b>\n\n"
        "۱) افزودن Edge از ویزارد موجود (Ingress).\n"
        "۲) Stage خروجی با Opt-in تأییدشده و Pin مستقل.\n"
        "۳) نصب اولیه Core / Boot Guard / PAM با مسیر بازیابی SSH.\n"
        "۴) تست IP، SSH/SOCKS، DNS/IPv6 و خرابی تونل روی Edge جدید.\n"
        "۵) ثبت شاهد F4 و فعال‌سازی محدود کاربران پس از تأیید.\n\n"
        "⚠️ مراحل حساس عمداً از دکمه تلگرام اجرا نمی‌شوند؛ "
        "افزودن Edge به‌تنهایی Egress را فعال نمی‌کند."
    )


def live_ip_probe(db_conn, edge_id: str, *, run=subprocess.run,
                  geteuid=os.geteuid) -> LiveIPResult:
    """Bounded, read-only packet probe from *existing* dedicated netns.

    This does not promote readiness or persist an observation. A pin created
    by a separate K2 operator acceptance must already exist in settings.
    """
    item = read_edge_detail(db_conn, edge_id)
    if item is None:
        raise EgressConsoleHold("EDGE_NOT_REGISTERED")
    if not item.stage_pin_present:
        raise EgressConsoleHold("STAGE_PIN_NOT_ATTESTED")
    if geteuid() != 0:
        raise EgressConsoleHold("ROOT_PROBE_REQUIRED")
    from ops.edge_egress_v1_transport import pinned, observe, EgressHold
    try:
        with db_conn() as conn:
            pin = conn.execute(
                "SELECT value FROM settings WHERE key=?",
                ("edge_egress_v1_stage_sha256_" + edge_id,),
            ).fetchone()[0]
        stage = Path("/root/nvl-egress-v1") / ("core-" + edge_id)
        spec, peer = pinned(stage, "core", pin)
        if spec.edge_id != edge_id or spec.edge_public_ipv4 != item.edge_ipv4:
            raise EgressConsoleHold("STAGE_EDGE_IDENTITY_MISMATCH")
        if observe(spec, "core", peer) != "UP":
            raise EgressConsoleHold("DEDICATED_TRANSPORT_NOT_RUNNING")
        args = (
            "ip", "netns", "exec", spec.namespace, "curl", "-4", "-fsS",
            "--noproxy", "*", "--connect-timeout", "4",
            "--max-time", "10", "--resolve",
            "one.one.one.one:443:1.1.1.1",
            "https://one.one.one.one/cdn-cgi/trace"
        )
        result = run(args, capture_output=True, text=True, timeout=14)
        if result.returncode or not isinstance(result.stdout, str):
            raise EgressConsoleHold("EGRESS_EXTERNAL_PROBE_FAILED")
        ip_lines = [line[3:].strip() for line in result.stdout.splitlines()
                    if line.startswith("ip=")]
        if len(ip_lines) != 1:
            raise EgressConsoleHold("EXTERNAL_IPV4_EVIDENCE_MISSING")
        observed = IPv4Address(ip_lines[0])
        if not observed.is_global or str(observed) != ip_lines[0]:
            raise EgressConsoleHold("UNTRUSTED_OBSERVED_IPV4")
        return LiveIPResult(str(observed), item.edge_ipv4,
                            str(observed) == item.edge_ipv4)
    except (EgressHold, OSError, ValueError, subprocess.TimeoutExpired,
            sqlite3.Error) as exc:
        if isinstance(exc, EgressConsoleHold):
            raise
        raise EgressConsoleHold("LIVE_PROBE_UNAVAILABLE") from exc


def probe_html(item: LiveIPResult) -> str:
    state = ("✅ برابر با Edge" if item.matches
             else "⛔ IP متفاوت — انتقال کاربر ممنوع")
    return (
        "🌍 <b>تست زنده IP خروجی</b>\n\n"
        f"IP مورد انتظار: <code>{escape(item.expected_ip)}</code>\n"
        f"IP مشاهده‌شده: <code>{escape(item.observed_ip)}</code>\n"
        f"نتیجه: <b>{state}</b>\n\n"
        "این تست فقط خواندنی است؛ به‌تنهایی مجوز READY یا تخصیص کاربر نیست."
    )
