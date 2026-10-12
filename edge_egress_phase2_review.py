"""K2 Phase 2-B3: independently rechecked, ONE-SHOT operation review only.

Creates no executable plan or privileged capability. Acknowledgement means
the administrator has READ the draft, NOT authorized any mutation. This is
a safe Telegram UI prerequisite for an independently reviewed future executor.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest
from html import escape
import json
import re
import secrets
import sqlite3
import time

from edge_egress_v1_console import EgressConsoleHold

ACTIONS = {
    "EDGE_PREPARE": ("📦 آماده‌سازی Edge", 0),
    "UID_ATTACH": ("👤 تخصیص محافظت‌شده کاربر", 1),
    "UID_FREEZE": ("🧊 توقف محافظت‌شده کاربر", 1),
}
USERNAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
TTL_SECONDS = 120
# This source release intentionally has NO execute, subprocess or apply API.
EXECUTOR_ENABLED = False


@dataclass(frozen=True)
class OperatorReview:
    action: str
    edge_id: str
    ip: str
    username: str
    current_host: str
    blockers: tuple[str, ...]
    steps: tuple[str, ...]
    checked_at: int
    digest: str
    affected_accounts: int
    decision: str = "HOLD"

    def __post_init__(self):
        if self.decision != "HOLD":
            raise EgressConsoleHold("REVIEW_MUST_HOLD_UNTIL_RELEASE")


@dataclass(frozen=True)
class ReviewTicket:
    token: str
    digest: str
    edge_id: str
    action: str
    username: str
    actor_id: int
    chat_id: int
    expires_at: int


def _tbl(conn, name):
    return bool(conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone())


def build_review(db_conn, card, stage, action: str, username: str = "",
                 *, now: int | None = None) -> OperatorReview:
    if action not in ACTIONS:
        raise EgressConsoleHold("UNSUPPORTED_REVIEW_ACTION")
    if ACTIONS[action][1]:
        if not isinstance(username, str) or not USERNAME.fullmatch(username):
            raise EgressConsoleHold("INVALID_REVIEW_USERNAME")
    elif username:
        raise EgressConsoleHold("EDGE_REVIEW_HAS_NO_USERNAME")
    stamp = int(time.time()) if now is None else now
    if type(stamp) is not int or stamp <= 0:
        raise EgressConsoleHold("INVALID_REVIEW_TIMESTAMP")

    blockers = []
    if not card.ingress_verified or not card.pool_active:
        blockers.append("INGRESS_IDENTITY_OR_POOL_UNVERIFIED")
    if card.allocation == "IDENTITY_CONFLICT":
        blockers.append("EDGE_IDENTITY_CONFLICT")
    elif card.allocation != "STAGED":
        blockers.append("F3_STAGED_ALLOCATION_MISSING")
    if not card.stage_pin or stage.stage_state != "PINNED":
        blockers.append("INDEPENDENT_STAGE_SHA_REQUIRED")
    if stage.stage_state in ("PIN_MISMATCH", "HOLD_IDENTITY"):
        blockers.append("STAGE_HASH_OR_IDENTITY_HOLD")
    if stage.tunnel_state != "UP":
        blockers.append("DEDICATED_TRANSPORT_NOT_VERIFIED_UP")
    if not card.f4_valid:
        blockers.append("F4_ACCEPTANCE_NOT_VALID")

    current_host = ""
    account_state = "NA"
    lease_state = "UNKNOWN"
    protected = "UNKNOWN"
    try:
        with db_conn() as conn:
            if not _tbl(conn, "settings"):
                blockers.append("PROTECTED_SETTING_UNAVAILABLE")
            else:
                mode = conn.execute(
                    "SELECT value FROM settings "
                    "WHERE key='edge_egress_protected_mode'"
                ).fetchone()
                protected = mode[0] if mode else "MISSING"
                if protected != "1":
                    blockers.append("PROTECTED_MODE_NOT_APPROVED")
            if not _tbl(conn, "failover_operations"):
                blockers.append("SHARED_6G_LEDGER_MISSING")
            else:
                running = conn.execute(
                    "SELECT COUNT(*) FROM failover_operations "
                    "WHERE status='RUNNING'"
                ).fetchone()[0]
                lease_state = f"RUNNING:{running}"
                if running:
                    blockers.append("ANOTHER_6G_OPERATION_RUNNING")
            if username:
                if not _tbl(conn, "ssh_accounts"):
                    blockers.append("SSH_ACCOUNT_SCHEMA_MISSING")
                    account_state = "SCHEMA_MISSING"
                else:
                    row = conn.execute(
                        "SELECT host,service_type,status FROM ssh_accounts "
                        "WHERE username=?", (username,),
                    ).fetchone()
                    if not row:
                        blockers.append("SSH_ACCOUNT_NOT_FOUND")
                        account_state = "MISSING"
                    else:
                        current_host = str(row[0] or "")[:64]
                        account_state = f"{row[1]}:{row[2]}"
                        if row[1] != "ssh" or not isinstance(row[2], str) or (
                            "فعال" not in row[2] or "غیر" in row[2]
                        ):
                            blockers.append("SSH_ACCOUNT_NOT_ACTIVE")
    except (sqlite3.Error, OSError):
        blockers.append("DATABASE_EVIDENCE_UNAVAILABLE")
        # A partial read is evidence-unavailable, never an actionable plan.

    # These fields currently have NO sufficient durable real-host attestation.
    # Even a forged READY row cannot unlock review's authority boundary.
    blockers.extend((
        "F2_PAM_BOOT_RESCUE_NOT_ACCEPTED",
        "DNS_IPV6_FAIL_CLOSED_NOT_ACCEPTED",
        "PROTECTED_6G_EXECUTOR_NOT_INSTALLED",
    ))
    if action == "UID_ATTACH":
        steps = (
            "بررسی هویت و نشست واقعی UID و Edge مقصد",
            "ثبت محافظت deny-first و Blackhole قبل از انتخاب UID",
            "تأیید PAM و DNS/IPv6 و Fail-Closed در پنجره تست",
            "تخصیص فقط تحت قفل 6G و بررسی مجدد خروجی",
        )
    elif action == "UID_FREEZE":
        steps = (
            "تأیید هویت UID و اتصال‌های موجود",
            "ثبت deny-first اختصاصی بدون حذف مسیر Edge مشترک",
            "مستندسازی وضعیت FROZEN و مسیر بازیابی",
        )
    else:
        steps = (
            "تأیید هویت wg0 و SHA مستقل هر دو Stage",
            "تست preflight و مالکیت منابع بدون راه‌اندازی مجدد wg0",
            "تأیید supervisor/PAM/Boot و بازیابی مستقل",
            "فقط سپس درخواست پذیرش F4 و ثبت Journal",
        )
    payload = {
        "edge_id": card.edge_id, "edge_ip": card.ip,
        "action": action, "username": username,
        "ingress_verified": card.ingress_verified,
        "pool_active": card.pool_active,
        "allocation": card.allocation, "f4_state": card.f4_state,
        "f4_valid": card.f4_valid, "evidence_at": card.evidence_at,
        "expires_at": card.expires_at, "stage_pin": card.stage_pin,
        "stage_state": stage.stage_state, "stage_sha": stage.local_sha256,
        "tunnel_state": stage.tunnel_state, "current_host": current_host,
        "account_state": account_state, "lease_state": lease_state,
        "protected_mode": protected, "blockers": blockers,
    }
    digest = sha256(json.dumps(
        payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")).hexdigest()
    return OperatorReview(
        action=action, edge_id=card.edge_id, ip=card.ip,
        username=username, current_host=current_host,
        blockers=tuple(dict.fromkeys(blockers)),
        steps=steps, checked_at=stamp, digest=digest,
        affected_accounts=int(bool(username)),
    )


def issue_ticket(review: OperatorReview, *, actor_id: int, chat_id: int,
                 now: int | None = None, nonce=None) -> ReviewTicket:
    """Non-transferable preview acknowledgement only, never live execution."""
    if review.decision != "HOLD" or type(actor_id) is not int or actor_id <= 0 or (
        type(chat_id) is not int or chat_id == 0
    ):
        raise EgressConsoleHold("REVIEW_TICKET_INVALID_CONTEXT")
    stamp = int(time.time()) if now is None else now
    token = secrets.token_hex(8) if nonce is None else nonce()
    if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{16}", token):
        raise EgressConsoleHold("INVALID_REVIEW_NONCE")
    return ReviewTicket(token, review.digest, review.edge_id, review.action,
                        review.username, actor_id, chat_id, stamp + TTL_SECONDS)


def acknowledge_ticket(ticket: ReviewTicket, refreshed: OperatorReview, *,
                       token: str, actor_id: int, chat_id: int,
                       now: int | None = None) -> str:
    """Caller MUST consume server-side ticket before awaiting new evidence.

    Returns only a read receipt code. It never authorizes an operation.
    """
    stamp = int(time.time()) if now is None else now
    if stamp >= ticket.expires_at:
        raise EgressConsoleHold("REVIEW_EXPIRED")
    if type(actor_id) is not int or type(chat_id) is not int or (
        actor_id != ticket.actor_id or chat_id != ticket.chat_id
    ):
        raise EgressConsoleHold("REVIEW_ACTOR_OR_CHAT_MISMATCH")
    if not isinstance(token, str) or not compare_digest(token, ticket.token):
        raise EgressConsoleHold("REVIEW_NONCE_MISMATCH")
    if (refreshed.edge_id != ticket.edge_id
            or refreshed.action != ticket.action
            or refreshed.username != ticket.username
            or not compare_digest(refreshed.digest, ticket.digest)):
        raise EgressConsoleHold("REVIEW_EVIDENCE_CHANGED")
    return "REVIEW_ACKNOWLEDGED_NO_EXECUTION"


def review_html(review: OperatorReview) -> str:
    def safe(v): return escape(str(v)[:100])
    title = ACTIONS[review.action][0]
    lines = [
        f"🧭 <b>{title} — فقط بررسی طرح</b>", "",
        f"🌍 Edge: <code>{safe(review.edge_id)}</code> · "
        f"<code>{safe(review.ip)}</code>",
    ]
    if review.username:
        lines.extend((
            f"👤 کاربر: <code>{safe(review.username)}</code>",
            f"📥 ورودی ثبت‌شده: <code>{safe(review.current_host or '—')}</code>",
        ))
    lines.extend((
        f"👥 حداکثر حساب‌های در طرح: {review.affected_accounts}",
        "⛔ <b>HOLD — اجرا غیرفعال است.</b>", "",
        "<b>موانع:</b>",
        *("• <code>" + safe(x) + "</code>" for x in review.blockers),
        "", "<b>مراحل اجرایی بعد از پذیرش:</b>",
        *("• " + safe(x) for x in review.steps),
        "", f"🔎 شناسه طرح: <code>{review.digest[:16]}</code>",
        "🕒 اعتبار بررسی: ۱۲۰ ثانیه",
        "⚠️ تأیید مطالعه، مجوز اجرا نیست و هیچ حساب، DNS، "
        "WireGuard یا Route تغییر نمی‌کند.",
    ))
    return "\n".join(lines)
