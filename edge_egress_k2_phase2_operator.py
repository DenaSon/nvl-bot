"""K2 Phase 2: manual, guarded ALL-PROTECTED relay handoff.

Uses the existing 6G protected saga/host driver, NOT legacy hpdef/6H. A
mixed Legacy/Protected cohort is never silently converted: it blocks before
the operator can issue a ticket. Every successful customer is kept on Core as
an SSH identity, and has a pinned Edge per-UID internet route. No auto-switch.
"""
from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
from hashlib import sha256
from hmac import compare_digest
from ipaddress import IPv4Address
import json
import os
from pathlib import Path
import pwd
import secrets
import sqlite3
import time
from typing import Callable

from edge_egress_f3_readiness import read_readiness, admission_eligible
from edge_egress_v1_cloudflare import ProtectedCloudflareDNS
from edge_egress_k2_p1_worker import load_stage_pin, _check_stage, _remote_transport
from edge_egress_v1_ingress import load_registry
from edge_egress_v1_live_driver import LiveDriverConfig, make_live_adapter
from edge_egress_v1_handoff_adapter import execute_protected_switch

TTL_SECONDS = 90
OPERATOR_SETTING = "k2_p2_relay_switch_enabled"


class Phase2Hold(ValueError):
    pass


@dataclass(frozen=True)
class RelayCohortReview:
    edge_id: str
    source: str
    target: str
    active_accounts: int
    legacy_accounts: int
    blockers: tuple[str, ...]
    fingerprint: str

    @property
    def ready(self) -> bool:
        return not self.blockers and self.active_accounts > 0


@dataclass(frozen=True)
class RelaySwitchTicket:
    edge_id: str
    source: str
    target: str
    cohort_fingerprint: str
    dns_fingerprint: str
    nonce: str
    actor_id: int
    chat_id: int
    expires_at: int


def _setting(conn, key: str, default: str = "") -> str:
    row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row[0] if row else default


def _fingerprint(data: object) -> str:
    return sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def review_relay_cohort(db_conn: Callable, edge_id: str,
                        *, os_uid: Callable = lambda name: pwd.getpwnam(name).pw_uid,
                        pin_loader: Callable = load_stage_pin,
                        now: int | None = None) -> RelayCohortReview:
    """Read-only, exact all-active SSH inventory and source-target identity."""
    from edge_egress_v1_console import edge_id_checked
    edge_id_checked(edge_id)
    clock = int(time.time()) if now is None else now
    blockers = []
    accounts = ()
    source = target = ""
    pin_hash = ""
    f4_marker = ()
    try:
        with db_conn() as db:
            source_rows = db.execute(
                "SELECT host,service_port FROM host_pool "
                "WHERE active=1 AND is_default=1"
            ).fetchall()
            if len(source_rows) != 1:
                raise Phase2Hold("NO_UNIQUE_DEFAULT_EDGE")
            source, source_port = source_rows[0]
            if _setting(db, "dns_current_ip") != source:
                blockers.append("PUBLIC_DNS_NOT_SOURCE")
            if _setting(db, "edge_egress_protected_mode") != "1":
                blockers.append("PROTECTED_MODE_REQUIRED")
            if _setting(db, OPERATOR_SETTING, "0") != "1":
                blockers.append("OPERATOR_RELEASE_DISABLED")
            allocations = db.execute(
                "SELECT edge_public_ipv4,core_public_ipv4,status "
                "FROM edge_egress_allocations WHERE edge_id=?", (edge_id,)
            ).fetchall()
            if len(allocations) != 1 or allocations[0][2] != "STAGED":
                raise Phase2Hold("F3_EDGE_ALLOCATION_REQUIRED")
            target = allocations[0][0]
            if (str(IPv4Address(source)) != source or
                    not IPv4Address(source).is_global or
                    str(IPv4Address(target)) != target or
                    not IPv4Address(target).is_global or source == target):
                raise Phase2Hold("SOURCE_TARGET_INVALID")
            if db.execute(
                "SELECT 1 FROM failover_operations WHERE status='RUNNING' LIMIT 1"
            ).fetchone():
                blockers.append("SHARED_6G_OPERATION_BUSY")
            if not admission_eligible(read_readiness(db, edge_id), now=clock):
                blockers.append("F4_LIVE_ACCEPTANCE_REQUIRED")
            ready = read_readiness(db, edge_id)
            f4_marker = (ready.witness, ready.probed_at, ready.expires_at,
                         ready.observed_ipv4) if ready else ()
            pin = pin_loader(edge_id)
            if pin.edge_id != edge_id or pin.edge_ipv4 != target or pin.core_ipv4 != allocations[0][1]:
                blockers.append("ORIGINAL_STAGE_IDENTITY_DRIFT")
            pin_hash = _fingerprint((pin.core_sha,pin.edge_sha,pin.ssh_host_key,pin.ssh_port,pin.customer_port, getattr(pin,"core_wg_pub",""),getattr(pin,"edge_wg_pub","")))
            target_pool = db.execute(
                "SELECT active,is_default,is_standby,service_port FROM host_pool WHERE host=?",
                (target,)
            ).fetchone()
            if target_pool is None:
                if pin.customer_port != source_port:
                    blockers.append("NEW_EDGE_SERVICE_PORT_NOT_PINNED")
            elif tuple(target_pool) != (1,0,1,source_port):
                blockers.append("TARGET_POOL_NOT_SAFE_STANDBY")
            rows = db.execute(
                "SELECT username,host FROM ssh_accounts "
                "WHERE service_type='ssh' AND status LIKE '%فعال%' "
                "AND status NOT LIKE '%غیر%' ORDER BY username"
            ).fetchall()
            if not rows:
                blockers.append("NO_ACTIVE_SSH_USERS")
            if any(host not in (source, "", None) for _,host in rows):
                blockers.append("SOME_USERS_ON_ANOTHER_EDGE")
            # Include the source Edge identity, not just a coincidentally
            # matching public IPv4. A changed Edge ID cannot inherit another
            # user's protected policy or be hidden by the ticket fingerprint.
            runtime = db.execute(
                "SELECT username,uid,edge_id,edge_ipv4,state "
                "FROM edge_egress_uid_runtime ORDER BY username"
            ).fetchall()
            binding = db.execute(
                "SELECT username,uid,edge_id,edge_ipv4,status "
                "FROM edge_egress_uid_bindings ORDER BY username"
            ).fetchall()
            # Existing protected users must belong to the unique source
            # allocation, not merely share its apparent public IP.
            source_allocations = db.execute(
                "SELECT edge_id,core_public_ipv4 FROM edge_egress_allocations "
                "WHERE edge_public_ipv4=?", (source,)
            ).fetchall()
            source_edge_id = (source_allocations[0][0]
                              if len(source_allocations) == 1
                              and source_allocations[0][1] == allocations[0][1]
                              else None)
            if source_edge_id is None:
                blockers.append("SOURCE_PROTECTED_EDGE_UNVERIFIED")
            owners = []
            for name,host in rows:
                rr = next((r for r in runtime if r[0] == name), None)
                bb = next((r for r in binding if r[0] == name), None)
                try:
                    valid = bool(
                        rr and bb and rr[1] == bb[1] == os_uid(name)
                        and source_edge_id is not None
                        and rr[2] == bb[2] == source_edge_id
                        and rr[3:] == (source, "PROTECTED")
                        and bb[3:] == (source, "PROTECTED")
                    )
                except (KeyError, OSError, ValueError, TypeError):
                    valid = False
                if not valid:
                    owners.append(name)
            if owners or len(runtime) != len(rows) or len(binding) != len(rows):
                blockers.append("MIXED_OR_UNPROTECTED_COHORT")
            accounts = tuple((r[0],r[1]) for r in rows)
            # A trusted H root registry is necessary for protected login
            # admission at the destination; a host_pool row alone is not.
            registry = [p for p in load_registry()
                        if p.edge_id == edge_id and p.edge_ipv4 == target]
            if len(registry) != 1 or registry[0].ingress_ipv4 != pin.ingress_ipv4:
                blockers.append("TARGET_INGRESS_IDENTITY_MISSING")
    except (OSError,ValueError,sqlite3.Error,TypeError) as exc:
        # No action can be authorized from a partial or ambiguous snapshot.
        if not isinstance(exc, Phase2Hold):
            raise Phase2Hold("COHORT_EVIDENCE_UNAVAILABLE") from exc
        raise
    fingerprint = _fingerprint((
        edge_id,source,target,accounts,tuple(runtime),tuple(binding),
        pin_hash,f4_marker,
    ))
    return RelayCohortReview(
        edge_id,source,target,len(accounts),len(owners),
        tuple(dict.fromkeys(blockers)),fingerprint,
    )


@dataclass(frozen=True)
class _Phase1Remote:
    """Reuses Phase1 host-key/Stage-pinned SSH without a parallel executor."""
    pin: object

    @property
    def ipv4(self): return self.pin.edge_ipv4

    @property
    def remote_stage(self): return Path("/root/nvl-egress-v1") / ("edge-"+self.pin.edge_id)

    def transport(self, action: str):
        return _remote_transport(self.pin, action)


def _dns_hash(plan) -> str:
    return _fingerprint(asdict(plan))


def make_switch_ticket(review: RelayCohortReview, *, actor_id: int,
                       chat_id: int, cf_config_loader: Callable,
                       now: int | None = None) -> RelaySwitchTicket:
    if (not isinstance(review, RelayCohortReview) or not review.ready or
            type(actor_id) is not int or actor_id <= 0 or
            type(chat_id) is not int or chat_id == 0):
        raise Phase2Hold("OPERATOR_REVIEW_NOT_READY")
    plan = ProtectedCloudflareDNS(cf_config_loader).preview_edge_to_edge(
        review.source, review.target
    )
    clock = int(time.time()) if now is None else now
    return RelaySwitchTicket(
        review.edge_id,review.source,review.target,
        review.fingerprint,_dns_hash(plan),
        secrets.token_hex(16),actor_id,chat_id,clock+TTL_SECONDS,
    )


async def execute_relay_switch(ticket: RelaySwitchTicket, *,
                               db_conn: Callable, acquire: Callable,
                               journal: Callable, cf_config_loader: Callable,
                               actor_id: int, chat_id: int,
                               getuid: Callable = os.geteuid,
                               now: Callable = time.time) -> object:
    """One-shot bot confirmation into the EXISTING guarded 6G saga.

    Caller consumes its Telegram ticket before awaiting this function. This
    function still re-reads source/user/F4/SSH pins and immutable Cloudflare
    record identities before constructing the root-only live host driver.
    """
    if (not isinstance(ticket, RelaySwitchTicket) or
            type(actor_id) is not int or type(chat_id) is not int or
            actor_id != ticket.actor_id or chat_id != ticket.chat_id or
            getuid() != 0 or now() >= ticket.expires_at or
            not isinstance(ticket.nonce,str) or
            not __import__("re").fullmatch(r"[a-f0-9]{32}",ticket.nonce)):
        raise Phase2Hold("EXPIRED_UNAUTHORIZED_OR_UNPRIVILEGED")
    current = await asyncio.to_thread(
        review_relay_cohort, db_conn, ticket.edge_id
    )
    if (not current.ready or current.source != ticket.source or
            current.target != ticket.target or
            not compare_digest(current.fingerprint,ticket.cohort_fingerprint)):
        raise Phase2Hold("COHORT_OR_F4_DRIFT")
    cf = ProtectedCloudflareDNS(cf_config_loader)
    dns = await asyncio.to_thread(
        cf.preview_edge_to_edge, ticket.source, ticket.target
    )
    if not compare_digest(_dns_hash(dns),ticket.dns_fingerprint):
        raise Phase2Hold("PUBLIC_DNS_PREVIEW_CHANGED")
    pin = await asyncio.to_thread(load_stage_pin,ticket.edge_id)
    await asyncio.to_thread(_check_stage,pin)
    from ops.edge_egress_v1_transport import pinned,observe
    core_stage=Path("/root/nvl-egress-v1")/("core-"+pin.edge_id)
    spec,peer=await asyncio.to_thread(pinned,core_stage,"core",pin.core_sha)
    if (spec.edge_public_ipv4 != ticket.target or
            await asyncio.to_thread(observe,spec,"core",peer) != "UP" or
            await asyncio.to_thread(_remote_transport,pin,"inspect") != "UP"):
        raise Phase2Hold("PINNED_CORE_EDGE_TRANSPORT_NOT_UP")
    # Protect all users before DNS mutation; the existing K driver enforces
    # F4, full roster, PAM, terminal UID DENY and per-user packet proof.
    config=LiveDriverConfig(
        core_stage=core_stage,core_digest=pin.core_sha,
        edge=_Phase1Remote(pin),acceptance_enabled=True,
        dns_plan=dns,
    )
    adapter=make_live_adapter(
        config=config,db_conn=db_conn,acquire_fn=acquire,
        journal_fn=journal,core_ip=pin.core_ipv4,
        cf_config_loader=cf_config_loader,
    )
    return await execute_protected_switch(adapter,ticket.source,ticket.target)


def render_cohort_review(review: RelayCohortReview) -> str:
    from html import escape
    reasons = {
        "PUBLIC_DNS_NOT_SOURCE": "نشانی دامنه با رله فعلی همخوان نیست",
        "PROTECTED_MODE_REQUIRED": "محافظت خروجی حساب‌ها فعال نیست",
        "OPERATOR_RELEASE_DISABLED": "مجوز اجرای انتقال در سرور فعال نشده",
        "SHARED_6G_OPERATION_BUSY": "عملیات دیگری در جریان است",
        "F4_LIVE_ACCEPTANCE_REQUIRED": "تأیید نهایی ایمنی سرور جدید موجود نیست",
        "ORIGINAL_STAGE_IDENTITY_DRIFT": "هویت سرور جدید ناسازگار است",
        "NEW_EDGE_SERVICE_PORT_NOT_PINNED": "درگاه سرویس سرور جدید تأیید نشده",
        "TARGET_POOL_NOT_SAFE_STANDBY": "وضعیت سرور مقصد نیازمند بررسی است",
        "NO_ACTIVE_SSH_USERS": "کاربری برای انتقال وجود ندارد",
        "SOME_USERS_ON_ANOTHER_EDGE": "برخی کاربران از رله دیگری استفاده می‌کنند",
        "SOURCE_PROTECTED_EDGE_UNVERIFIED": "هویت خروجی محافظت‌شده سرور فعلی معتبر نیست",
        "MIXED_OR_UNPROTECTED_COHORT": "بعضی کاربران هنوز خروجی محافظت‌شده ندارند",
        "TARGET_INGRESS_IDENTITY_MISSING": "مسیر ورودی مقصد تأیید نشده",
    }
    body=[
        "🔀 <b>تغییر رله ترافیک</b>", "",
        "رله فعلی: <code>"+escape(review.source,quote=True)+"</code>",
        "رله جدید: <code>"+escape(review.target,quote=True)+"</code>",
        f"حساب‌های SSH فعال: <b>{review.active_accounts}</b>", "",
    ]
    if review.ready:
        body.extend((
            "✅ بررسی اولیه موفق بود.",
            "🔒 انتقال فقط با تأیید نهایی و آزمایش مجدد انجام می‌شود.",
            "حساب‌ها روی Core باقی می‌مانند؛ مسیر اینترنت آن‌ها تغییر می‌کند.",
        ))
    else:
        body.extend(("⛔️ <b>انتقال فعلاً مجاز نیست.</b>",))
        for key in review.blockers:
            body.append("• "+escape(reasons.get(key,"نیاز به بررسی ایمنی سرور"),quote=True))
        body.append("هیچ مسیر، DNS یا حسابی تغییر نکرده است.")
    return "\n".join(body)


def relay_cohort_buttons(review: RelayCohortReview) -> list[list[tuple[str,str]]]:
    from edge_egress_v1_console import edge_id_checked
    eid=edge_id_checked(review.edge_id)
    rows=[]
    if review.ready:
        rows.append([("✅ بررسی نهایی انتقال",f"hpeg_p2_open_{eid}")])
    rows.extend((
        [("🔄 بروزرسانی",f"hpeg_relay_{eid}"),
         ("👥 جزئیات کاربران",f"hpeg_transfer_{eid}")],
        [("◀️ جزئیات سرور",f"hpeg_edge_{eid}")],
    ))
    return rows
