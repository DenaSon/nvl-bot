"""K2 P3 VPS rehearsal dashboard: zero-write snapshot for the EXISTING bot.

Never activates Core/Edge transport, issues tickets, mints F4 READY or makes
an execution-capable decision. A stage-only Edge IP probe is a DIFFERENT,
already-implemented, admin-protected action in the existing Telegram bot.
"""
from __future__ import annotations

from dataclasses import dataclass
from html import escape
from ipaddress import IPv4Address
import sqlite3
from typing import Callable

from edge_egress_f3_readiness import admission_eligible, read_readiness
from edge_egress_phase2_console import Dashboard, EdgeCard, get_card, read_dashboard
from edge_egress_v1_console import edge_id_checked


class LabReviewHold(ValueError):
    pass


@dataclass(frozen=True)
class K2LabReview:
    edge_id: str
    target_ipv4: str
    source_ipv4: str
    legacy_count: int
    protected_count: int
    inconsistent_count: int
    other_edge_count: int
    active_total: int
    staged: bool
    pinned: bool
    ingress_verified: bool
    source_f4: bool
    target_f4: bool
    shared_6g_idle: bool
    stage_trial_eligible: bool
    blockers: tuple[str, ...]
    customer_ready: bool = False
    can_execute: bool = False


def _ipv4(value: object) -> bool:
    try:
        return isinstance(value,str) and str(IPv4Address(value)) == value and IPv4Address(value).is_global
    except (TypeError,ValueError):
        return False


def review_vps_lab(
    db_conn: Callable, edge_id: str, *,
    dashboard_reader: Callable = read_dashboard,
) -> K2LabReview:
    """Uses only the existing 6G, F2/F3/F4, host/SSH records. No OS probes."""
    eid=edge_id_checked(edge_id)
    try:
        board=dashboard_reader(db_conn,only_edge=eid)
        if not isinstance(board,Dashboard):
            raise LabReviewHold("DASHBOARD_NOT_TRUSTED")
        card=get_card(board,eid)
        if not isinstance(card,EdgeCard) or not _ipv4(card.ip):
            raise LabReviewHold("TARGET_IDENTITY_NOT_ATTESTED")
        source=board.default_ip
        if not _ipv4(source) or not _ipv4(board.dns_ip):
            raise LabReviewHold("SOURCE_IDENTITY_NOT_ATTESTED")
        blockers=[]
        if source==card.ip or card.pool_default or card.dns_target:
            blockers.append("TARGET_IS_CURRENT_SOURCE")
        if board.dns_ip != source:
            blockers.append("PUBLIC_DNS_NOT_CURRENT_SOURCE")
        if not card.ingress_verified or not board.registry_trusted:
            blockers.append("TARGET_INGRESS_UNVERIFIED")
        if card.allocation!="STAGED":
            blockers.append("TARGET_F3_NOT_STAGED")
        if card.stage_pin is None:
            blockers.append("TARGET_STAGE_SHA_NOT_PINNED")
        with db_conn() as db:
            busy=db.execute(
                "SELECT 1 FROM failover_operations WHERE status='RUNNING' LIMIT 1"
            ).fetchone() is not None
            if busy:
                blockers.append("SHARED_6G_BUSY")
            sources=db.execute(
                "SELECT host FROM host_pool WHERE active=1 AND is_default=1"
            ).fetchall()
            if len(sources)!=1 or sources[0]!=(source,):
                blockers.append("SOURCE_NOT_UNIQUE")
            allocations=db.execute(
                "SELECT edge_id,edge_public_ipv4,core_public_ipv4,status "
                "FROM edge_egress_allocations ORDER BY edge_id"
            ).fetchall()
            match_target=[a for a in allocations if a[0]==eid and a[1]==card.ip and a[3]=="STAGED"]
            match_source=[a for a in allocations if a[1]==source and a[3]=="STAGED"]
            if len(match_target)!=1:
                blockers.append("TARGET_F3_IDENTITY_UNVERIFIED")
            if len(match_source)!=1 or (len(match_target)==1 and match_source[0][2]!=match_target[0][2]):
                blockers.append("SOURCE_F3_IDENTITY_UNVERIFIED")
            s_eid=match_source[0][0] if len(match_source)==1 else ""
            if len([a for a in allocations if a[1] in (source,card.ip)])!=2:
                blockers.append("SOURCE_TARGET_ALLOCATION_COLLISION")
            s_f4=read_readiness(db,s_eid) if s_eid else None
            t_f4=read_readiness(db,eid)
            source_ready=bool(s_f4 and s_f4.edge_ipv4==source and admission_eligible(s_f4))
            target_ready=bool(t_f4 and t_f4.edge_ipv4==card.ip and admission_eligible(t_f4))
            accounts=db.execute(
                "SELECT username,host FROM ssh_accounts "
                "WHERE service_type='ssh' AND status LIKE '%فعال%' "
                "AND status NOT LIKE '%غیر%' ORDER BY username"
            ).fetchall()
            rt=db.execute(
                "SELECT username,uid,edge_id,edge_ipv4,state "
                "FROM edge_egress_uid_runtime"
            ).fetchall()
            bm=db.execute(
                "SELECT username,uid,edge_id,edge_ipv4,status "
                "FROM edge_egress_uid_bindings"
            ).fetchall()
            runtimes={r[0]:r for r in rt}
            bindings={r[0]:r for r in bm}
            active={name for name,_ in accounts}
            legacy=protected=invalid=other=0
            for name,host in accounts:
                if host not in (source,"",None):
                    other+=1
                    continue
                r,b=runtimes.get(name),bindings.get(name)
                if r is None and b is None:
                    legacy+=1
                elif (r is not None and b is not None
                      and type(r[1]) is int and r[1]>=1000
                      and r[1]==b[1] and r[2:]==(s_eid,source,"PROTECTED")
                      and b[2:]==(s_eid,source,"PROTECTED")):
                    protected+=1
                else:
                    invalid+=1
            if len(rt)!=len(set(r[0] for r in rt)) or len(bm)!=len(set(r[0] for r in bm)):
                blockers.append("DUPLICATED_PROTECTED_IDENTITIES")
            if any(r[0] not in active for r in rt+bm):
                blockers.append("ORPHAN_PROTECTED_INTENTS")
            if other or invalid:
                blockers.append("ACCOUNT_INGRESS_OR_PROTECTION_INCONSISTENT")
            mode=db.execute(
                "SELECT value FROM settings WHERE key='edge_egress_protected_mode'"
            ).fetchone()
            if mode not in (("0",),("1",)):
                blockers.append("GLOBAL_MODE_UNTRUSTED")
            if mode==("1",) and (legacy or other or invalid):
                blockers.append("GLOBAL_PROTECTED_MODE_WITH_UNPROTECTED_USERS")
        trial=bool(not busy and card.allocation=="STAGED"
                   and card.stage_pin is not None and card.ingress_verified
                   and board.registry_trusted and source!=card.ip
                   and board.dns_ip==source and len(sources)==1
                   and len(match_target)==1
                   and len(match_source)==1
                   and not any(b in blockers for b in (
                       "SOURCE_TARGET_ALLOCATION_COLLISION",
                       "SOURCE_F3_IDENTITY_UNVERIFIED",
                       "TARGET_F3_IDENTITY_UNVERIFIED",
                       "GLOBAL_MODE_UNTRUSTED",
                   )))
        # This is never an F4 witness. 'trial' only means the operator may
        # navigate to the existing stage-only namespace IP probe.
        return K2LabReview(
            eid,card.ip,source,legacy,protected,invalid,other,len(accounts),
            card.allocation=="STAGED",card.stage_pin is not None,
            card.ingress_verified,source_ready,target_ready,not busy,trial,
            tuple(dict.fromkeys(blockers)),
        )
    except LabReviewHold:
        raise
    except (sqlite3.Error,OSError,ValueError,TypeError,KeyError,IndexError,AttributeError) as exc:
        raise LabReviewHold("LAB_INVENTORY_NOT_TRUSTED") from exc


def lab_html(review: K2LabReview) -> str:
    """Minimal Persian operator UX. Never expose privileged command details."""
    if not isinstance(review,K2LabReview):
        raise LabReviewHold("LAB_REVIEW_REQUIRED")
    def yn(p): return "✅" if p else "⛔"
    body=[
        "🧪 <b>آزمایش سرور جدید</b>","",
        f"🖥 سرور: <code>{escape(review.edge_id,quote=True)}</code>",
        f"🌐 IP هدف: <code>{escape(review.target_ipv4,quote=True)}</code>","",
        f"📦 آماده‌سازی: {yn(review.staged and review.pinned)}",
        f"📥 ورودی سرور: {yn(review.ingress_verified)}",
        f"🔒 نبود عملیات هم‌زمان: {yn(review.shared_6g_idle)}",
        f"👥 کاربران روی سرور فعلی: <b>{review.active_total-review.other_edge_count}</b>",
        f"محافظت‌شده: <b>{review.protected_count}</b> · قدیمی: <b>{review.legacy_count}</b>",
    ]
    if review.inconsistent_count or review.other_edge_count:
        body.append(f"نیازمند بررسی: <b>{review.inconsistent_count+review.other_edge_count}</b>")
    body.extend(("",
        "۱. ابتدا اتصال و IP خروجی سرور را آزمایش کنید.",
        "۲. سپس وضعیت کاربران و محافظت مسیر را بررسی کنید.",
        "۳. آزمون واقعی SSH و عدم نشت IP نیازمند VPS آزمایشی است.",
        "",
        "🟡 تأیید نهایی ایمنی هنوز انجام نشده است." if not review.target_f4
        else "✅ شاهد سرور ثبت شده؛ تست واقعی کاربران همچنان مستقل است.",
        "🔒 هیچ حسابی جابه‌جا یا تغییری داده نمی‌شود.",
    ))
    if not review.stage_trial_eligible:
        body.append("⛔ تست اولیه اتصال فعلاً مجاز نیست.")
    return "\n".join(body)


def lab_buttons(review: K2LabReview) -> list[list[tuple[str,str]]]:
    if not isinstance(review,K2LabReview):
        raise LabReviewHold("LAB_REVIEW_REQUIRED")
    eid=edge_id_checked(review.edge_id)
    buttons=[]
    if review.stage_trial_eligible:
        buttons.append([("🌍 تست IP سرور",f"hpeg_p1_probe_{eid}")])
    buttons.extend([
        [("👤 بررسی کاربر",f"hpeg_user_{eid}"),
         ("🔀 بررسی انتقال",f"hpeg_relay_{eid}")],
        [("🔄 بروزرسانی",f"hpeg_lab_{eid}"),
         ("◀️ جزئیات سرور",f"hpeg_edge_{eid}")],
    ])
    return buttons
