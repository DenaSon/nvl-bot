"""M4 read-only Telegram wave status and restart-safe 6G HOLD view.

This projects the existing ORIGINAL 6G and UID binding tables; it never
marks customer routing as verified solely from DB metadata. No second
operation authority, unlock, retry, reconciliation or route write.
"""
from __future__ import annotations

from dataclasses import dataclass
from html import escape
from typing import Callable
import sqlite3

from edge_egress_k2_migration_inventory import (
    MigrationSelection,select_migration,
)


class M4StatusHold(ValueError):
    pass


@dataclass(frozen=True)
class M4UserStatus:
    username: str
    state: str  # REGISTERED, FROZEN, HOLD, NOT_STARTED


@dataclass(frozen=True)
class M4WaveStatus:
    edge_id: str
    global_busy: bool
    accounts: tuple[M4UserStatus,...]
    verified_runtime: bool = False  # DB is NEVER an independent packet proof


def inspect_telegram_wave_status(
    db_conn: Callable, selection: MigrationSelection,
) -> M4WaveStatus:
    if not isinstance(selection,MigrationSelection) or not callable(db_conn):
        raise M4StatusHold("WAVE_STATUS_SCOPE_INVALID")
    if select_migration(selection.mode,selection.usernames,
                        selection.target_edge_id)!=selection:
        raise M4StatusHold("WAVE_STATUS_SELECTION_MUTATED")
    if len(selection.usernames)>10:
        raise M4StatusHold("WAVE_STATUS_SELECTION_TOO_LARGE")
    try:
        with db_conn() as conn:
            running=conn.execute(
                "SELECT COUNT(*) FROM failover_operations "
                "WHERE status='RUNNING'"
            ).fetchone()
            if not running or type(running[0]) is not int:
                raise M4StatusHold("ORIGINAL_6G_UNKNOWN")
            accounts=[]
            for name in selection.usernames:
                rr=conn.execute(
                    "SELECT uid,edge_id,edge_ipv4,state "
                    "FROM edge_egress_uid_runtime WHERE username=?", (name,),
                ).fetchall()
                bb=conn.execute(
                    "SELECT uid,edge_id,edge_ipv4,status "
                    "FROM edge_egress_uid_bindings WHERE username=?", (name,),
                ).fetchall()
                if not rr and not bb:
                    state="NOT_STARTED"
                elif len(rr)==1 and len(bb)==1 and (
                    rr[0][:3]==bb[0][:3] and
                    rr[0][1]==selection.target_edge_id and
                    rr[0][3]=="PROTECTED" and bb[0][3]=="PROTECTED"
                ):
                    state="REGISTERED"
                elif len(rr)==1 and rr[0][3] in ("BLOCKED","FROZEN"):
                    state="FROZEN"
                else:
                    state="HOLD"
                accounts.append(M4UserStatus(name,state))
            return M4WaveStatus(
                selection.target_edge_id,running[0]>0,tuple(accounts))
    except (sqlite3.Error,ValueError,TypeError,KeyError,OSError) as exc:
        raise M4StatusHold("WAVE_STATUS_READONLY_UNAVAILABLE") from exc


def status_html(s: M4WaveStatus) -> str:
    if not isinstance(s,M4WaveStatus):
        raise M4StatusHold("STATUS_REQUIRED")
    lines=["📋 <b>وضعیت انتقال</b>","",
           f"سرور: <code>{escape(s.edge_id)}</code>"]
    if s.global_busy:
        lines.extend(("⏳ یک عملیات در جریان است. برای جلوگیری از تداخل، "
                      "انتقال جدید متوقف می‌ماند.",""))
    else:
        lines.append("")
    labels={
        "NOT_STARTED":"⚪️ هنوز شروع نشده",
        "REGISTERED":"🟡 مسیر ثبت شده؛ اتصال باید تأیید شود",
        "FROZEN":"⛔️ متوقف و محافظت‌شده",
        "HOLD":"⛔️ نیازمند بررسی",
    }
    for user in s.accounts:
        if user.state not in labels:
            raise M4StatusHold("UNKNOWN_RUNTIME_STATE")
        lines.append(
            f"<code>{escape(user.username)}</code> — {labels[user.state]}"
        )
    lines.extend(("","این گزارش وضعیت ثبت‌شده است، "
                  "نه تأیید اتصال واقعی کاربر."))
    return "\n".join(lines)


def root_checkpoint_status_html(result: dict, selection: MigrationSelection) -> str:
    """A root-owned *receipt* view, not physical customer egress attestation."""
    if (not isinstance(result,dict) or result.get("state")!="STATUS"
        or not isinstance(selection,MigrationSelection)
        or result.get("edge_id")!=selection.target_edge_id
        or not isinstance(result.get("users"),list)
        or tuple(u.get("username") for u in result["users"]
                 if isinstance(u,dict))!=selection.usernames):
        raise M4StatusHold("ROOT_STATUS_SCOPE_INVALID")
    titles={
        "NO_CHECKPOINT":"⚪️ سابقه تأییدشده‌ای یافت نشد",
        "PREPARED":"🟡 در انتظار تأیید",
        "EXPIRED":"⚪️ درخواست قبلی منقضی شد",
        "UNKNOWN_INFLIGHT":"⏳ عملیات هنوز نتیجهٔ نهایی ندارد",
        "RECEIPTS_RECORDED":"🟡 رسیدهای انتقال ثبت شده‌اند",
        "HOLD":"⛔️ انتقال نیازمند بررسی است",
    }
    labels={
        "UNKNOWN":"⚪️ نامشخص",
        "NOT_STARTED":"⚪️ شروع نشده در این درخواست",
        "RECEIPT_SCOPED":"🟡 رسید اصلی ثبت و تطبیق شد",
        "RECEIPT_UNVERIFIED":"⛔️ رسید نیازمند بررسی است",
        "HOLD":"⛔️ متوقف شده",
        "DEFERRED":"⚪️ انجام نشده؛ پس از توقف باقی ماند",
    }
    state=result.get("wave_state")
    if (state not in titles or type(result.get("busy")) is not bool
        or type(result.get("unresolved")) is not bool):
        raise M4StatusHold("ROOT_STATUS_UNTRUSTED")
    lines=["📋 <b>وضعیت انتقال</b>","",
           "مقصد: <code>"+escape(selection.target_edge_id)+"</code>",
           titles[state],""]
    counts={key:sum(u.get("state")==key for u in result["users"]) for key in labels}
    lines.append(f"نتیجهٔ تطبیق‌داده‌شده: {counts['RECEIPT_SCOPED']} از {len(result['users'])} حساب")
    names=set(selection.usernames)
    for index,item in enumerate(result["users"]):
        name=item.get("username")
        status=item.get("state")
        if name not in names or status not in labels:
            raise M4StatusHold("ROOT_STATUS_USER_UNTRUSTED")
        if index<20:
            lines.append("<code>"+escape(name)+"</code> — "+labels[status])
    if len(result['users'])>20:
        verified=sum(u['state']=='RECEIPT_SCOPED' for u in result['users'])
        lines.append(f"رسید تأییدشده: {verified} از {len(result['users'])} حساب")
    if result["busy"] or result["unresolved"]:
        lines.extend(("","⛔️ حسابِ در حال اجرا را دوباره منتقل نکنید. "
                      "برای توقف، از دکمهٔ توقف استفاده کنید؛ نتیجه را دوباره بررسی کنید."))
    lines.extend(("","این گزارش تنها وضعیت رسیدها و سوابق است؛ "
                  "اتصال واقعی باید جداگانه تأیید شود."))
    return "\n".join(lines)
