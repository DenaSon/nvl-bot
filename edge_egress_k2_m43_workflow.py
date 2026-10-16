"""M4.3 Telegram-side ephemeral 2-step approval context; no root secrets.

Only server-issued opaque request_id is kept, exclusively in process-local
conversation state. Telegram callback_data includes action + Edge only.
One-shot consumption precedes any network I/O. Root independently binds
actor/chat/plan, confirms current admin role, F4 and original 6G.
"""
from __future__ import annotations

from dataclasses import dataclass
from html import escape
import re
import time

from edge_egress_k2_migration_inventory import MigrationSelection,select_migration
from edge_egress_k2_m43_client import M43ClientHold

_EDGE=re.compile(r"[a-z][a-z0-9_-]{1,23}\Z")
_REQUEST=re.compile(r"[0-9a-f]{32}\Z")


@dataclass(frozen=True)
class PendingTelegramApproval:
    actor_id: int
    chat_id: int
    message_id: int
    selection: MigrationSelection
    request_id: str
    expires_at: int
    activate_relay: bool = False

    @classmethod
    def create(cls, *, selection: MigrationSelection, actor_id: int,
               chat_id: int, message_id: int, result: dict,
               now: int | None = None, activate_relay: bool = False):
        stamp=int(time.time()) if now is None else now
        if (type(activate_relay) is not bool or not isinstance(selection,MigrationSelection)
            or select_migration(selection.mode,selection.usernames,
                                selection.target_edge_id)!=selection
            or type(actor_id) is not int or actor_id<=0
            or type(chat_id) is not int or chat_id==0
            or type(message_id) is not int or message_id<=0
            or not isinstance(result,dict)
            or set(result)!={"state","request_id","edge_id","user_count","expires_at"}
            or result["state"]!="PREPARED"
            or type(result["request_id"]) is not str
            or not _REQUEST.fullmatch(result["request_id"])
            or result["edge_id"]!=selection.target_edge_id
            or type(result["user_count"]) is not int
            or result["user_count"]!=len(selection.usernames)
            or type(result["expires_at"]) is not int
            or not stamp < result["expires_at"] <= stamp+90):
            raise M43ClientHold("M43_APPROVAL_SCOPE_NOT_VERIFIED")
        return cls(actor_id,chat_id,message_id,selection,result["request_id"],
                   result["expires_at"],activate_relay)

    def check(self, *, actor_id:int, chat_id:int, message_id:int,
              edge_id:str, now:int|None=None) -> None:
        stamp=int(time.time()) if now is None else now
        if (type(actor_id) is not int or type(chat_id) is not int
            or type(message_id) is not int
            or (actor_id,chat_id,message_id)!=(self.actor_id,self.chat_id,self.message_id)
            or edge_id!=self.selection.target_edge_id
            or stamp>=self.expires_at
            or select_migration(self.selection.mode,self.selection.usernames,
                                self.selection.target_edge_id)!=self.selection):
            raise M43ClientHold("M43_CONFIRMATION_EXPIRED_OR_CHANGED")


def confirmation_html(pending: PendingTelegramApproval) -> str:
    if not isinstance(pending,PendingTelegramApproval):
        raise M43ClientHold("M43_APPROVAL_MISSING")
    lines=[("⭐ <b>تأیید خروجی فعال</b>" if pending.activate_relay else "🔐 <b>تأیید انتقال</b>"),"",
           f"مقصد: <code>{escape(pending.selection.target_edge_id)}</code>",
           f"تعداد حساب: <b>{len(pending.selection.usernames)}</b>",""]
    lines.extend("• <code>"+escape(name)+"</code>"
                 for name in pending.selection.usernames[:10])
    if len(pending.selection.usernames)>10:
        lines.append(f"و {len(pending.selection.usernames)-10} حساب دیگر")
    lines.extend(("", "با تأیید، انتقال و بررسی نهایی آغاز می‌شود.",
                  "اگر شرایط تغییر کند، ادامهٔ عملیات متوقف می‌شود.",
                  "💡 حساب روی سرور مرکزی می‌ماند؛ IP خروجی از مقصد انتخابی خواهد بود.",
                  "این تأیید ۹۰ ثانیه اعتبار دارد."))
    if pending.activate_relay:
        lines.append("خروجی فعال فقط پس از تأیید همهٔ حساب‌های فعال ثبت می‌شود.")
    return "\n".join(lines)


def confirmation_buttons(edge_id: str):
    if not isinstance(edge_id,str) or not _EDGE.fullmatch(edge_id):
        raise M43ClientHold("M43_EDGE_INVALID")
    return [
        [("✅ تأیید انتقال",f"hpeg_m4_confirm_{edge_id}")],
        [("❌ انصراف",f"hpeg_m4_abort_{edge_id}")],
    ]


def result_html(result: dict, *, selection: MigrationSelection) -> str:
    if not isinstance(result,dict) or not isinstance(selection,MigrationSelection):
        raise M43ClientHold("M43_RESULT_INVALID")
    if result.get("state") not in ("COMPLETED","HOLD"):
        raise M43ClientHold("M43_RESULT_UNKNOWN")
    entries=result.get("accounts")
    if not isinstance(entries,list) or len(entries)!=len(selection.usernames):
        raise M43ClientHold("M43_RESULT_ACCOUNTS_INVALID")
    if any(not isinstance(item,dict) for item in entries):
        raise M43ClientHold("M43_RESULT_ACCOUNTS_INVALID")
    if tuple(item.get("username") for item in entries)!=selection.usernames:
        raise M43ClientHold("M43_RESULT_ACCOUNT_ORDER_DRIFT")
    if (any(not isinstance(item,dict) or item.get('state') not in
            ('VERIFIED','HOLD','DEFERRED') for item in entries)
        or result['state']=='COMPLETED' and any(item['state']!='VERIFIED' for item in entries)
        or result.get('relay_state') not in (None,'VERIFIED','HOLD')):
        raise M43ClientHold('M43_RESULT_INCONSISTENT')
    state=result["state"]
    marker_only=result.get("relay_state")=="VERIFIED" and result.get("completed")==0
    lines=[("✅ <b>خروجی فعال ثبت شد</b>" if marker_only else "✅ <b>انتقال تکمیل شد</b>" if state=="COMPLETED"
            else "⛔️ <b>انتقال متوقف شد</b>"),"",
           f"مقصد: <code>{escape(selection.target_edge_id)}</code>"]
    verified=sum(e.get("state")=="VERIFIED" for e in entries)
    deferred=sum(e.get("state")=="DEFERRED" for e in entries)
    lines.append(f"تأییدشده: {verified} · انجام‌نشده: {deferred} · نیازمند بررسی: {len(entries)-verified-deferred}")
    for item in entries[:10]:
        status=item.get("state")
        lines.append(("✅" if status=="VERIFIED" else "⚪️" if status=="DEFERRED" else "⛔️")
                     +f" <code>{escape(item['username'])}</code>"
                     +(" — تأیید شد" if status=="VERIFIED" else " — انجام نشد" if status=="DEFERRED" else " — نیازمند بررسی"))
    if len(entries)>10:
        count=sum(e.get('state')=='VERIFIED' for e in entries)
        lines.append(f"نتیجه کل: {count} تأییدشده از {len(entries)} حساب")
    if state=="HOLD":
        lines.extend(("","برای ادامه، وضعیت کاربران را بررسی کنید؛"
                      " اجرای خودکار مجدد انجام نمی‌شود."))
    if result.get('relay_state')=='VERIFIED':
        lines.extend(('','✅ خروجی فعال روی سرور انتخابی تأیید شد.'))
    elif result.get('relay_state')=='HOLD':
        lines.extend(('','⛔️ انتخاب خروجی فعال کامل نشد؛ وضعیت تمام حساب‌ها باید تأیید شود.'))
    return "\n".join(lines)


def halted_html() -> str:
    return ("⛔️ <b>وضعیت انتقال نامشخص است</b>\n\n"
            "هیچ درخواست مجددی ارسال نمی‌شود. ابتدا وضعیت انتقال را بررسی کنید.")


def cancel_html() -> str:
    return "❌ درخواست انتقال لغو شد. تغییری اجرا نشد."


class EphemeralApprovalStore:
    """In-memory ONLY, never PTB context.user_data/Pickle/DB.

    Serializes duplicate PREPARE for one actor/chat and consumes a matching
    confirmation in the event-loop turn before any awaited socket I/O.
    """

    def __init__(self):
        self._pending: dict[tuple[int,int],PendingTelegramApproval]={}
        self._busy: set[tuple[int,int]]=set()
        self._generation: dict[tuple[int,int],int]={}

    def discard(self, actor_id: int, chat_id: int) -> None:
        key=(actor_id,chat_id)
        self._pending.pop(key,None)
        self._generation[key]=self._generation.get(key,0)+1
        # Deliberately keep an in-flight PREPARE reservation until it ends.

    def begin(self, actor_id: int, chat_id: int) -> int:
        key=(actor_id,chat_id)
        if key in self._busy:
            raise M43ClientHold("M43_PREPARE_ALREADY_IN_PROGRESS")
        self._busy.add(key)
        self._pending.pop(key,None)
        self._generation[key]=self._generation.get(key,0)+1
        return self._generation[key]

    def finish(self, pending: PendingTelegramApproval, epoch: int) -> None:
        key=(pending.actor_id,pending.chat_id)
        if key not in self._busy:
            raise M43ClientHold("M43_PREPARE_NOT_RESERVED")
        self._busy.remove(key)
        if type(epoch) is not int or self._generation.get(key)!=epoch:
            raise M43ClientHold("M43_PREPARE_INVALIDATED_BY_NAVIGATION")
        self._pending[key]=pending

    def release(self, actor_id: int, chat_id: int) -> None:
        self._busy.discard((actor_id,chat_id))

    def consume(self, *, actor_id: int, chat_id: int, message_id: int,
                edge_id: str, now: int|None = None) -> PendingTelegramApproval:
        key=(actor_id,chat_id)
        pending=self._pending.get(key)
        if not isinstance(pending,PendingTelegramApproval):
            raise M43ClientHold("M43_PENDING_NOT_IN_MEMORY")
        pending.check(actor_id=actor_id,chat_id=chat_id,
                      message_id=message_id,edge_id=edge_id,now=now)
        # Pop synchronously BEFORE the awaited IPC request.
        self._pending.pop(key,None)
        return pending


# Module-global, purposefully not stored on the persistent Telegram context.
APPROVALS=EphemeralApprovalStore()
