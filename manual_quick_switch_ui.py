"""Admin-only Rich UI for Manual Edge Quick Switch.

The Cloudzy engine remains installed; no Cloudzy provider calls are made.
Callbacks never accept an arbitrary account destination or migration status.
"""
from __future__ import annotations

import asyncio
from html import escape
import os
import secrets
import threading
import time

from manual_edge_rich import ManualRichDelivery
from manual_quick_switch import QuickSwitchHold

PENDING_TTL = 180
HISTORICAL_SOURCE = "153.75.87.190"
HISTORICAL_TARGET = "45.59.126.73"

_MESSAGES = {
    "QUICK_ROUTE_UNRESOLVED": "یک انتقال نیمه‌تمام وجود دارد. ابتدا وضعیت و بازیابی را بررسی کنید.",
    "QUICK_SWITCH_NOT_RELEASED": "تغییر IP هنوز برای Production فعال نشده است.",
    "SHARED_6G_BUSY": "یک عملیات مهم دیگر روی مسیر فعال است.",
    "RELEVANT_CZ07_OPERATION": "یک انتقال مرتبط با این مسیر هنوز تعیین‌تکلیف نشده است.",
    "OTHER_DNS_ROUTE_OPERATION": "یک تغییر DNS قبلی هنوز باز است.",
    "SINGLE_HOST_ROUTE_NOT_COHERENT": "اطلاعات مسیر و DNS هماهنگ نیستند.",
    "MANUAL_STANDBY_NOT_READY": "این Edge آماده‌به‌کار و تأییدشده نیست.",
    "TARGET_NETWORK_NOT_VERIFIED": "سلامت SSH، WireGuard یا NAT مقصد تأیید نشد.",
    "DNS_NOT_ON_SOURCE": "DNS عمومی با IP فعلی هماهنگ نیست.",
    "DNS_RETRY_REQUIRES_CONFIRMATION": "DNS هنوز روی مبدأ است. برای تلاش مجدد تأیید جدا لازم است.",
    "DNS_UNCERTAIN_REVIEW_REQUIRED": "نتیجه DNS مشخص نیست؛ عملیات نیازمند بررسی است.",
    "DNS_WRITE_RESULT_UNCERTAIN": "پاسخ Cloudflare نامشخص است؛ درخواست را کورکورانه تکرار نکنید.",
    "ACCOUNT_OR_ROUTE_CHANGED": "حساب‌ها یا مسیر پس از پیش‌نمایش تغییر کرده‌اند.",
    "PREVIEW_CHANGED": "اطلاعات تغییر کرده است؛ پیش‌نمایش تازه بگیرید.",
    "EXTERNAL_ROUTE_UNVERIFIED": "شواهد انتقال اضطراری قبلی کامل نیستند.",
}

def _message(error):
    return _MESSAGES.get(str(error), "بررسی فنی این عملیات ضروری است.")


class ManualQuickSwitchUI:
    def __init__(self, *, engine, db, admin_ids, now=time.time,
                 enabled=None):
        self.enabled = enabled or (
            lambda: os.environ.get("NVL_MANUAL_QUICK_SWITCH_ENABLED","0")=="1")
        self.engine = engine
        self.db = db
        self.admin_ids = admin_ids
        self.now = now
        # Volatile preview; never serialize customer rows into user_data.
        self.pending = {}
        self.running = set()
        self.last_errors = {}
        # The engine runs in a worker thread to avoid blocking Telegram on
        # synchronous Cloudflare HTTP, so serialize effects across actors.
        self.effect_lock = threading.Lock()

    async def _view(self, context, chat, text, rows):
        return await ManualRichDelivery(context.application.bot.token).show(
            chat=chat, context=context, text=text, rows=rows)

    def _inventory(self):
        with self.db() as db:
            current = db.execute(
                "SELECT host FROM host_pool WHERE active=1 AND is_default=1"
            ).fetchall()
            standby = db.execute(
                "SELECT h.host FROM host_pool h "
                "JOIN manual_edge_operations m ON m.ip=h.host "
                "WHERE h.active=1 AND h.is_standby=1 "
                "AND h.is_default=0 AND h.provider='manual' "
                "AND h.provider_instance_id IS NULL "
                "AND m.status='STANDBY' ORDER BY h.host"
            ).fetchall()
            count = db.execute(
                "SELECT COUNT(*) FROM ssh_accounts WHERE service_type='ssh' "
                "AND status LIKE '%فعال%' AND status NOT LIKE '%غیر%'"
            ).fetchone()[0]
        return current[0][0] if len(current) == 1 else None, \
            [row[0] for row in standby], count

    async def _home(self, context, chat):
        current,standby,count=await asyncio.to_thread(self._inventory)
        rec=await asyncio.to_thread(self.engine.latest)
        text = ("🌐 <b>مدیریت Edge</b>\n\n"
                f"Edge فعال: <code>{escape(current or 'نامشخص')}</code>\n"
                f"کاربران SSH فعال: <b>{count}</b>\n"
                f"Edgeهای دستی آماده: <b>{len(standby)}</b>\n\n"
                "تغییر IP فقط پس از بررسی SSH/WG، DNS و تأیید شما انجام می‌شود.")
        if not self.enabled():
            text += "\n\n🟡 حالت آماده‌سازی: تغییر IP هنوز فعال نشده است."
        rows=[]
        if rec and rec["kind"]=="QUICK" and rec["status"] not in ("DONE","ABORTED"):
            rows.append([("⚠️ بررسی انتقال ناتمام","apps_edge_quick_status")])
        for ip in standby[:6]:
            rows.append([("🔁 تغییر IP به "+ip, "apps_edge_quick_select_"+ip)])
        rows.extend([
            [("➕ افزودن Edge دستی","apps_edge_manual_home")],
            [("🖥 وضعیت و سوابق","apps_edge_quick_status")],
        ])
        if current==HISTORICAL_TARGET:
            rows.append([("📋 ثبت بازیابی اضطراری قبلی","apps_edge_quick_attest")])
        rows.append([("↩️ برنامه‌ها","apps_home")])
        return await self._view(context,chat,text,rows)

    async def _status(self,context,chat):
        current,standby,count=await asyncio.to_thread(self._inventory)
        rec=await asyncio.to_thread(self.engine.latest)
        error=self.last_errors.get(str(chat))
        if not rec:
            return await self._view(
                context,chat,"📋 <b>سوابق انتقال</b>\n\n"
                "هنوز عملیات Quick Switch در Journal جدید ثبت نشده است.\n"
                f"Edge فعال: <code>{escape(current or 'نامشخص')}</code>\n"
                f"آخرین نتیجه: {escape(error or 'بدون عملیات جدید')}",
                [[("🔄 تازه‌سازی","apps_edge_quick_status")],
                 [("↩️ مدیریت Edge","apps_edge_quick_home")]])
        status=rec["status"]
        label={"DNS_INTENT":"در حال تغییر DNS","HOLD":"نیازمند بررسی",
               "DB_COMMITTED":"DNS و دیتابیس تغییر کرده؛ کنترل نهایی",
               "DONE":"تکمیل فنی","EXTERNAL_VERIFIED":"بازیابی دستی ثبت شد",
               "ABORTED":"لغوشده"}.get(status,status)
        rows=[]
        if (rec["kind"]=="QUICK" and rec["actor"]==str(chat)
                and status in ("DNS_INTENT","HOLD","DB_COMMITTED")):
            rows.append([("🔎 بررسی و ادامه بدون تکرار DNS",
                         "apps_edge_quick_resume_"+rec["id"])])
            if status=="HOLD":
                rows.append([("⚠️ تلاش مجدد DNS با تأیید مدیر",
                             "apps_edge_quick_retry_review_"+rec["id"])])
        rows.extend([[("🔄 تازه‌سازی","apps_edge_quick_status")],
                     [("↩️ مدیریت Edge","apps_edge_quick_home")]])
        return await self._view(context,chat,
            "📋 <b>وضعیت انتقال</b>\n\n"
            f"مبدأ: <code>{escape(rec['source'])}</code>\n"
            f"مقصد: <code>{escape(rec['target'])}</code>\n"
            f"حساب‌های انتقال: <b>{rec['account_count']}</b>\n"
            f"وضعیت: <b>{escape(label)}</b>\n"
            f"جزئیات فنی: <code>{escape(rec['error_code'] or error or '—')}</code>\n\n"
            "تکمیل فنی، جایگزین بررسی اتصال واقعی مشتری نیست.",
            rows)

    async def _execute(self, *, plan=None, actor, job=None, retry_dns=False):
        def run():
            with self.effect_lock:
                if job:
                    return asyncio.run(self.engine.resume(
                        job,actor=actor,retry_dns=retry_dns))
                return asyncio.run(self.engine.start(
                    plan,actor=actor,
                    client_witness="ADMIN_CONFIRMED_INDEPENDENT_NPV_ISP_E2E"))
        try:
            await asyncio.to_thread(run)
        except Exception as exc:
            # Durable engine journal is the source of truth; no second DNS PUT.
            # Only a sanitized reason is retained for UI diagnostics.
            self.last_errors[str(actor)] = (
                str(exc) if isinstance(exc,QuickSwitchHold)
                else type(exc).__name__)
        else:
            self.last_errors.pop(str(actor),None)
        finally:
            self.running.discard(str(actor))

    async def handle(self, query, context, data, *, role, actor, chat,
                     is_private):
        admins=await asyncio.to_thread(self.admin_ids)
        if (role!="admin" or actor!=chat or not is_private or
                actor not in set(admins)):
            return await self._view(
                context,chat,"⛔️ فقط مدیر فعال در چت خصوصی مجاز است.",
                [[("↩️ برنامه‌ها","apps_home")]])
        try:
            if data in ("apps_edge_quick_home","apps_cz_home"):
                return await self._home(context,chat)
            if data=="apps_edge_quick_status":
                return await self._status(context,chat)
            if data.startswith("apps_edge_quick_select_"):
                ip=data[len("apps_edge_quick_select_"):]
                plan=await self.engine.preview(ip)
                nonce=secrets.token_hex(8)
                self.pending[(actor,chat)]={"nonce":nonce,"plan":plan,
                                           "expires":self.now()+PENDING_TTL}
                return await self._view(
                    context,chat,
                    "🔁 <b>تأیید تغییر IP کاربران</b>\n\n"
                    f"از: <code>{escape(plan['source'])}</code>\n"
                    f"به: <code>{escape(plan['target'])}</code>\n"
                    f"حساب‌های SSH تحت تأثیر: <b>{plan['count']}</b>\n\n"
                    "هویت مقصد، WireGuard و مسیر مشتری بررسی شد.\n"
                    "پیش از ادامه، با IP مقصد اتصال واقعی NPV Tunnel را "
                    "مستقل آزمایش و تأیید کنید. Cloudflare خودکار تغییر می‌کند. "
                    "حساب‌ها و رمزهای Core بازسازی نمی‌شوند.",
                    [[("✅ تست اتصال واقعی انجام شد؛ تغییر IP",
                       "apps_edge_quick_confirm_"+nonce)],
                     [("انصراف","apps_edge_quick_home")]])
            if data.startswith("apps_edge_quick_confirm_"):
                if not self.enabled():
                    raise QuickSwitchHold("QUICK_SWITCH_NOT_RELEASED")
                nonce=data[len("apps_edge_quick_confirm_"):]
                pending=self.pending.pop((actor,chat),None)
                if (not pending or pending["nonce"]!=nonce or
                        self.now()>pending["expires"]):
                    raise QuickSwitchHold("PREVIEW_EXPIRED")
                if str(actor) in self.running:
                    raise QuickSwitchHold("OPERATION_ALREADY_RUNNING")
                self.running.add(str(actor))
                try:
                    asyncio.create_task(self._execute(
                        plan=pending["plan"],actor=actor))
                except Exception:
                    self.running.discard(str(actor))
                    raise
                return await self._view(
                    context,chat,"⏳ <b>تغییر مسیر شروع شد.</b>\n\n"
                    "نتیجه مراحل در Journal ذخیره می‌شود. برای بررسی یا "
                    "بازیابی از دکمه وضعیت استفاده کنید.",
                    [[("🔄 وضعیت انتقال","apps_edge_quick_status")]])
            if data.startswith("apps_edge_quick_resume_"):
                if not self.enabled():
                    raise QuickSwitchHold("QUICK_SWITCH_NOT_RELEASED")
                job=data[len("apps_edge_quick_resume_"):]
                if str(actor) in self.running:
                    raise QuickSwitchHold("OPERATION_ALREADY_RUNNING")
                self.running.add(str(actor))
                asyncio.create_task(self._execute(job=job,actor=actor))
                return await self._view(
                    context,chat,"🔎 <b>بررسی و بازیابی آغاز شد.</b>\n"
                    "DNS فقط خوانده می‌شود؛ اگر قبلاً تغییر کرده باشد، "
                    "عملیات از Journal ادامه می‌یابد.",
                    [[("🔄 وضعیت انتقال","apps_edge_quick_status")]])
            if data.startswith("apps_edge_quick_retry_review_"):
                job=data[len("apps_edge_quick_retry_review_"):]
                rec=await asyncio.to_thread(self.engine.get,job)
                if not rec or rec["actor"]!=str(actor) or rec["status"]!="HOLD":
                    raise QuickSwitchHold("RECOVERY_NOT_READY")
                nonce=secrets.token_hex(8)
                self.pending[(actor,chat)]={"nonce":nonce,"retry_job":job,
                                           "expires":self.now()+PENDING_TTL}
                return await self._view(
                    context,chat,
                    "⚠️ <b>بررسی تلاش مجدد Cloudflare</b>\n"
                    "این گزینه ممکن است درخواست تغییر DNS جدیدی ارسال کند. "
                    "فقط پس از بررسی وضعیت عمومی DNS و آماده‌بودن مقصد تأیید کنید.",
                    [[("✅ تلاش مجدد با بررسی تازه",
                       "apps_edge_quick_retry_yes_"+nonce)],
                     [("انصراف","apps_edge_quick_status")]])
            if data.startswith("apps_edge_quick_retry_yes_"):
                if not self.enabled():
                    raise QuickSwitchHold("QUICK_SWITCH_NOT_RELEASED")
                nonce=data[len("apps_edge_quick_retry_yes_"):]
                pending=self.pending.pop((actor,chat),None)
                if (not pending or pending.get("nonce")!=nonce or
                        not pending.get("retry_job") or
                        self.now()>pending["expires"]):
                    raise QuickSwitchHold("RECOVERY_CONFIRM_EXPIRED")
                if str(actor) in self.running:
                    raise QuickSwitchHold("OPERATION_ALREADY_RUNNING")
                self.running.add(str(actor))
                asyncio.create_task(self._execute(
                    job=pending["retry_job"],actor=actor,retry_dns=True))
                return await self._view(
                    context,chat,"⏳ <b>بازبینی DNS آغاز شد.</b>\n"
                    "موتور فقط با شواهد معتبر درخواست جدید ارسال می‌کند.",
                    [[("🔄 وضعیت انتقال","apps_edge_quick_status")]])
            if data=="apps_edge_quick_attest":
                current,_,count=await asyncio.to_thread(self._inventory)
                if current!=HISTORICAL_TARGET:
                    raise QuickSwitchHold("HISTORICAL_ROUTE_CHANGED")
                nonce=secrets.token_hex(8)
                self.pending[(actor,chat)]={"nonce":nonce,"attest":True,
                                           "count":count,
                                           "expires":self.now()+PENDING_TTL}
                return await self._view(
                    context,chat,
                    "📋 <b>ثبت بازیابی اضطراری قبلی</b>\n\n"
                    f"مبدأ: <code>{HISTORICAL_SOURCE}</code>\n"
                    f"مقصد: <code>{HISTORICAL_TARGET}</code>\n"
                    f"کاربران فعال فعلی: <b>{count}</b>\n\n"
                    "این عملیات فقط یک سند مستقل ثبت می‌کند و هیچ حساب، "
                    "DNS یا سابقه قدیمی را تغییر نمی‌دهد. اتصال واقعی "
                    "مشتری باید قبلاً تأیید شده باشد.",
                    [[("✅ ثبت نتیجه تأییدشده","apps_edge_quick_attest_yes_"+nonce)],
                     [("انصراف","apps_edge_quick_home")]])
            if data.startswith("apps_edge_quick_attest_yes_"):
                if not self.enabled():
                    raise QuickSwitchHold("QUICK_SWITCH_NOT_RELEASED")
                nonce=data[len("apps_edge_quick_attest_yes_"):]
                pending=self.pending.pop((actor,chat),None)
                if (not pending or pending.get("nonce")!=nonce or
                        pending.get("attest") is not True or
                        self.now()>pending["expires"]):
                    raise QuickSwitchHold("ATTESTATION_EXPIRED")
                job=await self.engine.record_external_cutover(
                    source=HISTORICAL_SOURCE,target=HISTORICAL_TARGET,
                    actor=actor,
                    client_witness="ADMIN_CONFIRMED_NPV_ISP_E2E_ON_20261029",
                    expected_active=pending["count"])
                return await self._view(
                    context,chat,"✅ <b>بازیابی اضطراری ثبت شد.</b>\n"
                    f"شناسه: <code>{escape(job)}</code>\n"
                    "سوابق قبلی و حساب‌های کاربران تغییری نکردند.",
                    [[("📋 سوابق","apps_edge_quick_status")],
                     [("↩️ مدیریت Edge","apps_edge_quick_home")]])
            return await self._home(context,chat)
        except Exception as exc:
            return await self._view(
                context,chat,"⛔️ <b>عملیات متوقف شد.</b>\n" +
                escape(_message(exc)) +
                "\nهیچ تغییر جدیدی را بدون بررسی وضعیت تکرار نکنید.",
                [[("📋 وضعیت و بازیابی","apps_edge_quick_status")],
                 [("↩️ مدیریت Edge","apps_edge_quick_home")]])
