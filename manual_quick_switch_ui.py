"""Admin-only native HTML UI for Manual Edge Quick Switch.

The Cloudzy engine remains installed; no Cloudzy provider calls are made.
Callbacks never accept an arbitrary account destination or migration status.
"""
from __future__ import annotations

import asyncio
from html import escape
import logging
import os
import secrets
import threading
import time

from manual_edge_html import ManualHtmlDelivery
from manual_quick_switch import QuickSwitchHold

log = logging.getLogger(__name__)
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
    "DNS_UNCERTAIN_REVIEW_REQUIRED": "نتیجه DNS مشخص نیست؛ عملیات نیازمند بررسی است.",
    "DNS_WRITE_RESULT_UNCERTAIN": "پاسخ Cloudflare نامشخص است؛ درخواست را کورکورانه تکرار نکنید.",
    "ACCOUNT_OR_ROUTE_CHANGED": "حساب‌ها یا مسیر پس از پیش‌نمایش تغییر کرده‌اند.",
    "PREVIEW_CHANGED": "اطلاعات تغییر کرده است؛ پیش‌نمایش تازه بگیرید.",
    "EXTERNAL_ROUTE_UNVERIFIED": "شواهد انتقال اضطراری قبلی کامل نیستند.",
    "FORCE_ABORT_ONLY_HOLD": "لغو اجباری فقط برای انتقال متوقف‌شده (HOLD) مجاز است.",
    "FORCE_ABORT_DNS_UNVERIFIED": "شناسه رکوردهای DNS قابل تأیید نیست.",
    "FORCE_ABORT_OTHER_LEASE_RUNNING": "عملیات دیگری هم قفل فعال دارد؛ لغو خودکار مجاز نیست.",
    "FORCE_CONFIRMATION_EXPIRED": "تأیید لغو منقضی شده؛ دوباره بررسی کنید.",
    "LEASE_OWNERSHIP_LOST": "قفل ثبت‌شده متعلق به این انتقال نیست؛ بررسی لازم است.",
    "LEASE_IDENTITY_UNVERIFIED": "هویت قفل انتقال تأیید نشد؛ لغو مجاز نیست.",
    "ORIGINAL_FAILOVER_RUNNING": "قفل یک انتقال دیگر هنوز فعال است؛ وضعیت انتقال را بررسی کنید.",
    "DB_COMMIT_REVIEW_REQUIRED": "ثبت مسیر در دیتابیس کامل نشده یا نتیجه‌اش نامشخص است؛ وضعیت DNS را بررسی کنید.",
    "POSTCOMMIT_REVIEW_REQUIRED": "ثبت مسیر انجام شده اما تأیید نهایی کامل نیست؛ از لغو اجباری استفاده نکنید.",
    "RECOVERY_UNEXPECTED_ERROR": "بازیابی با خطای پیش‌بینی‌نشده متوقف شد؛ جزئیات فنی باید بررسی شود.",
    "DNS_RETRY_REQUIRES_CONFIRMATION": "DNS هنوز روی مبدأ است؛ تلاش دوباره نیازمند تأیید جداگانه است.",
    "OPERATION_ALREADY_RUNNING": "یک عملیات در حال اجراست؛ پس از پایان آن وضعیت را تازه‌سازی کنید.",
    "RECOVERY_NOT_READY": "وضعیت فعلی برای تلاش مجدد DNS مناسب نیست؛ گزارش انتقال را بررسی کنید.",
    "FORCE_ABORT_ONLY_UNCOMMITTED": "این انتقال از مرحله‌ای که بتوان پرونده و قفلش را لغو کرد عبور کرده است.",
    "FORCE_ABORT_INTENT_TOO_RECENT": "هنوز ۳ دقیقه از ثبت انتقال نگذشته است؛ برای جلوگیری از تداخل، لغو مجاز نیست.",
    "FORCE_ABORT_DNS_NOT_ON_SOURCE": "DNS روی مبدأ یکپارچه نیست؛ ابتدا وضعیت واقعی DNS را بررسی کنید.",
    "FORCE_ABORT_ROUTE_CHANGED": "مسیر کاربران یا دیتابیس تغییر کرده؛ آزادسازی خودکار قفل مجاز نیست.",
    "FORCE_ABORT_SNAPSHOT_CHANGED": "وضعیت در هنگام تأیید تغییر کرده است؛ گزارش را تازه‌سازی کنید.",
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
        return await ManualHtmlDelivery(context.application.bot).show(
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
            if os.environ.get("NVL_LEGACY_WG_UI_ENABLED","0")!="1":
                from nvl_awg_target import target_backend
                allowed=[]
                for candidate in standby:
                    try:
                        if target_backend(db,candidate[0])=="amneziawg":
                            allowed.append(candidate)
                    except Exception:
                        pass  # stale/unverified inventory cannot appear as selectable
                standby=allowed
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
                f"🟢 رله اصلی: <code>{escape(current or 'نامشخص')}</code>\n"
                f"👥 کاربران SSH: <b>{count}</b>\n"
                f"🟡 آماده‌به‌کار: <b>{len(standby)}</b>")
        if not self.enabled():
            text += "\n\n⚠️ انتقال کاربران فعلاً غیرفعال است."
        rows=[]
        if rec and rec["kind"]=="QUICK" and rec["status"] not in ("DONE","ABORTED"):
            rows.append([("⚠️ بررسی انتقال ناتمام","apps_edge_quick_status")])
        for ip in standby[:6]:
            from nvl_awg_target import target_backend, core_limiter_canary_ready
            from nvl_tunnel_backend import lookup_binding
            try:
                with self.db() as db:
                    backend=target_backend(db,ip)
                    binding=lookup_binding(db,ip)
                ready=((backend=="wireguard" and
                        os.environ.get("NVL_LEGACY_WG_UI_ENABLED","0")=="1") or (
                    backend=="amneziawg" and
                    os.environ.get("NVL_AWG_CUTOVER_ENABLED")=="1"
                    and binding is not None
                    and core_limiter_canary_ready(binding.edge_tunnel_ip)))
            except Exception:
                ready=False
            if ready:
                rows.append([("🔁 انتقال کاربران و DNS به "+ip,
                             "apps_edge_quick_select_"+ip)])
        rows.extend([
            [("🖥 مدیریت سرورها","apps_edge_manual_home")],
            [("📋 وضعیت و سوابق انتقال","apps_edge_quick_status")],
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
                f"رله اصلی: <code>{escape(current or 'نامشخص')}</code>\n"
                f"نتیجه: {escape(error or 'هنوز انتقالی ثبت نشده است')}",
                [[("🔄 تازه‌سازی","apps_edge_quick_status")],
                 [("↩️ مدیریت سرورها","apps_edge_quick_home")]])
        status=rec["status"]
        label={"DNS_INTENT":"نتیجه انتقال نامشخص؛ نیازمند بررسی",
               "HOLD":"متوقف‌شده؛ نیازمند بررسی و بازیابی",
               "DB_COMMITTED":"DNS و دیتابیس تغییر کرده؛ کنترل نهایی",
               "DONE":"تکمیل فنی","EXTERNAL_VERIFIED":"بازیابی دستی ثبت شد",
               "ABORTED":"لغوشده"}.get(status,status)
        rows=[]
        if (rec["kind"]=="QUICK" and rec["actor"]==str(chat)
                and status in ("DNS_INTENT","HOLD","DB_COMMITTED")):
            rows.append([("🔎 بررسی وضعیت DNS و ادامه ایمن",
                         "apps_edge_quick_resume_"+rec["id"])])
            if status=="HOLD":
                rows.append([("⚠️ تلاش مجدد DNS با تأیید مدیر",
                             "apps_edge_quick_retry_review_"+rec["id"])])
            if status in ("DNS_INTENT","HOLD"):
                rows.append([("⛔ لغو انتقال و آزادسازی قفل",
                             "apps_edge_quick_force_review_"+rec["id"])])
        rows.extend([[("🔄 تازه‌سازی","apps_edge_quick_status")],
                     [("↩️ مدیریت سرورها","apps_edge_quick_home")]])
        title=("✅ <b>انتقال با موفقیت انجام شد</b>" if status=="DONE"
               else "📋 <b>وضعیت انتقال</b>")
        code=(rec.get("error_code") or
              (error if status not in ("DONE","ABORTED") else None))
        detail=(f"\n\n⚠️ {_message(code)}\n"
                f"کد پیگیری: <code>{escape(str(code))}</code>"
                if code else "")
        message=(title+"\n\n"
                 f"شناسه انتقال: <code>{escape(rec['id'])}</code>\n"
                 f"مبدأ: <code>{escape(rec['source'])}</code>\n"
                 f"مقصد: <code>{escape(rec['target'])}</code>\n"
                 f"حساب‌ها: <b>{rec['account_count']}</b>\n"
                 f"وضعیت: <b>{escape(label)}</b>"+detail)
        if status=="DNS_INTENT":
            message+=("\n\nتا زمانی که نتیجه DNS قطعی نشده، "
                      "از آغاز انتقال دیگر خودداری کنید. "
                      "دکمه بازیابی وضعیت را فقط بررسی می‌کند و "
                      "DNS را بدون تأیید جدا دوباره تغییر نمی‌دهد.")
        elif status=="HOLD":
            message+=("\n\nبرای تعیین‌تکلیف ابتدا وضعیت DNS را بررسی کنید. "
                      "لغو اجباری به معنی بازگرداندن مسیر یا اتصال کاربران نیست.")
        elif status=="DB_COMMITTED":
            message+=("\n\nمسیر در دیتابیس ثبت شده؛ "
                      "لغو اجباری مجاز نیست و کنترل نهایی لازم است.")
        if status=="DONE":
            message+="\n🌐 DNS: <b>تأییدشده</b>\n\n" \
                     "اتصال واقعی مشتری را نیز بررسی کنید."
        elif status=="ABORTED" and rec.get("error_code")=="ADMIN_FORCE_ABORT_UNRECONCILED":
            message+=("\n\n⚠️ فقط پرونده و قفل عملیات آزاد شده‌اند؛ "
                      "DNS و حساب‌های کاربران تغییر نکرده‌اند.")
        return await self._view(context,chat,message,rows)

    def _claim_done_notice(self, job, actor, chat):
        """One durable send intent per verified DONE job; fail closed.

        No retries after uncertain Telegram delivery, even across restarts.
        Only the source-of-truth job journal can authorize a success message.
        """
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            rec=db.execute(
                "SELECT kind,status,actor,source,target,account_count "
                "FROM manual_quick_switch_jobs WHERE id=?", (job,)
            ).fetchone()
            if (not rec or rec[:3]!=("QUICK","DONE",str(actor))
                    or type(chat) is not int or chat!=actor):
                db.rollback()
                return None
            defaults=db.execute(
                "SELECT host FROM host_pool WHERE active=1 AND is_default=1"
            ).fetchall()
            if defaults != [(rec[4],)]:
                db.rollback()
                return None
            db.execute("""
                CREATE TABLE IF NOT EXISTS manual_quick_success_notices (
                    job_id TEXT PRIMARY KEY,
                    actor INTEGER NOT NULL,
                    chat INTEGER NOT NULL,
                    status TEXT NOT NULL CHECK(status IN
                        ('CLAIMED','SENT','UNCERTAIN')),
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                )
            """)
            now=int(self.now())
            claim=db.execute(
                "INSERT OR IGNORE INTO manual_quick_success_notices "
                "(job_id,actor,chat,status,created_at,updated_at) "
                "VALUES (?,?,?,'CLAIMED',?,?)",
                (job,actor,chat,now,now),
            ).rowcount
            db.commit()
            return rec if claim==1 else None

    def _settle_done_notice(self, job, status):
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "UPDATE manual_quick_success_notices SET status=?,"
                "updated_at=? WHERE job_id=? AND status='CLAIMED'",
                (status,int(self.now()),job),
            )
            db.commit()

    async def _notify_done(self, *, job, actor, chat, bot):
        rec=await asyncio.to_thread(
            self._claim_done_notice,job,actor,chat)
        if rec is None:
            return False
        text=("✅ <b>انتقال با موفقیت انجام شد</b>\n\n"
              f"🟢 رله جدید: <code>{escape(rec[4])}</code>\n"
              f"👥 حساب‌های منتقل‌شده: <b>{rec[5]}</b>\n"
              "🌐 DNS: <b>تأییدشده</b>\n"
              "وضعیت: <b>تکمیل فنی</b>\n\n"
              "اتصال واقعی مشتری پس از انتقال نیز بررسی شود.")
        rows=[[("📋 گزارش انتقال","apps_edge_quick_status")],
              [("🖥 مدیریت سرورها","apps_edge_manual_home")]]
        try:
            await ManualHtmlDelivery(bot).send(
                chat=chat,text=text,rows=rows)
        except Exception:
            # Telegram may have delivered the message before a timeout.
            # Keep an UNCERTAIN durable receipt; never send a duplicate.
            await asyncio.to_thread(
                self._settle_done_notice,job,"UNCERTAIN")
            log.warning("Manual Quick Switch DONE notice unconfirmed job=%s",job)
            return False
        await asyncio.to_thread(self._settle_done_notice,job,"SENT")
        return True

    async def _execute(self, *, plan=None, actor, job=None, retry_dns=False,
                       chat=None, bot=None):
        def run():
            with self.effect_lock:
                if job:
                    return asyncio.run(self.engine.resume(
                        job,actor=actor,retry_dns=retry_dns))
                return asyncio.run(self.engine.start(
                    plan,actor=actor,
                    client_witness="ADMIN_CONFIRMED_INDEPENDENT_NPV_ISP_E2E"))
        try:
            receipt=await asyncio.to_thread(run)
        except Exception as exc:
            # Durable engine journal is the source of truth; no second DNS PUT.
            # Only a sanitized reason is retained for UI diagnostics.
            self.last_errors[str(actor)] = (
                str(exc) if isinstance(exc,QuickSwitchHold)
                else type(exc).__name__)
        else:
            self.last_errors.pop(str(actor),None)
            completed_job=job if job is not None else receipt
            if isinstance(completed_job,str) and bot is not None and chat==actor:
                try:
                    await self._notify_done(
                        job=completed_job,actor=actor,chat=chat,bot=bot)
                except Exception:
                    # Delivery cannot alter or replay the durable DNS/account
                    # transfer. The status screen remains independently usable.
                    log.exception("Manual Quick Switch notice check failed job=%s",
                                  completed_job)
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
            if data.startswith("apps_edge_quick_force_yes_"):
                nonce=data[len("apps_edge_quick_force_yes_"):]
                pending=self.pending.pop((actor,chat),None)
                if (not isinstance(pending,dict)
                        or pending.get("nonce")!=nonce
                        or not pending.get("force_job")
                        or self.now()>pending.get("expires",0)):
                    raise QuickSwitchHold("FORCE_CONFIRMATION_EXPIRED")
                if str(actor) in self.running:
                    raise QuickSwitchHold("OPERATION_ALREADY_RUNNING")
                job=pending["force_job"]
                def abort():
                    # Same local mutex as the background Cloudflare worker:
                    # do not race this button with an actual transfer.
                    with self.effect_lock:
                        return self.engine.force_abort(job,actor=actor)
                await asyncio.to_thread(abort)
                return await self._view(
                    context,chat,
                    "✅ <b>پرونده انتقال بسته شد؛ قفل آن آزاد شد.</b>\n\n"
                    "این اقدام فقط رکورد انتقال و Lease مربوط به آن را بست. "
                    "هیچ فرمانی برای تغییر DNS، کاربران یا رله ارسال نشد.\n"
                    "⚠️ بازگشت DNS یا برقرارشدن اتصال کاربران تأیید نشده است؛ "
                    "پیش از انتقال بعدی مسیر واقعی را بررسی کنید.",
                    [[("📋 وضعیت و سوابق","apps_edge_quick_status")],
                     [("🖥 مدیریت سرورها","apps_edge_manual_home")]])
            if data.startswith("apps_edge_quick_force_review_"):
                job=data[len("apps_edge_quick_force_review_"):]
                rec=await asyncio.to_thread(self.engine.get,job)
                if (not rec or rec.get("kind")!="QUICK"
                        or rec.get("status") not in ("DNS_INTENT","HOLD")
                        or rec.get("actor")!=str(actor)):
                    raise QuickSwitchHold("FORCE_ABORT_ONLY_HOLD")
                nonce=secrets.token_hex(8)
                self.pending[(actor,chat)]={
                    "force_job":job,"nonce":nonce,
                    "expires":self.now()+PENDING_TTL,
                }
                note=("برای پرونده «در انتظار DNS»، لغو فقط پس از ۳ دقیقه "
                      "و تأیید زنده همه رکوردهای DNS روی مبدأ و مسیر دیتابیس مجاز است."
                      if rec["status"]=="DNS_INTENT" else
                      "این انتقال متوقف شده است؛ قبل از تأیید، "
                      "وضعیت DNS و مسیر واقعی را مستقل بررسی کنید.")
                return await self._view(
                    context,chat,
                    "⚠️ <b>لغو پرونده انتقال و آزادسازی قفل</b>\n\n"
                    f"شناسه: <code>{escape(rec['id'])}</code>\n"
                    f"مبدأ: <code>{escape(rec['source'])}</code>\n"
                    f"مقصد: <code>{escape(rec['target'])}</code>\n"
                    f"وضعیت: <b>{escape(rec['status'])}</b>\n\n"
                    +note+"\n\n"
                    "این اقدام فقط پرونده و Lease همان انتقال را می‌بندد. "
                    "DNS، حساب‌ها و تنظیمات شبکه برگردانده نمی‌شوند؛ "
                    "آزادسازی قفل به معنی وصل‌شدن کاربران نیست.",
                    [[("⛔ تأیید بستن انتقال و آزادسازی قفل",
                       "apps_edge_quick_force_yes_"+nonce)],
                     [("انصراف","apps_edge_quick_status")]])
            if data.startswith("apps_edge_quick_select_"):
                ip=data[len("apps_edge_quick_select_"):]
                from nvl_awg_target import target_backend
                from nvl_tunnel_backend import TunnelHold
                try:
                    with self.db() as db:
                        backend=target_backend(db,ip)
                except (TunnelHold, ValueError, sqlite3.Error):
                    raise QuickSwitchHold("TUNNEL_REGISTRY_UNVERIFIED") from None
                if (backend=="wireguard" and
                        os.environ.get("NVL_LEGACY_WG_UI_ENABLED","0")!="1"):
                    raise QuickSwitchHold("LEGACY_WG_NOT_AVAILABLE")
                plan=await self.engine.preview(ip)
                nonce=secrets.token_hex(8)
                self.pending[(actor,chat)]={"nonce":nonce,"plan":plan,
                                           "expires":self.now()+PENDING_TTL}
                return await self._view(
                    context,chat,
                    "🔁 <b>تأیید انتقال کاربران و DNS</b>\n\n"
                    f"از: <code>{escape(plan['source'])}</code>\n"
                    f"به: <code>{escape(plan['target'])}</code>\n"
                    f"حساب‌ها: <b>{plan['count']}</b>\n\n"
                    "مسیر سرویس و تونل بررسی شد. قبل از تأیید، "
                    "اتصال واقعی NPV Tunnel را روی مقصد مستقل تست کنید. "
                    "DNS به‌صورت خودکار تغییر می‌کند.",
                    [[("✅ تست اتصال واقعی انجام شد؛ تغییر IP",
                       "apps_edge_quick_confirm_"+nonce)],
                     [("انصراف","apps_edge_quick_home")]])
            if data.startswith("apps_edge_quick_confirm_"):
                if not self.enabled():
                    raise QuickSwitchHold("QUICK_SWITCH_NOT_RELEASED")
                nonce=data[len("apps_edge_quick_confirm_"):]
                pending=self.pending.pop((actor,chat),None)
                if pending and os.environ.get("NVL_LEGACY_WG_UI_ENABLED","0")!="1":
                    from nvl_awg_target import target_backend
                    with self.db() as db:
                        backend=target_backend(db,pending["plan"]["target"])
                    if backend=="wireguard":
                        raise QuickSwitchHold("LEGACY_WG_NOT_AVAILABLE")
                if (not pending or pending["nonce"]!=nonce or
                        self.now()>pending["expires"]):
                    raise QuickSwitchHold("PREVIEW_EXPIRED")
                if str(actor) in self.running:
                    raise QuickSwitchHold("OPERATION_ALREADY_RUNNING")
                self.running.add(str(actor))
                try:
                    asyncio.create_task(self._execute(
                        plan=pending["plan"],actor=actor,
                        chat=chat,bot=context.application.bot))
                except Exception:
                    self.running.discard(str(actor))
                    raise
                return await self._view(
                    context,chat,"⏳ <b>انتقال آغاز شد.</b>\n"
                    "پس از تکمیل، نتیجه همین‌جا اعلام می‌شود.",
                    [[("🔄 وضعیت انتقال","apps_edge_quick_status")]])
            if data.startswith("apps_edge_quick_resume_"):
                if not self.enabled():
                    raise QuickSwitchHold("QUICK_SWITCH_NOT_RELEASED")
                job=data[len("apps_edge_quick_resume_"):]
                if str(actor) in self.running:
                    raise QuickSwitchHold("OPERATION_ALREADY_RUNNING")
                self.running.add(str(actor))
                asyncio.create_task(self._execute(
                    job=job,actor=actor,chat=chat,bot=context.application.bot))
                return await self._view(
                    context,chat,"🔎 <b>بازیابی آغاز شد.</b>\n"
                    "انتقال بدون تکرار کورکورانه DNS بررسی می‌شود.",
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
                    "⚠️ <b>تأیید تلاش مجدد DNS</b>\n"
                    "ممکن است درخواست جدیدی به Cloudflare ارسال شود. "
                    "قبل از تأیید، DNS عمومی و سلامت مقصد را بررسی کنید.",
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
                    job=pending["retry_job"],actor=actor,retry_dns=True,
                    chat=chat,bot=context.application.bot))
                return await self._view(
                    context,chat,"⏳ <b>بازبینی DNS آغاز شد.</b>\n"
                    "وضعیت را از گزارش انتقال دنبال کنید.",
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
                     [("↩️ مدیریت سرورها","apps_edge_quick_home")]])
            return await self._home(context,chat)
        except Exception as exc:
            code=(str(exc) if isinstance(exc,QuickSwitchHold)
                  else type(exc).__name__)
            return await self._view(
                context,chat,"⛔️ <b>عملیات متوقف شد.</b>\n"+
                escape(_message(code))+
                "\nکد پیگیری: <code>"+escape(code)+"</code>"+
                "\n\nوضعیت واقعی انتقال را پیش از اقدام دوباره بررسی کنید.",
                [[("📋 وضعیت انتقال و بازیابی","apps_edge_quick_status")],
                 [("↩️ مدیریت سرورها","apps_edge_quick_home")]])
