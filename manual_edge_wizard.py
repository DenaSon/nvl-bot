"""Admin-only manual Edge wizard: private WebApp → pinned SSH → Standby → shared Cloudflare+CZ07.

No Cloudzy imports or CloudzyService calls. Paid VPS lifecycle and receipts
remain entirely separate. Feature-flagged until HTTPS ingress is configured.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
from html import escape
from contextvars import ContextVar
from manual_edge_rich import ManualRichDelivery, render_manual_card
import os
import secrets
import socket
import time
from urllib.parse import urlsplit

from manual_edge_secure_form import IntakeHold, ManualFormStore
from manual_edge_journal import ManualEdgeHold, ManualEdgeJournal
from manual_edge_identity import assert_ref as assert_edge_ref
from cloudzy_cz04b import _digest


_RICH_SCOPE = ContextVar('manual_edge_rich_scope', default=None)


class ManualWizardHold(RuntimeError):
    pass


def fingerprint_ssh(ip, port, *, timeout=10):
    """Unauthenticated host-key observation; independent operator review needed."""
    import paramiko
    with socket.create_connection((ip,int(port)),timeout=timeout) as sock:
        transport=paramiko.Transport(sock)
        try:
            transport.banner_timeout=timeout
            transport.start_client(timeout=timeout)
            key=transport.get_remote_server_key()
            if key is None:
                raise ManualWizardHold("SSH_HOSTKEY_MISSING")
            digest=base64.b64encode(hashlib.sha256(key.asbytes()).digest())
            return key.get_name(), key.get_base64(), "SHA256:"+digest.decode().rstrip("=")
        finally:
            transport.close()


FA = {
    "PUBLIC_IPV4_REQUIRED":"IP عمومی معتبر نیست.",
    "CORE_IP_CANNOT_BE_EDGE":"این نشانی متعلق به خود Core است یا هویت آن قابل بررسی نیست.",
    "UBUNTU24_ROOT_REQUIRED":"اتصال مدیریت Root یا Ubuntu 24.04 تأیید نشد؛ نصب انجام نمی‌شود.",
    "SSH_PORT_INVALID":"پورت مدیریت SSH معتبر نیست.",
    "SSH_MANAGEMENT_PORT_CONFLICT":"پورت SSH مدیریت با پورت اتصال مشتری یا TLS یکسان است. پورت دیگری انتخاب کنید.",
    "EDGE_IP_ALREADY_REGISTERED":"این IP قبلاً در فهرست سرورها وجود دارد.",
    "EDGE_IP_HAS_CLOUDZY_RECEIPT":"این IP متعلق به پرونده Cloudzy موجود است.",
    "ACTIVE_MANUAL_OPERATION_EXISTS":"ابتدا وضعیت عملیات دستی قبلی را بررسی کنید.",
    "HOST_KEY_CHANGED":"اثر انگشت سرور تغییر کرده است. اتصال متوقف شد.",
    "FORM_NOT_SUBMITTED_OR_EXPIRED":"فرم هنوز ثبت نشده یا زمان آن تمام شده است.",
    "INTAKE_EXPIRED":"زمان فرم تمام شده است.",
    "MANUAL_OPERATION_CHANGED":"وضعیت عملیات تغییر کرده؛ صفحه را تازه کنید.",
    "INSTALL_PROOF_MISSING":"نصب سرور هنوز تأیید نشده است.",
    "MANUAL_HOST_POOL_MISMATCH":"ثبت سرور با نتیجه نصب سازگار نیست.",
    "STANDBY_ROLE_CHANGED":"وضعیت Standby سرور تغییر کرده است.",
    "CANCEL_REQUIRES_SAFE_RECONCILIATION":"این عملیات اثر خارجی داشته و لغو ساده مجاز نیست.",
    "CLOUDFLARE_CONFIG_MISSING":"اتصال Cloudflare تنظیم نشده است؛ سرور در Standby می‌ماند.",
    "DNS_CHANGED_CONCURRENTLY":"DNS در زمان بررسی تغییر کرد؛ انتقال متوقف شد.",
    "DNS_OR_DEFAULT_UNCERTAIN_LOCK_HELD":"نتیجه تغییر DNS مشخص نیست؛ مسیر باید بررسی شود.",
}


class ManualEdgeWizard:
    def __init__(self, *, db, preflight, provision, verify, probe, nat, queue,
                 form_store=None, now=time.time, key_reader=fingerprint_ssh,
                 enabled=None, form_url=None, guard=None, is_core_host=None,
                 os_check=None):
        self.journal=ManualEdgeJournal(db,now=now,guard=guard)
        # Production wires the authoritative Core-host validator. Without
        # this callback the mutating wizard must fail closed, not guess.
        self.is_core_host=is_core_host
        self.os_check=os_check
        self.db=db
        self.preflight=preflight
        self.provision=provision
        self.verify=verify
        self.probe=probe
        self.nat=nat
        self.queue=queue
        self.form=form_store or ManualFormStore(clock=now)
        self.now=now
        self.key_reader=key_reader
        self.enabled=enabled or (lambda:os.environ.get("NVL_EDGE_MANUAL_ENABLED")=="1")
        self.form_url=form_url or (lambda:os.environ.get("NVL_MANUAL_FORM_PUBLIC_URL",""))
        self.running=set()

    async def _view(self,query,text,rows):
        # The central handler binds operator-specific context once per
        # callback. ContextVar prevents cross-admin async state leakage.
        scope = _RICH_SCOPE.get()
        if not scope:
            raise ManualWizardHold("RICH_OPERATOR_UNAVAILABLE")
        token, context, chat = scope
        return await ManualRichDelivery(token).show(
            chat=chat, context=context, text=text, rows=rows)

    async def _form_button(self,query,*,text,notice,nonce):
        public_url=self.form_url().rstrip("/")
        u=urlsplit(public_url)
        if u.scheme!="https" or not u.netloc or u.username or u.password or u.fragment:
            raise ManualWizardHold("SECURE_WEB_FORM_NOT_CONFIGURED")
        url=public_url+"/manual-edge/form?ticket="+nonce
        return await self._view(query,text,[
            [(notice, {"web_app": {"url": url}})],
            [("✅ اطلاعات را ثبت کردم", "apps_edge_manual_form_done_"+nonce)],
            [("انصراف", "apps_edge_manual_cancel")],
        ])

    def _session(self,context,actor,chat):
        obj=context.user_data.get("manual_edge_session")
        if (not isinstance(obj,dict)
                or (obj.get("actor"),obj.get("chat"))!=(actor,chat)
                or self.now()>=obj.get("expires",0)):
            raise ManualWizardHold("SESSION_EXPIRED")
        return obj

    @staticmethod
    def _summary(op):
        return ("🛟 <b>سرور دستی</b>\n\n"
                f"IP: <code>{escape(str(op.get('ip') or '—'))}</code>\n"
                f"پورت SSH: <b>{int(op.get('admin_port') or 22)}</b>\n")

    async def _show(self,query,actor,chat):
        op=await asyncio.to_thread(self.journal.latest,actor,chat)
        if op is None:
            return await self._view(query,
                "🛟 <b>افزودن Edge دستی</b>\n\n"
                "سرور خودتان را بدون Cloudzy اضافه کنید. "
                "تغییر DNS پس از آماده‌سازی فقط از طریق Cloudflare انجام می‌شود.",
                [[("➕ افزودن سرور", "apps_edge_manual_new")],
                 [("↩️ مدیریت Edge","apps_cz_home")]])
        stage=op["status"]
        labels={
            "DRAFT":"در انتظار مشخصات سرور",
            "HOSTKEY_PENDING":"در انتظار تأیید هویت SSH",
            "READY_INSTALL":"آماده نصب",
            "INSTALLING":"در حال آماده‌سازی سرور",
            "INSTALL_HOLD":"نصب نیازمند بررسی است",
            "EDGE_READY":"نصب تکمیل شده؛ بررسی Standby",
            "STANDBY":"آماده انتقال",
            "ROUTING":"در حال تغییر مسیر یا انتقال کاربران",
            "ACTIVE":"رله فعال",
            "HOLD":"نیازمند بررسی",
        }
        rows=[]
        if stage=="HOSTKEY_PENDING":
            rows.append([("🔐 بررسی هویت SSH","apps_edge_manual_key_"+op["id"])])
        if stage=="READY_INSTALL":
            rows.append([("📝 ورود امن رمز","apps_edge_manual_password_"+op["id"])])
        if stage=="EDGE_READY":
            rows.append([("✅ بررسی و فعال‌سازی Standby",
                          "apps_edge_manual_standby_"+op["id"])])
        if stage=="STANDBY":
            rows.append([("🔁 بررسی انتقال کاربران",
                          "apps_edge_manual_review_"+op["id"])])
        if stage=="ROUTING":
            rows.append([("🔄 وضعیت انتقال و تکمیل",
                          "apps_edge_manual_progress_"+op["id"])])
        if stage=="ACTIVE":
            rows.append([("➕ افزودن سرور جدید",
                          "apps_edge_manual_new")])
        if stage in ("DRAFT","HOSTKEY_PENDING","READY_INSTALL"):
            rows.append([("❌ لغو درخواست","apps_edge_manual_cancel")])
        rows.extend([[("🔄 تازه‌سازی","apps_edge_manual_home")],
                     [("↩️ مدیریت Edge","apps_cz_home")]])
        return await self._view(query,self._summary(op)+
            "وضعیت: <b>"+escape(labels.get(stage,"نیازمند بررسی"))+"</b>\n"
            +("⚠️ نصب قبلی را تکرار نکنید؛ وضعیت سرور باید مستقل بررسی شود."
              if stage=="INSTALL_HOLD" else ""),rows)

    @staticmethod
    def _assert_management_port_safe(admin_port, customer_port, tls_port):
        # The Legacy Edge installs unconditional customer/TLS DNAT. A
        # management port collision would redirect admin SSH to the Core.
        # This must be rejected BEFORE SSH authentication or installer writes.
        if int(admin_port) in (int(customer_port), int(tls_port)):
            raise ManualWizardHold("SSH_MANAGEMENT_PORT_CONFLICT")

    async def _install_task(self,app,op_id,actor,chat,password):
        try:
            op=await asyncio.to_thread(self.journal.get,op_id)
            if self.is_core_host is None or await asyncio.to_thread(
                    self.is_core_host,op["ip"]):
                raise ManualWizardHold("CORE_IP_CANNOT_BE_EDGE")
            customer_port,_ = await asyncio.to_thread(self.preflight)
            tls_port = await asyncio.to_thread(self._tls_port)
            self._assert_management_port_safe(
                op["admin_port"],customer_port,tls_port)
            observed=await asyncio.to_thread(
                self.key_reader,op["ip"],op["admin_port"])
            if tuple(observed[:2])!=(op["pin_type"],op["pin_base64"]):
                raise ManualWizardHold("HOST_KEY_CHANGED")
            # OS and SSH root password are attested read-only against the
            # approved host key BEFORE recording a remote install intent.
            if self.os_check is None or not await asyncio.to_thread(
                    self.os_check,op["ip"],op["admin_port"],password,
                    (op["pin_type"],op["pin_base64"])):
                raise ManualWizardHold("UBUNTU24_ROOT_REQUIRED")
            # The journal commits intent before any remote mutation. Never
            # automatically rerun the Legacy installer after an ambiguous exit.
            await asyncio.to_thread(self.journal.begin_install,op_id,actor,chat)
            ok,ip,details=await self.provision(
                op["ip"],op["admin_port"],password,
                (op["pin_type"],op["pin_base64"]),chat,app)
            if not ok or not isinstance(details,dict) or not details.get("tunnel_ok"):
                raise ManualWizardHold("LEGACY_INSTALL_OR_TUNNEL_FAILED")
            if await self.verify(op["ip"],details,op["admin_port"]) is not True:
                raise ManualWizardHold("LEGACY_EDGE_POSTCHECK_FAILED")
            observed=await asyncio.to_thread(
                self.key_reader,op["ip"],op["admin_port"])
            if tuple(observed[:2])!=(op["pin_type"],op["pin_base64"]):
                raise ManualWizardHold("HOST_KEY_CHANGED_AFTER_INSTALL")
            port,_pub=await asyncio.to_thread(self.preflight)
            await asyncio.to_thread(
                self.journal.mark_edge_ready,op_id,actor,chat,port)
            await ManualRichDelivery(app.bot.token).api.send(
                chat_id=chat, rich_message=render_manual_card(
                    "✅ نصب سرور تکمیل شد.\nبرای بررسی Standby، وضعیت را باز کنید.",
                    [[("🟢 وضعیت سرور دستی", "apps_edge_manual_home")]],
                ))
        except Exception as exc:
            safe=str(exc) if isinstance(exc,(ManualEdgeHold,ManualWizardHold)) else type(exc).__name__
            if await asyncio.to_thread(self.journal.get,op_id):
                op=await asyncio.to_thread(self.journal.get,op_id)
                if op["status"]=="INSTALLING":
                    try:
                        await asyncio.to_thread(
                            self.journal.install_hold,op_id,actor,chat,safe)
                    except Exception:
                        pass
            try:
                await ManualRichDelivery(app.bot.token).api.send(
                    chat_id=chat, rich_message=render_manual_card(
                        "⛔️ آماده‌سازی به بررسی نیاز دارد.\n"
                        "برای جلوگیری از تکرار نصب و قوانین شبکه، عملیات متوقف شد.",
                        [[("🔄 وضعیت سرور دستی", "apps_edge_manual_home")]],
                    ))
            except Exception:
                # Telegram delivery failure must not replay an installer or
                # undo the durable INSTALL_HOLD receipt.
                pass
        finally:
            self.running.discard(op_id)
            password=None  # best effort only: Python strings cannot be zeroized

    async def handle(self,query,context,data,*,role,actor,chat,app):
        # This is a UI-only task-local scope; never persist the bot token in
        # user_data or a Telegram callback. No HTML screen fallback.
        _RICH_SCOPE.set((app.bot.token,context,chat))
        if role!="admin" or actor!=chat:
            return await self._view(query,"⛔️ فقط مدیر در گفتگوی خصوصی مجاز است.",
                                    [[("↩️ برنامه‌ها","apps_home")]])
        try:
            if data=="apps_edge_manual_home":
                return await self._show(query,actor,chat)
            if data=="apps_edge_manual_new":
                await asyncio.to_thread(self.preflight)
                op=await asyncio.to_thread(self.journal.start,actor,chat)
                context.user_data["manual_edge_session"]={
                    "actor":actor,"chat":chat,"op":op,
                    "stage":"server_ip","expires":self.now()+600,
                }
                context.user_data["state"]="MANUAL_EDGE_IP"
                return await self._view(query,
                    "۱/۴ · <b>سرور جدید</b>\n\n"
                    "IP عمومی VPS خام (Ubuntu 24.04) را در همین گفتگوی خصوصی "
                    "ارسال کنید. این مسیر هیچ API کلودزی یا HTTPS جداگانه‌ای ندارد. "
                    "برای لغو /cancel بفرستید.",
                    [[("↩️ وضعیت","apps_edge_manual_home")]])
            if data.startswith("apps_edge_manual_form_done_"):
                raise ManualWizardHold("OLD_WEBAPP_CALLBACK_DISABLED")
            if data.startswith("apps_edge_manual_key_"):
                opid=data[len("apps_edge_manual_key_"):]
                op=await asyncio.to_thread(self.journal.get,opid)
                if not op or (op["actor"],op["chat"])!=(actor,chat) or op["status"]!="HOSTKEY_PENDING":
                    raise ManualWizardHold("SSH_REVIEW_NOT_READY")
                key_type,key_b64,fingerprint=await asyncio.to_thread(
                    self.key_reader,op["ip"],op["admin_port"])
                context.user_data["manual_edge_pin"]={
                    "op":opid,"actor":actor,"chat":chat,
                    "key":(key_type,key_b64,fingerprint),
                    "expires":self.now()+180,
                }
                return await self._view(query,
                    "۲/۴ · <b>تأیید هویت سرور</b>\n\n"
                    f"IP: <code>{escape(op['ip'])}</code>\n"
                    f"اثر انگشت: <code>{escape(fingerprint)}</code>\n\n"
                    "این مقدار را با اثرانگشت SSH در کنسول مستقل VPS "
                    "مقایسه کنید. بدون تطبیق، نصب را ادامه ندهید.",
                    [[("✅ اثر انگشت را مستقل تأیید کردم",
                       "apps_edge_manual_pin_"+opid)],
                     [("↩️ وضعیت","apps_edge_manual_home")]])
            if data.startswith("apps_edge_manual_pin_"):
                opid=data[len("apps_edge_manual_pin_"):]
                proof=context.user_data.pop("manual_edge_pin",None)
                if (not isinstance(proof,dict) or proof["op"]!=opid
                        or (proof["actor"],proof["chat"])!=(actor,chat)
                        or self.now()>=proof["expires"]):
                    raise ManualWizardHold("SSH_APPROVAL_EXPIRED")
                op=await asyncio.to_thread(self.journal.get,opid)
                observed=await asyncio.to_thread(
                    self.key_reader,op["ip"],op["admin_port"])
                if observed[:2]!=proof["key"][:2]:
                    raise ManualWizardHold("HOST_KEY_CHANGED")
                await asyncio.to_thread(self.journal.pin,opid,actor,chat,*proof["key"])
                return await self._view(query,
                    "✅ هویت سرور تأیید شد.\n"
                    "اکنون رمز Root را فقط در گفتگوی خصوصی بات ارسال کنید. "
                    "بات پیام رمز را پیش از نصب حذف می‌کند؛ تلگرام جایگزین "
                    "یک کانال محرمانهٔ مستقل نیست.",
                    [[("🔐 ورود رمز و ادامه",
                       "apps_edge_manual_password_"+opid)]])
            if data.startswith("apps_edge_manual_password_"):
                opid=data[len("apps_edge_manual_password_"):]
                op=await asyncio.to_thread(self.journal.get,opid)
                if (not op or (op["actor"],op["chat"])!=(actor,chat)
                        or op["status"]!="READY_INSTALL" or opid in self.running):
                    raise ManualWizardHold("INSTALL_NOT_READY")
                context.user_data["manual_edge_session"]={
                    "actor":actor,"chat":chat,"op":opid,
                    "stage":"password","expires":self.now()+180,
                }
                context.user_data["state"]="MANUAL_EDGE_PASSWORD"
                return await self._view(query,
                    "۳/۴ · <b>رمز Root</b>\n\n"
                    "رمز SSH را فقط در چت خصوصی همین بات ارسال کنید. "
                    "پیش از استفاده، پیام حذف می‌شود؛ رمز در دیتابیس یا "
                    "user_data ذخیره نمی‌شود. اگر امکان حذف پیام نباشد "
                    "نصب انجام نمی‌شود. این روش به اندازه فرم HTTPS امن نیست.",
                    [[("↩️ وضعیت","apps_edge_manual_home")]])
            if data.startswith("apps_edge_manual_standby_"):
                opid=data[len("apps_edge_manual_standby_"):]
                op=await asyncio.to_thread(self.journal.get,opid)
                if not op or (op["actor"],op["chat"])!=(actor,chat) or op["status"]!="EDGE_READY":
                    raise ManualWizardHold("EDGE_NOT_READY")
                port,pub=await asyncio.to_thread(self.preflight)
                tls=await asyncio.to_thread(self._tls_port)
                ok=await self.probe(op["ip"],port,op["admin_port"])
                nat=await self.nat(op["ip"],op["admin_port"],port,tls,
                                   (op["pin_type"],op["pin_base64"]))
                if ok is not True or nat is not True:
                    raise ManualWizardHold("STANDBY_NETWORK_UNVERIFIED")
                await asyncio.to_thread(self.journal.mark_standby,opid,actor,chat)
                return await self._view(query,
                    "✅ <b>سرور در حالت آماده‌به‌کار قرار گرفت.</b>\n"
                    "DNS و حساب‌های مشتری هنوز تغییر نکرده‌اند.",
                    [[("🔁 بررسی انتقال کاربران",
                       "apps_edge_manual_review_"+opid)],
                     [("↩️ وضعیت","apps_edge_manual_home")]])
            if data.startswith("apps_edge_manual_review_"):
                opid=data[len("apps_edge_manual_review_"):]
                candidate=await asyncio.to_thread(self.queue.manual_candidate,actor,chat)
                if candidate[0]!=opid:
                    raise ManualWizardHold("STANDBY_IDENTITY_CHANGED")
                state=await asyncio.to_thread(self.queue.cz04b._state,candidate[1])
                await self.queue.cz04b._fresh(state,check_provider=False)
                snapshot=await asyncio.to_thread(self.queue.cz04b.dns.snapshot)
                self.queue.cz04b._expect_dns(snapshot,state["source"])
                nonce=secrets.token_hex(8)
                context.user_data["manual_edge_route"]={
                    "actor":actor,"chat":chat,"op":opid,"nonce":nonce,
                    "source":state["source"],"target":candidate[1],
                    "fingerprint":_digest(state["users"]),
                    "count":len(state["users"]),"expires":self.now()+180,
                }
                return await self._view(query,
                    "۴/۴ · <b>بررسی انتقال</b>\n\n"
                    f"مبدأ: <code>{escape(state['source'])}</code>\n"
                    f"مقصد: <code>{escape(state['target'])}</code>\n"
                    f"حساب‌های فعال: <b>{len(state['users'])}</b>\n\n"
                    "DNS با Cloudflare به‌صورت خودکار تغییر می‌کند. "
                    "سپس فقط حساب‌های باقی‌مانده جابه‌جا می‌شوند. "
                    "سرور قبلی حذف نمی‌شود. اتصال مشتری پیش از تأیید نهایی "
                    "باید مستقل آزمایش شده باشد.",
                    [[("✅ اتصال واقعی تأیید شد؛ آغاز انتقال",
                       "apps_edge_manual_go_"+nonce)],
                     [("انصراف","apps_edge_manual_home")]])
            if data.startswith("apps_edge_manual_go_"):
                sess=context.user_data.pop("manual_edge_route",None)
                if (not isinstance(sess,dict)
                        or (sess["actor"],sess["chat"])!=(actor,chat)
                        or data!="apps_edge_manual_go_"+sess["nonce"]
                        or self.now()>=sess["expires"]):
                    raise ManualWizardHold("TRANSFER_CONFIRMATION_EXPIRED")
                candidate=await asyncio.to_thread(
                    self.queue.manual_candidate,actor,chat)
                if (candidate[0],candidate[1])!=(sess["op"],sess["target"]):
                    raise ManualWizardHold("TRANSFER_IDENTITY_CHANGED")
                state=await asyncio.to_thread(self.queue.cz04b._state,candidate[1])
                if (state["source"]!=sess["source"] or
                        _digest(state["users"])!=sess["fingerprint"] or
                        len(state["users"])!=sess["count"]):
                    raise ManualWizardHold("TRANSFER_PREVIEW_EXPIRED")
                await self.queue.cz04b._fresh(state,check_provider=False)
                snap=await asyncio.to_thread(self.queue.cz04b.dns.snapshot)
                self.queue.cz04b._expect_dns(snap,state["source"])
                if not self.queue.enabled() or not self.queue.cz04b.enabled():
                    raise ManualWizardHold("TRANSFER_ENGINE_DISABLED")
                job=await asyncio.to_thread(
                    self.queue.reserve,candidate,state["source"],actor=actor,
                    chat=chat,expected_fp=sess["fingerprint"],
                    expected_count=sess["count"])
                await asyncio.to_thread(
                    self.journal.bind_route,sess["op"],actor,chat,job)
                self.queue.launch(app,job)
                return await self._view(query,
                    "⏳ <b>انتقال آغاز شد.</b>\n"
                    "Cloudflare به‌صورت خودکار تغییر می‌کند. پیشرفت واقعی "
                    "در دفتر انتقال ثبت می‌شود.",
                    [[("🔄 وضعیت انتقال",
                       "apps_edge_manual_progress_"+sess["op"])]])
            if data.startswith("apps_edge_manual_progress_"):
                opid=data[len("apps_edge_manual_progress_"):]
                op=await asyncio.to_thread(self.journal.get,opid)
                if not op or (op["actor"],op["chat"])!=(actor,chat) or not op["route_job"]:
                    raise ManualWizardHold("ROUTE_JOB_NOT_FOUND")
                rec=await asyncio.to_thread(self.queue.get,op["route_job"])
                if rec is None:
                    raise ManualWizardHold("ROUTE_JOB_NOT_FOUND")
                if rec["status"] in ("VERIFYING","MOVED"):
                    return await self._view(query,
                        self._summary(op)+
                        f"حساب‌های منتقل‌شده: <b>{rec['moved']}/{rec['total']}</b>\n"
                        "برای ثبت تکمیل فنی، مسیر DNS و اتصال را دوباره بررسی کنید.",
                        [[("✅ کنترل نهایی انتقال",
                           "apps_edge_manual_finish_"+opid)],
                         [("🔄 وضعیت","apps_edge_manual_home")]])
                return await self._view(query,
                    self._summary(op)+
                    f"انتقال: <b>{rec['moved']}/{rec['total']}</b>\n"
                    "وضعیت: <b>"+escape({
                        "QUEUED":"در انتظار شروع",
                        "ROUTING":"در حال تغییر خودکار DNS",
                        "MIGRATING":"در حال انتقال حساب‌ها",
                        "PAUSED_SAFE":"توقف پس از مرحله جاری",
                        "HOLD":"نیازمند بررسی",
                        "VERIFYING":"در انتظار تأیید نهایی",
                        "MOVED":"رله فعال، پذیرش مشتری در انتظار",
                    }.get(rec["status"],"نیازمند بررسی"))+"</b>",
                    [[("🔄 تازه‌سازی","apps_edge_manual_progress_"+opid)],
                     [("📋 بررسی و بازیابی صف","apps_cz7_status")]])
            if data.startswith("apps_edge_manual_finish_"):
                opid=data[len("apps_edge_manual_finish_"):]
                op=await asyncio.to_thread(self.journal.get,opid)
                if not op or (op["actor"],op["chat"])!=(actor,chat):
                    raise ManualWizardHold("OPERATOR_MISMATCH")
                rec=await asyncio.to_thread(self.queue.get,op["route_job"])
                if not rec or rec["status"] not in ("VERIFYING","MOVED"):
                    raise ManualWizardHold("TRANSPORT_NOT_READY")
                state=await asyncio.to_thread(
                    self.queue.cz04b._ready_probe_state,
                    rec["source"],rec["target"],rec["provider_id"])
                await self.queue.cz04b._fresh(state,check_provider=False)
                dns=await asyncio.to_thread(self.queue.cz04b.dns.snapshot)
                self.queue.cz04b._expect_dns(dns,rec["target"])
                if rec["status"]=="VERIFYING":
                    await asyncio.to_thread(
                        self.queue.complete_transport,rec["id"],
                        actor=actor,chat=chat,expected_updated_at=rec["updated_at"])
                await asyncio.to_thread(
                    self.journal.finish,opid,actor,chat,rec["id"])
                return await self._view(query,
                    "✅ <b>رله جدید فعال شد.</b>\n"
                    "تمام حساب‌های اولیه به مقصد جدید منتقل شده‌اند. "
                    "تأیید مستقل ساخت/تمدید و اتصال مشتری همچنان لازم است. "
                    "رله قبلی حذف نشده است.",
                    [[("🔄 وضعیت سرور","apps_edge_manual_home")]])
            if data=="apps_edge_manual_cancel":
                op=await asyncio.to_thread(self.journal.latest,actor,chat)
                if op and op["status"] in ("DRAFT","HOSTKEY_PENDING","READY_INSTALL"):
                    await asyncio.to_thread(
                        self.journal.cancel_draft,op["id"],actor,chat)
                    context.user_data.pop("manual_edge_session",None)
                    context.user_data.pop("manual_edge_pin",None)
                    return await self._view(query,"✅ درخواست بدون تغییر سرور لغو شد.",
                        [[("↩️ مدیریت Edge","apps_cz_home")]])
                raise ManualWizardHold("CANCEL_REQUIRES_SAFE_RECONCILIATION")
            return await self._show(query,actor,chat)
        except Exception as exc:
            code=str(exc) if isinstance(exc,(ManualWizardHold,ManualEdgeHold,IntakeHold)) else type(exc).__name__
            return await self._view(query,
                "⛔️ <b>عملیات متوقف شد.</b>\n"+
                escape(FA.get(code,"وضعیت سرور یا مسیر نیازمند بررسی است. "
                       "از انجام دوباره نصب یا تغییر DNS خودداری کنید.")),
                [[("🔄 وضعیت سرور دستی","apps_edge_manual_home")],
                 [("↩️ مدیریت Edge","apps_cz_home")]])


    async def receive_text(self,update,context,state,text,*,actor,chat,app,role):
        """Private Telegram emergency intake; never persist SSH password.

        Admin must explicitly approve the observed SSH host fingerprint BEFORE
        entering any password. The password message must be deleted before
        dispatch. No form server, Cloudzy API or runtime feature flag is used.
        """
        _RICH_SCOPE.set((app.bot.token,context,chat))
        # Delete ANY password-state message BEFORE checking owner/session/TTL.
        # An expired or missing session must not strand a raw root password
        # in Telegram history.
        if state=="MANUAL_EDGE_PASSWORD":
            try:
                await update.message.delete()
            except Exception:
                context.user_data.pop("state",None)
                context.user_data.pop("manual_edge_session",None)
                return await update.effective_chat.send_message(
                    "⛔️ حذف پیام رمز ممکن نبود؛ نصب متوقف شد. "
                    "این پیام را از تاریخچه چت حذف کنید.")
        if role!="admin" or actor!=chat or actor<=0:
            context.user_data.pop("manual_edge_session",None)
            context.user_data.pop("state",None)
            return await update.message.reply_text("⛔️ فقط مدیر در گفتگوی خصوصی مجاز است.")
        if text.strip() in ("/cancel","لغو","انصراف"):
            session=context.user_data.pop("manual_edge_session",None)
            context.user_data.pop("state",None)
            context.user_data.pop("manual_edge_candidate_ip",None)
            if isinstance(session,dict) and session.get("op"):
                try:
                    await asyncio.to_thread(self.journal.cancel_draft,
                                            session["op"],actor,chat)
                except ManualEdgeHold:
                    pass  # A started installer is never blindly cancelled.
            return await update.message.reply_text(
                "ورود اطلاعات لغو شد. اگر نصب شروع شده باشد، "
                "پرونده آن برای بررسی حفظ می‌شود.")
        try:
            sess=self._session(context,actor,chat)
            opid=sess["op"]
            if state=="MANUAL_EDGE_IP" and sess["stage"]=="server_ip":
                from manual_edge_secure_form import public_ip
                ip=public_ip(text.strip())
                if self.is_core_host is None or await asyncio.to_thread(
                        self.is_core_host,ip):
                    raise ManualWizardHold("CORE_IP_CANNOT_BE_EDGE")
                context.user_data["manual_edge_candidate_ip"]=ip
                sess["stage"]="server_port"
                context.user_data["state"]="MANUAL_EDGE_PORT"
                return await update.message.reply_text(
                    "✅ IP ثبت شد. پورت مدیریت SSH سرور را وارد کنید "
                    "(معمولاً 22؛ این پورت با پورت مشتری متفاوت است).")
            if state=="MANUAL_EDGE_PORT" and sess["stage"]=="server_port":
                from manual_edge_secure_form import ssh_port
                admin_port=ssh_port(text.strip())
                ip=context.user_data["manual_edge_candidate_ip"]
                customer_port,_=await asyncio.to_thread(self.preflight)
                tls_port=await asyncio.to_thread(self._tls_port)
                self._assert_management_port_safe(
                    admin_port,customer_port,tls_port)
                await asyncio.to_thread(self.journal.set_server,opid,
                                        actor,chat,ip,admin_port)
                context.user_data.pop("state",None)
                context.user_data.pop("manual_edge_candidate_ip",None)
                context.user_data.pop("manual_edge_session",None)
                return await self._view(None,
                    "✅ IP و پورت مدیریت ثبت شدند. پیش از دریافت رمز، "
                    "اثر انگشت SSH سرور را مستقلاً تأیید کنید.",
                    [[("🔐 بررسی اثر انگشت SSH",
                       "apps_edge_manual_key_"+opid)],
                     [("↩️ وضعیت Edge","apps_edge_manual_home")]])
            if state=="MANUAL_EDGE_PASSWORD" and sess["stage"]=="password":
                # Password was already deleted before session/TTL validation.
                # NEVER put it in context.user_data (persistent) or any log.
                context.user_data.pop("state",None)
                context.user_data.pop("manual_edge_session",None)
                op=await asyncio.to_thread(self.journal.get,opid)
                if (not op or op["status"]!="READY_INSTALL"
                        or (op["actor"],op["chat"])!=(actor,chat)
                        or opid in self.running):
                    raise ManualWizardHold("INSTALL_NOT_READY")
                if not text or len(text)>2048:
                    raise ManualWizardHold("PASSWORD_INVALID")
                self.running.add(opid)
                coro=self._install_task(app,opid,actor,chat,text)
                try:
                    app.create_task(coro)
                except Exception:
                    self.running.discard(opid)
                    coro.close()
                    raise
                return await self._view(None,
                    "⏳ <b>راه‌اندازی Edge آغاز شد.</b>\n"
                    "نتیجه در همین چت اعلام می‌شود. نصب را دوباره اجرا نکنید.",
                    [[("🔄 وضعیت Edge","apps_edge_manual_home")]])
            raise ManualWizardHold("TEXT_STAGE_CHANGED")
        except (ManualEdgeHold,ManualWizardHold,IntakeHold,ValueError) as exc:
            code=str(exc)
            return await update.message.reply_text(
                "⛔️ "+FA.get(code,"اطلاعات یا وضعیت این مرحله معتبر نیست. "
                      "برای لغو /cancel بفرستید."))

    def _tls_port(self):
        with self.db() as db:
            row=db.execute("SELECT value FROM settings WHERE key='tls_port'").fetchone()
            return int(row[0] if row else 2088)
