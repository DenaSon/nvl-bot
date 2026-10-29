"""Admin-only Rich UI for provider-free Quick Switch.

No Cloudzy UI, Cloudzy provider API, or per-user CZ07 queue. Reuses
ManualRichDelivery and an injected ManualQuickSwitch. All actions are
actor+chat scoped, guarded by live admin membership and private-chat checks.
"""
from __future__ import annotations

import secrets
import time

from manual_edge_rich import ManualRichDelivery
from manual_quick_switch import QuickSwitchHold

TTL = 180


class QuickSwitchUIHold(RuntimeError):
    pass


class QuickSwitchUI:
    def __init__(self, *, engine, token, db_conn, delivery_factory=ManualRichDelivery,
                 now=time.time):
        self.engine = engine
        self.db = db_conn
        self.delivery = delivery_factory(token)
        self.now = now

    async def _screen(self, chat, context, text, rows):
        return await self.delivery.show(
            chat=chat, context=context, text=text, rows=rows,
        )

    def _standbys(self):
        with self.db() as db:
            return [row[0] for row in db.execute(
                "SELECT h.host FROM host_pool h "
                "JOIN manual_edge_operations m ON m.ip=h.host "
                "WHERE h.active=1 AND h.is_default=0 AND h.is_standby=1 "
                "AND h.provider='manual' AND h.provider_instance_id IS NULL "
                "AND m.status='STANDBY' ORDER BY h.host"
            ).fetchall()]

    @staticmethod
    def _actor(actor):
        return f"telegram:{actor}"

    @staticmethod
    def _safe_reason(exc):
        value = str(exc)
        if not value or len(value) > 80 or not all(
                c.isupper() or c.isdigit() or c == "_" for c in value):
            return "REVIEW_REQUIRED"
        return value

    def _session(self, context, actor, chat, nonce):
        saved = context.user_data.get("quick_edge_approval")
        if (not isinstance(saved, dict)
                or saved.get("actor") != actor or saved.get("chat") != chat
                or saved.get("nonce") != nonce
                or self.now() >= saved.get("expires", 0)):
            raise QuickSwitchUIHold("CONFIRMATION_EXPIRED")
        return saved

    async def handle(self, *, data, query, context, actor, chat, role,
                     is_private, active_admin_ids):
        if (role != "admin" or type(actor) is not int or type(chat) is not int
                or actor != chat or not is_private
                or actor not in active_admin_ids):
            raise QuickSwitchUIHold("ADMIN_PRIVATE_REQUIRED")
        try:
            if data == "apps_edge_quick_home":
                context.user_data.pop("quick_edge_approval", None)
                current = self.engine.latest(actor=self._actor(actor))
                with self.db() as db:
                    defaults = db.execute(
                        "SELECT host FROM host_pool WHERE active=1 AND is_default=1"
                    ).fetchall()
                    active = db.execute(
                        "SELECT COUNT(*) FROM ssh_accounts WHERE service_type='ssh' "
                        "AND status LIKE '%فعال%' AND status NOT LIKE '%غیر%'"
                    ).fetchone()[0]
                default = defaults[0][0] if len(defaults) == 1 else "نیازمند بررسی"
                rows = [[("🔁 انتخاب Edge مقصد","apps_edge_quick_pick")]]
                if current and current["status"] not in (
                        "DONE", "ABORTED", "EXTERNAL_VERIFIED"):
                    rows.append([("🛠 بازیابی عملیات","apps_edge_quick_status")])
                rows.extend([[("🖥 سرورهای من","hp_menu")],
                             [("↩️ مدیریت Edge","apps_cz_home")]])
                return await self._screen(
                    chat,context,
                    "🌐 مدیریت Edge\n"
                    f"Edge فعال: {default}\n"
                    f"کاربران SSH فعال: {active}\n"
                    "تغییر IP پس از بررسی WireGuard، SSH و DNS انجام می‌شود.",
                    rows,
                )
            if data == "apps_edge_quick_pick":
                candidates = self._standbys()
                if not candidates:
                    return await self._screen(
                        chat,context,
                        "🟡 Edge آماده‌ای برای انتقال وجود ندارد.\n"
                        "ابتدا یک Edge دستی را آماده Standby کنید.",
                        [[("➕ افزودن دستی","apps_edge_manual_home")],
                         [("↩️ بازگشت","apps_edge_quick_home")]],
                    )
                rows = [[(f"🖥 {ip}","apps_edge_quick_review_"+ip)]
                        for ip in candidates[:8]]
                rows.append([("↩️ بازگشت","apps_edge_quick_home")])
                return await self._screen(
                    chat,context,"🔁 انتخاب Edge مقصد\n"
                    "فقط Edgeهای دستیِ آماده نمایش داده می‌شوند.",rows,
                )
            if data.startswith("apps_edge_quick_review_"):
                target = data[len("apps_edge_quick_review_"):]
                if target not in self._standbys():
                    raise QuickSwitchUIHold("TARGET_STANDBY_CHANGED")
                plan = await self.engine.preview(target)
                nonce = secrets.token_hex(8)
                context.user_data["quick_edge_approval"] = {
                    "actor":actor,"chat":chat,"nonce":nonce,
                    "plan":plan,"expires":self.now()+TTL,
                }
                return await self._screen(
                    chat,context,
                    "🔎 پیش‌نمایش تغییر IP\n"
                    f"مبدأ: {plan['source']}\n"
                    f"مقصد: {target}\n"
                    f"حساب‌های SSH مشمول: {plan['count']}\n"
                    "هویت سرور، WireGuard و مسیر SSH بررسی شد.\n"
                    "با تأیید، DNS و سپس Host کاربران تغییر می‌کند. "
                    "اتصال واقعی مشتری را پس از انتقال جداگانه تست کنید.",
                    [[("✅ تأیید تغییر IP","apps_edge_quick_yes_"+nonce)],
                     [("انصراف","apps_edge_quick_home")]],
                )
            if data.startswith("apps_edge_quick_yes_"):
                nonce = data[len("apps_edge_quick_yes_"):]
                session = self._session(context,actor,chat,nonce)
                context.user_data.pop("quick_edge_approval",None)
                plan = session["plan"]
                job = await self.engine.start(
                    plan,actor=self._actor(actor),
                    client_witness="OPERATOR_APPROVED_PINNED_STANDBY_PREFLIGHT",
                )
                return await self._screen(
                    chat,context,
                    "✅ تغییر مسیر ثبت شد.\n"
                    f"شناسه عملیات: {job[:16]}\n"
                    "اکنون اتصال واقعی NPV Tunnel و ساخت/تمدید حساب را بررسی کنید.",
                    [[("🔄 وضعیت","apps_edge_quick_status")],
                     [("↩️ مدیریت Edge","apps_cz_home")]],
                )
            if data == "apps_edge_quick_status":
                rec = self.engine.latest(actor=self._actor(actor))
                if not rec:
                    return await self._screen(
                        chat,context,"📋 هنوز انتقال سریعی ثبت نشده است.",
                        [[("↩️ مدیریت Edge","apps_cz_home")]],
                    )
                rows = [[("↩️ مدیریت Edge","apps_cz_home")]]
                if rec["kind"] == "QUICK" and rec["status"] not in (
                        "DONE","ABORTED"):
                    rows.insert(0,[("🔍 بررسی و ادامه امن","apps_edge_quick_resume")])
                return await self._screen(
                    chat,context,
                    "📋 وضعیت تغییر IP\n"
                    f"مبدأ: {rec['source']}\nمقصد: {rec['target']}\n"
                    f"وضعیت: {rec['status']}\n"
                    f"علت بررسی: {rec.get('error_code') or '—'}",
                    rows,
                )
            if data == "apps_edge_quick_resume":
                rec = self.engine.latest(actor=self._actor(actor))
                if not rec or rec["kind"] != "QUICK":
                    raise QuickSwitchUIHold("RECOVERY_NOT_FOUND")
                status = await self.engine.resume(
                    rec["id"],actor=self._actor(actor),retry_dns=False)
                return await self._screen(
                    chat,context,"✅ نتیجه بررسی: "+status,
                    [[("🔄 وضعیت","apps_edge_quick_status")],
                     [("↩️ مدیریت Edge","apps_cz_home")]],
                )
            raise QuickSwitchUIHold("CALLBACK_NOT_SUPPORTED")
        except (QuickSwitchHold,QuickSwitchUIHold) as exc:
            return await self._screen(
                chat,context,
                "⛔️ عملیات انجام نشد یا نیازمند بررسی است.\n"
                "کد: "+self._safe_reason(exc)+"\n"
                "در حالت نامطمئن DNS را دستی تکرار نکنید.",
                [[("🔄 وضعیت و بازیابی","apps_edge_quick_status")],
                 [("↩️ مدیریت Edge","apps_cz_home")]],
            )
