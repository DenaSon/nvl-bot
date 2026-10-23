"""CZ-02: small, admin-only Cloudzy Telegram UI controller (Phase 1).

Provider access only via CloudzyService; no VPS purchase/power/rebuild/delete,
no legacy host_pool, DNS, WireGuard, SSH user or K2 mutations.  No telegram
imports here, so the UI can be unit-tested using lightweight fake messages.
The bot supplies a Telegram InlineKeyboardMarkup adapter.
"""
from __future__ import annotations

import asyncio
import base64
from html import escape
import re
import secrets
import time

from cloudzy_service import CloudzyAPIError, CloudzyError, CloudzyService, CloudzyUncertainError

MAX_PAGE = 999
PAGE_SIZE = 6
REF_TTL = 600
ACTION_TTL = 180
KEY_TYPES = ("ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256",
             "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
             "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com")


def _obj(value):
    if not isinstance(value, dict):
        return {}
    data = value.get("data")
    root = data if isinstance(data, dict) else value
    for name in ("server", "service", "account", "summary", "user"):
        inner = root.get(name)
        if isinstance(inner, dict):
            return inner
    return root


def _items(value):
    if isinstance(value, list):
        return [x for x in value if isinstance(x, dict)]
    if isinstance(value, dict):
        for root in (value, _obj(value)):
            for field in ("items", "data", "services", "servers", "regions", "keys"):
                if isinstance(root.get(field), list):
                    return [x for x in root[field] if isinstance(x, dict)]
    return []


def _value(value, *, max_chars=110):
    """Only explicitly chosen scalar display fields, NEVER arbitrary API JSON."""
    if isinstance(value, bool):
        return "بله" if value else "خیر"
    if isinstance(value, (str, int, float)):
        out = str(value).strip()
        return escape(out[:max_chars]) if out else "—"
    if isinstance(value, list):
        return escape(", ".join(str(x) for x in value[:3] if isinstance(x, (str, int)))[:max_chars]) or "—"
    return "—"


def _get(record, *keys):
    if not isinstance(record, dict):
        return None
    for k in keys:
        v = record.get(k)
        if v is not None and v != "":
            return v
    return None


def _page(raw):
    if not isinstance(raw, str) or not re.fullmatch(r"[0-9]{1,3}", raw):
        raise ValueError("INVALID_PAGE")
    return min(int(raw), MAX_PAGE)


def _paged(items, page):
    count = max(1, (len(items) + PAGE_SIZE - 1) // PAGE_SIZE)
    page = min(page, count - 1)
    return items[page * PAGE_SIZE: (page + 1) * PAGE_SIZE], page, count


def _paging(prefix, page, count):
    buttons = []
    if page:
        buttons.append(("◀️ قبلی", f"{prefix}_{page - 1}"))
    if page + 1 < count:
        buttons.append(("بعدی ▶️", f"{prefix}_{page + 1}"))
    return [buttons] if buttons else []


def _public_key(raw):
    if not isinstance(raw, str) or len(raw) > 8192 or "\n" in raw or "\r" in raw:
        raise ValueError("INVALID_PUBLIC_KEY")
    parts = raw.strip().split()
    if len(parts) < 2 or parts[0] not in KEY_TYPES:
        raise ValueError("INVALID_PUBLIC_KEY")
    try:
        decoded = base64.b64decode(parts[1], validate=True)
    except (ValueError, base64.binascii.Error):
        raise ValueError("INVALID_PUBLIC_KEY") from None
    if not (20 <= len(decoded) <= 8192) or any(ord(c) < 32 for c in " ".join(parts[2:])):
        raise ValueError("INVALID_PUBLIC_KEY")
    if parts[0].encode() not in decoded[:128]:
        # ssh-rsa encodes "ssh-rsa", Ed25519 encodes "ssh-ed25519", etc.
        raise ValueError("INVALID_PUBLIC_KEY")
    return raw.strip()


class CloudzyAdminPanel:
    def __init__(self, *, factory=CloudzyService, now=time.time):
        self.factory = factory
        self.now = now

    async def _api(self, method, *args, **kwargs):
        return await asyncio.to_thread(lambda: getattr(self.factory(), method)(*args, **kwargs))

    async def _display(self, target, text, rows, markup):
        await target.edit_message_text(text, parse_mode="HTML", reply_markup=markup(rows))

    @staticmethod
    def _end_key_flow(context):
        context.user_data.pop("cz_key_input", None)
        context.user_data.pop("cz_key_action", None)
        if str(context.user_data.get("state", "")).startswith("CZ_KEY_"):
            context.user_data.pop("state", None)

    def _refs(self, context, kind, rows, actor, chat):
        refs = {}
        tokens = []
        for row in rows:
            token = secrets.token_hex(4)
            safe = {k: v for k, v in row.items()
                    if k in ("id", "uuid", "serviceId", "keyId",
                             "hostname", "name", "label", "state", "status",
                             "region", "regionId", "code", "planName", "planId")
                    and isinstance(v, (str, int, float, bool))}
            refs[token] = (kind, str(_get(row, "id", "uuid", "serviceId", "keyId") or ""), safe)
            tokens.append(token)
        context.user_data["cz_refs"] = {
            "actor": actor, "chat": chat, "expires": self.now() + REF_TTL,
            "items": refs,
        }
        return tokens

    def _resolve(self, context, token, kind, actor, chat):
        entry = context.user_data.get("cz_refs")
        if (not isinstance(entry, dict) or entry.get("actor") != actor
                or entry.get("chat") != chat or self.now() >= entry.get("expires", 0)):
            raise ValueError("EXPIRED_SELECTION")
        chosen = entry.get("items", {}).get(token)
        if not chosen or chosen[0] != kind or not chosen[1]:
            raise ValueError("EXPIRED_SELECTION")
        return chosen[1], chosen[2]

    def _pending(self, context, kind, actor, chat, **fields):
        nonce = secrets.token_hex(8)
        context.user_data["cz_key_action"] = {
            "kind": kind, "nonce": nonce, "actor": actor, "chat": chat,
            "expires": self.now() + ACTION_TTL, **fields,
        }
        return nonce

    def _consume(self, context, kind, nonce, actor, chat):
        pending = context.user_data.pop("cz_key_action", None)
        if (not isinstance(pending, dict) or pending.get("kind") != kind
                or pending.get("nonce") != nonce or pending.get("actor") != actor
                or pending.get("chat") != chat or self.now() >= pending.get("expires", 0)):
            raise ValueError("EXPIRED_ACTION")
        return pending

    async def handle_callback(self, query, context, data, *, role, actor, chat, markup):
        if role != "admin":
            await query.message.reply_text("⛔️ فقط مدیر مجاز است.")
            return
        # Fresh navigation cancels pending key input or destructive confirmations.
        if data in ("apps_cz_home", "apps_cz_account", "apps_cz_balance") or data.startswith(
                ("apps_cz_servers_", "apps_cz_regions_", "apps_cz_keys_")):
            self._end_key_flow(context)
        try:
            if data == "apps_cz_home":
                await self._display(query,
                    "☁️ <b>مدیریت Cloudzy و Edge</b>\n\n"
                    "⚡ ساخت سریع Edge در فاز بعد فعال می‌شود.\n"
                    "🛡 مسیر قدیمی Edge/Relay از تنظیمات سرور بدون تغییر باقی است.\n"
                    "ℹ️ مدیریت خروجی محافظت‌شده K2 در این بخش اجرا نمی‌شود.",
                    [
                        [("⚡ ساخت سریع Edge · فاز بعد", "apps_cz_wizard")],
                        [("🖥 سرورهای Cloudzy", "apps_cz_servers_0")],
                        [("🌍 مناطق و پلن‌ها", "apps_cz_regions_0"),
                         ("💰 موجودی", "apps_cz_balance")],
                        [("👤 اطلاعات حساب", "apps_cz_account"),
                         ("🔑 کلیدهای SSH", "apps_cz_keys_0")],
                        [("↩️ برنامه‌ها", "apps_home")],
                    ], markup)
            elif data == "apps_cz_wizard":
                await self._display(query,
                    "⚡ <b>ساخت سریع Edge</b>\n\n"
                    "این ویزارد در فاز ۲ تکمیل می‌شود؛ هنوز خرید یا نصب VPS مجاز نیست.",
                    [[("↩️ Cloudzy", "apps_cz_home")]], markup)
            elif data.startswith("apps_cz_servers_"):
                page = _page(data[len("apps_cz_servers_"):])
                all_rows = _items(await self._api("list_servers"))
                values, page, count = _paged(all_rows, page)
                tokens = self._refs(context, "server", values, actor, chat)
                rows = []
                for entry, token in zip(values, tokens):
                    title = _get(entry, "hostname", "name", "label", "id") or "سرور"
                    rows.append([(f"🖥 {str(title)[:32]}", "apps_cz_sv_" + token)])
                rows += _paging("apps_cz_servers", page, count)
                rows.append([("↩️ Cloudzy", "apps_cz_home")])
                await self._display(query,
                    f"🖥 <b>سرورهای Cloudzy</b>\n"
                    f"تعداد دریافت‌شده: {len(all_rows)}\n"
                    f"صفحه {page + 1} از {count}\n\n"
                    "این فهرست از حساب Cloudzy دریافت می‌شود؛ هر VPS الزاماً Edge فعال NVL نیست.",
                    rows, markup)
            elif data.startswith("apps_cz_sv_"):
                server_id, fallback = self._resolve(context, data[len("apps_cz_sv_"):], "server", actor, chat)
                server = _obj(await self._api("get_server", server_id))
                display = server or fallback
                await self._display(query,
                    "🖥 <b>جزئیات VPS</b>\n\n"
                    f"نام: {_value(_get(display, 'hostname', 'name'))}\n"
                    f"شناسه: <code>{_value(server_id)}</code>\n"
                    f"IP: {_value(_get(display, 'ipv4', 'primaryIpv4', 'publicIp', 'ipAddress'))}\n"
                    f"منطقه: {_value(_get(display, 'region', 'regionId'))}\n"
                    f"پلن: {_value(_get(display, 'planName', 'planId', 'plan'))}\n"
                    f"وضعیت: {_value(_get(display, 'state', 'status'))}\n\n"
                    "⚠️ وضعیت VPS به معنی سالم‌بودن Edge یا دسترسی اپراتورهای ایران نیست.",
                    [[("🔎 وضعیت", "apps_cz_st_" + data[len("apps_cz_sv_"):]),
                      ("📊 مصرف منابع", "apps_cz_use_" + data[len("apps_cz_sv_"):])],
                     [("↩️ سرورها", "apps_cz_servers_0")]], markup)
            elif data.startswith(("apps_cz_st_", "apps_cz_use_")):
                usage = data.startswith("apps_cz_use_")
                token = data[len("apps_cz_use_"):] if usage else data[len("apps_cz_st_"):]
                server_id, _ = self._resolve(context, token, "server", actor, chat)
                details = _obj(await self._api("get_server_usage" if usage else "get_server_status", server_id))
                fields = (("CPU", ("cpu", "cpuUsage", "cpuPercent")),
                          ("RAM", ("ram", "memory", "memoryUsage")),
                          ("دیسک", ("disk", "diskUsage", "storage")),
                          ("شبکه", ("network", "bandwidth", "traffic"))) if usage else (
                          ("وضعیت", ("state", "status")),
                          ("زمان", ("updatedAt", "lastUpdated", "createdAt")))
                description = "\n".join(f"{name}: {_value(_get(details, *keys))}" for name, keys in fields)
                await self._display(query,
                    ("📊 <b>مصرف منابع</b>" if usage else "🔎 <b>وضعیت سرور</b>")
                    + f"\n\nسرور: <code>{_value(server_id)}</code>\n{description}",
                    [[("↩️ جزئیات", "apps_cz_sv_" + token)]], markup)
            elif data.startswith("apps_cz_regions_"):
                page = _page(data[len("apps_cz_regions_"):])
                all_rows = _items(await self._api("list_regions"))
                values, page, count = _paged(all_rows, page)
                tokens = self._refs(context, "region", values, actor, chat)
                rows = [[("🌍 " + str(_get(v, "name", "code", "id") or "منطقه")[:30],
                          "apps_cz_rg_" + t)] for v, t in zip(values, tokens)]
                rows += _paging("apps_cz_regions", page, count)
                rows.append([("↩️ Cloudzy", "apps_cz_home")])
                await self._display(query,
                    f"🌍 <b>مناطق Cloudzy</b>\nتعداد: {len(all_rows)} · صفحه {page + 1} از {count}\n"
                    "برای نمایش پلن‌های منطقه انتخاب کنید.", rows, markup)
            elif data.startswith("apps_cz_rg_"):
                region_id, region = self._resolve(context, data[len("apps_cz_rg_"):], "region", actor, chat)
                res = await self._api("list_plans", region=region_id, billing_cycle="monthly")
                plans = _items(res.get("plans", []) if isinstance(res, dict) else res)
                lines = [f"📦 <b>پلن‌های ماهانه</b>\nمنطقه: {_value(_get(region, 'name', 'id'))}\n"]
                for p in plans[:15]:
                    price = p.get("price") or {}
                    cents = _get(price, "amountCents", "priceCents", "monthlyEquivCents")
                    line = (f"• {_value(_get(p, 'name', 'slug', 'id'))} — "
                            f"{_value(cents)} سنت (پایه)" if cents is not None
                            else f"• {_value(_get(p, 'name', 'slug', 'id'))} — قیمت نامشخص")
                    lines.append(line)
                if len(plans) > 15:
                    lines.append(f"… و {len(plans) - 15} پلن دیگر")
                lines.append("\n⚠️ قیمت پایه است؛ هزینه IPv4 و افزونه‌ها ممکن است جدا باشد.")
                await self._display(query, "\n".join(lines),
                    [[("↩️ مناطق", "apps_cz_regions_0")]], markup)
            elif data == "apps_cz_account":
                info = _obj(await self._api("whoami"))
                await self._display(query,
                    "👤 <b>حساب Cloudzy</b>\n\n"
                    f"نام: {_value(_get(info, 'name', 'fullName', 'username'))}\n"
                    f"ایمیل: {_value(_get(info, 'email'))}\n"
                    f"شناسه: {_value(_get(info, 'id', 'userId'))}\n"
                    f"وضعیت: {_value(_get(info, 'status'))}",
                    [[("↩️ Cloudzy", "apps_cz_home")]], markup)
            elif data == "apps_cz_balance":
                data_obj = _obj(await self._api("get_balance"))
                fields = [
                    ("موجودی", _get(data_obj, "balanceCents", "walletBalanceCents", "availableBalanceCents", "balance")),
                    ("اعتبار", _get(data_obj, "creditCents", "creditsCents", "credit")),
                    ("واحد پول", _get(data_obj, "currency")),
                ]
                lines = [f"{label}: {_value(v)}" for label, v in fields]
                await self._display(query, "💰 <b>خلاصه حساب Cloudzy</b>\n\n"
                    + "\n".join(lines)
                    + "\n\n⚠️ مقادیر پولی API در واحد سنت ارائه می‌شوند؛ واحد نمایش را پیش از خرید تأیید کنید.",
                    [[("↩️ Cloudzy", "apps_cz_home")]], markup)
            elif data.startswith("apps_cz_keys_"):
                page = _page(data[len("apps_cz_keys_"):])
                all_rows = _items(await self._api("list_ssh_keys"))
                rows_page, page, count = _paged(all_rows, page)
                tokens = self._refs(context, "key", rows_page, actor, chat)
                rows = [[("🗑 " + str(_get(v, "name", "id") or "کلید")[:27],
                          "apps_cz_kdel_" + t)] for v, t in zip(rows_page, tokens)]
                rows += _paging("apps_cz_keys", page, count)
                rows += [[("➕ افزودن کلید عمومی SSH", "apps_cz_kadd")],
                         [("↩️ Cloudzy", "apps_cz_home")]]
                await self._display(query,
                    f"🔑 <b>کلیدهای ذخیره‌شده Cloudzy</b>\n"
                    f"تعداد: {len(all_rows)} · صفحه {page + 1} از {count}\n\n"
                    "برای مشاهده تأیید حذف، روی نام کلید بزنید.\n"
                    "حذف کلید ذخیره‌شده الزاماً دسترسی SSH سرورهای قبلی را قطع نمی‌کند.",
                    rows, markup)
            elif data == "apps_cz_kadd":
                self._end_key_flow(context)
                context.user_data["cz_key_input"] = {
                    "actor": actor, "chat": chat, "expires": self.now() + ACTION_TTL
                }
                context.user_data["state"] = "CZ_KEY_NAME"
                await self._display(query,
                    "🔑 <b>افزودن SSH Public Key</b>\n\n"
                    "نام کلید را ارسال کنید. فقط کلید عمومی وارد می‌شود، نه رمز یا کلید خصوصی.",
                    [[("❌ انصراف", "apps_cz_keys_0")]], markup)
            elif data.startswith("apps_cz_kdel_"):
                key_id, item = self._resolve(context, data[len("apps_cz_kdel_"):], "key", actor, chat)
                nonce = self._pending(context, "delete", actor, chat, key_id=key_id)
                await self._display(query,
                    "⚠️ <b>حذف کلید ذخیره‌شده Cloudzy</b>\n\n"
                    f"نام: {_value(_get(item, 'name', 'id'))}\n"
                    f"شناسه: <code>{_value(key_id)}</code>\n\n"
                    "این عملیات برگشت‌ناپذیر است و نباید برای کلید مدیریت Edge فعال بدون بررسی انجام شود.",
                    [[("✅ تأیید حذف کلید", "apps_cz_kconfirm_" + nonce)],
                     [("❌ انصراف", "apps_cz_keys_0")]], markup)
            elif data.startswith("apps_cz_kconfirm_"):
                pending = self._consume(context, "delete", data[len("apps_cz_kconfirm_"):], actor, chat)
                await self._api("delete_ssh_key", pending["key_id"], confirm=True)
                await self._display(query,
                    "✅ کلید ذخیره‌شده از حساب Cloudzy حذف شد.\n"
                    "وضعیت دسترسی به سرورهای موجود جداگانه بررسی شود.",
                    [[("↩️ کلیدها", "apps_cz_keys_0")]], markup)
            elif data.startswith("apps_cz_kaddyes_"):
                pending = self._consume(context, "add", data[len("apps_cz_kaddyes_"):], actor, chat)
                await self._api("add_ssh_key", pending["name"], pending["public_key"])
                await self._display(query, "✅ کلید عمومی در Cloudzy ثبت شد.",
                    [[("↩️ کلیدها", "apps_cz_keys_0")]], markup)
            else:
                await query.message.reply_text("⛔️ گزینه نامعتبر یا منقضی است.")
        except CloudzyUncertainError:
            await query.message.reply_text(
                "⚠️ نتیجه عملیات Cloudzy قطعی نیست. ابتدا فهرست را بررسی کنید؛ درخواست را کورکورانه تکرار نکنید.")
        except CloudzyAPIError as exc:
            await query.message.reply_text(f"⛔️ Cloudzy درخواست را رد کرد (HTTP {exc.status}). "
                                          "مجوز توکن یا وضعیت حساب را بررسی کنید.")
        except (CloudzyError, ValueError, TypeError, KeyError):
            await query.message.reply_text(
                "⛔️ اطلاعات Cloudzy در دسترس یا معتبر نیست. توکن، پاسخ API و وضعیت درخواست را بررسی کنید.")
        except Exception:
            # Avoid spilling raw HTTP response bodies, tokens or key material.
            await query.message.reply_text("⛔️ خطای غیرمنتظره در پنل Cloudzy؛ تغییری را تکرار نکنید.")

    async def handle_text(self, message, context, text, *, role, actor, chat, markup):
        state = context.user_data.get("state")
        if state not in ("CZ_KEY_NAME", "CZ_KEY_PUBLIC"):
            return False
        if role != "admin":
            self._end_key_flow(context)
            await message.reply_text("⛔️ فقط مدیر مجاز است.")
            return True
        flow = context.user_data.get("cz_key_input")
        if (not isinstance(flow, dict) or flow.get("actor") != actor
                or flow.get("chat") != chat or self.now() >= flow.get("expires", 0)):
            self._end_key_flow(context)
            await message.reply_text("⏳ مهلت ثبت کلید تمام شد؛ دوباره از پنل شروع کنید.")
            return True
        if text.strip() in ("لغو", "انصراف", "/cancel", "🏠 منوی اصلی", "🧩 برنامه‌ها"):
            self._end_key_flow(context)
            await message.reply_text("✅ ثبت کلید لغو شد.")
            return True
        if state == "CZ_KEY_NAME":
            name = text.strip()
            if len(name) > 80 or len(name) < 2 or any(ord(x) < 32 for x in name):
                await message.reply_text("نام کلید باید بین ۲ تا ۸۰ نویسه و بدون کاراکتر کنترلی باشد.")
                return True
            flow["name"] = name
            context.user_data["state"] = "CZ_KEY_PUBLIC"
            await message.reply_text("کلید عمومی OpenSSH را ارسال کنید (مثلاً ssh-ed25519 …). کلید خصوصی ارسال نکنید.")
            return True
        try:
            public_key = _public_key(text)
        except ValueError:
            await message.reply_text("⛔️ فرمت کلید عمومی معتبر نیست؛ فقط یک خط Public Key استاندارد بفرستید.")
            return True
        name = flow["name"]
        self._end_key_flow(context)
        nonce = self._pending(context, "add", actor, chat, name=name, public_key=public_key)
        await message.reply_text(
            "🔑 <b>تأیید ثبت کلید</b>\n\n"
            f"نام: {_value(name)}\n"
            f"نوع: {_value(public_key.split()[0])}\n\n"
            "فقط کلید عمومی ذخیره خواهد شد.",
            parse_mode="HTML",
            reply_markup=markup([
                [("✅ ثبت در Cloudzy", "apps_cz_kaddyes_" + nonce)],
                [("❌ انصراف", "apps_cz_keys_0")]
            ]),
        )
        return True
