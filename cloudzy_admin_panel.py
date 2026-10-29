"""Cloudzy admin inventory, safe VPS deletion and read-only account views.

The main bot dispatches purchase, operation-journal and SSH public-key add
callbacks to QuickEdgeWizard before this panel. This panel itself does not
create VPSs or mutate Legacy Edge/Relay state.
The bot supplies a Telegram InlineKeyboardMarkup adapter.
"""
from __future__ import annotations

import asyncio
from html import escape
import re
import secrets
import time

from cloudzy_service import CloudzyAPIError, CloudzyError, CloudzyService, CloudzyUncertainError
from cloudzy_cz08_vps_delete import CloudzyDeleteGuard, DeletionHold, ipv4_from_service

MAX_PAGE = 999
PAGE_SIZE = 6
REF_TTL = 600


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




class CloudzyAdminPanel:
    def __init__(self, *, factory=CloudzyService, now=time.time, delete_guard=None):
        self.factory = factory
        self.now = now
        self.delete_guard = delete_guard if delete_guard is not None else CloudzyDeleteGuard(now=now)

    async def _api(self, method, *args, **kwargs):
        return await asyncio.to_thread(lambda: getattr(self.factory(), method)(*args, **kwargs))

    async def _display(self, target, text, rows, markup):
        await target.edit_message_text(text, parse_mode="HTML", reply_markup=markup(rows))

    def _refs(self, context, kind, rows, actor, chat):
        refs = {}
        tokens = []
        for row in rows:
            token = secrets.token_hex(4)
            safe = {k: v for k, v in row.items()
                    if k in ("id", "uuid", "serviceId", "keyId",
                             "hostname", "name", "label", "state", "status",
                             "region", "regionId", "code", "planName", "planId",
                             "primaryIpv4", "ipv4", "publicIp", "ipAddress")
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

    async def handle_callback(self, query, context, data, *, role, actor, chat, markup):
        if role != "admin":
            await query.message.reply_text("⛔️ فقط مدیر مجاز است.")
            return
        try:
            if data == "apps_cz_home":
                await self._display(query,
                    "🌐 <b>مدیریت Edge</b>\n\n"
                    "سرور را با Cloudzy یا به‌صورت دستی اضافه کنید. "
                    "بعد از آماده‌شدن Standby، تغییر DNS از Cloudflare "
                    "و انتقال کاربران با تأیید شما انجام می‌شود.",
                    [
                        [("☁️ افزودن با Cloudzy", "apps_cz6_start")],
                        [("🛟 افزودن دستی (اضطراری)", "apps_edge_manual_home")],
                        [("📦 انتقال کاربران SSH", "apps_cz7_home")],
                        [("🌐 مدیریت Edge و Relay", "apps_cz_edge")],
                        [("🖥 سرورهای Cloudzy · مدیریت و حذف", "apps_cz_servers_0")],
                        [("🛠 مدیریت VPS", "apps_cz4_vps")],
                        [("🌍 مناطق و پلن‌ها", "apps_cz_regions_0"),
                         ("💰 موجودی", "apps_cz_balance")],
                        [("👤 اطلاعات حساب", "apps_cz_account"),
                         ("🔑 کلیدهای SSH", "apps_cz_keys_0")],
                        [("📋 سوابق و وضعیت عملیات", "apps_cz_operations")],
                        [("↩️ برنامه‌ها", "apps_home")],
                    ], markup)
            elif data.startswith("apps_cz_servers_"):
                page = _page(data[len("apps_cz_servers_"):])
                all_rows = _items(await self._api("list_servers"))
                values, page, count = _paged(all_rows, page)
                tokens = self._refs(context, "server", values, actor, chat)
                rows, descriptions = [], []
                icons = {"PRIMARY": "🟢", "ELIGIBLE": "🖥", "PROTECTED": "🔒", "UNKNOWN": "⚠️"}
                for entry, token in zip(values, tokens):
                    server_id = str(_get(entry, "id", "uuid", "serviceId") or "")
                    ip = ipv4_from_service(entry)
                    state, reason = self.delete_guard.status(server_id, ip)
                    title = str(_get(entry, "hostname", "name", "label", "id") or "VPS")
                    label = ("رله اصلی" if state == "PRIMARY" else
                             "قابل حذف با تأیید" if state == "ELIGIBLE" else
                             "Standby محافظت‌شده" if reason == "STANDBY_FAILOVER_TARGET" else
                             "محافظت‌شده" if state == "PROTECTED" else "نامشخص")
                    rows.append([(f"{icons[state]} {title[:22]} · {label}",
                                  "apps_cz_sv_" + token)])
                    detail = (f"\n   علت: <code>{_value(reason)}</code>"
                              if state in ("PROTECTED", "UNKNOWN") else "")
                    descriptions.append(
                        f"{icons[state]} <b>{_value(title, max_chars=48)}</b>\n"
                        f"   <code>{_value(ip or 'IP نامشخص')}</code> · {label}"
                        + detail)
                rows += _paging("apps_cz_servers", page, count)
                rows += [[("🔄 تازه‌سازی فهرست", "apps_cz_servers_0")],
                         [("↩️ Cloudzy", "apps_cz_home")]]
                await self._display(query,
                    f"🖥 <b>سرورهای Cloudzy</b>\n"
                    f"تعداد دریافت‌شده: {len(all_rows)}\n"
                    f"صفحه {page + 1} از {count}\n\n"
                    + ("\n\n".join(descriptions) if descriptions else
                       "📭 در حساب Cloudzy سروری یافت نشد.")
                    + "\n\n🟢 رله پیش‌فرض NVL فقط نمایش داده می‌شود و حذف ندارد."
                    "\n🔐 حذف سایر VPSها پس از بازبینی زنده و تأیید مجدد مدیر است.",
                    rows, markup)
            elif data.startswith("apps_cz_sv_"):
                token = data[len("apps_cz_sv_"):]
                server_id, fallback = self._resolve(context, token, "server", actor, chat)
                server = _obj(await self._api("get_server", server_id))
                identified = _get(server, "id", "uuid", "serviceId")
                if identified is not None and str(identified) != server_id:
                    raise DeletionHold("PROVIDER_ID_CHANGED")
                display = server or fallback
                ip = ipv4_from_service(server) or ipv4_from_service(fallback)
                state, reason = self.delete_guard.status(server_id, ip)
                caption = ("🟢 <b>رله اصلی NVL — حفاظت‌شده</b>" if state == "PRIMARY"
                           else "🔒 <b>دارای وابستگی یا عملیات فعال — حذف غیرفعال</b>"
                           if state == "PROTECTED"
                           else "⚠️ <b>نقش سرور قابل تأیید نیست — حذف غیرفعال</b>"
                           if state == "UNKNOWN"
                           else "🗑 <b>سرور غیرپیش‌فرض — امکان درخواست حذف</b>")
                rows = [[("🔎 وضعیت", "apps_cz_st_" + token),
                         ("📊 مصرف منابع", "apps_cz_use_" + token)]]
                if state == "ELIGIBLE":
                    rows.append([("🗑 درخواست حذف از Cloudzy", "apps_cz_del_" + token)])
                rows.append([("↩️ فهرست سرورها", "apps_cz_servers_0")])
                await self._display(query,
                    "🖥 <b>جزئیات VPS</b>\n\n"
                    f"{caption}\n\n"
                    f"نام: {_value(_get(display, 'hostname', 'name'))}\n"
                    f"شناسه: <code>{_value(server_id)}</code>\n"
                    f"IP: <code>{_value(ip or 'نامشخص')}</code>\n"
                    f"منطقه: {_value(_get(display, 'region', 'regionId'))}\n"
                    f"پلن: {_value(_get(display, 'planName', 'planId', 'plan'))}\n"
                    f"وضعیت Cloudzy: {_value(_get(display, 'state', 'status'))}\n"
                    + (f"کد حفاظت: <code>{_value(reason)}</code>\n"
                       if state in ("PROTECTED", "UNKNOWN") else "")
                    + "\n🛡 نقش Relay از دیتابیس زنده NVL خوانده می‌شود؛ "
                      "هیچ IP ثابتی برای حفاظت استفاده نشده است.",
                    rows, markup)
            elif data.startswith("apps_cz_del_"):
                token = data[len("apps_cz_del_"):]
                server_id, fallback = self._resolve(context, token, "server", actor, chat)
                server = _obj(await self._api("get_server", server_id))
                if _get(server, "id", "uuid", "serviceId") not in (None, server_id):
                    raise DeletionHold("PROVIDER_ID_CHANGED")
                ip = ipv4_from_service(server) or ipv4_from_service(fallback)
                state, reason = self.delete_guard.status(server_id, ip)
                if state != "ELIGIBLE":
                    raise DeletionHold(reason)
                nonce = secrets.token_hex(6)
                context.user_data["cz_delete_pending"] = {
                    "actor": actor, "chat": chat, "id": server_id, "ip": ip,
                    "nonce": nonce, "expires": self.now() + 90,
                }
                await self._display(query,
                    "⚠️ <b>تأیید نهایی حذف VPS از Cloudzy</b>\n\n"
                    f"سرور: {_value(_get(server, 'hostname', 'name') or server_id)}\n"
                    f"IP: <code>{_value(ip)}</code>\n"
                    f"شناسه: <code>{_value(server_id)}</code>\n\n"
                    "🗑 حذف از Cloudzy واقعی و برگشت‌ناپذیر است و ممکن است هزینه "
                    "و داده‌های این VPS را از بین ببرد.\n"
                    "🛡 پیش از DELETE نقش Relay و وابستگی‌ها دوباره بررسی می‌شوند.\n"
                    "❗ این عملیات Core، DNS و سایر Relayها را تغییر نمی‌دهد.",
                    [[("🔴 تأیید حذف دائمی VPS", "apps_cz_yes_" + nonce)],
                     [("❌ انصراف", "apps_cz_servers_0")]], markup)
            elif data.startswith("apps_cz_yes_"):
                nonce = data[len("apps_cz_yes_"):]
                pending = context.user_data.pop("cz_delete_pending", None)
                if (not isinstance(pending, dict) or pending.get("nonce") != nonce
                        or pending.get("actor") != actor or pending.get("chat") != chat
                        or self.now() >= pending.get("expires", 0)):
                    raise DeletionHold("DELETE_CONFIRMATION_EXPIRED")
                server_id, expected_ip = pending["id"], pending["ip"]
                current = _items(await self._api("list_servers"))
                matched = [item for item in current
                           if str(_get(item, "id", "uuid", "serviceId") or "") == server_id]
                if len(matched) != 1:
                    raise DeletionHold("SERVER_NOT_IN_LIVE_INVENTORY")
                details = _obj(await self._api("get_server", server_id))
                if _get(details, "id", "uuid", "serviceId") not in (None, server_id):
                    raise DeletionHold("PROVIDER_ID_CHANGED")
                observed_ip = ipv4_from_service(details) or ipv4_from_service(matched[0])
                if observed_ip != expected_ip:
                    raise DeletionHold("SERVER_IPV4_CHANGED")
                state, reason = self.delete_guard.status(server_id, observed_ip)
                if state != "ELIGIBLE":
                    raise DeletionHold(reason)
                opid = await asyncio.to_thread(
                    self.delete_guard.reserve, server_id, observed_ip,
                    actor=actor, chat=chat)
                try:
                    await self._api("delete_server", server_id, confirm=True)
                except CloudzyAPIError as exc:
                    await asyncio.to_thread(
                        self.delete_guard.finish, opid, success=False,
                        code=f"PROVIDER_REJECTED_HTTP_{exc.status}")
                    raise
                except Exception:
                    # Timeouts and ambiguous 5xx MUST remain HOLD; never retry blindly.
                    await asyncio.to_thread(
                        self.delete_guard.finish, opid, success=False,
                        code="PROVIDER_RESULT_UNCERTAIN")
                    raise
                await asyncio.to_thread(
                    self.delete_guard.finish, opid, success=True,
                    code="PROVIDER_DELETE_ACCEPTED")
                await self._display(query,
                    "✅ <b>درخواست حذف Cloudzy پذیرفته شد</b>\n\n"
                    f"شناسه سرور: <code>{_value(server_id)}</code>\n"
                    f"IP: <code>{_value(observed_ip)}</code>\n"
                    f"پیگیری: <code>{_value(opid[:16])}</code>\n\n"
                    "🛡 Relay پیش‌فرض، DNS و حساب‌های NVL تغییر نکرده‌اند.\n"
                    "ℹ️ برای تأیید حذف نهایی نزد ارائه‌دهنده، فهرست را تازه‌سازی کنید.",
                    [[("🔄 بررسی فهرست Cloudzy", "apps_cz_servers_0")],
                     [("↩️ Cloudzy", "apps_cz_home")]], markup)
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
            elif data.startswith(("apps_cz_rg_", "apps_cz_pl_")):
                if data.startswith("apps_cz_rg_"):
                    token = data[len("apps_cz_rg_"):]
                    cycle = "monthly"
                else:
                    selector = data[len("apps_cz_pl_"):]
                    cycle, separator, token = selector.partition("_")
                    if not separator or cycle not in ("monthly", "hourly", "quarterly", "annually"):
                        raise ValueError("INVALID_BILLING_CYCLE")
                region_id, region = self._resolve(context, token, "region", actor, chat)
                res = await self._api("list_plans", region=region_id, billing_cycle=cycle)
                plans = _items(res.get("plans", []) if isinstance(res, dict) else res)
                cycle_title = {"monthly": "ماهانه", "hourly": "ساعتی",
                               "quarterly": "سه‌ماهه", "annually": "سالانه"}[cycle]
                lines = [f"📦 <b>پلن‌ها — {cycle_title}</b>\nمنطقه: {_value(_get(region, 'name', 'id'))}\n"]
                for p in plans[:15]:
                    price = p.get("price") or {}
                    cents = _get(price, "amountCents", "priceCents", "monthlyEquivCents")
                    price_kind = ("معادل ماهانه" if _get(price, "monthlyEquivCents") is not None
                                  and _get(price, "amountCents", "priceCents") is None
                                  else cycle_title)
                    line = (f"• {_value(_get(p, 'name', 'slug', 'id'))} — "
                            f"{_value(cents)} سنت ({price_kind}، پایه)" if cents is not None
                            else f"• {_value(_get(p, 'name', 'slug', 'id'))} — قیمت نامشخص")
                    lines.append(line)
                if len(plans) > 15:
                    lines.append(f"… و {len(plans) - 15} پلن دیگر")
                lines.append("\n⚠️ قیمت پایه است؛ هزینه IPv4 و افزونه‌ها ممکن است جدا باشد.")
                await self._display(query, "\n".join(lines),
                    [[("ساعتی", "apps_cz_pl_hourly_" + token),
                      ("ماهانه", "apps_cz_pl_monthly_" + token)],
                     [("سه‌ماهه", "apps_cz_pl_quarterly_" + token),
                      ("سالانه", "apps_cz_pl_annually_" + token)],
                     [("↩️ مناطق", "apps_cz_regions_0")]], markup)
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
                rows = [[("🔑 " + str(_get(v, "name", "id") or "کلید")[:27],
                          "apps_cz_key_" + t)] for v, t in zip(rows_page, tokens)]
                rows += _paging("apps_cz_keys", page, count)
                rows += [[("🔑 ثبت کلید عمومی Core", "apps_cz_qsavekey")],
                         [("↩️ Cloudzy", "apps_cz_home")]]
                await self._display(query,
                    f"🔑 <b>کلیدهای عمومی SSH</b>\n"
                    f"تعداد: {len(all_rows)} · صفحه {page + 1} از {count}\n\n"
                    "🔑 ثبت کلید عمومی Core با تأیید مدیر فعال است؛ حذف کلید هنوز ارائه نشده است.",
                    rows, markup)
            elif data.startswith("apps_cz_key_"):
                key_id, item = self._resolve(context, data[len("apps_cz_key_"):], "key", actor, chat)
                await self._display(query,
                    "🔑 <b>مشخصات SSH Public Key</b>\n\n"
                    f"نام: {_value(_get(item, 'name'))}\n"
                    f"شناسه: <code>{_value(key_id)}</code>\n\n"
                    "جزئیات کلید خواندنی است؛ حذف کلید در نسخه فعلی فعال نیست.",
                    [[("↩️ کلیدها", "apps_cz_keys_0")]], markup)
            else:
                await query.message.reply_text("⛔️ گزینه نامعتبر یا منقضی است.")
        except DeletionHold as exc:
            await query.message.reply_text(
                f"⛔️ حذف VPS متوقف شد. کد: <code>{_value(str(exc))}</code>. "
                "Relay پیش‌فرض یا سرور دارای وابستگی قابل حذف نیست.",
                parse_mode="HTML")
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

