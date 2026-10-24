"""Cloudzy admin's read-only API views, used alongside the CZ-03 Quick Edge wizard.

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
    def __init__(self, *, factory=CloudzyService, now=time.time):
        self.factory = factory
        self.now = now

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

    async def handle_callback(self, query, context, data, *, role, actor, chat, markup):
        if role != "admin":
            await query.message.reply_text("⛔️ فقط مدیر مجاز است.")
            return
        try:
            if data == "apps_cz_home":
                await self._display(query,
                    "☁️ <b>مدیریت Cloudzy و Edge</b>\n\n"
                    "⚡ ساخت سریع Edge: خرید VPS و نصب Legacy با تأیید مدیر.\n"
                    "🛡 Edge جدید ابتدا غیرفعال ثبت می‌شود؛ DNS، Relay و کاربران تغییر نمی‌کنند.\n"
                    "ℹ️ آماده‌سازی Relay به‌صورت Standby فعال است؛ تغییر مسیر و انتقال کاربران در CZ-04B است.",
                    [
                        [("⚡ ساخت سریع Edge", "apps_cz_wizard")],
                        [("🌐 Edge و Relay · آماده‌به‌کار", "apps_cz_edge")],
                        [("🖥 سرورهای Cloudzy", "apps_cz_servers_0"),
                         ("🛠 مدیریت VPS", "apps_cz4_vps")],
                        [("🌍 مناطق و پلن‌ها", "apps_cz_regions_0"),
                         ("💰 موجودی", "apps_cz_balance")],
                        [("👤 اطلاعات حساب", "apps_cz_account"),
                         ("🔑 کلیدهای SSH", "apps_cz_keys_0")],
                        [("📋 وضعیت عملیات", "apps_cz_operations")],
                        [("↩️ برنامه‌ها", "apps_home")],
                    ], markup)
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

