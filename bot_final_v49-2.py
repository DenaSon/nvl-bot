"""
NeVeL Enterprise Bot - نسخه تجاری (v54.1)
==================================================
تمامی امکانات نسخه‌های قبلی (رزرو اتمیک یوزرنیم، Rollback کامل، پایش ظرفیت، هش رمزها،
WAL دیتابیس، ضدِ SQLi، درگاه کارت‌به‌کارت، نمودار فروش، بکاپ، تاییدیهٔ خروج، پایش کاربران
آنلاین) حفظ شده و این دور، موارد زیر اضافه شدند (طبق درخواست صریح کاربر):

  1. 👥 دسترسی کامل ادمین به کاربران هر نماینده: در پنل «مدیریت نماینده‌ها» روی هر نماینده،
     دکمهٔ «مشاهده کاربران این نماینده» اضافه شد که لیست فیلترشدهٔ فقط همان نماینده را نشان
     می‌دهد (با همان قابلیت‌های مدیریتی کامل: حذف/فعال‌سازی/تمدید/تغییر پسورد).
  2. 💰 شارژ دستی مستقیم کیف‌پول نماینده توسط ادمین: دکمهٔ «شارژ مستقیم کیف‌پول» در پنل هر
     نماینده — مستقل از جریان تایید رسید کارت‌به‌کارت — برای مواقعی که ادمین می‌خواهد بدون
     نیاز به رسید، مبلغ دلخواهی را فوراً به حساب یک نماینده اضافه کند (نماینده هم مطلع می‌شود).
  3. 💹 ردیابی جداگانهٔ «درآمد از زیرمجموعه‌گیری»: ستون جدید referral_income به جدول agents
     اضافه شد که فقط کمیسیون شبکه‌ای (override از فروش زیرشاخه‌ها) را جدا از موجودی کلی
     کیف‌پول جمع می‌زند، و در پنل «اطلاعات حساب» نماینده و در جزئیات هر نماینده (نمای ادمین)
     نمایش داده می‌شود.
  4. ✅ تایید شد که موارد زیر از نسخهٔ قبلی از قبل به‌درستی پیاده بودند و بدون تغییر باقی
     ماندند: تاییدیهٔ خروج (بله/خیر) در هر دو پنل، شمارش دقیق کاربران آنلاین (کلی و به‌تفکیک
     هر نماینده)، و ارسال رسید کارت‌به‌کارت منحصراً به ادمین.

نسخهٔ V33 — رفع باگ‌ها/بهبودهای درخواستی جدید:
  5. 👤👤 چند ادمین هم‌زمان: قبلاً chat_id فقط آخرین ادمینی که لاگین می‌کرد در یک ستون تکی
     ذخیره می‌شد؛ پس رسیدهای کارت‌به‌کارت و هشدارهای پایش ظرفیت فقط برای همان یک نفر ارسال
     می‌شد. الان لیستی از تمام ادمین‌های واردشده نگه‌داری می‌شود و همه هم‌زمان اعلان می‌گیرند.
     (چند ادمین از قبل هم می‌توانستند هم‌زمان با یک یوزر/پس واحد لاگین و کار کنند، چون
     user_data در تلگرام به‌ازای هر چت جداست؛ فقط اعلان‌رسانی مشترک بود که رفع شد.)
  6. ➕ افزایش تعداد کاربر: حالا به‌جای فقط گرفتن عدد از چت، سه دکمهٔ آماده (+۱/+۲/+۳ کاربر)
     + دکمهٔ «دلخواه» (برای هر عددی) + دکمهٔ «بازگشت» (به همان صفحهٔ کاربر) نمایش داده می‌شود.
  7. 🔑 تغییر پسورد: دکمهٔ «بازگشت» به صفحهٔ همان کاربر اضافه شد و پیش از اعمال، تاییدیهٔ
     بله/خیر برای پسورد جدید گرفته می‌شود.
  8. 🗑 حذف اکانت: پیش از حذف واقعی، تاییدیهٔ بله/خیر گرفته می‌شود (مشابه حذف نماینده).
  9. 🔁 «تمرکز روی همان مرحله»: اگر رمز عبور هنگام ورود اشتباه باشد، دیگر کاربر را به مرحلهٔ
     یوزرنیم برنمی‌گرداند؛ همان‌جا (مرحلهٔ رمز) با پیام خطا نگه داشته می‌شود.
  10. 💼 موارد ۶ تا ۹ برای اکانت‌های زیرمجموعهٔ هر نماینده هم فعال است (همان مسیر کد مشترک)،
      و علاوه بر آن حذف نماینده هم تاییدیهٔ بله/خیر گرفت. ناوبری «بازگشت» داخل لیست فیلترشدهٔ
      یک نماینده هم دیگر بعد از عملیات روی کاربر گم نمی‌شود.
  11. 🧩 خطای «اکانت تکراری» روی لینوکس (useradd already exists): سقف تلاش مجدد برای یافتن
      یوزرنیم آزاد بالا برده شد و اگر خودِ useradd هم (به‌خاطر رقابت هم‌زمان) با «already exists»
      شکست بخورد، به‌جای نمایش خطای خام، ربات خودکار یوزرنیم بعدی را امتحان می‌کند.

نسخهٔ V35 — رفع باگ درخواستی جدید:
  12. 🧾 رسید کارت‌به‌کارت واقعاً منحصر به ادمین شد: اگر چتِ یک نماینده قبلاً (مثلاً در تست)
      یک‌بار هم با یوزر/پس مدیر لاگین کرده بود، chat_id آن در جدول admin_chat_ids باقی می‌ماند؛
      در نتیجه هنگام ارسال عکس رسید، پیامِ مخصوص ادمین (عکس + دکمه‌های ✅ تایید/❌ رد) علاوه بر
      ارسال به مدیر واقعی، به همان چتِ نماینده هم می‌رفت. الان چتِ فرستندهٔ رسید همیشه از لیست
      گیرنده‌های پیام ادمین حذف می‌شود؛ نماینده فقط همان پیام تاییدِ «رسید دریافت شد» را می‌بیند
      و دکمه‌های تصمیم‌گیری ادمین دیگر هرگز برای او ارسال نمی‌شود.

نسخهٔ V58 — رفع ریشه‌ای همان باگ (وصلهٔ V35 کافی نبود):
  13. 📢 پیام‌های مخصوص ادمین واقعاً فقط برای ادمین: وصلهٔ V35 فقط «فرستندهٔ همان پیام» را از
      لیست گیرنده‌ها کنار می‌گذاشت؛ اگر chat_id یک نمایندهٔ دیگر (نه فرستنده) هم به‌خاطر تست
      قبلی با یوزر/پس مدیر آلوده بود، همچنان پیام‌های ادمین (قفل خودکار ظرفیت، هشدار فشار
      CPU/RAM، درخواست برداشت وجه، مصرف شارژ اضطراری) را دریافت می‌کرد. حالا خودِ تابع
      _db_get_admin_chat_ids همیشه هر chat_id که در جدول agents به‌عنوان telegram_id ثبت شده را
      کنار می‌گذارد — یعنی این پاک‌سازی یک‌جا برای همهٔ نقاط استفاده اعمال می‌شود. همچنین پیام
      قفل خودکار ظرفیت که قبلاً هم به ادمین هم به نمایندهٔ مالک اکانت می‌رفت، الان طبق درخواست
      صریح فقط به مدیریت ارسال می‌شود.

نسخهٔ V59 — تغییر جهت‌دهی مجدد طبق درخواست:
  14. 🔔 پیام قفل خودکار ظرفیت، حالا برعکسِ V58: فقط برای خودِ صاحب اکانت (نمایندهٔ فروشنده)
      ارسال می‌شود — نه برای مدیریت و نه برای هیچ نمایندهٔ دیگری — تا فقط او مطلع شود و بتواند
      از «👥 مدیریت کاربران» پسورد را تغییر داده و اکانت را دوباره فعال کند. اگر اکانت مستقیماً
      توسط ادمین ساخته شده باشد (بدون نماینده) یا نمایندهٔ صاحبش هنوز هیچ‌وقت وارد ربات نشده
      (telegram_id ثبت‌نشده)، چون گیرندهٔ دیگری وجود ندارد، به‌جای گم‌شدن پیام، به مدیریت می‌رود.
      پیامِ جداگانهٔ «تلاش خودکار قفل روی سرور شکست خورد» (یک خطای فنی/زیرساختی که فقط ادمین با
      دسترسی سرور می‌تواند حلش کند) همچنان فقط برای مدیریت ارسال می‌شود، چون نماینده کاری از
      دستش برنمی‌آید.

نسخهٔ V60 — درخواست‌های جدید کاربر (زمان‌بندی به‌وقت ایران، گزارش خوش‌آمدگویی، تاریخچهٔ اتصالات
کاملاً فارسی/شمسی + نمودار):
  15. ⏰ گزارش روزانهٔ فروش حالا دقیقاً راس ساعت ۰۰:۰۰ به‌وقت ایران (Asia/Tehran) ارسال می‌شود —
      نه به‌وقت سیستم سرور (که معمولاً UTC است). از zoneinfo استاندارد پایتون استفاده شده، بدون
      وابستگی جدید.
  16. 👋 وقتی یک ادمین برای اولین‌بار با یوزر/پس مدیریت وارد ربات می‌شود، دقیقاً ۱۰ دقیقه بعد یک
      گزارش فروشِ خوش‌آمدگویی («امروز تا همین لحظه») فقط برای همان چت ارسال می‌شود؛ از همان شب
      اول هم وارد چرخهٔ همیشگیِ گزارش نیمه‌شب می‌شود.
  17. 📜 بخش «تاریخچهٔ اتصالات» (هم برای ادمین، هم برای نماینده) حالا تاریخ/ساعت را کاملاً فارسی و
      شمسی نشان می‌دهد، «اولین اتصالِ موجود در لاگ» و «آخرین اتصال» و «تعداد کل اتصالات» را هم
      جداگانه خلاصه می‌کند.
  18. 📈 یک دکمهٔ «نمودار اتصالات» به همان بخش اضافه شد: نموداری با تم تیره و زیبا که دقیقاً ساعتِ
      شبانه‌روزِ هر اتصال (مثلاً ۱۶:۳۰ یا ۰۰:۳۰) را روی محور عمودی و تاریخ هر اتصال را روی محور
      افقی نشان می‌دهد، به‌همراه تعداد کل اتصالات.
"""

import sqlite3
import asyncio
import logging
import random
import string
import json
import aiohttp
import qrcode
import v2ray_engine
import secrets

import base64
import re
import os
import tempfile
import shutil
import hmac
import hashlib
import html
import time
import csv
import contextlib
import io
import socket
import urllib.request
import urllib.error
import subprocess
import shlex
import sys
import traceback
try:
    import paramiko  # 🚀 برای مدیریتِ از راه دورِ Edgeها (SSH با کلیدِ دائمی) و افزودنِ Edge جدید
except ImportError:
    paramiko = None
from decimal import Decimal, InvalidOperation
from datetime import datetime, timedelta, timezone

# 🐛🔧 فیکس سراسری «هنگِ کاملاً بی‌فیدبک»: چند عملیاتِ حساس (ارتقا، افزودنِ Edge، تغییرِ پورت)
# با asyncio.create_task(coro()) بدونِ نگه‌داشتنِ هیچ رفرنسی صدا زده می‌شدند. طبقِ مستنداتِ
# رسمیِ پایتون، event loop فقط weak reference به Task نگه می‌دارد؛ اگر جای دیگری رفرنسِ قوی
# نداشته باشد، ممکن است GC هر لحظه (حتی وسطِ اجرا، حتی وسطِ یک sleep/await طولانی) آن را
# بی‌سروصدا نابود کند — بدونِ هیچ Exception یا پیامی به کاربر. این دقیقاً همان «هنگِ رندوم و
# بی‌فیدبکِ» عملیاتِ ارتقا بود که هیچ‌جا (نه try/except خودِ تابع، نه لاگ) قابلِ ردیابی نمی‌شد.
# راه‌حلِ استاندارد: یک ستِ سطحِ ماژول که رفرنسِ قوی نگه می‌دارد و با done_callback خودش را
# بعد از اتمام (موفق یا ناموفق) پاک می‌کند.
_BACKGROUND_TASKS: set = set()

def spawn_bg_task(coro):
    """جایگزینِ امنِ asyncio.create_task برای عملیات‌های پس‌زمینهٔ fire-and-forget."""
    t = asyncio.create_task(coro)
    _BACKGROUND_TASKS.add(t)
    t.add_done_callback(_BACKGROUND_TASKS.discard)
    return t

# ⏰ منطقهٔ زمانی ایران — از zoneinfo استاندارد پایتون (۳٫۹+) استفاده می‌شود تا هیچ وابستگی
# جدیدی (مثل pytz) به requirements.txt اضافه نشود. اگر دیتابیس tzdata روی سرور نصب نباشد
# (بعضی توزیع‌های مینیمال لینوکس/داکر آلپاین)، به‌جای کرش کل ربات، محاسبه با آفست ثابت
# ۰۳:۳۰+ (بدون تغییر ساعت تابستانی؛ ایران از سال ۱۴۰۰ دیگر ساعت تابستانی ندارد) ادامه می‌یابد.
try:
    from zoneinfo import ZoneInfo
    IRAN_TZ = ZoneInfo("Asia/Tehran")
except Exception:
    IRAN_TZ = timezone(timedelta(hours=3, minutes=30))

# تلاش برای ایمپورت کتابخانه نمودار (اگر نصب نباشد ارور نمیدهد، فقط نمودار رسم نمیشود)
try:
    import matplotlib
    matplotlib.use('Agg')  # 🔧 بک‌اند غیرتعاملی؛ روی VPS بدون دسکتاپ/Display همیشه تضمینی کار می‌کند
    import matplotlib.pyplot as plt
    import matplotlib.font_manager  # 🆕 برای تشخیص وجود فونت فارسی روی سرور (نمودار انیمیشنی دوزبانه)
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

# 🆕 نمودار انیمیشنی (GIF): از همان matplotlib با PillowWriter ساخته می‌شود؛ اگر Pillow نصب
# نباشد (به‌ندرت، چون معمولاً همراه matplotlib می‌آید)، این قابلیت خاموش می‌ماند ولی بقیهٔ ربات
# (نمودار ثابت قبلی و غیره) سالم کار می‌کند.
try:
    from matplotlib.animation import FuncAnimation, PillowWriter
    ANIMATION_AVAILABLE = MATPLOTLIB_AVAILABLE
except ImportError:
    ANIMATION_AVAILABLE = False

# ==========================================
# 🇮🇷 نمایش صحیح متن فارسی داخل نمودارهای matplotlib (برچسب‌های دوزبانه)
# ==========================================
# matplotlib خودش متن فارسی/عربی را «شکل» نمی‌دهد (حروف باید بر اساس موقعیتشان در کلمه به هم
# بچسبند) و آن را چپ‌به‌راست رسم می‌کند (باید راست‌به‌چپ باشد). برای همین از دو کتابخانهٔ سبک
# arabic_reshaper (اتصال حروف) و python-bidi (ترتیب راست‌به‌چپ) استفاده می‌شود. اگر این دو روی
# سرور نصب نباشند، بخش فارسیِ برچسب‌ها به‌جای نمایش حروف بریده‌بریده و اشتباه، به‌طور کامل حذف
# می‌شود و فقط نسخهٔ انگلیسی (که همیشه درست است) نمایش داده می‌شود — تا هیچ‌وقت متن خراب دیده نشود.
try:
    import arabic_reshaper
    from bidi.algorithm import get_display as _bidi_get_display
    FARSI_SHAPING_AVAILABLE = True
except Exception:
    FARSI_SHAPING_AVAILABLE = False

# همچنین برای نمایش صحیحِ گلیف‌های فارسی، فونت رسم‌کننده هم باید خودش از فارسی پشتیبانی کند
# (فونت پیش‌فرض matplotlib این پشتیبانی را ندارد و حروف را به‌صورت جعبه‌های خالی نشان می‌دهد).
# لیستی از رایج‌ترین فونت‌های فارسیِ نصب‌شونده روی سرورهای لینوکسی چک می‌شود؛ اولین موردی که
# واقعاً روی این سرور نصب باشد انتخاب می‌شود. اگر هیچ‌کدام نصب نبود، همان منطق فوق (فقط انگلیسی)
# به‌طور خودکار جایگزین می‌شود.
_FA_FONT_CANDIDATES = ["Vazirmatn", "Vazir", "IRANSans", "IRANSansX", "IRANSansWeb",
                       "Noto Naskh Arabic", "Noto Sans Arabic", "B Nazanin", "Tahoma"]
def _detect_fa_font_name():
    if not MATPLOTLIB_AVAILABLE:
        return None
    try:
        available = {f.name for f in matplotlib.font_manager.fontManager.ttflist}
    except Exception:
        return None
    for c in _FA_FONT_CANDIDATES:
        if c in available:
            return c
    return None
FA_FONT_NAME = _detect_fa_font_name()
FARSI_CHARTS_AVAILABLE = FARSI_SHAPING_AVAILABLE and bool(FA_FONT_NAME)

def _fa_shape(text: str) -> str:
    """متن فارسی خام را برای رسم صحیح در matplotlib آماده می‌کند (حروف‌چسبان + راست‌به‌چپ)."""
    if not FARSI_SHAPING_AVAILABLE:
        return text
    with contextlib.suppress(Exception):
        return _bidi_get_display(arabic_reshaper.reshape(text))
    return text

def _bilingual_label(en: str, fa: str) -> str:
    """
    یک برچسب دوخطی می‌سازد: خط اول انگلیسی (همیشه تضمینی درست)، خط دوم فارسی (فقط اگر هم
    کتابخانه‌های شکل‌دهی و هم یک فونت فارسی روی سرور موجود باشند — وگرنه فقط همان خط انگلیسی
    برگردانده می‌شود تا هیچ‌وقت متن بریده/خراب دیده نشود).
    """
    if not FARSI_CHARTS_AVAILABLE or not fa:
        return en
    return f"{en}\n{_fa_shape(fa)}"

from telegram import Update, ReplyKeyboardMarkup, InlineKeyboardButton, InlineKeyboardMarkup, InputFile, InputMediaPhoto
from telegram.error import BadRequest
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, CallbackQueryHandler, filters, ContextTypes, PicklePersistence, PersistenceInput

# ==========================================
# ⚙️ پیکربندی امن (از Environment Variables)
# ==========================================
# 🏷️ نشانگر نسخه — برای تایید قطعی اینکه دقیقاً همین فایل روی سرور در حال اجراست
# (به‌جای حدس‌زدن از روی رفتار، همیشه با این دستور چک کنید:
#   grep -n "BOT_VERSION_TAG" nvlbot.py
# و بعد از استارت هم توی لاگ سرویس دیده می‌شود.)
BOT_VERSION_TAG = "V102-2026-07-26-edge-permitrootlogin-fix"

# ==========================================
# ⏳ ماژول مدیریت چرخهٔ عمر «On hold پنهان» (V88)
# ==========================================
from dataclasses import dataclass
from typing import Callable, Iterable, Optional, Union

@dataclass(frozen=True)
class HiddenHoldSchedule:
    visible_expire_date: str
    hold_deadline: str
    hold_duration_days: int
    linux_expire_date: str

@dataclass(frozen=True)
class HoldActivation:
    username: str
    started_at: str
    expire_date: str
    source: str

def calculate_hidden_hold_schedule(plan_days: int, hold_days: int = 3, created_at: Optional[datetime] = None, linux_safety_margin_days: int = 1) -> HiddenHoldSchedule:
    created = created_at or datetime.now()
    visible_expiry_at = created + timedelta(days=plan_days)
    hold_deadline_at = created + timedelta(days=hold_days)
    linux_expiry_at = max(visible_expiry_at, hold_deadline_at + timedelta(days=linux_safety_margin_days))
    return HiddenHoldSchedule(
        visible_expire_date=visible_expiry_at.date().strftime("%Y-%m-%d"),
        hold_deadline=hold_deadline_at.strftime("%Y-%m-%d %H:%M:%S"),
        hold_duration_days=plan_days,
        linux_expire_date=linux_expiry_at.date().strftime("%Y-%m-%d"),
    )

def install_hidden_hold_guards(connection: sqlite3.Connection) -> None:
    existing = {row[1] for row in connection.execute("PRAGMA table_info(ssh_accounts)").fetchall()}
    additions = {"hold_active": "INTEGER DEFAULT 0", "hold_deadline": "TEXT DEFAULT NULL", "hold_duration_days": "INTEGER DEFAULT NULL", "first_connected_at": "TEXT DEFAULT NULL"}
    for name, decl in additions.items():
        if name not in existing: connection.execute(f"ALTER TABLE ssh_accounts ADD COLUMN {name} {decl}")
    connection.execute("DROP TRIGGER IF EXISTS ssh_accounts_hidden_hold_visible_expiry_insert")
    connection.execute("DROP TRIGGER IF EXISTS ssh_accounts_hidden_hold_visible_expiry_update")
    connection.execute("""
        CREATE TRIGGER ssh_accounts_hidden_hold_visible_expiry_insert AFTER INSERT ON ssh_accounts FOR EACH ROW WHEN COALESCE(NEW.hold_active, 0) = 1 AND COALESCE(NEW.hold_duration_days, 0) > 0
        BEGIN UPDATE ssh_accounts SET expire_date = date(substr(COALESCE(NULLIF(NEW.creation_date, ''), datetime('now', 'localtime')), 1, 10), printf('+%d days', NEW.hold_duration_days)) WHERE username = NEW.username; END
    """)
    connection.execute("""
        CREATE TRIGGER ssh_accounts_hidden_hold_visible_expiry_update AFTER UPDATE OF hold_active, hold_duration_days, creation_date ON ssh_accounts FOR EACH ROW WHEN COALESCE(NEW.hold_active, 0) = 1 AND COALESCE(NEW.hold_duration_days, 0) > 0
        BEGIN UPDATE ssh_accounts SET expire_date = date(substr(COALESCE(NULLIF(NEW.creation_date, ''), datetime('now', 'localtime')), 1, 10), printf('+%d days', NEW.hold_duration_days)) WHERE username = NEW.username; END
    """)

def put_account_on_hidden_hold(connection: sqlite3.Connection, username: str, plan_days: int, hold_days: int = 3, created_at: Optional[datetime] = None, linux_safety_margin_days: int = 1) -> HiddenHoldSchedule:
    sched = calculate_hidden_hold_schedule(plan_days, hold_days, created_at, linux_safety_margin_days)
    connection.execute("UPDATE ssh_accounts SET expire_date=?, hold_active=1, hold_deadline=?, hold_duration_days=?, first_connected_at=NULL WHERE username=?", (sched.visible_expire_date, sched.hold_deadline, sched.hold_duration_days, username))
    return sched

def format_visible_expiry_message(connection: sqlite3.Connection, username: str, date_formatter: Optional[Callable[[str], str]] = None) -> str:
    row = connection.execute("SELECT expire_date FROM ssh_accounts WHERE username=?", (username,)).fetchone()
    expiry = row[0] if row else "نامشخص"
    if date_formatter: expiry = date_formatter(expiry)
    return f"📅 <b>تاریخ انقضا:</b> <code>{expiry}</code>"

def _parse_flexible_datetime(s: str) -> datetime:
    """
    🐛🔧 رفع باگ کرش تکرارشونده: برخی رکوردهای hold_deadline فقط به‌شکل تاریخ خام
    (مثلاً '2026-07-24'، بدون ساعت) ذخیره شده بودند، در حالی‌که این کد همیشه انتظار
    فرمت کامل «تاریخ+ساعت» را داشت. نتیجه: هر چند دقیقه یک ValueError پرتاب می‌شد،
    حلقهٔ خودکار فعال‌سازی «آنهولد» کرش می‌کرد و هیچ اکانتی در این حالت خودکار
    فعال نمی‌شد. این تابع هر دو فرمت را امتحان می‌کند؛ اگر فقط تاریخ بود، ساعت را
    نیمه‌شب (00:00:00) در نظر می‌گیرد.
    """
    try:
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return datetime.strptime(s, "%Y-%m-%d")

def activate_on_first_connection(connection: sqlite3.Connection, username: str, connected_at: Optional[datetime] = None, set_linux_expiry: Optional[Callable[[str, str], None]] = None) -> Optional[HoldActivation]:
    row = connection.execute("SELECT hold_active, hold_deadline, hold_duration_days FROM ssh_accounts WHERE username=?", (username,)).fetchone()
    if not row or not row[0]: return None
    duration = row[2]; observed = connected_at or datetime.now()
    deadline = _parse_flexible_datetime(row[1])
    started = min(observed, deadline)
    expiry = (started + timedelta(days=duration)).date().strftime("%Y-%m-%d")
    if set_linux_expiry: set_linux_expiry(username, expiry)
    connection.execute("UPDATE ssh_accounts SET expire_date=?, hold_active=0, hold_deadline=NULL, hold_duration_days=NULL, first_connected_at=? WHERE username=?", (expiry, observed.strftime("%Y-%m-%d %H:%M:%S"), username))
    return HoldActivation(username, observed.strftime("%Y-%m-%d %H:%M:%S"), expiry, "first_connection")

def activate_expired_holds(connection: sqlite3.Connection, checked_at: Optional[datetime] = None, set_linux_expiry: Optional[Callable[[str, str], None]] = None) -> Iterable[HoldActivation]:
    now = (checked_at or datetime.now()).strftime("%Y-%m-%d %H:%M:%S")
    rows = connection.execute("SELECT username, hold_deadline, hold_duration_days FROM ssh_accounts WHERE hold_active=1 AND hold_deadline <= ?", (now,)).fetchall()
    results = []
    for un, deadline_s, duration in rows:
        started = _parse_flexible_datetime(deadline_s)
        expiry = (started + timedelta(days=duration)).date().strftime("%Y-%m-%d")

        if set_linux_expiry:
            try:
                set_linux_expiry(un, expiry)
            except Exception as e:
                # Linux تغییر نکرد؛ این اکانت باید همچنان روی Hold بماند.
                # شکست یک اکانت نباید فعال‌سازی بقیهٔ Batch را متوقف کند.
                log.error(
                    "آنهولد: اعمال تاریخ انقضای Linux برای %s شکست خورد؛ "
                    "Hold این اکانت فعال می‌ماند: %s",
                    un, e
                )
                continue

        connection.execute(
            "UPDATE ssh_accounts SET expire_date=?, hold_active=0, "
            "hold_deadline=NULL, hold_duration_days=NULL WHERE username=?",
            (expiry, un)
        )
        results.append(HoldActivation(un, deadline_s, expiry, "hold_deadline"))
    return results

# 🔐 هرگز توکن/رمز را در کد هاردکد نکنید (حتی به‌عنوان fallback)؛ اگر env تنظیم نشود، ربات
# باید صراحتاً از اجرا امتناع کند تا هیچ‌وقت با یک توکن/رمز قدیمی و لو‌رفته بالا نیاید.
TOKEN = os.environ.get("BOT_TOKEN")
MASTER_USER = os.environ.get("MASTER_USER")
MASTER_PASS = os.environ.get("MASTER_PASS")
# 🐛🔧 رفع باگِ واقعیِ «نماینده‌ها بعد از هر انتقال/ری‌استارتِ سرویس مجبور به ورود مجدد
# می‌شدند»: مقدارهای پیش‌فرضِ زیر قبلاً مسیرِ نسبی («master_bot.db» و «bot_persistence.pickle»
# بدونِ هیچ پوشه‌ای) بودن — یعنی محلِ واقعیِ این فایل‌ها کاملاً به WorkingDirectory سرویسِ
# systemd بستگی داشت. هیچ‌کدوم از اسکریپت‌های Promote/Demote/Sync صراحتاً WorkingDirectory
# ست نمی‌کنند؛ اگر این خط در فایلِ سرویس جا بیفتد، systemd پیش‌فرض را روی «/» می‌گذارد،
# نه «/root» — یعنی ربات دنبالِ «/bot_persistence.pickle» می‌گشت، نه «/root/bot_persistence.pickle»
# که واقعاً همان‌جا (کنارِ خودِ اسکریپت) قرار داشت، پس همیشه با user_data خالی بالا می‌آمد.
# الان هر دو مسیر، مستقل از WorkingDirectory، به پوشهٔ خودِ همین فایلِ پایتون گره خورده‌اند —
# دقیقاً همان الگویی که خودِ کد چند خط پایین‌تر (persistence_src) برای بکاپ‌گیری استفاده می‌کند.
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("BOT_DB_PATH", os.path.join(_SCRIPT_DIR, "master_bot.db"))
# 🆕 مسیر فایل Persistence — وضعیت لاگین هر چت (user_data: logged_in/role/agent_id) روی دیسک
# ذخیره می‌شود تا با ری‌استارت سرویس (مثلاً بعد از هر آپدیت ربات) از بین نرود و ادمین/نماینده‌ها
# مجبور به ورود مجدد نشوند.
PERSISTENCE_PATH = os.environ.get("BOT_PERSISTENCE_PATH", os.path.join(_SCRIPT_DIR, "bot_persistence.pickle"))
# 🆘 سقف کل «شارژ اضطراری» هر نماینده (تومان) — یعنی موجودی نماینده حداکثر تا این مقدار
# می‌تواند منفی شود تا در نبود دسترسی به مدیریت هم بتواند اکانت بسازد. مبلغ مصرف‌شده در اولین
# شارژ واقعی بعدی (دستی توسط ادمین یا تاییدِ رسید کارت‌به‌کارت) به‌طور خودکار کسر می‌شود.
EMERGENCY_CREDIT_LIMIT = 1_000_000.0
# 🆘 حداکثر تعداد درخواست‌های «پیاپی» شارژ اضطراری (بدون هیچ شارژ واقعی بین آن‌ها). با هر شارژ
# واقعی حساب نماینده (حتی جزئی)، این شمارنده صفر می‌شود و دوباره ۲ درخواست در اختیارش قرار می‌گیرد.
EMERGENCY_MAX_CONSECUTIVE_REQUESTS = 2
EMERGENCY_MIN_ACTIVE_ACCOUNTS = 50
HOLD_EXPIRY_SAFETY_MARGIN_DAYS = 1

if not TOKEN:
    raise SystemExit("❌ متغیر محیطی BOT_TOKEN تنظیم نشده است.\nمثال: export BOT_TOKEN='xxxxx:yyyyy'")
if not MASTER_USER or not MASTER_PASS:
    raise SystemExit(
        "❌ متغیرهای محیطی MASTER_USER و MASTER_PASS تنظیم نشده‌اند.\n"
        "مثال:\n  export MASTER_USER='nevel'\n  export MASTER_PASS='یک-رمز-قوی'"
    )

# سیستم ثبت لاگ پیشرفته در فایل
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("bot_operations.log", encoding='utf-8'),
        logging.StreamHandler()
    ]
)
log = logging.getLogger("NeVeL_Enterprise")

SUBPROCESS_TIMEOUT = 12.0      # تایم‌اوت دستورات حساس (useradd/chpasswd/usermod) — از ۶ به ۱۲ ثانیه افزایش یافت
MONITOR_TIMEOUT = 8.0          # تایم‌اوت دستورات مانیتورینگ (ps/awk برای کاربران آنلاین)

SUPER_ADMIN_ID = 1947045855    # 👑 آیدی تلگرام مدیر کل (Super Admin)
ACCOUNTANT_IDS = (8404452597, 6455747868) # 📊 آیدی تلگرام حسابدارها (چند نفر)
ACCOUNTING_DB_PATH = os.path.join(_SCRIPT_DIR, "accounting.db") # 🗄 مسیر دیتابیس دوم (حسابداری)

# 🔴🔵 رمز تاییدِ عملیات سراسری RED & BLUE (قطع/وصل کامل سرور و افزودن روز به همه کاربران).
# مقدار باید فقط از Environment دریافت شود؛ هیچ رمز پیش‌فرضی داخل Source Control نگه‌داری نمی‌شود.
# اگر تنظیم نشده باشد، عملیات‌های RED/BLUE با هیچ متن معمولی تأیید نمی‌شوند.
RB_CONFIRM_PASS = os.environ.get("RB_CONFIRM_PASS")

# لیست نام‌های پردازه دیمون SSH که ممکن است روی سرور در حال اجرا باشند (برخی پنل‌ها به‌جای
# OpenSSH از Dropbear استفاده می‌کنند). برای شمارش درست کاربران آنلاین هر دو را پوشش می‌دهیم.
SSH_DAEMON_NAMES = ("sshd", "sshd-session", "dropbear")

# 🛡️ سیستم پایش تخطی از ظرفیت مجاز هر اکانت (جلوگیری از اشتراک‌گذاری غیرمجاز):
# هر چند وقت یک‌بار تعداد اتصالات هم‌زمان واقعی هر اکانت با «تعداد کاربر مجاز»ش مقایسه شود،
# و اگر تخطی به‌صورت *مستمر* (نه فقط یک لحظه) به مدت مشخصی ادامه یافت، اکانت خودکار قفل شود.
CAPACITY_CHECK_INTERVAL_SECONDS = 120   # هر ۲ دقیقه یک‌بار چک شود
CAPACITY_SUSPEND_AFTER_MINUTES = 25     # این مدت تخطی مستمر قبل از غیرفعال‌سازی خودکار
# 🆕 «آنهولد» اکانت‌های تازه‌ساخت (چه توسط ادمین، چه توسط نماینده‌ها): شمارش انقضا بلافاصله از
# لحظهٔ ساخت شروع نمی‌شود؛ اکانت تا ACCOUNT_HOLD_DAYS روز منتظر «اولین اتصال واقعی» می‌ماند.
# اگر مشتری زودتر وصل شود، انقضا از همان لحظهٔ اولین اتصال محاسبه می‌شود؛ اگر تا پایان همین مهلت
# هیچ اتصالی ثبت نشود، انقضا از پایان همان مهلت (نه از لحظهٔ ساخت) شروع می‌شود.
ACCOUNT_HOLD_DAYS = 3

# 🛡️ رفع مشکل: سیستم هیچ‌جا وابسته به یک ارائه‌دهندهٔ خاص (مثل DigitalOcean) نیست — افزودن هاست
# جدید («➕ افزودن IP جدید به استخر» و «🚀 افزودن Edge جدید») کاملاً عمومی است و با VPS خریداری‌شده
# از هر شرکتی کار می‌کند (فقط ساخت خودکار یک‌دکمه‌ای «☁️ ساخت VPS جدید» مخصوص DigitalOcean است،
# که کاملاً اختیاری است و اگر توکن API آن تنظیم نشود اصلاً استفاده نمی‌شود).
# اما این IP پایین در نسخهٔ قبلی به‌صورت رشتهٔ تکراری در ~۱۰ نقطهٔ مختلف کد، به‌عنوان مقدار
# احتیاطیِ «اگر تنظیمِ hosts به هر دلیلی خالی بود» کپی‌پیست شده بود. این تکرار خودش منبع خطاست
# (اگر فقط بعضی از نسخه‌ها آپدیت شوند، رفتار سیستم ناهماهنگ می‌شود) و همچنین یک IP خاص و قدیمی
# را به‌طور خاموش جایگزین می‌کرد بدون اینکه ادمین اصلاً متوجه شود. حالا این مقدار فقط یک‌بار،
# در همین‌جا، تعریف شده و هر جای دیگر کد از تابع کمکی _get_primary_host_fallback_sync پایین
# استفاده می‌کند که علاوه بر برگرداندن این مقدار، یک هشدار هم در لاگ ثبت می‌کند — یعنی اگر این
# حالت واقعاً پیش بیاید، به‌جای خرابیِ خاموش، ادمین در لاگ سرور متوجه می‌شود که «hosts» را
# تنظیم کند (از طریق مدیریت میزبان‌ها، با هر ارائه‌دهندهٔ VPS که باشد).
LAST_RESORT_HOST_IP = "46.101.114.34"
HOLD_CHECK_INTERVAL_SECONDS = 180       # هر ۳ دقیقه وضعیت اکانت‌های در حال آنهولد چک شود
# 🛡️ حاشیهٔ ایمنیِ انقضای لینوکسی (usermod/useradd -e) نسبت به مهلت آنهولد: چون useradd/usermod
# فقط دقتِ روزانه دارد (نه ساعت/دقیقه)، اگر انقضای لینوکسی دقیقاً روی همان روز پایان مهلت تنظیم
# شود، ممکن است پیش از اجرای تیک پایش (که واقعاً انقضای نهایی را محاسبه می‌کند) کاربر همان روز
# قفل شود. یک روز حاشیهٔ اضافه به تاریخ انقضای *لینوکسیِ* دوران آنهولد اضافه می‌شود (فقط در سطح
# سیستم‌عامل؛ منطق تصمیم‌گیری خودِ ربات همچنان دقیقاً از همان ACCOUNT_HOLD_DAYS پیروی می‌کند).
HOLD_OS_EXPIRY_BUFFER_DAYS = 1

# 🆕 «نمودار زنده»: به‌جای یک عکس ثابت که فقط با کلیک دستی رفرش می‌شود، این حالت هر چند ثانیه
# یک‌بار خودکار داده‌های تازه از سرور می‌خواند و همان پیامِ عکس را به‌جا (edit_message_media)
# با نمودار جدید جایگزین می‌کند — یعنی واقعاً «زنده» به‌نظر می‌رسد، بدون نیاز به کلیک مکرر.
LIVE_CHART_INTERVAL_SECONDS = 20
LIVE_CHART_MAX_ITERATIONS = 45   # ≈ ۱۵ دقیقه پایش پیوسته، بعد خودکار متوقف می‌شود (صرفه‌جویی منابع سرور)
CAPACITY_RENOTIFY_HOURS = 6             # اگر قفل خودکار روی لینوکس مدام شکست بخورد، هر چند ساعت یادآوری شود

# 🌐 پایش خودکار فشار CPU/RAM سرور برای «سرویس IP» (مستقل از دکمهٔ دستی «انجام خودکار»):
# اگر مصرف CPU یا RAM به آستانهٔ هشدار برسد، فقط یک پیام هشدار به همهٔ ادمین‌ها فرستاده می‌شود؛
# اگر فشار همچنان ادامه داشت و ادمین ظرف مهلت زیر از «سرویس IP» اقدامی نکرد، ربات خودش کاربران
# را بین تمام IPهای ثبت‌شده بالانس می‌کند.
IP_PRESSURE_CHECK_INTERVAL_SECONDS = 300     # هر ۵ دقیقه یک‌بار وضعیت سرور چک شود
IP_PRESSURE_WARN_PCT = 90                    # از این درصد مصرف CPU/RAM به بالا، هشدار فشار ارسال می‌شود
# 🆕 برای رفع درخواست «تشخیص دقیق‌تر فشار سرور»: به‌جای هشداردادن بلافاصله سرِ اولین باری که یک
# نمونه‌گیری از آستانه رد شود (که می‌تواند یک اسپایک چند-دقیقه‌ای و بی‌ضرر باشد، همان‌طور که واقعاً
# دیده شد)، باید فشار در این تعداد بررسیِ متوالیِ پشت‌سرهم هم دیده شود تا هشدار واقعاً ارسال شود.
# با فاصلهٔ ۵ دقیقه‌ای بین بررسی‌ها، مقدار ۲ یعنی فشار باید حداقل ۵ دقیقه واقعاً ادامه داشته باشد.
IP_PRESSURE_CONFIRM_TICKS = 2
IP_PRESSURE_AUTOBALANCE_AFTER_HOURS = 3      # اگر این مدت از هشدار گذشت و فشار برطرف نشد، بالانس خودکار انجام می‌شود

# 🆕 پایش سلامت/در دسترس‌بودن IPها (تشخیص فیلترشدن/از کار افتادن، مستقل از فشار CPU/RAM بالا):
# هر IP ثبت‌شده در «تنظیمات هاست» به‌صورت دوره‌ای با یک اتصال TCP ساده تست می‌شود. اگر چند بار
# متوالی پاسخ نداد، به‌صورت خودکار از لیست IPهای فعال (که برای فاکتور/کد اتصال استفاده می‌شود)
# حذف می‌شود و به ادمین اطلاع داده می‌شود — بدون این‌که هیچ سروری نابود یا بازسازی شود.
HOST_HEALTH_CHECK_INTERVAL_SECONDS = 300   # هر ۵ دقیقه یک دور بررسی
HOST_HEALTH_FAIL_THRESHOLD = 3             # ۳ بار متوالیِ ناموفق → غیرفعال‌سازی خودکار
HOST_HEALTH_TCP_TIMEOUT_SECONDS = 6
# 🆕 دورهٔ مهلتِ IP تازه‌افزوده‌شده: ظرف این چند دقیقهٔ اول بعد از افزودن (مثلاً هنگام ساخت یک
# Edge جدید که سرورش تازه Reinstall/استارت شده)، پایش خودکار اصلاً چک نمی‌کند — چون در این بازه
# طبیعی است سرور هنوز کامل بالا نیامده باشد؛ رد کردنش در این مدت باعث غیرفعال‌سازیِ زودهنگام و
# نادرست می‌شد (دقیقاً همان مشکلی که یک‌بار موقع افزودن Edge جدید رخ داد).
HOST_HEALTH_GRACE_PERIOD_MINUTES = 15

# ==========================================
# 🆕 V89 — سیستم شناسایی خودکار فیلتر شدن بر اساس کاربران آنلاین
# ==========================================
# اگر تعداد کاربران آنلاین به این درصد از کل کاربران فعال برسد،
# سیستم IP فعلی را فیلتر شده تشخیص می‌دهد و IP را تعویض می‌کند.
# مثال: 5 یعنی اگر کمتر از ۵٪ کاربران آنلاین باشند → فیلتر شده
FILTER_DETECT_ONLINE_PCT_THRESHOLD = 5   # درصد آستانه (پیش‌فرض ۵٪)
FILTER_DETECT_CHECK_INTERVAL_SECONDS = 120  # هر ۲ دقیقه یک‌بار چک شود
FILTER_DETECT_CONFIRM_TICKS = 3          # ۳ بار متوالی زیر آستانه → فیلتر تشخیص داده شود
FILTER_DETECT_MIN_ACTIVE_ACCOUNTS = 5   # حداقل تعداد کاربران فعال برای فعال‌شدن این سیستم
# 🆕 دورهٔ خنک‌شدن بعد از هر سوییچ IP (خودکار یا دستی): در این بازه، حتی اگر درصد آنلاین
# زیر آستانه بیفته (که طبیعیه چون تعویض IP خودش باعث نویز موقت در شمارش می‌شه)، سیستم
# خودکار دوباره سوییچ نمی‌کنه. جلوی «فلَپینگ» (سوییچ پشت سر هم بی‌دلیل) رو می‌گیره.
FILTER_DETECT_SWITCH_COOLDOWN_SECONDS = 600  # ۱۰ دقیقه

# 🆕 V89 — تست سرعت همه IPها به‌صورت یکجا
IP_SPEED_TEST_PARALLEL_TIMEOUT = 10      # تایم‌اوت هر تست سرعت (ثانیه)
IP_SPEED_TEST_SAMPLES = 3               # تعداد نمونه برای میانگین‌گیری

# 🆕 پایش سلامت سرویس UDPGW (badvpn-udpgw): چون این سرویس روی همین سرور (نه یک هاست دوردست)
# اجرا می‌شود، بررسی‌اش یک اتصال TCP محلی به 127.0.0.1:udpgw_port است — نه یک تست از راه دور.
# هدف این است که به‌جای فهمیدن از شکایتِ مشتری («فلان بازی/تماس بالا نمی‌آید»)، خودِ ربات
# متوجه شود که پروسهٔ badvpn-udpgw کرش کرده/بالا نیامده و فوراً به ادمین اطلاع بدهد.
UDPGW_HEALTH_CHECK_INTERVAL_SECONDS = 180  # هر ۳ دقیقه (محلی و سبک است، نیازی به بازهٔ بلند نیست)
UDPGW_HEALTH_FAIL_THRESHOLD = 2             # ۲ بار متوالیِ ناموفق → هشدار (نه غیرفعال‌سازیِ خودکارِ چیزی)

# ==========================================
# 🔐 هش امن رمز عبور و Anti-Brute-force
# ==========================================
def hash_password(password: str, salt: bytes = None) -> str:
    if salt is None: salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 200_000)
    return f"{salt.hex()}${dk.hex()}"

def verify_password(password: str, stored: str) -> bool:
    if not stored: return False
    if "$" in stored:
        try:
            salt_hex, hash_hex = stored.split("$", 1)
            salt = bytes.fromhex(salt_hex)
            dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 200_000)
            return hmac.compare_digest(dk.hex(), hash_hex)
        except Exception: return False
    return hmac.compare_digest(password, stored)

def is_legacy_plaintext(stored: str) -> bool:
    return bool(stored) and "$" not in stored

_LOGIN_ATTEMPTS = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 300

def _login_locked(chat_id):
    info = _LOGIN_ATTEMPTS.get(chat_id)
    if not info: return 0
    return max(0, int(info.get("locked_until", 0) - time.time()))

def _register_login_failure(chat_id):
    info = _LOGIN_ATTEMPTS.setdefault(chat_id, {"count": 0, "locked_until": 0})
    info["count"] += 1
    if info["count"] >= MAX_LOGIN_ATTEMPTS:
        info["locked_until"] = time.time() + LOCKOUT_SECONDS; info["count"] = 0

def _register_login_success(chat_id):
    _LOGIN_ATTEMPTS.pop(chat_id, None)

# ==========================================
# 🛠 توابع تقویم و متن
# ==========================================
def fa_to_en_digits(text):
    if not text: return text
    d = {'۰':'0', '۱':'1', '۲':'2', '۳':'3', '۴':'4', '۵':'5', '۶':'6', '۷':'7', '۸':'8', '۹':'9'}
    for k, v in d.items(): text = text.replace(k, v)
    return text

_JALALI_BREAKS = [-61, 9, 38, 199, 426, 686, 756, 818, 1111, 1181, 1210, 1635, 2060, 2097, 2192, 2262, 2324, 2394, 2456, 3178]
def _idiv(a, b):
    """
    تقسیم صحیح به‌سمت صفر (truncate towards zero) — دقیقاً مطابق رفتار عملگر division در
    پیاده‌سازی مرجع جاوااسکریپتیِ این الگوریتم (jalaali-js).
    🔧 رفع باگ حیاتی: عملگر // پایتون تقسیم صحیح را به‌سمت منفی بی‌نهایت (floor) انجام می‌دهد که
    برای اعداد منفی با رفتار تقسیم به‌سمت صفر (truncate) که این الگوریتم به آن نیاز دارد فرق دارد.
    همین اختلاف باعث می‌شد گاه‌به‌گاه (برای حدود یک‌سوم تاریخ‌های هر سال) ماه محاسبه‌شده عددی
    نامعتبر مثل ۱۷ یا ۱۸ باشد که در نهایت با ایندکس خارج از محدوده در _JALALI_MONTHS باعث کرش
    خاموش می‌شد — دقیقاً همان چیزی که «تمدید اکانت» را (بعد از موفقیت واقعیِ عملیات روی
    لینوکس/دیتابیس، فقط در مرحلهٔ فرمت‌کردن پیام موفقیت) با خطای مبهم متوقف می‌کرد.
    """
    q = abs(a) // abs(b)
    return q if (a >= 0) == (b >= 0) else -q
def _imod(a, b): return a - _idiv(a, b) * b
def _jal_cal(jy):
    bl = len(_JALALI_BREAKS); gy = jy + 621; leap_j = -14; jp = _JALALI_BREAKS[0]; jump = 0
    for i in range(1, bl):
        jm = _JALALI_BREAKS[i]; jump = jm - jp
        if jy < jm: break
        leap_j += _idiv(jump, 33) * 8 + _idiv(_imod(jump, 33), 4); jp = jm
    n = jy - jp; leap_j += _idiv(n, 33) * 8 + _idiv(_imod(n, 33) + 3, 4)
    if _imod(jump, 33) == 4 and jump - n == 4: leap_j += 1
    leap_g = _idiv(gy, 4) - _idiv((_idiv(gy, 100) + 1) * 3, 4) - 150; march = 20 + leap_j - leap_g
    if jump - n < 6: n = n - jump + _idiv(jump + 4, 33) * 33
    leap = _imod(_imod(n + 1, 33) - 1, 4)
    if leap == -1: leap = 4
    return leap, gy, march
def _gregorian_to_jdn(gy, gm, gd):
    d = _idiv((gy + _idiv(gm - 8, 6) + 100100) * 1461, 4)
    d += _idiv(153 * _imod(gm + 9, 12) + 2, 5) + gd - 34840408
    d -= _idiv(_idiv(gy + 100100 + _idiv(gm - 8, 6), 100) * 3, 4) - 752
    return d
def gregorian_to_jalali(gy, gm, gd):
    jdn = _gregorian_to_jdn(gy, gm, gd); jy = gy - 621; leap, gy2, march = _jal_cal(jy); jdn1f = _gregorian_to_jdn(gy, 3, march)
    k = jdn - jdn1f
    if k >= 0:
        if k <= 185: return jy, 1 + _idiv(k, 31), _imod(k, 31) + 1
        k -= 186
    else:
        jy -= 1; k += 179; leap2, _, _ = _jal_cal(jy)
        if leap2 == 1: k += 1
    return jy, 7 + _idiv(k, 30), _imod(k, 30) + 1

_JALALI_MONTHS = ["", "فروردین", "اردیبهشت", "خرداد", "تیر", "مرداد", "شهریور", "مهر", "آبان", "آذر", "دی", "بهمن", "اسفند"]
def gregorian_to_jalali_text(gy, gm, gd):
    jy, jm, jd = gregorian_to_jalali(gy, gm, gd)
    return f"{jd} {_JALALI_MONTHS[jm]} {jy}"

# نام روز هفته فارسی (شنبه تا جمعه) بر اساس تاریخ میلادی
_FA_WEEKDAYS = ["دوشنبه", "سه‌شنبه", "چهارشنبه", "پنجشنبه", "جمعه", "شنبه", "یکشنبه"]  # ترتیب متناظر با date.weekday() پایتون (دوشنبه=0)
def gregorian_weekday_fa(gy, gm, gd):
    try: return _FA_WEEKDAYS[datetime(gy, gm, gd).weekday()]
    except Exception: return ""

def gregorian_to_jalali_text_full(gy, gm, gd):
    """تاریخ جلالی همراه با نام روز هفته، مخصوص فاکتور نهایی"""
    jy, jm, jd = gregorian_to_jalali(gy, gm, gd)
    wd = gregorian_weekday_fa(gy, gm, gd)
    return f"{wd} {jd} {_JALALI_MONTHS[jm]} {jy}".strip()

def format_db_date_to_jalali(date_str):
    if not date_str or '-' not in date_str: return date_str
    try: return gregorian_to_jalali_text(*map(int, date_str.split('-')))
    except: return date_str

def format_db_datetime_to_jalali(dt_str):
    """مثل format_db_date_to_jalali، ولی برای رشته‌های تاریخ+ساعت ('YYYY-MM-DD HH:MM') — مثلاً
    ستون created_at جدول receipts. تاریخ به جلالی تبدیل می‌شود و ساعت همان‌طور که ثبت شده کنارش
    می‌آید (برای گزارش مالی نمایندگان: چه روزی، چه ساعتی واریز کرده‌اند)."""
    if not dt_str: return dt_str
    date_part, _, time_part = dt_str.strip().partition(' ')
    jdate = format_db_date_to_jalali(date_part)
    return f"{jdate} ساعت {time_part}" if time_part else jdate

def get_remaining_days(exp_date_str):
    try:
        exp_dt = datetime.strptime(exp_date_str, "%Y-%m-%d").date()
        rem = (exp_dt - datetime.now().date()).days
        if rem < 0: return "🔴 منقضی شده"
        elif rem == 0: return "⚠️ امروز منقضی می‌شود"
        return f"{rem} روز باقی مانده"
    except: return "نامشخص"

def esc(text) -> str: return html.escape(str(text)) if text is not None else ""

# ==========================================
# 📅 نمایش کاملاً فارسیِ تاریخ+ساعت (روی همان تبدیل جلالی موجود پروژه، gregorian_to_jalali)
# ==========================================
_PERSIAN_DIGIT_MAP = str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹")

def fa_digits(s) -> str:
    """اعداد لاتین داخل یک رشته را به ارقام فارسی تبدیل می‌کند (فقط برای نمایش)."""
    return str(s).translate(_PERSIAN_DIGIT_MAP)

def fmt_jalali_datetime(dt: datetime, with_weekday: bool = True) -> str:
    """
    یک datetime میلادی را به‌صورت رشتهٔ کاملاً فارسیِ شمسی (با ارقام فارسی) برمی‌گرداند، مثلاً:
    «سه‌شنبه ۲۹ تیر ۱۴۰۵ — ساعت ۲۳:۴۵»
    از همان توابع تبدیل جلالیِ موجود پروژه (gregorian_to_jalali_text_full) استفاده می‌کند تا
    دقیقاً با بقیهٔ تاریخ‌های فارسیِ نمایش‌داده‌شده در ربات (مثلاً در فاکتور) یکسان باشد.
    ⚠️ توجه: این فقط تقویم/زبان را تبدیل می‌کند؛ عدد ساعت همان ساعتِ سیستمِ سرور است. اگر
    ساعت سیستم سرور روی ایران (Asia/Tehran) تنظیم نباشد، برای دقتِ کامل باید تایم‌زون سرور را
    روی ایران تنظیم کنید؛ در غیر این‌صورت فقط شکل نمایش تاریخ فارسی می‌شود نه ساعتش.
    """
    if dt is None:
        return "نامشخص"
    if with_weekday:
        date_part = gregorian_to_jalali_text_full(dt.year, dt.month, dt.day)
    else:
        date_part = gregorian_to_jalali_text(dt.year, dt.month, dt.day)
    time_part = fa_digits(dt.strftime("%H:%M"))
    return f"{fa_digits(date_part)} — ساعت {time_part}"

def fmt_jalali_date_only(dt: datetime) -> str:
    return fa_digits(gregorian_to_jalali_text(dt.year, dt.month, dt.day))

# ==========================================
# ⚙️ لایه دیتابیس جامع و پایدار
# ==========================================
_ALLOWED_AGENT_FIELDS = {"base_price", "commission_pct", "l2_pct", "l3_pct", "telegram_id", "v2ray_base_price", "v2ray_vol_price"}

@contextlib.contextmanager
def db_conn():
# ... (کدهای کانکشن دیتابیس اینجا هستند، دست نزن)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute("PRAGMA foreign_keys=ON")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally: conn.close()

def init_db():
    with db_conn() as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)''')
        c.executemany("INSERT OR IGNORE INTO settings VALUES (?,?)",
                       [('brand', 'NeVeL'), ('counter', '0350'), ('hosts', LAST_RESORT_HOST_IP),
                        ('port', '22'), ('base_price', '125000'), ('bank_card', '6037-xxxx-xxxx-xxxx\nبنام: تنظیم نشده'), ('admin_chat_id', '0'),
                        # 🆕 دامنه/پورتی که سرور TLS واقعی (stunnel یا مشابه، با گواهیِ معتبر) روی آن
                        # گوش می‌دهد — طبق تست‌های واقعی روی سرور با openssl s_client تایید شده.
                        # کلاینت مستقیماً با هندشیک TLS واقعی (نه پشت Cloudflare) به این دامنه/پورت
                        # وصل می‌شود؛ از «تنظیمات سرور ← 🔐 تنظیمات TLS» قابل تغییر است.
                        ('tls_domain', 'ws.nvlsup.com'), ('tls_port', '2088'),
                        # 🆕 پورتی که سرویس badvpn-udpgw واقعاً روی سرور گوش می‌دهد. قبلاً این عدد
                        # توی کد کاملاً هاردکد شده بود (1234) بدون توجه به این‌که badvpn-udpgw واقعاً
                        # روی چه پورتی بالا آمده — اگه udpgw سرور شما (مثلاً طبق کانفیگ دستیِ قبلی‌تان)
                        # روی پورت دیگری (مثلاً 7300) گوش می‌ده، اون هاردکد باعث می‌شد کلاینت‌هایی که
                        # به UDP forwarding نیاز دارن (بازی، تماس صوتی، DNS/QUIC) نتونن وصل بشن، حتی
                        # اگه خودِ تونل SSH/TLS برقرار می‌شد. از «تنظیمات سرور ← 🔌 تنظیمات UDPGW»
                        # قابل تغییره.
                        ('udpgw_port', '7300'),
                        # 🆕 قبلاً این مقدار همیشه False هاردکد بود، در حالی‌که تو تنظیمِ دستیِ
                        # قبلی‌ات (همونی که تست شد و کار کرد) این گزینه فعال بود. حالا قابل‌تغییره
                        # و پیش‌فرضش هم مطابق همون کانفیگِ تست‌شده «فعال» گذاشته شده.
                        ('udpgw_transparent_dns', '1'),
                        # 🆕 حالتِ تعویضِ خودکار (Failover — بندِ ۴): '1'=خودکار (اولین Standbyِ سالم
                        # بی‌درنگ فعال می‌شود)، '0'=دستی (پیش‌فرضِ امن — ادمین از پنل انتخاب می‌کند).
                        ('auto_failover_mode', '0')])
        c.execute('''CREATE TABLE IF NOT EXISTS ssh_accounts (
                        username TEXT PRIMARY KEY, password TEXT, expire_date TEXT, creation_date TEXT,
                        users_limit INTEGER, status TEXT DEFAULT '🟢 فعال', agent_id INTEGER DEFAULT 0)''')
        try: c.execute("ALTER TABLE ssh_accounts ADD COLUMN agent_id INTEGER DEFAULT 0")
        except sqlite3.OperationalError: pass
        # 🆕 برای سیستم پایش تخطی از ظرفیت مجاز (رفع اشتراک‌گذاری غیرمجاز اکانت):
        # این ستون زمان شروع «تخطی مستمر» را نگه می‌دارد؛ NULL یعنی الان تخطی‌ای در جریان نیست.
        try: c.execute("ALTER TABLE ssh_accounts ADD COLUMN violation_since TEXT DEFAULT NULL")
        except sqlite3.OperationalError: pass
        try: c.execute("ALTER TABLE ssh_accounts ADD COLUMN violation_last_notified TEXT DEFAULT NULL")
        except sqlite3.OperationalError: pass
        # 🆕 IP اختصاصی هر اکانت (برای قابلیت «انتقال کاربر به IP دیگر» هنگام فشار روی سرور).
        # NULL یعنی از اولین IP لیست سراسری «hosts» استفاده شود (رفتار قبلی، بدون تغییر).
        try: c.execute("ALTER TABLE ssh_accounts ADD COLUMN host TEXT DEFAULT NULL")
        except sqlite3.OperationalError: pass
        # 🆕 حالت اتصال هر اکانت: 'direct' یعنی SSH خام مستقیم (رفتار قبلی، بدون تغییر) و
        # 'tls' یعنی SSH روی یک هندشیک TLS واقعی (گواهی معتبر). این ستون فقط برای «به‌خاطرسپاری»
        # انتخاب هر اکانت است؛ سرور TLS خودش مستقل و از قبل روی سرور در حال اجراست و به این ستون
        # کاری ندارد — این ستون فقط تعیین می‌کند هنگام ساخت کد نپسترنت، کدام مقصد (IP:22 مستقیم
        # یا دامنهٔ TLS) داخل کد قرار بگیرد.
        try: c.execute("ALTER TABLE ssh_accounts ADD COLUMN conn_mode TEXT DEFAULT 'direct'")
        except sqlite3.OperationalError: pass
        # 🆕 «آنهولد» اکانت‌های تازه‌ساخت: hold_active=1 یعنی هنوز منتظر اولین اتصال/پایان مهلت
        # است (شمارش انقضای واقعی هنوز شروع نشده)؛ hold_deadline پایان مهلت (تاریخ میلادی
        # ساده، هم‌فرمت با expire_date/creation_date) و hold_duration_days مدت واقعی خریداری‌شده
        # (بر حسب روز) است که هنگام فعال‌سازی برای محاسبهٔ انقضای واقعی استفاده می‌شود.
        try: c.execute("ALTER TABLE ssh_accounts ADD COLUMN hold_active INTEGER DEFAULT 0")
        except sqlite3.OperationalError: pass
        try: c.execute("ALTER TABLE ssh_accounts ADD COLUMN hold_deadline TEXT DEFAULT NULL")
        except sqlite3.OperationalError: pass
        try: c.execute("ALTER TABLE ssh_accounts ADD COLUMN hold_duration_days INTEGER DEFAULT NULL")
        except sqlite3.OperationalError: pass
        try: c.execute("ALTER TABLE ssh_accounts ADD COLUMN customer_name TEXT DEFAULT NULL")
        except sqlite3.OperationalError: pass
        # ---------------------------------------------------------
        # V2Ray Database Updates
        # ---------------------------------------------------------
        try: c.execute("ALTER TABLE ssh_accounts ADD COLUMN service_type TEXT DEFAULT 'ssh'")
        except sqlite3.OperationalError: pass
        
        try: c.execute("ALTER TABLE ssh_accounts ADD COLUMN data_limit REAL DEFAULT NULL")
        except sqlite3.OperationalError: pass
        
        try: c.execute("ALTER TABLE ssh_accounts ADD COLUMN sub_url TEXT DEFAULT NULL")
        except sqlite3.OperationalError: pass

        try: c.execute("ALTER TABLE agents ADD COLUMN v2ray_gb_price REAL DEFAULT 3000.0")
        except sqlite3.OperationalError: pass

        # Seed Marzban settings from environment only when the DB does not already
        # contain them. Real credentials must never be committed to source control.
        _marzban_bootstrap = [
            ('marzban_url', os.environ.get('MARZBAN_URL', '').strip()),
            ('marzban_username', os.environ.get('MARZBAN_USERNAME', '').strip()),
            ('marzban_password', os.environ.get('MARZBAN_PASSWORD', '').strip()),
        ]
        c.executemany(
            "INSERT OR IGNORE INTO settings VALUES (?,?)",
            [(key, value) for key, value in _marzban_bootstrap if value],
        )
        # ---------------------------------------------------------
        

        # 🧹 پاک‌سازی خودکار رزروهای نیمه‌کاره: اگر ربات وسط ساخت یک اکانت (بین گام رزرو دیتابیس
        # و تکمیل نهایی) کرش کند یا ری‌استارت شود، یک ردیف با وضعیت «⏳ درحال ساخت» باقی می‌ماند که
        # یوزرنیمش را برای همیشه اشغال نگه می‌دارد. چون چنین ردیفی هرگز نمی‌تواند واقعاً «در حال پردازش»
        # در یک پردازش تازه‌شروع‌شده باشد، در ابتدای هر اجرا حذف می‌شود تا آن یوزرنیم‌ها آزاد شوند.
        n_cleaned = c.execute("DELETE FROM ssh_accounts WHERE status='⏳ درحال ساخت'").rowcount
        if n_cleaned:
            log.warning("%s ردیف رزرو نیمه‌کاره (باقی‌مانده از اجرای قبلی) پاک‌سازی شد.", n_cleaned)
        
        c.execute('''CREATE TABLE IF NOT EXISTS agents (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, name TEXT,
                        referral_code TEXT UNIQUE, balance REAL DEFAULT 0.0, commission_pct REAL DEFAULT 8.0,
                        base_price TEXT DEFAULT '125000', telegram_id INTEGER DEFAULT 0,
                        parent_id INTEGER DEFAULT 0, l2_pct REAL DEFAULT 3.0, l3_pct REAL DEFAULT 1.0)''')
        # 🆕 درآمد انباشته از پورسانت شبکه (زیرمجموعه‌گیری) — جدا از موجودی کیف‌پول نگه‌داری می‌شود
        # تا نماینده بتواند دقیقاً ببیند از فروش زیرمجموعه‌هایش چقدر واریزی گرفته (نه کل موجودی
        # که شامل شارژهای دستی/کارت‌به‌کارت هم می‌شود).
        try: c.execute("ALTER TABLE agents ADD COLUMN referral_income REAL DEFAULT 0.0")
        except sqlite3.OperationalError: pass

        # 🆕 پیشوند یوزرنیم اختصاصی هر نماینده — اگر خالی/NULL باشد، از برند سراسری ادمین استفاده
        # می‌شود؛ اگر نماینده مقداری برای خودش تنظیم کند، فقط اکانت‌های خودِ او را تحت‌تاثیر قرار
        # می‌دهد و روی اکانت‌های ادمین یا سایر نمایندگان اثری نمی‌گذارد (رفع درخواست ایزوله‌سازی).
        try: c.execute("ALTER TABLE agents ADD COLUMN username_prefix TEXT DEFAULT NULL")
        except sqlite3.OperationalError: pass

        # 🆕 نصب محافظ‌ها و ستون‌های On hold پنهان (V88)
        install_hidden_hold_guards(conn)

        # 🆘 ستون‌های «شارژ اضطراری»: emergency_used مقدار فعلیِ مصرف‌شده از سقف شارژ اضطراری این
        # نماینده است (۰ تا EMERGENCY_CREDIT_LIMIT) و emergency_request_count تعداد درخواست‌های
        # «پیاپی» فعال‌سازی آن (بدون شارژ واقعی بین‌شان) است که حداکثر ۲ می‌تواند باشد.
        try: c.execute("ALTER TABLE agents ADD COLUMN emergency_used REAL DEFAULT 0.0")
        except sqlite3.OperationalError: pass
        try: c.execute("ALTER TABLE agents ADD COLUMN emergency_request_count INTEGER DEFAULT 0")
        except sqlite3.OperationalError: pass

        # 🆕 استخر «قابل‌برداشت»: از این پس پورسانت شبکه (override والد/پدربزرگ) و کش‌بک ۷٪
        # (نمایندگان با ۵۰+ اکانت فعال) دیگر مستقیماً به موجودی قابل‌خرج (balance) اضافه نمی‌شوند؛
        # به‌جای آن در withdrawable_balance جمع می‌شوند تا خودِ نماینده انتخاب کند این مبلغ را
        # نقداً برداشت کند یا به کیف‌پول قابل‌خرجش منتقل کند. cashback_income فقط برای نمایش
        # مجموع تاریخی کش‌بک (اطلاعاتی، مثل referral_income) نگه‌داری می‌شود.
        try: c.execute("ALTER TABLE agents ADD COLUMN withdrawable_balance REAL DEFAULT 0.0")
        except sqlite3.OperationalError: pass
        try: c.execute("ALTER TABLE agents ADD COLUMN cashback_income REAL DEFAULT 0.0")
        except sqlite3.OperationalError: pass

        # 🛡️ رفع سوءاستفادهٔ احتمالی از کش‌بک ۷٪: قبلاً شرط واجدشرایط‌بودن روی COUNT زندهٔ
        # اکانت‌های «فعال»/«کل» جدول ssh_accounts بود که با حذف اکانت هم کم می‌شود؛ یعنی یک
        # نماینده می‌توانست ۵۰+ اکانت بسازد، تا وقتی این آستانه را رد کرده از کش‌بک روی خریدهای
        # بعدی استفاده کند، مبلغ استخر را برداشت نقدی بگیرد و بعد همان اکانت‌ها را حذف کند —
        # عدد فعلی/کل دوباره افت می‌کرد ولی کش‌بکِ برداشت‌شده هرگز پس گرفته نمی‌شد، و اگر بعداً
        # امکان بازپرداخت حذف هم اضافه شود، همین چرخهٔ ساخت→برداشت→حذف→بازپرداخت می‌توانست
        # پول واقعی تولید کند. lifetime_accounts_sold یک شمارندهٔ صرفاً افزایشی است که با هر
        # فروش موفق (تکی یا عمده) یک واحد بالا می‌رود و هرگز با حذف اکانت کم نمی‌شود؛ کش‌بک از
        # این پس روی همین عدد سنجیده می‌شود.
        try: c.execute("ALTER TABLE agents ADD COLUMN lifetime_accounts_sold INTEGER DEFAULT 0")
        except sqlite3.OperationalError: pass

        # 🆕 شمارهٔ کارت اختصاصیِ هر نماینده — اگر یک نماینده این را برای خودش ثبت کند، از آن پس
        # هر زیرمجموعه‌اش (فرزندان مستقیم/غیرمستقیم بر اساس parent_id) هنگام شارژ کیف‌پول با
        # کارت‌به‌کارت، به‌جای «کارت سیستم» (کارت مدیریت)، همین کارت را می‌بینند. اگر یک نماینده
        # کارتی ثبت نکرده باشد، جستجو یک سطح بالاتر (والدِ او) ادامه پیدا می‌کند تا به کارت سیستم
        # برسد (_db_get_effective_card_for_agent همین منطق را پیاده می‌کند).
        try: c.execute("ALTER TABLE agents ADD COLUMN custom_card_number TEXT DEFAULT NULL")
        except sqlite3.OperationalError: pass
        try: c.execute("ALTER TABLE agents ADD COLUMN custom_card_name TEXT DEFAULT NULL")
        except sqlite3.OperationalError: pass
        # 🆕 مجوز «کارت اختصاصی خودگردان»: پیش‌فرض ۰ (بدون مجوز) — فقط مدیریت از داخل «گزارش مالی
        # نمایندگان» می‌تواند این مجوز را برای یک نمایندهٔ خاص صادر/لغو کند. تا وقتی مجوز صادر نشده،
        # دکمهٔ «کارت اختصاصی من» اصلاً توی پنل آن نماینده نمایش داده نمی‌شود (نه فقط غیرفعال — کلاً
        # مخفی)، و بقیهٔ نمایندگان هیچ‌وقت این دکمه یا هرگونه اشاره‌ای به وجودش را نمی‌بینند.
        try: c.execute("ALTER TABLE agents ADD COLUMN card_permission INTEGER DEFAULT 0")
        except sqlite3.OperationalError: pass
        try: c.execute("ALTER TABLE agents ADD COLUMN v2ray_base_price TEXT DEFAULT '160000'")
        except sqlite3.OperationalError: pass
        try: c.execute("ALTER TABLE agents ADD COLUMN v2ray_vol_price TEXT DEFAULT '4000'")
        except sqlite3.OperationalError: pass
        # 🔧 مهاجرت یک‌بارهٔ امن (و idempotent — هربار اجرا هم بی‌خطر است): برای نمایندگانی که
        # از قبل این سیستم وجود داشت، شمارندهٔ جدید را حداقل برابر تعداد فعلیِ رکوردهای موجودشان
        # قرار می‌دهد تا واجدشرایط‌های واقعی و قدیمی، به‌ناحق صفر نشوند. این شرط تضمین می‌کند مقدار
        # هرگز کاهش پیدا نکند (فقط وقتی داده‌های زندهٔ فعلی از مقدار ذخیره‌شده بیشتر باشد، بالا می‌رود).
        c.execute('''UPDATE agents SET lifetime_accounts_sold = (
                        SELECT COUNT(*) FROM ssh_accounts WHERE ssh_accounts.agent_id = agents.id
                     )
                     WHERE (SELECT COUNT(*) FROM ssh_accounts WHERE ssh_accounts.agent_id = agents.id) > lifetime_accounts_sold''')

        c.execute('''CREATE TABLE IF NOT EXISTS favorite_configs (months INTEGER, users INTEGER, PRIMARY KEY (months, users))''')
        
        # جدول جدید رسیدهای مالی
        c.execute('''CREATE TABLE IF NOT EXISTS receipts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id INTEGER, amount REAL, 
                        photo_id TEXT, status TEXT DEFAULT 'pending', created_at TEXT)''')
        # 🆕 وقتی زیرمجموعهٔ یک نماینده با کارت اختصاصیِ آن نماینده (نه کارت سیستم) شارژ می‌کند،
        # این ستون شناسهٔ همان نماینده (صاحب کارت) را نگه می‌دارد تا هم تاییدیه به خودش برود
        # هم در «گزارش مالی نمایندگان» زیر نام او دیده شود. برای واریزهای مستقیم NULL می‌ماند.
        try: c.execute("ALTER TABLE receipts ADD COLUMN card_owner_agent_id INTEGER DEFAULT NULL")
        except sqlite3.OperationalError: pass

        # 🆕 درخواست‌های برداشت نقدی نماینده از استخر «قابل‌برداشت» (پورسانت شبکه + کش‌بک).
        # نماینده مبلغ + شماره کارت + نام و نام‌خانوادگی می‌فرستد؛ مبلغ همان لحظه از
        # withdrawable_balance کسر می‌شود (رزرو می‌شود) تا دوبار خرج نشود؛ وضعیت تا وقتی ادمین
        # رسید واریز را برای نماینده ارسال کند 'pending' می‌ماند و بعد 'done' می‌شود.
        c.execute('''CREATE TABLE IF NOT EXISTS withdrawal_requests (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id INTEGER, amount REAL,
                        card_number TEXT, full_name TEXT, status TEXT DEFAULT 'pending',
                        created_at TEXT, done_at TEXT)''')
        
        # 👑 جدول ثبت سوابق و فعالیت‌های مالی جهت گزارش‌گیری سوپر ادمین
        c.execute('''CREATE TABLE IF NOT EXISTS activity_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id INTEGER, username TEXT,
                        action TEXT, service_type TEXT, details TEXT, cost REAL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')

        # 🆕 جدول دامنه‌های ثبت‌شده/مدیریت‌شده در ربات (پنل «مدیریت دامنه‌ها» در تنظیمات سرور)
        c.execute('''CREATE TABLE IF NOT EXISTS domains (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT UNIQUE, host TEXT,
                        reg_date TEXT, expire_date TEXT, notes TEXT)''')

        # 🆕 استخر IPهای شناخته‌شده برای پایش سلامت/در دسترس‌بودن (تشخیص خودکار فیلترشدن).
        # ستون 'active' مشخص می‌کند این IP جزو لیست فعلیِ سرویس‌دهی («hosts» در settings) هست یا نه.
        c.execute('''CREATE TABLE IF NOT EXISTS host_pool (
                        host TEXT PRIMARY KEY, active INTEGER DEFAULT 1, consecutive_fails INTEGER DEFAULT 0,
                        last_check TEXT, last_status TEXT DEFAULT 'بررسی‌نشده', disabled_reason TEXT, disabled_at TEXT)''')
        # 🆕 کدام IP به‌عنوان «پیش‌فرض کل سیستم» انتخاب شده — یعنی همیشه اول لیست «hosts» قرار
        # می‌گیرد (جایی که کدهای قبلی fallback را با hl[0] می‌گرفتند)، به‌جای مرتب‌سازی الفبایی
        # تصادفیِ قبلی. فقط یک ردیف می‌تواند در هر لحظه is_default=1 داشته باشد.
        try: c.execute("ALTER TABLE host_pool ADD COLUMN is_default INTEGER DEFAULT 0")
        except sqlite3.OperationalError: pass
        # 🆕 اگر این Edge از طریق «ساخت VPS ابری خودکار» ساخته شده، این ستون‌ها اطلاعات لازم برای
        # مدیریتش (نمایش provider/region/اندازه، یا در آینده حذف/ریسایز از طریق API) را نگه می‌دارند.
        try: c.execute("ALTER TABLE host_pool ADD COLUMN provider TEXT DEFAULT NULL")
        except sqlite3.OperationalError: pass
        try: c.execute("ALTER TABLE host_pool ADD COLUMN provider_instance_id TEXT DEFAULT NULL")
        except sqlite3.OperationalError: pass
        # 🆕 «کدام VPS سرعتش بهتره»: میانگین (هموارشدهٔ) تاخیر اتصال TCP بر حسب میلی‌ثانیه، برای
        # مقایسهٔ IPهای فعال با هم و پیشنهاد سریع‌ترین‌شان — نه فقط «بالا هست یا نه».
        try: c.execute("ALTER TABLE host_pool ADD COLUMN avg_latency_ms REAL DEFAULT NULL")
        except sqlite3.OperationalError: pass
        # 🆕 هر IP می‌تواند پورت SSH مستقل داشته باشد. مقدارهای قدیمی از تنظیم سراسری فعلی
        # پر می‌شوند تا پس از به‌روزرسانی، لینک‌های قبلی و سرورهای موجود بدون تغییر کار کنند.
        try: c.execute("ALTER TABLE host_pool ADD COLUMN ssh_port INTEGER DEFAULT NULL")
        except sqlite3.OperationalError: pass
        # 🆕 زمان افزوده‌شدنِ این IP — برای دادن «دورهٔ مهلت» به Edgeهای تازه‌ساخته قبل از اینکه
        # پایش خودکار سلامت (_host_health_tick) سخت‌گیری کند. سرور تازه‌استارت‌شده معمولاً چند
        # دقیقه طول می‌کشد تا کامل بالا بیاید؛ بدون این مهلت، پایش می‌تواند در همون بازهٔ کوتاه
        # (که هنوز آماده نیست) آن را به‌اشتباه «از دسترس خارج» تشخیص بدهد و غیرفعالش کند — دقیقاً
        # همان false-positive که قبلاً موقع افزودن یک Edge تازه رخ داد. برای ردیف‌های قدیمیِ از قبل
        # موجود، مقدار NULL می‌ماند و کد پایین آن را «مهلت گذشته» در نظر می‌گیرد (بدون تغییر رفتار).
        try: c.execute("ALTER TABLE host_pool ADD COLUMN added_at TEXT DEFAULT NULL")
        except sqlite3.OperationalError: pass
        # 🆕 Standby: این Edge عمداً بدونِ مشتریِ فعال نگه داشته می‌شود تا در Failoverِ دستی/خودکار
        # (نگاه کنید به _activate_standby_for_filtered_edge)، کاربرانِ یک Edgeِ فیلترشده رویش
        # بازسازی و جایگزین شوند.
        try: c.execute("ALTER TABLE host_pool ADD COLUMN is_standby INTEGER DEFAULT 0")
        except sqlite3.OperationalError: pass
        _legacy_port_row = c.execute("SELECT value FROM settings WHERE key='port'").fetchone()
        try:
            _legacy_port = int(_legacy_port_row[0]) if _legacy_port_row else 22
        except (TypeError, ValueError):
            _legacy_port = 22
        if not (1 <= _legacy_port <= 65535):
            _legacy_port = 22
        c.execute("UPDATE host_pool SET ssh_port=? WHERE ssh_port IS NULL OR ssh_port < 1 OR ssh_port > 65535", (_legacy_port,))

        # 🆕 پیام‌های آمادهٔ «پیام همگانی به نمایندگان» — تا ادمین برای وضعیت‌های تکرارشونده
        # (مثلاً قطعی سرور) لازم نباشد هر بار از نو تایپ کند؛ فقط یک بار می‌سازد، بعد با یک لمس
        # + تاییدیه ارسال می‌کند.
        c.execute('''CREATE TABLE IF NOT EXISTS broadcast_presets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, body TEXT NOT NULL,
                        created_at TEXT)''')

async def _notify_super_admin(app, text: str, tg_user=None):
    super_admin_text = text
    if tg_user:
        u_info = f"\n\n👤 <b>مجری عملیات (اطلاعات تلگرام):</b>\nنام: {esc(tg_user.first_name or 'بدون نام')}\nآیدی: <code>{tg_user.id}</code>"
        if tg_user.username:
            u_info += f"\nیوزرنیم: @{esc(tg_user.username)}"
        super_admin_text = text + u_info  # این اطلاعات فقط به متن سوپر ادمین اضافه می‌شود
        
    with contextlib.suppress(Exception):
        await app.bot.send_message(chat_id=SUPER_ADMIN_ID, text=super_admin_text, parse_mode="HTML")
        
    # 📊 ارسال رونوشت به حسابدارها (فقط متن اصلی، بدون اطلاعات مجری)
    for acc_id in ACCOUNTANT_IDS:
        with contextlib.suppress(Exception):
            await app.bot.send_message(chat_id=acc_id, text=f"📊 <b>[رونوشت حسابداری]</b>\n{text}", parse_mode="HTML")

def _db_log_activity(agent_id, username, action, service_type, details, cost):
    with db_conn() as conn:
        conn.execute("INSERT INTO activity_log (agent_id, username, action, service_type, details, cost) VALUES (?, ?, ?, ?, ?, ?)",
                     (agent_id, username, action, service_type, details, cost))
        if agent_id == 0:
            agent_name = "مستقیم (ادمین)"
        else:
            r = conn.execute("SELECT name FROM agents WHERE id=?", (agent_id,)).fetchone()
            agent_name = r[0] if r else str(agent_id)
    
    # 🗄 ذخیره در دیتابیس مجزای حسابداری
    try:
        with sqlite3.connect(ACCOUNTING_DB_PATH) as acc_conn:
            acc_conn.execute('''CREATE TABLE IF NOT EXISTS finance_logs (
                            id INTEGER PRIMARY KEY AUTOINCREMENT, 
                            date TEXT, agent_name TEXT, action_type TEXT, 
                            service TEXT, amount REAL, details TEXT)''')
            acc_conn.execute("INSERT INTO finance_logs (date, agent_name, action_type, service, amount, details) VALUES (?, ?, ?, ?, ?, ?)",
                             (datetime.now(IRAN_TZ).strftime("%Y-%m-%d %H:%M:%S"), agent_name, action, service_type, cost, f"کاربر: {username} | {details}"))
            acc_conn.commit()
    except Exception as e:
        log.error(f"خطا در ثبت دیتابیس حسابداری: {e}")

async def _generate_accounting_csv(days):
    def _build():
        start_date = (datetime.now(IRAN_TZ) - timedelta(days=days)).strftime("%Y-%m-%d 00:00:00")
        try:
            with sqlite3.connect(ACCOUNTING_DB_PATH) as conn:
                conn.execute('''CREATE TABLE IF NOT EXISTS finance_logs (
                                id INTEGER PRIMARY KEY AUTOINCREMENT, 
                                date TEXT, agent_name TEXT, action_type TEXT, 
                                service TEXT, amount REAL, details TEXT)''')
                rows = conn.execute("SELECT date, agent_name, action_type, service, amount, details FROM finance_logs WHERE date >= ? ORDER BY id DESC", (start_date,)).fetchall()
        except Exception:
            rows = []
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["تاریخ و ساعت", "نماینده / شخص", "نوع عملیات", "سرویس", "مبلغ (تومان)", "توضیحات تکمیلی"])
        for r in rows:
            writer.writerow(r)
        return buf.getvalue().encode("utf-8-sig")
    return await asyncio.to_thread(_build)

def _get_super_admin_stats(aid=None):
    now = datetime.now()
    today = now.strftime("%Y-%m-%d")
    yesterday = (now - timedelta(days=1)).strftime("%Y-%m-%d")
    jy, jm, jd = gregorian_to_jalali(now.year, now.month, now.day)
    last_jm = jm - 1 if jm > 1 else 12
    last_jy = jy if jm > 1 else jy - 1
    
    with db_conn() as conn:
        c = conn.cursor()
        if aid is not None:
            creations = c.execute("SELECT creation_date FROM ssh_accounts WHERE agent_id=? AND status != '⏳ درحال ساخت'", (aid,)).fetchall()
            renewals = c.execute("SELECT created_at FROM activity_log WHERE agent_id=? AND action='extend'", (aid,)).fetchall()
            receipts = c.execute("SELECT amount, created_at FROM receipts WHERE agent_id=? AND status='approved' ORDER BY id DESC LIMIT 5", (aid,)).fetchall()
            
            s1, s2, s3, s6 = 0, 0, 0, 0
            for (cd,) in creations:
                if not cd: continue
                try:
                    days_diff = (now - datetime.strptime(cd[:10], "%Y-%m-%d")).days
                    if days_diff <= 30: s1 += 1
                    if days_diff <= 60: s2 += 1
                    if days_diff <= 90: s3 += 1
                    if days_diff <= 180: s6 += 1
                except: pass
                
            r_this, r_last = 0, 0
            for (rd,) in renewals:
                if not rd: continue
                try:
                    ry, rm, rday = map(int, rd[:10].split('-'))
                    rjy, rjm, rjd = gregorian_to_jalali(ry, rm, rday)
                    if rjy == jy and rjm == jm: r_this += 1
                    elif rjy == last_jy and rjm == last_jm: r_last += 1
                except: pass
            return s1, s2, s3, s6, r_this, r_last, receipts
        else:
            cr_tdy, cr_yest, cr_week, cr_month = 0, 0, 0, 0
            rn_tdy, rn_yest, rn_week, rn_month, rn_last_month = 0, 0, 0, 0, 0
            creations = c.execute("SELECT creation_date FROM ssh_accounts WHERE agent_id=0 AND status != '⏳ درحال ساخت'").fetchall()
            for (cd,) in creations:
                if not cd: continue
                if cd[:10] == today: cr_tdy += 1
                if cd[:10] == yesterday: cr_yest += 1
                try:
                    if (now - datetime.strptime(cd[:10], "%Y-%m-%d")).days <= 7: cr_week += 1
                    cy, cm, cday = map(int, cd[:10].split('-'))
                    cjy, cjm, cjd = gregorian_to_jalali(cy, cm, cday)
                    if cjy == jy and cjm == jm: cr_month += 1
                except: pass
                
            renewals = c.execute("SELECT created_at FROM activity_log WHERE agent_id=0 AND action='extend'").fetchall()
            for (rd,) in renewals:
                if not rd: continue
                if rd[:10] == today: rn_tdy += 1
                if rd[:10] == yesterday: rn_yest += 1
                try:
                    if (now - datetime.strptime(rd[:10], "%Y-%m-%d")).days <= 7: rn_week += 1
                    ry, rm, rday = map(int, rd[:10].split('-'))
                    rjy, rjm, rjd = gregorian_to_jalali(ry, rm, rday)
                    if rjy == jy and rjm == jm: rn_month += 1
                    elif rjy == last_jy and rjm == last_jm: rn_last_month += 1
                except: pass
            return cr_tdy, cr_yest, cr_week, cr_month, rn_tdy, rn_yest, rn_week, rn_month, rn_last_month
# --- توابع دیتابیس ---
def _db_get_setting(k, d):
    with db_conn() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key=?", (k,)).fetchone()
        return row[0] if row else d

def _hosts_fallback_with_warning(context_hint=""):
    """
    فقط وقتی صدا زده می‌شود که تنظیم 'hosts' واقعاً خالی از هر IP معتبر باشد (نه حالت عادی).
    به‌جای جایگزینیِ خاموش با یک IP قدیمی، این را به‌وضوح در لاگ سرور هشدار می‌دهد تا ادمین از
    «مدیریت میزبان‌ها» حداقل یک IP واقعی (از هر ارائه‌دهندهٔ VPS، بدون وابستگی به DigitalOcean) ثبت کند.
    """
    log.warning("تنظیم 'hosts' خالی/نامعتبر بود؛ موقتاً از LAST_RESORT_HOST_IP استفاده شد%s. "
                "لطفاً از «مدیریت میزبان‌ها» حداقل یک IP واقعی ثبت کنید.",
                f" ({context_hint})" if context_hint else "")
    return LAST_RESORT_HOST_IP
def _db_update_setting(k, v):
    with db_conn() as conn: conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (k, v))


def _build_server_settings_kb():
    """
    🛡️ نکتهٔ ساختاری برای جلوگیری از تکرار باگ امروز: قبلاً این منو در دو جای مختلف کد
    (مسیر ورود از کیبورد و مسیر بازگشتِ inline) به‌صورت دستی و جداگانه کپی شده بود، و یک‌بار
    یکی از این دو نسخه از دیگری عقب افتاد (یک دکمه فقط در یکی از آن‌ها بود). با متمرکز کردن
    ساخت این کیبورد در همین یک تابع، و صدا زدنش از هر دو مسیر، این دسته از باگ‌ها دیگر از نظر
    ساختاری امکان‌پذیر نیست — هر تغییری این‌جا، خودکار در هر دو مسیر ورودی اعمال می‌شود.
    """
    return [[InlineKeyboardButton("🖥 وضعیت و نقش سرورها (Core/Edge)", callback_data="srv_status")],
            [InlineKeyboardButton("✏️ تغییر نام برند", callback_data="srv_brand")],
            [InlineKeyboardButton("🎯 تنظیمات مستقیم", callback_data="srv_direct_menu"), InlineKeyboardButton("🔐 تنظیمات TLS", callback_data="srv_tls")],
            [InlineKeyboardButton("🔌 تنظیمات UDPGW", callback_data="srv_udpgw")],
            [InlineKeyboardButton("🖥 وضعیت سرور (CPU/RAM)", callback_data="srv_health")],
            [InlineKeyboardButton("🩺 عیب‌یابی خام اتصالات SSH", callback_data="srv_ssh_debug")],
            [InlineKeyboardButton("🩹 خودتشخیصی و رفع خودکار اتصال SSH", callback_data="srv_ssh_diag")],
            [InlineKeyboardButton("🧹 کاربران یتیم (بدون رکورد در ربات)", callback_data="orphan_menu")],
            [InlineKeyboardButton("🌐 سرویس IP / خرید سرور جدید(دستی)", callback_data="ipsvc_menu")],
            [InlineKeyboardButton("🌍 مدیریت دامنه‌ها", callback_data="dom_menu")],
            [InlineKeyboardButton("🔴🔵 RED & BLUE", callback_data="srv_rb")],
            [InlineKeyboardButton("🔙 بازگشت", callback_data="uact_back_to_menu")]]

# 🆕 توابع دیتابیس مربوط به استخر IP و پایش سلامت خودکار (تشخیص فیلترشدن/از کار افتادن)
def _normalize_ssh_port(value, fallback=22):
    """یک پورت معتبر برمی‌گرداند؛ ورودی نامعتبر هرگز وارد منطق اتصال نمی‌شود."""
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        port = int(fallback)
    return port if 1 <= port <= 65535 else int(fallback)


def _db_get_host_ssh_port(host, fallback=None):
    """پورت واقعی ثبت‌شده برای یک IP؛ در داده‌های قدیمی به پورت سراسری بازمی‌گردد."""
    with db_conn() as conn:
        if fallback is None:
            row = conn.execute("SELECT value FROM settings WHERE key='port'").fetchone()
            fallback = row[0] if row else 22
        try:
            row = conn.execute("SELECT ssh_port FROM host_pool WHERE host=?", (host,)).fetchone()
            return _normalize_ssh_port(row[0] if row and row[0] is not None else fallback,
                                       _normalize_ssh_port(fallback, 22))
        except Exception:
            return _normalize_ssh_port(fallback, 22)


def _db_get_host_ssh_port_map():
    """نقشهٔ {IP: port} برای پنل‌ها و پایش‌های دسته‌ای."""
    with db_conn() as conn:
        fallback_row = conn.execute("SELECT value FROM settings WHERE key='port'").fetchone()
        fallback = _normalize_ssh_port(fallback_row[0] if fallback_row else 22, 22)
        rows = conn.execute("SELECT host, ssh_port FROM host_pool").fetchall()
        return {host: _normalize_ssh_port(port, fallback) for host, port in rows}


def _db_set_host_ssh_port(host, port):
    port = _normalize_ssh_port(port, 22)
    with db_conn() as conn:
        conn.execute("UPDATE host_pool SET ssh_port=? WHERE host=?", (port, host))


def _db_host_exists(host):
    with db_conn() as conn:
        return conn.execute("SELECT 1 FROM host_pool WHERE host=?", (host,)).fetchone() is not None


def _db_is_default_host(host):
    with db_conn() as conn:
        row = conn.execute("SELECT is_default FROM host_pool WHERE host=?", (host,)).fetchone()
        return bool(row and row[0])


def _db_sync_host_pool():
    """هر IP که در تنظیمات «hosts» هست ولی هنوز در host_pool ثبت نشده را به‌عنوان فعال اضافه می‌کند."""
    with db_conn() as conn:
        raw = conn.execute("SELECT value FROM settings WHERE key='hosts'").fetchone()
        default_row = conn.execute("SELECT value FROM settings WHERE key='port'").fetchone()
        default_port = _normalize_ssh_port(default_row[0] if default_row else 22, 22)
        hosts = [h.strip() for h in (raw[0] if raw else '').split(',') if h.strip()]
        for h in hosts:
            conn.execute("INSERT OR IGNORE INTO host_pool (host, active, ssh_port) VALUES (?, 1, ?)", (h, default_port))
def _db_get_host_pool():
    with db_conn() as conn:
        return conn.execute("SELECT host, active, consecutive_fails, last_check, last_status, disabled_reason, disabled_at, is_default, avg_latency_ms, added_at, is_standby FROM host_pool ORDER BY is_default DESC, active DESC, host").fetchall()
def _db_get_active_hosts_from_pool():
    with db_conn() as conn:
        return [r[0] for r in conn.execute("SELECT host FROM host_pool WHERE active=1").fetchall()]
def _db_record_host_latency(host, latency_ms):
    """
    🆕 «کدام VPS سرعتش بهتره»: تاخیر اتصال TCP این بار را ثبت می‌کند. برای اینکه یک نوسان لحظه‌ای
    (مثلاً یک بستهٔ کند اتفاقی) کل رتبه‌بندی را به‌هم نریزد، به‌جای جایگزینی خام، میانگین متحرکِ
    نمایی (EMA) با وزن ۳۰٪ برای مقدار تازه محاسبه می‌شود — یعنی روند کلی سریع منعکس می‌شود ولی
    یک تک‌جهش لحظه‌ای غالب نمی‌شود.
    """
    with db_conn() as conn:
        row = conn.execute("SELECT avg_latency_ms FROM host_pool WHERE host=?", (host,)).fetchone()
        old = row[0] if row and row[0] is not None else None
        new_avg = latency_ms if old is None else (old * 0.7 + latency_ms * 0.3)
        conn.execute("UPDATE host_pool SET avg_latency_ms=? WHERE host=?", (round(new_avg, 1), host))
def _db_get_fastest_active_host():
    """سریع‌ترین IP فعال (کمترین avg_latency_ms) را برمی‌گرداند؛ اگر هیچ‌کدام هنوز تاخیرسنجی
    نشده باشند None می‌دهد (یعنی هنوز داده‌ای برای مقایسه نیست، نه اینکه IP فعالی نباشد)."""
    with db_conn() as conn:
        row = conn.execute("SELECT host FROM host_pool WHERE active=1 AND avg_latency_ms IS NOT NULL ORDER BY avg_latency_ms ASC LIMIT 1").fetchone()
        return row[0] if row else None
async def _run_speed_test_all_hosts():
    """
    🆕 V89 — تست سرعت همهٔ IPهای فعال به‌صورت یکجا و موازی.
    هر IP را IP_SPEED_TEST_SAMPLES بار تست می‌کند و میانگین تاخیر را در دیتابیس ذخیره می‌کند.
    خروجی: لیست [(host, avg_ms, ok), ...] مرتب از سریع‌ترین به کندترین
    """
    pool = await asyncio.to_thread(_db_get_host_pool)
    port_map = await asyncio.to_thread(_db_get_host_ssh_port_map)

    async def _test_one_host(host):
        samples = []
        host_port = port_map.get(host, 22)
        for _ in range(IP_SPEED_TEST_SAMPLES):
            t0 = time.monotonic()
            ok, err = await _tcp_health_check(host, host_port, timeout=IP_SPEED_TEST_PARALLEL_TIMEOUT)
            elapsed = (time.monotonic() - t0) * 1000
            if ok:
                samples.append(elapsed)
            await asyncio.sleep(0.3)
        if samples:
            avg = sum(samples) / len(samples)
            await asyncio.to_thread(_db_record_host_latency, host, avg)
            return host, round(avg, 1), True
        return host, None, False

    active_hosts = [r[0] for r in pool if r[1]]  # r[1] = active
    if not active_hosts:
        return []
    tasks = [_test_one_host(h) for h in active_hosts]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    out = []
    for r in results:
        if isinstance(r, Exception):
            continue
        out.append(r)
    out.sort(key=lambda x: (x[2] is False, x[1] if x[1] is not None else 99999))
    return out

def _db_record_host_check(host, ok, reason=None):
    """نتیجهٔ یک بار تست را ثبت می‌کند و تعداد شکست‌های متوالیِ فعلی را برمی‌گرداند (۰ یعنی موفق)."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with db_conn() as conn:
        if ok:
            conn.execute("UPDATE host_pool SET consecutive_fails=0, last_check=?, last_status='🟢 سالم' WHERE host=?", (now, host))
            return 0
        row = conn.execute("SELECT consecutive_fails FROM host_pool WHERE host=?", (host,)).fetchone()
        fails = (row[0] if row else 0) + 1
        conn.execute("UPDATE host_pool SET consecutive_fails=?, last_check=?, last_status=? WHERE host=?",
                     (fails, now, f"🔴 ناموفق: {str(reason)[:150]}", host))
        return fails
def _db_set_host_active(host, active: bool, reason=None):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with db_conn() as conn:
        if active:
            conn.execute("UPDATE host_pool SET active=1, consecutive_fails=0, disabled_reason=NULL, disabled_at=NULL, last_status='🟢 سالم', last_check=? WHERE host=?", (now, host))
        else:
            conn.execute("UPDATE host_pool SET active=0, disabled_reason=?, disabled_at=? WHERE host=?", (reason, now, host))
def _db_add_host_pool(host):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with db_conn() as conn: conn.execute("INSERT OR IGNORE INTO host_pool (host, active, added_at) VALUES (?, 1, ?)", (host, now))
def _db_remove_host_pool(host):
    with db_conn() as conn: conn.execute("DELETE FROM host_pool WHERE host=?", (host,))

def _db_set_host_standby(host, is_standby: bool):
    """🆕 علامت‌گذاریِ یک Edge به‌عنوانِ Standby (بدونِ مشتریِ فعال، آمادهٔ Failover)."""
    with db_conn() as conn:
        conn.execute("UPDATE host_pool SET is_standby=? WHERE host=?", (1 if is_standby else 0, host))

def _db_get_standby_hosts():
    """Standbyهایی که active=1 هستند (یعنی سالم و آمادهٔ فعال‌سازیِ فوری)."""
    with db_conn() as conn:
        return [r[0] for r in conn.execute(
            "SELECT host FROM host_pool WHERE is_standby=1 AND active=1").fetchall()]

def _pick_target_host_for_new_account():
    try:
        pool = _db_get_host_pool()
        # استفاده از len برای اطمینان از اینکه اگر ستون is_standby در دیتابیس ساخته نشده بود، کرش نکند
        candidates = [r[0] for r in pool if r[1] and (len(r) < 11 or not r[10])]
        if not candidates:
            return _hosts_fallback_with_warning("pick_target_host_for_new_account")
        with db_conn() as conn:
            rows = conn.execute(
                "SELECT host, COUNT(*) FROM ssh_accounts WHERE host IS NOT NULL AND host != '' GROUP BY host").fetchall()
        counts = dict(rows)
        candidates.sort(key=lambda h: counts.get(h, 0))
        return candidates[0]
    except Exception as e:
        log.error(f"Error in picking target host: {e}")
        return _hosts_fallback_with_warning("error_in_picking_host")

async def _acct_host_port(owner_row):
    """
    🆕 برایِ عملیاتِ مدیریتی روی یک اکانتِ **از‌قبل‌موجود** (حذف/قفل/تغییرِ پسورد/انقضا):
    Edgeِ صاحبِ اکانت را از خودِ رکورد می‌خواند (owner_row = خروجیِ _db_get_user، ایندکسِ ۶ = host).
    اگر رکورد قدیمی باشد و host مقدار نداشته باشد (host=NULL از قبل از این مهاجرت)، برایِ
    سازگاریِ عقب‌رو، یک Edgeِ فعال انتخاب می‌شود — نه اینکه عملیات کلاً شکست بخورد.
    خروجی: (host, port)
    """
    host = owner_row[6] if owner_row and len(owner_row) > 6 else None
    if not host:
        host = await asyncio.to_thread(_pick_target_host_for_new_account)
    port = await asyncio.to_thread(_db_get_host_ssh_port, host, 22)
    return host, port

# 🆕 حذفِ *کامل* یک Edge — قبلاً «حذف» فقط یک ردیف از دیتابیس (host_pool) پاک می‌کرد، ولی
# Peer متناظرش در wg0.conf محلی (که موقع «افزودن خودکار Edge جدید» نوشته شده بود) دست‌نخورده
# می‌ماند — یعنی تونل WireGuard آن Edge روی Core هنوز برقرار/تعریف‌شده باقی می‌ماند، با این‌که
# از دید ربات آن IP دیگر جزو استخر نبود. این تابع همان بلاک [Peer] را هم پیدا و پاک می‌کند.
# شناسایی بلاک از روی همان کامنتی انجام می‌شود که _provision_new_edge_sync موقع افزودن نوشته:
# «# edge-{ip-with-dashes}» — دقیقاً همان قالبی که در آنجا ساخته می‌شود.
def _remove_edge_wg_peer_sync(edge_ip):
    """
    تابع مسدودکننده: بلاک [Peer] مربوط به این Edge را از wg0.conf محلی حذف می‌کند و بلافاصله
    همان تغییر را (بدون قطع تونل بقیهٔ Edgeها) روی رابط زندهٔ wg0 هم با «wg set ... remove»
    اعمال می‌کند.
    خروجی: (ok, message)
    """
    edge_name = f"edge-{edge_ip.replace('.', '-')}"
    if not os.path.exists(WG_CONF_PATH):
        return False, "❌ فایل wg0.conf روی این سرور پیدا نشد."
    try:
        with open(WG_CONF_PATH) as f:
            lines = f.readlines()
    except Exception as e:
        return False, f"❌ خواندن wg0.conf شکست خورد: {e}"

    new_lines = []
    removed_pubkey = None
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.strip() == "[Peer]" and i + 1 < len(lines) and lines[i + 1].strip() == f"# {edge_name}":
            # این همان بلاکیه که باید حذف بشه — قبل از ردکردنش، PublicKey رو برای «wg set remove» استخراج کن
            j = i + 1
            while j < len(lines) and not (lines[j].strip() == "[Peer]" and j != i):
                m = re.match(r'\s*PublicKey\s*=\s*(\S+)', lines[j])
                if m:
                    removed_pubkey = m.group(1)
                j += 1
            i = j
            continue
        new_lines.append(line)
        i += 1

    if removed_pubkey is None:
        return False, f"ℹ️ هیچ Peerای با نام «{edge_name}» توی wg0.conf پیدا نشد (شاید قبلاً حذف شده یا این IP اصلاً Edge نبوده)."

    try:
        with open(WG_CONF_PATH, "w") as f:
            f.writelines(new_lines)
    except Exception as e:
        return False, f"❌ نوشتن wg0.conf شکست خورد: {e}"

    try:
        subprocess.run(["wg", "set", "wg0", "peer", removed_pubkey, "remove"], check=True, timeout=10)
    except Exception as e:
        return True, f"⚠️ از wg0.conf حذف شد، ولی اعمال زنده روی رابط wg0 شکست خورد ({e}) — با ریستارت سرویس wg-quick@wg0 هم اعمال می‌شود."

    return True, "✅ Peer از wg0.conf و از رابط زندهٔ wg0 حذف شد."

def _db_set_host_provider_meta(host, provider, instance_id):
    with db_conn() as conn:
        conn.execute("UPDATE host_pool SET provider=?, provider_instance_id=? WHERE host=?", (provider, instance_id, host))
# 🆕 ☁️ لازم برای Self-Heal کلودزی: قبل از تصمیم به حذفِ خودکارِ یک Edge از طریق API، باید
# مطمئن شویم آن Edge اصلاً از طریق همان ارائه‌دهنده ساخته شده (وگرنه ممکن است یک VPS دستی/از
# ارائه‌دهندهٔ دیگر را اشتباهی با یک instance_id نامرتبط حذف کنیم).
def _db_get_host_provider_meta(host):
    with db_conn() as conn:
        row = conn.execute("SELECT provider, provider_instance_id FROM host_pool WHERE host=?", (host,)).fetchone()
        return (row[0], row[1]) if row else (None, None)

# 🆕 «پیش‌فرض کل سیستم» — فقط یک IP در هر لحظه می‌تواند این باشد
def _db_set_default_host(host):
    with db_conn() as conn:
        conn.execute("UPDATE host_pool SET is_default=0")
        conn.execute("UPDATE host_pool SET is_default=1 WHERE host=?", (host,))
def _db_get_default_host():
    with db_conn() as conn:
        row = conn.execute("SELECT host FROM host_pool WHERE is_default=1 AND active=1").fetchone()
        return row[0] if row else None

# 🆕 ثبت زمان آخرین سوییچ IP (چه خودکار چه دستی) — برای اعمال cooldown و جلوگیری از فلَپینگ
def _db_mark_ip_switch_now():
    _db_update_setting('last_ip_switch_at', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
def _db_seconds_since_last_ip_switch():
    """اگر سوییچی ثبت نشده باشد، مقدار بزرگی برمی‌گرداند (یعنی محدودیتی وجود ندارد)."""
    raw = _db_get_setting('last_ip_switch_at', '')
    if not raw:
        return float('inf')
    try:
        last = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return float('inf')
    return (datetime.now() - last).total_seconds()

# ============================================================================
# 🚀 افزودن خودکار Edge جدید — SSH به یک VPS خام، اجرای setup_edge_relay.sh،
# ثبت خودکار Peer روی Core، و افزودن به سرویس IP. (نیازمند: pip install paramiko)
# ============================================================================
EDGE_SETUP_SCRIPT_LOCAL_PATH = "/root/setup_edge_relay.sh"   # مسیر محلی روی Core
WG_CONF_PATH = "/etc/wireguard/wg0.conf"
CORE_PUBKEY_PATH = "/etc/wireguard/core_public.key"

# رمز روتِ Edge جدید فقط این‌جا (حافظهٔ RAM، نه در context.user_data که persist
# می‌شود) نگه‌داری می‌شود تا هرگز به‌صورت متن‌ساده روی دیسک (bot_persistence.pickle)
# ذخیره نشود. بلافاصله بعد از مصرف با .pop() پاک می‌شود.
_EDGE_PROVISION_SECRETS = {}


def _get_core_wg_identity():
    """پورت گوش‌دادن و کلید عمومی Core را از فایل‌های محلی می‌خواند."""
    port = None
    try:
        with open(WG_CONF_PATH) as f:
            for line in f:
                line = line.strip()
                if line.startswith("ListenPort"):
                    port = line.split("=", 1)[1].strip()
                    break
    except FileNotFoundError:
        return None, None
    try:
        with open(CORE_PUBKEY_PATH) as f:
            pubkey = f.read().strip()
    except FileNotFoundError:
        return port, None
    return port, pubkey


def _force_ipv4_urlopen(url, timeout=6):
    """
    یک URL را با اجبار به IPv4 باز می‌کند — دقیقاً معادل رفتار «curl -4».
    چرا لازم است: Python's urllib به‌صورت پیش‌فرض هر رکورد IPی که getaddrinfo برگرداند (چه IPv4
    چه IPv6) را امتحان می‌کند، معمولاً IPv6 را اول. اگر مسیر IPv6 این سرور سالم نباشد (نه بلاک،
    فقط بی‌پاسخ/سیاه‌چاله)، اتصال تا انتهای timeout آویزان می‌ماند و بعد شکست می‌خورد — حتی وقتی
    curl -4 دستی (که صراحتاً IPv4 را انتخاب می‌کند) فوری و بی‌مشکل جواب می‌دهد.
    اینجا موقتاً socket.getaddrinfo را طوری monkey-patch می‌کنیم که فقط رکوردهای IPv4 (AF_INET)
    برگرداند، درخواست را می‌فرستیم، و بلافاصله در finally نسخهٔ اصلی تابع را برمی‌گردانیم — تا
    این تغییر فقط روی همین یک درخواست اثر بگذارد و هیچ بخش دیگری از ربات (که شاید به IPv6 نیاز
    داشته باشد) تحت‌تاثیر قرار نگیرد.
    """
    orig_getaddrinfo = socket.getaddrinfo

    def _ipv4_only_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        return orig_getaddrinfo(host, port, socket.AF_INET, type, proto, flags)

    socket.getaddrinfo = _ipv4_only_getaddrinfo
    try:
        return urllib.request.urlopen(url, timeout=timeout).read().decode().strip()
    finally:
        socket.getaddrinfo = orig_getaddrinfo


def _get_core_public_ip_cached():
    """
    IP عمومی خودِ Core را از تنظیمات دیتابیس می‌خواند؛ اگر نبود، از یکی از چند سرویس مستقلِ
    تشخیص IP می‌گیرد و ذخیره می‌کند.
    🐛🔧 رفع باگ: قبلاً فقط یک سرویس (ifconfig.me) و بدون اجبار IPv4 امتحان می‌شد. دو مشکل داشت:
    ۱) اگر مسیر IPv6 این سرور سالم نبود، urllib آن را اول امتحان می‌کرد و تا پایان timeout آویزان
       می‌ماند، حتی وقتی curl -4 دستی فوری جواب می‌داد (دقیقاً همان چیزی که با تست دستی تایید شد).
    ۲) اگر خودِ ifconfig.me موقتاً کند/بی‌پاسخ/rate-limit بود، کل فرآیند تشخیص IP (و به‌تبع آن
       افزودن Edge جدید) متوقف می‌شد، چون هیچ جایگزینی نداشت.
    الان: هر درخواست با اجبار IPv4 انجام می‌شود (_force_ipv4_urlopen)، و چهار سرویس مستقل از هم
    به‌ترتیب امتحان می‌شوند تا یکی جواب بدهد.
    """
    ip = _db_get_setting('core_wg_public_ip', '')
    if ip:
        return ip
    ip_services = [
        'https://api.ipify.org',
        'https://ifconfig.me',
        'https://icanhazip.com',
        'https://checkip.amazonaws.com',
    ]
    for svc in ip_services:
        try:
            candidate = _force_ipv4_urlopen(svc, timeout=6)
            if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', candidate):
                _db_update_setting('core_wg_public_ip', candidate)
                return candidate
        except Exception:
            continue  # 🔁 این سرویس جواب نداد؛ سرویس مستقل بعدی را امتحان کن
    return ''


def _next_edge_wg_ip():
    """با خواندن wg0.conf محلی، اولین IP داخلی آزاد (10.77.0.X) را پیدا می‌کند."""
    used = set()
    try:
        with open(WG_CONF_PATH) as f:
            content = f.read()
        for m in re.finditer(r'AllowedIPs\s*=\s*10\.77\.0\.(\d+)/32', content):
            used.add(int(m.group(1)))
    except FileNotFoundError:
        pass
    n = 2
    while n in used:
        n += 1
    return f"10.77.0.{n}"


def _provision_new_edge_sync(edge_ip, root_password, customer_port, edge_name, private_key_path=None, connect_retries=1):
    """
    تابع مسدودکننده (blocking، به‌خاطر paramiko و subprocess). باید حتماً با
    asyncio.to_thread صدا زده شود، نه مستقیم داخل event loop.
    خروجی: (ok: bool, error_msg: str, result: dict|None)
    🆕 private_key_path: اگر داده شود، به‌جای رمز عبور، با کلید SSH وارد می‌شود — دقیقاً همان
    روشی که VPSهای ساخته‌شده از طریق «ساخت VPS ابری خودکار» با آن دسترسی دارند (چون آن
    دراپلت‌ها اصلاً رمز روت ندارند، فقط کلید). connect_retries برای زمانی است که سرور تازه
    از cloud-init بالا آمده و SSHـش هنوز کاملاً آماده نیست — چند بار با فاصله دوباره تلاش می‌کند.
    """
    if paramiko is None:
        return False, "❌ کتابخانهٔ paramiko نصب نیست. روی Core بزنید: pip install paramiko --break-system-packages", None

    core_port, core_pubkey = _get_core_wg_identity()
    core_public_ip = _get_core_public_ip_cached()
    if not core_port or not core_pubkey:
        return False, "❌ نتوانستم هویت WireGuard خودِ Core را از /etc/wireguard بخوانم. مطمئن شوید setup_core_wireguard.sh قبلاً روی Core اجرا شده.", None
    if not core_public_ip:
        return False, "❌ نتوانستم IP عمومی Core را تشخیص دهم (هر ۴ سرویس تشخیص IP بی‌پاسخ ماندند؛ اتصال خروجی HTTPS این سرور را چک کنید).", None
    if not os.path.exists(EDGE_SETUP_SCRIPT_LOCAL_PATH):
        return False, f"❌ فایل {EDGE_SETUP_SCRIPT_LOCAL_PATH} روی Core پیدا نشد؛ اول آن را همان‌جا آپلود کنید.", None

    edge_wg_ip = _next_edge_wg_ip()

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    last_err = None
    connected_port = None
    # 🐛🔧 رفع باگ «اتصال SSH روی Edge شکست خورد: timed out»: قبلاً این‌جا همیشه فقط پورت
    # پیش‌فرض ۲۲ امتحان می‌شد (فرض: «این همیشه یک VPS کاملاً خام است»). این فرض برای سروری که
    # قبلاً (مثلاً از طریق پنل «تغییر واقعی پورت SSH») پورتش عوض شده و الان دیگه واقعاً یک VPS
    # خام نیست، غلطه — sshd دیگه روی ۲۲ گوش نمی‌ده. الان اگه ۲۲ جواب نداد، پورتِ مشتری که خودِ
    # ادمین همین الان وارد کرده (customer_port) هم به‌عنوان تلاش دوم امتحان می‌شه.
    candidate_ports = [22] + ([_normalize_ssh_port(customer_port, 22)] if _normalize_ssh_port(customer_port, 22) != 22 else [])
    for attempt in range(connect_retries):
        for cp in candidate_ports:
            try:
                if private_key_path:
                    pkey = paramiko.Ed25519Key.from_private_key_file(private_key_path)
                    ssh.connect(edge_ip, port=cp, username='root', pkey=pkey, timeout=15, banner_timeout=20)
                else:
                    # 🐛🔧 رفع باگ «Authentication failed» با رمز درست: پیش‌فرض paramiko قبل از
                    # امتحان‌کردن رمز، اول چند فایل کلید محلی رایج (id_rsa/id_ed25519/...) را هم
                    # امتحان می‌کند. اگر سرور مقصد MaxAuthTries محدودی داشته باشد (رایج در
                    # سخت‌سازی‌های امنیتی)، همین چند تلاش اضافه با کلید، سهمیه را قبل از رسیدن به
                    # رمز واقعی مصرف می‌کند و سرور با «Authentication failed» اتصال را می‌بندد —
                    # حتی با رمز کاملاً درست. با غیرفعال‌کردن look_for_keys/allow_agent فقط همان
                    # یک تلاشِ رمز انجام می‌شود.
                    ssh.connect(edge_ip, port=cp, username='root', password=root_password, timeout=15,
                                banner_timeout=15, look_for_keys=False, allow_agent=False)
                last_err = None
                connected_port = cp
                break
            except Exception as e:
                last_err = e
        if last_err is None:
            break
        if attempt < connect_retries - 1:
            time.sleep(10)
    if last_err is not None:
        tried = ", ".join(str(p) for p in candidate_ports)
        with contextlib.suppress(Exception):
            ssh.close()
        return False, f"❌ اتصال SSH روی Edge شکست خورد (بعد از {connect_retries} تلاش، پورت‌های امتحان‌شده: {tried}): {last_err}", None

    # 🐛🔧 همون فیکسِ «هنگِ ابدی» (keepalive + timeout واقعیِ SFTP) که تو مسیرهای Promote اعمال
    # شد، اینجا هم لازم بود — چون sftp.put پایین‌تر (خطِ setup_edge_relay.sh) قبلاً هیچ timeout
    # ی نداشت.
    _transport = ssh.get_transport()
    if _transport is not None:
        _transport.set_keepalive(10)

    # 🆕 رفع خودکار تناقضِ شناخته‌شدهٔ ایمیج‌های ابری اوبونتو (Hostinger و اکثر ارائه‌دهنده‌های دیگر
    # از همین ایمیج پایه استفاده می‌کنند): فایل پیش‌فرض /etc/ssh/sshd_config.d/60-cloudimg-settings.conf
    # معمولاً هم «PasswordAuthentication no» و هم «PermitRootLogin prohibit-password» دارد، در حالی‌که
    # فایل دیگری از cloud-init (50-cloud-init.conf) «PasswordAuthentication yes» می‌گذارد. فایل ۶۰
    # (به‌خاطر ترتیب الفبایی بارگذاری) روی PasswordAuthentication برنده می‌شود، و PermitRootLogin
    # جداگانه ورود روت با رمز را می‌بندد — حتی اگر PasswordAuthentication را دستی «yes» کنید. نتیجه:
    # از کنسول وب پنل هاست (که اصلاً از SSH رد نمی‌شود) رمز کار می‌کند، ولی از هر کلاینت واقعی SSH
    # (ربات/MobaXterm/JuiceSSH/NPV Tunnel) همیشه «Authentication failed» می‌گیرید — بدون اینکه رمز
    # واقعاً اشتباه یا عوض‌شده باشد.
    # 🔧 راه‌حل قوی‌تر از sed ساده: به‌جای ویرایش فایل‌های موجود (که فقط یک الگوی خاص را می‌شناسد)،
    # یک فایل override با نام «99-» می‌سازیم که چون آخر همه خوانده می‌شود، همیشه برنده است — فارغ
    # از اینکه فایل‌های ۵۰/۶۰ چه چیز دیگری بگویند یا در آینده اضافه شوند.
    try:
        _fix_cmd = (
            "cat > /etc/ssh/sshd_config.d/99-nvlbot-force-password-auth.conf << 'INNER'\n"
            "PasswordAuthentication yes\n"
            "PermitRootLogin yes\n"
            "KbdInteractiveAuthentication yes\n"
            "INNER\n"
            "sshd -t && (systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true)"
        )
        _stdin, _stdout, _stderr = ssh.exec_command(_fix_cmd, timeout=20)
        _stdout.channel.recv_exit_status()  # منتظر پایان واقعی دستور می‌مانیم
    except Exception as _e:
        log.warning("رفع خودکار تناقض PasswordAuthentication/PermitRootLogin روی Edge %s شکست خورد (غیربحرانی): %s", edge_ip, _e)

    # 🆕 نصب کلید عمومی دائمیِ Core روی این Edge (idempotent) — تا از این به بعد Core بدون نیاز
    # به رمز روت بتواند دوباره SSH بزند (مثلاً برای گرفتن CPU/RAM واقعی این سرور). اگر این مرحله
    # شکست بخورد، کل عملیات را متوقف نمی‌کنیم — فقط لاگ می‌شود، چون خودِ Edge نصب می‌شود.
    ok_key, err_key = _install_local_pubkey_on_open_ssh(ssh)
    if not ok_key:
        log.warning("نصب کلید SSH دائمی روی Edge %s شکست خورد: %s", edge_ip, err_key)
    
    with db_conn() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key='tls_port'").fetchone()
        tls_port_val = row[0] if row else '2088'

    sftp = None
    try:
        sftp = ssh.open_sftp()
        sftp.get_channel().settimeout(90)  # 🆕 دیگه put ابدی بلاک نمی‌مونه
        sftp.put(EDGE_SETUP_SCRIPT_LOCAL_PATH, "/root/setup_edge_relay.sh")
        sftp.close()
        sftp = None

        cmd = (
            "chmod +x /root/setup_edge_relay.sh && "
            f"bash /root/setup_edge_relay.sh {core_public_ip} {core_port} {core_pubkey} {edge_wg_ip} {customer_port} {tls_port_val}"
        )
        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=240)
        out = stdout.read().decode(errors='replace')
        err = stderr.read().decode(errors='replace')
    except Exception as e:
        return False, f"❌ اجرای اسکریپت روی Edge شکست خورد: {e}", None
    finally:
        if sftp is not None:
            with contextlib.suppress(Exception):
                sftp.close()
        with contextlib.suppress(Exception):
            ssh.close()

    m = re.search(r'کلید عمومی این Edge:\s*(\S+)', out)
    if not m:
        return False, (f"❌ اسکریپت روی Edge اجرا شد ولی کلید عمومی در خروجی پیدا نشد.\n\n"
                        f"انتهای خروجی:\n<code>{esc(out[-1200:])}</code>\n\n"
                        f"خطا:\n<code>{esc(err[-500:])}</code>"), None
    edge_pubkey = m.group(1)

    # ثبت پیر روی خودِ Core (محلی، نه SSH)
    try:
        with open(WG_CONF_PATH, "a") as f:
            f.write(f"\n[Peer]\n# {edge_name}\nPublicKey = {edge_pubkey}\nAllowedIPs = {edge_wg_ip}/32\n")
        subprocess.run(
            "wg syncconf wg0 <(wg-quick strip wg0)",
            shell=True, executable="/bin/bash", check=True, timeout=10
        )
    except Exception as e:
        return False, f"⚠️ Edge راه‌اندازی شد ولی ثبتش روی Core شکست خورد: {e}\nکلید عمومی Edge (دستی ثبت کنید): <code>{esc(edge_pubkey)}</code>", None

    # تست هندشیک/اتصال داخل تونل
    time.sleep(2)
    tunnel_ok = False
    try:
        ping_out = subprocess.run(["ping", "-c", "3", "-W", "2", edge_wg_ip],
                                   capture_output=True, text=True, timeout=15)
        tunnel_ok = "0% packet loss" in ping_out.stdout
    except Exception:
        pass

    return True, "", {"edge_wg_ip": edge_wg_ip, "edge_pubkey": edge_pubkey, "tunnel_ok": tunnel_ok}


async def _provision_new_edge(edge_ip, root_password, customer_port, edge_name, chat_id, app,
                               private_key_path=None, connect_retries=1, provider=None, provider_instance_id=None):
    """رَپِر async: کار سنگین را در thread جدا اجرا می‌کند تا event loop ربات بلاک نشود.
    🆕 private_key_path/connect_retries برای VPSهایی که از «ساخت VPS ابری خودکار» می‌آیند (بدون
    رمز روت، فقط کلید، و تازه بوت شده پس ممکن است SSHـش چند ثانیه دیرتر آماده شود).
    provider/provider_instance_id فقط برای نمایش/آیندهٔ مدیریت (حذف از طریق API) ذخیره می‌شود.
    🆕 ☁️ خروجی: (ok: bool, edge_ip_or_None, result_dict_or_None) — قبلاً این تابع چیزی برنمی‌گرداند
    (فراخوان‌های قبلی هم چیزی از خروجی نمی‌خوانند، پس این تغییر با آن‌ها کاملاً سازگار می‌ماند)،
    ولی گردش‌کارهای خودکارِ جدید (Self-Heal کلودزی / خرید دستی) باید *برنامه‌نویسی‌شده* بدانند
    که آیا راه‌اندازی واقعاً موفق بود یا نه، تا فقط در صورت موفقیت به مرحلهٔ بعد (سوییچ ترافیک،
    حذفِ سرور قدیمی) بروند."""
    # 🐛🔧 سقفِ زمانیِ بیرونی: حتی اگه thread (به هر دلیلِ پیش‌بینی‌نشده‌ای) گیر کنه، ربات بعد از
    # این مهلت خودش کنترل رو پس می‌گیره به‌جای اینکه برای همیشه بی‌پاسخ بمونه.
    # connect_retries می‌تونه چند بار با فاصلهٔ ۱۰ ثانیه تلاش کنه، پس سقف باید فضای کافی بده.
    _provision_timeout = 300 + max(0, connect_retries - 1) * 15
    try:
        ok, err, result = await asyncio.wait_for(
            asyncio.to_thread(
                _provision_new_edge_sync, edge_ip, root_password, customer_port, edge_name,
                private_key_path, connect_retries
            ),
            timeout=_provision_timeout,
        )
    except asyncio.TimeoutError:
        await app.bot.send_message(
            chat_id,
            f"❌ راه‌اندازیِ Edge <code>{esc(edge_ip)}</code> بعد از {_provision_timeout} ثانیه بدون پاسخ موند "
            f"(احتمالاً شبکه قطع/گیر کرده) — عملیات لغو شد. دوباره امتحان کنید.",
            parse_mode="HTML")
        return False, None, None
    if not ok:
        await app.bot.send_message(chat_id, err, parse_mode="HTML")
        return False, None, None

    await asyncio.to_thread(_db_add_host_pool, edge_ip)
    if provider:
        await asyncio.to_thread(_db_set_host_provider_meta, edge_ip, provider, provider_instance_id)
    cur_hosts = [h.strip() for h in (await asyncio.to_thread(_db_get_setting, 'hosts', '')).split(',') if h.strip()]
    if edge_ip not in cur_hosts:
        cur_hosts.append(edge_ip)
        await asyncio.to_thread(_db_update_setting, 'hosts', ",".join(cur_hosts))
    await asyncio.to_thread(_db_set_host_active, edge_ip, True)

    status = "✅ پینگ داخل تونل جواب داد." if result["tunnel_ok"] else "⚠️ تونل بالا آمد ولی پینگ داخلی جواب نداد — دستی با «wg show» چک کنید."
    kb = InlineKeyboardMarkup([[InlineKeyboardButton("⭐ این IP را پیش‌فرض کل سیستم کن", callback_data=f"hpdef_{edge_ip}")],
                               [InlineKeyboardButton("🛡 وضعیت و مسدودسازی IPها", callback_data="hp_menu")]])
    await app.bot.send_message(
        chat_id,
        f"🎉 <b>Edge جدید با موفقیت راه‌اندازی شد</b>\n\n"
        f"🌐 IP عمومی: <code>{esc(edge_ip)}</code>\n"
        f"🔒 IP داخلی تونل: <code>{result['edge_wg_ip']}</code>\n"
        f"🔑 کلید عمومی Edge: <code>{esc(result['edge_pubkey'])}</code>\n"
        f"{status}\n\n"
        f"این IP هم‌اکنون به «🌐 سرویس IP» اضافه و فعال شد.",
        parse_mode="HTML", reply_markup=kb
    )
    return True, edge_ip, result
# ============================================================================
# پایان بخش «افزودن خودکار Edge جدید»
# ============================================================================

# ============================================================================
# 🔑 کلیدِ دائمیِ SSH برایِ مدیریتِ Edgeها — طبقِ معماریِ جدید (Control-Plane/Data-Plane)
# این کلید دیگر به هیچ ارائه‌دهندهٔ خاصی (DigitalOcean/Cloudzy) وابسته نیست؛ صرفاً همان
# جفت‌کلیدِ ثابتی است که ربات برایِ SSH به هر Edge (چه دستی اضافه شده، چه با هر روشِ دیگر)
# استفاده می‌کند. نامش به‌خاطرِ سازگاری با بقیهٔ کدبیس (و اسکریپت‌های Bash که همین مسیر را
# hardcode دارند) عوض نشد.
# ============================================================================
DO_SSH_KEY_PATH = "/root/.ssh/edge_provision_ed25519"

def _ensure_local_ssh_keypair_sync():
    """
    🆕 جفت‌کلید SSH دائمیِ Core را (اگر قبلاً نساخته) می‌سازد. این همان کلیدی است که قبلاً فقط
    برای VPSهای ساخته‌شده از طریق «ساخت VPS ابری خودکار» استفاده می‌شد؛ حالا برای *هر* Edge
    (چه دستی اضافه شده باشد چه خودکار) هم استفاده می‌شود تا Core بعد از راه‌اندازیِ اولیه، بدون
    نیاز به نگه‌داشتن رمز روت، بتواند دوباره به آن سرور SSH بزند (مثلاً برای خواندن CPU/RAM واقعی).
    خروجی: (ok, error_or_none, pubkey_content_or_None)
    """
    os.makedirs(os.path.dirname(DO_SSH_KEY_PATH), exist_ok=True)
    if not os.path.exists(DO_SSH_KEY_PATH):
        r = subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", DO_SSH_KEY_PATH, "-N", "", "-q"],
                            capture_output=True, text=True, timeout=20)
        if r.returncode != 0:
            return False, f"❌ ساخت کلید SSH محلی شکست خورد: {r.stderr.strip()}", None
    with open(DO_SSH_KEY_PATH + ".pub") as f:
        pubkey_content = f.read().strip()
    return True, None, pubkey_content


def _install_local_pubkey_on_open_ssh(ssh):
    """
    با یک نشست paramiko *از قبل متصل*، کلید عمومی دائمیِ Core را (اگر از قبل نبود) به
    authorized_keys روت همان سرور اضافه می‌کند. idempotent است — اجرای دوباره خطا نمی‌دهد.
    خروجی: (ok, error_or_none)
    """
    ok, err, pubkey_content = _ensure_local_ssh_keypair_sync()
    if not ok:
        return False, err
    try:
        pubkey_escaped = pubkey_content.replace("'", "'\\''")
        cmd = (
            "mkdir -p /root/.ssh && chmod 700 /root/.ssh && "
            f"grep -qxF '{pubkey_escaped}' /root/.ssh/authorized_keys 2>/dev/null || "
            f"echo '{pubkey_escaped}' >> /root/.ssh/authorized_keys && "
            "chmod 600 /root/.ssh/authorized_keys"
        )
        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=20)
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            return False, stderr.read().decode(errors='ignore').strip() or "کد خروج ناموفق"
        return True, None
    except Exception as e:
        return False, str(e)


# 🗑 حذف‌شده: خریدِ خودکارِ VPS از طریقِ APIِ DigitalOcean (_do_ensure_ssh_key_sync،
# _do_create_droplet_sync، _do_wait_for_ip_sync، _do_delete_droplet_sync، _do_provision_new_vps).
# طبقِ معماریِ جدید (Control-Plane/Data-Plane)، افزودنِ Edge فقط دستی و از پیش‌آماده انجام
# می‌شود؛ Failover هم فقط با سرورهایِ Standbyِ از‌قبل‌ثبت‌شده کار می‌کند، نه خریدِ زندهٔ VPS.

# 🗑 حذف‌شده: کل یکپارچه‌سازیِ Cloudzy API (پیکربندی، Self-Healing خودکار هنگامِ فیلترشدن،
# و خریدِ دستیِ VPS). طبقِ معماریِ جدید، Failover فقط با سرورهایِ Standbyِ از‌قبل‌ثبت‌شده در
# host_pool کار می‌کند (نگاه کنید به _activate_standby_for_filtered_edge پایین‌تر در همین فایل).

def _db_rebuild_hosts_from_pool():
    """تنظیم «hosts» (که همه‌جای ربات برای ساخت فاکتور/کد اتصال استفاده می‌شود) را از روی
    IPهای فعالِ host_pool بازسازی می‌کند. سایر بخش‌های کد بدون هیچ تغییری همچنان از همان
    تنظیم قدیمی «hosts» می‌خوانند؛ فقط منبع تولیدش عوض شده.
    🆕 اگر یک IP به‌عنوان «پیش‌فرض کل سیستم» ست شده باشد، همیشه اول لیست قرار می‌گیرد — چون
    تمام جاهای کد قدیمی که fallback را با hl[0] می‌گرفتند، دقیقاً همین رفتار را انتظار دارند."""
    with db_conn() as conn:
        active = [r[0] for r in conn.execute("SELECT host FROM host_pool WHERE active=1 ORDER BY is_default DESC, host").fetchall()]
        if active:  # هرگز لیست را کامل خالی نمی‌کنیم تا فاکتورسازی از کار نیفتد
            conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('hosts', ?)", (",".join(active),))
def _db_resync_host_pool_from_full_list(hosts_list):
    """وقتی ادمین از مسیر قدیمیِ متنیِ «تنظیمات هاست» کل لیست را یک‌جا جایگزین می‌کند، این تابع
    host_pool را با همان لیست هماهنگ می‌کند: مواردی که در لیست جدید هستند فعال می‌شوند، مواردی
    که حذف شده‌اند غیرفعال می‌شوند (نه پاک) تا تاریخچه/آمار پایش از بین نرود."""
    with db_conn() as conn:
        existing = {r[0] for r in conn.execute("SELECT host FROM host_pool").fetchall()}
        wanted = set(hosts_list)
        for h in hosts_list:
            if h in existing:
                conn.execute("UPDATE host_pool SET active=1, consecutive_fails=0, disabled_reason=NULL, disabled_at=NULL WHERE host=?", (h,))
            else:
                conn.execute("INSERT INTO host_pool (host, active) VALUES (?, 1)", (h,))
        for h in existing - wanted:
            conn.execute("UPDATE host_pool SET active=0 WHERE host=?", (h,))

# 🆕 دامنهٔ ثابت عمومی (سراسری) که در تمام کدهای نپسترنت/فاکتورهای حالت مستقیم به‌جای IP خام
# نمایش داده می‌شود. کاربر همیشه همین دامنه را در اپش دارد؛ IP واقعی پشتش با Cloudflare API عوض
# می‌شود بدون این‌که کاربر مجبور شود کد جدید بگیرد یا دوباره چیزی ایمپورت کند.
#
# 🔧 یکپارچه‌سازی: قبلاً دو تابع جدا و ناهماهنگ برای همین کار وجود داشت که هرکدام یک مشکل داشت:
#   - نسخهٔ قدیمی («cf_api_token/cf_zone_id/cf_record_id») به یک Record ID دستی نیاز داشت که
#     هیچ‌وقت در دیتابیس ثبت نشده بود، پس همیشه بی‌صدا شکست می‌خورد.
#   - نسخهٔ جدیدتر («cf_email/cf_key/cf_zone») از کتابخانهٔ requests استفاده می‌کرد که اصلاً روی
#     venv ربات نصب نبود (فقط python-telegram-bot/matplotlib/pillow نصب شده)، پس با
#     ModuleNotFoundError شکست می‌خورد.
# الان فقط یک پیاده‌سازی هست: بدون هیچ وابستگی خارجی (urllib داخلی پایتون)، خودش Record ID را
# پیدا می‌کند (نیازی به تنظیم دستی‌اش نیست)، و هم روش توکن مدرن هم روش قدیمی ایمیل+کلید را
# امتحان می‌کند. هر کلید قدیمی که از قبل در دیتابیس ثبت شده باشد (هرکدام از دو نام) همچنان خوانده
# می‌شود، برای این‌که تنظیمات قبلی از دست نروند.
def _cf_get_config():
    with db_conn() as conn:
        rows = dict(conn.execute(
            "SELECT key, value FROM settings WHERE key IN "
            "('public_domain','cf_api_token','cf_zone_id','cf_email','cf_key','cf_zone','dns_current_ip','tls_domain','tls_passthrough')"
        ).fetchall())
    return {
        "public_domain": rows.get("public_domain", ""),
        "tls_domain": rows.get("tls_domain", ""),
        "tls_passthrough": rows.get("tls_passthrough", "1"), # حالت پیش‌فرض: 1 (فعال)
        "token": rows.get("cf_key", "") or rows.get("cf_api_token", ""),
        "zone": rows.get("cf_zone", "") or rows.get("cf_zone_id", ""),
        "email": rows.get("cf_email", ""),
        "dns_current_ip": rows.get("dns_current_ip", ""),
    }

def _cf_configured(cfg=None):
    cfg = cfg or _cf_get_config()
    return all([cfg["public_domain"], cfg["token"], cfg["zone"]])

def _cf_update_dns_record_sync(new_ip: str):
    cfg = _cf_get_config()
    if not cfg["token"] or not cfg["zone"]:
        return False, "تنظیمات Cloudflare (توکن/Zone) در دیتابیس کامل نیست."

    domains_to_update = []
    if cfg.get("public_domain"): domains_to_update.append(cfg["public_domain"])
    
    # 🔴 تغییر حیاتی: دامنه TLS فقط در صورتی به Edge آپدیت می‌شود که فلگ فعال باشد
    if cfg.get("tls_domain") and cfg.get("tls_passthrough") == "1":
        domains_to_update.append(cfg["tls_domain"])
    
    if not domains_to_update:
        return False, "هیچ دامنه‌ای برای آپدیت تنظیم نشده است."

    def _try_update(headers, target_domain):
        find_url = f"https://api.cloudflare.com/client/v4/zones/{cfg['zone']}/dns_records?name={target_domain}&type=A"
        req = urllib.request.Request(find_url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            found = json.loads(resp.read())
        if not found.get("success") or not found.get("result"):
            return False, f"رکورد A برای دامنه {target_domain} پیدا نشد."
        record_id = found["result"][0]["id"]
        update_url = f"https://api.cloudflare.com/client/v4/zones/{cfg['zone']}/dns_records/{record_id}"
        payload = json.dumps({"type": "A", "name": target_domain, "content": new_ip, "ttl": 60, "proxied": False}).encode()
        upd_req = urllib.request.Request(update_url, data=payload, method="PUT", headers=headers)
        with urllib.request.urlopen(upd_req, timeout=15) as resp:
            result = json.loads(resp.read())
        if not result.get("success"):
            return False, str(result.get("errors"))
        return True, None

    bearer_headers = {"Authorization": f"Bearer {cfg['token']}", "Content-Type": "application/json"}
    legacy_headers = {"X-Auth-Email": cfg["email"], "X-Auth-Key": cfg["token"], "Content-Type": "application/json"} if cfg["email"] else None

    last_err = None
    all_success = True
    
    for dom in domains_to_update:
        ok, err = False, ""
        try:
            ok, err = _try_update(bearer_headers, dom)
        except Exception:
            if legacy_headers:
                try: ok, err = _try_update(legacy_headers, dom)
                except Exception as e: err = str(e)
            else:
                err = "خطای ارتباط با API کلودفلر"
                
        if not ok:
            all_success = False
            last_err = err

    if all_success:
        _db_update_setting("dns_current_ip", new_ip)
        return True, None
    return False, last_err or "خطای نامشخص در آپدیت کلودفلر"

async def _cf_switch_public_domain(new_ip: str, app=None):
    """
    نقطهٔ مرکزیِ سوییچ دامنهٔ ثابت (Cloudflare). tlstoedge، clfch، Self-Heal کلودزی، پایش
    خودکار سلامت IPها و ارتقا/تنزل خودکار Core همه از همین یک تابع استفاده می‌کنند تا
    dns_current_ip همیشه با واقعیت هماهنگ بماند.
    خروجی: (ok: bool, msg: str)
    اگر app داده شود، فقط در صورتِ شکست به ادمین‌ها اطلاع می‌دهد (چون بیشتر فراخوان‌ها خودشان
    پیام موفقیت را با جزئیات بیشتر می‌فرستند).
    """
    cf_cfg = await asyncio.to_thread(_cf_get_config)
    if not _cf_configured(cf_cfg):
        return False, "تنظیمات Cloudflare (دامنه/توکن/Zone) کامل نیست؛ سوییچ دامنه انجام نشد."
    ok, err = await asyncio.to_thread(_cf_update_dns_record_sync, new_ip)
    if ok:
        return True, f"دامنهٔ ثابت اکنون به {new_ip} اشاره می‌کند."
    msg = f"سوییچ دامنه به {new_ip} شکست خورد: {err}"
    if app is not None:
        with contextlib.suppress(Exception):
            await _notify_admins(app, f"⚠️ <b>خطای سوییچ دامنهٔ ثابت</b>\n{esc(msg)}")
    return False, msg

async def _update_cloudflare_dns(new_ip: str):
    """🔧 نام قدیمی برای سازگاری با فراخوانی‌های موجود (هدایت به همان پیادهٔ یکپارچهٔ بالا)."""
    return await _cf_switch_public_domain(new_ip, app=None)


# 🆕 پشتیبانی از چند ادمین هم‌زمان: به‌جای یک chat_id تکی («admin_chat_id» قدیمی که هربار
# overwrite می‌شد)، لیستی از تمام chat_idهایی که تابه‌حال با MASTER_USER/MASTER_PASS واردشده‌اند
# در کلید جدید «admin_chat_ids» (جدا شده با کاما) نگه‌داری می‌شود تا رسیدها/هشدارها به همه برسد.
def _db_add_admin_chat_id(chat_id):
    with db_conn() as conn:
        # ادمین‌های در حال کار (آنلاین)
        row = conn.execute("SELECT value FROM settings WHERE key='admin_chat_ids'").fetchone()
        ids = set()
        if row and row[0]:
            ids = {x.strip() for x in row[0].split(',') if x.strip()}
        ids.add(str(chat_id))
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_chat_ids', ?)", (",".join(sorted(ids)),))
        
        # تاریخچه ادمین‌ها (هرکسی که تا به حال لاگین کرده)
        row_hist = conn.execute("SELECT value FROM settings WHERE key='historical_admin_ids'").fetchone()
        hist_ids = set()
        if row_hist and row_hist[0]:
            hist_ids = {x.strip() for x in row_hist[0].split(',') if x.strip()}
        hist_ids.add(str(chat_id))
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('historical_admin_ids', ?)", (",".join(sorted(hist_ids)),))
        
        # خنثی کردن کلید قدیمی برای جلوگیری از باگ ماندگاری
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_chat_id', '0')")

def _db_remove_admin_chat_id(chat_id):
    with db_conn() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key='admin_chat_ids'").fetchone()
        if row and row[0]:
            ids = {x.strip() for x in row[0].split(',') if x.strip()}
            if str(chat_id) in ids:
                ids.remove(str(chat_id))
                conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_chat_ids', ?)", (",".join(sorted(ids)),))
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_chat_id', '0')")

def _db_get_admin_chat_ids():
    with db_conn() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key='admin_chat_ids'").fetchone()
        ids = set()
        if row and row[0]:
            ids = {x.strip() for x in row[0].split(',') if x.strip()}
        out = set()
        for x in ids:
            with contextlib.suppress(Exception): out.add(int(x))
        out.add(SUPER_ADMIN_ID)
        return out

def _db_get_historical_admin_chat_ids():
    with db_conn() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key='historical_admin_ids'").fetchone()
        ids = set()
        if row and row[0]:
            ids = {x.strip() for x in row[0].split(',') if x.strip()}
        out = set()
        for x in ids:
            with contextlib.suppress(Exception): out.add(int(x))
        return out
def _db_get_favs():
    with db_conn() as conn: return conn.execute("SELECT months, users FROM favorite_configs").fetchall()
def _db_check_fav(m, u):
    with db_conn() as conn: return conn.execute("SELECT 1 FROM favorite_configs WHERE months=? AND users=?", (m, u)).fetchone()
def _db_add_fav(m, u):
    with db_conn() as conn: conn.execute("INSERT OR IGNORE INTO favorite_configs VALUES (?, ?)", (m, u))
def _db_rem_fav(m, u):
    with db_conn() as conn: conn.execute("DELETE FROM favorite_configs WHERE months=? AND users=?", (m, u))
def _db_get_user(un):
    # 🆕 ستون host هم اضافه شد (آخرین ستون، برای اینکه اندیس‌های قبلی cur[0..5] در جای دیگر کد جابه‌جا نشوند)
    # 🆕 ستون conn_mode هم به همین ترتیب در انتها اضافه شد (index=7) تا هیچ فراخوانی قدیمیِ
    # _db_get_user که فقط از cur[0..6] استفاده می‌کند خراب نشود.
    with db_conn() as conn: return conn.execute("SELECT password, expire_date, creation_date, users_limit, status, agent_id, host, conn_mode FROM ssh_accounts WHERE username=?", (un,)).fetchone()
def _db_set_conn_mode(un, mode):
    """'direct' یا 'tls' — برای تغییر حالت اتصال یک اکانت از قبل‌ساخته‌شده."""
    with db_conn() as conn: conn.execute("UPDATE ssh_accounts SET conn_mode=? WHERE username=?", (mode, un))

def _db_get_customer_name(un):
    with db_conn() as conn:
        try:
            row = conn.execute("SELECT customer_name FROM ssh_accounts WHERE username=?", (un,)).fetchone()
            return row[0] if row and row[0] else None
        except Exception: return None
def _db_set_account_host(un, host):
    with db_conn() as conn: conn.execute("UPDATE ssh_accounts SET host=? WHERE username=?", (host, un))
def _db_set_hosts_bulk(usernames, host):
    with db_conn() as conn: conn.executemany("UPDATE ssh_accounts SET host=? WHERE username=?", [(host, u) for u in usernames])
def _db_set_all_accounts_host(host):
    with db_conn() as conn: conn.execute("UPDATE ssh_accounts SET host=? WHERE status != '⏳ درحال ساخت'", (host,))
def _db_get_recent_active_accounts(days=7):
    """اکانت‌های فعالی که در N روز اخیر ساخته شده‌اند (برای انتقال خودکار هنگام فشار سرور)."""
    w = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
    with db_conn() as conn:
        return conn.execute("SELECT username, host FROM ssh_accounts WHERE creation_date >= ? AND status='🟢 فعال' AND service_type='ssh'", (w,)).fetchall()

def _db_get_all_active_accounts_with_host():
    """🆕 همهٔ اکانت‌های فعال سرور (نه فقط تازه‌ها) — برای بالانس کامل خودکار هنگام فشار پایدار."""
    with db_conn() as conn:
        return conn.execute("SELECT username, host FROM ssh_accounts WHERE status='🟢 فعال' AND service_type='ssh'").fetchall()

def _db_get_all_ssh_users():
    with db_conn() as conn: return conn.execute("SELECT username FROM ssh_accounts WHERE status != '⏳ درحال ساخت' AND service_type='ssh'").fetchall()

def _db_search_ssh_users(term):
    with db_conn() as conn: return conn.execute("SELECT username FROM ssh_accounts WHERE username LIKE ? AND status != '⏳ درحال ساخت' AND service_type='ssh'", (f"%{term}%",)).fetchall()

# 🆕 V89 — توابع دیتابیس سیستم شناسایی فیلتر
def _db_get_filter_detect_setting(key, default=None):
    return _db_get_setting(f'filter_detect_{key}', default)
def _db_set_filter_detect_setting(key, value):
    _db_update_setting(f'filter_detect_{key}', value)
def _db_get_active_accounts_count():
    with db_conn() as conn:
        row = conn.execute("SELECT COUNT(*) FROM ssh_accounts WHERE status='\U0001f7e2 \u0641\u0639\u0627\u0644'").fetchone()
        return row[0] if row else 0
def _db_get_active_accounts_count_by_agent(agent_id):
    """🆕 تعداد اکانت‌های فعال (نه کل اکانت‌ها) متعلق به یک نمایندهٔ خاص — برای نمایش در «کاربران آنلاین»."""
    with db_conn() as conn:
        row = conn.execute("SELECT COUNT(*) FROM ssh_accounts WHERE status='\U0001f7e2 \u0641\u0639\u0627\u0644' AND agent_id=?", (agent_id,)).fetchone()
        return row[0] if row else 0
def _db_get_total_active_accounts_count():
    """تعداد کل کاربران فعال SSH سیستم را برمی‌گرداند — برای محاسبهٔ درصد سیستم ضدفیلتر SSH."""
    with db_conn() as conn:
        # فیلتر فقط روی اکانت‌های SSH تا از تداخل با آمار V2Ray برای سیستم فیلتر جلوگیری شود
        row = conn.execute("SELECT COUNT(*) FROM ssh_accounts WHERE status='\U0001f7e2 \u0641\u0639\u0627\u0644' AND service_type='ssh'").fetchone()
        return row[0] if row else 0
def _db_get_filter_detect_enabled():
    val = _db_get_setting('filter_detect_enabled', '0')
    return val == '1'
def _db_set_filter_detect_enabled(enabled: bool):
    _db_update_setting('filter_detect_enabled', '1' if enabled else '0')
def _db_get_filter_detect_threshold():
    try:
        return float(_db_get_setting('filter_detect_threshold', str(FILTER_DETECT_ONLINE_PCT_THRESHOLD)))
    except Exception:
        return float(FILTER_DETECT_ONLINE_PCT_THRESHOLD)

# --- توابع دیتابیس دامنه‌ها ---
def _db_add_domain(domain, host, reg_date, expire_date, notes):
    with db_conn() as conn:
        try:
            conn.execute("INSERT INTO domains (domain, host, reg_date, expire_date, notes) VALUES (?,?,?,?,?)",
                         (domain, host, reg_date, expire_date, notes))
            return True
        except sqlite3.IntegrityError:
            return False
def _db_get_domains():
    with db_conn() as conn: return conn.execute("SELECT id, domain, host, expire_date FROM domains ORDER BY domain").fetchall()
def _db_get_domain(did):
    with db_conn() as conn: return conn.execute("SELECT domain, host, reg_date, expire_date, notes FROM domains WHERE id=?", (did,)).fetchone()
def _db_delete_domain(did):
    with db_conn() as conn: conn.execute("DELETE FROM domains WHERE id=?", (did,))
def _db_get_all_users():
    with db_conn() as conn: return conn.execute("SELECT username FROM ssh_accounts WHERE status != '⏳ درحال ساخت'").fetchall()
def _db_get_users_with_agents():
    with db_conn() as conn:
        return conn.execute("""
            SELECT s.username, s.agent_id 
            FROM ssh_accounts s 
            LEFT JOIN (
                SELECT username, MAX(created_at) as last_act 
                FROM activity_log 
                WHERE action IN ('create', 'extend') 
                GROUP BY username
            ) a ON s.username = a.username
            WHERE s.status != '⏳ درحال ساخت' 
            ORDER BY COALESCE(a.last_act, s.creation_date) DESC, s.rowid DESC
        """).fetchall()

def _db_get_users_with_agents_by_type(stype='ssh'):
    with db_conn() as conn:
        has_cname = False
        try:
            cols = [info[1] for info in conn.execute("PRAGMA table_info(ssh_accounts)").fetchall()]
            has_cname = "customer_name" in cols
        except: pass
        cname_col = "s.customer_name" if has_cname else "NULL as customer_name"
        
        return conn.execute(f"""
            SELECT s.username, s.agent_id,
                (SELECT action FROM activity_log WHERE username = s.username AND action IN ('create', 'extend') ORDER BY created_at DESC LIMIT 1) as act_type,
                {cname_col}
            FROM ssh_accounts s 
            LEFT JOIN (
                SELECT username, MAX(created_at) as last_act 
                FROM activity_log 
                WHERE action IN ('create', 'extend') 
                GROUP BY username
            ) a ON s.username = a.username
            WHERE s.status != '⏳ درحال ساخت' AND s.service_type=? 
            ORDER BY COALESCE(a.last_act, s.creation_date) DESC, s.rowid DESC
        """, (stype,)).fetchall()
def _db_search_users(term):
    with db_conn() as conn: return conn.execute("SELECT username FROM ssh_accounts WHERE username LIKE ? AND status != '⏳ درحال ساخت'", (f"%{term}%",)).fetchall()
def _db_toggle_status(un):
    with db_conn() as conn:
        row = conn.execute("SELECT status FROM ssh_accounts WHERE username=?", (un,)).fetchone()
        if not row: return None
        nxt = "🔴 غیرفعال" if row[0] == "🟢 فعال" else "🟢 فعال"
        conn.execute("UPDATE ssh_accounts SET status=? WHERE username=?", (nxt, un))
        return nxt

# ==========================================
# 🛡️ پایش تخطی از ظرفیت مجاز (جلوگیری از اشتراک‌گذاری غیرمجاز اکانت)
# ==========================================
def _db_get_active_accounts_for_monitor():
    """لیست اکانت‌های فعال با ظرفیت مجازشان و وضعیت فعلی «تخطی مستمر» (برای حلقهٔ پایش).
    🆕 ستونِ host هم اضافه شد تا اقدامِ قفل‌کردن روی Edgeِ درست اجرا شود."""
    with db_conn() as conn:
        return conn.execute(
            "SELECT username, users_limit, agent_id, violation_since, violation_last_notified, host FROM ssh_accounts WHERE status='🟢 فعال' AND service_type='ssh'").fetchall()

def _db_set_violation_since(un, ts_or_none):
    """ثبت/پاک‌کردن زمان شروع تخطی مستمر برای یک اکانت (ts_or_none=None یعنی ریست، چون به زیر ظرفیت برگشته)."""
    with db_conn() as conn:
        conn.execute("UPDATE ssh_accounts SET violation_since=? WHERE username=? AND status='🟢 فعال'", (ts_or_none, un))

def _db_set_violation_last_notified(un, ts):
    """زمان آخرین یادآوریِ «قفل خودکار شکست خورد» را ثبت می‌کند (برای جلوگیری از اسپم پیام)."""
    with db_conn() as conn:
        conn.execute("UPDATE ssh_accounts SET violation_last_notified=? WHERE username=?", (ts, un))

def _db_get_agent_telegram_id(agent_id):
    """آیدی تلگرام نمایندهٔ مالک یک اکانت را برمی‌گرداند (برای اطلاع‌رسانی مستقیم به او)."""
    if not agent_id: return None
    with db_conn() as conn:
        row = conn.execute("SELECT telegram_id FROM agents WHERE id=?", (agent_id,)).fetchone()
        return row[0] if row and row[0] else None

def _db_force_disable_for_violation(un):
    """
    اکانت را به‌خاطر تخطی مستمر از ظرفیت مجاز غیرفعال می‌کند (فقط اگر هنوز واقعاً فعال باشد —
    تا با غیرفعال‌سازی دستی هم‌زمان توسط ادمین تداخل نکند).
    خروجی: True اگر واقعاً تغییر اعمال شد.
    """
    with db_conn() as conn:
        cur = conn.execute("UPDATE ssh_accounts SET status='🔴 غیرفعال', violation_since=NULL, violation_last_notified=NULL WHERE username=? AND status='🟢 فعال'", (un,))
        return cur.rowcount > 0
def _db_insert_user(un, pw, exp, cr, lim, cnt, agid=0, conn_mode='direct'):
    with db_conn() as conn:
        conn.execute("INSERT INTO ssh_accounts (username, password, expire_date, creation_date, users_limit, status, agent_id, conn_mode) VALUES (?,?,?,?,?, '🟢 فعال', ?, ?)", (un, pw, exp, cr, lim, agid, conn_mode))
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('counter', ?)", (cnt,))

# ==========================================
# 🔒 رزرو اتمیک یوزرنیم برای جلوگیری از Race Condition
# ==========================================
# ایده: به‌جای «چک کردن که یوزرنیم آزاد است» و سپس (با فاصله زمانی) ساختنش که در دو خرید
# همزمان می‌تواند هر دو یک یوزرنیم را انتخاب کنند، همان محدودیت UNIQUE کلید اصلی جدول
# ssh_accounts به‌عنوان قفل رزرو استفاده می‌شود: تلاش برای INSERT یک ردیف موقت با وضعیت
# «⏳ درحال ساخت» انجام می‌شود؛ چون SQLite این INSERTها را به‌صورت سریالی و اتمیک پردازش
# می‌کند، اگر دو درخواست همزمان یک یوزرنیم را امتحان کنند فقط یکی موفق می‌شود و دیگری
# IntegrityError می‌گیرد و یوزرنیم بعدی را امتحان می‌کند.
def _db_reserve_username(br: str, start_counter: int, max_attempts: int = 300):
    c = start_counter
    for _ in range(max_attempts):
        candidate = f"{br}{c:04d}"
        with db_conn() as conn:
            try:
                conn.execute(
                    "INSERT INTO ssh_accounts (username, password, expire_date, creation_date, users_limit, status, agent_id) "
                    "VALUES (?, '', '', '', 0, '⏳ درحال ساخت', 0)", (candidate,))
                return candidate, c
            except sqlite3.IntegrityError:
                c += 1
                continue
    return None, c

def _db_cancel_reservation(un: str):
    """در صورت شکست ساخت اکانت روی سرور لینوکس، ردیف رزروشده را کامل از دیتابیس حذف می‌کند (Rollback)."""
    with db_conn() as conn:
        conn.execute("DELETE FROM ssh_accounts WHERE username=? AND status='⏳ درحال ساخت'", (un,))

def _db_finalize_reserved_user(un, pw, exp, cr, lim, cnt, br, agid=0, conn_mode='direct', hold_deadline=None, hold_duration_days=None):
    """ردیف رزروشده را با اطلاعات نهایی اکانت (و حالت اتصال انتخاب‌شده) تکمیل و شمارندهٔ
    اختصاصی همان پیشوند/برند را آپدیت می‌کند.
    🆕 اگر hold_deadline مقدار داشته باشد، اکانت در حالت «آنهولد» ثبت می‌شود (شمارش انقضای واقعی
    هنوز شروع نشده) و exp در این حالت فقط یک مقدار موقت (پایان مهلت آنهولد) است، نه انقضای واقعی."""
    with db_conn() as conn:
        conn.execute(
            "UPDATE ssh_accounts SET password=?, expire_date=?, creation_date=?, users_limit=?, status='🟢 فعال', agent_id=?, conn_mode=?, "
            "hold_active=?, hold_deadline=?, hold_duration_days=? "
            "WHERE username=?",
            (pw, exp, cr, lim, agid, conn_mode, 1 if hold_deadline else 0, hold_deadline, hold_duration_days, un))
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (f"counter_{br}", cnt))
def _db_finalize_v2ray_user(un, pw, exp, cr, lim, cnt, br, agid, data_limit, sub_url, hold_deadline, hold_duration_days):
    with db_conn() as conn:
        conn.execute(
            "UPDATE ssh_accounts SET password=?, expire_date=?, creation_date=?, users_limit=?, status='🟢 فعال', agent_id=?, conn_mode='v2ray', service_type='v2ray', data_limit=?, sub_url=?, hold_active=?, hold_deadline=?, hold_duration_days=? WHERE username=?",
            (pw, exp, cr, lim, agid, data_limit, sub_url, 1 if hold_deadline else 0, hold_deadline, hold_duration_days, un))
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (f"counter_{br}", cnt))

def _db_get_hold_info(un):
    """(hold_active, hold_deadline, hold_duration_days) برای نمایش نشان «در حال آنهولد»."""
    with db_conn() as conn:
        row = conn.execute("SELECT hold_active, hold_deadline, hold_duration_days FROM ssh_accounts WHERE username=?", (un,)).fetchone()
        return row if row else (0, None, None)

def _db_get_hold_accounts():
    """لیست اکانت‌های در حال آنهولد (منتظر اولین اتصال یا پایان مهلت) برای تیک پایش دوره‌ای."""
    with db_conn() as conn:
        return conn.execute(
            "SELECT username, hold_deadline, hold_duration_days, agent_id FROM ssh_accounts "
            "WHERE hold_active=1 AND status='🟢 فعال'").fetchall()

def _db_activate_hold_account(un, real_exp_db):
    """پایان دادن به دوران آنهولد: انقضای واقعی‌محاسبه‌شده در دیتابیس ثبت و حالت آنهولد خاموش می‌شود."""
    with db_conn() as conn:
        conn.execute("UPDATE ssh_accounts SET expire_date=?, hold_active=0 WHERE username=?", (real_exp_db, un))

# ==========================================
# 🔢 شمارندهٔ اختصاصیِ هر پیشوند/برند یوزرنیم
# ==========================================
# 🐛🔧 رفع باگ «شمارهٔ یوزرنیم‌ها بین برندهای مختلف قاطی می‌شود»: قبلاً یک شمارندهٔ سراسریِ
# مشترک (کلید 'counter' در جدول settings) بین همهٔ برندها/پیشوندها (ادمین، هرکدام از
# نمایندگان با پیشوند اختصاصی) به اشتراک گذاشته می‌شد؛ یعنی اگر نمایندهٔ «یوسف» (پیشوند usef)
# یک اکانت می‌ساخت، شمارهٔ بعدیِ برند «nevel» هم از همان‌جا ادامه پیدا می‌کرد. الان هر پیشوند
# شمارندهٔ کاملاً مستقل و مجزای خودش را دارد (کلید 'counter_<prefix>')، در دیتابیس ذخیره
# می‌شود و هیچ‌وقت با برندهای دیگر تداخل ندارد.
def _db_get_prefix_start_counter(br: str) -> int:
    """
    شمارهٔ شروع رزرو برای این پیشوند را برمی‌گرداند:
    ۱) اگر قبلاً برای همین پیشوند شمارنده‌ای ذخیره شده، همان استفاده می‌شود.
    ۲) در غیر این صورت (اولین بار استفاده از این برند)، یوزرنیم‌های موجود همان پیشوند در
       دیتابیس اسکن می‌شوند و از «بزرگ‌ترین شمارهٔ موجود + ۱» شروع می‌شود — تا با اکانت‌های
       واقعیِ قبلی همان برند برخورد نکند.
    ۳) اگر اصلاً اکانتی با این پیشوند وجود نداشت، برای سازگاری با نصب‌های قبل از این تغییر
       (که فقط یک شمارندهٔ سراسری 'counter' داشتند)، از همان مقدار سراسری قدیمی ادامه داده
       می‌شود تا شماره‌ها به عقب برنگردند؛ در نبود هر دو، از عدد ۱ شروع می‌شود.
    """
    raw = _db_get_setting(f"counter_{br}", None)
    if raw:
        digits = re.sub(r'\D', '', fa_to_en_digits(str(raw)))
        if digits: return int(digits)
    with db_conn() as conn:
        rows = conn.execute("SELECT username FROM ssh_accounts WHERE username LIKE ?", (f"{br}%",)).fetchall()
    max_n = 0
    pat = re.compile(rf'^{re.escape(br)}(\d+)$')
    for (un,) in rows:
        mtc = pat.match(un or "")
        if mtc:
            with contextlib.suppress(ValueError):
                max_n = max(max_n, int(mtc.group(1)))
    if max_n > 0: return max_n + 1
    legacy = _db_get_setting('counter', None)
    if legacy:
        digits = re.sub(r'\D', '', fa_to_en_digits(str(legacy)))
        if digits: return int(digits)
    return 1
def _db_delete_user(un):
    with db_conn() as conn: conn.execute("DELETE FROM ssh_accounts WHERE username=?", (un,))
def _db_update_password(un, pw):
    with db_conn() as conn: conn.execute("UPDATE ssh_accounts SET password=? WHERE username=?", (pw, un))
def _db_extend_user(un, new_exp):
    # 🆕 اگر اکانت هنوز در حال آنهولد بود، یک تمدید/کاهش دستی به این معناست که ادمین/نماینده
    # صراحتاً می‌خواهد انقضا را همین الان کنترل کند — پس حالت آنهولد خاموش می‌شود تا حلقهٔ پس‌زمینهٔ
    # آنهولد بعداً این مقدارِ دستی را با محاسبهٔ خودش بازنویسی نکند.
    with db_conn() as conn: conn.execute("UPDATE ssh_accounts SET expire_date=?, hold_active=0 WHERE username=?", (new_exp, un))
# 🔴🔵 RED & BLUE: عملیات سراسری روی همه اکانت‌های سرور
def _db_get_all_accounts_full():
    """همه اکانت‌های واقعی (غیر در-حال-ساخت) را با انقضا، وضعیت، میزبان و نوع سرویس برمی‌گرداند."""
    with db_conn() as conn: return conn.execute("SELECT username, expire_date, status, host, service_type FROM ssh_accounts WHERE status != '⏳ درحال ساخت'").fetchall()
def _db_update_users_limit(un, new_limit):
    with db_conn() as conn: conn.execute("UPDATE ssh_accounts SET users_limit=? WHERE username=?", (new_limit, un))

def _db_get_sales_stats(agid=None, stype=None):
    """خروجی: (today, week, month, active_now, total_all_time)"""
    with db_conn() as conn:
        c = conn.cursor()
        t = datetime.now().strftime("%Y-%m-%d"); w = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d"); m = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")
        excl = "AND status != '⏳ درحال ساخت'"
        ac_excl = ""
        params = []
        
        if stype == 'v2ray':
            excl += " AND service_type IN ('v2ray', 'v2ray_vol')"
            ac_excl = " AND service_type IN ('v2ray', 'v2ray_vol')"
        elif stype:
            excl += " AND service_type = ?"
            ac_excl = " AND service_type = ?"
            params.append(stype)
            
        if agid is not None and agid != 0:
            tc = c.execute(f"SELECT COUNT(*) FROM ssh_accounts WHERE creation_date = ? AND agent_id = ? {excl}", [t, agid] + params).fetchone()[0]
            wc = c.execute(f"SELECT COUNT(*) FROM ssh_accounts WHERE creation_date >= ? AND agent_id = ? {excl}", [w, agid] + params).fetchone()[0]
            mc = c.execute(f"SELECT COUNT(*) FROM ssh_accounts WHERE creation_date >= ? AND agent_id = ? {excl}", [m, agid] + params).fetchone()[0]
            ac = c.execute(f"SELECT COUNT(*) FROM ssh_accounts WHERE status = '🟢 فعال' AND agent_id = ? {ac_excl}", [agid] + params).fetchone()[0]
            total = c.execute(f"SELECT COUNT(*) FROM ssh_accounts WHERE agent_id = ? {excl}", [agid] + params).fetchone()[0]
        else:
            tc = c.execute(f"SELECT COUNT(*) FROM ssh_accounts WHERE creation_date = ? {excl}", [t] + params).fetchone()[0]
            wc = c.execute(f"SELECT COUNT(*) FROM ssh_accounts WHERE creation_date >= ? {excl}", [w] + params).fetchone()[0]
            mc = c.execute(f"SELECT COUNT(*) FROM ssh_accounts WHERE creation_date >= ? {excl}", [m] + params).fetchone()[0]
            ac = c.execute(f"SELECT COUNT(*) FROM ssh_accounts WHERE status = '🟢 فعال' {ac_excl}", params).fetchone()[0]
            total = c.execute(f"SELECT COUNT(*) FROM ssh_accounts WHERE 1=1 {excl}", params).fetchone()[0]
        return tc, wc, mc, ac, total

def _db_increment_lifetime_sold(aid: int, count: int = 1):
    """با هر فروش موفق (تکی یا عمده) صدا زده می‌شود؛ فقط بالا می‌رود، هرگز با حذف اکانت کم نمی‌شود."""
    if not aid: return
    with db_conn() as conn:
        conn.execute("UPDATE agents SET lifetime_accounts_sold = lifetime_accounts_sold + ? WHERE id=?", (count, aid))

def _db_get_agent_lifetime_sold(aid: int) -> int:
    with db_conn() as conn:
        row = conn.execute("SELECT lifetime_accounts_sold FROM agents WHERE id=?", (aid,)).fetchone()
        return int(row[0]) if row and row[0] else 0

def _db_agent_username_exists(u):
    with db_conn() as conn: return conn.execute("SELECT 1 FROM agents WHERE username=?", (u,)).fetchone() is not None

def _db_verify_agent(u, p):
    with db_conn() as conn:
        row = conn.execute("SELECT id, name, password FROM agents WHERE username=?", (u,)).fetchone()
        if not row: return None
        aid, name, stored_pw = row
        if not verify_password(p, stored_pw): return None
        if is_legacy_plaintext(stored_pw): conn.execute("UPDATE agents SET password=? WHERE id=?", (hash_password(p), aid))
        return (aid, name)

def _db_get_agent_info(aid):
    # 🆕 ستون‌های آخر: referral_income (9)، username_prefix (10)، username (11)،
    # emergency_used (12)، emergency_request_count (13)، withdrawable_balance (14)،
    # cashback_income (15)، v2ray_base_price (16) و v2ray_vol_price (17)
    with db_conn() as conn: return conn.execute("SELECT name, referral_code, balance, commission_pct, base_price, l2_pct, l3_pct, parent_id, telegram_id, referral_income, username_prefix, username, emergency_used, emergency_request_count, withdrawable_balance, cashback_income, v2ray_base_price, v2ray_vol_price FROM agents WHERE id = ?", (aid,)).fetchone()
def _db_set_agent_prefix(aid, prefix):
    with db_conn() as conn: conn.execute("UPDATE agents SET username_prefix=? WHERE id=?", (prefix, aid))

def _db_get_sub_agents(aid):
    """
    🆕 لیست زیرمجموعه‌های مستقیم یک نماینده (فرزندانی که parent_id آن‌ها همین aid است) را
    برمی‌گرداند، به‌همراه چند آمار خلاصه برای هرکدام؛ برای بخش «👥 زیرمجموعه‌های من».
    خروجی هر ردیف: (id, name, username, balance, referral_income, lifetime_accounts_sold)
    """
    with db_conn() as conn:
        return conn.execute(
            "SELECT id, name, username, balance, referral_income, lifetime_accounts_sold "
            "FROM agents WHERE parent_id=? ORDER BY id", (aid,)).fetchall()

def _db_set_agent_card(aid, card_number, card_name):
    """ثبت/به‌روزرسانی شمارهٔ کارت اختصاصی یک نماینده (برای نمایش به زیرمجموعه‌اش هنگام شارژ کیف‌پول)."""
    with db_conn() as conn:
        conn.execute("UPDATE agents SET custom_card_number=?, custom_card_name=? WHERE id=?", (card_number, card_name, aid))

def _db_clear_agent_card(aid):
    with db_conn() as conn:
        conn.execute("UPDATE agents SET custom_card_number=NULL, custom_card_name=NULL WHERE id=?", (aid,))

def _db_get_agent_card(aid):
    """فقط کارت اختصاصیِ خودِ همین نماینده (بدون بالارفتن از زنجیرهٔ والدین) — برای نمایش در فرم تنظیمات."""
    with db_conn() as conn:
        return conn.execute("SELECT custom_card_number, custom_card_name FROM agents WHERE id=?", (aid,)).fetchone()

def _db_get_agent_card_permission(aid):
    """🆕 آیا این نماینده مجوز ثبت/ویرایش خودگردانِ کارت اختصاصیِ خودش را دارد؟ (۰/۱)"""
    with db_conn() as conn:
        row = conn.execute("SELECT card_permission FROM agents WHERE id=?", (aid,)).fetchone()
        return bool(row[0]) if row and row[0] is not None else False

def _db_toggle_agent_card_permission(aid):
    """🆕 صدور/لغو مجوز کارت اختصاصیِ خودگردان برای یک نماینده — فقط از پنل ادمین (گزارش مالی
    نمایندگان) صدا زده می‌شود. مقدار جدید را برمی‌گرداند تا پیام تأیید دقیق نمایش داده شود."""
    with db_conn() as conn:
        row = conn.execute("SELECT card_permission FROM agents WHERE id=?", (aid,)).fetchone()
        new_val = 0 if (row and row[0]) else 1
        conn.execute("UPDATE agents SET card_permission=? WHERE id=?", (new_val, aid))
        return bool(new_val)

def _db_get_effective_card_for_agent(aid):
    """
    🆕 کارتی که باید هنگام شارژ کیف‌پول به این نماینده نشان داده شود را برمی‌گرداند:
    از خودِ نماینده شروع می‌کند، اگر کارت اختصاصی ثبت نکرده باشد یک سطح بالاتر (والد) را چک
    می‌کند و همین‌طور بالا می‌رود؛ اگر تا ریشهٔ زنجیره هیچ‌کس کارت ثبت نکرده باشد، کارت سراسریِ
    سیستم (تنظیمات ادمین) برگردانده می‌شود.
    خروجی: (card_number, card_name_or_None, owner_agent_id_or_None)
    owner_agent_id فقط وقتی None نیست که کارت واقعاً متعلق به یک نمایندهٔ بالادستی باشد (نه سیستم).
    """
    with db_conn() as conn:
        current = aid
        seen = set()  # 🛡️ محافظت در برابر حلقهٔ احتمالی نامعتبر در زنجیرهٔ parent_id
        while current and current not in seen:
            seen.add(current)
            row = conn.execute("SELECT custom_card_number, custom_card_name, parent_id FROM agents WHERE id=?", (current,)).fetchone()
            if not row: break
            card_num, card_name, parent_id = row
            if card_num:
                return (card_num, card_name, current)
            current = parent_id if parent_id else None
    sys_card = _db_get_setting('bank_card', 'تنظیم نشده')
    return (sys_card, None, None)

def _db_admin_topup_agent(aid, amount):
    """شارژ دستی مستقیم کیف‌پول یک نماینده توسط ادمین (مستقل از جریان تایید رسید کارت‌به‌کارت).
    🆘 اگر این نماینده قبلاً از «شارژ اضطراری» استفاده کرده باشد، به‌محض هر شارژ واقعی (حتی جزئی)،
    مقدار مصرف‌شدهٔ شارژ اضطراری به‌طور خودکار کسر می‌شود و شمارندهٔ درخواست‌های پیاپی صفر می‌شود
    (نماینده دوباره ۲ درخواست شارژ اضطراری در اختیار خواهد داشت)."""
    with db_conn() as conn:
        conn.execute("UPDATE agents SET balance = balance + ? WHERE id=?", (amount, aid))
        _apply_emergency_repayment(conn, aid, amount)
        r = conn.execute("SELECT name FROM agents WHERE id=?", (aid,)).fetchone()
        agent_name = r[0] if r else str(aid)
    
    try:
        with sqlite3.connect(ACCOUNTING_DB_PATH) as acc_conn:
            acc_conn.execute("INSERT INTO finance_logs (date, agent_name, action_type, service, amount, details) VALUES (?, ?, ?, ?, ?, ?)",
                             (datetime.now(IRAN_TZ).strftime("%Y-%m-%d %H:%M:%S"), agent_name, "شارژ دستی", "-", amount, "توسط ادمین"))
            acc_conn.commit()
    except Exception: pass
def _db_admin_deduct_agent(aid, amount):
    """🆕 کاهش دستی مستقیم کیف‌پول یک نماینده توسط ادمین — برای اصلاح شارژهای اشتباهی
    (مثلاً وقتی ادمین با تایپ غلط، مبلغی را به‌اشتباه به حساب یک نماینده اضافه کرده).
    برخلاف تابع شارژ، این عملیات ربطی به جریان «شارژ اضطراری» ندارد (چون کاهش موجودی، بازپرداخت
    شارژ اضطراری محسوب نمی‌شود) و صرفاً مبلغ داده‌شده را از موجودی کم می‌کند؛ موجودی می‌تواند
    منفی هم بشود (تشخیص با خودِ ادمین است، مثلاً برای ثبت بدهی)."""
    with db_conn() as conn:
        conn.execute("UPDATE agents SET balance = balance - ? WHERE id=?", (amount, aid))
def _apply_emergency_repayment(conn, aid, topup_amount):
    """با هر شارژ واقعی (دستی توسط ادمین یا تاییدِ رسید)، تا سقفِ همان مبلغِ واریزی از emergency_used
    کسر می‌شود و emergency_request_count صفر می‌گردد. باید با کانکشن دیتابیسِ باز فراخوانی شود."""
    row = conn.execute("SELECT emergency_used FROM agents WHERE id=?", (aid,)).fetchone()
    used = (row[0] or 0.0) if row else 0.0
    deduct = min(used, topup_amount) if used > 0 else 0.0
    conn.execute("UPDATE agents SET emergency_used = emergency_used - ?, emergency_request_count = 0 WHERE id=?", (deduct, aid))
def _db_agent_register_emergency_use(aid, amount):
    """مصرف یک بار «شارژ اضطراری» را ثبت می‌کند: مبلغ به emergency_used اضافه (تا سقف
    EMERGENCY_CREDIT_LIMIT) و emergency_request_count یکی افزایش می‌یابد."""
    with db_conn() as conn:
        row = conn.execute("SELECT emergency_used, emergency_request_count FROM agents WHERE id=?", (aid,)).fetchone()
        used, cnt = ((row[0] or 0.0), (row[1] or 0)) if row else (0.0, 0)
        new_used = min(EMERGENCY_CREDIT_LIMIT, used + amount)
        new_cnt = min(EMERGENCY_MAX_CONSECUTIVE_REQUESTS, cnt + 1)
        conn.execute("UPDATE agents SET emergency_used=?, emergency_request_count=? WHERE id=?", (new_used, new_cnt, aid))
def _check_emergency_option(ainf, cost):
    """
    بر اساس اطلاعات فعلی نماینده (خروجی _db_get_agent_info) و هزینهٔ مورد نیاز، بررسی می‌کند که
    آیا امکان تکمیل این خرید با «شارژ اضطراری» وجود دارد یا نه.
    خروجی: (has_option, remaining_emergency, shortfall, used, req_count)
    """
    used = ainf[12] if len(ainf) > 12 and ainf[12] else 0.0
    req_count = ainf[13] if len(ainf) > 13 and ainf[13] else 0
    remaining_emergency = EMERGENCY_CREDIT_LIMIT - used
    shortfall = cost - ainf[2]
    has_option = (req_count < EMERGENCY_MAX_CONSECUTIVE_REQUESTS) and (0 < shortfall <= remaining_emergency)
    return has_option, remaining_emergency, shortfall, used, req_count
def _db_update_agent_username(aid, new_username):
    """🆕 تغییر یوزرنیم لاگین یک نماینده توسط ادمین. چون username در جدول agents یکتا (UNIQUE) است،
    اگر یوزرنیم جدید از قبل توسط نمایندهٔ دیگری استفاده شده باشد، به‌جای خطای دیتابیس، False برمی‌گرداند."""
    with db_conn() as conn:
        try:
            conn.execute("UPDATE agents SET username=? WHERE id=?", (new_username, aid))
            return True
        except sqlite3.IntegrityError:
            return False
def _db_update_agent_password(aid, new_password):
    """🆕 تغییر پسورد لاگین یک نماینده توسط ادمین — مثل ساخت نماینده، پسورد قبل از ذخیره هش می‌شود."""
    with db_conn() as conn: conn.execute("UPDATE agents SET password=? WHERE id=?", (hash_password(new_password), aid))
def _db_get_all_agents():
    with db_conn() as conn: return conn.execute("SELECT id, name, referral_code FROM agents").fetchall()

def _get_active_account_count_by_agent(agent_id: int) -> int:
    """تعداد اکانت‌های فعلاً فعال (وضعیت '🟢 فعال') یک نماینده را برمی‌گرداند."""
    with db_conn() as conn:
        row = conn.execute("SELECT COUNT(*) FROM ssh_accounts WHERE agent_id=? AND status='🟢 فعال'", (agent_id,)).fetchone()
        return row[0] if row else 0

def _agent_can_use_emergency_credit(agent_id: int) -> tuple[bool, int]:
    """بررسی اینکه آیا نماینده واجد شرایط استفاده از شارژ اضطراری است (حداقل ۵۰ اکانت فعال)."""
    active_count = _get_active_account_count_by_agent(agent_id)
    can_use = active_count >= EMERGENCY_MIN_ACTIVE_ACCOUNTS
    return can_use, active_count

def _prepare_hidden_hold_for_new_account(username, plan_days, created_at=None):
    with db_conn() as conn:
        return put_account_on_hidden_hold(conn, username, plan_days, hold_days=3, created_at=created_at, linux_safety_margin_days=HOLD_EXPIRY_SAFETY_MARGIN_DAYS)

def _public_expiry_message(username, date_formatter=None):
    with db_conn() as conn:
        return format_visible_expiry_message(conn, username, date_formatter=date_formatter)

def _activate_hidden_hold_at_first_connection(username, connected_at=None, set_linux_expiry=None):
    with db_conn() as conn:
        return activate_on_first_connection(conn, username, connected_at=connected_at, set_linux_expiry=set_linux_expiry)

def _activate_expired_hidden_holds(checked_at=None, set_linux_expiry=None):
    with db_conn() as conn:
        return list(activate_expired_holds(conn, checked_at=checked_at, set_linux_expiry=set_linux_expiry))

async def _calc_account_refund(username: str) -> tuple[float, str]:
    """محاسبهٔ مبلغ بازگشتی هنگام حذف اکانت (پشتیبانی از SSH و V2Ray)."""
    def _get_row():
        with db_conn() as conn:
            return conn.execute(
                "SELECT a.expire_date, a.creation_date, a.hold_active, a.users_limit, ag.base_price, a.service_type, ag.v2ray_base_price, ag.v2ray_vol_price "
                "FROM ssh_accounts a LEFT JOIN agents ag ON ag.id = a.agent_id WHERE a.username = ?", (username,)
            ).fetchone()
    row = await asyncio.to_thread(_get_row)
    if not row: return 0.0, "اکانت یافت نشد"
    expire_date, creation_date, hold_active, users_limit, ssh_bp_raw, stype, v2_bp_raw, v2_vol_bp_raw = row
    
    if stype == 'v2ray_vol':
        try: base_price = float(str(v2_vol_bp_raw or '4000').replace(",", "").strip())
        except: base_price = 4000.0
        
        m_url = await asyncio.to_thread(_db_get_setting, 'marzban_url', '')
        m_user = await asyncio.to_thread(_db_get_setting, 'marzban_username', '')
        m_pwd = await asyncio.to_thread(_db_get_setting, 'marzban_password', '')
        ok, m_data = await v2ray_engine.get_user(m_url, m_user, m_pwd, username)
        
        if ok and isinstance(m_data, dict):
            used_bytes = m_data.get('used_traffic', 0)
            limit_bytes = m_data.get('data_limit', 0)
            if limit_bytes > 0:
                used_gb = used_bytes / (1024**3)
                total_gb = limit_bytes / (1024**3)
                effective_used_gb = max(1.0, used_gb)
                remaining_gb = max(0.0, total_gb - effective_used_gb)
                refund = remaining_gb * base_price
                return float(refund), f"بازگشت {remaining_gb:.2f} گیگ از {total_gb:.2f} گیگ (حداقل مصرف ۱ گیگ لحاظ شد): {refund:,.0f} تومان"
        return 0.0, "خطا در دریافت حجم مصرفی از سرور V2Ray، بازپرداختی انجام نشد."
        
    # 🌟 انتخاب هوشمند قیمت پایه بر اساس نوع سرویس
    bp_raw = v2_bp_raw if stype == 'v2ray' else ssh_bp_raw
    if stype == 'v2ray' and not bp_raw: bp_raw = '160000'
    
    try: base_price = float(str(bp_raw).replace(",", "").strip())
    except: base_price = 0.0
    if base_price <= 0: return 0.0, "قیمت پایه تنظیم نشده"
    
    if hold_active: 
        cost = base_price * users_limit
        return cost, f"بازگشت کامل (استفاده نشده): {cost:,.0f} تومان"
    
    if not expire_date or not creation_date: return 0.0, "تاریخ ناقص"
    try:
        exp_dt = datetime.strptime(expire_date[:10], "%Y-%m-%d")
        cre_dt = datetime.strptime(creation_date[:10], "%Y-%m-%d")
        now = datetime.now()
        if exp_dt <= now: return 0.0, "منقضی شده"
        total_days = (exp_dt - cre_dt).days
        if total_days <= 0: return 0.0, "پلن نامعتبر"
        rem_days = (exp_dt - now).days
        refund = round((base_price * users_limit / total_days) * max(0, rem_days))
        return float(refund), f"بازگشت {rem_days} روز از {total_days} روز: {refund:,.0f} تومان"
    except: return 0.0, "خطا در محاسبه"

def _db_get_agents_with_telegram():
    """🆕 لیست نمایندگانی که chat_id تلگرام معتبر دارند (telegram_id != 0) — مقصد «پیام همگانی»."""
    with db_conn() as conn:
        return conn.execute("SELECT id, name, telegram_id FROM agents WHERE telegram_id IS NOT NULL AND telegram_id != 0").fetchall()

def _db_add_broadcast_preset(title, body):
    with db_conn() as conn:
        conn.execute("INSERT INTO broadcast_presets (title, body, created_at) VALUES (?, ?, ?)",
                     (title, body, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

def _db_get_broadcast_presets():
    with db_conn() as conn:
        return conn.execute("SELECT id, title, body FROM broadcast_presets ORDER BY id DESC").fetchall()

def _db_get_broadcast_preset(pid):
    with db_conn() as conn:
        return conn.execute("SELECT id, title, body FROM broadcast_presets WHERE id=?", (pid,)).fetchone()

def _db_delete_broadcast_preset(pid):
    with db_conn() as conn:
        conn.execute("DELETE FROM broadcast_presets WHERE id=?", (pid,))

def _db_get_agent_receipts(agent_id):
    """🆕 واریزی‌های تاییدشدهٔ (approved) یک نماینده، جدیدترین اول — برای «گزارش مالی نمایندگان».
    فقط رسیدهای approved می‌آیند، نه pending/rejected، چون فقط اینها واقعاً به کیف‌پول اضافه شده‌اند.
    🆕 علاوه بر واریزی‌های مستقیم خودِ نماینده، واریزی‌هایی که زیرمجموعه‌هایش با کارت اختصاصیِ همین
    نماینده انجام داده‌اند (card_owner_agent_id) هم اینجا می‌آید تا در گزارش مالی مشخص باشد که
    زیرمجموعه‌اش واریزی انجام داده. خروجی هر سطر: (amount, created_at, submitter_agent_id, submitter_name)"""
    with db_conn() as conn:
        return conn.execute(
            "SELECT r.amount, r.created_at, r.agent_id, a.name "
            "FROM receipts r LEFT JOIN agents a ON a.id = r.agent_id "
            "WHERE r.status='approved' AND (r.agent_id=? OR r.card_owner_agent_id=?) "
            "ORDER BY r.created_at DESC",
            (agent_id, agent_id)).fetchall()
def _db_find_agent_by_ref(ref):
    with db_conn() as conn: res = conn.execute("SELECT id FROM agents WHERE referral_code=?", (ref,)).fetchone(); return res[0] if res else 0
def _db_create_agent(u, p, n, pid):
    ref = "REF-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
    with db_conn() as conn:
        try:
            conn.execute("INSERT INTO agents (username, password, name, referral_code, parent_id) VALUES (?,?,?,?,?)", (u, hash_password(p), n, ref, pid))
            return True, ref
        except: return False, None
def _db_update_agent_field(aid, field, v):
    if field not in _ALLOWED_AGENT_FIELDS: raise ValueError("فیلد غیرمجاز")
    with db_conn() as conn: conn.execute(f"UPDATE agents SET {field}=? WHERE id=?", (v, aid))
def _db_delete_agent(aid):
    with db_conn() as conn: conn.execute("DELETE FROM agents WHERE id=?", (aid,))

def _resolve_username_prefix(role: str, agent_info) -> str:
    """
    پیشوند یوزرنیم مؤثر را برمی‌گرداند:
    - ادمین: همیشه از تنظیم سراسری 'brand' استفاده می‌کند (بدون تغییر رفتار قبلی).
    - نماینده: اگر برای خودش پیشوند اختصاصی تنظیم کرده باشد (username_prefix)، همان استفاده
      می‌شود؛ در غیر این صورت به همان برند سراسری ادمین بازمی‌گردد. این‌طوری تغییر پیشوند یک
      نماینده روی ادمین یا سایر نمایندگان هیچ اثری نمی‌گذارد و برعکس.
    """
    if role == 'agent' and agent_info and len(agent_info) > 10 and agent_info[10]:
        candidate = re.sub(r'[^a-zA-Z0-9]', '', str(agent_info[10])).lower()
        if candidate:
            return candidate
    return None  # یعنی «از برند سراسری ادمین استفاده کن» — در محل فراخوانی fallback می‌شود

def _parse_price_to_decimal(price_str, default=Decimal("125000")):
    try:
        digits = re.sub(r'\D', '', str(price_str))
        return Decimal(digits) if digits else default
    except: return default

def _db_distribute_commission(aid, retail_amount):
    """
    توزیع پورسانت overrideِ شبکه‌ای فقط به والد (l2_pct) و پدربزرگ (l3_pct) یک نماینده.

    🔧 رفع باگ مالی مهم: نسخهٔ قبلی این تابع، خودِ نمایندهٔ فروشنده (aid) را هم با
    commission_pct بار دیگر بستانکار می‌کرد. چون آن نماینده در لحظهٔ خرید، هزینه را از قبل
    با همان درصد «تخفیف مستقیم»ِ خودش کسر شده از کیف پولش پرداخت می‌کند (نگاه کنید به محاسبهٔ
    cost_dec در بخش «buy_yes»/«rnm_»)، بستانکار کردن دوبارهٔ خودش یعنی تخفیف او عملاً به‌صورت
    مرکب (compounded) دو بار اعمال می‌شد — یک باگ مالی واقعی که نماینده را ناخواسته بیشتر از
    حد در نظر گرفته‌شده تخفیف می‌داد. الان:
      • خودِ نماینده هیچ اعتبار اضافه‌ای نمی‌گیرد (تخفیفش همان کسر مستقیم از کیف‌پول است).
      • والد و پدربزرگ، پورسانت overrideِ خود را از روی «مبلغ خرده‌فروشی/retail» (یعنی
        قیمت پایه × ماه × تعداد کاربر، پیش از اعمال تخفیف خودِ این نماینده) دریافت می‌کنند —
        نه از روی مبلغ نهاییِ تخفیف‌خورده — تا درصدهای لایهٔ ۲ و ۳ همیشه معنای ثابتی داشته
        باشند و با تغییر تخفیف مستقیم یک نماینده، پورسانت والدینش دستخوش نوسان نشود.

    🆕 تغییر مهم: این پورسانت دیگر مستقیماً به موجودی قابل‌خرج (balance) اضافه نمی‌شود؛ به
    استخر جداگانهٔ withdrawable_balance می‌رود تا خودِ نماینده انتخاب کند نقداً برداشت کند یا
    به کیف‌پول قابل‌خرجش منتقل کند (referral_income هم‌چنان فقط برای نمایش مجموع تاریخی است).
    """
    retail_amount = retail_amount if isinstance(retail_amount, Decimal) else Decimal(str(retail_amount))
    with db_conn() as conn:
        ag1 = conn.execute("SELECT parent_id FROM agents WHERE id=?", (aid,)).fetchone()
        if not ag1:
            return
        p1 = ag1[0]
        if not p1:
            return  # این نماینده لایهٔ اول است؛ والدی برای پرداخت override وجود ندارد
        ag2 = conn.execute("SELECT parent_id, l2_pct FROM agents WHERE id=?", (p1,)).fetchone()
        if not ag2:
            return
        p2, pct2 = ag2
        share2 = float(retail_amount * Decimal(str(pct2)) / Decimal("100"))
        conn.execute("UPDATE agents SET withdrawable_balance = withdrawable_balance + ?, referral_income = referral_income + ? WHERE id=?",
                     (share2, share2, p1))
        if p2:
            ag3 = conn.execute("SELECT l3_pct FROM agents WHERE id=?", (p2,)).fetchone()
            if ag3:
                share3 = float(retail_amount * Decimal(str(ag3[0])) / Decimal("100"))
                conn.execute("UPDATE agents SET withdrawable_balance = withdrawable_balance + ?, referral_income = referral_income + ? WHERE id=?",
                             (share3, share3, p2))

# ==========================================
# 🎁 کش‌بک ترغیبی نمایندگان پرفروش: اگر نمایندهٔ خریدار، از قبل (پیش از همین خرید) ۵۰ اکانت
# فعال یا بیشتر داشته باشد، ۷٪ از هزینهٔ خرده‌فروشی همین خرید (base_price × ماه × کاربر، پیش
# از تخفیف مستقیم خودِ نماینده) به‌عنوان کش‌بک به استخر withdrawable_balance او اضافه می‌شود.
# ==========================================
AGENT_CASHBACK_MIN_ACTIVE_ACCOUNTS = 50
AGENT_CASHBACK_PCT = Decimal("7")

async def _apply_agent_cashback_if_eligible(aid: int, retail_amount):
    """
    خروجی: مبلغ کش‌بک اعمال‌شده (float) یا 0.0 اگر نماینده واجد شرایط نبود.
    شرط واجد بودن: مجموع کل اکانت‌هایی که این نماینده «تابه‌حال» فروخته (lifetime_accounts_sold؛
    یک شمارندهٔ صرفاً افزایشی که با حذف اکانت کم نمی‌شود) از AGENT_CASHBACK_MIN_ACTIVE_ACCOUNTS
    (۵۰) کمتر نباشد.
    🛡️ قبلاً این شرط روی COUNT زندهٔ اکانت‌های «فعال» بود که با حذف اکانت افت می‌کرد — یعنی
    نماینده می‌توانست با ساختن و بعداً حذف‌کردن اکانت‌های الکی، این آستانه را دور بزند یا برای
    خرید‌های بعدی هم واجد شرایط بماند بدون اینکه واقعاً حجم فروش واقعی داشته باشد. حالا این شمارنده
    فقط با فروش واقعی بالا می‌رود و دیگر قابل دستکاری با حذف اکانت نیست.
    """
    try:
        lifetime_sold = await asyncio.to_thread(_db_get_agent_lifetime_sold, aid)
    except Exception:
        log.exception("خطا در بررسی تعداد کل فروش برای کش‌بک نمایندهٔ %s", aid)
        return 0.0
    if lifetime_sold < AGENT_CASHBACK_MIN_ACTIVE_ACCOUNTS:
        return 0.0
    retail_amount = retail_amount if isinstance(retail_amount, Decimal) else Decimal(str(retail_amount))
    cashback_dec = retail_amount * AGENT_CASHBACK_PCT / Decimal("100")
    cashback = float(cashback_dec)
    if cashback <= 0:
        return 0.0
    with db_conn() as conn:
        conn.execute("UPDATE agents SET withdrawable_balance = withdrawable_balance + ?, cashback_income = cashback_income + ? WHERE id=?",
                     (cashback, cashback, aid))
    log.info("کش‌بک %s تومان به نمایندهٔ %s تعلق گرفت (کل فروش تابه‌حال: %s).", cashback, aid, lifetime_sold)
    return cashback

# ==========================================
# 💵 مدیریت استخر «قابل‌برداشت» (پورسانت شبکه + کش‌بک) — انتقال به کیف‌پول یا درخواست برداشت نقدی
# ==========================================
def _db_move_withdrawable_to_wallet(aid: int, amount: float) -> bool:
    """مبلغ داده‌شده را از withdrawable_balance کم و به balance (قابل‌خرج) اضافه می‌کند.
    اگر مبلغ بیشتر از موجودی استخر باشد، هیچ تغییری اعمال نمی‌شود و False برمی‌گردد."""
    with db_conn() as conn:
        row = conn.execute("SELECT withdrawable_balance FROM agents WHERE id=?", (aid,)).fetchone()
        if not row or row[0] < amount:
            return False
        conn.execute("UPDATE agents SET withdrawable_balance = withdrawable_balance - ?, balance = balance + ? WHERE id=?", (amount, amount, aid))
        return True

def _db_create_withdrawal_request(aid: int, amount: float, card_number: str, full_name: str):
    """ثبت درخواست برداشت نقدی و رزرو (کسر) همان لحظهٔ مبلغ از withdrawable_balance تا دوبار
    قابل برداشت/انتقال نباشد. اگر موجودی استخر کافی نباشد، None برمی‌گرداند."""
    with db_conn() as conn:
        row = conn.execute("SELECT withdrawable_balance FROM agents WHERE id=?", (aid,)).fetchone()
        if not row or row[0] < amount:
            return None
        conn.execute("UPDATE agents SET withdrawable_balance = withdrawable_balance - ? WHERE id=?", (amount, aid))
        cur = conn.cursor()
        cur.execute("INSERT INTO withdrawal_requests (agent_id, amount, card_number, full_name, status, created_at) VALUES (?, ?, ?, ?, 'pending', ?)",
                    (aid, amount, card_number, full_name, datetime.now().strftime("%Y-%m-%d %H:%M")))
        return cur.lastrowid

def _db_get_withdrawal_request(req_id: int):
    with db_conn() as conn:
        return conn.execute("SELECT id, agent_id, amount, card_number, full_name, status, created_at FROM withdrawal_requests WHERE id=?", (req_id,)).fetchone()

def _db_get_agent_pending_withdrawals(aid: int):
    with db_conn() as conn:
        return conn.execute("SELECT id, amount, card_number, full_name, created_at FROM withdrawal_requests WHERE agent_id=? AND status='pending' ORDER BY id", (aid,)).fetchall()

def _db_mark_withdrawal_done(req_id: int):
    with db_conn() as conn:
        conn.execute("UPDATE withdrawal_requests SET status='done', done_at=? WHERE id=?", (datetime.now().strftime("%Y-%m-%d %H:%M"), req_id))

def _db_cancel_withdrawal_request(req_id: int):
    """لغو یک درخواست برداشتِ در انتظار و بازگرداندن مبلغ رزروشده به withdrawable_balance."""
    with db_conn() as conn:
        row = conn.execute("SELECT agent_id, amount, status FROM withdrawal_requests WHERE id=?", (req_id,)).fetchone()
        if not row or row[2] != 'pending':
            return False
        conn.execute("UPDATE agents SET withdrawable_balance = withdrawable_balance + ? WHERE id=?", (row[1], row[0]))
        conn.execute("UPDATE withdrawal_requests SET status='cancelled' WHERE id=?", (req_id,))
        return True



# ==========================================
# 📈 رسم نمودار فروش (آمار ۷ روز اخیر)
# ==========================================
def _generate_sales_chart_buffer():
    if not MATPLOTLIB_AVAILABLE: return None
    with db_conn() as conn:
        c = conn.cursor()
        date_labels = []
        counts = []
        for i in range(6, -1, -1):
            dt = (datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d")
            cnt = c.execute("SELECT COUNT(*) FROM ssh_accounts WHERE creation_date=?", (dt,)).fetchone()[0]
            date_labels.append(dt[-5:]) # فقط ماه و روز
            counts.append(cnt)
            
    plt.figure(figsize=(8, 5))
    plt.bar(date_labels, counts, color='#4CAF50', edgecolor='black')
    plt.title('Sales Last 7 Days (NeVeL System)')
    plt.xlabel('Date')
    plt.ylabel('Accounts Created')
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    plt.close()
    return buf

# ==========================================
# 🖥 اجرای امن دستورات سیستمی (sudo/linux)
# ==========================================
async def run_cmd(*args, input_data: bytes = None, timeout: float = None):
    """
    اجرای امن یک دستور سیستمی.
    🔧 نسخه اصلاح‌شده:
      - در صورت Timeout، پردازه هنگ‌کرده حتماً kill می‌شود (قبلاً رها می‌شد و ممکن بود
        باعث نیمه‌کاره ماندن ساخت اکانت در دفعه بعد شود).
      - خطای «sudo نیازمند پسورد است» به‌صورت جداگانه و با پیام واضح تشخیص داده می‌شود؛
        این رایج‌ترین دلیل شکست مداوم «ساخت اکانت» و «فعال/غیرفعال‌سازی» روی سرورهایی
        است که دسترسی NOPASSWD برای این دستورات در sudoers تنظیم نشده باشد.
    خروجی: (ok: bool, err: str, err_kind: str)
      err_kind یکی از: '' (موفق) | 'sudo_password' | 'not_found' | 'timeout' | 'other'
    """
    timeout = timeout or SUBPROCESS_TIMEOUT
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdin=asyncio.subprocess.PIPE if input_data is not None else None,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(input=input_data), timeout)
        except asyncio.TimeoutError:
            with contextlib.suppress(Exception):
                proc.kill(); await proc.wait()
            log.error("⏱ Timeout در اجرای دستور %s (بیش از %s ثانیه طول کشید)", args, timeout)
            return False, f"دستور بیش از {timeout} ثانیه طول کشید و متوقف شد (Timeout).", "timeout"

        err_txt = stderr.decode(errors='ignore').strip()
        if proc.returncode != 0:
            log.error("دستور %s شکست خورد (کد %s): %s", args, proc.returncode, err_txt)
            low = err_txt.lower()
            if "a password is required" in low or "no tty present" in low or ("sudo:" in low and "password" in low):
                return False, err_txt or "sudo برای اجرا به رمز عبور نیاز دارد.", "sudo_password"
            return False, err_txt, "other"
        return True, "", ""
    except FileNotFoundError as e:
        log.error("دستور %s یافت نشد روی سرور: %s", args, str(e))
        return False, str(e), "not_found"
    except Exception as e:
        log.error("خطا در اجرای %s: %s", args, str(e))
        if proc is not None:
            with contextlib.suppress(Exception):
                proc.kill()
        return False, str(e), "other"

# 🆕 قفل سخت تعداد کاربر هم‌زمان (سطح PAM/سرور):
# دیتابیس ربات فقط «تعداد کاربر مجاز» را نگه می‌دارد؛ خودِ اجرای این محدودیت (رد کردن اتصال
# اضافه) روی سرور و توسط یک اسکریپت PAM انجام می‌شود (نصب یک‌بارهٔ آن جدا از ربات — پایین توضیح
# داده شده). این دو تابع فقط وظیفه دارند فایلِ عدد مجاز هر یوزرنیم را روی سرور به‌روز نگه دارند تا
# آن اسکریپت PAM همیشه آخرین «تعداد کاربر مجاز» ثبت‌شده در ربات را بخواند.
# ⚠️ عمداً best-effort است: اگر این sync شکست بخورد، ساخت/ویرایش اکانت در دیتابیس ربات هرگز
# fail/rollback نمی‌شود — فقط در لاگ هشدار ثبت می‌شود؛ چون هدف این دو تابع فقط «همگام‌سازی» است،
# نه بخشی از تراکنش اصلی.
USER_LIMITS_DIR = "/etc/ssh/user-limits"

async def _sync_user_limit_file(un: str, limit: int, host: str = None, port: int = 22):
    """🆕 اگر host داده شود (معماریِ Control-Plane/Data-Plane)، فایل روی همان Edgeِ واقعیِ
    صاحبِ اکانت نوشته می‌شود؛ وگرنه (سازگاری با فراخوانی‌های قدیمی) محلی/Core نوشته می‌شود."""
    if host is not None:
        ok, err, kind = await _run_linux_cmd_on_host(
            host, port, "sudo", "sh", "-c",
            f"mkdir -p {USER_LIMITS_DIR} && printf '%s' {int(limit)} > {USER_LIMITS_DIR}/{un}")
    else:
        ok, err, kind = await run_cmd(
            "sudo", "sh", "-c",
            f"mkdir -p {USER_LIMITS_DIR} && printf '%s' {int(limit)} > {USER_LIMITS_DIR}/{un}")
    if not ok:
        log.warning("همگام‌سازی فایل سقف اتصال (PAM) برای %s شکست خورد: %s", un, err)
    return ok

async def _remove_user_limit_file(un: str, host: str = None, port: int = 22):
    """🆕 اگر host داده شود، حذف روی همان Edgeِ واقعی انجام می‌شود؛ وگرنه محلی/Core."""
    if host is not None:
        ok, err, kind = await _run_linux_cmd_on_host(host, port, "sudo", "rm", "-f", f"{USER_LIMITS_DIR}/{un}")
    else:
        ok, err, kind = await run_cmd("sudo", "rm", "-f", f"{USER_LIMITS_DIR}/{un}")
    if not ok:
        log.warning("حذف فایل سقف اتصال (PAM) برای %s شکست خورد: %s", un, err)
    return ok

def _fmt_linux_error(action: str, err: str, kind: str) -> str:
    """پیام خطای کاربرپسند و دقیق برای عملیات‌های سیستمی (به‌جای پیام مبهم قبلی)."""
    if kind == "sudo_password":
        return (f"❌ خطا در «{action}»: sudo برای اجرای این دستور از ربات درخواست رمز عبور می‌کند.\n\n"
                f"🔧 <b>راه‌حل:</b> روی سرور، دسترسی بدون‌رمز (NOPASSWD) برای کاربری که ربات با آن اجرا می‌شود "
                f"به دستورات useradd, userdel, usermod, chpasswd در فایل sudoers بدهید. مثال:\n"
                f"<code>botuser ALL=(ALL) NOPASSWD: /usr/sbin/useradd, /usr/sbin/userdel, /usr/sbin/usermod, /usr/sbin/chpasswd</code>")
    if kind == "timeout":
        return f"❌ خطا در «{action}»: اجرای دستور روی سرور بیش از حد طول کشید (Timeout) و متوقف شد. لطفاً بار دیگر تلاش کنید."
    if kind == "not_found":
        return f"❌ خطا در «{action}»: دستور مورد نیاز روی سرور یافت نشد.\n({esc(err)})"
    return f"❌ خطا در «{action}» روی سرور لینوکس.\n({esc(err)})"

async def _get_server_health():
    """
    وضعیت لحظه‌ای فشار سرور را برمی‌گرداند: درصد مصرف CPU، RAM، Load Average و فضای دیسک.
    فقط از فایل‌های /proc (قابل‌خواندن برای هر کاربر، بدون نیاز به sudo) و دستور df استفاده می‌کند.
    خروجی: (dict یا None, error_str یا None)
    """
    try:
        cpu_count = os.cpu_count() or 1

        def _read_cpu_times():
            with open('/proc/stat') as f:
                parts = f.readline().split()[1:]
            nums = [int(x) for x in parts]
            idle = nums[3] + (nums[4] if len(nums) > 4 else 0)
            return idle, sum(nums)

        idle1, total1 = await asyncio.to_thread(_read_cpu_times)
        # 🔧 رفع درخواست «تشخیص دقیق‌تر فشار سرور»: قبلاً این بازهٔ نمونه‌برداری فقط ۰.۷ ثانیه بود.
        # یک بازهٔ به این کوتاهی به‌شدت مستعد ثبت یک برخورد لحظه‌ای (مثلاً چند handshake هم‌زمان SSH/TLS
        # که کسری از ثانیه طول می‌کشند) به‌عنوان «فشار ۹۰٪+» است، درحالی‌که میانگین واقعی مصرف در
        # بازهٔ ۵ دقیقه‌ای بین دو بررسی می‌تواند کاملاً عادی باشد. بازهٔ ۳ ثانیه‌ای نوسانات ریز و
        # آنی را میانگین‌گیری می‌کند و عدد گزارش‌شده را به مصرف واقعی نزدیک‌تر می‌کند.
        await asyncio.sleep(3.0)
        idle2, total2 = await asyncio.to_thread(_read_cpu_times)
        d_idle, d_total = idle2 - idle1, total2 - total1
        cpu_pct = round((1 - d_idle / d_total) * 100, 1) if d_total > 0 else 0.0

        def _read_mem():
            info = {}
            with open('/proc/meminfo') as f:
                for line in f:
                    k, v = line.split(':', 1)
                    info[k.strip()] = int(v.strip().split()[0])
            return info

        mem = await asyncio.to_thread(_read_mem)
        total_kb = mem.get('MemTotal', 0)
        avail_kb = mem.get('MemAvailable', mem.get('MemFree', 0))
        used_kb = max(total_kb - avail_kb, 0)
        ram_pct = round((used_kb / total_kb) * 100, 1) if total_kb > 0 else 0.0

        with open('/proc/loadavg') as f:
            load1, load5, load15 = f.read().split()[:3]

        disk_line = ""
        try:
            p = await asyncio.create_subprocess_shell("df -h / | tail -1", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            out, _err = await asyncio.wait_for(p.communicate(), MONITOR_TIMEOUT)
            disk_line = out.decode(errors='ignore').strip()
        except Exception:
            pass

        return {
            "cpu_count": cpu_count, "cpu_pct": cpu_pct,
            "ram_total_mb": round(total_kb / 1024), "ram_used_mb": round(used_kb / 1024), "ram_pct": ram_pct,
            "load1": float(load1), "load5": float(load5), "load15": float(load15),
            "disk_line": disk_line,
        }, None
    except Exception as e:
        log.error(f"خطا در بررسی وضعیت سرور: {e}")
        return None, str(e)

async def _get_remote_server_health(host, port=22, timeout=12):
    """
    🆕 نسخهٔ راه‌دورِ _get_server_health، مخصوص Edgeها: با همان کلید SSH دائمیِ Core (که موقع
    افزودن/ارتقای هر Edge نصب می‌شود) وصل می‌شود و یک اسکریپت کوچک پایتون روی خودِ Edge اجرا
    می‌کند تا CPU/RAM واقعیِ همان سرور را بخواند — نه سرور Core.
    خروجی: (dict یا None, error_str یا None) — همان شکل خروجیِ _get_server_health (فقط بدون
    load average و دیسک، چون این دو برای این پنل ضروری نیستند).
    """
    if paramiko is None:
        return None, "کتابخانهٔ paramiko روی Core نصب نیست."
    if not os.path.exists(DO_SSH_KEY_PATH):
        return None, "هنوز کلید SSH دائمی برای این سرور نصب نشده. اول از دکمهٔ «🔑 نصب دسترسی دائمی» استفاده کنید."

    def _sync():
        ssh = None
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            pkey = paramiko.Ed25519Key.from_private_key_file(DO_SSH_KEY_PATH)
            ssh.connect(host, port=port, username='root', pkey=pkey, timeout=timeout, banner_timeout=timeout)
            remote_script = (
                "python3 - <<'PYEOF'\n"
                "import time\n"
                "def cpu_times():\n"
                "    with open('/proc/stat') as f:\n"
                "        parts = f.readline().split()[1:]\n"
                "    nums = [int(x) for x in parts]\n"
                "    idle = nums[3] + (nums[4] if len(nums) > 4 else 0)\n"
                "    return idle, sum(nums)\n"
                "i1, t1 = cpu_times()\n"
                "time.sleep(1.0)\n"
                "i2, t2 = cpu_times()\n"
                "d_idle, d_total = i2 - i1, t2 - t1\n"
                "cpu_pct = round((1 - d_idle / d_total) * 100, 1) if d_total > 0 else 0.0\n"
                "info = {}\n"
                "with open('/proc/meminfo') as f:\n"
                "    for line in f:\n"
                "        k, v = line.split(':', 1)\n"
                "        info[k.strip()] = int(v.strip().split()[0])\n"
                "total_kb = info.get('MemTotal', 0)\n"
                "avail_kb = info.get('MemAvailable', info.get('MemFree', 0))\n"
                "used_kb = max(total_kb - avail_kb, 0)\n"
                "ram_pct = round((used_kb / total_kb) * 100, 1) if total_kb > 0 else 0.0\n"
                "print(f'{cpu_pct}|{round(total_kb/1024)}|{round(used_kb/1024)}|{ram_pct}')\n"
                "PYEOF"
            )
            stdin, stdout, stderr = ssh.exec_command(remote_script, timeout=timeout)
            out = stdout.read().decode(errors='ignore').strip()
            err_txt = stderr.read().decode(errors='ignore').strip()
            if not out or '|' not in out:
                return None, err_txt or "پاسخ نامعتبر از Edge (شاید python3 روی آن نصب نیست)."
            cpu_pct_s, ram_total_s, ram_used_s, ram_pct_s = out.split('|')
            return {
                "cpu_pct": float(cpu_pct_s), "ram_total_mb": int(ram_total_s),
                "ram_used_mb": int(ram_used_s), "ram_pct": float(ram_pct_s),
            }, None
        except Exception as e:
            return None, str(e)
        finally:
            if ssh is not None:
                try:
                    ssh.close()
                except Exception:
                    pass

    return await asyncio.to_thread(_sync)


async def _get_health_for_host(host):
    """
    🆕 نقطهٔ ورود مشترک برای «وضعیت سرور مشخص یک اکانت/IP»: اگر host همان Core خودمان باشد
    (یا خالی/تنظیم‌نشده که یعنی هاست پیش‌فرض محلی است)، از تابع محلی (بدون نیاز به SSH) استفاده
    می‌کند؛ در غیر این صورت واقعاً روی همان Edge با SSH چک می‌کند تا عدد واقعیِ همان IP نشان
    داده شود، نه عدد Core.
    خروجی: (health_dict یا None, error_or_none, is_remote: bool)
    """
    core_ip = await asyncio.to_thread(_get_core_public_ip_cached)
    if not host or host == core_ip:
        health, err = await _get_server_health()
        return health, err, False
    port = await asyncio.to_thread(_db_get_host_ssh_port, host, 22)
    health, err = await _get_remote_server_health(host, port)
    return health, err, True


async def _run_ip_service_auto_migrate():
    """
    🌐 سرویس IP → «انجام خودکار»: با همان تابع _get_server_health وضعیت لحظه‌ای CPU/RAM/Load
    را می‌سنجد. اگر سرور زیر فشار باشد (هرکدام از آستانه‌های هشدار رد شود)، تا ۱۰ اکانت فعالی
    که در ۷ روز اخیر ساخته شده‌اند را به‌صورت خودکار و بی‌سروصدا (بدون اطلاع به خودِ کاربر) به
    هاست دیگری از لیست «تنظیمات هاست» منتقل می‌کند تا احتمال قطعی/کندی اتصال کاهش یابد.
    خروجی: (health_dict یا None, پیام_اطلاعاتی یا None, لیست [(username, new_host), ...])
    """
    health, herr = await _get_server_health()
    if not health:
        return None, herr, []
    under_pressure = (health['cpu_pct'] >= 85 or health['ram_pct'] >= 85
                       or health['load1'] >= health['cpu_count'] * 1.5)
    if not under_pressure:
        return health, "فشار خاصی روی سرور نیست؛ نیازی به انتقال کاربران نبود.", []
    hl = [h.strip() for h in (await asyncio.to_thread(_db_get_setting, 'hosts', LAST_RESORT_HOST_IP)).split(',') if h.strip()]
    if len(hl) < 2:
        return health, "برای انتقال خودکار حداقل باید ۲ هاست در «تنظیمات هاست» ثبت شده باشد.", []
    rows = await asyncio.to_thread(_db_get_recent_active_accounts, 7)
    if not rows:
        return health, "سرور زیر فشار است ولی هیچ اکانتی در ۷ روز اخیر ساخته نشده که بشود منتقلش کرد.", []
    primary = hl[0]
    batch = rows[:10]  # حداکثر ۱۰ اکانت در هر بار اجرا، تا فشار یک‌باره روی سرور مقصد هم زیاد نشود
    moved = []
    for i, (un, cur_host) in enumerate(batch):
        cur_effective = cur_host or primary
        candidates = [h for h in hl if h != cur_effective]
        if not candidates: continue
        target = candidates[i % len(candidates)]
        await asyncio.to_thread(_db_set_account_host, un, target)
        moved.append((un, target))
    return health, None, moved

async def _run_ip_service_full_balance():
    """
    🆕 بالانس کامل خودکار: برخلاف _run_ip_service_auto_migrate (که فقط تا ۱۰ اکانتِ تازه را به یک
    هاست جایگزین منتقل می‌کند)، این تابع همهٔ اکانت‌های فعال سرور را به‌صورت round-robin بین تمام
    هاست‌های ثبت‌شده در «تنظیمات هاست» پخش می‌کند. فقط توسط حلقهٔ پس‌زمینهٔ پایش فشار IP و پس از
    گذشتن مهلت IP_PRESSURE_AUTOBALANCE_AFTER_HOURS بدون رفع فشار صدا زده می‌شود.
    خروجی: (moved: [(username, new_host), ...], error_str یا None)
    """
    hl = [h.strip() for h in (await asyncio.to_thread(_db_get_setting, 'hosts', LAST_RESORT_HOST_IP)).split(',') if h.strip()]
    if len(hl) < 2:
        return [], "برای بالانس خودکار حداقل باید ۲ هاست در «تنظیمات هاست» ثبت شده باشد."
    rows = await asyncio.to_thread(_db_get_all_active_accounts_with_host)
    if not rows:
        return [], None
    moved = []
    for i, (un, cur_host) in enumerate(sorted(rows)):
        target = hl[i % len(hl)]
        if target != (cur_host or hl[0]):
            await asyncio.to_thread(_db_set_account_host, un, target)
            moved.append((un, target))
    return moved, None

from collections import defaultdict
import re
import asyncio

class ConnectionCounts(dict):
    """یک دیکشنری سفارشی که بدون خراب کردن کدهای قبلی، آمار تفکیک‌شده را هم نگه می‌دارد"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.global_ssh = 0
        self.global_tls = 0
        self.users_detail = defaultdict(lambda: {'ssh': 0, 'tls': 0})

async def _get_live_connection_counts():
    """
    📊 سیستم پایش توزیع‌شده با تفکیک ترافیک Direct و TLS
    نسخه نهایی: ترکیب شده با ترفندِ موفق شما در ps
    """
    counts = ConnectionCounts()
    monitor_errors = []
    try:
        # ۱. استخراج پورت‌های پایش
        port_direct = await asyncio.to_thread(_db_get_setting, 'port', '22')
        port_tls = await asyncio.to_thread(_db_get_setting, 'tls_port', '2088')
        ports_to_check = sorted({str(port_direct).strip(), str(port_tls).strip(), '22'} - {''})
        if not ports_to_check:
            ports_to_check = ['22']
        port_filter = " or ".join(f"sport = :{p}" for p in ports_to_check)

        # ۲. شمارش اتصال‌ها فقط روی Core
        # در معماری فعلی، Edgeها صرفاً پورت‌های سرویس مشتری (مثل 2252/2088)
        # را از طریق DNAT/WireGuard به Core فوروارد می‌کنند و sessionهای واقعی
        # sshd کاربران روی خود Core terminate می‌شوند.
        #
        # قبلاً تمام host_pool نیز اسکن می‌شد؛ اما ssh_port=2252 روی Edgeها
        # دوباره به Core فوروارد می‌شود و در نتیجه همان socket table چند بار
        # خوانده و یک اتصال چند بار شمرده می‌شد.
        core_ip = await asyncio.to_thread(_get_core_public_ip_cached)
        active_hosts = {core_ip} if core_ip else {'127.0.0.1'}

        # استفاده از دستور موفقِ شما برای جلوگیری از قطعی نام کاربری
        cmd = f"sudo -n ss -Htnp state established '( {port_filter} )' ; echo '---SEP---' ; sudo -n ps -eo pid:12,euser:32"

        async def _check_host(host):
            if host == '127.0.0.1' or host == core_ip:
                p = await asyncio.create_subprocess_shell(
                    cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                out_data, err_data = await asyncio.wait_for(p.communicate(), 15.0)
                if p.returncode != 0:
                    return host, False, err_data.decode(errors='ignore').strip()
                return host, True, out_data.decode(errors='ignore')
            else:
                port = await asyncio.to_thread(_db_get_host_ssh_port, host, 22)
                def _sync_remote():
                    import paramiko
                    ssh = None
                    try:
                        ssh = paramiko.SSHClient()
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        pkey = paramiko.Ed25519Key.from_private_key_file(DO_SSH_KEY_PATH)
                        ssh.connect(host, port=port, username='root', pkey=pkey, timeout=12.0, banner_timeout=12.0)
                        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=12.0)
                        out = stdout.read().decode(errors='ignore')
                        err = stderr.read().decode(errors='ignore')
                        exit_code = stdout.channel.recv_exit_status()
                        if exit_code != 0:
                            return False, err.strip()
                        return True, out
                    except Exception as e:
                        return False, str(e)
                    finally:
                        if ssh is not None:
                            try:
                                ssh.close()
                            except Exception:
                                pass
                ok, out = await asyncio.to_thread(_sync_remote)
                return host, ok, out

        tasks = [_check_host(h) for h in active_hosts]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        user_to_ips = defaultdict(set)
        user_tls_pids = defaultdict(list)

        for res in results:
            if isinstance(res, Exception):
                monitor_errors.append(f"خطای ارتباطی: {res}")
                continue
            host, ok, out = res
            if not ok:
                error_short = (out.strip()[:100] + "...") if len(out.strip()) > 100 else out.strip()
                monitor_errors.append(f"[{host}]: {error_short}")
                continue
            
            parts = out.split("---SEP---")
            if len(parts) != 2: continue
            ss_out, ps_out = parts[0], parts[1]
            
            # مپ کردن PID به نام کاربری
            pid_to_user = {}
            for line in ps_out.splitlines():
                ps_parts = line.split()
                if len(ps_parts) >= 2:
                    pid_to_user[ps_parts[0]] = ps_parts[1]
                    
            # خواندن لاگ سوکت‌ها
            for line in ss_out.splitlines():
                cols = line.split()
                if len(cols) < 4: continue
                
                # فیکس حیاتی: پیدا کردنِ هوشمندانهٔ آی‌پیِ کلاینت
                users_col_idx = -1
                for i, c in enumerate(cols):
                    if 'users:(' in c:
                        users_col_idx = i
                        break
                
                # همیشه ستونِ ماقبلِ کلمه users:( همان آی‌پی ماست
                if users_col_idx > 0:
                    peer_field = cols[users_col_idx - 1]
                else:
                    peer_field = cols[3]
                    
                peer_ip = peer_field.rsplit(':', 1)[0].strip('[]') if ':' in peer_field else peer_field
                
                # فیکس برای پردازه‌های چندگانه OpenSSH
                pids = re.findall(r'pid=(\d+)', line)
                if not pids: continue
                
                user_found = None
                for p in pids:
                    u = pid_to_user.get(p)
                    if u and u.lower() != "root":
                        user_found = u.lower()
                        break
                
                if user_found:
                    is_tls = any(local_ip in peer_ip for local_ip in ('127.0.0.1', '::1', 'localhost'))
                    
                    if is_tls:
                        user_tls_pids[user_found].append(pids[0])
                        counts.global_tls += 1
                        counts.users_detail[user_found]['tls'] += 1
                    else:
                        # اضافه کردن PID برای اینکه دقیقاً مثل کدی که فرستادی تمام کانکشن‌های مستقیم شمرده شوند
                        user_to_ips[user_found].add(f"{host}_{peer_ip}_{pids[0]}")
                        counts.global_ssh += 1
                        counts.users_detail[user_found]['ssh'] += 1

        # جمع زدن آمار نهایی
        for u in set(list(user_to_ips.keys()) + list(user_tls_pids.keys())):
            counts[u] = len(user_to_ips[u]) + len(user_tls_pids[u])
            
    except Exception as e:
        log.error(f"خطای پیش‌بینی نشده در پایش چندسروره: {e}")
        return counts, f"خطای سیستمی: {str(e)}"

    error_msg = " | ".join(monitor_errors) if monitor_errors else None
    return counts, error_msg

# 🐛🔧 رفع باگ اصلی «دکمه‌های بازگشتِ تاریخچهٔ اتصالات کار نمی‌کنند»: صفحهٔ «تاریخچهٔ اتصالات»
# همیشه با query.edit_message_text ساخته می‌شد. این تابع از هر جای دیگری هم صدا زده می‌شد —
# از جمله دکمهٔ «🔙 بازگشت به تاریخچه» که زیر یک پیامِ *عکس* (نمودار/نمودار زنده) قرار داشت.
# edit_message_text روی یک پیامِ عکس اصلاً کار نمی‌کند (تلگرام برای آن خطا می‌دهد: «There is no
# text in the message to edit»)، پس با کلیک روی آن دکمه، این خطا رخ می‌داد و بی‌صدا قورت داده
# می‌شد؛ از دید کاربر دقیقاً یعنی «دکمه هیچ واکنشی نداشت». حالا اگر ویرایش پیام فعلی به هر دلیلی
# (پیام عکس بودن، خیلی قدیمی بودن و...) شکست بخورد، به‌جایش یک پیام متنی تازه ارسال می‌شود.
async def _safe_edit_or_send(query, text, reply_markup=None, parse_mode=None):
    try:
        await query.edit_message_text(
            text,
            reply_markup=reply_markup,
            parse_mode=parse_mode
        )
    except BadRequest as e:
        # کلیک تکراری روی صفحه‌ای که متن و کیبوردش تغییر نکرده،
        # خطای واقعی نیست و نباید پیام تکراری یا Traceback تولید کند.
        if "message is not modified" in str(e).lower():
            return

        # سایر BadRequestها ممکن است مثلاً ناشی از غیرقابل‌ویرایش بودن
        # پیام باشند؛ رفتار fallback قبلی حفظ می‌شود.
        with contextlib.suppress(Exception):
            await query.message.reply_text(
                text,
                reply_markup=reply_markup,
                parse_mode=parse_mode
            )
    except Exception:
        with contextlib.suppress(Exception):
            await query.message.reply_text(
                text,
                reply_markup=reply_markup,
                parse_mode=parse_mode
            )

async def _get_connection_history(username: str, n: int = 8):
    """
    📜 تاریخچهٔ اتصالات یک اکانت را از لاگ احرازهویت واقعیِ sshd می‌خواند (نه wtmp/دستور `last`).

    🐛 چرا نسخهٔ قبلی (مبتنی بر `last -F`) همیشه خالی برمی‌گشت، حتی برای اکانت‌هایی که همان
    لحظه واقعاً وصل بودند (`ps aux` پردازهٔ sshd را نشان می‌داد): دستور `last` از wtmp می‌خواند،
    و OpenSSH فقط وقتی وارد wtmp می‌شود که کلاینت یک pty واقعی (شل تعاملی) درخواست بدهد.
    اپ‌های مشتری (نپسترنت/HTTP Injector) SSH را فقط برای port-forwarding خام به‌کار می‌برند —
    بدون pty — پس sshd پردازه را می‌سازد (که `ps` می‌بیندش) ولی هرگز رکورد wtmp نمی‌نویسد؛
    نتیجه، تاریخچهٔ همیشه خالی برای همهٔ اکانت‌های واقعیِ مشتری بود، در حالی که
    `journalctl -u ssh` همان لحظه صریحاً خط‌های «Accepted password for X ...» و
    «session opened/closed for user X» را نشان می‌داد.

    ✅ راه‌حل: به‌جای wtmp، مستقیم لاگ syslog خودِ sshd (از طریق journalctl، که چه با pty چه
    بدونش همیشه نوشته می‌شود) پارس می‌شود. ورود/خروج هر سشن با شمارهٔ PID یکتای sshd به‌هم وصل
    می‌شوند تا مدت اتصال هم دقیق محاسبه شود؛ اگر خروج ثبت نشده باشد، سشن «هنوز متصل» علامت
    می‌خورد (دقیقاً هم‌معنی با «still logged in» قبلی).

    خروجی همچنان (lines: list[str]|None, error: str|None) است — خط‌های ساختگیِ برگشتی دقیقاً
    با همان قالب خروجی «last -F» تولید می‌شوند تا _parse_last_lines بدون هیچ تغییری کار کند.
    """
    accepted_re = re.compile(r'^(\S+)\s+\S+\s+sshd(?:-session)?\[(\d+)\]:\s+Accepted \S+ for (\S+) from (\S+) port')
    closed_re = re.compile(r'^(\S+)\s+\S+\s+sshd(?:-session)?\[(\d+)\]:\s+pam_unix\(sshd:session\):\s+session closed for user (\S+)')

    def _parse_iso_ts(ts_raw):
        # 🐛🔧 رفع باگ «ساعت‌های تاریخچهٔ اتصالات با ساعت واقعی ایران هم‌خوانی ندارند»: جورنال
        # سرور با آفست UTC (+00:00) نوشته می‌شود؛ نسخهٔ قبلی فقط برچسب timezone را پاک می‌کرد
        # (replace(tzinfo=None)) بدون این‌که واقعاً ساعت را به وقت تهران تبدیل کند — یعنی همیشه
        # دقیقاً ۳ ساعت و ۳۰ دقیقه عقب‌تر از ساعت واقعی نمایش داده می‌شد (و گاهی حتی تاریخ/روز هفته
        # هم اشتباه می‌شد، وقتی لحظهٔ واقعی از نیمه‌شب گذشته بود ولی معادل UTC هنوز روز قبل بود).
        # ✅ الان قبل از پاک‌کردن tzinfo، ابتدا با astimezone(IRAN_TZ) واقعاً به وقت تهران تبدیل
        # می‌شود.
        for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S"):
            try:
                dt = datetime.strptime(ts_raw, fmt)
                if dt.tzinfo is not None:
                    dt = dt.astimezone(IRAN_TZ)
                return dt.replace(tzinfo=None)
            except ValueError:
                continue
        return None

    async def _run_journalctl(unit: str):
        # 🐛 باگ اصلی که باعث می‌شد تاریخچهٔ اکانت‌هایی که واقعاً وصل شده بودند هم «پیدا نشد» نشان
        # بدهد: قبلاً بدون هیچ فیلتری آخرین ۸۰۰۰ خط خام این سرویس خوانده می‌شد. روی هر سرور SSH
        # عمومی، اسکنرهای اینترنتی هر چند ثانیه یک‌بار خط «Timeout before authentication» تولید
        # می‌کنند (دیدیم: چند هزار خط در روز) — یعنی همان ۸۰۰۰ خط ممکن است کمتر از یک روزِ واقعی
        # را پوشش بدهد و اتصال‌های واقعی مشتری که چند روز/هفته قبل بوده از پنجره بیرون بیفتند.
        # ✅ راه‌حل: با «-g» (grep داخل journalctl) از همان ابتدا فقط خط‌های Accepted/session را
        # می‌خواهیم؛ این خط‌ها نسبت به نویز اسکنرها بسیار کم‌تعدادند، پس همان -n 8000 عملاً کل
        # تاریخچهٔ واقعی را پوشش می‌دهد، نه فقط چند ساعت آخر را.
        p = await asyncio.create_subprocess_exec(
            "sudo", "-n", "journalctl", "-u", unit, "-o", "short-iso", "--no-pager",
            "-g", "Accepted .+ for .+ from .+ port|session closed for user", "-n", "8000",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await asyncio.wait_for(p.communicate(), MONITOR_TIMEOUT)
        return p.returncode, out.decode(errors='ignore'), err.decode(errors='ignore').strip()

    raw_out = None
    last_err = None
    # 🔁 نام سرویس بسته به توزیع فرق می‌کند («ssh» روی Ubuntu/Debian، «sshd» روی خیلی از بقیه)
    for unit in ("ssh", "sshd"):
        try:
            rc, out, err = await _run_journalctl(unit)
        except asyncio.TimeoutError:
            return None, f"اجرای journalctl بیش از {MONITOR_TIMEOUT} ثانیه طول کشید (Timeout)."
        except FileNotFoundError:
            return None, "دستور «journalctl» روی این سرور پیدا نشد."
        except Exception as e:
            log.error(f"خطا در خواندن تاریخچهٔ اتصالات: {e}")
            return None, str(e)
        if "a password is required" in err.lower() or "no tty present" in err.lower():
            return None, (
                "دسترسی sudo برای دستور «journalctl» (لازم برای تاریخچهٔ اتصالات) نیازمند رمز عبور است.\n"
                "🔧 راه‌حل: این خط را به دسترسی NOPASSWD کاربر ربات در sudoers اضافه کنید:\n"
                "botuser ALL=(ALL) NOPASSWD: /usr/bin/journalctl"
            )
        if rc == 0 and out.strip():
            raw_out = out
            break
        last_err = err or last_err
    if raw_out is None:
        return None, (last_err or "هیچ لاگی از سرویس ssh/sshd روی این سرور پیدا نشد.")

    open_sessions = {}  # pid -> رکوردِ سشنی که هنوز خط «session closed» برایش ندیده‌ایم
    records = []
    for line in raw_out.splitlines():
        m = accepted_re.match(line)
        if m:
            ts_raw, pid, un, ip = m.groups()
            if un != username:
                continue
            dt = _parse_iso_ts(ts_raw)
            if not dt:
                continue
            rec = {'login': dt, 'logout': None, 'still_active': True, 'ip': ip}
            open_sessions[pid] = rec
            records.append(rec)
            continue
        m = closed_re.match(line)
        if m:
            ts_raw, pid, un = m.groups()
            if un != username:
                continue
            rec = open_sessions.pop(pid, None)
            if rec is None:
                continue
            dt = _parse_iso_ts(ts_raw)
            if dt:
                rec['logout'] = dt
                rec['still_active'] = False

    if not records:
        return [], None  # یعنی واقعاً هیچ اتصال موفقی برای این یوزرنیم در این بازهٔ لاگ ثبت نشده

    records.sort(key=lambda r: r['login'], reverse=True)  # جدید به قدیم، دقیقاً مثل خروجی last
    lines_out = []
    for r in records[:n]:
        login_str = r['login'].strftime("%a %b %d %H:%M:%S %Y")
        if r['still_active']:
            lines_out.append(f"{username}   pts/0   {r['ip']}   {login_str}   still logged in")
        else:
            logout_str = r['logout'].strftime("%a %b %d %H:%M:%S %Y")
            lines_out.append(f"{username}   pts/0   {r['ip']}   {login_str} - {logout_str}")
    return lines_out, None

# 🔎 الگوی یک تاریخ/ساعت معتبر داخل هر خط خروجی «last -F»، مثلاً: "Tue Jul 15 08:23:45 2025"
_LAST_DT_RE = re.compile(r'\b\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}\b')

def _parse_last_lines(lines):
    """
    🆕 خروجی خام دستور «last -F» را به لیستی از رکوردهای ساخت‌یافته تبدیل می‌کند تا بشود آن‌ها
    را به شمسی/فارسی نمایش داد و برای رسم نمودار استفاده کرد.
    خروجی هر رکورد: {'login': datetime, 'logout': datetime|None, 'still_active': bool, 'raw': str}
    خط‌هایی که هیچ تاریخ معتبری در آن‌ها یافت نشود (مثلاً خط خلاصهٔ پایانی) نادیده گرفته می‌شوند.
    """
    records = []
    for raw in lines:
        matches = _LAST_DT_RE.findall(raw)
        if not matches:
            continue
        try:
            login_dt = datetime.strptime(matches[0], "%a %b %d %H:%M:%S %Y")
        except ValueError:
            continue
        logout_dt = None
        if len(matches) >= 2:
            with contextlib.suppress(ValueError):
                logout_dt = datetime.strptime(matches[1], "%a %b %d %H:%M:%S %Y")
        still_active = "still logged in" in raw.lower() or "still running" in raw.lower()
        records.append({'login': login_dt, 'logout': logout_dt, 'still_active': still_active, 'raw': raw})
    return records

def _generate_connection_history_chart_buffer(username: str, records: list):
    """
    📈 نمودار «فوق‌العاده»ی اتصالات یک اکانت — دو پنل، تم تیره:
    پنل بالا: نمودار ناحیه‌ای/پله‌ایِ «تعداد اتصالات هم‌زمان در طول زمان» — دقیقاً همان مفهومی
    که پنل RadVPN با یک نمودار میله‌ای ساده نشان می‌داد، ولی اینجا با محاسبهٔ واقعیِ هم‌پوشانیِ
    بازهٔ ورود/خروج هر سشن رسم می‌شود (نه فقط شمارش خام)، به‌همراه خط و برچسبِ اوج هم‌زمانی.
    پنل پایین: تعداد سشن به ازای هر روز، به‌صورت میله‌ای با گرادیان رنگ.
    محورهای زمانی عمداً میلادی/انگلیسی‌اند چون فونت فارسی داخل Matplotlib روی اکثر سرورها نصب
    نیست و باعث نمایش مربع‌های خالی می‌شود؛ کپشن پیام (جایی که ارسال می‌شود) فارسی می‌ماند.
    """
    if not MATPLOTLIB_AVAILABLE or not records:
        return None
    now = datetime.now()
    ordered = sorted(records, key=lambda r: r['login'])

    # --- پنل ۱: هم‌زمانیِ اتصالات (concurrency) با جاروب رویدادهای ورود/+۱ و خروج/-۱ ---
    events = []
    for r in ordered:
        events.append((r['login'], 1))
        end = r['logout'] if r['logout'] else now  # سشن هنوز باز/نامشخص → تا همین لحظه ادامه‌دار فرض می‌شود
        events.append((max(end, r['login']), -1))
    events.sort(key=lambda e: e[0])
    xs, ys = [], []
    concurrent = 0
    for t, delta in events:
        xs.append(t); ys.append(concurrent)
        concurrent += delta
        xs.append(t); ys.append(concurrent)
    peak = max(ys) if ys else 0

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(11, 8.5), gridspec_kw={'height_ratios': [2, 1]})
    fig.patch.set_facecolor('#0b1220')
    for ax in (ax1, ax2):
        ax.set_facecolor('#0b1220')
        for spine in ax.spines.values(): spine.set_color('#334155')
        ax.grid(True, linestyle='--', alpha=0.2, color='white')
        ax.tick_params(colors='white')

    ax1.plot(xs, ys, color='#22d3ee', linewidth=2, zorder=3)
    ax1.fill_between(xs, ys, color='#22d3ee', alpha=0.25, zorder=2)
    ax1.set_ylim(0, max(peak * 1.3, 1))
    ax1.set_ylabel("Simultaneous Connections", color='white', fontsize=11)
    ax1.set_title(f"Live Connection Activity — {username}   (Peak: {peak} • Total sessions: {len(records)})",
                  color='white', fontsize=13, fontweight='bold')
    if xs:
        ax1.axhline(peak, color='#f59e0b', linewidth=1, linestyle=':', alpha=0.8, zorder=4)
        ax1.text(xs[-1], peak, f'  peak = {peak}', color='#f59e0b', va='bottom', fontsize=9, fontweight='bold')
    plt.setp(ax1.get_xticklabels(), rotation=20, ha='right', color='white')

    # --- پنل ۲: تعداد سشن به ازای هر روز ---
    day_counts = {}
    for r in ordered:
        d = r['login'].date()
        day_counts[d] = day_counts.get(d, 0) + 1
    days = sorted(day_counts.keys())
    counts = [day_counts[d] for d in days]
    n_days = max(len(days) - 1, 1)
    bar_colors = plt.cm.plasma([i / n_days for i in range(len(days))])
    ax2.bar([d.strftime("%m-%d") for d in days], counts, color=bar_colors, edgecolor='white', linewidth=0.5, zorder=3)
    ax2.set_ylabel("Sessions / day", color='white', fontsize=11)
    ax2.set_xlabel("Date", color='white', fontsize=11)
    plt.setp(ax2.get_xticklabels(), rotation=45, ha='right', color='white')

    fig.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format='png', dpi=150, facecolor=fig.get_facecolor())
    buf.seek(0)
    plt.close(fig)
    return buf


def _generate_connection_history_animation_buffer(username: str, records: list):
    """
    🎬 نسخهٔ انیمیشنی (GIF) همان نمودار دو‌پنلی بالا — به‌جای یک تصویر ثابت، خط هم‌زمانیِ
    اتصالات به‌مرور «کشیده» می‌شود و میله‌های سشن روزانه از صفر رشد می‌کنند تا به مقدار نهایی
    برسند. محاسبات و استایل (رنگ‌ها، عنوان، محورها) دقیقاً همان نمودار ثابت است تا حس یکسانی
    داشته باشند؛ فقط خروجی به‌جای PNG یک GIF چندفریمی است.
    🆕 طبق درخواست صریح:
      • کیفیت تصویر بالاتر رفت (رزولوشن و dpi بیشتر از قبل).
      • مدت کل انیمیشن دقیقاً ۶ ثانیه شد (قبلاً ~۲ ثانیه) و رشد خط/میله‌ها با یک منحنیِ نرم
        (ease-in-out) پیش می‌رود تا کاملاً «آرام‌آرام» و طبیعی دیده شود، نه یک‌باره و پرشی.
      • تمام برچسب‌ها (عنوان، محورها) دوزبانه شدند: خط اول انگلیسی (همیشه درست نمایش داده
        می‌شود)، خط دوم فارسی (فقط اگر کتابخانه‌های شکل‌دهی متن + یک فونت فارسی روی سرور نصب
        باشند؛ در غیر این صورت فقط همان خط انگلیسی نمایش داده می‌شود — نه متن فارسی خراب/بریده).
    """
    if not ANIMATION_AVAILABLE or not records:
        return None
    now = datetime.now()
    ordered = sorted(records, key=lambda r: r['login'])

    events = []
    for r in ordered:
        events.append((r['login'], 1))
        end = r['logout'] if r['logout'] else now
        events.append((max(end, r['login']), -1))
    events.sort(key=lambda e: e[0])
    xs, ys = [], []
    concurrent = 0
    for t, delta in events:
        xs.append(t); ys.append(concurrent)
        concurrent += delta
        xs.append(t); ys.append(concurrent)
    peak = max(ys) if ys else 0
    if len(xs) < 2:  # حداقل دو نقطه لازم است تا خط/انیمیشن معنا داشته باشد
        xs = xs + xs
        ys = ys + ys

    day_counts = {}
    for r in ordered:
        d = r['login'].date()
        day_counts[d] = day_counts.get(d, 0) + 1
    days = sorted(day_counts.keys())
    counts = [day_counts[d] for d in days]
    n_days = max(len(days) - 1, 1)
    bar_colors = plt.cm.plasma([i / n_days for i in range(len(days))])

    # 🔧 کیفیت بالاتر: هم اندازهٔ شکل و هم dpi نسبت به نسخهٔ قبلی افزایش یافت (~۵۰٪ پیکسل بیشتر).
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(9, 7), gridspec_kw={'height_ratios': [2, 1]})
    fig.patch.set_facecolor('#0b1220')
    for ax in (ax1, ax2):
        ax.set_facecolor('#0b1220')
        for spine in ax.spines.values(): spine.set_color('#334155')
        ax.grid(True, linestyle='--', alpha=0.25, color='white')
        ax.tick_params(colors='white', labelsize=9.5)

    fa_kw = {"fontname": FA_FONT_NAME} if FARSI_CHARTS_AVAILABLE else {}

    # 🔧 اول یک بارِ «نامرئی» با دادهٔ کامل رسم می‌شود تا matplotlib مبدل محور تاریخ/زمان را
    # درست ثبت کند و xlim/ylim نهایی همان چیزی باشد که نمودار ثابت هم استفاده می‌کند؛ سپس همان
    # آبجکتِ خط را برای فریم‌های بعدی با set_data به‌روزرسانی می‌کنیم (بدون رسم دوباره از صفر).
    line, = ax1.plot(xs, ys, color='#22d3ee', linewidth=2.4, zorder=3, alpha=0)
    ax1.set_ylim(0, max(peak * 1.3, 1))
    ax1.set_ylabel(_bilingual_label("Simultaneous Connections", "تعداد اتصال هم‌زمان"),
                   color='white', fontsize=10.5, **fa_kw)
    ax1.set_title(_bilingual_label(f"Connection Activity — {username}  (Peak: {peak} • Total: {len(records)})",
                                    f"نمودار اتصالات {username}  (اوج هم‌زمان: {fa_digits(peak)} • مجموع: {fa_digits(len(records))})"),
                  color='white', fontsize=12.5, fontweight='bold', **fa_kw)
    plt.setp(ax1.get_xticklabels(), rotation=20, ha='right', color='white')
    fill_holder = {'poly': None}

    bars = ax2.bar(range(len(days)), [0] * len(days), color=bar_colors, edgecolor='white', linewidth=0.5, zorder=3)
    ax2.set_ylim(0, max(counts) * 1.25 if counts else 1)
    ax2.set_xticks(range(len(days)))
    ax2.set_xticklabels([d.strftime("%m-%d") for d in days], rotation=45, ha='right', color='white')
    ax2.set_ylabel(_bilingual_label("Sessions / day", "ورود در روز"), color='white', fontsize=10.5, **fa_kw)
    ax2.set_xlabel(_bilingual_label("Date", "تاریخ"), color='white', fontsize=10.5, **fa_kw)

    fig.tight_layout()

    # 🔧 مدت کل: ۶ ثانیه (FPS × مدت = تعداد فریم). ۲۰٪ آخرِ فریم‌ها روی حالت کامل «مکث» می‌کنند
    # تا بیننده فرصت کافی برای دیدن نمودار نهاییِ کامل داشته باشد.
    FPS = 12
    DURATION_SECONDS = 6
    N_FRAMES = FPS * DURATION_SECONDS       # = 90
    GROWTH_FRAMES = int(N_FRAMES * 0.8)     # = 72  (رشد در ۴.۸ ثانیهٔ اول)
    total_points = len(xs)

    def _ease_in_out(t: float) -> float:
        """منحنی نرمِ smoothstep — شروع و پایانِ رشد آهسته، وسط سریع‌تر: کاملاً «آرام‌آرام» دیده می‌شود."""
        t = max(0.0, min(1.0, t))
        return t * t * (3 - 2 * t)

    def update(frame):
        raw_frac = min(1.0, (frame + 1) / GROWTH_FRAMES)
        frac = _ease_in_out(raw_frac)
        cut = max(2, int(total_points * frac))
        line.set_data(xs[:cut], ys[:cut])
        line.set_alpha(1)
        if fill_holder['poly'] is not None:
            fill_holder['poly'].remove()
        fill_holder['poly'] = ax1.fill_between(xs[:cut], ys[:cut], color='#22d3ee', alpha=0.25, zorder=2)
        for bar, target in zip(bars, counts):
            bar.set_height(target * frac)
        return [line, fill_holder['poly'], *bars]

    anim = FuncAnimation(fig, update, frames=N_FRAMES, blit=False)
    # 🐛🔧 نکتهٔ مهم: برخلاف fig.savefig (که مستقیم BytesIO می‌پذیرد)، anim.save در این نسخهٔ
    # matplotlib فقط مسیر فایل واقعی قبول می‌کند نه یک آبجکت BytesIO — پس ابتدا روی یک فایل
    # موقت نوشته می‌شود و سپس بایت‌هایش به یک بافر حافظه خوانده می‌شود.
    tmp_path = tempfile.mktemp(suffix=".gif")
    buf = io.BytesIO()
    try:
        anim.save(tmp_path, writer=PillowWriter(fps=FPS), dpi=120)
        with open(tmp_path, "rb") as f:
            buf.write(f.read())
    except Exception:
        log.exception("ساخت GIF انیمیشنی تاریخچهٔ اتصالات برای %s ناموفق بود.", username)
    finally:
        with contextlib.suppress(Exception):
            if os.path.exists(tmp_path): os.remove(tmp_path)
    plt.close(fig)
    if buf.tell() == 0:  # ساخت GIF ناموفق بود
        return None
    buf.seek(0)
    return buf


async def _live_chart_loop(app, chat_id: int, message_id: int, un: str):
    """
    🔴 حلقهٔ «نمودار زنده»: هر LIVE_CHART_INTERVAL_SECONDS ثانیه، دوباره از سرور می‌خواند و
    همان پیامِ عکس را با نمودار تازه جایگزین می‌کند (edit_message_media) — تا LIVE_CHART_MAX_ITERATIONS
    بار، یا تا وقتی که کاربر روی «⏹ توقف» بزند (که این تسک را از بیرون cancel می‌کند).
    """
    stop_kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("⏹ توقف پایش زنده", callback_data=f"uact_livechart_stop_{un}")],
        [InlineKeyboardButton("🔙 بازگشت به تاریخچه", callback_data=f"uact_hist_{un}")]])
    try:
        for i in range(1, LIVE_CHART_MAX_ITERATIONS + 1):
            await asyncio.sleep(LIVE_CHART_INTERVAL_SECONDS)
            lines, herr = await _get_connection_history(un, n=200)
            if herr or not lines:
                continue  # 🔁 یک بار خواندن ناموفق باعث توقف کامل پایش زنده نشود؛ دور بعد دوباره تلاش می‌شود
            records = _parse_last_lines(lines)
            if not records:
                continue
            buf = await asyncio.to_thread(_generate_connection_history_chart_buffer, un, records)
            if buf is None:
                continue
            now_txt = datetime.now().strftime("%H:%M:%S")
            with contextlib.suppress(Exception):
                await app.bot.edit_message_media(
                    chat_id=chat_id, message_id=message_id,
                    media=InputMediaPhoto(
                        media=InputFile(buf, filename=f"{un}_connections_live.png"),
                        caption=(f"📈🔴 <b>نمودار زندهٔ اتصالات اکانت {esc(un)}</b>\n"
                                 f"تعداد کل: {fa_digits(len(records))} اتصال | آخرین بروزرسانی: {now_txt}\n"
                                 f"(هر {LIVE_CHART_INTERVAL_SECONDS} ثانیه خودکار بروزرسانی می‌شود — بروزرسانی {fa_digits(i)} از {fa_digits(LIVE_CHART_MAX_ITERATIONS)})"),
                        parse_mode="HTML"),
                    reply_markup=stop_kb)
        # ⏹ اتمام سقف تعداد بروزرسانی‌ها
        with contextlib.suppress(Exception):
            end_kb = InlineKeyboardMarkup([
                [InlineKeyboardButton("▶️ ادامهٔ پایش زنده", callback_data=f"uact_livechart_{un}")],
                [InlineKeyboardButton("🔙 بازگشت به تاریخچه", callback_data=f"uact_hist_{un}")]])
            await app.bot.edit_message_caption(
                chat_id=chat_id, message_id=message_id,
                caption=f"⏹ پایش زندهٔ اکانت {esc(un)} به‌دلیل گذشت زمان (حدود {LIVE_CHART_MAX_ITERATIONS * LIVE_CHART_INTERVAL_SECONDS // 60} دقیقه) متوقف شد.",
                parse_mode="HTML", reply_markup=end_kb)
    except asyncio.CancelledError:
        raise  # 🛑 توقف دستی توسط کاربر (دکمهٔ «⏹ توقف») — همان‌جا که cancel صدا زده شده پیام را ویرایش می‌کند
    finally:
        tasks_map = app.bot_data.get('live_chart_tasks')
        if tasks_map is not None:
            tasks_map.pop((chat_id, message_id), None)


async def _get_established_socket_count(port):
    """
    🆕 شمارش مستقل تعداد اتصالات TCP برقرارِ (ESTABLISHED) روی پورتِ پنل، با استفاده از `ss`.
    چرا این تابع جدا از _get_live_connection_counts لازم است: روش قبلی فرض می‌کند هر اتصال کاربر
    حتماً یک پردازهٔ sshd/dropbear جداگانه با مالکیتِ همان کاربر لینوکسی می‌سازد. این فرض برای
    اتصال «SSH خام» درست است، ولی در پنل‌هایی که اتصال از طریق یک پروکسی/پِیلود WebSocket (مثلاً
    اپ‌هایی مثل HTTP Injector یا NPV) رد می‌شود، ممکن است پردازه‌ای که ps دنبالش می‌گردد اصلاً به
    همان شکل ساخته نشود و شمارش قبلی همیشه صفر برگرداند، حتی وقتی کاربر واقعاً وصل است. شمارش
    اتصالات TCP برقرار روی همان پورت، مستقل از این جزئیات معماری، یک سیگنال قابل‌اتکاتر برای
    «آیا الان کسی وصل است؟» می‌دهد (هرچند نمی‌تواند بگوید این اتصال مال کدام یوزرنیم است).
    خروجی: (count: int|None, error: str|None)
    """
    try:
        p = await asyncio.create_subprocess_shell(
            f"sudo -n ss -Htn state established '( sport = :{port} or dport = :{port} )' | wc -l",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await asyncio.wait_for(p.communicate(), MONITOR_TIMEOUT)
        if p.returncode != 0:
            return None, (err.decode(errors='ignore').strip() or "دستور ss با خطا مواجه شد.")
        return int(out.decode(errors='ignore').strip() or "0"), None
    except asyncio.TimeoutError:
        return None, f"اجرای دستور ss بیش از {MONITOR_TIMEOUT} ثانیه طول کشید (Timeout)."
    except FileNotFoundError:
        return None, "دستور ss روی سرور یافت نشد."
    except Exception as e:
        log.error(f"خطا در شمارش سوکت‌ها: {e}")
        return None, str(e)

async def _os_user_exists(username: str, host: str = None, port: int = 22) -> bool:
    """بررسی می‌کند که آیا یوزرنیم داده‌شده از قبل در سیستم لینوکس وجود دارد یا خیر.
    🆕 اگر host داده شود، این بررسی روی همان Edge (نه لزوماً محلی/Core) انجام می‌شود — چون در
    معماریِ Control-Plane/Data-Plane، یک یوزرنیمِ رزروشده ممکن است روی Core خالی باشد ولی
    دقیقاً روی Edgeِ مقصد اشغال شده باشد."""
    if host is not None:
        ok, _, _ = await _run_linux_cmd_on_host(host, port, "id", "-u", username)
    else:
        ok, _, _ = await run_cmd("id", "-u", username)
    return ok

async def _ensure_ssh_linux_user_for_renewal(username: str, owner_row, new_exp_db: str):
    """
    Self-heal برای اکانت‌های SSH قدیمی/منقضی که رکوردشان در master_bot.db باقی مانده ولی
    Linux user آن‌ها (مثلاً بعد از Migration/Rebuild که فقط کاربران فعال بازسازی شده‌اند)
    دیگر وجود ندارد.

    این تابع فقط هنگام تمدید صدا زده می‌شود:
      • اگر Linux user وجود داشته باشد، هیچ تغییری نمی‌دهد.
      • اگر وجود نداشته باشد، همان username/password/users_limit ذخیره‌شده در DB را روی
        host واقعی اکانت بازسازی می‌کند و expiry را مستقیماً روی تاریخ تمدید جدید می‌گذارد.
      • در شکست chpasswd، user تازه‌ساخته‌شده Rollback و حذف می‌شود.
      • DB و کیف‌پول را دست نمی‌زند؛ ادامهٔ مسیر تمدید عادی مسئول commit نهایی است.

    خروجی: (ok, err, kind, recreated)
    """
    if not owner_row:
        return False, "اطلاعات اکانت در دیتابیس پیدا نشد.", "other", False

    # Active production topology is Edge-as-Relay: Linux SSH users live on Core.
    if await _os_user_exists(username):
        return True, "", "", False

    password = owner_row[0]
    users_limit = owner_row[3]
    if not password:
        return False, "رمز ذخیره‌شدهٔ اکانت خالی است و بازسازی امن ممکن نیست.", "other", False

    log.warning(
        "Self-heal تمدید: Linux user %s روی Core وجود ندارد؛ بازسازی از DB آغاز شد.",
        username
    )

    ok_add, err_add, kind_add = await run_cmd(
        "sudo", "useradd", "-s", "/bin/false", "-e", new_exp_db, username
    )
    if not ok_add:
        # اگر بین check و useradd یک اجرای هم‌زمان کاربر را ساخته باشد، آن را شکست واقعی ندان.
        if "already exists" not in (err_add or "").lower():
            return False, err_add, kind_add, False

    ok_pw, err_pw, kind_pw = await run_cmd(
        "sudo", "chpasswd", input_data=f"{username}:{password}\n".encode()
    )
    if not ok_pw:
        # فقط اگر خودمان واقعاً useradd را انجام داده‌ایم Rollback حذف انجام شود؛ در حالت
        # race/already-exists ممکن است user متعلق به اجرای دیگری باشد و نباید حذف شود.
        if ok_add:
            await run_cmd("sudo", "userdel", "-f", username)
        return False, err_pw, kind_pw, False

    await _sync_user_limit_file(username, users_limit)

    log.warning("Self-heal تمدید: Linux user %s با موفقیت از DB بازسازی شد.", username)
    return True, "", "", True

async def _get_os_bot_users():
    """
    🆕 «کاربران یتیم»: یوزرنیم‌های لینوکسی‌ای که ظاهراً توسط خودِ ربات ساخته شده‌اند (همان الگویی
    که هنگام useradd استفاده می‌شود: شل == /bin/false و UID غیرسیستمی یعنی >= 1000، تا کاربران
    سیستمی/سرویس‌ها مثل root یا daemon حساب نشوند) را از روی خودِ سرور لینوکس برمی‌گرداند — صرف‌نظر
    از اینکه در دیتابیس ربات رکوردی دارند یا نه. با مقایسهٔ این لیست با دیتابیس، اکانت‌هایی که قبلاً
    از ربات حذف شده‌اند ولی حذف واقعی‌شان روی لینوکس (userdel) به هر دلیلی ناموفق بوده و همچنان
    قابل اتصال مانده‌اند، پیدا می‌شوند.
    خروجی: (set[str] یا None, error یا None)
    """
    try:
        p = await asyncio.create_subprocess_shell(
            "sudo -n getent passwd | awk -F: '($7==\"/bin/false\" && $3>=1000){print $1}'",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await asyncio.wait_for(p.communicate(), MONITOR_TIMEOUT)
        if p.returncode != 0:
            err_txt = err.decode(errors='ignore').strip()
            low = err_txt.lower()
            if "a password is required" in low or "no tty present" in low or ("sudo:" in low and "password" in low):
                return None, ("دسترسی sudo برای دستور «getent» نیازمند رمز عبور است.\n"
                               "🔧 راه‌حل: این خط را هم به دسترسی NOPASSWD کاربر ربات در sudoers اضافه کنید:\n"
                               "botuser ALL=(ALL) NOPASSWD: /usr/bin/getent")
            return None, (err_txt or "دستور getent/awk با خطا مواجه شد.")
        names = {ln.strip() for ln in out.decode(errors='ignore').splitlines() if ln.strip()}
        return names, None
    except asyncio.TimeoutError:
        return None, f"اجرای دستور getent بیش از {MONITOR_TIMEOUT} ثانیه طول کشید (Timeout)."
    except FileNotFoundError:
        return None, "دستور getent روی سرور یافت نشد."
    except Exception as e:
        log.error(f"خطا در دریافت لیست کاربران لینوکسی: {e}")
        return None, str(e)
# ==========================================

# ==========================================
# 🛡 سیستم مدیریت سشن و لاگین
# ==========================================
def safe_clear_context(context):
    # 🔧 قبلاً users_agent_filter/user_page هم پاک می‌شد؛ یعنی وقتی ادمین از داخل «کاربران یک
    # نمایندهٔ خاص» روی کاربری عملیات انجام می‌داد (تغییر پسورد/افزایش ظرفیت/حذف)، دکمهٔ
    # «بازگشت» بعد از آن به لیست کامل همهٔ کاربران می‌رفت نه لیست فیلترشدهٔ همان نماینده.
    # این دو کلید هم نگه داشته می‌شوند تا ناوبری در بخش نمایندگان درست بماند.
    keep = {k: context.user_data[k] for k in ['logged_in', 'role', 'agent_id', 'users_agent_filter', 'user_page'] if k in context.user_data}
    context.user_data.clear(); context.user_data.update(keep)

def is_auth(context): return context.user_data.get('logged_in', False)

def _can_manage_user(role, ag_id, owner_agent_id):
    """کنترل دسترسی: ادمین به همه اکانت‌ها و هر نماینده فقط به اکانت‌های خودش دسترسی مدیریتی دارد."""
    return role == 'admin' or (role == 'agent' and owner_agent_id == ag_id)

async def require_login(update):
    text = "⛔️ <b>سیستم قفل است.</b>\n\n👤 لطفاً نام کاربری (Username) خود را بفرستید:"
    if update.message: await update.message.reply_text(text, parse_mode="HTML")
    else: await update.effective_message.reply_text(text, parse_mode="HTML")

PORTAL_DISPLAY_NAME = "NeVeL"  # 🔒 نام ثابت پورتال و مدیریت — با تغییر «نام برند» در تنظیمات عوض نمی‌شود

async def show_main_menu(update_or_query, context):
    role = context.user_data.get('role')
    
    # 👑 استخراج دقیق chat_id چه ورودی از نوع پیام متنی باشد چه کلیک روی دکمه شیشه‌ای
    chat_id = 0
    if hasattr(update_or_query, 'effective_chat') and update_or_query.effective_chat:
        chat_id = update_or_query.effective_chat.id
    elif hasattr(update_or_query, 'message') and update_or_query.message:
        chat_id = update_or_query.message.chat.id
        
    if role == 'admin':
        kb = [['🛒 خرید اشتراک', '👥 مدیریت کاربران'], 
              ['💼 مدیریت نماینده‌ها', '📊 آمار و لاگ'],
              ['💳 تنظیمات مالی', '⚙️ تنظیمات سرور'], 
              ['🛠 مدیریت V2Ray', '📦 دریافت بکاپ']]
        if chat_id == SUPER_ADMIN_ID:
            kb.append(['👑 تنظیمات سوپر ادمین'])
        kb.append(['❌ خروج'])
    elif role == 'accountant':
        kb = [['📊 خروجی مالی امروز (اکسل)', '📅 خروجی مالی این هفته (اکسل)'],
              ['👑 آمار فروش ادمین']]
        text = "📊 پنل اختصاصی حسابداری\n\nجهت دریافت گزارشات مالی از دکمه‌های زیر استفاده نمایید:"
    else:
        kb = [['🛒 خرید اشتراک', '👥 مدیریت کاربران'],
              ['📊 اطلاعات حساب', '💳 شارژ حساب (کارت به کارت)'],
              ['✏️ تغییر نام برند']]
        ag_id = context.user_data.get('agent_id', 0)
        if ag_id and await asyncio.to_thread(_db_get_agent_card_permission, ag_id):
            kb.append(['💳 کارت اختصاصی من'])
        kb.append(['❌ خروج'])
    
    reply_markup = ReplyKeyboardMarkup(kb, resize_keyboard=True)
    if role == 'admin':
        text = (f"🏛 پورتال و مدیریت {PORTAL_DISPLAY_NAME}\n"
                f"⚡️ سطح دسترسی: ادمین کل\n\nجهت استفاده، از دکمه‌های زیر استفاده نمایید:")
    elif role != 'accountant':
        text = "🏛 پنل نماینده\n⚡️ سطح دسترسی: نماینده فروش\n\nجهت استفاده، از دکمه‌های زیر استفاده نمایید:"
        
    if hasattr(update_or_query, 'message') and update_or_query.message: 
        await update_or_query.message.reply_text(text, reply_markup=reply_markup)
    else: 
        await update_or_query.effective_message.reply_text(text, reply_markup=reply_markup)

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id if hasattr(update, 'effective_chat') else 0
    
    # 👑 ورود اتوماتیک و بدون رمز برای سوپر ادمین
    if chat_id == SUPER_ADMIN_ID:
        _register_login_success(chat_id)
        await asyncio.to_thread(_db_add_admin_chat_id, chat_id)
        context.user_data.update({'logged_in': True, 'role': 'admin', 'agent_id': 0, 'state': None})
        safe_clear_context(context)
        await update.message.reply_text(f"👑 <b>لاگین خودکار سوپر ادمین</b>\nبه پنل مدیریت {esc(PORTAL_DISPLAY_NAME)} خوش آمدید.", parse_mode="HTML")
        await show_main_menu(update, context)
        return

    # 📊 ورود اتوماتیک و بدون رمز برای حسابدارها
    if chat_id in ACCOUNTANT_IDS:
        _register_login_success(chat_id)
        context.user_data.update({'logged_in': True, 'role': 'accountant', 'agent_id': 0, 'state': None})
        safe_clear_context(context)
        await update.message.reply_text(f"📊 <b>لاگین خودکار حسابدار</b>\nبه پنل حسابداری خوش آمدید.", parse_mode="HTML")
        await show_main_menu(update, context)
        return

    if not is_auth(context):
        context.user_data.clear(); context.user_data['state'] = 'LOGIN_USER'
        await require_login(update)
    else: 
        safe_clear_context(context)
        await show_main_menu(update, context)

# ==========================================
# 🎯 توابع رابط‌های گرافیکی (نمایش اکانت‌ها)
# ==========================================
async def _show_buy_start(update, context):
    ssh_en = await asyncio.to_thread(_db_get_setting, 'sell_ssh', '1') == '1'
    bulk_en = await asyncio.to_thread(_db_get_setting, 'sell_bulk', '1') == '1'
    v2_unlimit_en = await asyncio.to_thread(_db_get_setting, 'sell_v2ray_unlimit', '1') == '1'
    v2_vol_en = await asyncio.to_thread(_db_get_setting, 'sell_v2ray_vol', '1') == '1'
    v2_any = v2_unlimit_en or v2_vol_en

    kb = []
    if ssh_en:
        favs = await asyncio.to_thread(_db_get_favs)
        for m, u in favs:
            kb.append([InlineKeyboardButton(f"⭐ اکانت {m} ماهه {u} کاربره (SSH)", callback_data=f"buyfav_{m}_{u}")])
        kb.append([InlineKeyboardButton("🔹 سرویس SSH", callback_data="buy_direct")])
    
    if v2_any:
        kb.append([InlineKeyboardButton("🚀 سرویس V2Ray", callback_data="v2ray_buy_menu")])
        
    if bulk_en and ssh_en:
        kb.append([InlineKeyboardButton("📦 ساخت اکانت عمده (Bulk)", callback_data="buy_bulk_start")])
        
    kb.append([InlineKeyboardButton("🔙 بازگشت", callback_data="uact_back_to_menu")])
    
    if not ssh_en and not v2_any and not bulk_en:
        txt = "⚠️ <b>سیستم موقتاً از دسترس خارج است</b>\n\nفروش تمامی سرویس‌ها جهت تعمیرات و به‌روزرسانی متوقف شده است. لطفاً شکیبا باشید."
    else:
        txt = "لطفاً نوع سرویس مورد نظر خود را انتخاب نمایید:"
        
    if update.message: await update.message.reply_text(txt, reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
    else: await update.callback_query.edit_message_text(txt, reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
    context.user_data['state'] = 'BUY_MONTHS'

async def _show_users_panel(update, context, page=0, agent_filter=None):
    context.user_data['user_page'] = page
    role, ag_id = context.user_data.get('role'), context.user_data.get('agent_id', 0)
    
    # 🆕 اگر ادمین از پنل «مدیریت نماینده‌ها» وارد شده باشد
    if agent_filter is not None:
        context.user_data['users_agent_filter'] = agent_filter
    else:
        agent_filter = context.user_data.get('users_agent_filter') if role == 'admin' else None

    show_owner_label = False  
    
    # 🌟 گرفتن نوع سرویس انتخابی کاربر و تعیین نام برای نمایش در هدر
    manage_type = context.user_data.get('manage_type', 'ssh')
    if manage_type == "v2ray": srv_name = "V2Ray نامحدود"
    elif manage_type == "v2ray_vol": srv_name = "V2Ray حجمی"
    else: srv_name = "SSH"

    if role == 'agent':
        rows = await asyncio.to_thread(_db_get_users_with_agents_by_type, manage_type)
        users = [(u, act, cname) for u, owner, act, cname in rows if owner == ag_id]
        panel_title = f"👤 لیست اکانت‌های {srv_name} شما"
    elif agent_filter is not None:
        rows = await asyncio.to_thread(_db_get_users_with_agents_by_type, manage_type)
        users = [(u, act, cname) for u, owner, act, cname in rows if owner == agent_filter]
        agent_info = await asyncio.to_thread(_db_get_agent_info, agent_filter)
        agent_name = agent_info[0] if agent_info else "؟"
        panel_title = f"👤 لیست کاربران {srv_name} نمایندهٔ «{esc(agent_name)}»"
    else:
        rows = await asyncio.to_thread(_db_get_users_with_agents_by_type, manage_type)
        agents_map = {a[0]: a[1] for a in await asyncio.to_thread(_db_get_all_agents)}
        users = [(u, agents_map.get(owner, "مستقیم (ادمین)") if owner else "مستقیم (ادمین)", act, cname) for u, owner, act, cname in rows]
        panel_title = f"👤 لیست تمام کاربران {srv_name} سیستم"
        show_owner_label = True
        
    back_cb = f"agm_det_{agent_filter}" if agent_filter is not None else "uact_back_to_menu"
    bottom_kb = [[InlineKeyboardButton("🔍 جستجوی کاربر", callback_data="usearch")]]
    
    if role == 'admin' and agent_filter is None:
        bottom_kb.append([InlineKeyboardButton("📢 پیام همگانی به نمایندگان", callback_data="bcast_menu")])
    bottom_kb.append([InlineKeyboardButton("🔙 بازگشت", callback_data=back_cb)])

    if not users:
        txt = f"{panel_title}\n\nهیچ کاربری یافت نشد."; kb = bottom_kb
    else:
        start = page * 10; end = start + 10; page_users = users[start:end]
        user_kb = []
        if show_owner_label:
            for u in page_users:
                act_label = " (تمدیدی)" if u[2] == 'extend' else (" (جدید)" if u[2] == 'create' else "")
                cname_label = f" ({u[3]}) " if len(u) > 3 and u[3] else " "
                user_kb.append([InlineKeyboardButton(f"👤 {u[0]}{cname_label}{act_label} — {u[1]}", callback_data=f"udet_{u[0]}")])
        else:
            for u in page_users:
                act_label = " (تمدیدی)" if u[1] == 'extend' else (" (جدید)" if u[1] == 'create' else "")
                cname_label = f" ({u[2]}) " if len(u) > 2 and u[2] else " "
                user_kb.append([InlineKeyboardButton(f"👤 {u[0]}{cname_label}{act_label}", callback_data=f"udet_{u[0]}"), InlineKeyboardButton("⚙️ تنظیمات", callback_data=f"udet_{u[0]}")])
        nav = []
        if page > 0: nav.append(InlineKeyboardButton("◀️ قبلی", callback_data=f"upage_{page-1}"))
        if end < len(users): nav.append(InlineKeyboardButton("بعدی ▶️", callback_data=f"upage_{page+1}"))
        if nav: user_kb.append(nav)
        kb = user_kb + bottom_kb
        txt = f"{panel_title} (صفحه {page+1}):"

    if hasattr(update, 'callback_query') and update.callback_query: await update.callback_query.edit_message_text(txt, reply_markup=InlineKeyboardMarkup(kb))
    else: await update.message.reply_text(txt, reply_markup=InlineKeyboardMarkup(kb))

async def _bcast_build_menu_kb():
    """کیبورد منوی «پیام همگانی به نمایندگان»: گزینهٔ نوشتن پیام جدید + دکمهٔ هر پیام آماده."""
    presets = await asyncio.to_thread(_db_get_broadcast_presets)
    kb = [[InlineKeyboardButton("✍️ نوشتن پیام جدید", callback_data="bcast_new")]]
    for pid, title, _body in presets:
        kb.append([InlineKeyboardButton(f"⚡️ {title}", callback_data=f"bcast_preset_{pid}")])
    kb.append([InlineKeyboardButton("➕ افزودن پیام آماده", callback_data="bcast_add_preset")])
    if presets:
        kb.append([InlineKeyboardButton("🗑 مدیریت پیام‌های آماده", callback_data="bcast_manage_presets")])
    kb.append([InlineKeyboardButton("🔙 بازگشت", callback_data="uact_back")])
    return InlineKeyboardMarkup(kb)

async def _bcast_show_preview(query_or_update, context, body: str, edit: bool = True):
    """پیش‌نمایش پیام + دکمهٔ تاییدیهٔ ارسال، قبل از فرستادن واقعی به همهٔ نمایندگان."""
    context.user_data['bcast_pending_text'] = body
    agents = await asyncio.to_thread(_db_get_agents_with_telegram)
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton(f"✅ بله، برای {fa_digits(len(agents))} نماینده ارسال شود", callback_data="bcast_confirm_send")],
        [InlineKeyboardButton("↩️ انصراف", callback_data="bcast_cancel")]])
    txt = (f"📢 <b>پیش‌نمایش پیام همگانی</b>\n(دقیقاً به همین شکل ساده و بدون قالب‌بندی برای نمایندگان ارسال می‌شود)\n\n"
           f"➖➖➖➖➖➖➖➖\n{esc(body)}\n➖➖➖➖➖➖➖➖\n\n"
           f"👥 گیرندگان: {fa_digits(len(agents))} نماینده (که chat_id تلگرامشان ثبت شده)")
    if edit:
        await query_or_update.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    else:
        await query_or_update.message.reply_text(txt, reply_markup=kb, parse_mode="HTML")

async def _bcast_send_now(app, body: str):
    """پیام را واقعاً برای همهٔ نمایندگانِ دارای chat_id ارسال می‌کند. خروجی: (تعداد موفق, تعداد ناموفق)."""
    agents = await asyncio.to_thread(_db_get_agents_with_telegram)
    ok_n, fail_n = 0, 0
    full_text = f"📢 اطلاعیهٔ مدیریت:\n\n{body}"
    for aid, name, chat_id in agents:
        try:
            await app.bot.send_message(chat_id=chat_id, text=full_text)
            ok_n += 1
        except Exception:
            fail_n += 1
    return ok_n, fail_n

async def _build_napsternet_link(host: str, port, un: str, pw: str, conn_mode: str = 'direct') -> str:
    """
    یک کد اتصال نپسترنت (Napsternetv) تمیز و تکی می‌سازد — نه یکی به‌ازای هر هاست.
    🔧 قبلاً برای هر هاست تنظیم‌شده یک بلوک کد جداگانه و طولانی ساخته می‌شد که هم فاکتور را
    شلوغ می‌کرد و هم چون این رشته با یک الگوی شبیه URL (npvt-ssh://) شروع می‌شود، ممکن بود
    کلاینت تلگرام آن را به‌جای «کپی با یک لمس» به‌صورت یک لینک آبی/زیرخط‌دار نمایش دهد.
    اینجا فقط یک لینک — مربوط به هاست اصلی — و کاملاً داخل تگ <code> برمی‌گردانیم.

    🆕 conn_mode='direct' (پیش‌فرض، رفتار قبلی بدون تغییر): IP/هاست و پورت واقعی سرور مستقیماً
    داخل کد قرار می‌گیرد (sshConfigType=SSH-Direct).
    conn_mode='tls': اتصال SSH-TLS واقعی — کلاینت مستقیماً یک هندشیک TLS واقعی با دامنه/گواهیِ
    ست‌شده روی سرور برقرار می‌کند (sshConfigType=SSH-TLS). دامنه/پورت از تنظیمات سرور ←
    🔐 تنظیمات TLS خوانده می‌شود.
    """
    # 🆕 پورت UDPGW دیگر هاردکد نیست — از تنظیمات سرور خوانده می‌شود تا با پورت واقعیِ سرویس
    # badvpn-udpgw روی سرور یکی باشد (قبلاً همیشه 1234 فرستاده می‌شد، صرف‌نظر از این‌که سرور
    # واقعاً روی چه پورتی گوش می‌داد — همان چیزی که باعث «برای بعضی‌ها وصل نمی‌شود» می‌شد).
    udpgw_port = int(await asyncio.to_thread(_db_get_setting, 'udpgw_port', '7300'))
    # 🆕 این هم دیگر هاردکد (False) نیست — طبق همان کانفیگ دستیِ تست‌شده، پیش‌فرض «فعال»ه.
    udpgw_tdns = (await asyncio.to_thread(_db_get_setting, 'udpgw_transparent_dns', '1')) == '1'
    if conn_mode == 'tls':
        tls_domain = await asyncio.to_thread(_db_get_setting, 'tls_domain', 'ws.nvlsup.com')
        tls_port = await asyncio.to_thread(_db_get_setting, 'tls_port', '2088')
        cfg = {"sshConfigType": "SSH-TLS", "remarks": un, "sshHost": tls_domain, "sshPort": int(tls_port),
               "sshUsername": un, "sshPassword": pw, "sni": tls_domain, "tlsVersion": "DEFAULT", "httpProxy": "",
               "authenticateProxy": False, "proxyUsername": "", "proxyPassword": "", "payload": "", "dnsTTMode": "UDP",
               "dnsServer": "", "nameserver": "", "publicKey": "", "udpgwPort": udpgw_port, "udpgwTransparentDNS": udpgw_tdns}
    else:
        # 🆕 اگر دامنهٔ ثابت عمومی تنظیم شده باشد، به‌جای IP خام همان دامنه در کد قرار می‌گیرد —
        # این‌طوری وقتی IP پشت‌صحنه عوض می‌شود (فیلترشدن/قطعی)، کد قبلی که در اپ مشتری ایمپورت
        # شده هم بدون نیاز به دریافت کد جدید، خودکار به IP جدید وصل می‌شود.
        public_domain = await asyncio.to_thread(_db_get_setting, 'public_domain', '')
        effective_host = public_domain.strip() if public_domain.strip() else host
        # اگر دامنهٔ ثابت فعال باشد، DNS ممکن است به IP دیگری اشاره کند؛ پورت همان IP خوانده می‌شود.
        dns_target = await asyncio.to_thread(_db_get_setting, 'dns_current_ip', '') if public_domain.strip() else ''
        effective_port = await asyncio.to_thread(_db_get_host_ssh_port, dns_target.strip() or host, port)
        cfg = {"sshConfigType": "SSH-Direct", "remarks": un, "sshHost": effective_host, "sshPort": int(effective_port),
               "sshUsername": un, "sshPassword": pw, "sni": "", "tlsVersion": "DEFAULT", "httpProxy": "",
               "authenticateProxy": False, "proxyUsername": "", "proxyPassword": "", "payload": "", "dnsTTMode": "UDP",
               "dnsServer": "", "nameserver": "", "publicKey": "", "udpgwPort": udpgw_port, "udpgwTransparentDNS": udpgw_tdns}
    code = base64.b64encode(json.dumps(cfg, separators=(',', ':')).encode()).decode()
    return f"npvt-ssh://{code}"

async def _build_invoice_text(un: str):
    """
    متن کامل فاکتور یک اکانت را همیشه تازه و از روی دیتابیس فعلی می‌سازد (نه از یک متن ذخیره‌شدهٔ
    قدیمی). چون تمام اطلاعات لازم (پسورد، تاریخ‌ها، ظرفیت) در جدول ssh_accounts نگه‌داری می‌شود،
    این تابع همیشه — حتی روزها بعد از ساخت اکانت و حتی بعد از ری‌استارت ربات — قابل فراخوانی و
    ارسال مجدد است؛ بنابراین «امکان ارسال مجدد فاکتور» دیگر وابسته به لاگ یا حافظهٔ موقت نیست.
    خروجی: متن HTML فاکتور، یا None اگر اکانت دیگر وجود نداشته باشد.
    """
    row = await asyncio.to_thread(_db_get_user, un)
    if not row: return None
    pw, exp, crt, lim, st, _agid, acc_host, acc_conn_mode = row
    hl = [h.strip() for h in (await asyncio.to_thread(_db_get_setting, 'hosts', LAST_RESORT_HOST_IP)).split(',') if h.strip()]
    prt = await asyncio.to_thread(_db_get_setting, 'port', '22')
    # 🆕 اگر حالت اتصال این اکانت «tls» باشد، در فاکتور هم به‌جای IP خامِ سرور، همان دامنهٔ TLS
    # (و پورت مربوطه) نمایش داده می‌شود — چون در این حالت کلاینت اصلاً نباید مستقیم به IP وصل شود.
    if acc_conn_mode == 'tls':
        primary_host = await asyncio.to_thread(_db_get_setting, 'tls_domain', 'ws.nvlsup.com')
        prt = await asyncio.to_thread(_db_get_setting, 'tls_port', '2088')
        mode_line = "🔐 حالت اتصال: TLS (اتصال مستقیم با گواهی معتبر)\n"
    else:
        public_domain = await asyncio.to_thread(_db_get_setting, 'public_domain', '')
        if public_domain.strip():
            primary_host = public_domain.strip()
        else:
            primary_host = acc_host if acc_host else (hl[0] if hl else _hosts_fallback_with_warning())
        # در حالت دامنهٔ ثابت، پورت باید متعلق به IP فعلیِ همان دامنه باشد، نه لزوماً IP اولیهٔ اکانت.
        dns_target = await asyncio.to_thread(_db_get_setting, 'dns_current_ip', '') if public_domain.strip() else ''
        prt = await asyncio.to_thread(_db_get_host_ssh_port, dns_target.strip() or primary_host, prt)
        mode_line = "🔌 حالت اتصال: مستقیم\n"
    rem_str = get_remaining_days(exp)
    hold_active, _hd, hold_days = await asyncio.to_thread(_db_get_hold_info, un)
    if hold_active:
        rem_str = f"ON HOLD ({ACCOUNT_HOLD_DAYS} Days)"

    # 🗓 محاسبهٔ تعداد ماه اشتراک بر اساس روزهای پلن
    m_count = 1
    if hold_days:
        m_count = max(1, round(int(hold_days) / 30))
    else:
        try:
            exp_dt = datetime.strptime(exp[:10], "%Y-%m-%d")
            crt_dt = datetime.strptime(crt[:10], "%Y-%m-%d")
            m_count = max(1, round((exp_dt - crt_dt).days / 30))
        except Exception:
            m_count = 1

    return (f"host: {esc(primary_host)}\n"
            f"username: <code>{esc(un)}</code>\npassword: <code>{esc(pw)}</code>\nport: <code>{esc(prt)}</code>\n\n"
            f"{mode_line}"
            f"مدت اشتراک: {m_count} ماهه\n"
            f"تاریخ انقضا: {format_db_date_to_jalali(exp)} | ({rem_str})\n"
            f"تعداد کاربر مجاز به اتصال: {lim}\nحجم: نامحدود\nتاریخ ساخت: {format_db_date_to_jalali(crt)}\nوضعیت: {st}")
#----------------------------------------------------
async def _show_v2ray_user_detail(update_or_query, username, context, db_res, v2_res):
    p, exp, crt, lim, st, owner_aid, _, _ = db_res
    stype, db_data_limit, sub_url = v2_res
    role, ag_id = context.user_data.get('role'), context.user_data.get('agent_id', 0)
    c_name = await asyncio.to_thread(_db_get_customer_name, username)
    c_name_txt = f"\n🔖 نام مشتری/نشانه: {esc(c_name)}" if c_name else ""
    
    is_vol = (stype == 'v2ray_vol')
    
    owner_label = "مستقیم (ادمین)"
    if owner_aid:
        owner_info = await asyncio.to_thread(_db_get_agent_info, owner_aid)
        owner_label = f"نمایندهٔ «{owner_info[0]}»" if owner_info else "نماینده نامشخص"
        
    rem_str = get_remaining_days(exp)
    status_v2 = st
    usage_extra_txt = ""
    
    # 🌟 دریافت اطلاعات مصرف: برای ادمین (روی همه اکانت‌ها) و برای نمایندگان (فقط روی اکانت‌های حجمی)
    if role == 'admin' or is_vol:
        m_url = await asyncio.to_thread(_db_get_setting, 'marzban_url', '')
        m_user = await asyncio.to_thread(_db_get_setting, 'marzban_username', '')
        m_pwd = await asyncio.to_thread(_db_get_setting, 'marzban_password', '')
        ok, m_data = await v2ray_engine.get_user(m_url, m_user, m_pwd, username)
        
        usage_txt = "نامشخص (خطا در ارتباط با سرور)"
        if ok and isinstance(m_data, dict):
            used = m_data.get('used_traffic', 0)
            limit = m_data.get('data_limit', 0)
            used_gb = round(used / (1024**3), 2)
            limit_gb = round(limit / (1024**3), 2) if limit else "نامحدود"
            usage_txt = f"{used_gb} GB / {limit_gb} GB"
            
            m_status = m_data.get('status', '')
            if m_status == 'disabled': status_v2 = "🔴 غیرفعال"
            elif m_status == 'active': status_v2 = "🟢 فعال"

        if is_vol:
            usage_extra_txt = f"\n📦 حجم مصرفی: {usage_txt}"
        else:
            usage_extra_txt = f"\n📊 لیمیت روزانه: {usage_txt}"

    rem_txt = "نامحدود زمانی" if is_vol else get_remaining_days(exp)
    exp_txt = "بدون محدودیت زمانی" if is_vol else format_db_date_to_jalali(exp)
    lim_txt = "نامحدود" if is_vol else lim

    txt = (f"username: <code>{esc(username)}</code>{c_name_txt}\n\n"
           f"👤 مالک: {esc(owner_label)}\n"
           f"تعداد کاربر: {lim_txt}\n"
           f"🔀 حالت اتصال: {'V2Ray حجمی' if is_vol else 'V2Ray نامحدود'}\n"
           f"انقضا: {exp_txt} | ({rem_txt})\n"
           f"تاریخ ساخت: {format_db_date_to_jalali(crt)}\n"
           f"وضعیت: {status_v2}{usage_extra_txt}")

    kb = [
        [InlineKeyboardButton("🔗 دریافت لینک اتصال", callback_data=f"v2act_sub_{username}")]
    ]
    
    if not is_vol:
        rn_row = [InlineKeyboardButton("🔄 تمدید اکانت", callback_data=f"v2act_rn_{username}")]
        if role == 'admin':
            rn_row.append(InlineKeyboardButton("🔻 کاهش زمان", callback_data=f"v2act_rd_{username}"))
        kb.append(rn_row)
        
        if role == 'admin':
            kb.append([InlineKeyboardButton("👥 تغییر تعداد کاربر", callback_data=f"v2act_ul_{username}"), 
                       InlineKeyboardButton("📊 تغییر لیمیت روزانه", callback_data=f"v2act_lim_{username}")])
    else:
        vol_row = [InlineKeyboardButton("➕ افزایش حجم", callback_data=f"v2act_addvol_{username}")]
        if role == 'admin':
            vol_row.append(InlineKeyboardButton("➖ کاهش حجم", callback_data=f"v2act_decvol_{username}"))
        kb.append(vol_row)
    
    kb.extend([
        [InlineKeyboardButton("🔴 غیرفعال" if status_v2 == "🟢 فعال" else "🟢 فعال", callback_data=f"v2act_tg_{username}"), 
         InlineKeyboardButton("🗑 حذف اکانت", callback_data=f"v2act_dl_{username}")],
        [InlineKeyboardButton("🔙 بازگشت به لیست", callback_data="uact_back")]
    ])
    
    if hasattr(update_or_query, 'callback_query') and update_or_query.callback_query:
        await update_or_query.callback_query.edit_message_text(txt, reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
    elif hasattr(update_or_query, 'edit_message_text'):
        await update_or_query.edit_message_text(txt, reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
    else:
        await update_or_query.message.reply_text(txt, reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")

#----------------------------------------------------------

async def _show_user_detail(update_or_query, username, context):
    res = await asyncio.to_thread(_db_get_user, username)
    if not res:
        target = update_or_query.callback_query if hasattr(update_or_query, 'callback_query') and update_or_query.callback_query else update_or_query
        msg = "❌ این کاربر دیگر در دیتابیس وجود ندارد."
        if hasattr(target, 'edit_message_text'): await target.edit_message_text(msg)
        else: await target.message.reply_text(msg)
        return
    p, exp, crt, lim, st, owner_aid, acc_host, acc_conn_mode = res
    # 🌟 روتینگ هوشمند: هدایت به پنل V2Ray در صورت نیاز
    with db_conn() as conn:
        stype_row = conn.execute("SELECT service_type, data_limit, sub_url FROM ssh_accounts WHERE username=?", (username,)).fetchone()
    if stype_row and stype_row[0] in ('v2ray', 'v2ray_vol'):
        return await _show_v2ray_user_detail(update_or_query, username, context, res, stype_row)
    
    acc_conn_mode = acc_conn_mode or 'direct'
    target = update_or_query.callback_query if hasattr(update_or_query, 'callback_query') and update_or_query.callback_query else update_or_query
    role, ag_id = context.user_data.get('role'), context.user_data.get('agent_id', 0)
    if not _can_manage_user(role, ag_id, owner_aid):
        msg = "⛔️ شما مجاز به مشاهده/مدیریت این اکانت نیستید."
        if hasattr(target, 'edit_message_text'): await target.edit_message_text(msg)
        else: await target.message.reply_text(msg)
        return
    rem_str = get_remaining_days(exp)
    owner_label = "مستقیم (ادمین)"
    if owner_aid:
        owner_info = await asyncio.to_thread(_db_get_agent_info, owner_aid)
        owner_label = f"نمایندهٔ «{owner_info[0]}»" if owner_info else f"نمایندهٔ حذف‌شده (کد {owner_aid})"
    hl = [h.strip() for h in (await asyncio.to_thread(_db_get_setting, 'hosts', LAST_RESORT_HOST_IP)).split(',') if h.strip()]
    display_host = acc_host if acc_host else (f"{hl[0]} (پیش‌فرض)" if hl else "تنظیم‌نشده")

    if role == 'agent':
        host_display_text = ""
        conn_line = ""
        health_line = ""
    else:
        host_display_text = f"\n🌐 هاست فعلی: {esc(display_host)}"
        conn_counts, conn_err = await _get_live_connection_counts()
        if conn_err:
            conn_line = "\nتعداد دستگاه های متصل شده: نامشخص (خطای مانیتورینگ سرور)"
        else:
            live_n = conn_counts.get(username.lower(), 0)
            u_det = getattr(conn_counts, 'users_detail', {}).get(username.lower(), {'ssh': 0, 'tls': 0})
            conn_line = f"\nتعداد دستگاه های متصل شده: {live_n} (مستقیم: {u_det['ssh']} | TLS: {u_det['tls']})"

        health, herr, is_remote = await _get_health_for_host(acc_host or (hl[0] if hl else None))
        host_label = "Edge" if is_remote else "Core"
        if herr:
            health_line = f"\n📊 وضعیت سرور ({host_label} — {esc(display_host)}): نامشخص ({esc(herr)})"
        else:
            health_line = (f"\n📊 وضعیت سرور ({host_label} — {esc(display_host)}): CPU {health['cpu_pct']}٪ | "
                            f"RAM {health['ram_used_mb']:,}/{health['ram_total_mb']:,} مگابایت ({health['ram_pct']}٪)")

    kb = [
        [InlineKeyboardButton("🔗 دریافت کد نپسترنت", callback_data=f"uact_ni_{username}"), InlineKeyboardButton("🧾 دریافت فاکتور کامل", callback_data=f"uact_inv_{username}")],
        [InlineKeyboardButton("🔄 تمدید اکانت", callback_data=f"uact_rn_{username}"), InlineKeyboardButton("🔻 کاهش تمدید", callback_data=f"uact_rd_{username}")],
        [InlineKeyboardButton("تغییر پسورد", callback_data=f"uact_pw_{username}"), InlineKeyboardButton("👥 تعداد کاربر", callback_data=f"uact_uc_{username}")],
        [InlineKeyboardButton("📜 تاریخچه اتصالات", callback_data=f"uact_hist_{username}")],
        [InlineKeyboardButton("🔴 غیرفعال" if st == "🟢 فعال" else "🟢 فعال", callback_data=f"uact_tg_{username}"), InlineKeyboardButton("🗑 حذف اکانت", callback_data=f"uact_dl_{username}")],
        [InlineKeyboardButton("🔙 بازگشت به لیست", callback_data="uact_back")]
    ]
    mode_label = {"tls": "🔐 TLS (اتصال مستقیم با گواهی معتبر)"}.get(acc_conn_mode, "🔌 مستقیم")
    hold_active, _hd, hold_days = await asyncio.to_thread(_db_get_hold_info, username)
    hold_line = ""
    if hold_active:
        real_days_txt = f"{int(hold_days)} روزه" if hold_days else "خریداری‌شده"
        hold_line = f"\n⏳ در حال آنهولد (اشتراک {real_days_txt} — منتظر اولین اتصال یا پایان مهلت {ACCOUNT_HOLD_DAYS} روزه)"
    
    txt = (f"username: {esc(username)}\npassword: {esc(p)}\n\n👤 مالک: {esc(owner_label)}\nتعداد کاربر: {lim}"
           f"{host_display_text}\n🔀 حالت اتصال: {mode_label}\n"
           f"انقضا: {format_db_date_to_jalali(exp)} | ({rem_str})\nتاریخ ساخت: {format_db_date_to_jalali(crt)}\nوضعیت: {st}" + conn_line + health_line + hold_line)
    if hasattr(update_or_query, 'callback_query') and update_or_query.callback_query: await update_or_query.callback_query.edit_message_text(txt, reply_markup=InlineKeyboardMarkup(kb))
    elif hasattr(update_or_query, 'edit_message_text'): await update_or_query.edit_message_text(txt, reply_markup=InlineKeyboardMarkup(kb))
    else: await update_or_query.message.reply_text(txt, reply_markup=InlineKeyboardMarkup(kb))

async def _show_agent_detail(query, context, a_id):
    """🆕 پنل جزئیات یک نماینده را (دوباره) رندر می‌کند — هم از دکمهٔ «مشاهده نماینده» در لیست و هم
    بعد از لغو/تکمیل تغییر یوزرنیم/پسورد ورود یک نماینده استفاده می‌شود، تا کد تکراری نشود."""
    info = await asyncio.to_thread(_db_get_agent_info, a_id)
    if not info: await query.edit_message_text("❌ وجود ندارد."); return
    t, w, m_val, act, total = await asyncio.to_thread(_db_get_sales_stats, a_id)
    t_ssh, w_ssh, m_ssh, act_ssh, total_ssh = await asyncio.to_thread(_db_get_sales_stats, a_id, 'ssh')
    t_v2, w_v2, m_v2, act_v2, total_v2 = await asyncio.to_thread(_db_get_sales_stats, a_id, 'v2ray')
    
    referral_income = info[9] if len(info) > 9 and info[9] is not None else 0
    agent_prefix = info[10] if len(info) > 10 and info[10] else "پیش‌فرض سیستم"
    agent_username = info[11] if len(info) > 11 and info[11] else "-"
    emergency_used = info[12] if len(info) > 12 and info[12] else 0.0
    emergency_req_count = info[13] if len(info) > 13 and info[13] else 0
    withdrawable = info[14] if len(info) > 14 and info[14] is not None else 0.0
    cashback_income = info[15] if len(info) > 15 and info[15] is not None else 0.0
    v2_base_price = info[16] if len(info) > 16 and info[16] else '160000'
    try: ssh_bp_fmt = f"{int(str(info[4]).replace(',', '')):,}"
    except: ssh_bp_fmt = str(info[4])
    try: v2_bp_fmt = f"{int(str(v2_base_price).replace(',', '')):,}"
    except: v2_bp_fmt = str(v2_base_price)
    v2_vol_bp = info[17] if len(info) > 17 and info[17] else '4000'
    try: v2_vol_bp_fmt = f"{int(str(v2_vol_bp).replace(',', '')):,}"
    except: v2_vol_bp_fmt = str(v2_vol_bp)

    txt = (f"💼 نماینده: {esc(info[0])}\n👤 یوزرنیم ورود: <code>{esc(agent_username)}</code>\n🔑 رفرال: <code>{esc(info[1])}</code>\n💰 موجودی: {int(info[2]):,} تومان\n"
           f"💹 درآمد از زیرمجموعه: {int(referral_income):,} تومان\n"
           f"💵 نرخ پایه SSH (هر کاربر/ماه): {ssh_bp_fmt} تومان\n"
           f"🚀 نرخ پایه V2Ray (هر کاربر/ماه): {v2_bp_fmt} تومان\n"
           f"🪐 نرخ پایه V2Ray حجمی (هر گیگ): {v2_vol_bp_fmt} تومان\n"
           f"🎁 مجموع کش‌بک: {int(cashback_income):,} تومان\n"
           f"💵 استخر قابل‌برداشت: {int(withdrawable):,} تومان\n"
           f"🏷 پیشوند یوزرنیم: <code>{esc(agent_prefix)}</code>\n")

    if emergency_used > 0:
        txt += (f"\n🆘 <b>شارژ اضطراری فعال:</b> {int(emergency_used):,} از {int(EMERGENCY_CREDIT_LIMIT):,} تومان مصرف‌شده "
                f"(درخواست {emergency_req_count} از {EMERGENCY_MAX_CONSECUTIVE_REQUESTS})\n"
                f"↳ این مبلغ در اولین شارژ بعدی به‌طور خودکار کسر می‌شود.\n")

    txt += (f"\n📉 <b>درصدهای شبکه:</b>\nلایه 1: {info[3]}%\nلایه 2: {info[5]}%\nلایه 3: {info[6]}%\n\n"
            f"📦 <b>آمار کل فروش نماینده:</b>\n"
            f"کل فروخته‌شده: {total} | اکانت فعال: {act}\n"
            f"فروش امروز: {t} | فروش هفته: {w} | فروش ماه: {m_val}\n\n"
            f"🔹 <b>تفکیک SSH:</b>\n"
            f"کل فروخته‌شده: {total_ssh} | اکانت فعال: {act_ssh}\n"
            f"فروش امروز: {t_ssh} | فروش هفته: {w_ssh} | فروش ماه: {m_ssh}\n\n"
            f"🚀 <b>تفکیک V2Ray:</b>\n"
            f"کل فروخته‌شده: {total_v2} | اکانت فعال: {act_v2}\n"
            f"فروش امروز: {t_v2} | فروش هفته: {w_v2} | فروش ماه: {m_v2}")
    pending_wds = await asyncio.to_thread(_db_get_agent_pending_withdrawals, a_id)
    kb = [[InlineKeyboardButton("👥 مشاهده کاربران این نماینده", callback_data=f"agm_users_{a_id}")],
          [InlineKeyboardButton("💰 شارژ مستقیم کیف‌پول", callback_data=f"agm_topup_{a_id}"), InlineKeyboardButton("➖ کاهش شارژ کیف‌پول", callback_data=f"agm_deduct_{a_id}")],
          [InlineKeyboardButton(f"🧾 درخواست‌های برداشت{f' ({len(pending_wds)} در انتظار)' if pending_wds else ''}", callback_data=f"agm_wdlist_{a_id}")],
          [InlineKeyboardButton("🏷 تنظیم پیشوند یوزرنیم", callback_data=f"agm_prefix_{a_id}")],
          [InlineKeyboardButton("👤 تغییر یوزرنیم ورود", callback_data=f"agm_edituser_{a_id}"), InlineKeyboardButton("🔑 تغییر پسورد ورود", callback_data=f"agm_editpass_{a_id}")],
          [InlineKeyboardButton("💵 قیمت پایه SSH", callback_data=f"ag_p_{a_id}"), InlineKeyboardButton("🚀 قیمت پایه V2Ray", callback_data=f"ag_pv2_{a_id}")],
          [InlineKeyboardButton("🪐 قیمت پایه V2Ray حجمی", callback_data=f"ag_pv2v_{a_id}")],
          [InlineKeyboardButton("📉 تخفیف مستقیم", callback_data=f"ag_c1_{a_id}")],
          [InlineKeyboardButton("📉 تخفیف پدر", callback_data=f"ag_c2_{a_id}"), InlineKeyboardButton("📉 تخفیف پدربزرگ", callback_data=f"ag_c3_{a_id}")],
          [InlineKeyboardButton("🗑 حذف نماینده", callback_data=f"agm_del_{a_id}")],
          [InlineKeyboardButton("🔙 بازگشت به لیست", callback_data="agm_list")]]
    await query.edit_message_text(txt, reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")

async def _show_buy_summary(update_or_message, context, edit=False):
    m, u = context.user_data.get('months'), context.user_data.get('users')
    if m is None or u is None: return
    bulk_mode = context.user_data.get('bulk_mode', False)
    bulk_count = context.user_data.get('bulk_count', 1)
    role = context.user_data.get('role')

    # 🆕 حالت اتصالِ اجباری روی مستقیم (TLS از سبد خرید حذف شد)
    context.user_data['conn_mode'] = 'direct'

    # 📦 در حالت عمده، دکمهٔ افزودن/حذف از «کانفیگ‌های مورد علاقه» نمایش داده نمی‌شود
    kb = [
        [InlineKeyboardButton("✅ بله، تایید و ساخت", callback_data="buy_yes"), InlineKeyboardButton("❌ خیر، بازگشت", callback_data="buy_back_start")]
    ]
    if not bulk_mode:
        is_fav = await asyncio.to_thread(_db_check_fav, m, u)
        if is_fav: kb.append([InlineKeyboardButton("❌ حذف از کانفیگ‌های مورد علاقه", callback_data=f"fav_rem_{m}_{u}")])
        else: kb.append([InlineKeyboardButton("⭐ اضافه کردن به کانفیگ‌های مورد علاقه", callback_data=f"fav_add_{m}_{u}")])

    if bulk_mode:
        txt = f"📦 <b>ساخت اکانت عمده SSH</b>\n\n🔢 تعداد اکانت: {bulk_count}\n📅 مدت هرکدام: {m} ماهه\n👥 تعداد کاربر مجاز هرکدام: {u}\n🔀 حالت اتصال: 🔌 مستقیم\n"
        if role == 'agent':
            ainf = await asyncio.to_thread(_db_get_agent_info, context.user_data.get('agent_id', 0))
            if ainf:
                price_preview = _parse_price_to_decimal(ainf[4]) * Decimal(m) * Decimal(u) * Decimal(bulk_count)
                txt += f"💳 مجموع هزینهٔ این خرید ({bulk_count} اکانت): {int(price_preview):,} تومان\n"
        txt += f"\nآیا از ساخت این {bulk_count} اکانت مطمئن هستید؟"
    else:
        txt = f"📋 <b>تایید ساخت اکانت SSH</b>\n\n📅 مدت اکانت: {m} ماهه\n👥 تعداد کاربر: {u}\n🔀 حالت اتصال: 🔌 مستقیم\n"
        if role == 'agent':
            ainf = await asyncio.to_thread(_db_get_agent_info, context.user_data.get('agent_id', 0))
            if ainf:
                price_preview = _parse_price_to_decimal(ainf[4]) * Decimal(m) * Decimal(u)
                txt += f"💳 هزینهٔ این خرید: {int(price_preview):,} تومان\n"
        txt += "\nآیا از ساخت این اکانت مطمئن هستید؟"

    if edit:
        try:
            await update_or_message.edit_text(txt, reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
        except Exception as e:
            if "not modified" not in str(e).lower():
                raise e
    else:
        await update_or_message.reply_text(txt, reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")

# ==========================================
# 🔄 منطق مشترک «تاییدیهٔ تمدید اکانت» — هم برای دکمه‌های آمادهٔ ۱/۲/۳ ماهه و هم برای
# ورودی «تعداد روز دلخواه» استفاده می‌شود تا هیچ منطقی دوبار نوشته نشود.
# ==========================================
async def _show_renew_confirm(target, context, un, days, label, edit=True, mode='extend'):
    # 🆕 «mode» می‌تواند 'extend' (تمدید معمولی) یا 'reduce' (کاهش تعداد روز/ماه‌های تمدیدشده،
    # برای اصلاح تمدید اشتباهی) باشد. هر دو از همین یک مسیر تاییدیه/اجرا عبور می‌کنند.
    role, ag_id = context.user_data.get('role'), context.user_data.get('agent_id', 0)
    context.user_data['renew_days'] = days
    context.user_data['renew_label'] = label
    context.user_data['renew_mode'] = mode
    cur = await asyncio.to_thread(_db_get_user, un)
    if mode == 'reduce':
        txt = f"🔻 آیا مطمئنید که می‌خواهید از تمدید اکانت {esc(un)} به‌مقدار {label} ({days} روز) کم کنید؟"
    else:
        txt = f"🔄 آیا مطمئنید که می‌خواهید اکانت {esc(un)} را {label} ({days} روز) تمدید کنید؟"
    if role == 'agent' and cur:
        ainf = await asyncio.to_thread(_db_get_agent_info, ag_id)
        if ainf:
            account_users_limit = cur[3]
            preview_cost = _parse_price_to_decimal(ainf[4]) * (Decimal(days) / Decimal(30)) * Decimal(account_users_limit)
            if mode == 'reduce':
                txt += f"\n💰 مبلغی که به موجودی شما بازگردانده می‌شود: {int(preview_cost):,} تومان"
            else:
                txt += f"\n💳 هزینهٔ این تمدید: {int(preview_cost):,} تومان"
    kb = InlineKeyboardMarkup([[InlineKeyboardButton("✅ بله، انجام شود", callback_data="rnyes"), InlineKeyboardButton("❌ خیر", callback_data="rnno")]])
    if edit: await target.edit_message_text(txt, reply_markup=kb)
    else: await target.reply_text(txt, reply_markup=kb)

# ==========================================
# ➕ منطق مشترک «افزایش تعداد کاربر مجاز» — هم برای دکمه‌های آماده (+۱/+۲/+۳) و هم برای
# ورودی دلخواه (کاستوم) استفاده می‌شود تا هیچ منطقی دوبار نوشته نشود.
# ==========================================
async def _apply_user_limit_increase(context, role, ag_id, un, new_limit, emergency_approved=False):
    """
    تلاش برای افزایش «تعداد کاربر مجاز» یک اکانت به new_limit.
    خروجی: (ok: bool, text: str, emergency_kb: InlineKeyboardMarkup|None)
    اگر emergency_kb مقداری غیر از None داشته باشد، یعنی موجودی کافی نیست ولی امکان استفاده از
    «شارژ اضطراری» وجود دارد؛ در این حالت ok=False است و باید همان کیبورد به کاربر نشان داده شود
    (context حاوی هدف/تعداد جدید برای اجرای واقعی بعد از تایید نگه داشته می‌شود).
    """
    cur = await asyncio.to_thread(_db_get_user, un)
    if not cur:
        return False, "❌ این کاربر دیگر وجود ندارد.", None
    if not _can_manage_user(role, ag_id, cur[5]):
        return False, "⛔️ شما مجاز به مدیریت این اکانت نیستید.", None
    cur_limit = cur[3]
    if new_limit <= cur_limit:
        return False, f"❌ عدد جدید باید بزرگ‌تر از تعداد فعلی ({cur_limit}) باشد.", None
    added_users = new_limit - cur_limit
    try:
        cost = 0.0
        retail_dec = Decimal("0")
        ag_id_local = ag_id
        ainf = None
        if role == 'agent':
            ainf = await asyncio.to_thread(_db_get_agent_info, ag_id_local)
            if not ainf:
                return False, "❌ خطا: اطلاعات نمایندگی شما یافت نشد.", None
            rem_days = (datetime.strptime(cur[1], "%Y-%m-%d").date() - datetime.now().date()).days
            rem_months = max(1, -(-max(rem_days, 1) // 30))  # سقف تقسیم (ceil)
            base_price_dec = _parse_price_to_decimal(ainf[4])
            retail_dec = base_price_dec * Decimal(added_users) * Decimal(rem_months)
            cost = float(retail_dec)
            if ainf[2] < cost and not emergency_approved:
                has_opt, remaining_em, shortfall, used_em, req_cnt = _check_emergency_option(ainf, cost)
                if has_opt:
                    # 🆘 هدف و تعداد جدید در context ذخیره می‌شود تا بعد از کلیک روی دکمهٔ شارژ
                    # اضطراری (uinc_emergency_yes) بتوانیم دقیقاً همین درخواست را دوباره اجرا کنیم.
                    context.user_data['ul_emergency_un'] = un
                    context.user_data['ul_emergency_new_limit'] = new_limit
                    kb_em = InlineKeyboardMarkup([[InlineKeyboardButton("🆘 استفاده از شارژ اضطراری", callback_data="uinc_emergency_yes")]])
                    return False, (f"❌ <b>موجودی ناکافی!</b>\n\n💰 موجودی شما: {int(ainf[2]):,} تومان\n"
                                    f"💳 هزینهٔ افزایش {added_users} کاربر برای {rem_months} ماه باقی‌مانده: {int(cost):,} تومان\n\n"
                                    f"🆘 می‌توانید از <b>شارژ اضطراری</b> استفاده کنید (سقف کل: {int(EMERGENCY_CREDIT_LIMIT):,} تومان، "
                                    f"باقی‌ماندهٔ شما: {int(remaining_em):,} تومان). این مبلغ در اولین شارژ بعدی حساب شما به‌طور خودکار کسر می‌شود."), kb_em
                extra = ""
                if req_cnt >= EMERGENCY_MAX_CONSECUTIVE_REQUESTS:
                    extra = "\n\n🆘 سقف درخواست‌های پیاپی شارژ اضطراری (۲ بار) شما پر شده؛ لطفاً منتظر شارژ حساب توسط مدیریت بمانید."
                elif used_em > 0:
                    extra = f"\n\n🆘 شارژ اضطراری باقی‌ماندهٔ شما ({int(remaining_em):,} تومان) برای این افزایش کافی نیست."
                return False, (f"❌ <b>موجودی ناکافی!</b>\n\n💰 موجودی شما: {int(ainf[2]):,} تومان\n"
                                f"💳 هزینهٔ افزایش {added_users} کاربر برای {rem_months} ماه باقی‌مانده: {int(cost):,} تومان{extra}"), None

        await asyncio.to_thread(_db_update_users_limit, un, new_limit)
        await _sync_user_limit_file(un, new_limit)  # 🆕 فایل سقف اتصال PAM هم‌زمان با تغییر عدد به‌روز می‌شود

        if role == 'agent':
            with db_conn() as conn: conn.execute("UPDATE agents SET balance = balance - ? WHERE id=?", (cost, ag_id_local))
            await asyncio.to_thread(_db_distribute_commission, ag_id_local, retail_dec)
            # 🎁 کش‌بک ترغیبی نمایندگان پرفروش (۵۰+ اکانت فعال): ۷٪ از هزینهٔ همین افزایش کاربر
            await _apply_agent_cashback_if_eligible(ag_id_local, retail_dec)
            msg = f"✅ تعداد کاربر مجاز اکانت {esc(un)} از {cur_limit} به {new_limit} افزایش یافت.\n💳 هزینهٔ کسرشده: {int(cost):,} تومان"
            # 🆘 اگر این افزایش با کمک شارژ اضطراری تکمیل شد، مصرف ثبت و به ادمین‌ها اطلاع داده می‌شود
            emergency_shortfall = max(0.0, cost - ainf[2]) if ainf else 0.0
            if emergency_shortfall > 0:
                await asyncio.to_thread(_db_agent_register_emergency_use, ag_id_local, emergency_shortfall)
                msg += f"\n🆘 از این مبلغ، {int(emergency_shortfall):,} تومان از شارژ اضطراری تامین شد."
                with contextlib.suppress(Exception):
                    await _notify_admins(context.application,
                        f"🆘 <b>استفاده از شارژ اضطراری</b>\nنمایندهٔ «{esc(ainf[0])}» برای افزایش تعداد کاربر اکانت <code>{esc(un)}</code> "
                        f"مبلغ {int(emergency_shortfall):,} تومان از شارژ اضطراری استفاده کرد.")
            return True, msg, None
        else:
            return True, f"✅ تعداد کاربر مجاز اکانت {esc(un)} از {cur_limit} به {new_limit} افزایش یافت.", None
    except Exception:
        log.exception("خطا در افزایش تعداد کاربر مجاز اکانت %s", un)
        return False, "❌ خطا در افزایش تعداد کاربر. لطفاً دوباره تلاش کنید.", None

# ➖ منطق مشترک «کاهش تعداد کاربر مجاز» — دقیقاً برعکس تابع بالا؛ اگر نماینده باشد، مبلغ
# متناسب با کاربرهای کم‌شده (به‌نسبت روزهای باقی‌ماندهٔ اکانت) به کیف‌پولش بازگردانده می‌شود.
async def _apply_user_limit_decrease(context, role, ag_id, un, new_limit):
    cur = await asyncio.to_thread(_db_get_user, un)
    if not cur:
        return False, "❌ این کاربر دیگر وجود ندارد."
    if not _can_manage_user(role, ag_id, cur[5]):
        return False, "⛔️ شما مجاز به مدیریت این اکانت نیستید."
    cur_limit = cur[3]
    if new_limit >= cur_limit:
        return False, f"❌ عدد جدید باید کوچک‌تر از تعداد فعلی ({cur_limit}) باشد."
    if new_limit < 1:
        return False, "❌ تعداد کاربر مجاز نمی‌تواند کمتر از ۱ باشد."
    removed_users = cur_limit - new_limit
    try:
        refund = 0.0
        refund_dec = Decimal("0")
        if role == 'agent':
            ainf = await asyncio.to_thread(_db_get_agent_info, ag_id)
            if not ainf:
                return False, "❌ خطا: اطلاعات نمایندگی شما یافت نشد."
            rem_days = (datetime.strptime(cur[1], "%Y-%m-%d").date() - datetime.now().date()).days
            rem_months = max(1, -(-max(rem_days, 1) // 30))  # سقف تقسیم (ceil) — همان روش محاسبهٔ افزایش
            base_price_dec = _parse_price_to_decimal(ainf[4])
            refund_dec = base_price_dec * Decimal(removed_users) * Decimal(rem_months)
            refund = float(refund_dec)

        await asyncio.to_thread(_db_update_users_limit, un, new_limit)
        await _sync_user_limit_file(un, new_limit)  # 🆕 فایل سقف اتصال PAM هم‌زمان با تغییر عدد به‌روز می‌شود

        if role == 'agent':
            emergency_repaid = 0.0
            with db_conn() as conn:
                conn.execute("UPDATE agents SET balance = balance + ? WHERE id=?", (refund, ag_id))
                if refund > 0:
                    used_before_row = conn.execute("SELECT emergency_used FROM agents WHERE id=?", (ag_id,)).fetchone()
                    used_before = (used_before_row[0] or 0.0) if used_before_row else 0.0
                    _apply_emergency_repayment(conn, ag_id, refund)
                    emergency_repaid = min(used_before, refund) if used_before > 0 else 0.0
            msg = f"✅ تعداد کاربر مجاز اکانت {esc(un)} از {cur_limit} به {new_limit} کاهش یافت.\n💰 مبلغ بازگردانده‌شده به کیف‌پول: {int(refund):,} تومان"
            if emergency_repaid > 0:
                msg += f"\n🆘 از همین مبلغ، {int(emergency_repaid):,} تومان بدهیِ شارژ اضطراری نیز پاک شد."
            return True, msg
        else:
            return True, f"✅ تعداد کاربر مجاز اکانت {esc(un)} از {cur_limit} به {new_limit} کاهش یافت."
    except Exception:
        log.exception("خطا در کاهش تعداد کاربر مجاز اکانت %s", un)
        return False, "❌ خطا در کاهش تعداد کاربر. لطفاً دوباره تلاش کنید."

# ==========================================
# 📦 ساخت اکانت عمده (Bulk) — همان منطق گام‌به‌گامِ ساخت تکی (رزرو اتمیک یوزرنیم → useradd →
# chpasswd → ثبت نهایی دیتابیس → کسر کیف‌پول/کمیسیون) به‌ازای هرکدام از اکانت‌های درخواستی
# تکرار می‌شود، با این تفاوت‌ها:
#   • قبل از شروع، در صورت نمایندگی، مجموع هزینهٔ کل دسته یک‌جا چک می‌شود تا نماینده وسط کار
#     با موجودی ناکافی متوقف نشود.
#   • شمارندهٔ یوزرنیم (c) بین اکانت‌های ساخته‌شده به‌درستی و پیوسته جلو می‌رود (خروجی هر
#     رزرو، ورودی رزرو بعدی است) تا هیچ برخورد/تکراری رخ ندهد.
#   • اگر ساخت یکی از اکانت‌ها در وسط کار شکست بخورد، عملیات همان‌جا متوقف می‌شود؛ اکانت‌های
#     قبلی که قبلاً با موفقیت کامل ساخته شده‌اند دست‌نخورده باقی می‌مانند (Rollback فقط برای
#     همان اکانتِ درحال ساخت انجام می‌شود) و گزارش نهایی هم موفق‌ها و هم خطای توقف را نشان می‌دهد.
# ==========================================
async def _handle_bulk_purchase(query, context, role, ag_id):
    if context.user_data.get('purchase_in_progress'):
        await query.message.reply_text("⏳ درخواست قبلی هنوز در حال پردازش است؛ چند لحظه صبر کنید.")
        return
    context.user_data['purchase_in_progress'] = True
    try:
        m = context.user_data.get('months')
        u = context.user_data.get('users')
        count = context.user_data.get('bulk_count')
        if not m or not u or not count:
            await query.message.reply_text("❌ تراکنش منقضی شده است.")
            return
        # 🆕 حالت اتصال انتخاب‌شده (همان دکمهٔ «حالت اتصال» روی صفحهٔ تاییدیه، برای ساخت عمده هم مشترک است)
        chosen_conn_mode = context.user_data.get('conn_mode', 'direct')

        ainf = None
        cost_per = 0.0
        retail_per_dec = Decimal("0")
        if role == 'agent':
            ainf = await asyncio.to_thread(_db_get_agent_info, ag_id)
            if not ainf:
                await query.edit_message_text("❌ خطا: اطلاعات نمایندگی شما یافت نشد. لطفاً دوباره وارد شوید.")
                return
            base_price_dec = _parse_price_to_decimal(ainf[4])
            retail_per_dec = base_price_dec * Decimal(m) * Decimal(u)
            cost_per = float(retail_per_dec)
            total_cost = cost_per * count
            if ainf[2] < total_cost and not context.user_data.get('emergency_approved'):
                has_opt, remaining_em, shortfall, used_em, req_cnt = _check_emergency_option(ainf, total_cost)
                can_use_em, active_count = _agent_can_use_emergency_credit(ag_id)
                if has_opt and can_use_em:
                    kb_em = [[InlineKeyboardButton("🆘 استفاده از شارژ اضطراری", callback_data="buy_emergency_yes")],
                             [InlineKeyboardButton("↩️ انصراف", callback_data="buy_no")]]
                    await query.edit_message_text(
                        f"❌ <b>موجودی ناکافی!</b>\n\n💰 موجودی شما: {int(ainf[2]):,} تومان\n"
                        f"💳 هزینهٔ ساخت {count} اکانت: {int(total_cost):,} تومان\n\n"
                        f"🆘 می‌توانید از <b>شارژ اضطراری</b> استفاده کنید (سقف کل: {int(EMERGENCY_CREDIT_LIMIT):,} تومان، "
                        f"باقی‌ماندهٔ شما: {int(remaining_em):,} تومان). این مبلغ در اولین شارژ بعدی حساب شما به‌طور خودکار کسر می‌شود.",
                        reply_markup=InlineKeyboardMarkup(kb_em), parse_mode="HTML")
                    context.user_data['_skip_purchase_clear'] = True
                    return
                extra = ""
                if req_cnt >= EMERGENCY_MAX_CONSECUTIVE_REQUESTS:
                    extra = "\n\n🆘 سقف درخواست‌های پیاپی شارژ اضطراری (۲ بار) شما پر شده؛ لطفاً منتظر شارژ حساب توسط مدیریت بمانید."
                elif used_em > 0:
                    extra = f"\n\n🆘 شارژ اضطراری باقی‌ماندهٔ شما ({int(remaining_em):,} تومان) برای این خرید کافی نیست."
                await query.edit_message_text(
                    f"❌ <b>موجودی ناکافی!</b>\n\n💰 موجودی شما: {int(ainf[2]):,} تومان\n"
                    f"💳 هزینهٔ ساخت {count} اکانت: {int(total_cost):,} تومان\n\n"
                    f"لطفاً از منوی اصلی ابتدا حساب خود را شارژ کنید.{extra}", parse_mode="HTML")
                return

        br = _resolve_username_prefix(role, ainf)
        if br is None:
            br = (await asyncio.to_thread(_db_get_setting, 'brand', 'NeVeL')).lower().strip()
            br = re.sub(r'[^a-z0-9]', '', br) or "nevel"
        c_start = await asyncio.to_thread(_db_get_prefix_start_counter, br)

        with contextlib.suppress(Exception):
            await query.edit_message_text(f"⏳ در حال ساخت {count} اکانت... لطفاً صبر کنید (ممکن است چند لحظه طول بکشد).")

        # 🌐 اطلاعات هاست/پورت پیش از شروع حلقه خوانده می‌شود تا برای فاکتور جداگانهٔ هر اکانت
        # (که بلافاصله بعد از ساخته‌شدنش ارسال می‌شود) در دسترس باشد.
        hl = [h.strip() for h in (await asyncio.to_thread(_db_get_setting, 'hosts', LAST_RESORT_HOST_IP)).split(',') if h.strip()]
        prt = await asyncio.to_thread(_db_get_setting, 'port', '22')
        primary_host = hl[0] if hl else _hosts_fallback_with_warning()

        MAX_OS_RETRIES = 500
        created = []  # [(username, password), ...]
        failed_msg = None
        c = c_start - 1  # اولین رزرو با c_start انجام می‌شود، رزروهای بعدی از خروجی رزرو قبلی ادامه می‌یابند

        # Edge فقط endpoint عمومی این دسته است؛ Linux userها در توپولوژی Relay روی Core ساخته می‌شوند.
        # همهٔ اکانت‌های همین دسته یک endpoint مشترک می‌گیرند تا خروجی/مدیریت آن‌ها یکدست بماند.
        target_host = await asyncio.to_thread(_pick_target_host_for_new_account)
        target_port = await asyncio.to_thread(_db_get_host_ssh_port, target_host, 22)

        for i in range(count):
            # گام ۱: رزرو اتمیک یوزرنیم
            un, c = await asyncio.to_thread(_db_reserve_username, br, c + 1)
            if un is None:
                failed_msg = "❌ خطا: امکان یافتن یوزرنیم آزاد وجود ندارد."
                break

            os_retries = 0
            while await _os_user_exists(un, target_host, target_port) and os_retries < MAX_OS_RETRIES:
                await asyncio.to_thread(_db_cancel_reservation, un)
                un, c = await asyncio.to_thread(_db_reserve_username, br, c + 1)
                if un is None:
                    failed_msg = "❌ خطا: امکان یافتن یوزرنیم آزاد وجود ندارد."
                    break
                os_retries += 1
            if un is None:
                break

            pw = "".join(random.choices(string.digits, k=5))
            now = datetime.now(); exp_days = m * 30
            # 🆕 آنهولد پنهان (V88): استفاده از ماژول متمرکز
            hold_sched = await asyncio.to_thread(_prepare_hidden_hold_for_new_account, un, exp_days)
            os_exp_db = hold_sched.linux_expire_date
            exp_db, cr_db = hold_sched.visible_expire_date, now.strftime("%Y-%m-%d")

            # گام ۲: ساخت کاربر لینوکسی روی Core (endpoint انتخاب‌شده فقط metadata/routing است).
            useradd_retries = 0
            ok_created = False
            while True:
                ok1, err1, kind1 = await run_cmd("sudo", "useradd", "-s", "/bin/false", "-e", os_exp_db, un)
                if ok1:
                    ok_created = True
                    break
                is_duplicate = "already exists" in (err1 or "").lower()
                if is_duplicate and useradd_retries < MAX_OS_RETRIES:
                    log.warning("useradd (bulk) برای %s با «already exists» شکست خورد؛ تلاش با یوزرنیم بعدی...", un)
                    await asyncio.to_thread(_db_cancel_reservation, un)
                    un, c = await asyncio.to_thread(_db_reserve_username, br, c + 1)
                    if un is None:
                        failed_msg = "❌ خطا: امکان یافتن یوزرنیم آزاد وجود ندارد."
                        break
                    useradd_retries += 1
                    continue
                await asyncio.to_thread(_db_cancel_reservation, un)
                log.error("ساخت اکانت bulk %s شکست خورد در مرحله useradd؛ رزرو دیتابیس لغو شد.", un)
                failed_msg = _fmt_linux_error("ساخت کاربر لینوکسی", err1, kind1)
                break
            if not ok_created:
                break

            # گام ۳: تنظیم پسورد لینوکسی
            ok2, err2, kind2 = await run_cmd("sudo", "chpasswd", input_data=f"{un}:{pw}\n".encode())
            if not ok2:
                ok_del, err_del, _ = await run_cmd("sudo", "userdel", "-f", un)
                await asyncio.to_thread(_db_cancel_reservation, un)
                if not ok_del:
                    log.error("Rollback ناقص برای %s (bulk): userdel شکست خورد: %s", un, err_del)
                failed_msg = _fmt_linux_error("تنظیم پسورد", err2, kind2)
                break

            # گام ۴: تکمیل نهایی رکورد دیتابیس
            try:
                await asyncio.to_thread(_db_finalize_reserved_user, un, pw, exp_db, cr_db, u, str(c + 1).zfill(4), br, ag_id, chosen_conn_mode, hold_sched.hold_deadline, exp_days)
                await asyncio.to_thread(_db_set_account_host, un, target_host)  # 🆕 ثبتِ Edgeِ صاحبِ این اکانت
            except Exception:
                log.exception("خطا در ثبت نهایی اکانت bulk %s در دیتابیس؛ کاربر لینوکسی حذف می‌شود (Rollback).", un)
                await run_cmd("sudo", "userdel", "-f", un)
                await asyncio.to_thread(_db_cancel_reservation, un)
                failed_msg = "❌ خطا در ثبت نهایی اکانت در دیتابیس."
                break

            log.info("اکانت bulk %s با موفقیت ساخته شد (%d/%d) — نماینده: %s.", un, i + 1, count, ag_id if role == 'agent' else 'ادمین')
            await _sync_user_limit_file(un, u)  # فایل سقف اتصال PAM روی Core نوشته می‌شود

            # 🛡️ شمارندهٔ صرفاً‌افزایشیِ «کل فروش تابه‌حال» (مبنای کش‌بک) — مستقل از کسر کیف‌پول
            # زیر ثبت می‌شود تا حتی اگر آن مرحله بعداً خطا داد، این عدد به‌درستی افزایش یافته باشد.
            if role == 'agent':
                with contextlib.suppress(Exception):
                    await asyncio.to_thread(_db_increment_lifetime_sold, ag_id)

            # گام ۵: کسر هزینهٔ همین اکانت از کیف‌پول نماینده و توزیع کمیسیون (خطای احتمالی اینجا اکانت را باطل نمی‌کند)
            if role == 'agent':
                try:
                    with db_conn() as conn: conn.execute("UPDATE agents SET balance = balance - ? WHERE id=?", (cost_per, ag_id))
                    await asyncio.to_thread(_db_distribute_commission, ag_id, retail_per_dec)
                    # 🎁 کش‌بک ترغیبی نمایندگان پرفروش (۵۰+ اکانت فعال): ۷٪ از هزینهٔ همین اکانت
                    await _apply_agent_cashback_if_eligible(ag_id, retail_per_dec)
                    # 🆘 اگر این خرید با کمک شارژ اضطراری تکمیل شد، مصرف ثبت می‌شود
                    emergency_shortfall = max(0.0, cost_per - ainf[2])
                    if emergency_shortfall > 0:
                        await asyncio.to_thread(_db_agent_register_emergency_use, ag_id, emergency_shortfall)
                except Exception:
                    log.exception("خطا در کسر کیف‌پول/توزیع کمیسیون برای اکانت bulk %s (اکانت ساخته‌شده باقی می‌ماند).", un)

            created.append((un, pw))

            # 🧾 برخلاف نسخهٔ قبلی (که یک پیامِ خلاصه با فهرست یوزرنیم/پسورد همهٔ اکانت‌ها می‌فرستاد)،
            # طبق الگوی درخواستی، هر اکانت بلافاصله بعد از ساخته‌شدن به‌صورت یک فاکتور کامل و
            # مستقل (دقیقاً مثل فاکتور خرید تکی) در یک پیام جداگانه ارسال می‌شود.
            # 🔧 به‌جای ساخت دستیِ متن فاکتور اینجا، از همان _build_invoice_text مرکزی استفاده
            # می‌شود که برای حالت conn_mode='tls' هم دامنهٔ TLS را به‌جای IP خام نشان می‌دهد.
            invoice_txt = await _build_invoice_text(un)
            if invoice_txt is None:
                continue
            # 🆕 طبق درخواست: دکمهٔ «دریافت کد نپسترنت» بلافاصله زیر فاکتور همین اکانت (نه فقط
            # در انتهای دسته) قرار می‌گیرد تا نیازی به رفتن به لیست کاربران نباشد.
            bulk_inv_kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔗 دریافت کد نپسترنت", callback_data=f"uact_niinv_{un}")]])
            with contextlib.suppress(Exception):
                await context.bot.send_message(chat_id=query.message.chat_id, text=invoice_txt, parse_mode="HTML", reply_markup=bulk_inv_kb)


        # 🧾 گزارش نهایی کوتاه — تعداد اکانت‌های واقعاً ساخته‌شده (فاکتور کامل هرکدام قبلاً
        # به‌صورت پیام جداگانه ارسال شده) به‌همراه هزینهٔ کسرشده و آخرین خطا (در صورت توقف زودهنگام).
        if not created:
            err_txt = failed_msg or "❌ هیچ اکانتی ساخته نشد."
            with contextlib.suppress(Exception):
                await context.bot.send_message(chat_id=query.message.chat_id, text=err_txt, parse_mode="HTML")
            return

        summary = f"✅ <b>{len(created)} از {count} اکانت با موفقیت ساخته شد.</b>"
        if role == 'agent':
            actual_charged = cost_per * len(created)
            summary += f"\n💳 مجموع هزینهٔ کسرشده: {int(actual_charged):,} تومان"
            # 🆘 اگر بخشی/همهٔ این خرید عمده با شارژ اضطراری تکمیل شد، مصرف ثبت و به ادمین‌ها اطلاع داده می‌شود
            emergency_shortfall = max(0.0, actual_charged - ainf[2])
            if emergency_shortfall > 0:
                await asyncio.to_thread(_db_agent_register_emergency_use, ag_id, emergency_shortfall)
                summary += f"\n🆘 از این مبلغ، {int(emergency_shortfall):,} تومان از شارژ اضطراری تامین شد."
                with contextlib.suppress(Exception):
                    await _notify_admins(context.application,
                        f"🆘 <b>استفاده از شارژ اضطراری</b>\nنمایندهٔ «{esc(ainf[0])}» برای ساخت عمدهٔ {len(created)} اکانت "
                        f"مبلغ {int(emergency_shortfall):,} تومان از شارژ اضطراری استفاده کرد.")
        if failed_msg:
            summary += f"\n\n⚠️ ساخت در همین‌جا متوقف شد؛ آخرین خطا:\n{failed_msg}"
        with contextlib.suppress(Exception):
            await context.bot.send_message(chat_id=query.message.chat_id, text=summary, parse_mode="HTML")
    except Exception:
        log.exception("خطای پیش‌بینی‌نشده در فرآیند ساخت اکانت عمده (bulk)")
        with contextlib.suppress(Exception):
            await context.bot.send_message(chat_id=query.message.chat_id, text="❌ خطای غیرمنتظره‌ای در فرآیند ساخت عمده رخ داد. لطفاً لاگ سرور را بررسی کنید.")
    finally:
        if context.user_data.pop('_skip_purchase_clear', False):
            context.user_data['purchase_in_progress'] = False
        else:
            safe_clear_context(context)


    # ==========================================
# 📝 هندلر اصلی پیام‌های متنی (و منوها)
# ==========================================
async def text_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text
    if not text: return
    state = context.user_data.get('state')
    role = context.user_data.get('role')
    chat_id = update.effective_chat.id

    # --- دستور مخفی ادمین برای فعال‌سازی همه اینباندها (از جمله REALITY) برای کاربران V2Ray فعلی ---
    if text == 'v2ray_upgrade_inbounds' and role == 'admin':
        await update.message.reply_text("⏳ در حال ارتقای اینباندهای V2Ray (این عملیات ممکن است چند دقیقه طول بکشد)...")
        
        m_url = await asyncio.to_thread(_db_get_setting, 'marzban_url', '')
        m_user = await asyncio.to_thread(_db_get_setting, 'marzban_username', '')
        m_pwd = await asyncio.to_thread(_db_get_setting, 'marzban_password', '')
        
        with db_conn() as conn:
            v2_users = conn.execute("SELECT username FROM ssh_accounts WHERE service_type IN ('v2ray', 'v2ray_vol')").fetchall()
        
        # بدون تغییر در پروکسی‌ها (مرزبان خودش حفظشان می‌کند)
        new_proxies = None 
        
        # بر اساس فایل جیسون شما، این نام دقیق اینباندهاست
        new_inbounds = {
            "vless": [
                "VLESS TCP REALITY",
                "VLESS TCP HTTP"
            ],
            "vmess": [
                "VMess WS"
            ],
            "trojan": [
                "Trojan WS"
            ],
            "shadowsocks": [
                "Shadowsocks TCP"
            ]
        }
        
        success_count = 0
        for (un,) in v2_users:
            # ارسال صریح inbounds برای بازنویسی کامل تنظیمات قبلی
            ok, _ = await v2ray_engine.modify_user(m_url, m_user, m_pwd, un, inbounds=new_inbounds)
            if ok:
                success_count += 1
            await asyncio.sleep(0.3)
            
        await update.message.reply_text(f"✅ ارتقای کاربران پایان یافت.\n{success_count} کاربر از مجموع {len(v2_users)} کاربر V2Ray با موفقیت آپدیت شدند و دسترسی به تمام اینباندها (از جمله VLESS TCP REALITY) برایشان فعال شد.")
        return
    # --- دستور مخفی ادمین برای آپدیت خودکار پورت TLS روی سرورهای Edge ---
    if text == 'tlstoedge' and role == 'admin':
        await update.message.reply_text("⏳ در حال انتقال دامنه به سرور Edge (رله فعال) و تنظیم پورت‌ها...")
        
        async def _set_domain_to_edge():
            # ۱. گرفتن لیست تمام آی‌پی‌های فعال و آی‌پی Core
            active_edges = await asyncio.to_thread(_db_get_active_hosts_from_pool)
            core_ip_raw = await asyncio.to_thread(_get_core_public_ip_cached)
            core_ip = str(core_ip_raw).strip() if core_ip_raw else ""
            
            # 🔴 فیلتر حیاتی و رفع باگ: با استفاده از strip آی‌پی Core را قطعی حذف می‌کنیم
            real_edges = [str(h).strip() for h in active_edges if str(h).strip() != core_ip]
            if not real_edges:
                await context.bot.send_message(chat_id, "❌ هیچ سرور Edge (غیر از Core) در دیتابیس یافت نشد.")
                return

            # ۲. پیدا کردن Edge دیفالت
            default_edge_raw = await asyncio.to_thread(_db_get_default_host)
            default_edge = str(default_edge_raw).strip() if default_edge_raw else None
            
            # اگر به خاطر باگ قبلی دیفالت روی Core ست شده بود، اون رو نادیده می‌گیریم
            if default_edge == core_ip: 
                default_edge = None 
                
            active_edge_ip = default_edge if default_edge else real_edges[0]

            # ۳. آپدیت کلودفلر (انتقال دامنه به Edge)
            await asyncio.to_thread(_db_update_setting, 'tls_passthrough', '1') # روشن کردن فلگ
            cf_ok, cf_msg = await asyncio.to_thread(_cf_update_dns_record_sync, active_edge_ip)
            
            if cf_ok:
                await asyncio.to_thread(_db_set_default_host, active_edge_ip) # ثبت در دیتابیس
                await asyncio.to_thread(_db_update_setting, "dns_current_ip", active_edge_ip)
                await context.bot.send_message(chat_id, f"✅ <b>دامنه با موفقیت به Edge فعال منتقل شد!</b>\nآی‌پی: <code>{esc(active_edge_ip)}</code>", parse_mode="HTML")
            else:
                await context.bot.send_message(chat_id, f"❌ خطا در انتقال دامنه روی کلودفلر:\n<code>{esc(cf_msg)}</code>", parse_mode="HTML")
                return

            # ۴. آپدیت iptables روی Edge فعال
            tls_port = await asyncio.to_thread(_db_get_setting, 'tls_port', '2088')
            port_map = await asyncio.to_thread(_db_get_host_ssh_port_map)
            ssh_port = port_map.get(active_edge_ip, 22)
            
            try:
                def _run_iptables():
                    ssh = None
                    try:
                        ssh = paramiko.SSHClient()
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        pkey = paramiko.Ed25519Key.from_private_key_file(DO_SSH_KEY_PATH)
                        ssh.connect(active_edge_ip, port=ssh_port, username='root', pkey=pkey, timeout=15)
                        cmd = (
                            f"iptables -t nat -C PREROUTING -p tcp --dport {tls_port} -j DNAT --to-destination 10.77.0.1:{tls_port} 2>/dev/null || "
                            f"iptables -t nat -A PREROUTING -p tcp --dport {tls_port} -j DNAT --to-destination 10.77.0.1:{tls_port} ; "
                            "(command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1) || iptables-save > /etc/iptables/rules.v4"
                        )
                        ssh.exec_command(cmd, timeout=20)
                    finally:
                        if ssh is not None:
                            try:
                                ssh.close()
                            except Exception:
                                pass
                await asyncio.to_thread(_run_iptables)
                await context.bot.send_message(chat_id, "✅ تنظیمات پورت (NAT) روی Edge فعال اعمال شد.")
            except Exception as e:
                await context.bot.send_message(chat_id, f"⚠️ دامنه منتقل شد اما خطای SSH در تنظیم پورت Edge رخ داد:\n<code>{esc(str(e))}</code>", parse_mode="HTML")

        spawn_bg_task(_set_domain_to_edge())
        return
    
    # --- دستور مخفی ادمین برای روشن/خاموش کردن رول‌بک TLS ---
    elif text == 'clfch' and role == 'admin':
        cur_flag = await asyncio.to_thread(_db_get_setting, 'tls_passthrough', '1')
        new_flag = '0' if cur_flag == '1' else '1'
        await asyncio.to_thread(_db_update_setting, 'tls_passthrough', new_flag)

        core_ip_raw = await asyncio.to_thread(_get_core_public_ip_cached)
        core_ip = str(core_ip_raw).strip() if core_ip_raw else ""
        
        if new_flag == '0':
            target_ip = core_ip
            mode_txt = "مستقیم به Core (حالت اضطراری، بدون رلهٔ Edge)"
        else:
            default_edge_raw = await asyncio.to_thread(_db_get_default_host)
            default_edge = str(default_edge_raw).strip() if default_edge_raw else None
            
            active_edges = await asyncio.to_thread(_db_get_active_hosts_from_pool)
            real_edges = [str(h).strip() for h in active_edges if str(h).strip() != core_ip]
            
            # 🔴 جلوگیری قطعی از انتخاب مجدد Core
            if default_edge == core_ip: 
                default_edge = None
                
            target_ip = default_edge or next((h for h in real_edges), None)
            mode_txt = "رلهٔ Edge فعال (حالت عادی)"

        if not target_ip:
            await update.message.reply_text(
                f"❌ فلگ tls_passthrough به «{new_flag}» تغییر کرد، ولی IP مقصدی برای سوییچ پیدا نشد (احتمالاً Edge فعالی غیر از Core وجود ندارد).")
            return

        await update.message.reply_text(
            f"⏳ در حال سوییچ اضطراری دامنه به «{mode_txt}» (<code>{esc(target_ip)}</code>)...",
            parse_mode="HTML")
        
        cf_ok, cf_msg = await asyncio.to_thread(_cf_update_dns_record_sync, target_ip)
        
        if cf_ok:
            await asyncio.to_thread(_db_update_setting, "dns_current_ip", target_ip)
            if new_flag != '0':
                await asyncio.to_thread(_db_set_default_host, target_ip)
            await update.message.reply_text(f"✅ دامنه به حالت «{mode_txt}» سوییچ شد.", parse_mode="HTML")
        else:
            await update.message.reply_text(f"❌ سوییچ دامنه شکست خورد:\n<code>{esc(cf_msg)}</code>", parse_mode="HTML")
        return
    

    # 🛡 گارد منوها
    main_menus = ['🛒 خرید اشتراک', '👥 مدیریت کاربران', '💼 مدیریت نماینده‌ها', '📊 آمار و لاگ', '💳 تنظیمات مالی', '⚙️ تنظیمات سرور', '🛠 مدیریت V2Ray', '📦 دریافت بکاپ', '💳 شارژ حساب (کارت به کارت)', '📊 اطلاعات حساب', '✏️ تغییر نام برند', '❌ خروج', '👑 تنظیمات سوپر ادمین', '📊 خروجی مالی امروز (اکسل)', '📅 خروجی مالی این هفته (اکسل)', '👑 آمار فروش ادمین']
    
    # 🚨 گارد اجباری بودن برند نماینده (بررسی مستقیم از دیتابیس)
    if is_auth(context) and role == 'agent':
        ag_info = await asyncio.to_thread(_db_get_agent_info, context.user_data.get('agent_id', 0))
        if ag_info and not ag_info[10]:  # ایندکس 10 مربوط به username_prefix است
            allowed_texts = ['✏️ تغییر نام برند', '❌ خروج']
            if text not in allowed_texts and state != 'AGENT_SELF_PREFIX_INPUT':
                safe_clear_context(context)
                await update.message.reply_text(
                    "⛔️ <b>کاربر گرامی، ابتدا باید نام برند اختصاصی خود را تعیین کنید.</b>\n\n"
                    "جهت استقلال و تفکیک اکانت‌های شما، داشتن یک نام برند اجباری است (مثلاً: <b>AliVpn</b>). "
                    "لطفاً از منوی پایین روی دکمه «✏️ تغییر نام برند» کلیک کنید.", 
                    parse_mode="HTML"
                )
                return

    if text in main_menus and is_auth(context):
        safe_clear_context(context)
        if text == '👑 تنظیمات سوپر ادمین' and chat_id == SUPER_ADMIN_ID:
            kb = [[InlineKeyboardButton("📊 فعالیت‌های سیستم (ادمین)", callback_data="super_admin_stats")],
                  [InlineKeyboardButton("💼 سوابق مالی نمایندگان", callback_data="super_agent_list")],
                  [InlineKeyboardButton("⚙️ مدیریت فروش سرویس‌ها", callback_data="super_admin_sales_manage")],
                  [InlineKeyboardButton("👥 مدیریت کاربران و ادمین‌های ربات", callback_data="super_admin_users_menu")],
                  [InlineKeyboardButton("🔙 بستن", callback_data="uact_back_to_menu")]]
            await update.message.reply_text("👑 <b>پنل تنظیمات اختصاصی سوپر ادمین</b>\n\nبخش مورد نظر را انتخاب کنید:", reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
            return
        elif role == 'accountant':
            if text == '📊 خروجی مالی امروز (اکسل)':
                await update.message.reply_text("⏳ در حال استخراج دیتابیس مالی امروز...")
                csv_bytes = await _generate_accounting_csv(days=1)
                await update.message.reply_document(document=InputFile(io.BytesIO(csv_bytes), filename=f"Daily_Accounting_{datetime.now().strftime('%Y-%m-%d')}.csv"), caption="📊 <b>گزارش مالی ۲۴ ساعت گذشته</b>\nشامل میزان فروش، شارژهای دستی و واریزی‌های تاییدشده.", parse_mode="HTML")
                return
            elif text == '📅 خروجی مالی این هفته (اکسل)':
                await update.message.reply_text("⏳ در حال استخراج دیتابیس مالی ۷ روز گذشته...")
                csv_bytes = await _generate_accounting_csv(days=7)
                await update.message.reply_document(document=InputFile(io.BytesIO(csv_bytes), filename=f"Weekly_Accounting_{datetime.now().strftime('%Y-%m-%d')}.csv"), caption="📅 <b>گزارش مالی ۷ روز گذشته</b>\nشامل میزان فروش، شارژهای دستی و واریزی‌های تاییدشده.", parse_mode="HTML")
                return
            elif text == '👑 آمار فروش ادمین':
                cr_tdy, cr_yest, cr_wk, cr_mo, rn_tdy, rn_yest, rn_wk, rn_mo, rn_lmo = await asyncio.to_thread(_get_super_admin_stats, None)
                txt = (f"👑 <b>فعالیت‌های سیستم (توسط شخص ادمین)</b>\n\n"
                       f"🆕 <b>ساخت اکانت:</b>\n"
                       f"امروز: {cr_tdy} | دیروز: {cr_yest}\nاین هفته: {cr_wk} | این ماه (شمسی): {cr_mo}\n\n"
                       f"🔄 <b>تمدید اکانت:</b>\n"
                       f"امروز: {rn_tdy} | دیروز: {rn_yest}\nاین هفته: {rn_wk}\nاین ماه (شمسی): {rn_mo} | ماه گذشته: {rn_lmo}")
                await update.message.reply_text(txt, parse_mode="HTML")
                return
            
        elif text == '❌ خروج':
            # 🆕 قبل از خروج واقعی، تاییدیهٔ بله/خیر گرفته می‌شود (هم برای پنل ادمین و هم پنل نمایندگی،
            # چون هر دو نقش از همین مسیر مشترک عبور می‌کنند). خروج واقعی در callback_handler
            # (confirm_logout_yes/confirm_logout_no) انجام می‌شود.
            kb = [[InlineKeyboardButton("✅ بله، خارج شو", callback_data="confirm_logout_yes"),
                   InlineKeyboardButton("↩️ خیر، انصراف", callback_data="confirm_logout_no")]]
            await update.message.reply_text("⚠️ آیا مطمئن هستید که می‌خواهید از ربات خارج شوید؟", reply_markup=InlineKeyboardMarkup(kb))
            return
        elif text == '🛒 خرید اشتراک': await _show_buy_start(update, context); return
        elif text == '👥 مدیریت کاربران' and role in ('admin', 'agent'):
            context.user_data.pop('users_agent_filter', None)
            kb = [
                [InlineKeyboardButton("🔹 کاربران SSH", callback_data="umanage_ssh")],
                [InlineKeyboardButton("🚀 کاربران V2Ray (نامحدود)", callback_data="umanage_v2ray")],
                [InlineKeyboardButton("📦 کاربران V2Ray (حجمی)", callback_data="umanage_v2ray_vol")]
            ]
            await update.message.reply_text("👥 لطفاً بخش مورد نظر را انتخاب کنید:", reply_markup=InlineKeyboardMarkup(kb))
            return
        elif text == '💼 مدیریت نماینده‌ها' and role == 'admin':
            kb = [[InlineKeyboardButton("➕ افزودن نماینده جدید", callback_data="agm_add")], [InlineKeyboardButton("📋 لیست نمایندگان", callback_data="agm_list")],
                  [InlineKeyboardButton("📊 گزارش مالی نمایندگان", callback_data="agm_finlist")],
                  [InlineKeyboardButton("🔙 بازگشت", callback_data="uact_back_to_menu")]]
            await update.message.reply_text("💼 <b>پنل مدیریت نمایندگان فروش</b>", reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML"); return
        elif text in ['📊 اطلاعات حساب', '📊 آمار و لاگ']:
            kb = [[InlineKeyboardButton("📊 اطلاعات کلان و مالی", callback_data="info_general")], [InlineKeyboardButton("⚡️ مشاهده کاربران آنلاین", callback_data="info_online")]]
            if MATPLOTLIB_AVAILABLE and role == 'admin': kb.append([InlineKeyboardButton("📈 نمودار فروش ۷ روز گذشته", callback_data="info_chart")])
            kb.append([InlineKeyboardButton("🔙 بازگشت", callback_data="uact_back_to_menu")])
            await update.message.reply_text("📊 <b>پورتال گزارشات سیستم</b>", reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML"); return
        elif text == '⚙️ تنظیمات سرور' and role == 'admin':
            kb = _build_server_settings_kb()
            await update.message.reply_text("⚙️ <b>تنظیمات سرور</b>\nیکی از گزینه‌های زیر را انتخاب کنید:", reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML"); return
        elif text == '🛠 مدیریت V2Ray' and role == 'admin':
            await update.message.reply_text("⏳ در حال دریافت اطلاعات از nevel...")
            m_url = await asyncio.to_thread(_db_get_setting, 'marzban_url', '')
            m_user = await asyncio.to_thread(_db_get_setting, 'marzban_username', '')
            m_pwd = await asyncio.to_thread(_db_get_setting, 'marzban_password', '')
            ok, stats = await v2ray_engine.get_system_stats(m_url, m_user, m_pwd)
            if ok:
                mem = round(stats.get('mem_used', 0) / 1024**2, 1)
                txt = f"🛠 <b>وضعیت سرور V2Ray</b>\nCPU: {stats.get('cpu_usage',0):.1f}%\nRAM: {mem} MB\nکاربران فعال: {stats.get('users_active',0)}"
                await update.message.reply_text(txt, parse_mode="HTML")
            else:
                await update.message.reply_text(f"❌ خطا در اتصال به nevel: {stats}")
            return
        elif text == '⚙️ تغییر نام برند' and role == 'admin':
            await update.message.reply_text("✍️ لطفاً نام برند جدید خود را وارد نمایید:"); context.user_data['state'] = 'BRAND_INPUT'; return
        elif text == '✏️ تغییر نام برند' and role == 'agent':
            ag_id_local = context.user_data.get('agent_id', 0)
            info = await asyncio.to_thread(_db_get_agent_info, ag_id_local)
            my_prefix = info[10] if info and len(info) > 10 and info[10] else None
            prefix_line = f"<code>{esc(my_prefix)}</code>" if my_prefix else "تنظیم‌نشده ❌ (اجباری)"
            context.user_data['state'] = 'AGENT_SELF_PREFIX_INPUT'
            await update.message.reply_text(
                f"✏️ <b>تعیین / تغییر نام برند اختصاصی</b>\nوضعیت فعلی: {prefix_line}\n\n"
                f"نام برند دلخواه خود را بفرستید (فقط حروف و اعداد انگلیسی مجاز است، بدون فاصله. مثلاً: <b>AliVpn</b>).\n"
                f"تمامی اکانت‌های مشتریان شما از این پس با این نام ساخته خواهند شد (مثال: AliVpn0001).\n"
                f"💡 در آینده نیز هروقت بخواهید می‌توانید در همین بخش ، نام برندتان را به نام دیگری تغییر دهید.", parse_mode="HTML")
            return
        elif text == '🌐 تنظیمات هاست' and role == 'admin':
            ch = await asyncio.to_thread(_db_get_setting, 'hosts', LAST_RESORT_HOST_IP)
            kb = InlineKeyboardMarkup([[InlineKeyboardButton("➕ افزودن IP جدید (بدون حذف بقیه)", callback_data="srv_hosts_add")]])
            await update.message.reply_text(f"🌐 هاست فعلی:\n<code>{esc(ch)}</code>\n\n✍️ لیست جدید را با کاما (,) جدا کرده و بفرستید (کل لیست جایگزین می‌شود):", parse_mode="HTML", reply_markup=kb); context.user_data['state'] = 'HOSTS_INPUT'; return
        elif text == '💳 تنظیمات مالی' and role == 'admin':
            kb = InlineKeyboardMarkup([
                [InlineKeyboardButton("💳 شماره کارت مدیر", callback_data="fin_admin_card")],
                [InlineKeyboardButton("💳 شماره کارت نمایندگان", callback_data="fin_agents_1")]])
            await update.message.reply_text("💳 <b>تنظیمات مالی</b>\n\nکدام کارت را می‌خواهید مدیریت کنید؟", parse_mode="HTML", reply_markup=kb); return
        elif text == '📦 دریافت بکاپ' and role == 'admin':
            try:
                await update.message.reply_document(document=open(DB_PATH, 'rb'), filename=f"NeVeL_DB_{datetime.now().strftime('%Y%m%d')}.db", caption="📦 بکاپ دیتابیس")
                if os.path.exists("bot_operations.log"): await update.message.reply_document(document=open('bot_operations.log', 'rb'), filename="operations.log", caption="📝 فایل لاگ سرور")
            except Exception as e: await update.message.reply_text(f"❌ خطا در تهیه بکاپ: {e}")
            return
        elif text == '💳 شارژ حساب (کارت به کارت)' and role == 'agent':
            kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="uact_back_to_menu")]])
            await update.message.reply_text("💰 لطفاً مبلغی که قصد واریز دارید را به تومان وارد کنید (فقط عدد):", reply_markup=kb)
            context.user_data['state'] = 'C2C_AMOUNT'; return
        # 🆕 «کارت اختصاصی من» — فقط برای نماینده‌ای که ادمین صراحتاً مجوزش را صادر کرده باشد.
        # حتی اگه کسی با ترفند همین متن رو دستی بفرسته، این چک دیتابیسی جلوی سوءاستفاده رو می‌گیره
        # (دفاع دوم، مستقل از مخفی‌بودن دکمه توی کیبورد).
        elif text == '💳 کارت اختصاصی من' and role == 'agent':
            ag_id = context.user_data.get('agent_id', 0)
            if not ag_id or not await asyncio.to_thread(_db_get_agent_card_permission, ag_id):
                await update.message.reply_text("❌ شما مجوز استفاده از این بخش را ندارید."); return
            card_row = await asyncio.to_thread(_db_get_agent_card, ag_id)
            if card_row and card_row[0]:
                status_txt = f"💳 کارت فعلی شما:\n<code>{esc(card_row[0])}</code>\n👤 {esc(card_row[1] or '')}"
                kb = InlineKeyboardMarkup([
                    [InlineKeyboardButton("✏️ ویرایش کارت", callback_data="agself_card_set")],
                    [InlineKeyboardButton("🗑 حذف کارت من", callback_data="agself_card_clear")]])
            else:
                status_txt = "💳 شما هنوز کارت اختصاصی ثبت نکرده‌اید.\n\nتا وقتی کارتی ثبت نکنید، زیرمجموعه‌های شما همچنان کارت سیستم (یا کارت یکی از نمایندگان بالادستی‌تان، در صورت وجود) را می‌بینند."
                kb = InlineKeyboardMarkup([[InlineKeyboardButton("✏️ ثبت کارت من", callback_data="agself_card_set")]])
            await update.message.reply_text(status_txt, parse_mode="HTML", reply_markup=kb); return

    # 🔐 لاگین دو مرحله‌ای
    if not is_auth(context):
        locked_secs = _login_locked(chat_id)
        if locked_secs > 0:
            await update.message.reply_text(f"⛔️ ورود موقتاً قفل شده.\n⏳ لطفاً حدود {locked_secs//60 + 1} دقیقه دیگر تلاش کنید."); return
        
        if state == 'LOGIN_USER':
            context.user_data['login_username'] = text.strip(); context.user_data['state'] = 'LOGIN_PASS'
            await update.message.reply_text("🔑 حالا لطفاً رمز عبور (Password) خود را بفرستید:")
        elif state == 'LOGIN_PASS':
            u, p = context.user_data.get('login_username'), text.strip()
            if u == MASTER_USER and hmac.compare_digest(p, MASTER_PASS):
                _register_login_success(chat_id)
                
                # 👑 ارسال پیام به سوپر ادمین برای اطلاع‌رسانی ورود ادمین جدید
                if chat_id != SUPER_ADMIN_ID:
                    await _notify_super_admin(context.application, f"🔐 <b>ورود به حساب ادمین کل</b>\nیک کاربر با یوزرنیم و پسورد مدیریت وارد ربات شد.", tg_user=update.effective_user)

                # 🆕 به‌جای overwrite کردن یک chat_id تکی، این چت هم به لیست ادمین‌های فعال اضافه
                # می‌شود؛ به این ترتیب چند ادمین می‌توانند هم‌زمان با همان یوزرنیم/پسورد وارد شوند
                # و هرکدام هم‌زمان رسیدها/هشدارهای پایش ظرفیت را دریافت کنند.
                existing_admin_ids = await asyncio.to_thread(_db_get_admin_chat_ids)
                is_first_ever_login_for_this_chat = str(chat_id) not in {str(x) for x in existing_admin_ids}
                await asyncio.to_thread(_db_add_admin_chat_id, chat_id)
                if is_first_ever_login_for_this_chat:
                    # 🆕 طبق درخواست: ۱۰ دقیقه پس از اولین ورود این چت با یوزر/پس مدیریت، یک
                    # گزارش فروشِ خوش‌آمدگویی (امروز تا همین لحظه) فقط برای همین چت ارسال شود؛
                    # از همان شب اول، حلقهٔ همیشگیِ نیمه‌شب هم شامل این چت خواهد بود.
                    task = asyncio.create_task(_welcome_sales_report_delayed(context.application, chat_id))
                    context.application.bot_data.setdefault('welcome_report_tasks', []).append(task)
                context.user_data.update({'logged_in': True, 'role': 'admin', 'agent_id': 0, 'state': None})
                await update.message.reply_text(f"✅ <b>ورود موفق!</b>\nبه پنل {esc(PORTAL_DISPLAY_NAME)} خوش آمدید.", parse_mode="HTML"); await show_main_menu(update, context)
            else:
                agent = await asyncio.to_thread(_db_verify_agent, u, p)
                if agent:
                    _register_login_success(chat_id)
                    await asyncio.to_thread(_db_update_agent_field, agent[0], 'telegram_id', chat_id) # ذخیره آیدی نماینده
                    # 🆕 پاک کردن چت‌آیدی از لیست ادمین‌ها در صورت ورود به عنوان فروشنده
                    await asyncio.to_thread(_db_remove_admin_chat_id, chat_id)
                    context.user_data.update({'logged_in': True, 'role': 'agent', 'agent_id': agent[0], 'state': None})
                    await update.message.reply_text(
                        f"✅ <b>ورود موفق!</b>\nبه پنل فروش خوش آمدید.\n\n"
                        f"👤 کاربر نمایندهٔ «{esc(agent[1])}» با یوزرنیم <code>{esc(u)}</code> وارد شد.",
                        parse_mode="HTML"); await show_main_menu(update, context)
                else:
                    # 🔧 رفع درخواست کاربر: پیام خطا حالا مشخص می‌کند مشکل از نام کاربری است یا رمز عبور.
                    # اگر نام کاربری اصلاً وجود نداشته باشد (نه MASTER_USER و نه هیچ نماینده‌ای)،
                    # کاربر به مرحلهٔ وارد کردن نام کاربری برمی‌گردد. اگر نام کاربری معتبر بود ولی
                    # رمز اشتباه بود، همان مرحلهٔ رمز عبور تکرار می‌شود (بدون نیاز به تایپ دوبارهٔ یوزرنیم).
                    _register_login_failure(chat_id)
                    username_is_valid = (u == MASTER_USER) or await asyncio.to_thread(_db_agent_username_exists, u)
                    if username_is_valid:
                        await update.message.reply_text("❌ رمز عبور را اشتباه وارد کرده‌اید.\n\n🔑 لطفاً دوباره رمز عبور (Password) را بفرستید:")
                        context.user_data['state'] = 'LOGIN_PASS'
                    else:
                        await update.message.reply_text("❌ نام کاربری را اشتباه وارد کرده‌اید.\n\n👤 لطفاً دوباره نام کاربری (Username) را بفرستید:")
                        context.user_data['state'] = 'LOGIN_USER'
        else: await require_login(update); context.user_data['state'] = 'LOGIN_USER'
        return

    # 💼 ساخت و مدیریت نماینده
    if state == 'AGENT_NEW_USER':
        context.user_data['new_ag_u'] = text.strip(); context.user_data['state'] = 'AGENT_NEW_PASS'; await update.message.reply_text("🔑 رمز عبور نماینده را بفرست:"); return
    elif state == 'AGENT_NEW_PASS':
        context.user_data['new_ag_p'] = text.strip(); context.user_data['state'] = 'AGENT_NEW_NAME'; await update.message.reply_text("👤 نام نماینده را بفرست:"); return
    elif state == 'AGENT_NEW_NAME':
        context.user_data['new_ag_n'] = text.strip(); context.user_data['state'] = 'AGENT_NEW_REF'; await update.message.reply_text("🔗 **کد رفرال معرف** او را بفرست (یا عدد 0):"); return
    elif state == 'AGENT_NEW_REF':
        u, p, n, ref_input = (context.user_data.get('new_ag_u'), context.user_data.get('new_ag_p'), context.user_data.get('new_ag_n'), text.strip())
        parent_id = await asyncio.to_thread(_db_find_agent_by_ref, ref_input) if ref_input != "0" else 0
        success, ref = await asyncio.to_thread(_db_create_agent, u, p, n, parent_id)
        if success: 
            await update.message.reply_text(f"✅ <b>نماینده ساخته شد!</b>\nیوزرنیم: <code>{esc(u)}</code>\nپسورد: <code>{esc(p)}</code>\nکد معرف: <code>{esc(ref)}</code>", parse_mode="HTML")
            await _notify_super_admin(context.application, f"🆕 <b>تعریف نماینده جدید</b>\nنام: {esc(n)}\nیوزرنیم ورود: <code>{esc(u)}</code>", tg_user=update.effective_user)
        else: 
            await update.message.reply_text("❌ خطا: یوزرنیم تکراری است.")
        safe_clear_context(context); await show_main_menu(update, context); return
    elif state == 'AGENT_EDIT_PRICE':
        await asyncio.to_thread(_db_update_agent_field, context.user_data['edit_ag_id'], 'base_price', text.strip()); await update.message.reply_text("✅ آپدیت شد."); safe_clear_context(context); return
    elif state == 'AGENT_EDIT_PRICE_V2':
        await asyncio.to_thread(_db_update_agent_field, context.user_data['edit_ag_id'], 'v2ray_base_price', text.strip())
        await update.message.reply_text("✅ قیمت پایه V2Ray با موفقیت آپدیت شد.")
        safe_clear_context(context); return
    elif state == 'AGENT_EDIT_PRICE_V2_VOL':
        await asyncio.to_thread(_db_update_agent_field, context.user_data['edit_ag_id'], 'v2ray_vol_price', text.strip())
        await update.message.reply_text("✅ قیمت پایه V2Ray حجمی با موفقیت آپدیت شد.")
        safe_clear_context(context); return
    elif state == 'V2_VOL_CUSTOM_INPUT':
        val = fa_to_en_digits(text).strip()
        if not val.isdigit():
            await update.message.reply_text("❌ فقط عدد بفرستید:"); return
        gb = int(val)
        if not (10 <= gb <= 100):
            await update.message.reply_text("❌ حجم باید بین 10 تا 100 گیگ باشد. دوباره بفرستید:"); return
        context.user_data['v2_vol_gb'] = gb
        context.user_data['state'] = 'V2_VOL_CUSTOMER_NAME'
        kb = [[InlineKeyboardButton("🔙 بازگشت", callback_data="v2r_type_vol")]]
        await update.message.reply_text("👤 <b>مرحله بعد:</b>\nلطفاً نام مشتری (یا یک نشانه برای تشخیص این اکانت) را بفرستید:", reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
        return
    elif state == 'V2_VOL_CUSTOMER_NAME':
        context.user_data['v2_customer_name'] = text.strip()
        gb = context.user_data.get('v2_vol_gb')
        await _show_v2_vol_confirm(update.message, context, gb, role, context.user_data.get('agent_id', 0), is_edit=False)
        return
    elif state == 'V2_ADD_VOL_INPUT':
        val = fa_to_en_digits(text).strip()
        if not val.isdigit() or not (10 <= int(val) <= 100):
            return await update.message.reply_text("❌ فقط عدد بین 10 تا 100 گیگ بفرستید:")
        await _show_v2_addvol_confirm(update.message, context, int(val), role, context.user_data.get('agent_id', 0))
        return

    elif state == 'V2_CUSTOM_DAYS_INPUT':
        val = fa_to_en_digits(text).strip()
        if not val.isdigit() or not (1 <= int(val) <= 60):
            return await update.message.reply_text("❌ لطفاً یک عدد صحیح مثبت بین ۱ تا ۶۰ (تعداد روز) بفرستید:")
        
        days = int(val)
        context.user_data['v2_days'] = days
        u = context.user_data.get('v2_users', '1')
        
        cost_txt = ""
        if role == 'agent':
            ainf = await asyncio.to_thread(_db_get_agent_info, context.user_data.get('agent_id', 0))
            v2_bp = ainf[16] if ainf and len(ainf)>16 and ainf[16] else '160000'
            base_price_dec = _parse_price_to_decimal(v2_bp, Decimal("160000"))
            import math
            daily_price = float(base_price_dec) / 30.0
            retail_dec = Decimal(math.ceil(daily_price * days * int(u)))
            cost_txt = f"\n💳 هزینهٔ این خرید: {int(retail_dec):,} تومان"
            
        txt = f"🚀 <b>تایید ساخت اکانت V2Ray</b>\n\n📅 مدت اکانت: {days} روزه\n👥 تعداد کاربر: {u}{cost_txt}\n\nآیا از ساخت این اکانت مطمئن هستید؟"
        kb = [[InlineKeyboardButton("✅ بله، ساخته شود", callback_data="v2conf_yes")], [InlineKeyboardButton("❌ خیر، انصراف", callback_data="v2r_type_unlimit")]]
        await update.message.reply_text(txt, reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
        return

    elif state == 'V2_RENEW_DAYS_INPUT':
        val = fa_to_en_digits(text).strip()
        if not val.isdigit() or int(val) <= 0:
            return await update.message.reply_text("❌ لطفاً یک عدد صحیح مثبت (تعداد روز) بفرستید:")
        days = int(val)
        un = context.user_data.get('v2_renew_un')
        if not un: return await update.message.reply_text("❌ تراکنش منقضی شده است.")
        await _show_v2_renew_confirm(update.message, context, un, days)
        return
    elif state == 'V2_DEC_VOL_INPUT' and role == 'admin':
        val = fa_to_en_digits(text).strip()
        if not val.isdigit():
            return await update.message.reply_text("❌ فقط عدد بفرستید:")
        gb = int(val)
        un = context.user_data.get('v2_vol_un')
        if not un: return await update.message.reply_text("❌ تراکنش منقضی شده است.")
        context.user_data['v2_vol_dec_gb'] = gb
        kb = [
            [InlineKeyboardButton("✅ بله، کم شود", callback_data="v2decvol_conf_yes")],
            [InlineKeyboardButton("❌ خیر", callback_data=f"udet_{un}")]
        ]
        await update.message.reply_text(f"❓ آیا از کسر <b>{gb} گیگابایت</b> از حجم اکانت <code>{esc(un)}</code> مطمئن هستید؟", reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
        return
    elif state == 'AGENT_SELF_PREFIX_INPUT':
        my_ag_id = context.user_data.get('agent_id', 0)
        raw = text.strip()
        cleaned = re.sub(r'[^a-zA-Z0-9]', '', raw).lower()
        if not cleaned or cleaned == "0":
            await update.message.reply_text("❌ داشتن نام برند اختصاصی اجباری است و نمی‌تواند خالی یا 0 باشد. لطفاً یک نام معتبر (فقط حروف و اعداد انگلیسی، مثل: AliVpn) بفرستید:"); return
        await asyncio.to_thread(_db_set_agent_prefix, my_ag_id, cleaned)
        await update.message.reply_text(f"✅ عالی! از این پس یوزرنیم اکانت‌های شما با «{esc(cleaned)}» ساخته خواهد شد.\nدر آینده نیز هر زمان بخواهید می‌توانید از طریق همین منو، نام برند خود را ویرایش کنید.")
        safe_clear_context(context); await show_main_menu(update, context); return
    elif state == 'AGENT_EDIT_PREFIX':
        raw = text.strip()
        target_aid = context.user_data['edit_ag_id']
        if raw == "0":
            await asyncio.to_thread(_db_set_agent_prefix, target_aid, None)
            await update.message.reply_text("✅ پیشوند این نماینده به حالت پیش‌فرض سیستم بازگشت.")
        else:
            cleaned = re.sub(r'[^a-zA-Z0-9]', '', raw).lower()
            if not cleaned:
                await update.message.reply_text("❌ فقط حروف/عدد انگلیسی مجاز است. دوباره بفرستید (یا 0 برای پیش‌فرض):"); return
            await asyncio.to_thread(_db_set_agent_prefix, target_aid, cleaned)
            await update.message.reply_text(f"✅ پیشوند این نماینده روی «{esc(cleaned)}» تنظیم شد.")
        safe_clear_context(context); return
    elif state in ('AGENT_EDIT_PCT1', 'AGENT_EDIT_PCT2', 'AGENT_EDIT_PCT3'):
        fmap = {'AGENT_EDIT_PCT1':'commission_pct', 'AGENT_EDIT_PCT2':'l2_pct', 'AGENT_EDIT_PCT3':'l3_pct'}
        try: pct = float(fa_to_en_digits(text).strip())
        except ValueError: await update.message.reply_text("❌ فقط عدد!"); return
        await asyncio.to_thread(_db_update_agent_field, context.user_data['edit_ag_id'], fmap[state], pct); await update.message.reply_text("✅ آپدیت شد."); safe_clear_context(context); return
    elif state == 'AGENT_MANUAL_TOPUP':
        val_topup = fa_to_en_digits(text).strip()
        if not val_topup.isdigit() or int(val_topup) <= 0:
            await update.message.reply_text("❌ لطفاً فقط یک عدد مثبت (به تومان) بفرستید:"); return
        a_id = context.user_data.get('topup_ag_id')
        amount = float(val_topup)
        info = await asyncio.to_thread(_db_get_agent_info, a_id)
        if not info:
            await update.message.reply_text("❌ این نماینده دیگر وجود ندارد."); safe_clear_context(context); return
        # 🆕 قبل از اعمال واقعی، تاییدیهٔ بله/خیر گرفته می‌شود تا شارژ اشتباهی/تایپی به یک
        # حساب واقعی اعمال نشود.
        context.user_data['pending_topup_amount'] = amount
        context.user_data['state'] = 'AGENT_MANUAL_TOPUP_CONFIRM'
        kb = [[InlineKeyboardButton("✅ بله، شارژ شود", callback_data="topupconf_yes"), InlineKeyboardButton("↩️ خیر، انصراف", callback_data="topupconf_no")]]
        await update.message.reply_text(
            f"❓ آیا مطمئنید می‌خواهید مبلغ <b>{int(amount):,} تومان</b> به کیف‌پول «{esc(info[0])}» اضافه شود؟",
            reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
        return
    elif state == 'AGENT_MANUAL_TOPUP_CONFIRM':
        await update.message.reply_text("❓ لطفاً با دکمه‌های «بله» یا «خیر» بالا پاسخ دهید.")
        return
    elif state == 'AGENT_MANUAL_DEDUCT':
        val_deduct = fa_to_en_digits(text).strip()
        if not val_deduct.isdigit() or int(val_deduct) <= 0:
            await update.message.reply_text("❌ لطفاً فقط یک عدد مثبت (به تومان) بفرستید:"); return
        a_id = context.user_data.get('deduct_ag_id')
        amount = float(val_deduct)
        info = await asyncio.to_thread(_db_get_agent_info, a_id)
        if not info:
            await update.message.reply_text("❌ این نماینده دیگر وجود ندارد."); safe_clear_context(context); return
        # ⚠️ قبل از اعمال واقعی، تاییدیهٔ بله/خیر گرفته می‌شود تا کاهش اشتباهی/تایپی روی یک
        # حساب واقعی اعمال نشود؛ اگر مبلغ از موجودی فعلی بیشتر باشد، هشدار اضافه نمایش داده می‌شود.
        context.user_data['pending_deduct_amount'] = amount
        context.user_data['state'] = 'AGENT_MANUAL_DEDUCT_CONFIRM'
        kb = [[InlineKeyboardButton("✅ بله، کم شود", callback_data="deductconf_yes"), InlineKeyboardButton("↩️ خیر، انصراف", callback_data="deductconf_no")]]
        warn = ""
        if amount > info[2]:
            warn = f"\n⚠️ این مبلغ از موجودی فعلی ({int(info[2]):,} تومان) بیشتر است؛ موجودی نهایی منفی می‌شود.\n"
        await update.message.reply_text(
            f"❓ آیا مطمئنید می‌خواهید مبلغ <b>{int(amount):,} تومان</b> از کیف‌پول «{esc(info[0])}» کم شود؟{warn}",
            reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
        return
    elif state == 'AGENT_MANUAL_DEDUCT_CONFIRM':
        await update.message.reply_text("❓ لطفاً با دکمه‌های «بله» یا «خیر» بالا پاسخ دهید.")
        return
    elif state == 'AGENT_EDIT_USERNAME':
        a_id = context.user_data.get('edit_ag_id')
        info = await asyncio.to_thread(_db_get_agent_info, a_id) if a_id else None
        if not info:
            await update.message.reply_text("❌ تراکنش منقضی شده است."); safe_clear_context(context); return
        new_u = text.strip()
        if not new_u or " " in new_u or len(new_u) < 3:
            await update.message.reply_text("❌ یوزرنیم نامعتبر است (حداقل ۳ کاراکتر، بدون فاصله). دوباره بفرستید:"); return
        context.user_data['pending_new_agent_username'] = new_u
        context.user_data['state'] = 'AGENT_EDIT_USERNAME_CONFIRM'
        kb = [[InlineKeyboardButton("✅ بله، اعمال شود", callback_data="aguserconf_yes"), InlineKeyboardButton("↩️ خیر، انصراف", callback_data="aguserconf_no")]]
        await update.message.reply_text(
            f"❓ آیا مطمئنید می‌خواهید یوزرنیم ورود نمایندهٔ «{esc(info[0])}» به مقدار زیر تغییر کند؟\n\n<code>{esc(new_u)}</code>",
            reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
        return
    elif state == 'AGENT_EDIT_USERNAME_CONFIRM':
        await update.message.reply_text("❓ لطفاً با دکمه‌های «بله» یا «خیر» بالا پاسخ دهید.")
        return
    elif state == 'AGENT_EDIT_PASSWORD':
        a_id = context.user_data.get('edit_ag_id')
        info = await asyncio.to_thread(_db_get_agent_info, a_id) if a_id else None
        if not info:
            await update.message.reply_text("❌ تراکنش منقضی شده است."); safe_clear_context(context); return
        new_p = text.strip()
        if not new_p or len(new_p) < 3:
            await update.message.reply_text("❌ پسورد خیلی کوتاه است. دوباره پسورد جدید را بفرستید:"); return
        context.user_data['pending_new_agent_pass'] = new_p
        context.user_data['state'] = 'AGENT_EDIT_PASSWORD_CONFIRM'
        kb = [[InlineKeyboardButton("✅ بله، اعمال شود", callback_data="agpassconf_yes"), InlineKeyboardButton("↩️ خیر، انصراف", callback_data="agpassconf_no")]]
        await update.message.reply_text(
            f"❓ آیا مطمئنید می‌خواهید پسورد ورود نمایندهٔ «{esc(info[0])}» به مقدار زیر تغییر کند؟\n\n<code>{esc(new_p)}</code>",
            reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
        return
    elif state == 'AGENT_EDIT_PASSWORD_CONFIRM':
        await update.message.reply_text("❓ لطفاً با دکمه‌های «بله» یا «خیر» بالا پاسخ دهید.")
        return

    # 🔍 جستجوی کاربر
    elif state == 'USER_SEARCH_INPUT':
        res = await asyncio.to_thread(_db_search_users, text.strip().lower())
        if role == 'agent':
            rows_owner = await asyncio.to_thread(_db_get_users_with_agents)
            owned = {u for u, owner in rows_owner if owner == context.user_data.get('agent_id', 0)}
            res = [r for r in res if r[0] in owned]
        if res:
            if len(res) == 1: safe_clear_context(context); await _show_user_detail(update, res[0][0], context)
            else:
                kb = [[InlineKeyboardButton(f"👤 {row[0]}", callback_data=f"udet_{row[0]}")] for row in res]
                kb.append([InlineKeyboardButton("🔙 بازگشت", callback_data="uact_back")])
                await update.message.reply_text(f"🔍 {len(res)} کاربر یافت شد:", reply_markup=InlineKeyboardMarkup(kb))
        else: await update.message.reply_text("❌ یافت نشد!", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="uact_back")]]))
        return

    # 📢 پیام همگانی به نمایندگان: متن دلخواه → پیش‌نمایش + تاییدیه
    elif state == 'BCAST_CUSTOM_INPUT' and role == 'admin':
        safe_clear_context(context)
        await _bcast_show_preview(update, context, text.strip(), edit=False)
        return

    # 📢 ساخت پیام آمادهٔ جدید: مرحلهٔ ۱) عنوان کوتاه
    elif state == 'BCAST_PRESET_TITLE_INPUT' and role == 'admin':
        title = text.strip()[:60]
        if not title:
            await update.message.reply_text("❌ عنوان نمی‌تواند خالی باشد. دوباره بفرستید:"); return
        context.user_data['bcast_new_preset_title'] = title
        context.user_data['state'] = 'BCAST_PRESET_BODY_INPUT'
        await update.message.reply_text(f"✅ عنوان: «{esc(title)}»\n\n✍️ حالا متن کامل پیام را بفرستید:", parse_mode="HTML")
        return

    # 📢 ساخت پیام آمادهٔ جدید: مرحلهٔ ۲) متن کامل پیام → ذخیره در دیتابیس
    elif state == 'BCAST_PRESET_BODY_INPUT' and role == 'admin':
        title = context.user_data.get('bcast_new_preset_title', '').strip()
        body = text.strip()
        if not title or not body:
            await update.message.reply_text("❌ خطا؛ لطفاً از منوی «➕ افزودن پیام آماده» دوباره شروع کنید."); safe_clear_context(context); return
        await asyncio.to_thread(_db_add_broadcast_preset, title, body)
        safe_clear_context(context)
        kb = await _bcast_build_menu_kb()
        await update.message.reply_text(f"✅ پیام آمادهٔ «{esc(title)}» ذخیره شد.", parse_mode="HTML")
        await update.message.reply_text("📢 <b>پیام همگانی به نمایندگان</b>", reply_markup=kb, parse_mode="HTML")
        return

    # 🌐 سرویس IP: جستجوی کاربران برای انتخاب چندتایی (فقط ادمین)
    elif state == 'IPSVC_SEARCH_INPUT' and role == 'admin':
        term = text.strip()
        if term == "0":
            # تغییر به تابع مخصوص لیست SSH
            res = await asyncio.to_thread(_db_get_all_ssh_users)
        else:
            # تغییر به تابع مخصوص جستجوی SSH
            res = await asyncio.to_thread(_db_search_ssh_users, term.lower())
        usernames = [r[0] for r in res][:50]  # سقف ۵۰ نتیجه برای خوانا ماندن لیست دکمه‌ها
        if not usernames:
            kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="ipsvc_menu")]])
            await update.message.reply_text("❌ کاربری با این مشخصات یافت نشد.", reply_markup=kb); return
        context.user_data['ipsvc_results'] = usernames
        context.user_data['ipsvc_selected'] = set()
        context.user_data['state'] = None
        rows = [[InlineKeyboardButton("⬜️ " + u, callback_data=f"ipsel_{u}")] for u in usernames]
        rows.append([InlineKeyboardButton("☑️ انتخاب همه", callback_data="ipsel_all"), InlineKeyboardButton("🔲 پاک‌کردن انتخاب", callback_data="ipsel_clear")])
        rows.append([InlineKeyboardButton("▶️ ادامه (0 انتخاب‌شده)", callback_data="ipsel_go")])
        rows.append([InlineKeyboardButton("🔙 بازگشت", callback_data="ipsvc_menu")])
        trunc_note = "\n⚠️ فقط ۵۰ نتیجهٔ اول نشان داده شده؛ برای دقیق‌تر شدن، عبارت جستجو را کامل‌تر بفرستید (یا برای انتقال همهٔ کاربران از گزینهٔ «انتقال همهٔ کاربران» در منوی سرویس IP استفاده کنید)." if len(res) > 50 else ""
        await update.message.reply_text(f"🔍 {len(usernames)} کاربر یافت شد — روی هرکدام بزنید تا انتخاب/لغو شود:{trunc_note}", reply_markup=InlineKeyboardMarkup(rows))
        return

    # 🌍 مدیریت دامنه‌ها: مراحل افزودن دامنهٔ جدید (فقط ادمین)
    elif state == 'DOM_ADD_NAME' and role == 'admin':
        dn = text.strip().lower()
        if not dn or " " in dn:
            await update.message.reply_text("❌ نام دامنه معتبر نیست. دوباره بفرستید (مثال: example.com):"); return
        context.user_data['dom_new_name'] = dn; context.user_data['state'] = 'DOM_ADD_HOST'
        await update.message.reply_text("🌐 هاست/IP یا مقصد این دامنه را بفرستید (یا برای رد شدن، خط تیره - بفرستید):"); return
    elif state == 'DOM_ADD_HOST' and role == 'admin':
        h = text.strip()
        context.user_data['dom_new_host'] = None if h == "-" else h
        context.user_data['state'] = 'DOM_ADD_EXP'
        await update.message.reply_text("⏳ تاریخ انقضای دامنه را به فرمت میلادی YYYY-MM-DD بفرستید (مثال: 2026-10-01) یا خط تیره - برای رد شدن:"); return
    elif state == 'DOM_ADD_EXP' and role == 'admin':
        e = text.strip()
        context.user_data['dom_new_exp'] = None if e == "-" else e
        context.user_data['state'] = 'DOM_ADD_NOTES'
        await update.message.reply_text("📝 یادداشت دلخواه دربارهٔ این دامنه را بفرستید (یا خط تیره - برای رد شدن):"); return
    elif state == 'DOM_ADD_NOTES' and role == 'admin':
        notes = text.strip(); notes = None if notes == "-" else notes
        dn = context.user_data.get('dom_new_name'); dh = context.user_data.get('dom_new_host'); de = context.user_data.get('dom_new_exp')
        reg_date = datetime.now().strftime("%Y-%m-%d")
        ok = await asyncio.to_thread(_db_add_domain, dn, dh, reg_date, de, notes)
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت به مدیریت دامنه‌ها", callback_data="dom_menu")]])
        if ok: await update.message.reply_text(f"✅ دامنهٔ <code>{esc(dn)}</code> ثبت شد.", reply_markup=kb, parse_mode="HTML")
        else: await update.message.reply_text("❌ این دامنه قبلاً ثبت شده است.", reply_markup=kb)
        safe_clear_context(context); return

    elif state == 'USER_NEW_PASS':
        # 🆕 دیگر پسورد بلافاصله اعمال نمی‌شود؛ ابتدا با یک پیام تاییدیهٔ بله/خیر از ادمین/نماینده
        # پرسیده می‌شود، تا تایپ اشتباهی به‌طور ناخواسته پسورد یک مشتری را عوض نکند.
        un = context.user_data.get('target_pw')
        if not un:
            await update.message.reply_text("❌ تراکنش منقضی شده است."); safe_clear_context(context); return
        new_pw = text.strip()
        if not new_pw or len(new_pw) < 3:
            await update.message.reply_text("❌ پسورد خیلی کوتاه است. دوباره پسورد جدید را بفرستید:"); return
        context.user_data['pending_new_pw'] = new_pw
        context.user_data['state'] = 'USER_NEW_PASS_CONFIRM'
        kb = [[InlineKeyboardButton("✅ بله، اعمال شود", callback_data="pwconf_yes"), InlineKeyboardButton("↩️ خیر، انصراف", callback_data="pwconf_no")]]
        await update.message.reply_text(
            f"❓ آیا مطمئنید می‌خواهید پسورد اکانت {esc(un)} به مقدار زیر تغییر کند؟\n\n<code>{esc(new_pw)}</code>",
            reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
        return
    elif state == 'USER_NEW_PASS_CONFIRM':
        # کاربر به‌جای زدن دکمهٔ بله/خیر، پیام متنی دیگری فرستاده — همان مرحله را با یادآوری نگه می‌داریم
        await update.message.reply_text("❓ لطفاً با دکمه‌های «بله» یا «خیر» بالا پاسخ دهید.")
        return
    elif state == 'USER_INC_LIMIT':
        # 🐛🔧 رفع باگ اصلی «افزایش تعداد کاربر عمل نمی‌کند»: نسخهٔ قبلی اینجا از متغیر global
        # به‌نام «val» استفاده می‌کرد که اصلاً در این زنجیرهٔ if/elif تعریف نشده بود (فقط در یک
        # زنجیرهٔ کاملاً جداگانه و بعدتر در همین تابع تعریف می‌شد) — یعنی به‌محض رسیدن به این
        # مرحله، پایتون بلافاصله NameError می‌داد و کل درخواست ربات را بی‌پاسخ (ساکت) می‌گذاشت.
        # الان عدد مستقیماً از همان پیام فعلی محاسبه می‌شود.
        un = context.user_data.get('target_ul')
        if not un:
            await update.message.reply_text("❌ تراکنش منقضی شده است."); safe_clear_context(context); return
        ul_val = fa_to_en_digits(text).strip()
        if not ul_val.isdigit():
            await update.message.reply_text("❌ فقط عدد صحیح بفرستید:"); return
        new_limit = int(ul_val)
        ok, msg, kb = await _apply_user_limit_increase(context, role, context.user_data.get('agent_id', 0), un, new_limit)
        await update.message.reply_text(msg, parse_mode="HTML", reply_markup=kb)
        if kb is not None:
            # 🆘 گزینهٔ شارژ اضطراری نمایش داده شد؛ context عمداً پاک نمی‌شود چون هدف/تعداد جدید
            # برای اجرای واقعی بعد از کلیک روی آن دکمه لازم است. فقط state فعلی پاک می‌شود.
            context.user_data.pop('state', None)
            return
        safe_clear_context(context); await _show_user_detail(update, un, context); return
    elif state == 'USER_DEC_LIMIT':
        un = context.user_data.get('target_ul')
        if not un:
            await update.message.reply_text("❌ تراکنش منقضی شده است."); safe_clear_context(context); return
        ul_val = fa_to_en_digits(text).strip()
        if not ul_val.isdigit():
            await update.message.reply_text("❌ فقط عدد صحیح بفرستید:"); return
        new_limit = int(ul_val)
        ok, msg = await _apply_user_limit_decrease(context, role, context.user_data.get('agent_id', 0), un, new_limit)
        await update.message.reply_text(msg, parse_mode="HTML")
        safe_clear_context(context); await _show_user_detail(update, un, context); return
    elif state == 'RENEW_DAYS_INPUT':
        # 🆕 گزینهٔ «تعداد روز دلخواه» برای تمدید اکانت — عدد صحیح مثبت روز را می‌گیرد و به همان
        # مرحلهٔ تاییدیهٔ مشترکِ تمدید (بله/خیر) می‌رود.
        un = context.user_data.get('renew_target')
        if not un:
            await update.message.reply_text("❌ تراکنش منقضی شده است."); safe_clear_context(context); return
        cur = await asyncio.to_thread(_db_get_user, un)
        if not cur:
            await update.message.reply_text("❌ این کاربر دیگر وجود ندارد."); safe_clear_context(context); return
        if not _can_manage_user(role, context.user_data.get('agent_id', 0), cur[5]):
            await update.message.reply_text("⛔️ شما مجاز به مدیریت این اکانت نیستید."); safe_clear_context(context); return
        days_val = fa_to_en_digits(text).strip()
        if not days_val.isdigit() or int(days_val) <= 0:
            await update.message.reply_text("❌ فقط یک عدد صحیح مثبت (تعداد روز) بفرستید:"); return
        days = int(days_val)
        mode = context.user_data.get('renew_mode', 'extend')
        await _show_renew_confirm(update.message, context, un, days, f"{days} روز", edit=False, mode=mode)
        return

    # 🆕 دسترسی سریع با کد نپسترنت: اگر کاربر یک کد اتصال به‌شکل npvt-ssh://<base64> را از هر جای
    # چت (حتی وسط یک پیام دیگر) کپی/فوروارد و ارسال کند، ربات آن را دیکود کرده، یوزرنیم داخلش را
    # استخراج و پنل مدیریت همان اکانت (برای تمدید سریع، تغییر پسورد، فعال/غیرفعال‌سازی و غیره) را باز می‌کند.
    if not state:
        npvt_match = re.search(r'npvt-ssh://([A-Za-z0-9+/=_-]+)', text)
        if npvt_match:
            target = None
            try:
                b64_payload = npvt_match.group(1)
                b64_payload += "=" * (-len(b64_payload) % 4)  # جبران padding از دست‌رفته احتمالی
                cfg = json.loads(base64.b64decode(b64_payload).decode(errors='ignore'))
                target = str(cfg.get("sshUsername", "")).strip().lower()
            except Exception:
                log.warning("کد نپسترنت ارسالی توسط کاربر قابل دیکود نبود.")
            if target:
                row = await asyncio.to_thread(_db_get_user, target)
                if row:
                    if _can_manage_user(role, context.user_data.get('agent_id', 0), row[5]):
                        safe_clear_context(context); await _show_user_detail(update, target, context); return
                    else:
                        await update.message.reply_text("⛔️ این اکانت متعلق به شما نیست."); return
                else:
                    await update.message.reply_text("❌ کد نپسترنت دیکود شد اما اکانتی با این یوزرنیم در دیتابیس یافت نشد.")
                    return
            else:
                await update.message.reply_text("❌ کد نپسترنت ارسالی معتبر نبود یا قابل خواندن نیست.")
                return

    # 📋 دسترسی سریع: فوروارد کردن یا کپی‌کردن متن فاکتور یک اکانت (حاوی «username:») از هر جای ربات
    # مستقیماً پنل مدیریت همان اکانت را باز می‌کند (برای تمدید سریع و کارهای دیگر روی اکانت مشتری)
    labeled_match = re.search(r'username:\s*([a-zA-Z0-9_.-]{3,32})', text, re.IGNORECASE)
    if labeled_match and not state:
        target = labeled_match.group(1).strip().lower()
        row = await asyncio.to_thread(_db_get_user, target)
        if row:
            if _can_manage_user(role, context.user_data.get('agent_id', 0), row[5]):
                safe_clear_context(context); await _show_user_detail(update, target, context); return
            else:
                await update.message.reply_text("⛔️ این اکانت متعلق به شما نیست."); return

    # دسترسی سریع (حالت قدیمی): اگر پیام صرفاً شبیه یک یوزرنیم اکانت باشد و استیتی فعال نباشد
    match = re.search(r'(?:username:|\b)([a-z0-9]{3,15}\d{4})', text.lower())
    if match and not state:
        target = match.group(1).strip()
        row = await asyncio.to_thread(_db_get_user, target)
        if row and _can_manage_user(role, context.user_data.get('agent_id', 0), row[5]):
            await _show_user_detail(update, target, context); return

    # استیت‌های متفرقه
    val = fa_to_en_digits(text)
    if state == 'BULK_COUNT':
        if not val.isdigit() or int(val) < 2:
            await update.message.reply_text("❌ لطفاً یک عدد صحیح ۲ یا بزرگ‌تر بفرستید (تعداد اکانت‌های عمده):"); return
        if int(val) > 200:
            await update.message.reply_text("❌ حداکثر تعداد مجاز در هر بار ساخت عمده ۲۰۰ اکانت است. عدد کوچک‌تری بفرستید:"); return
        context.user_data['bulk_count'] = int(val); context.user_data['bulk_mode'] = True
        context.user_data['state'] = 'BUY_MONTHS'
        kb = [[InlineKeyboardButton(f"{i} ماهه", callback_data=f"bm_{i}") for i in range(1, 4)]]
        await update.message.reply_text(f"📦 تعداد اکانت عمده: {int(val)}\n\n📅 چند ماهه؟", reply_markup=InlineKeyboardMarkup(kb)); return
    if state == 'BUY_MONTHS':
        if not val.isdigit(): await update.message.reply_text("❌ فقط عدد:"); return
        context.user_data['months'] = int(val); context.user_data['state'] = 'BUY_USERS'
        kb = [[InlineKeyboardButton(f"{i} کاربره", callback_data=f"bu_{i}") for i in range(1, 4)]]
        await update.message.reply_text("👥 تعداد کاربران مجاز را انتخاب کنید:", reply_markup=InlineKeyboardMarkup(kb))
    elif state == 'BUY_USERS':
        if not val.isdigit(): await update.message.reply_text("❌ فقط عدد:"); return
        context.user_data['users'] = int(val); await _show_buy_summary(update.message, context, edit=False)
    elif state == 'BRAND_INPUT':
        await asyncio.to_thread(_db_update_setting, 'brand', text.strip()); await update.message.reply_text("✅ برند تغییر یافت."); safe_clear_context(context); await show_main_menu(update, context)
    elif state == 'HOSTS_INPUT':
        new_hosts = [h.strip() for h in text.replace(" ", "").split(',') if h.strip()]
        await asyncio.to_thread(_db_update_setting, 'hosts', ",".join(new_hosts))
        await asyncio.to_thread(_db_resync_host_pool_from_full_list, new_hosts)  # 🔧 هماهنگ‌سازی با استخر پایش سلامت
        await update.message.reply_text("✅ هاست‌ها آپدیت شدند."); safe_clear_context(context); await show_main_menu(update, context)
    elif state == 'HOSTS_APPEND_INPUT':
        new_ip = text.strip().replace(" ", "")
        if not new_ip:
            await update.message.reply_text("❌ یک IP معتبر بفرستید:"); return
        cur_hosts = [h.strip() for h in (await asyncio.to_thread(_db_get_setting, 'hosts', '')).split(',') if h.strip()]
        if new_ip in cur_hosts:
            await update.message.reply_text("ℹ️ این IP از قبل در لیست بود؛ چیزی تغییر نکرد.")
        else:
            cur_hosts.append(new_ip)
            await asyncio.to_thread(_db_update_setting, 'hosts', ",".join(cur_hosts))
            await asyncio.to_thread(_db_add_host_pool, new_ip)  # 🔧 هماهنگ‌سازی با استخر پایش سلامت
            await update.message.reply_text(f"✅ IP جدید <code>{esc(new_ip)}</code> به لیست اضافه شد.\n🌐 لیست فعلی: <code>{esc(', '.join(cur_hosts))}</code>", parse_mode="HTML")
        safe_clear_context(context); await show_main_menu(update, context)
    elif state == 'HOSTPOOL_ADD_INPUT':
        new_ip = text.strip().replace(" ", "")
        if not new_ip:
            await update.message.reply_text("❌ یک IP/دامنهٔ معتبر بفرستید:"); return
        cur_hosts = [h.strip() for h in (await asyncio.to_thread(_db_get_setting, 'hosts', '')).split(',') if h.strip()]
        if new_ip not in cur_hosts:
            cur_hosts.append(new_ip)
            await asyncio.to_thread(_db_update_setting, 'hosts', ",".join(cur_hosts))
        await asyncio.to_thread(_db_add_host_pool, new_ip)
        await asyncio.to_thread(_db_set_host_active, new_ip, True)
        await update.message.reply_text(f"✅ IP <code>{esc(new_ip)}</code> به استخر پایش سلامت اضافه و فعال شد.", parse_mode="HTML")
        safe_clear_context(context); await show_main_menu(update, context)

    elif state == 'EDGE_NEW_IP':
        ip = text.strip()
        if not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip):
            await update.message.reply_text("❌ فرمت IP درست نیست (مثال: 104.194.134.158). دوباره بفرستید:")
            return
        context.user_data['edge_new_ip'] = ip
        context.user_data['state'] = 'EDGE_NEW_ROOTPASS'
        await update.message.reply_text(
            "۲) رمز روتِ همین سرور را بفرستید (فقط همین یک‌بار استفاده می‌شود؛ پیام شما بلافاصله "
            "بعد از خواندن از چت حذف خواهد شد و هرگز روی دیسک ذخیره نمی‌شود):")

    elif state == 'EDGE_NEW_ROOTPASS':
        chat_id = update.effective_chat.id
        _EDGE_PROVISION_SECRETS[chat_id] = text  # فقط در RAM؛ در context.user_data ذخیره نمی‌شود
        try:
            await update.message.delete()
        except Exception:
            pass
        context.user_data['state'] = 'EDGE_NEW_PORT'
        default_port = await asyncio.to_thread(_db_get_setting, 'port', '2252')
        await update.message.reply_text(
            f"✅ رمز دریافت و پیام حذف شد.\n\n"
            f"۳) پورت SSH مشتری‌ها را بفرستید (اگر مطمئن نیستید همین را بفرستید: {default_port}):")

    elif state == 'EDGE_NEW_PORT':
        if not text.strip().isdigit():
            await update.message.reply_text("❌ فقط عدد بفرستید:")
            return
        customer_port = text.strip()
        chat_id = update.effective_chat.id
        edge_ip = context.user_data.get('edge_new_ip')
        root_pass = _EDGE_PROVISION_SECRETS.pop(chat_id, None)
        if not edge_ip or not root_pass:
            await update.message.reply_text("❌ اطلاعات ناقص است؛ از اول با «🚀 افزودن Edge جدید» شروع کنید.")
            safe_clear_context(context)
            return
        edge_name = f"edge-{edge_ip.replace('.', '-')}"
        safe_clear_context(context)
        await update.message.reply_text(
            f"⏳ در حال راه‌اندازی کامل Edge روی <code>{esc(edge_ip)}</code>... "
            f"(معمولاً ۱ تا ۳ دقیقه طول می‌کشد، منتظر پیام بعدی بمانید)",
            parse_mode="HTML")

        async def _provision_task_guarded():
            try:
                await _provision_new_edge(edge_ip, root_pass, customer_port, edge_name, chat_id, context.application)
            except Exception:
                log.exception("خطای غیرمنتظره در تسک پس‌زمینهٔ راه‌اندازی Edge")
                tb = traceback.format_exc()[-3000:]
                with contextlib.suppress(Exception):
                    await context.application.bot.send_message(
                        chat_id, f"❌ <b>خطای غیرمنتظره حین راه‌اندازی Edge:</b>\n\n<code>{esc(tb)}</code>", parse_mode="HTML")

        spawn_bg_task(_provision_task_guarded())

    # 🚀 ویزارد Promote (ارتقای Edge به Core)
    elif state == 'SRV_PROMOTE_PORT_INPUT':
        if not text.strip().isdigit():
            await update.message.reply_text("❌ فقط عدد بفرستید:"); return
        context.user_data['srv_cust_port'] = text.strip()
        context.user_data['state'] = 'SRV_PROMOTE_GOST_PORTS'
        await update.message.reply_text(
            "🌐 <b>پورت‌های Gost (TLS/WSS) سرور Core فعلی</b> را با فاصله وارد کنید (مثلاً 443 2087 2088 2089):\n"
            "اگر ندارید خالی بگذارید یا یک پورت الکی بزنید.\n\n"
            "💡 این مقدار فقط برای مرحلهٔ بعدی لازم است: بعد از موفقیتِ ارتقا، سرور Core فعلی خودش "
            "خودکار به Edge تنزل داده می‌شود (بدون نیاز به کار دستی جداگانه).",
            parse_mode="HTML")

    elif state == 'SRV_PROMOTE_GOST_PORTS':
        context.user_data['srv_promote_gost_ports'] = text.strip()
        context.user_data['state'] = 'SRV_PROMOTE_PASS_INPUT'
        await update.message.reply_text("🔑 <b>رمز روت (Root Password)</b> سرور مقصد را بفرستید (پیام حذف خواهد شد):")

    elif state == 'SRV_PROMOTE_PASS_INPUT':
        chat_id = update.effective_chat.id
        root_pass = text.strip()
        try: await update.message.delete()
        except: pass
        target_ip = context.user_data.get('srv_target_ip')
        cust_port = context.user_data.get('srv_cust_port')
        gost_ports = context.user_data.get('srv_promote_gost_ports', '')
        # 🆕 IP فعلیِ Core را همین الان (قبل از هرگونه تغییر) ثبت می‌کنیم، چون بعد از تنزل
        # خودکار در ادامه، همین مقدار به‌عنوان «سروری که باید Edge شود» استفاده می‌شود.
        old_core_ip = _get_core_public_ip_cached()
        safe_clear_context(context)
        # 🚀 خودکار: خودِ ربات هر ۶ فایل مهاجرت لازم را از Core می‌سازد و آپلود می‌کند،
        # سپس promote_edge_to_core.sh را روی مقصد اجرا می‌کند — نیازی به انتقال دستی نیست.
        # 🆕 اگر ارتقا موفق شود، بلافاصله و خودکار Core قدیمی هم به Edge تنزل داده می‌شود — طبق
        # درخواست صریح، «Promote» و «Demote» دیگر دو عملیات کاملاً مجزا نیستند.
        async def _promote_task_guarded():
            try:
                await context.bot.send_message(
                    chat_id,
                    f"⏳ <b>در حال اجرای فیل‌اوور ایمن و انتقال به <code>{target_ip}</code>...</b>\n"
                    f"⚠️ ربات تا لحظاتی دیگر روی این سرور متوقف شده و روی سرور جدید استارت می‌شود. سپس این سرور خودکار به Edge تبدیل خواهد شد.\n"
                    f"✅ از این پس نیازی به کار دستی نیست؛ صبور باشید تا ربات روی سرور جدید پاسخگو شود.",
                    parse_mode="HTML"
                )
                
                # 💡 Root-cause fix: use systemd-run to detach the upgrade process from the bot
                # This way, when the bot is stopped by the failover script, the process isn't killed and the demote script runs successfully.
                cmd = (
                    f"systemd-run --unit=failover-job-$(date +%s) bash -c '"
                    f"{{ bash /root/core_side_failover.sh {target_ip} {cust_port} && "
                    f"bash /root/demote_core_to_edge.sh {target_ip} {cust_port}; }} > /root/failover_migration.log 2>&1'"
                )
                
                await run_cmd("sudo", "bash", "-c", cmd)
                
            except Exception:
                log.exception("خطای مدیریت‌نشده در حین ارتقای %s به Core.", target_ip)
                with contextlib.suppress(Exception):
                    await context.bot.send_message(chat_id, f"❌ خطای غیرمنتظره در حین ارتقا رخ داد؛ لاگ سرور را بررسی کنید.")
                    
        spawn_bg_task(_promote_task_guarded())
        


    # 📉 ویزارد Demote (تنزل Core به Edge)
    elif state == 'SRV_DEMOTE_NEW_CORE_IP':
        new_core_ip = text.strip()
        if not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', new_core_ip):
            await update.message.reply_text("❌ فرمت IP درست نیست. دوباره بفرستید:"); return
        context.user_data['srv_new_core_ip'] = new_core_ip
        context.user_data['state'] = 'SRV_DEMOTE_CUST_PORT'
        await update.message.reply_text("🔢 <b>پورت SSH مشتری (Customer SSH Port)</b> را وارد کنید:")

    elif state == 'SRV_DEMOTE_CUST_PORT':
        if not text.strip().isdigit():
            await update.message.reply_text("❌ فقط عدد بفرستید:"); return
        context.user_data['srv_cust_port'] = text.strip()
        context.user_data['state'] = 'SRV_DEMOTE_GOST_PORTS'
        await update.message.reply_text("🌐 <b>پورت‌های Gost (TLS/WSS)</b> را با فاصله وارد کنید (مثلاً 443 2087 2088 2089):\nاگر ندارید خالی بگذارید یا یک پورت الکی بزنید.")

    elif state == 'SRV_DEMOTE_GOST_PORTS':
        gost_ports = text.strip()
        context.user_data['srv_gost_ports'] = gost_ports
        context.user_data['state'] = 'SRV_DEMOTE_PORT'
        default_port = await asyncio.to_thread(_db_get_setting, 'port', '2252')
        await update.message.reply_text(f"🔌 پورت SSH همین سرور (Core فعلی) را بفرستید (پیش‌فرض ربات: {esc(default_port)}):", parse_mode="HTML")
    elif state == 'SRV_DEMOTE_PORT':
        pv = text.strip()
        if not pv.isdigit() or not (1 <= int(pv) <= 65535):
            await update.message.reply_text("❌ پورت باید یک عدد بین 1 تا 65535 باشد. دوباره بفرستید:"); return
        context.user_data['srv_target_port'] = pv
        context.user_data['state'] = 'SRV_DEMOTE_PASS_INPUT'
        await update.message.reply_text("🔑 <b>رمز روت (Root Password)</b> همین سرور (Core فعلی) را بفرستید:", parse_mode="HTML")

    elif state == 'SRV_DEMOTE_PASS_INPUT':
        chat_id = update.effective_chat.id
        root_pass = text.strip()
        try: await update.message.delete()
        except: pass
        target_ip = context.user_data.get('srv_target_ip')
        target_port = context.user_data.get('srv_target_port')
        new_core_ip = context.user_data.get('srv_new_core_ip')
        cust_port = context.user_data.get('srv_cust_port')
        gost_ports = context.user_data.get('srv_gost_ports')
        safe_clear_context(context)
        # اجرای اسکریپت demote_core_to_edge.sh
        # آرگومان‌ها: <NEW_CORE_PUBLIC_IP> <CUSTOMER_SSH_PORT> [GOST_PORTS...]
        script_file = os.path.join(os.path.dirname(__file__), "demote_core_to_edge.sh")
        await _run_remote_script(target_ip, root_pass, script_file, f"{new_core_ip} {cust_port} {gost_ports}", chat_id, context, ssh_port=target_port)

    # 🔄 ویزارد Update Endpoint
    elif state == 'SRV_UPDATE_EP_NEW_CORE':
        new_core_ip = text.strip()
        if not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', new_core_ip):
            await update.message.reply_text("❌ فرمت IP درست نیست. دوباره بفرستید:"); return
        context.user_data['srv_new_core_ip'] = new_core_ip
        context.user_data['state'] = 'SRV_UPDATE_EP_PORT'
        default_port = await asyncio.to_thread(_db_get_setting, 'port', '2252')
        await update.message.reply_text(f"🔌 پورت SSH سرور Edge مقصد را بفرستید (پیش‌فرض ربات: {esc(default_port)}):", parse_mode="HTML")
    elif state == 'SRV_UPDATE_EP_PORT':
        pv = text.strip()
        if not pv.isdigit() or not (1 <= int(pv) <= 65535):
            await update.message.reply_text("❌ پورت باید یک عدد بین 1 تا 65535 باشد. دوباره بفرستید:"); return
        context.user_data['srv_target_port'] = pv
        context.user_data['state'] = 'SRV_UPDATE_EP_PASS'
        await update.message.reply_text("🔑 <b>رمز روت (Root Password)</b> سرور Edge مقصد را بفرستید:", parse_mode="HTML")

    elif state == 'SRV_UPDATE_EP_PASS':
        chat_id = update.effective_chat.id
        root_pass = text.strip()
        try: await update.message.delete()
        except: pass
        target_ip = context.user_data.get('srv_target_ip')
        target_port = context.user_data.get('srv_target_port')
        new_core_ip = context.user_data.get('srv_new_core_ip')
        safe_clear_context(context)
        # اجرای اسکریپت update_edge_endpoint.sh
        # آرگومان‌ها: <NEW_CORE_PUBLIC_IP> [NEW_CORE_WG_PORT]
        script_file = os.path.join(os.path.dirname(__file__), "update_edge_endpoint.sh")
        await _run_remote_script(target_ip, root_pass, script_file, f"{new_core_ip}", chat_id, context, ssh_port=target_port)

    # 🚀 ویزارد Optimize
    elif state == 'SRV_OPTIMIZE_PORT':
        pv = text.strip()
        if not pv.isdigit() or not (1 <= int(pv) <= 65535):
            await update.message.reply_text("❌ پورت باید یک عدد بین 1 تا 65535 باشد. دوباره بفرستید:"); return
        context.user_data['srv_target_port'] = pv
        context.user_data['state'] = 'SRV_OPTIMIZE_PASS'
        target_ip = context.user_data.get('srv_target_ip')
        await update.message.reply_text(f"🚀 بهینه‌سازی <code>{esc(target_ip)}:{esc(pv)}</code>\n\n🔑 لطفاً <b>رمز روت</b> سرور مقصد را بفرستید:", parse_mode="HTML")
    elif state == 'SRV_OPTIMIZE_PASS':
        chat_id = update.effective_chat.id
        root_pass = text.strip()
        try: await update.message.delete()
        except: pass
        target_ip = context.user_data.get('srv_target_ip')
        target_port = context.user_data.get('srv_target_port')
        safe_clear_context(context)
        script_file = os.path.join(os.path.dirname(__file__), "speed_optimizer.sh")
        await _run_remote_script(target_ip, root_pass, script_file, "", chat_id, context, ssh_port=target_port)

    elif state == 'SRV_INSTALLKEY_PASS':
        chat_id = update.effective_chat.id
        root_pass = text.strip()
        try: await update.message.delete()
        except: pass
        target_ip = context.user_data.get('srv_target_ip')
        target_port = await asyncio.to_thread(_db_get_host_ssh_port, target_ip, 22)
        safe_clear_context(context)
        if paramiko is None:
            await update.message.reply_text("❌ کتابخانهٔ paramiko روی Core نصب نیست.")
        else:
            def _connect_and_install():
                ssh = None
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    # 🐛🔧 همان رفع باگ «Authentication failed با رمز درست»: بدون این دو فلگ،
                    # paramiko قبل از رمز، چند کلید محلی پیش‌فرض را هم امتحان می‌کند و روی
                    # سرورهای با MaxAuthTries محدود، سهمیهٔ تلاش را قبل از رسیدن به رمز واقعی
                    # مصرف می‌کند (دقیقاً همان چیزی که در بخش «بهینه‌سازی سرعت»/«تغییر پورت SSH»
                    # قبلاً کشف و درست شده بود، ولی این‌جا فراموش شده بود).
                    ssh.connect(target_ip, port=target_port, username='root', password=root_pass, timeout=15,
                                banner_timeout=15, look_for_keys=False, allow_agent=False)
                    ok_k, err_k = _install_local_pubkey_on_open_ssh(ssh)
                    return ok_k, err_k
                except Exception as e:
                    return False, str(e)
                finally:
                    if ssh is not None:
                        try:
                            ssh.close()
                        except Exception:
                            pass
            ok_install, err_install = await asyncio.to_thread(_connect_and_install)
            if ok_install:
                await context.bot.send_message(chat_id, f"✅ دسترسی SSH دائمی روی <code>{esc(target_ip)}</code> نصب شد. از این به بعد، CPU/RAM واقعیِ همین سرور بدون نیاز به رمز روت قابل‌مشاهده است.", parse_mode="HTML")
            else:
                await context.bot.send_message(chat_id, f"❌ نصب کلید روی <code>{esc(target_ip)}</code> شکست خورد:\n<code>{esc(err_install)}</code>", parse_mode="HTML")

    elif state == 'FILTER_THRESHOLD_INPUT':
        val_str = text.strip()
        if not val_str.isdigit() or not (1 <= int(val_str) <= 99):
            await update.message.reply_text("❌ لطفاً یک عدد بین \u06f1 تا \u06f9\u06f9 بفرستید:"); return
        new_threshold = int(val_str)
        await asyncio.to_thread(_db_update_setting, 'filter_detect_threshold', str(new_threshold))
        await update.message.reply_text(f"✅ آستانه فیلتر به <b>{new_threshold}\u066a</b> تغییر یافت.\nاگر کمتر از {new_threshold}\u066a کاربران آنلاین باشند → IP فیلتر تشخیص داده می‌شود.", parse_mode="HTML")
        safe_clear_context(context); await show_main_menu(update, context)

    elif state == 'CF_DOMAIN_INPUT':
        await asyncio.to_thread(_db_update_setting, 'public_domain', text.strip())
        await update.message.reply_text("✅ دامنهٔ ثابت ذخیره شد.")
        safe_clear_context(context); await show_main_menu(update, context)
    elif state == 'CF_TOKEN_INPUT':
        await asyncio.to_thread(_db_update_setting, 'cf_api_token', text.strip())
        await update.message.reply_text("✅ Cloudflare API Token ذخیره شد.")
        safe_clear_context(context); await show_main_menu(update, context)
    elif state == 'CF_ZONE_INPUT':
        await asyncio.to_thread(_db_update_setting, 'cf_zone_id', text.strip())
        await update.message.reply_text("✅ Zone ID ذخیره شد.")
        safe_clear_context(context); await show_main_menu(update, context)
    elif state == 'CF_RECORD_INPUT':
        await asyncio.to_thread(_db_update_setting, 'cf_record_id', text.strip())
        await update.message.reply_text("✅ Record ID ذخیره شد.")
        safe_clear_context(context); await show_main_menu(update, context)

    elif state == 'SSH_PORT_NEW_INPUT':
        pv = text.strip()
        if not pv.isdigit() or not (1 <= int(pv) <= 65535):
            await update.message.reply_text("❌ پورت باید یک عدد بین 1 تا 65535 باشد. دوباره بفرستید:"); return
        target_host = context.user_data.get('ssh_port_target_host')
        current_port = _normalize_ssh_port(context.user_data.get('ssh_port_current'), 22)
        if not target_host or not await asyncio.to_thread(_db_host_exists, target_host):
            safe_clear_context(context)
            await update.message.reply_text("❌ درخواست تغییر پورت منقضی شده یا IP دیگر در استخر نیست.")
            return
        if int(pv) == current_port:
            safe_clear_context(context)
            await update.message.reply_text(f"ℹ️ پورت <code>{esc(pv)}</code> از قبل برای <code>{esc(target_host)}</code> ثبت شده است.", parse_mode='HTML')
            return
        context.user_data['ssh_port_new'] = int(pv)
        context.user_data['state'] = 'SSH_PORT_ROOT_PASSWORD'
        await update.message.reply_text(
            f"🔑 رمز <b>root</b> سرور <code>{esc(target_host)}:{current_port}</code> را بفرستید. "
            "پیام رمز بلافاصله حذف می‌شود و روی دیسک ذخیره نخواهد شد.", parse_mode='HTML')

    elif state == 'SSH_PORT_ROOT_PASSWORD':
        chat_id = update.effective_chat.id
        target_host = context.user_data.get('ssh_port_target_host')
        current_port = _normalize_ssh_port(context.user_data.get('ssh_port_current'), 22)
        new_port = _normalize_ssh_port(context.user_data.get('ssh_port_new'), 0)
        root_password = text
        try:
            await update.message.delete()
        except Exception:
            pass
        if not target_host or not new_port or not await asyncio.to_thread(_db_host_exists, target_host):
            safe_clear_context(context)
            await context.bot.send_message(chat_id, '❌ درخواست تغییر پورت منقضی شده است.')
            return
        safe_clear_context(context)

        async def _run_port_change():
            progress = await context.bot.send_message(
                chat_id, f"⏳ در حال تغییر واقعی پورت SSH روی <code>{esc(target_host)}:{current_port}</code>...", parse_mode='HTML')
            try:
                ok, detail = await _change_remote_ssh_port(target_host, current_port, new_port, root_password)
                if ok:
                    await asyncio.to_thread(_db_set_host_ssh_port, target_host, new_port)
                    core_ip = await asyncio.to_thread(_get_core_public_ip_cached)
                    is_default = await asyncio.to_thread(_db_is_default_host, target_host)
                    # تنظیم سراسری فقط fallback/سازگاری است؛ برای Core یا IP پیش‌فرض همگام نگه داشته می‌شود.
                    if target_host == core_ip or is_default:
                        await asyncio.to_thread(_db_update_setting, 'port', str(new_port))
                    reply = InlineKeyboardMarkup([[InlineKeyboardButton('🔌 مشاهدهٔ همهٔ پورت‌ها', callback_data='srv_port')]])
                    await context.bot.edit_message_text(
                        f"✅ <b>پورت SSH واقعاً تغییر کرد.</b>\n\n"
                        f"IP: <code>{esc(target_host)}</code>\n"
                        f"پورت جدید: <code>{new_port}</code>\n\n"
                        f"{esc(detail)}\n\n"
                        "از این پس فاکتورها و کدهای اتصال مستقیمِ این IP پورت جدید را می‌گیرند.",
                        chat_id=chat_id, message_id=progress.message_id, parse_mode='HTML', reply_markup=reply)
                else:
                    reply = InlineKeyboardMarkup([[InlineKeyboardButton('🔙 بازگشت به پورت‌ها', callback_data='srv_port')]])
                    await context.bot.edit_message_text(
                        f"❌ <b>پورت تغییر نکرد.</b>\n\n<code>{esc(detail)}</code>",
                        chat_id=chat_id, message_id=progress.message_id, parse_mode='HTML', reply_markup=reply)
            except Exception:
                log.exception('خطای غیرمنتظره در تغییر واقعی پورت SSH')
                await context.bot.edit_message_text(
                    '❌ خطای غیرمنتظره در تغییر پورت رخ داد؛ پورت ثبت‌شده در ربات تغییر نکرد.',
                    chat_id=chat_id, message_id=progress.message_id)

        spawn_bg_task(_run_port_change())

    elif state == 'PORT_INPUT':
        # سازگاری با stateهای مانده از نسخه‌های قبلی؛ تغییر واقعی از پنل جدید انجام می‌شود.
        pv = text.strip()
        if not pv.isdigit() or not (1 <= int(pv) <= 65535):
            await update.message.reply_text("❌ پورت باید یک عدد بین 1 تا 65535 باشد. دوباره بفرستید:"); return
        await asyncio.to_thread(_db_update_setting, 'port', pv)
        await update.message.reply_text(f"✅ پورت پیش‌فرض به {esc(pv)} تغییر یافت. برای تغییر واقعیِ هر سرور از پنل «تغییر پورت» استفاده کنید.", parse_mode="HTML")
        safe_clear_context(context); await show_main_menu(update, context)
    # 🆕 ورودی دامنه/پورت سرور TLS به‌صورت «دامنه:پورت» — هر دو مقدار با هم ذخیره می‌شوند تا هرگز
    # یکی به‌روز و دیگری قدیمی نماند.
    elif state == 'TLS_INPUT':
        raw = text.strip()
        if ':' not in raw:
            await update.message.reply_text("❌ فرمت درست نیست. به‌صورت دامنه:پورت بفرستید (مثال: ws.example.com:2088):"); return
        dom, _, prt = raw.rpartition(':')
        dom = dom.strip(); prt = prt.strip()
        if not dom or not prt.isdigit() or not (1 <= int(prt) <= 65535):
            await update.message.reply_text("❌ فرمت درست نیست. به‌صورت دامنه:پورت بفرستید (مثال: ws.example.com:2088):"); return
        await asyncio.to_thread(_db_update_setting, 'tls_domain', dom)
        await asyncio.to_thread(_db_update_setting, 'tls_port', prt)
        await update.message.reply_text(f"✅ دامنه/پورت TLS به <code>{esc(dom)}:{esc(prt)}</code> تغییر یافت.", parse_mode="HTML")
        safe_clear_context(context); await show_main_menu(update, context)
    # 🆕 ورودی پورت UDPGW — باید دقیقاً با پورتی که badvpn-udpgw روی سرور با آن اجرا شده یکی باشد.
    elif state == 'UDPGW_INPUT':
        pv = text.strip()
        if not pv.isdigit() or not (1 <= int(pv) <= 65535):
            await update.message.reply_text("❌ پورت باید یک عدد بین 1 تا 65535 باشد. دوباره بفرستید:"); return
        await asyncio.to_thread(_db_update_setting, 'udpgw_port', pv)
        await update.message.reply_text(f"✅ پورت UDPGW به {esc(pv)} تغییر یافت. این عدد از این پس در کد اتصال اکانت‌های جدید استفاده می‌شود.", parse_mode="HTML")
        safe_clear_context(context); await show_main_menu(update, context)
    elif state == 'RB_PASS_EXTEND':
        if text.strip() != RB_CONFIRM_PASS:
            kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 انصراف", callback_data="srv_rb")]])
            await update.message.reply_text("❌ رمز اشتباه است. دوباره بفرستید:", reply_markup=kb); return
        context.user_data['state'] = 'RB_EXTEND_DAYS'
        stype = context.user_data.get('rb_target_type', 'ssh')
        await update.message.reply_text(f"✅ رمز تایید شد.\n\n✍️ چند روز به تاریخ انقضای همه کاربران {stype.upper()} اضافه شود؟ فقط عدد بفرستید:")
    elif state == 'RB_EXTEND_DAYS':
        dv = text.strip()
        if not dv.isdigit() or int(dv) <= 0:
            await update.message.reply_text("❌ فقط یک عدد صحیح مثبت بفرستید:"); return
        days = int(dv)
        context.user_data['rb_days'] = days
        stype = context.user_data.get('rb_target_type', 'ssh')
        accounts = [a for a in await asyncio.to_thread(_db_get_all_accounts_full) if a[4] == stype]
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("بلی، اعمال کن", callback_data="rb_extend_confirm"), InlineKeyboardButton("خیر", callback_data="rb_extend_cancel")]])
        await update.message.reply_text(f"⚠️ آیا مطمئنید می‌خواهید <b>{days} روز</b> به تاریخ انقضای <b>{len(accounts)}</b> اکانت {stype.upper()} اضافه شود؟", reply_markup=kb, parse_mode="HTML")
    elif state == 'RB_PASS_LOCK':
        if text.strip() != RB_CONFIRM_PASS:
            kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 انصراف", callback_data="srv_rb")]])
            await update.message.reply_text("❌ رمز اشتباه است. دوباره بفرستید:", reply_markup=kb); return
        stype = context.user_data.get('rb_target_type', 'ssh')
        accounts = [a for a in await asyncio.to_thread(_db_get_all_accounts_full) if a[4] == stype]
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("بلی، قطع کن", callback_data="rb_lock_confirm"), InlineKeyboardButton("خیر", callback_data="rb_lock_cancel")]])
        await update.message.reply_text(f"⚠️ آیا مطمئنید می‌خواهید تمام <b>{len(accounts)}</b> کاربر {stype.upper()} به‌صورت سراسری قطع شوند؟", reply_markup=kb, parse_mode="HTML")
    elif state == 'RB_PASS_UNLOCK':
        if text.strip() != RB_CONFIRM_PASS:
            kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 انصراف", callback_data="srv_rb")]])
            await update.message.reply_text("❌ رمز اشتباه است. دوباره بفرستید:", reply_markup=kb); return
        stype = context.user_data.get('rb_target_type', 'ssh')
        accounts = [a for a in await asyncio.to_thread(_db_get_all_accounts_full) if a[4] == stype]
        n_active = sum(1 for _u, _e, st, _h, _stype in accounts if st == '🟢 فعال')
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("بلی، وصل کن", callback_data="rb_unlock_confirm"), InlineKeyboardButton("خیر", callback_data="rb_unlock_cancel")]])
        await update.message.reply_text(f"⚠️ آیا مطمئنید می‌خواهید <b>{n_active}</b> کاربرِ «فعال» {stype.upper()} دوباره وصل شوند؟", reply_markup=kb, parse_mode="HTML")
    elif state == 'SET_BANK_CARD':
        await asyncio.to_thread(_db_update_setting, 'bank_card', text.strip()); await update.message.reply_text("✅ اطلاعات کارت بانکی سیستم ثبت شد."); safe_clear_context(context); await show_main_menu(update, context)
    elif state == 'C2C_AMOUNT':
        if not val.isdigit(): await update.message.reply_text("❌ لطفاً مبلغ را فقط به صورت عدد وارد کنید."); return
        context.user_data['c2c_amount'] = float(val); context.user_data['state'] = 'C2C_PHOTO'
        # 🆕 اگر یکی از نمایندگان بالادستیِ این کاربر برای خودش کارت اختصاصی ثبت کرده باشد، همان
        # نشان داده می‌شود (نه کارت مدیریت) — تا زیرمجموعه‌ها مستقیماً به همان نماینده واریز کنند.
        card_num, card_name, owner_aid = await asyncio.to_thread(_db_get_effective_card_for_agent, context.user_data.get('agent_id', 0))
        context.user_data['c2c_card_owner_agent_id'] = owner_aid  # 🆕 برای مسیردهی تاییدیه و گزارش مالی
        card_note = f"\n👤 به‌نام: {esc(card_name)}" if card_name else ""
        await update.message.reply_text(f"💳 لطفاً مبلغ <b>{int(val):,} تومان</b> را به کارت زیر واریز کنید:\n\n<code>{esc(card_num)}</code>{card_note}\n\n📸 پس از واریز، **عکس رسید** را در همین چت ارسال کنید:", parse_mode="HTML"); return
    elif state == 'WD2W_AMOUNT':
        if not val.isdigit() or int(val) <= 0: await update.message.reply_text("❌ فقط عدد مثبت:"); return
        amount = float(val)
        info = await asyncio.to_thread(_db_get_agent_info, role_agent_id := context.user_data.get('agent_id', 0))
        withdrawable = info[14] if info and len(info) > 14 and info[14] is not None else 0.0
        if amount > withdrawable:
            await update.message.reply_text(f"❌ مبلغ از موجودی استخر ({int(withdrawable):,} تومان) بیشتر است. عدد کوچک‌تری بفرستید:"); return
        ok = await asyncio.to_thread(_db_move_withdrawable_to_wallet, role_agent_id, amount)
        safe_clear_context(context)
        if ok:
            await update.message.reply_text(f"✅ مبلغ {int(amount):,} تومان به کیف‌پول قابل‌خرج شما منتقل شد.")
        else:
            await update.message.reply_text("❌ خطا: موجودی استخر تغییر کرده بود. دوباره تلاش کنید.")
        return
    elif state == 'WD_AMOUNT':
        if not val.isdigit() or int(val) <= 0: await update.message.reply_text("❌ فقط عدد مثبت:"); return
        amount = float(val)
        info = await asyncio.to_thread(_db_get_agent_info, context.user_data.get('agent_id', 0))
        withdrawable = info[14] if info and len(info) > 14 and info[14] is not None else 0.0
        if amount > withdrawable:
            await update.message.reply_text(f"❌ مبلغ از موجودی استخر ({int(withdrawable):,} تومان) بیشتر است. عدد کوچک‌تری بفرستید:"); return
        context.user_data['wd_amount'] = amount
        context.user_data['state'] = 'WD_CARD'
        await update.message.reply_text(f"💳 مبلغ برداشت: {int(amount):,} تومان\n\nلطفاً شمارهٔ کارت بانکی مقصد را بفرستید:")
        return
    elif state == 'WD_CARD':
        card = fa_to_en_digits(text).strip().replace(" ", "")
        if not re.fullmatch(r'\d{12,19}', card):
            await update.message.reply_text("❌ شمارهٔ کارت نامعتبر است (فقط عدد، بین ۱۲ تا ۱۹ رقم). دوباره بفرستید:"); return
        context.user_data['wd_card'] = card
        context.user_data['state'] = 'WD_NAME'
        await update.message.reply_text("👤 لطفاً نام و نام‌خانوادگی صاحب کارت را بفرستید:")
        return
    elif state == 'WD_NAME':
        full_name = text.strip()
        if len(full_name) < 3:
            await update.message.reply_text("❌ نام وارد‌شده خیلی کوتاه است. دوباره بفرستید:"); return
        context.user_data['wd_full_name'] = full_name
        amount = context.user_data.get('wd_amount'); card = context.user_data.get('wd_card')
        context.user_data['pending_wd_amount'] = amount
        context.user_data['state'] = 'WD_CONFIRM'
        kb = [[InlineKeyboardButton("✅ بله، ثبت شود", callback_data="wdconf_yes"), InlineKeyboardButton("↩️ خیر، انصراف", callback_data="wdconf_no")]]
        await update.message.reply_text(
            f"❓ آیا مطمئنید می‌خواهید این درخواست برداشت ثبت شود؟\n\n💰 مبلغ: {int(amount):,} تومان\n👤 نام: {esc(full_name)}\n💳 کارت: <code>{esc(card)}</code>",
            reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
        return
    elif state == 'WD_CONFIRM':
        await update.message.reply_text("❓ لطفاً با دکمه‌های «بله» یا «خیر» بالا پاسخ دهید.")
        return

    # 🆕 ثبت کارت یک نماینده توسط ادمین (از داخل «تنظیمات مالی → شماره کارت نمایندگان»)
    elif state == 'ADMIN_SET_AGENT_CARD_NUM':
        card = fa_to_en_digits(text).strip().replace(" ", "").replace("-", "")
        if not re.fullmatch(r'\d{12,19}', card):
            await update.message.reply_text("❌ شمارهٔ کارت نامعتبر است (فقط عدد، بین ۱۲ تا ۱۹ رقم). دوباره بفرستید:"); return
        context.user_data['fin_agent_card_num'] = card
        context.user_data['state'] = 'ADMIN_SET_AGENT_CARD_NAME'
        await update.message.reply_text("👤 لطفاً نام و نام‌خانوادگی صاحب کارت را بفرستید:")
        return
    elif state == 'ADMIN_SET_AGENT_CARD_NAME':
        full_name = text.strip()
        if len(full_name) < 3:
            await update.message.reply_text("❌ نام وارد‌شده خیلی کوتاه است. دوباره بفرستید:"); return
        target_aid = context.user_data.pop('fin_target_agent_id', None)
        card = context.user_data.pop('fin_agent_card_num', None)
        safe_clear_context(context)
        if not target_aid or not card:
            await update.message.reply_text("❌ خطا: اطلاعات ناقص شد؛ لطفاً از اول تلاش کنید."); return
        ainf = await asyncio.to_thread(_db_get_agent_info, target_aid)
        await asyncio.to_thread(_db_set_agent_card, target_aid, card, full_name)
        await update.message.reply_text(
            f"✅ کارت نمایندهٔ «{esc(ainf[0] if ainf else target_aid)}» ثبت شد.\n\n💳 <code>{esc(card)}</code>\n👤 {esc(full_name)}\n\n"
            f"از این پس زیرمجموعه‌های این نماینده هنگام شارژ کیف‌پول، همین کارت را می‌بینند.",
            parse_mode="HTML")
        await show_main_menu(update, context)
        return

    # 🆕 ثبت خودگردانِ کارت اختصاصی توسط خودِ نماینده (فقط با مجوز) — از دکمهٔ «کارت اختصاصی من»
    elif state == 'AGSELF_CARD_NUM':
        ag_id = context.user_data.get('agent_id', 0)
        if not ag_id or not await asyncio.to_thread(_db_get_agent_card_permission, ag_id):
            await update.message.reply_text("❌ شما مجوز این بخش را ندارید."); safe_clear_context(context); return
        card = fa_to_en_digits(text).strip().replace(" ", "").replace("-", "")
        if not re.fullmatch(r'\d{12,19}', card):
            await update.message.reply_text("❌ شمارهٔ کارت نامعتبر است (فقط عدد، بین ۱۲ تا ۱۹ رقم). دوباره بفرستید:"); return
        context.user_data['agself_card_num'] = card
        context.user_data['state'] = 'AGSELF_CARD_NAME'
        await update.message.reply_text("👤 لطفاً نام و نام‌خانوادگی صاحب کارت را بفرستید:")
        return
    elif state == 'AGSELF_CARD_NAME':
        ag_id = context.user_data.get('agent_id', 0)
        if not ag_id or not await asyncio.to_thread(_db_get_agent_card_permission, ag_id):
            await update.message.reply_text("❌ شما مجوز این بخش را ندارید."); safe_clear_context(context); return
        full_name = text.strip()
        if len(full_name) < 3:
            await update.message.reply_text("❌ نام وارد‌شده خیلی کوتاه است. دوباره بفرستید:"); return
        card = context.user_data.pop('agself_card_num', None)
        safe_clear_context(context)
        if not card:
            await update.message.reply_text("❌ خطا: اطلاعات ناقص شد؛ لطفاً از اول تلاش کنید."); return
        await asyncio.to_thread(_db_set_agent_card, ag_id, card, full_name)
        await update.message.reply_text(
            f"✅ کارت اختصاصی شما ثبت شد.\n\n💳 <code>{esc(card)}</code>\n👤 {esc(full_name)}\n\n"
            f"از این پس زیرمجموعه‌های شما هنگام شارژ کیف‌پول، همین کارت را می‌بینند.", parse_mode="HTML")
        await show_main_menu(update, context)
        return

# ==========================================
# 📸 هندلر عکس (تاییدیه رسید بانکی)
# ==========================================
async def photo_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    state = context.user_data.get('state')
    role = context.user_data.get('role')
    
    if state == 'C2C_PHOTO' and role == 'agent':
        photo_id = update.message.photo[-1].file_id
        amount = context.user_data.get('c2c_amount')
        agent_id = context.user_data.get('agent_id')
        card_owner_agent_id = context.user_data.get('c2c_card_owner_agent_id')  # 🆕 ممکن است None باشد (کارت سیستم)
        date_str = datetime.now().strftime("%Y-%m-%d %H:%M")
        
        # ذخیره در دیتابیس در حالت انتظار
        with db_conn() as conn:
            cur = conn.cursor()
            cur.execute("INSERT INTO receipts (agent_id, amount, photo_id, created_at, card_owner_agent_id) VALUES (?, ?, ?, ?, ?)",
                        (agent_id, amount, photo_id, date_str, card_owner_agent_id))
            receipt_id = cur.lastrowid

        # 🔧 رفع باگ: قبلاً ابتدا به خودِ نماینده گفته می‌شد «رسید برای مدیریت ارسال گردید» و بعد
        # تازه تلاش برای ارسال واقعی به ادمین انجام می‌شد؛ اگر admin_chat_id هنوز تنظیم نشده بود
        # (هیچ ادمینی هنوز از /start وارد نشده) یا ارسال با خطا مواجه می‌شد، نماینده یک تاییدیهٔ
        # کاذب می‌دید درحالی‌که هیچ پیامی واقعاً به ادمین نرسیده بود. حالا ابتدا تلاش برای ارسال به
        # ادمین انجام می‌شود و سپس پیام صادقانه‌ای متناسب با نتیجهٔ واقعی به نماینده نمایش داده می‌شود.
        # 🆕 حالا رسید به تمام ادمین‌هایی که تابه‌حال وارد شده‌اند ارسال می‌شود (نه فقط آخرین نفر)
        # 🔧 رفع باگ: اگر همین چت (همین اکانت تلگرام) قبلاً یک‌بار با یوزر/پس مدیر هم لاگین کرده
        # باشد، chat_id آن در جدول admin_chat_ids ثبت مانده و در نتیجه پیامِ مخصوص ادمین (با
        # دکمه‌های تایید/رد) به‌جای اینکه فقط برای مدیر برود، به همین چتِ نماینده هم ارسال
        # می‌شد. حالا چتِ فرستندهٔ رسید همیشه از لیست گیرنده‌های ادمین کنار گذاشته می‌شود.
        current_chat_id = update.effective_chat.id
        admin_ids = await asyncio.to_thread(_db_get_admin_chat_ids)
        admin_ids = {a for a in admin_ids if a != current_chat_id}
        sent_to_admin = False
        if admin_ids:
            try:
                agent_info = await asyncio.to_thread(_db_get_agent_info, agent_id)
                agent_name = agent_info[0] if agent_info else "نامشخص"

                kb = [[InlineKeyboardButton("✅ تایید و شارژ کیف‌پول", callback_data=f"c2c_acc_{receipt_id}_{agent_id}_{amount}")],
                      [InlineKeyboardButton("❌ رد رسید", callback_data=f"c2c_rej_{receipt_id}_{agent_id}")]]

                cap = f"🧾 <b>درخواست شارژ جدید (کارت‌به‌کارت)</b>\n\n👤 نماینده: {esc(agent_name)} (کد: {agent_id})\n💰 مبلغ: {int(amount):,} تومان\n📅 تاریخ: {date_str}"
                for admin_chat_id in admin_ids:
                    try:
                        await context.bot.send_photo(chat_id=admin_chat_id, photo=photo_id, caption=cap, reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
                        sent_to_admin = True
                    except Exception as e:
                        log.error(f"خطا در ارسال رسید {receipt_id} به ادمین {admin_chat_id}: {e}")
            except Exception as e:
                log.error(f"خطا در آماده‌سازی رسید {receipt_id} برای ارسال به ادمین‌ها: {e}")
        else:
            log.warning("رسید %s ثبت شد اما هنوز هیچ ادمینی وارد نشده؛ رسید فقط در دیتابیس در انتظار ماند.", receipt_id)

        # 🆕 اگر این واریزی از طریق کارت اختصاصیِ یک نمایندهٔ بالادستی انجام شده (نه کارت سیستم)،
        # همان نماینده هم مستقیماً پیام تاییدیه (با دکمه‌های تایید/رد) دریافت می‌کند — چون واریزی
        # عملاً به کارت بانکی خودش رفته و او بهتر از هرکس می‌تواند رسیدش را چک کند. تایید مدیریت
        # هم همچنان معتبر می‌ماند (هرکدام زودتر بزند، دیگری دیگر «قبلاً بررسی شده» می‌بیند).
        if card_owner_agent_id and card_owner_agent_id != agent_id:
            try:
                owner_info = await asyncio.to_thread(_db_get_agent_info, card_owner_agent_id)
                owner_chat_id = owner_info[8] if owner_info and len(owner_info) > 8 else None
                sub_info = await asyncio.to_thread(_db_get_agent_info, agent_id)
                sub_name = sub_info[0] if sub_info else "نامشخص"
                if owner_chat_id and owner_chat_id != current_chat_id:
                    kb_owner = [[InlineKeyboardButton("✅ تایید و شارژ کیف‌پول", callback_data=f"c2c_acc_{receipt_id}_{agent_id}_{amount}")],
                                [InlineKeyboardButton("❌ رد رسید", callback_data=f"c2c_rej_{receipt_id}_{agent_id}")]]
                    cap_owner = (f"🧾 <b>واریزی زیرمجموعهٔ شما به کارت اختصاصی‌تان</b>\n\n"
                                 f"👤 زیرمجموعه: {esc(sub_name)} (کد: {agent_id})\n"
                                 f"💰 مبلغ: {int(amount):,} تومان\n📅 تاریخ: {date_str}\n\n"
                                 f"لطفاً پس از بررسی واریز به کارتتان، تایید یا رد کنید:")
                    await context.bot.send_photo(chat_id=owner_chat_id, photo=photo_id, caption=cap_owner,
                                                  reply_markup=InlineKeyboardMarkup(kb_owner), parse_mode="HTML")
            except Exception as e:
                log.error(f"خطا در ارسال تاییدیهٔ رسید {receipt_id} به نمایندهٔ صاحب کارت {card_owner_agent_id}: {e}")

        if sent_to_admin:
            for acc_id in ACCOUNTANT_IDS:
                with contextlib.suppress(Exception):
                    await context.bot.send_photo(chat_id=acc_id, photo=photo_id, caption=f"🧾 <b>[رونوشت حسابداری - فیش جدید]</b>\n\n👤 نماینده: {esc(agent_name)} (کد: {agent_id})\n💰 مبلغ: {int(amount):,} تومان\n📅 تاریخ: {date_str}", parse_mode="HTML")
            await update.message.reply_text("✅ رسید شما با موفقیت دریافت شد و برای مدیریت ارسال گردید. پس از تایید، حساب شما شارژ خواهد شد.")
        else:
            await update.message.reply_text("✅ رسید شما ثبت شد و در صف بررسی مدیریت قرار گرفت؛ ممکن است ارسال آنی به مدیریت با تاخیر مواجه شود. پس از تایید، حساب شما شارژ خواهد شد.")
        safe_clear_context(context)

    # 📤 ادمین دارد عکس رسید واریزِ یک درخواست برداشت را برای همان نماینده ارسال می‌کند
    elif state == 'ADMIN_SEND_RECEIPT_PHOTO' and role == 'admin':
        req_id = context.user_data.get('pending_receipt_req_id')
        req = await asyncio.to_thread(_db_get_withdrawal_request, req_id) if req_id else None
        if not req or req[5] != 'pending':
            await update.message.reply_text("❌ این درخواست دیگر معتبر نیست (شاید قبلاً پردازش یا لغو شده)."); safe_clear_context(context); return
        _, a_id, amount, card, full_name, status, created_at = req
        agent_info = await asyncio.to_thread(_db_get_agent_info, a_id)
        agent_chat_id = agent_info[8] if agent_info and len(agent_info) > 8 else None
        photo_id = update.message.photo[-1].file_id
        sent_ok = False
        if agent_chat_id:
            with contextlib.suppress(Exception):
                await context.bot.send_photo(
                    chat_id=agent_chat_id, photo=photo_id,
                    caption=f"🧾 <b>رسید واریز درخواست برداشت شما</b>\n\n💰 مبلغ واریزشده: {int(amount):,} تومان\n👤 نام: {esc(full_name)}\n💳 کارت: <code>{esc(card)}</code>\n\n✅ این درخواست تکمیل شد.",
                    parse_mode="HTML")
                sent_ok = True
        await asyncio.to_thread(_db_mark_withdrawal_done, req_id)
        safe_clear_context(context)
        if sent_ok:
            await update.message.reply_text(f"✅ رسید برای «{esc(agent_info[0]) if agent_info else a_id}» ارسال شد و درخواست #{req_id} تکمیل‌شده علامت خورد.", parse_mode="HTML")
        else:
            await update.message.reply_text(f"⚠️ نماینده هنوز از طریق ربات وارد نشده (chat_id ندارد)؛ رسید ارسال نشد اما درخواست #{req_id} تکمیل‌شده علامت خورد.")

# ==========================================
# 🔘 هندلر جامع کالبک‌های شیشه‌ای (Callback)
# ==========================================
async def _render_udpgw_panel(query):
    cu = await asyncio.to_thread(_db_get_setting, 'udpgw_port', '7300')
    tdns = (await asyncio.to_thread(_db_get_setting, 'udpgw_transparent_dns', '1')) == '1'
    try:
        port_i = int(cu)
    except Exception:
        port_i = 7300
    # 🔍 چک زندهٔ محلی: چون خودِ ربات روی همین سرور اجرا می‌شود، یک اتصال TCP سریع به
    # 127.0.0.1:udpgw_port دقیقاً همان چیزی را می‌سنجد که ادمین قبلاً باید دستی با
    # «ss -lunp | grep badvpn» چک می‌کرد.
    ok, err = await _tcp_health_check('127.0.0.1', port_i, timeout=3)
    status_line = f"🟢 هم‌اکنون در حال گوش‌دادن است" if ok else f"🔴 هیچ پاسخی نمی‌دهد (<code>{esc(err)}</code>)"
    kb = [[InlineKeyboardButton("🔍 تست دوباره", callback_data="udpgw_test")],
          [InlineKeyboardButton(("✅ " if tdns else "☐ ") + "Transparent DNS", callback_data="udpgw_toggle_dns")],
          [InlineKeyboardButton("✏️ تغییر پورت", callback_data="udpgw_edit_port")],
          [InlineKeyboardButton("🔙 بازگشت", callback_data="srv_menu_back")]]
    await query.edit_message_text(
        f"🔌 <b>تنظیمات UDPGW</b>\n\n"
        f"پورت فعلی: <code>{port_i}</code>\n"
        f"وضعیت زنده: {status_line}\n"
        f"Transparent DNS: {'فعال ✅' if tdns else 'غیرفعال ☐'}\n\n"
        f"این پورت باید دقیقاً همان پورتی باشد که سرویس <code>badvpn-udpgw</code> روی سرور با آن اجرا "
        f"شده — وگرنه کاربرهایی که برای بازی/تماس صوتی‌تصویری به فوروارد UDP نیاز دارند دچار مشکل "
        f"می‌شوند، حتی اگر خودِ تونل SSH/TLS بدون مشکل وصل شود.",
        parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))

async def _render_host_pool_panel(query):
    await asyncio.to_thread(_db_sync_host_pool)
    pool = await asyncio.to_thread(_db_get_host_pool)
    port_map = await asyncio.to_thread(_db_get_host_ssh_port_map)
    fastest_host = await asyncio.to_thread(_db_get_fastest_active_host)
    lines = []
    kb = []
    for host, active, fails, last_check, last_status, disabled_reason, disabled_at, is_default, avg_latency_ms, added_at, is_standby in pool:
        icon = "🟢" if active else "🔴"
        star = " ⭐ (پیش‌فرض سیستم)" if is_default else ""
        standby_badge = " 🅢 (Standby)" if is_standby else ""
        # 🆕 «کدام VPS سرعتش بهتره»: تاخیر اتصال TCP (میانگین هموارشده) کنار وضعیت هر IP نشان داده
        # می‌شود؛ سریع‌ترین IP فعال هم با 🏆 مشخص می‌شود تا مقایسه با چشم هم ساده باشد.
        trophy = " 🏆" if (active and host == fastest_host) else ""
        latency_txt = f" — ⚡ {avg_latency_ms:.0f}ms{trophy}" if (active and avg_latency_ms is not None) else ""
        host_port = port_map.get(host, 22)
        line = f"{icon} <code>{esc(host)}:{host_port}</code>{star}{standby_badge}{latency_txt} — {esc(last_status or 'بررسی‌نشده')}"
        if last_check: line += f"\n   ⏱ آخرین بررسی: {esc(last_check)}"
        if not active and disabled_reason: line += f"\n   🚫 غیرفعال از: {esc(disabled_at)} ({esc(disabled_reason)})"
        # 🆕 اگر هنوز داخل دورهٔ مهلت تازه‌افزوده‌شدن است، همین‌جا شفاف نشان می‌دهیم — وگرنه
        # «بررسی‌نشده» تنها می‌تواند گیج‌کننده باشد (چرا هنوز تست نشده؟).
        if active and added_at:
            try:
                age_minutes = (datetime.now() - datetime.strptime(added_at, "%Y-%m-%d %H:%M:%S")).total_seconds() / 60
                remaining = HOST_HEALTH_GRACE_PERIOD_MINUTES - age_minutes
                if remaining > 0:
                    line += f"\n   ⏳ در دورهٔ مهلت (تا {remaining:.0f} دقیقهٔ دیگر پایش خودکار نمی‌شود)"
            except ValueError:
                pass
        lines.append(line)
        if active:
            row = [InlineKeyboardButton(f"🚫 بلاک کن: {host}", callback_data=f"hpblk_{host}")]
            kb.append(row)
            if not is_default:
                kb.append([InlineKeyboardButton(f"⭐ پیش‌فرض کل سیستم کن: {host}", callback_data=f"hpdef_{host}")])
            kb.append([InlineKeyboardButton(f"📍 دامنهٔ ثابت را به این IP بزن", callback_data=f"hpdns_{host}")])
            # 🆕 Standby (بندِ ۴): این Edge می‌تواند عمداً بدونِ مشتریِ فعال نگه داشته شود تا در
            # Failover، کاربرانِ یک Edgeِ فیلترشده رویش بازسازی شوند.
            kb.append([InlineKeyboardButton(
                "◽️ برداشتنِ Standby" if is_standby else "🅢 علامت‌گذاری به‌عنوانِ Standby",
                callback_data=f"hpstandby_{host}")])
            kb.append([InlineKeyboardButton(f"🗑 حذف کامل: {host}", callback_data=f"hpdelconfirm_{host}")])
        else:
            kb.append([InlineKeyboardButton(f"✅ تست و فعال‌سازی مجدد: {host}", callback_data=f"hpact_{host}")])
            kb.append([InlineKeyboardButton(f"🗑 حذف کامل: {host}", callback_data=f"hpdelconfirm_{host}")])
    # 🆕 اگر سریع‌ترین IP فعال از قبل پیش‌فرض نیست، یک دکمهٔ اختصاصی برای سوییچ سریع نشان داده می‌شود
    # (این سوییچ کاملاً دستی/به‌انتخاب ادمین است — خودکار سوییچ نمی‌کنیم تا صرفِ نوسان لحظه‌ایِ تاخیر
    # باعث جابه‌جایی مکرر و آزاردهندهٔ مشتریانِ درحال‌اتصال نشود).
    if fastest_host:
        fastest_is_default = any(p[0] == fastest_host and p[7] for p in pool)
        if not fastest_is_default:
            kb.insert(0, [InlineKeyboardButton(f"🏆 پیش‌فرض = سریع‌ترین ({fastest_host})", callback_data=f"hpdef_{fastest_host}")])
    kb.append([InlineKeyboardButton("⚡ تست سرعت همه IPها (Speed Test)", callback_data="hp_speedtest_all")])
    kb.append([InlineKeyboardButton("➕ افزودن IP جدید به استخر", callback_data="hp_add")])
    kb.append([InlineKeyboardButton("🚀 افزودن Edge جدید (VPS از قبل‌خریداری‌شده)", callback_data="hp_addedge")])
    kb.append([InlineKeyboardButton("🌍 دامنهٔ ثابت + Cloudflare", callback_data="hp_cf_settings")])
    auto_failover_on = (await asyncio.to_thread(_db_get_setting, 'auto_failover_mode', '0')) == '1'
    kb.append([InlineKeyboardButton(
        "🔴 خاموش‌کردنِ حالتِ خودکارِ Failover" if auto_failover_on else "🟢 روشن‌کردنِ حالتِ خودکارِ Failover",
        callback_data="hp_failover_toggle")])
    kb.append([InlineKeyboardButton("🔙 بازگشت", callback_data="ipsvc_menu")])
    cf_cfg = await asyncio.to_thread(_cf_get_config)
    if _cf_configured(cf_cfg):
        dns_line = (f"\n\n🌍 دامنهٔ ثابت مشتریان: <code>{esc(cf_cfg['public_domain'])}</code>"
                    f"\n📍 الان به این IP اشاره می‌کند: <code>{esc(cf_cfg['dns_current_ip'] or 'هنوز ست نشده')}</code>")
    else:
        dns_line = ("\n\n⚠️ دامنهٔ ثابت هنوز تنظیم نشده — مشتریان مستقیم IP خام می‌بینند. "
                     "برای فعال‌سازی سوییچ خودکار، روی «🌍 دامنهٔ ثابت + Cloudflare» بزنید.")
    # 🆕 وضعیتِ Failover (جایگزینِ وضعیتِ قدیمیِ Self-Heal کلودزی): این پنل محلِ مدیریتِ کلِ
    # استخر Edgeهاست، پس همین‌جا شفاف نشان می‌دهیم که اگر یک Edge فیلتر شود چه اتفاقی می‌افتد.
    standby_count = len(await asyncio.to_thread(_db_get_standby_hosts))
    if auto_failover_on and standby_count > 0:
        cz_line = f"\n\n🤖 Failoverِ خودکار: <b>فعال</b> ✅ — {standby_count} Standbyِ سالم آماده."
    elif auto_failover_on:
        cz_line = "\n\n⚠️ Failoverِ خودکار فعال است ولی هیچ Standbyِ سالمی ثبت نشده — عملاً فقط دامنه روی Core می‌ماند."
    elif standby_count > 0:
        cz_line = f"\n\nℹ️ Failoverِ دستی: {standby_count} Standby آمادهٔ فعال‌سازیِ دستی از پنل ادمین است."
    else:
        cz_line = "\n\nℹ️ هنوز هیچ Standbyی علامت‌گذاری نشده — در صورتِ فیلترشدنِ یک Edge، دامنه فقط روی Core باقی می‌ماند."
    body = "\n\n".join(lines) if lines else "هیچ IP ای هنوز در استخر پایش ثبت نشده."
    await query.edit_message_text(
        f"🛡 <b>وضعیت پایش سلامت IPها</b>\n\n{body}{dns_line}{cz_line}\n\n"
        f"🟢 = فعال و در حال سرویس‌دهی | 🔴 = غیرفعال (خودکار یا دستی) | ⚡ = تاخیر اتصال (هرچه کمتر بهتر) | 🏆 = سریع‌ترین فعال\n"
        f"می‌توانید هر IP سالم را دستی «بلاک» کنید (مثلاً وقتی مشتری گزارش فیلترشدن داده) یا یک IP "
        f"غیرفعال را دوباره تست و فعال کنید.", reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")

async def _host_has_working_persistent_key(host, port=22, timeout=8):
    """🆕 تست سریع (بدون اجرای هیچ عملیاتی): آیا همین الان می‌شود با کلید دائمی، بدون رمز،
    روی این هاست لاگین کرد؟ برای نمایشِ ✅/❌ روی دکمهٔ «نصب دسترسی دائمی SSH» استفاده می‌شود."""
    if paramiko is None or not os.path.exists(DO_SSH_KEY_PATH):
        return False
    def _sync():
        ssh = None
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            pkey = paramiko.Ed25519Key.from_private_key_file(DO_SSH_KEY_PATH)
            ssh.connect(host, port=port, username='root', pkey=pkey, timeout=timeout, banner_timeout=timeout)
            return True
        except Exception:
            return False
        finally:
            if ssh is not None:
                try:
                    ssh.close()
                except Exception:
                    pass
    return await asyncio.to_thread(_sync)


async def _render_server_status_panel(query, context):
    """رندر پنل وضعیت و نقش سرورها (Core/Edge)"""
    core_ip = await asyncio.to_thread(_get_core_public_ip_cached)
    await asyncio.to_thread(_db_sync_host_pool)
    pool = await asyncio.to_thread(_db_get_host_pool)
    port_map = await asyncio.to_thread(_db_get_host_ssh_port_map)

    # 🆕 اضافه شدن متغیرهای مربوط به تشخیص Edge فعال (دامنه)
    active_edge_ip = await asyncio.to_thread(_db_get_setting, 'dns_current_ip', '')
    default_edge = await asyncio.to_thread(_db_get_default_host)

    # 🔧 گارد ایمنی: اگر IP خودِ Core قابل‌تشخیص نباشد...
    if not core_ip:
        kb = [[InlineKeyboardButton("🔙 بازگشت", callback_data="srv_menu_back")]]
        await query.edit_message_text(
            "⚠️ <b>نمی‌توانم IP عمومی سرور Core را تشخیص بدهم.</b>\n\n"
            "چون این پنل دکمه‌های حساس «ارتقا/تنزل» دارد، برای جلوگیری از نمایش اشتباهِ نقش هر "
            "سرور، فعلاً باز نمی‌شود. لطفاً اول یک‌بار از «🚀 افزودن Edge جدید» استفاده کنید (که "
            "IP عمومی Core را خودکار تشخیص و ذخیره می‌کند)، سپس دوباره امتحان کنید.",
            reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
        return

    lines = [f"🖥 <b>وضعیت و نقش سرورها</b>\n"]
    lines.append(f"🏠 <b>سرور Core فعلی:</b> <code>{esc(core_ip)}</code>\n")

    # چکِ موازیِ وضعیتِ کلیدِ دائمی برای همهٔ Edgeها هم‌زمان
    edge_hosts = [(host, port_map.get(host, 22)) for host, *_ in pool if host != core_ip]
    if edge_hosts:
        key_check_results = await asyncio.gather(
            *[_host_has_working_persistent_key(h, p) for h, p in edge_hosts]
        )
        key_status = {h: ok for (h, p), ok in zip(edge_hosts, key_check_results)}
    else:
        key_status = {}

    kb = []
    for host, active, fails, last_check, last_status, disabled_reason, disabled_at, is_default, avg_latency_ms, added_at, _is_standby in pool:
        if host == core_ip:
            role_icon = "👑 <b>[Core]</b>"
            btn_row = [
                InlineKeyboardButton("📉 تنزل به Edge", callback_data=f"srv_demote_{host}"),
                InlineKeyboardButton("⚡ بهینه‌سازی سرعت", callback_data=f"srv_optimize_{host}")
            ]
            kb.append(btn_row)
        else:
            # 🆕 تشخیص اینکه آیا این Edge در حال حاضر رله فعال (متصل به دامنه) است یا خیر
            btn_row1 = []
            if host == active_edge_ip or host == default_edge:
                role_icon = "🎯 <b>[رله فعال - متصل به دامنه]</b>"
            else:
                role_icon = "⚪️ [آماده به کار - Standby]"
                # 🆕 دکمه شیفت ترافیک فقط برای سرورهای آماده به کار (Standby) نشان داده می‌شود
                btn_row1 = [InlineKeyboardButton("🎯 تنظیم به عنوان رله فعال", callback_data=f"srv_mkactive_{host}")]

            btn_row2 = [
                InlineKeyboardButton("🚀 ارتقا به Core", callback_data=f"srv_promote_{host}"),
                InlineKeyboardButton("🔄 آپدیت Endpoint", callback_data=f"srv_update_ep_{host}"),
                InlineKeyboardButton("⚡ بهینه‌سازی سرعت", callback_data=f"srv_optimize_{host}")
            ]
            
            # ✅ یعنی همین الان بدونِ رمز با کلیدِ دائمی وصل می‌شه
            key_ok = key_status.get(host, False)
            key_label = ("✅" if key_ok else "❌") + " نصب دسترسی دائمی SSH"
            key_row = [InlineKeyboardButton(key_label, callback_data=f"srv_installkey_{host}")]

            # اضافه کردن دکمه‌ها به کیبورد
            if btn_row1:
                kb.append(btn_row1)
            kb.append(btn_row2)
            kb.append(key_row)
        
        status_icon = "🟢" if active else "🔴"
        lines.append(f"{status_icon} <code>{esc(host)}:{port_map.get(host, 22)}</code> {role_icon}")
        
    kb.append([InlineKeyboardButton("🔙 بازگشت", callback_data="srv_menu_back")])
    
    await _safe_edit_or_send(
        query,
        "\n".join(lines) + "\n\n"
        "💡 <b>راهنما:</b>\n"
        "- <b>Core:</b> سرور اصلی که دیتابیس و ربات روی آن اجرا می‌شوند.\n"
        "- <b>Edge:</b> سرورهای رله که ترافیک را به Core منتقل می‌کنند.\n"
        "- <b>رله فعال:</b> سرور Edge ای که در حال حاضر ترافیک دامنه روی آن تنظیم شده است.\n"
        "- <b>ارتقا:</b> تبدیل یک Edge به Core جدید.\n"
        "- <b>تنزل:</b> تبدیل Core قدیمی به Edge بعد از جابه‌جایی.",
        reply_markup=InlineKeyboardMarkup(kb),
        parse_mode="HTML"
    )

# ============================================================================
# 🚀 خودکارسازی «ارتقا (Promote)»: قبلاً ادمین باید دستی ۶ فایل را از Core به Edge
# مقصد منتقل می‌کرد. حالا خودِ ربات همه را می‌سازد و از طریق همان اتصال SSH آپلود
# می‌کند — ادمین فقط رمز روت مقصد را می‌دهد.
# ============================================================================
def _prepare_migration_files_locally():
    """
    روی خودِ Core (محلی) اجرا می‌شود: ۶ فایل لازم برای promote_edge_to_core.sh را در یک
    پوشهٔ موقت می‌سازد و مسیرش را برمی‌گرداند.
    خروجی: (ok: bool, msg: str, tmp_dir: str|None)
    """
    tmp_dir = tempfile.mkdtemp(prefix="core_migration_")

    # ۱) کلید خصوصی WireGuard — الزامی
    core_priv_src = "/etc/wireguard/core_private.key"
    if not os.path.exists(core_priv_src):
        return False, f"❌ فایل کلید خصوصی وایرگارد پیدا نشد: {core_priv_src}\nیعنی این سرور خودش هنوز به‌عنوان Core راه‌اندازی نشده.", None
    shutil.copy2(core_priv_src, os.path.join(tmp_dir, "core_private.key"))

    # ۲) بلاک‌های Peer از wg0.conf فعلی — الزامی
    wg_conf_src = "/etc/wireguard/wg0.conf"
    if not os.path.exists(wg_conf_src):
        return False, f"❌ فایل {wg_conf_src} پیدا نشد.", None
    ok, out, _ = _shell_capture(f"awk '/^\\[Peer\\]/{{f=1}} f' {shlex.quote(wg_conf_src)}")
    if not ok:
        return False, f"❌ استخراج بلاک‌های Peer از wg0.conf شکست خورد: {out}", None
    with open(os.path.join(tmp_dir, "wg0.conf.peers"), "w") as f:
        f.write(out)

    # ۳) دیتابیس ربات — الزامی. با sqlite3 backup API (نه کپی خام فایل) چون دیتابیس ممکن است
    # هم‌زمان در حال نوشته‌شدن باشد (WAL) و کپی مستقیم فایل می‌تواند snapshot ناقص/خراب بدهد.
    db_src = os.path.abspath(DB_PATH)
    if not os.path.exists(db_src):
        return False, f"❌ فایل دیتابیس ربات پیدا نشد: {db_src}", None
    try:
        src_conn = sqlite3.connect(db_src)
        dst_conn = sqlite3.connect(os.path.join(tmp_dir, "master_bot.db"))
        with dst_conn:
            src_conn.backup(dst_conn)
        src_conn.close(); dst_conn.close()
    except Exception as e:
        return False, f"❌ گرفتن نسخهٔ سالم (backup) از دیتابیس شکست خورد: {e}", None

    # ۴) gost_config.yaml — اختیاری (لایهٔ TLS/WSS)
    gost_src = "/etc/gost/config.yaml"
    if os.path.exists(gost_src):
        shutil.copy2(gost_src, os.path.join(tmp_dir, "gost_config.yaml"))

    # ۵) گواهی‌های Let's Encrypt — اختیاری
    if os.path.isdir("/etc/letsencrypt"):
        ok, out, _ = _shell_capture(f"tar -czf {shlex.quote(os.path.join(tmp_dir, 'letsencrypt.tar.gz'))} -C /etc letsencrypt")
        if not ok:
            log.warning("ساخت letsencrypt.tar.gz شکست خورد (نادیده گرفته می‌شود): %s", out)

    # ۶) گواهی‌های Cloudflare (اگر لایهٔ wss/CF فعال است) — اختیاری
    if os.path.isdir("/etc/ssl/cf"):
        ok, out, _ = _shell_capture(f"tar -czf {shlex.quote(os.path.join(tmp_dir, 'cf_certs.tar.gz'))} -C /etc ssl/cf")
        if not ok:
            log.warning("ساخت cf_certs.tar.gz شکست خورد (نادیده گرفته می‌شود): %s", out)

    # 🐛🔧 رفع باگ واقعی: این چهار فایلِ اختیاری هیچ‌وقت اینجا ساخته نمی‌شدند، در حالی که
    # promote_edge_to_core.sh صریحاً دنبالشان می‌گردد و نبودشان باعثِ چاپِ ⚠️/❌ در خروجی می‌شود —
    # حتی وقتی خودِ اسکریپت کاملاً موفق (exit 0) تمام شده. نبودشان الان دیگر «موفقیت» را خراب
    # نمی‌کند (چون معیار موفقیت را هم در ادامه به exit_status تغییر دادیم)، اما وجودشان باعث
    # می‌شود سرویس‌های UDPGW/gost و دسترسی به Edgeها هم واقعاً روی Core جدید کار کنند، نه فقط
    # اسکریپت «بدون خطا» تمام شود.

    # ۷) باینریِ gost — اختیاری (بدونش لایهٔ TLS/WSS روی Core جدید غیرفعال می‌ماند)
    gost_bin_src = "/usr/local/bin/gost"
    if os.path.exists(gost_bin_src):
        with contextlib.suppress(Exception):
            shutil.copy2(gost_bin_src, os.path.join(tmp_dir, "gost_bin"))

    # ۸) باینریِ badvpn-udpgw — اختیاری (بدونش سرویسِ UDPGW روی Core جدید نصب نمی‌شود)
    udpgw_bin_src = "/usr/local/bin/badvpn-udpgw"
    if os.path.exists(udpgw_bin_src):
        with contextlib.suppress(Exception):
            shutil.copy2(udpgw_bin_src, os.path.join(tmp_dir, "badvpn_udpgw_bin"))

    # ۹) کلیدِ SSH دائمیِ ربات برای مدیریتِ خودکارِ Edgeها — اختیاری (بدونش ربات روی Core جدید
    # نمی‌تواند به Edgeهای دیگر بدون رمز وصل شود)
    if os.path.exists(DO_SSH_KEY_PATH):
        with contextlib.suppress(Exception):
            shutil.copy2(DO_SSH_KEY_PATH, os.path.join(tmp_dir, "edge_provision_ed25519"))
        pub_src = DO_SSH_KEY_PATH + ".pub"
        if os.path.exists(pub_src):
            with contextlib.suppress(Exception):
                shutil.copy2(pub_src, os.path.join(tmp_dir, "edge_provision_ed25519.pub"))

    # ۱۰) وضعیتِ لاگینِ ادمین/نمایندگان — اختیاری (بدونش همه باید یک‌بار دوباره وارد شوند)
    persistence_src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bot_persistence.pickle")
    if os.path.exists(persistence_src):
        with contextlib.suppress(Exception):
            shutil.copy2(persistence_src, os.path.join(tmp_dir, "bot_persistence.pickle"))

    # 🆕 ۱۱) اسنپ‌شاتِ کاملِ محیط: تا اینجا فقط یک لیستِ ثابت از فایل‌های شناخته‌شده منتقل می‌شد.
    # ادمین ممکن است خودش دستی اسکریپت/یادداشت/فایلِ کمکیِ جدید اضافه کرده باشد، یا یکی از
    # همین اسکریپت‌ها را خودش ادیت کرده باشد — که با لیستِ ثابتِ بالا هیچ‌کدام منتقل نمی‌شدند.
    # این تارِ کاملِ BOT_DIR (پیش‌فرض /root) هر همچین چیزی را هم می‌گیرد. عمداً از این تار کنار
    # گذاشته می‌شوند: venv/ (حجیم و بازتولیدشدنی — با pip install دوباره ساخته می‌شود)،
    # نسخه‌های .bak قدیمی، __pycache__، nvlbot_standby (پوشهٔ استیجینگِ مخصوصِ Edgeها، نه Core)،
    # و master_bot.db/bot_persistence.pickle (که چند خط بالاتر با روشِ اختصاصیِ امن‌تری
    # کپی شده‌اند و اینجا دوباره‌کاری/تناقض ایجاد می‌کردند).
    bot_dir = os.path.dirname(os.path.abspath(__file__))
    snapshot_dest = os.path.join(tmp_dir, "root_full_snapshot.tar.gz")
    exclude_args = " ".join(
        f"--exclude={shlex.quote(p)}" for p in [
            "venv", "venv.bak.*", "__pycache__", "*.pyc", ".cache",
            "nvlbot_standby", "core_migration", "master_bot.db*",
            "bot_persistence.pickle*", "*.bak.*",
            # ---- لیست سیاه تقویت‌شده ----
            "*.log", "*.log.*", "*.tar.gz", "*.zip", "*.rar", "*.gz", "*.7z",
            "*.db", "*.sqlite", "*.db-shm", "*.db-wal", "*.iso",
            ".npm", ".local", ".config", ".gnupg", "snap", ".ssh"
        ]
    )
    ok, out, _ = _shell_capture(
        f"tar -czf {shlex.quote(snapshot_dest)} {exclude_args} -C {shlex.quote(os.path.dirname(bot_dir))} "
        f"{shlex.quote(os.path.basename(bot_dir))}",
        timeout=120,
    )
    if not ok:
        log.warning("ساخت root_full_snapshot.tar.gz شکست خورد (نادیده گرفته می‌شود، فقط لیستِ ثابت منتقل می‌شود): %s", out)

    return True, "", tmp_dir


def _shell_capture(cmd: str, timeout: int = 60):
    """اجرای همزمان (blocking) یک دستور شل محلی و برگرداندن (ok, stdout+stderr, returncode). فقط
    برای استفاده داخل توابعی که خودشان از قبل در thread جدا اجرا می‌شوند (نه مستقیم در event loop).
    🐛🔧 timeout حالا پارامتر است (پیش‌فرض همان ۶۰ ثانیهٔ قبلی) — چون بعضی دستورها (مثل اجرای
    محلیِ demote_core_to_edge.sh که خودش apt-get install wireguard دارد) می‌توانند به‌راحتی از
    ۶۰ ثانیه بیشتر طول بکشند و timeout ثابتِ قبلی باعثِ قطع‌شدنِ نیمه‌کاره‌شان می‌شد."""
    try:
        r = subprocess.run(cmd, shell=True, executable="/bin/bash", capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, (r.stdout + r.stderr).strip(), r.returncode
    except Exception as e:
        return False, str(e), -1


def _check_tcp_reachable(host: str, port: int, timeout: float = 4.0) -> bool:
    """
    🩺 تست ساده و سریعِ «آیا این host:port واقعاً از بیرون قابل‌اتصاله؟» — بدون احراز هویت،
    فقط یک TCP handshake خام. برای پیش‌بینیِ خطاهای paramiko («Unable to connect to port
    X») قبل از این‌که واقعاً امتحان کنیم و کاربر مجبور بشه یه پیام خطای خام و گنگ ببینه.
    """
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:
        return False


async def _run_promote_with_migration(ip, password, cust_port, chat_id, context):
    """
    🚀 نسخهٔ خودکار «ارتقا»: قبل از اجرای promote_edge_to_core.sh روی Edge مقصد، ابتدا هر ۶ فایل
    لازم را خودش (بدون دخالت دستی ادمین) از Core می‌سازد و از طریق همان اتصال SSH به مسیر
    /root/core_migration روی مقصد آپلود می‌کند، سپس اسکریپت را اجرا می‌کند.
    🆕 خروجی: True/False — موفقیت کلی عملیات، تا فراخوان (مثلاً تنزل خودکار Core قبلی) بداند
    آیا ادامه دادن اصلاً معنی دارد یا نه.
    """
    if paramiko is None:
        await context.bot.send_message(chat_id, "❌ کتابخانه paramiko نصب نیست.")
        return False

    script_path = os.path.join(os.path.dirname(__file__), "promote_edge_to_core.sh")
    if not os.path.exists(script_path):
        await context.bot.send_message(chat_id, f"❌ فایل اسکریپت پیدا نشد: <code>{esc(script_path)}</code>", parse_mode="HTML")
        return False

    msg = await context.bot.send_message(chat_id, "⏳ مرحلهٔ ۱/۳ — آماده‌سازی فایل‌های مهاجرت روی Core...", parse_mode="HTML")

    ok, err, tmp_dir = await asyncio.to_thread(_prepare_migration_files_locally)
    if not ok:
        await msg.edit_text(err, parse_mode="HTML")
        return False

    # 🐛🔧 رفع باگ «رمز روت قبول نمی‌شه»: قبلاً اتصال SSH این‌جا همیشه فقط پورت پیش‌فرض ۲۲ رو
    # امتحان می‌کرد. اگه پورت SSH این IP خاص قبلاً (مثلاً با «تغییر واقعی پورت SSH») عوض شده
    # بود، اتصال با ۲۲ همیشه شکست می‌خورد — با رمز کاملاً درست، بازم رد می‌شد چون اصلاً پورت
    # درست رو امتحان نمی‌کرد. الان هم ۲۲ (پورت مدیریتیِ استاندارد) هم پورتِ ثبت‌شدهٔ واقعیِ این
    # IP در دیتابیس، هر دو امتحان می‌شن.
    known_port = await asyncio.to_thread(_db_get_host_ssh_port, ip, 22)
    candidate_ports = [22] + ([known_port] if known_port != 22 else [])

    try:
        await msg.edit_text(f"⏳ مرحلهٔ ۲/۳ — آپلود فایل‌ها به <code>{esc(ip)}</code>...", parse_mode="HTML")

        # 🐛🔧 فیکس «هنگِ ابدیِ ربات در مرحلهٔ ۲/۳»: قبلاً هیچ‌جای این تابع (نه روی اتصالِ SSH،
        # نه روی sftp.put، نه روی کل thread) یک سقفِ زمانیِ واقعی نبود. اگه شبکه بینِ Core و
        # مقصد (رویِ مسیرِ فیلترشده) وسطِ آپلودِ یه فایلِ حجیم (مثلِ باینریِ gost) گیر می‌کرد یا
        # کند می‌شد، sftp.put برای همیشه بلاک می‌موند — و چون asyncio.to_thread هیچ‌جا با
        # asyncio.wait_for پیچیده نشده بود، ربات هیچ‌وقت نمی‌فهمید باید timeout بده و برگرده؛
        # فقط ساکت می‌موند (دقیقاً همون «هنگِ کاملِ ربات» که مشاهده شد). الان: (۱) روی خودِ
        # ssh.connect علاوه‌بر connect-timeout، banner_timeout و auth_timeout هم گذاشته شده،
        # (۲) بلافاصله بعدِ اتصال یه keepalive فعال شده تا کانکشنِ مرده زودتر شناسایی بشه،
        # (۳) کانالِ SFTP هم settimeout می‌گیره تا put روی یه فایلِ گیرکرده ابدی بلاک نمونه،
        # (۴) از بیرون، کل ۲/۳ + ۳/۳ با یه سقفِ سختِ UPLOAD_RUN_TIMEOUT (۱۰ دقیقه) پیچیده شده —
        # اگه هرجایی (حتی جایی که پیش‌بینی نکرده باشیم) گیر کرد، بعد از این سقف ربات کنترل رو
        # پس می‌گیره و یه خطای روشن می‌ده، به‌جای اینکه برای همیشه بی‌پاسخ بمونه.
        SFTP_CHANNEL_TIMEOUT = 90    # ثانیه — سقفِ سکوت روی هر عملیاتِ SFTP (نه کلِ آپلود)
        UPLOAD_RUN_TIMEOUT = 600     # ثانیه — سقفِ کلیِ کل عملیاتِ آپلود + اجرای اسکریپت روی مقصد

        def _upload_and_run():
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                connect_errs = []
                connected = False
                for cp in candidate_ports:
                    try:
                        ssh.connect(ip, port=cp, username='root', password=password, timeout=15,
                                    banner_timeout=20, auth_timeout=20,
                                    look_for_keys=False, allow_agent=False)
                        connected = True
                        break
                    except Exception as ce:
                        connect_errs.append(f"پورت {cp}: {ce}")
                if not connected:
                    return False, "اتصال ناموفق — " + " | ".join(connect_errs), None, []

                transport = ssh.get_transport()
                if transport is not None:
                    transport.set_keepalive(10)  # 🆕 تشخیصِ زودهنگامِ کانکشنِ مرده/گیرکرده

                remote_migration_dir = "/root/core_migration"
                ssh.exec_command(f"mkdir -p {remote_migration_dir}", timeout=30)[1].channel.recv_exit_status()

                sftp = ssh.open_sftp()
                sftp.get_channel().settimeout(SFTP_CHANNEL_TIMEOUT)  # 🆕 دیگه put ابدی بلاک نمی‌مونه
                uploaded = []
                for fname in os.listdir(tmp_dir):
                    sftp.put(os.path.join(tmp_dir, fname), f"{remote_migration_dir}/{fname}")
                    uploaded.append(fname)
                # اسکریپت خودش هم باید روی مقصد باشد
                remote_script = f"/root/{os.path.basename(script_path)}"
                sftp.put(script_path, remote_script)
                sftp.close()

                # 🆕 همان کلید عمومی دائمیِ Core را هم روی سرور تازه‌ارتقایافته نصب می‌کنیم (اگر
                # قبلاً نصب نشده باشد) — چون این سرور از این به بعد ممکن است دوباره Edge شود و
                # پایش CPU/RAM واقعی به همین کلید نیاز دارد.
                with contextlib.suppress(Exception):
                    _install_local_pubkey_on_open_ssh(ssh)

                cmd = f"chmod +x {remote_script} && bash {remote_script} {cust_port} {remote_migration_dir}"
                stdin, stdout, stderr = ssh.exec_command(cmd, timeout=300)
                out = stdout.read().decode(errors='replace')
                err_txt = stderr.read().decode(errors='replace')
                exit_status = stdout.channel.recv_exit_status()
                # 🧹 پاک‌سازی امنیتی: بعد از اجرای اسکریپت (که فایل‌ها را به مسیر دائمی‌شان مثل
                # /etc/wireguard کپی می‌کند)، نسخهٔ تکراری حاوی کلید خصوصی در core_migration
                # را از روی مقصد پاک می‌کنیم — چون اسکریپت با set -e متوقف می‌شود، این پاک‌سازی
                # را فقط وقتی انجام می‌دهیم که واقعاً با موفقیت کامل تمام شده باشد.
                if exit_status == 0:
                    ssh.exec_command(f"rm -rf {remote_migration_dir}", timeout=30)[1].channel.recv_exit_status()
                ssh.close()
                return exit_status == 0, out, err_txt, uploaded
            except Exception as e:
                return False, str(e), "", []
            finally:
                with contextlib.suppress(Exception):
                    ssh.close()

        try:
            ok2, out, err_txt, uploaded = await asyncio.wait_for(
                asyncio.to_thread(_upload_and_run), timeout=UPLOAD_RUN_TIMEOUT
            )
        except asyncio.TimeoutError:
            # 🆕 حتی اگه thread واقعاً هنوز درحالِ اجراست (leaked)، ربات دیگه منتظرش نمی‌مونه —
            # کنترل رو پس می‌گیره، به کاربر خبر می‌ده، و به کارِ عادیِ خودش ادامه می‌ده.
            await msg.edit_text(
                f"❌ ارتقای <code>{esc(ip)}</code> بعد از {UPLOAD_RUN_TIMEOUT} ثانیه بدون پاسخ موند "
                f"(احتمالاً شبکه بین Core و مقصد قطع/گیر کرده) — عملیات لغو شد. دوباره امتحان کنید.",
                parse_mode="HTML")
            return False
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)  # 🧹 پاک‌سازی فایل‌های موقت (حاوی کلید خصوصی!) روی Core

    if not ok2:
        # 🐛🔧 فیکس: قبلاً کل خروجیِ اسکریپت (که می‌تواند خیلی طولانی باشد) مستقیم توی پیام
        # می‌رفت و اگر از سقفِ ۴۰۹۶ کاراکترِ تلگرام رد می‌شد، خودِ ارسالِ همین پیامِ خطا
        # Message_too_long می‌داد و باعث می‌شد علتِ واقعیِ شکست هیچ‌وقت دیده نشود.
        combined = (out or "") + ("\n--- STDERR ---\n" + err_txt if err_txt else "")
        MAX_LEN = 3500
        if len(combined) > MAX_LEN:
            combined = "...(ابتدای خروجی بریده شد)...\n" + combined[-MAX_LEN:]
        await msg.edit_text(f"❌ <b>ارتقای {esc(ip)} ناموفق بود (در آپلود یا در اجرای اسکریپت):</b>\n<code>{esc(combined)}</code>", parse_mode="HTML")
        return False

    await msg.edit_text(f"⏳ مرحلهٔ ۳/۳ — اسکریپت روی <code>{esc(ip)}</code> اجرا شد. در حال ارسال نتیجه...", parse_mode="HTML")
    # 🐛🔧 رفع باگ واقعی: قبلاً معیارِ موفقیت از رویِ متنِ خروجی («✅» in out and «❌» not in out)
    # تشخیص داده می‌شد. چون خودِ promote_edge_to_core.sh برایِ فایل‌های اختیاریِ غایب هم ⚠️/❌
    # چاپ می‌کند (حتی وقتی با exit 0 کاملاً موفق تمام شده)، این معیار همیشه False برمی‌گشت و
    # به تبعِ آن، تنزلِ خودکارِ Core قبلی هیچ‌وقت اجرا نمی‌شد. معیارِ واقعی همان ok2 (که چند خط
    # بالاتر مستقیماً از exit_status==0 گرفته شده) است؛ اسکنِ متنی فقط برای اطلاع‌رسانیِ هشدارِ
    # غیربحرانی نگه داشته می‌شود، نه برای تصمیم‌گیریِ نهایی.
    success = ok2
    has_warning_markers = ("❌" in out) or ("⚠️" in out)
    report = f"✅ <b>ارتقای {esc(ip)} به Core به پایان رسید.</b>\n📦 فایل‌های منتقل‌شده: {', '.join(esc(u) for u in uploaded)}\n\n"
    if success and not has_warning_markers:
        report += "نتیجه: موفقیت‌آمیز ✌️ — خروجی کامل زیر را هم بررسی کنید.\n"
    elif success:
        report += "نتیجه: موفقیت‌آمیز (exit 0) ✌️ — ولی چند هشدارِ غیربحرانی هم در خروجی هست، بررسی کنید.\n"
    else:
        report += "⚠️ خروجی را با دقت بررسی کنید (ممکن است در یکی از مراحل خطا رخ داده باشد).\n"
    await context.bot.send_message(chat_id, report, parse_mode="HTML")
    full_out = out + ("\n--- STDERR ---\n" + err_txt if err_txt.strip() else "")
    if len(full_out) > 3000:
        with io.BytesIO(full_out.encode()) as f:
            f.name = "promote_output.txt"
            await context.bot.send_document(chat_id, document=f, caption="📄 خروجی کامل اسکریپت")
    else:
        await context.bot.send_message(chat_id, f"📄 <b>خروجی:</b>\n<code>{esc(full_out)}</code>", parse_mode="HTML")
    return success


async def _auto_demote_old_core(old_core_ip, new_core_ip, cust_port, gost_ports, chat_id, context):
    """
    🆕 ادامهٔ خودکارِ «ارتقا»: بلافاصله بعد از اینکه Edge مقصد با موفقیت به Core جدید تبدیل شد،
    همین‌جا و بدون نیاز به هیچ ورودی دیگری از ادمین، سرور Core قدیمی (که خودِ ربات همین الان
    رویش در حال اجراست) را به Edge تنزل می‌دهد.

    نکتهٔ مهم: چون این عملیات روی خودِ سروری اجرا می‌شود که ربات همین الان رویش زنده است،
    _run_remote_script این را به‌صورت خودکار به‌عنوان «اجرای محلی» تشخیص می‌دهد (چون old_core_ip
    با core_wg_public_ip فعلی یکی است) — یعنی هیچ رمز روتی هم لازم نیست.

    فقط *بعد* از موفقیتِ خودِ تنزل، تنظیم core_wg_public_ip را به IP سرور جدید تغییر می‌دهیم؛ اگر
    این ترتیب برعکس می‌شد، همین تابع قبل از اجرای دستور تنزل، خودش را «Edge غیر خودی» تشخیص
    می‌داد و به‌جای اجرای محلی، بی‌خودی دنبال SSH با رمز می‌گشت.
    """
    await context.bot.send_message(
        chat_id,
        f"🔄 ارتقا موفق بود؛ در حال تنزل خودکار Core قبلی (<code>{esc(old_core_ip)}</code>) به Edge...",
        parse_mode="HTML")

    script_file = os.path.join(os.path.dirname(__file__), "demote_core_to_edge.sh")
    # 🐛🔧 فیکس: demote_core_to_edge.sh دقیقاً 2 آرگومان می‌گیرد (NEW_CORE_IP و
    # CUSTOMER_SSH_PORT). قبلاً gost_ports هم اضافه می‌شد که چون خودش رشته‌ای چندتایی است، عملاً
    # به چند آرگومان جدا تبدیل می‌شد و اسکریپت را با خطای Usage همان اول متوقف می‌کرد.
    args_str = f"{new_core_ip} {cust_port}".strip()
    # password=None: چون هدف همان ماشین محلی است، _run_remote_script اصلاً به SSH نیاز پیدا نمی‌کند.
    demote_ok, demote_out, demote_err = await _run_remote_script(old_core_ip, None, script_file, args_str, chat_id, context, ssh_port=None)

    # 🐛🔧 فیکس: قبلاً نتیجهٔ اجرای اسکریپت اصلاً چک نمی‌شد -- یعنی حتی اگر تنزل واقعاً
    # شکست می‌خورد، دیتابیس بی‌قیدوشرط به‌روزرسانی می‌شد و طوری نشان می‌داد که انگار Core عوض شده،
    # درحالی‌که روی خودِ سرور قدیمی هیچ‌چیز واقعاً تغییر نکرده بود.
    if not demote_ok:
        await context.bot.send_message(
            chat_id,
            f"⚠️ تنزلِ خودکارِ Core قبلی شکست خورد -- اطلاعاتِ داخلی به‌روزرسانی نشد.\n"
            f"<code>{esc((demote_err or demote_out or '')[-2000:])}</code>",
            parse_mode="HTML")
        return

    # 🔧 از این به بعد، این ماشین یک Edge معمولی است — Core واقعی سرور جدید است. این تغییر باید
    # *بعد* از اجرای موفق اسکریپت تنزل ثبت شود.
    await asyncio.to_thread(_db_update_setting, 'core_wg_public_ip', new_core_ip)
    await asyncio.to_thread(_db_sync_host_pool)
    await asyncio.to_thread(_db_set_default_host, new_core_ip)
    await context.bot.send_message(
        chat_id,
        f"✅ Core قبلی هم به Edge تنزل یافت و اطلاعات داخلی ربات به‌روزرسانی شد. Core جدید سیستم: "
        f"<code>{esc(new_core_ip)}</code>",
        parse_mode="HTML")

    # 🐛🔧 فیکس: دامنهٔ ثابت (Cloudflare) هیچ‌وقت بعد از Promote خودکار سوییچ نمی‌شد --
    # مشتریانی که با دامنه (نه IP خام) وصل می‌شوند تا این فیکس همچنان به Core قدیمی می‌رفتند.
    cf_ok, cf_msg = await _cf_switch_public_domain(new_core_ip, app=context.application)
    if cf_ok:
        await context.bot.send_message(chat_id, f"🌍 دامنهٔ ثابت: {esc(cf_msg)}", parse_mode="HTML")

    # 🆕 آپدیت خودکار Endpoint روی همهٔ Edgeهای فعال دیگر (به‌جز خودِ Core جدید و Core قدیمی که
    # همین الان توسط demote_core_to_edge.sh مقدار Endpoint خودش را از قبل درست تنظیم کرده).
    # این کار پیش‌تر می‌بایست دستی، یکی‌یکی روی هر Edge با update_edge_endpoint.sh انجام می‌شد؛
    # از این پس بلافاصله بعد از Demote موفقِ Core قبلی، خودکار و پشتِ‌سرِهم انجام می‌شود.
    update_script = os.path.join(os.path.dirname(__file__), "update_all_edges_endpoint.sh")
    if os.path.exists(update_script):
        await context.bot.send_message(chat_id, "🔄 در حال آپدیت Endpoint روی بقیهٔ Edgeها...")

        def _run_update_all():
            _shell_capture(f"chmod +x {shlex.quote(update_script)}")
            return _shell_capture(f"bash {shlex.quote(update_script)} {shlex.quote(new_core_ip)}")

        ok_u, out_u, _ = await asyncio.to_thread(_run_update_all)
        report_u = "✅" if ok_u else "⚠️"
        await context.bot.send_message(
            chat_id,
            f"{report_u} <b>نتیجهٔ آپدیت Endpointها:</b>\n<code>{esc(out_u[-3000:])}</code>",
            parse_mode="HTML")
    else:
        await context.bot.send_message(
            chat_id,
            f"ℹ️ فایل <code>{esc(update_script)}</code> پیدا نشد — آپدیت Endpoint روی بقیهٔ Edgeها "
            f"باید دستی (یا با اجرای مستقیمِ همین اسکریپت روی Core) انجام شود.",
            parse_mode="HTML")



async def _send_remote_script_result(chat_id, context, ip, ok, out, err, msg=None):
    """نمایش نتیجهٔ اجرای اسکریپت (چه محلی چه از راه دور) — یک مسیر مشترک برای هر دو حالت."""
    if ok:
        report = f"✅ <b>اجرای اسکریپت روی {esc(ip)} به پایان رسید.</b>\n\n"
        if "✅" in out: report += "نتیجه: موفقیت‌آمیز ✌️\n"
        else: report += "⚠️ خروجی را بررسی کنید (ممکن است خطایی رخ داده باشد).\n"

        await context.bot.send_message(chat_id, report, parse_mode="HTML")
        if len(out) > 3000:
            with io.BytesIO(out.encode()) as f:
                f.name = "script_output.txt"
                await context.bot.send_document(chat_id, document=f, caption="📄 خروجی کامل اسکریپت")
        else:
            await context.bot.send_message(chat_id, f"📄 <b>خروجی:</b>\n<code>{esc(out)}</code>", parse_mode="HTML")
    else:
        await context.bot.send_message(chat_id, f"❌ <b>خطا در اجرا روی {esc(ip)}:</b>\n<code>{esc(out)}</code>", parse_mode="HTML")

    if msg is not None:
        try:
            await context.bot.delete_message(chat_id, msg.message_id)
        except Exception:
            pass


async def _run_remote_script(ip, password, script_path, args_str, chat_id, context, ssh_port=None):
    """اجرای اسکریپت روی سرور از راه دور از طریق SSH.
    🆕 اگر ssh_port صراحتاً داده شود (چون هر ویزارد الان قبل از رمز، پورت را هم از ادمین می‌پرسد)،
    همان استفاده می‌شود — نه لزوماً «پورت SSH مشتری‌ها»ی سراسری ربات. این برای اجرای اسکریپت روی
    یک سرور دلخواه/تازه (که هنوز عضو host_pool نیست و پورتش لزوماً با تنظیمات فعلی ربات یکی نیست)
    ضروری است؛ وگرنه با «Authentication failed» یا خطای اتصال مبهم مواجه می‌شدیم چون پورت اشتباه
    امتحان می‌شد."""
    if paramiko is None:
        await context.bot.send_message(chat_id, "❌ کتابخانه paramiko نصب نیست.")
        return

    # 🔧 چک صریح قبل از تلاش برای اتصال: اگر فایل اسکریپت روی همین Core (کنار خودِ ربات) پیدا
    # نشود، به‌جای نمایش خطای خام پایتون (که مبهم است)، پیام واضح می‌دهیم که دقیقاً چه فایلی و
    # در چه مسیری لازم است.
    if not os.path.exists(script_path):
        await context.bot.send_message(
            chat_id,
            f"❌ فایل اسکریپت پیدا نشد: <code>{esc(script_path)}</code>\n"
            f"این فایل باید دقیقاً با همین اسم، کنار خودِ فایل ربات روی سرور Core قرار داشته باشد.",
            parse_mode="HTML")
        return

    if ssh_port is not None:
        try:
            ssh_port = int(ssh_port)
        except (TypeError, ValueError):
            ssh_port = 8443
    else:
        # سازگاری با فراخوانی‌های قدیمی‌تر: پورت ثبت‌شدهٔ همان IP را می‌گیریم، نه یک مقدار سراسری.
        ssh_port = await asyncio.to_thread(_db_get_host_ssh_port, ip, 8443)

    # 🩺🔧 رفع ریشه‌ای کل خانوادهٔ این باگ‌ها: اگر IP هدف دقیقاً همون سروریه که خودِ ربات
    # روش در حال اجراست (مثلاً دکمهٔ «بهینه‌سازی سرعت و شبکه» روی Core خودش)، اصلاً نیازی
    # به SSH نیست — چون ربات همین الان با دسترسی محلی روی همون ماشین اجرا میشه. این یعنی
    # هیچ فرضی دربارهٔ پورت SSH، وضعیت فایروال، یا اینکه sshd فقط روی 127.0.0.1 گوش میده
    # (مثلاً بعد از تنظیم HAProxy transparent) لازم نیست؛ مستقیم و بدون واسطه اجرا میشه.
    
    # 🔴 فیکس مهم اعمال شده در خط زیر:
    core_public_ip = await asyncio.to_thread(_get_core_public_ip_cached)
    
    if core_public_ip and ip == core_public_ip:
        msg = await context.bot.send_message(chat_id, "⏳ اجرای محلی روی همین سرور (بدون نیاز به SSH)...")

        def _exec_local():
            ok_chmod, out_chmod, _ = _shell_capture(f"chmod +x {shlex.quote(script_path)}")
            if not ok_chmod:
                return False, out_chmod, ""
            # 🐛🔧 رفع باگ واقعی و خطرناک (self-kill): این تابع به‌عنوان زیرپروسه‌ی خودِ
            # nvlbot.service اجرا می‌شود (همان cgroup). اما اسکریپت‌هایی مثل
            # demote_core_to_edge.sh در میانه‌ی کارشان صراحتاً «systemctl disable --now nvlbot»
            # را صدا می‌زنند. چون systemd به‌صورت پیش‌فرض با توقفِ یک سرویس، کلِ cgroupِ آن را
            # می‌کشد (KillMode=control-group)، این اسکریپت هم قبل از رسیدن به مراحلِ حیاتیِ
            # بعدی (مثل بازسازیِ واقعیِ wg0.conf) ناقص کشته می‌شد — دقیقاً همان چیزی که باعث
            # می‌شد سرورِ قدیمی با کانفیگِ نیمه‌کاره (نه Core نه Edge) بماند.
            # systemd-run --scope یک scope/cgroup کاملاً جدا و مستقل برای اسکریپت می‌سازد؛
            # وقتی خودِ اسکریپت nvlbot.service را متوقف می‌کند، این scope (و در نتیجه خودِ
            # اسکریپتِ در حال اجرا) بیرون از آن cgroup است و زنده می‌ماند تا کامل تمام شود.
            # timeout هم از ۶۰ ثانیهٔ پیش‌فرض به ۳۰۰ ثانیه افزایش یافت، چون apt-get install
            # wireguard (که خودِ این اسکریپت‌ها اجرا می‌کنند) معمولاً بیشتر از ۶۰ ثانیه طول می‌کشد.
            ok_run, out_run, _ = _shell_capture(
                f"systemd-run --scope --quiet -p KillMode=process -- "
                f"bash {shlex.quote(script_path)} {args_str}",
                timeout=300,
            )
            return ok_run, out_run, ""

        ok, out, err = await asyncio.to_thread(_exec_local)
        await _send_remote_script_result(chat_id, context, ip, ok, out, err, msg=msg)
        return

    # 🩺🔧 رفع باگ: قبلاً اگه پورت داده‌شده (ssh_port) جواب نمی‌داد ولی پورت ۲۲ (مدیریتی) در
    # واقع باز و در دسترس بود، این تابع فقط این حقیقت رو گزارش می‌داد و بدون هیچ تلاش واقعی‌ای
    # خارج می‌شد — یعنی مثلاً «تنزل به Edge» یا «آپدیت Endpoint» با رمز کاملاً درست هم شکست
    # می‌خورد، چون هیچ‌وقت واقعاً پورت ۲۲ رو امتحان می‌کرد. الان اگه پورت اصلی جواب نداد ولی
    # ۲۲ در دسترس بود، خودکار با ۲۲ ادامه می‌ده (نه فقط گزارش می‌ده).
    effective_port = None
    reachable = await asyncio.to_thread(_check_tcp_reachable, ip, ssh_port)
    if reachable:
        effective_port = ssh_port
    else:
        fallback_reachable = await asyncio.to_thread(_check_tcp_reachable, ip, 22) if ssh_port != 22 else False
        if fallback_reachable:
            effective_port = 22
        else:
            diag = (
                f"❌ <b>پورت {ssh_port} روی {esc(ip)} قابل‌اتصال نیست.</b>\n\n"
                f"🩺 تشخیص:\n"
                f"• پورت درخواستی: <code>{ssh_port}</code> — بسته/بدون پاسخ\n"
                f"• پورت پیش‌فرض ۲۲: ❌ آن هم بسته/بدون پاسخ است\n\n"
                "💡 هیچ‌کدوم از دو پورت پاسخ ندادن — یا سرور خاموشه، یا فایروال جلوی هر دو رو گرفته، یا (اگه اخیراً "
                "HAProxy/TPROXY تنظیم کردید) sshd الان فقط روی 127.0.0.1 گوش میده و از بیرون اصلاً قابل‌دسترس نیست."
            )
            await context.bot.send_message(chat_id, diag, parse_mode="HTML")
            return
    ssh_port = effective_port

    msg = await context.bot.send_message(chat_id, f"⏳ در حال اتصال به <code>{ip}:{ssh_port}</code> و اجرای اسکریپت...", parse_mode="HTML")

    # 🐛🔧 فیکسِ همون خانوادهٔ باگِ «هنگِ ابدی» که تو _upload_and_run پیدا شد، اینجا هم عیناً
    # وجود داشت: sftp.put بدون timeout، connect بدون banner/auth timeout، بدون keepalive، و
    # asyncio.to_thread بدون هیچ سقفِ زمانیِ بیرونی. این تابع برای اجرای اسکریپت رو Edgeهای
    # واقعاً دیگه (نه خودِ سروری که ربات رویش اجراست) استفاده می‌شه — پس همون ریسکِ گیرکردنِ
    # ابدیِ ربات رو داره. همون سه لایه‌ی دفاعی اینجا هم اعمال شده:
    SFTP_CHANNEL_TIMEOUT = 90
    REMOTE_SCRIPT_TIMEOUT = 600  # ثانیه — سقفِ کلیِ اتصال + آپلود + اجرای اسکریپت روی Edge

    def _exec():
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        def _try_connect(p):
            ssh.connect(ip, port=p, username='root', password=password, timeout=15,
                        banner_timeout=20, auth_timeout=20,
                        look_for_keys=False, allow_agent=False)

        try:
            try:
                _try_connect(ssh_port)
            except paramiko.AuthenticationException:
                # 🐛🔧 رفع رگرسیون: طبق طراحیِ امنیتیِ همین ناوگان (setup_edge_relay.sh و مشابه)،
                # ورود root با رمز روی پورتِ *مشتری* می‌تونه عمداً مسدود باشه (تا مشتری‌ها نتونن
                # رمز روت رو حدس بزنن) — حتی وقتی همون پورت از نظر TCP کاملاً باز و در دسترسه.
                # قبلاً این‌جا فقط reachability رو چک می‌کردیم، نه واقعاً auth رو؛ پس این حالت خاص
                # («پورت باز است ولی root+رمز عمداً رد می‌شه») نادیده گرفته می‌شد و کاربر پیام گنگِ
                # «Authentication failed» می‌گرفت با رمز کاملاً درست. الان اگه auth رد شد (نه فقط
                # اتصال شبکه)، فهرست کاملِ پورت‌های نامزد مدیریتیِ این ناوگان (۲۲/۸۴۴۳/۲۰۸۷/...) هم
                # امتحان می‌شه، نه فقط ۲۲.
                connected = False
                last_auth_err = None
                for cand in _get_admin_port_candidates():
                    if cand == ssh_port:
                        continue
                    try:
                        _try_connect(cand)
                        connected = True
                        break
                    except Exception as e2:
                        last_auth_err = e2
                if not connected:
                    raise

            transport = ssh.get_transport()
            if transport is not None:
                transport.set_keepalive(10)  # 🆕 تشخیصِ زودهنگامِ کانکشنِ مرده/گیرکرده

            sftp = ssh.open_sftp()
            sftp.get_channel().settimeout(SFTP_CHANNEL_TIMEOUT)  # 🆕 دیگه put ابدی بلاک نمی‌مونه
            remote_path = f"/root/{os.path.basename(script_path)}"
            sftp.put(script_path, remote_path)
            sftp.close()

            cmd = f"chmod +x {remote_path} && bash {remote_path} {args_str}"
            stdin, stdout, stderr = ssh.exec_command(cmd, timeout=300)
            out = stdout.read().decode(errors='replace')
            err = stderr.read().decode(errors='replace')
            ssh.close()
            return True, out, err
        except paramiko.AuthenticationException:
            tried = ", ".join(str(p) for p in ([ssh_port] + [p for p in _get_admin_port_candidates() if p != ssh_port]))
            return False, (f'رمز root برای {ip} روی هیچ‌کدام از پورت‌های امتحان‌شده ({tried}) پذیرفته نشد. '
                           'اگر مطمئنید رمز درست است، یک‌بار با یک کلاینت SSH معمولی (مثلاً MobaXterm) روی پورت ۲۲ '
                           'با همین رمز تست کنید تا مطمئن شوید مشکل از رمز/سرور نیست.'), ""
        except Exception as e:
            return False, str(e), ""
        finally:
            with contextlib.suppress(Exception):
                ssh.close()

    try:
        ok, out, err = await asyncio.wait_for(asyncio.to_thread(_exec), timeout=REMOTE_SCRIPT_TIMEOUT)
    except asyncio.TimeoutError:
        # 🆕 حتی اگه thread هنوز درحالِ اجراست (leaked)، ربات دیگه منتظرش نمی‌مونه — کنترل رو
        # پس می‌گیره، به کاربر خبر می‌ده، و به کارِ عادیِ خودش ادامه می‌ده.
        await context.bot.send_message(
            chat_id,
            f"❌ اجرای اسکریپت روی <code>{esc(ip)}</code> بعد از {REMOTE_SCRIPT_TIMEOUT} ثانیه بدون پاسخ موند "
            f"(احتمالاً شبکه قطع/گیر کرده) — عملیات لغو شد. دوباره امتحان کنید.",
            parse_mode="HTML")
        with contextlib.suppress(Exception):
            await context.bot.delete_message(chat_id, msg.message_id)
        return

    await _send_remote_script_result(chat_id, context, ip, ok, out, err, msg=msg)
# 🐛🔧 رفع باگ «پورت ۲۲ پیش‌فرضِ کل سیستم شد»: قبلاً یک ثابت تکی SSH_ADMIN_PORT=22 در همه‌جای این
# فایل به‌عنوان «تنها پورت مدیریتیِ معتبر» استفاده می‌شد. مشکل: خیلی از سرورهای همین ناوگان از
# اول با پورت‌های دیگری (مثلاً 8443، 2087، 2088، 2089، 443) راه‌اندازی شده‌اند و اصلاً پورت ۲۲
# رویشان باز نیست یا اصلاً استفاده نمی‌شود؛ فرض کردن ۲۲ به‌عنوان «پورت مدیریتیِ همیشه‌بازِ استاندارد»
# برای این سرورها از اساس غلط بود و می‌توانست باعث رفتار غیرمنتظره (یا حتی baseline-fail نادرست)
# شود. الان به‌جای یک عدد ثابت، یک *فهرست* از «پورت‌های نامزد مدیریتی» داریم که هم شامل ۲۲ (برای
# سازگاری با عقب) هم شامل پورت‌های رایجِ خودِ این ناوگان می‌شود، و از طریق تنظیمات دیتابیس
# (کلید admin_port_candidates) قابل تغییر/افزودن است — یعنی هیچ پورت خاصی به‌صورت اجباری
# «پیش‌فرض کل سیستم» نیست؛ فقط یک ترتیب امتحان معقول برای زمانی است که پورت ثبت‌شدهٔ یک IP
# مشخص پاسخ نمی‌دهد.
_DEFAULT_ADMIN_PORT_CANDIDATES = "22,8443,2087,2088,2089,443"


def _get_admin_port_candidates():
    """فهرست پورت‌های نامزد مدیریتی را از تنظیمات دیتابیس می‌خواند (قابل تغییر توسط ادمین، بدون
    نیاز به تغییر کد). اگر تنظیمی ثبت نشده باشد، یا دیتابیس موقتاً در دسترس نباشد، از فهرست
    پیش‌فرضِ همین ناوگان استفاده می‌شود — این تابع هرگز Exception پرتاب نمی‌کند (چون داخل چند
    تابع/فیچر مختلف صدا زده می‌شود و نباید یک مشکل موقتی/گذرای دیتابیس، آن عملیات را خراب کند)."""
    try:
        raw = _db_get_setting('admin_port_candidates', _DEFAULT_ADMIN_PORT_CANDIDATES) or _DEFAULT_ADMIN_PORT_CANDIDATES
    except Exception:
        raw = _DEFAULT_ADMIN_PORT_CANDIDATES
    ports = []
    for part in str(raw).split(','):
        part = part.strip()
        if part.isdigit():
            p = int(part)
            if 1 <= p <= 65535 and p not in ports:
                ports.append(p)
    return ports or [22]


# 🐛🔧 رفع باگ حیاتیِ «کل ربات موقع استارت با خطا کرش می‌کرد»: قبلاً همین‌جا یک خط در سطح
# ماژول (بیرون از هر تابعی) وجود داشت: SSH_ADMIN_PORT = _get_admin_port_candidates()[0].
# چون این خط در لحظهٔ import شدنِ فایل اجرا می‌شه — یعنی قبل از این‌که init_db() (که پایین‌تر
# در بلوکِ __main__ صدا زده می‌شه) فرصت کنه جدول «settings» رو بسازه — روی هر دیتابیس تازه/خالی
# (مثلاً نصب اول یا بعد از پاک‌کردن master_bot.db)، همین خط با خطای «no such table: settings»
# می‌ترکید و کل فایل ربات حتی قبل از رسیدن به تابع main، با کرش کامل متوقف می‌شد.
# راه‌حل: این متغیر اصلاً جایی در کد واقعی استفاده نمی‌شه (تنها مصرف‌کنندهٔ واقعی همون تابع
# _get_admin_port_candidates() هست که مستقیم و به‌صورت تنبل (lazy) داخل توابع صدا زده می‌شه —
# مثلاً همون‌جایی که چند خط پایین‌تر هست) — پس به‌جای این‌که یک نسخهٔ کش‌شده و خطرناک در سطح
# ماژول نگه داریم، این خط رو کاملاً حذف کردیم؛ هیچ تغییر رفتاری‌ای هم ایجاد نمی‌کنه.


async def _check_ssh_reachable(host, port, timeout=6):
    """
    🆕 چک سبک و بدون نیاز به احراز هویت: آیا روی host:port واقعاً یک سرویس SSH واقعی در حال
    گوش‌دادن است؟ فقط سطح TCP/بنر را می‌خواند (نه لاگین)، پس کاملاً مستقل از رمز/سیاست
    PermitRootLogin است. برای جلوگیری از «پیش‌فرض کردن/انتقال همهٔ کاربران به یک IP که واقعاً
    آماده نیست» قبل از هر عملیات پرخطر استفاده می‌شود.
    خروجی: (ok: bool, detail: str)
    """
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        try:
            banner = await asyncio.wait_for(reader.read(64), timeout=timeout)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        if banner.startswith(b'SSH-'):
            return True, ''
        return False, f'پاسخ غیرمنتظره از {host}:{port} (سرویس روی این پورت SSH نیست): {banner[:40]!r}'
    except Exception as e:
        return False, f'{host}:{port} در دسترس نبود: {e}'


async def _change_remote_ssh_port(host, current_port, new_port, root_password):
    """پورت واقعی sshd را روی یک سرور تغییر می‌دهد و فقط پس از اتصال مجدد موفق تأیید می‌کند.

    روند دو مرحله‌ای است: ابتدا پیکربندی و فایروال روی مقصد تغییر می‌کند، سپس ربات با پورت تازه
    از بیرون دوباره لاگین می‌کند. اگر این تأیید شکست بخورد، همان نشست SSH قدیمی پیکربندی را
    برمی‌گرداند تا سرور پشت پورت اشتباه قفل نشود.
    """
    if paramiko is None:
        return False, 'کتابخانهٔ paramiko روی ربات نصب نیست.'
    current_port = _normalize_ssh_port(current_port, 22)
    new_port = _normalize_ssh_port(new_port, 0)
    if not new_port:
        return False, 'پورت جدید نامعتبر است.'
    if new_port == current_port:
        return True, f'پورت {new_port} از قبل برای این IP ثبت شده است.'

    # 🆕 چک اولیه (قبل از هر تغییری روی سرور): مطمئن می‌شویم خودِ Core اصلاً از بیرون به پورت
    # *فعلی* همین سرور دسترسی دارد. اگر همین baseline هم شکست بخورد، مشکل اصلاً ربطی به پورت
    # جدید/فایروال آن ندارد — یا مسیر شبکهٔ Core تا این IP قطع است، یا پورت فعلی که ثبت شده
    # اساساً اشتباه است؛ در این حالت شروع فرآیند تغییر پورت (و صبر ۱۱۰ ثانیه‌ای بی‌فایده) را رد
    # می‌کنیم و همان‌جا با یک پیام روشن خارج می‌شویم.
    def _probe_ssh_banner(probe_port, timeout=8):
        """تست خام: آیا این پورت با یک بنر SSH جواب می‌ده؟ برای تشخیص «این پورت واقعاً sshd
        داره یا نه» بدون نیاز به احراز هویت کامل."""
        try:
            with socket.create_connection((host, probe_port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                banner = sock.recv(64)
                return banner.startswith(b'SSH-')
        except Exception:
            return False

    # 🐛🔧 رفع باگ «چک اولیه ناموفق بود / پورت تغییر نکرد»: نسخهٔ قبلی این baseline فقط پورتِ
    # *ثبت‌شده در دیتابیس* (current_port) را امتحان می‌کرد و اگر آن پاسخ نمی‌داد، بلافاصله با خطا
    # خارج می‌شد — بدون این‌که مثل بخش اتصال مدیریتیِ پایین‌تر، پورت مدیریتیِ استاندارد (۲۲) را
    # هم به‌عنوان جایگزین امتحان کند، و بدون این‌که چک کند شاید پورت جدید از قبل (مثلاً در تلاش
    # ناقص/موفق قبلی) واقعاً فعال شده باشد. الان هر سه احتمال قبل از اعلام شکست بررسی می‌شوند:
    admin_candidates = _get_admin_port_candidates()
    baseline_port = None
    if _probe_ssh_banner(current_port):
        baseline_port = current_port
    else:
        # 🐛🔧 قبلاً اینجا فقط یک عدد ثابت (۲۲) به‌عنوان تنها جایگزین امتحان می‌شد. الان کل فهرست
        # پورت‌های نامزد مدیریتیِ همین ناوگان (که شامل ۸۴۴۳/۲۰۸۷/۲۰۸۸/۲۰۸۹/۴۴۳ هم می‌شود، نه فقط ۲۲)
        # به ترتیب امتحان می‌شود — هیچ‌کدام «پیش‌فرض اجباری» نیست، فقط اولین موردی که واقعاً پاسخ
        # می‌دهد استفاده می‌شود.
        for cand in admin_candidates:
            if cand != current_port and _probe_ssh_banner(cand):
                baseline_port = cand
                current_port = cand  # از همین‌جا به بعد برای اتصال مدیریتی هم همین پورت استفاده می‌شود
                break

    if baseline_port is None:
        # هنوز جواب نگرفتیم — قبل از اعلام شکست، یک احتمال دیگر را هم چک می‌کنیم: شاید پورت
        # *جدید* از قبل (در یک تلاش قبلی که دیتابیس ربات ازش خبر نداره) واقعاً با موفقیت فعال
        # شده باشه. اگر این‌طور بود، این عملیات را «قبلاً انجام‌شده» در نظر می‌گیریم، نه شکست.
        if _probe_ssh_banner(new_port):
            await asyncio.to_thread(_db_set_host_ssh_port, host, new_port)
            return True, (f'پورت {new_port} از قبل روی این سرور فعال بود (احتمالاً در یک تلاش قبلی با موفقیت اعمال شده ولی '
                          f'دیتابیس ربات هماهنگ نشده بود). دیتابیس اکنون با پورت {new_port} هماهنگ شد — نیازی به تغییر مجدد نیست.')
        tried = ", ".join(str(p) for p in ([current_port] + [p for p in admin_candidates if p != current_port]))
        return False, (f'چک اولیه ناموفق بود: هیچ‌کدام از پورت‌های امتحان‌شده ({tried}) و نه پورت جدید ({new_port}) '
                        'از بیرون با بنر SSH پاسخ دادند. '
                        'یعنی مشکل ربطی به پورت جدید ندارد — یا مسیر شبکه بین Core و این IP قطع است، یا فایروال (چه خودِ سرور، '
                        'چه پنل ارائه‌دهندهٔ VPS) این پورت‌ها را مسدود کرده. قبل از تغییر پورت، همین را رفع کنید.\n\n'
                        'اگر این IP از پورت مدیریتیِ دیگری (خارج از فهرست بالا) استفاده می‌کند، آن را با تنظیم دیتابیسِ '
                        '"admin_port_candidates" (مقادیر جدا با کاما) اضافه کنید.')

    run_id = secrets.token_hex(8)
    remote_script = f'/root/.manus_change_ssh_port_{run_id}.sh'
    remote_backup = f'/root/.manus_ssh_port_backup_{run_id}'
    script = r"""#!/usr/bin/env bash
set -Eeuo pipefail
MODE="${1:-apply}"
NEW_PORT="${2:-}"
BACKUP_DIR="${3:-}"
MAIN_CONF="/etc/ssh/sshd_config"
CONF_DIR="/etc/ssh/sshd_config.d"

find_sshd() {
  for item in "$(command -v sshd 2>/dev/null || true)" /usr/sbin/sshd /usr/local/sbin/sshd; do
    if [ -n "$item" ] && [ -x "$item" ]; then printf '%s' "$item"; return 0; fi
  done
  return 1
}

has_ssh_socket() {
  systemctl list-unit-files ssh.socket >/dev/null 2>&1 && systemctl cat ssh.socket >/dev/null 2>&1
}

reload_sshd() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || \
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
    # 🐛🔧 رفع باگ NEW_PORT_NOT_LISTENING: از اوبونتو ۲۲.۰۴ به بعد، sshd معمولاً با
    # socket activation اجرا می‌شود — یعنی پورتِ واقعی گوش‌داده‌شده از خطِ ListenStream=
    # در واحد ssh.socket می‌آید، نه از Port در sshd_config! ری‌استارت/ریلودِ ssh.service
    # به‌تنهایی این پورت را عوض نمی‌کند. اگر ssh.socket وجود دارد، باید خودش هم
    # ری‌استارت شود تا override تازهٔ ListenStream واقعاً اعمال شود.
    has_ssh_socket && { systemctl restart ssh.socket 2>/dev/null || true; }
  elif command -v service >/dev/null 2>&1; then
    service ssh reload 2>/dev/null || service sshd reload 2>/dev/null || \
    service ssh restart 2>/dev/null || service sshd restart 2>/dev/null
  else
    return 1
  fi
}

# 🐛🔧 اگر ssh.socket فعال است، پورت واقعی را روی همان واحد (نه فقط sshd_config) هم ست می‌کنیم.
set_socket_port() {
  local port="$1"
  has_ssh_socket || return 0
  mkdir -p /etc/systemd/system/ssh.socket.d
  {
    echo "[Socket]"
    echo "ListenStream="
    echo "ListenStream=${port}"
  } > /etc/systemd/system/ssh.socket.d/override.conf
  systemctl daemon-reload
}

# 🐛🔧 رفع باگ مهم: قبلاً منطق rollback فقط در حالت MODE=rollback (که پایتون جداگانه و فقط بعد از
# شکستِ تست اتصالِ بیرونی صدا می‌زد) وجود داشت. یعنی اگر خودِ این اسکریپت، *بعد از* تغییر واقعی
# sshd_config (نه قبلش)، در یکی از مراحل بعدی شکست می‌خورد — مثلاً «sshd -t» پیکربندی را نامعتبر
# می‌دید، یا reload شکست می‌خورد، یا حتی بعد از reloadِ موفق پورت جدید گوش نمی‌داد — اسکریپت فقط
# با کد خطا خارج می‌شد و پیکربندیِ نیمه‌تغییریافته دقیقاً همان‌جا روی سرور می‌ماند؛ چون پایتون هم
# تنها زمانی rollback را صدا می‌زد که خودِ اسکریپت با کد ۰ («MANUS_PORT_CHANGE_OK») تمام شده باشد.
# یعنی در بدترین حالت (مثلاً NEW_PORT_NOT_LISTENING بعد از یک reload موفق) سرور می‌توانست کاملاً
# روی هیچ پورتی SSH نداشته باشد و هیچ rollback خودکاری هم اتفاق نیفتد. الان تابع rollback به یک
# تابع مشترک تبدیل شده و در هر نقطهٔ شکستِ *بعد از* گرفتن بکاپ، بلافاصله و خودکار همین‌جا (بدون
# نیاز به یک اتصال SSH دومِ جداگانه از پایتون) صدا زده می‌شود.
do_rollback() {
  [ -n "$BACKUP_DIR" ] && [ -f "$BACKUP_DIR/sshd_config" ] || return 1
  cp -af "$BACKUP_DIR/sshd_config" "$MAIN_CONF"
  rm -rf "$CONF_DIR"
  if [ -d "$BACKUP_DIR/sshd_config.d" ]; then cp -a "$BACKUP_DIR/sshd_config.d" "$CONF_DIR"; fi
  # 🐛🔧 override قبلیِ ssh.socket را هم برمی‌گردانیم (یا اگر قبلاً وجود نداشت، حذفش می‌کنیم)
  # تا سرور دقیقاً به همان وضعیتِ قبل از تغییر برگردد، نه با پورت جدید نیمه‌اعمال‌شده.
  if [ -f "$BACKUP_DIR/ssh.socket.override.conf" ]; then
    mkdir -p /etc/systemd/system/ssh.socket.d
    cp -af "$BACKUP_DIR/ssh.socket.override.conf" /etc/systemd/system/ssh.socket.d/override.conf
  else
    rm -f /etc/systemd/system/ssh.socket.d/override.conf
  fi
  systemctl daemon-reload 2>/dev/null || true
  local sshd_bin
  sshd_bin="$(find_sshd)" || return 1
  "$sshd_bin" -t || return 1
  reload_sshd
}

if [ "$MODE" = "rollback" ]; then
  do_rollback || { echo "ROLLBACK_FAILED" >&2; exit 41; }
  echo "ROLLBACK_OK"
  exit 0
fi

case "$NEW_PORT" in
  ''|*[!0-9]*) echo "INVALID_PORT" >&2; exit 10 ;;
esac
[ "$NEW_PORT" -ge 1 ] && [ "$NEW_PORT" -le 65535 ] || { echo "INVALID_PORT" >&2; exit 10; }
SSHD_BIN="$(find_sshd)" || { echo "SSHD_NOT_FOUND" >&2; exit 11; }
[ -f "$MAIN_CONF" ] || { echo "SSHD_CONFIG_NOT_FOUND" >&2; exit 12; }

# از تصاحب پورتی که سرویس دیگری روی آن گوش می‌دهد جلوگیری می‌کنیم.
if command -v ss >/dev/null 2>&1 && ss -H -ltn "sport = :$NEW_PORT" | grep -q .; then
  if ! ss -H -ltnp "sport = :$NEW_PORT" 2>/dev/null | grep -Eq 'sshd|dropbear'; then
    echo "PORT_IN_USE_BY_ANOTHER_SERVICE" >&2; exit 13
  fi
fi

# مسیر backup از فراخوانی پایتون می‌آید تا هم rollback خودکار همین‌جا و هم rollback دستیِ بعدی
# (در صورت لزوم) دقیقاً همین نسخه را بازگردانند.
[ -n "$BACKUP_DIR" ] || { echo "BACKUP_PATH_MISSING" >&2; exit 18; }
mkdir -p "$BACKUP_DIR"
cp -a "$MAIN_CONF" "$BACKUP_DIR/sshd_config"
if [ -d "$CONF_DIR" ]; then cp -a "$CONF_DIR" "$BACKUP_DIR/sshd_config.d"; fi
if [ -f /etc/systemd/system/ssh.socket.d/override.conf ]; then
  cp -a /etc/systemd/system/ssh.socket.d/override.conf "$BACKUP_DIR/ssh.socket.override.conf"
fi
# 🔒 از این خط به بعد، پیکربندی واقعاً تغییر می‌کند — هر شکستی از این نقطه به بعد باید
# خودکار rollback شود، نه فقط با پیام خطا خارج شود.

# همهٔ Portهای فعال قدیمی را (هم در فایل اصلی و هم snippetهای استاندارد) غیرفعال می‌کنیم.
# سپس یک Port جدید را قبل از نخستین Match به فایل اصلی وارد می‌کنیم؛ به این ترتیب حتی روی سرورهایی
# که Include برای sshd_config.d ندارند نیز پورت جدید واقعاً توسط sshd خوانده می‌شود.
for conf in "$MAIN_CONF" "$CONF_DIR"/*.conf; do
  [ -f "$conf" ] || continue
  sed -Ei '/^[[:space:]]*Port[[:space:]]+[0-9]+([[:space:]]*(#.*)?)?$/ s/^[[:space:]]*/# /' "$conf"
done
PORT_TMP="$(mktemp)"
awk -v port="$NEW_PORT" '
  BEGIN { inserted=0 }
  /^[[:space:]]*[Mm]atch([[:space:]]|$)/ && !inserted { print "Port " port; inserted=1 }
  { print }
  END { if (!inserted) print "Port " port }
' "$MAIN_CONF" > "$PORT_TMP"
cat "$PORT_TMP" > "$MAIN_CONF"
rm -f "$PORT_TMP"

# SELinux روی خانوادهٔ RHEL برای پورت سفارشی نیاز به برچسب مناسب دارد.
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" != "Disabled" ]; then
  if command -v semanage >/dev/null 2>&1; then
    semanage port -m -t ssh_port_t -p tcp "$NEW_PORT" 2>/dev/null || \
    semanage port -a -t ssh_port_t -p tcp "$NEW_PORT"
  else
    do_rollback; echo "SELINUX_SEMANAGE_MISSING_ROLLED_BACK" >&2; exit 14
  fi
fi

"$SSHD_BIN" -t || { do_rollback; echo "SSHD_CONFIG_INVALID_ROLLED_BACK" >&2; exit 15; }
# 🐛🔧 اگر این سرور با socket activation اجرا می‌شود، خودِ ssh.socket را هم روی پورت جدید تنظیم می‌کنیم؛
# وگرنه sshd_config عوض می‌شود ولی پورت واقعیِ گوش‌داده‌شده (که از ssh.socket می‌آید) دست‌نخورده می‌ماند.
set_socket_port "$NEW_PORT"
# در فایروال‌های معمول سیستم‌عامل، پورت تازه باز می‌شود. فایروال ارائه‌دهندهٔ VPS ممکن است جداگانه باشد.
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
  ufw allow "${NEW_PORT}/tcp" >/dev/null
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd --permanent --add-port="${NEW_PORT}/tcp" >/dev/null
  firewall-cmd --reload >/dev/null
fi
if ! reload_sshd; then
  do_rollback; echo "SSHD_RELOAD_FAILED_ROLLED_BACK" >&2; exit 16
fi
sleep 1
if command -v ss >/dev/null 2>&1 && ! ss -H -ltn "sport = :$NEW_PORT" | grep -q .; then
  do_rollback; echo "NEW_PORT_NOT_LISTENING_ROLLED_BACK" >&2; exit 17
fi
echo "MANUS_PORT_CHANGE_OK:$BACKUP_DIR"
"""

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # 🐛🔧 رفع باگ: قبلاً این نشستِ مدیریتی (که خودِ ربات برای اعمال تغییرات استفاده می‌کند) از
    # طریق «پورت مشتری» (current_port، مثلاً 8443) با کاربر root وصل می‌شد. روی خیلی از سرورها
    # (طبق طراحی امنیتیِ setup_edge_relay.sh)، ورود root با رمز روی همان پورتِ مشتری‌ها عمداً
    # مسدود است (تا مشتری‌ها نتوانند حدس بزنند/امتحان کنند) — در حالی‌که پورت مدیریتی استاندارد
    # (۲۲) که در همان لحظهٔ راه‌اندازی اولیهٔ سرور استفاده شده، همیشه باز و برای root در دسترس
    # می‌ماند. اتصال روی پورت مشتری همیشه دقیقاً با پیام «Authentication failed» شکست می‌خورد،
    # حتی با رمز کاملاً درست. الان اول پورت ۲۲ (پورت مدیریتیِ شناخته‌شده) امتحان می‌شود؛ فقط اگر
    # آن هم شکست خورد (مثلاً روی سرورهایی که ۲۲ را عمداً بسته‌اند)، به‌عنوان تلاش دوم و آخر،
    # پورت فعلیِ مشتری امتحان می‌شود.
    connect_errors = []
    connected = False
    # 🐛🔧 قبلاً فقط ۲۲ (SSH_ADMIN_PORT) و سپس current_port امتحان می‌شد. الان کل فهرست پورت‌های
    # نامزد مدیریتیِ همین ناوگان امتحان می‌شود (بدون تکرار current_port اگر از قبل در فهرست بود)،
    # چون در این ناوگان پورت مدیریتیِ واقعی می‌تواند ۸۴۴۳/۲۰۸۷/۲۰۸۸/۲۰۸۹/۴۴۳ هم باشد، نه فقط ۲۲.
    _admin_candidates_for_connect = _get_admin_port_candidates()
    attempt_ports = [current_port] + [p for p in _admin_candidates_for_connect if p != current_port]
    for attempt_port in attempt_ports:
        try:
            client.connect(host, port=attempt_port, username='root', password=root_password,
                           timeout=15, banner_timeout=15, auth_timeout=15, look_for_keys=False,
                           allow_agent=False)
            connected = True
            break
        except Exception as e:
            connect_errors.append(f"پورت {attempt_port}: {e}")
    if not connected:
        with contextlib.suppress(Exception):
            client.close()
        return False, "اتصال مدیریتی برقرار نشد — " + " | ".join(connect_errors)
    try:
        payload = base64.b64encode(script.encode('utf-8')).decode('ascii')
        install_cmd = (
            f"printf %s {shlex.quote(payload)} | base64 -d > {shlex.quote(remote_script)} && "
            f"chmod 700 {shlex.quote(remote_script)} && "
            f"bash {shlex.quote(remote_script)} apply {new_port} {shlex.quote(remote_backup)}"
        )
        _stdin, stdout, stderr = client.exec_command(install_cmd, timeout=100)
        out = stdout.read().decode(errors='replace')
        err = stderr.read().decode(errors='replace')
        status = stdout.channel.recv_exit_status()
        if status != 0 or 'MANUS_PORT_CHANGE_OK:' not in out:
            client.close()
            detail = (err or out or f'کد خروج {status}').strip()[-700:]
            return False, f'اعمال پیکربندی روی سرور ناموفق بود: {detail}'

        # 🐛🔧 رفع باگ: قبلاً این‌جا با کاربر root و رمز دوباره به «پورت جدید» وصل می‌شد تا اتصال
        # واقعی تأیید شود. این دقیقاً همان مشکلِ بالا را تکرار می‌کرد: اگر ورود root با رمز روی
        # پورت مشتری (چه قدیم چه جدید) عمداً مسدود باشد، این تأیید همیشه شکست می‌خورد و باعث
        # Rollback ناخواستهٔ یک تغییرِ در واقع کاملاً موفق می‌شد.
        # الان به‌جای احراز هویت کامل، فقط سطح TCP/بنرِ SSH را از بیرون چک می‌کنیم — این هم واقعاً
        # ثابت می‌کند سرویس از بیرون (نه فقط داخل خودِ سرور) در دسترس است (که فایروال پنل
        # ارائه‌دهندهٔ VPS را هم پوشش می‌دهد)، و هم کاملاً مستقل از سیاست ورود root است.
        # 🆕 رفع باگ «Rollback زودهنگام»: قبلاً فقط یک تلاش با timeout ۱۰ ثانیه انجام می‌شد. خیلی
        # از پنل‌های فایروال ابری (Cloud/SDN-level، نه فایروال محلی سرور) بعد از ثبت/فعال‌سازی یک
        # قانون، چند ثانیه تا حتی نیم دقیقه طول می‌کشد تا واقعاً روی زیرساخت اعمال شود — خصوصاً وقتی
        # ادمین همان لحظه قانون را باز کرده. یک تلاش تنها، این تأخیرِ کاملاً طبیعی را با «پورت واقعاً
        # کار نمی‌کند» اشتباه می‌گرفت و باعث Rollback بی‌خودیِ یک تغییرِ در واقع درست می‌شد. الان چند
        # بار با فاصلهٔ فزاینده امتحان می‌شود؛ فقط اگر همهٔ تلاش‌ها (مجموعاً حدود ۴۵ ثانیه) شکست
        # بخورند، Rollback انجام می‌شود.
        banner_ok, banner_err = False, ''
        attempt_errors = []  # 🆕 خطای هر تلاش را جدا نگه می‌داریم تا تشخیص نهایی دقیق‌تر باشد
        # 🆕 رفع باگ «۳۰ ثانیه هم کافی نبود»: حتی بعد از باز کردن فایروال پنل VPS و تست بلافاصله،
        # ۴ تلاش در ۳۰ ثانیه هنوز با timeout شکست می‌خورد — یعنی روی این ارائه‌دهنده‌ها انتشار واقعی
        # قانون فایروال می‌تواند به‌وضوح بیش از ۳۰ ثانیه طول بکشد. بودجهٔ صبر را به حدود ۱۱۰ ثانیه
        # (۷ تلاش) افزایش دادیم — همچنان محدود، ولی برای اکثر تأخیرهای واقعیِ SDN/Cloud Firewall کافی است.
        retry_delays = [0, 5, 10, 15, 20, 30, 30]  # ثانیه — مجموع صبر ≈ ۱۱۰ ثانیه + خودِ زمان اتصال هر تلاش
        for i, delay in enumerate(retry_delays):
            if delay:
                await asyncio.sleep(delay)
            try:
                with socket.create_connection((host, new_port), timeout=10) as sock:
                    sock.settimeout(10)
                    banner = sock.recv(64)
                    banner_ok = banner.startswith(b'SSH-')
                    if not banner_ok:
                        banner_err = f'پاسخ غیرمنتظره از پورت جدید: {banner[:40]!r}'
            except Exception as e:
                banner_err = str(e)
            attempt_errors.append(banner_err if not banner_ok else 'OK')
            if banner_ok:
                break

        if not banner_ok:
            rollback_cmd = f"bash {shlex.quote(remote_script)} rollback {new_port} {shlex.quote(remote_backup)}"
            for line in out.splitlines():
                if line.startswith('MANUS_PORT_CHANGE_OK:'):
                    remote_backup = line.split(':', 1)[1].strip()
                    rollback_cmd = f"bash {shlex.quote(remote_script)} rollback {new_port} {shlex.quote(remote_backup)}"
                    break
            _i, rb_out, rb_err = client.exec_command(rollback_cmd, timeout=60)
            rb_status = rb_out.channel.recv_exit_status()
            rb_detail = rb_err.read().decode(errors='replace').strip() or rb_out.read().decode(errors='replace').strip()
            client.close()
            rollback_note = 'پیکربندی قبلی با موفقیت بازگردانده شد.' if rb_status == 0 else f'بازگردانی ناموفق بود: {rb_detail[-400:]}'
            # 🆕 تشخیص نوع خطا: «timed out» یعنی بسته اصلاً پاسخ نمی‌گیرد (بیشتر نشانهٔ فایروال است)،
            # در حالی‌که «Connection refused» یعنی بسته به سرور رسیده ولی هیچ‌چیزی روی آن پورت گوش
            # نمی‌دهد (نشانهٔ اینکه خودِ sshd/socket واقعاً روی پورت جدید بالا نیامده، نه مشکل فایروال).
            lowered = [e.lower() for e in attempt_errors if e != 'OK']
            all_timeout = lowered and all('timed out' in e or 'timeout' in e for e in lowered)
            all_refused = lowered and all('refused' in e for e in lowered)
            if all_refused:
                diag = ('همهٔ تلاش‌ها با «Connection refused» شکست خوردند — یعنی بسته‌ها به سرور می‌رسند ولی sshd/socket '
                        'واقعاً روی پورت جدید گوش نمی‌دهد (این احتمالاً فایروال نیست؛ به لاگ اجرای اسکریپت روی خودِ سرور نیاز است).')
            elif all_timeout:
                diag = ('همهٔ تلاش‌ها با Timeout شکست خوردند — یعنی بسته‌ها اصلاً پاسخی نمی‌گیرند؛ این تقریباً همیشه یعنی یک '
                        'فایروال (پنل ارائه‌دهندهٔ VPS یا فایروال محلی سرور) هنوز پورت جدید را مسدود کرده یا انتشار قانونش کامل نشده.')
            else:
                diag = 'خطاهای متفاوتی در تلاش‌های مختلف دیده شد (جزئیات هر تلاش پایین آمده).'
            per_attempt = " | ".join(f"تلاش {i+1}: {e}" for i, e in enumerate(attempt_errors))
            return False, (f'پورت جدید از بیرون (نه فقط داخل سرور)، حتی بعد از {len(retry_delays)} بار تلاش در '
                           f'~{sum(retry_delays)} ثانیه، در دسترس نبود. {diag} {rollback_note}\n\n'
                           f'جزئیات هر تلاش: {per_attempt}\n\n'
                           'اگر فایروال پنل ارائه‌دهندهٔ VPS دارید، ابتدا آن پورت را در همان پنل باز کنید و چند دقیقه صبر کنید '
                           'قبل از تلاش مجدد (تا قانون واقعاً روی زیرساخت اعمال شود).')

        # پاک‌سازی فایل موقت و نسخهٔ پشتیبان فقط پس از تأیید دسترسی واقعی از بیرون انجام می‌شود.
        cleanup_cmd = f"rm -f {shlex.quote(remote_script)}; rm -rf {shlex.quote(remote_backup)}"
        client.exec_command(cleanup_cmd, timeout=20)
        client.close()
        return True, f'دسترسی SSH به {host}:{new_port} از بیرون تأیید شد.'
    except Exception as exc:
        try:
            client.close()
        except Exception:
            pass
        return False, f'اتصال یا احراز هویت مدیریتی با {host} ناموفق بود: {exc}'


async def _render_ssh_port_panel(query):
    """پنل تغییر واقعی پورت؛ هر IP با پورت اختصاصی خودش نمایش داده می‌شود."""
    await asyncio.to_thread(_db_sync_host_pool)
    pool = await asyncio.to_thread(_db_get_host_pool)
    port_map = await asyncio.to_thread(_db_get_host_ssh_port_map)
    lines, kb = [], []
    for host, active, *_rest in pool:
        port = port_map.get(host, 22)
        icon = '🟢' if active else '🔴'
        lines.append(f'{icon} <code>{esc(host)}:{port}</code>')
        kb.append([InlineKeyboardButton(f'✏️ تغییر پورت — {host}:{port}', callback_data=f'sshport_edit:{host}')])
    kb.append([InlineKeyboardButton('🔄 بروزرسانی', callback_data='srv_port')])
    kb.append([InlineKeyboardButton('🔙 بازگشت', callback_data='srv_direct_menu')])
    body = '\n'.join(lines) if lines else 'هیچ IPی در استخر ثبت نشده است.'
    await query.edit_message_text(
        '🔌 <b>تغییر واقعی پورت SSH هر IP</b>\n\n'
        f'{body}\n\n'
        'با زدن «تغییر پورت»، ربات با پورت فعلی به همان سرور متصل می‌شود، تنظیمات sshd و فایروال سیستم‌عامل را تغییر می‌دهد، سپس از پورت جدید اتصال مجدد را آزمایش می‌کند. '
        'فقط پس از موفقیت این آزمون، پورت تازه در فاکتورها و کد اتصال مشتری ثبت می‌شود.',
        parse_mode='HTML', reply_markup=InlineKeyboardMarkup(kb))
#--------------------------------------------------------

async def _show_v2_addvol_confirm(message_or_query, context, gb, role, ag_id, is_edit=False):
    context.user_data['v2_vol_add_gb'] = gb
    un = context.user_data.get('v2_vol_un')
    if not un: return await message_or_query.reply_text("❌ خطا: نام کاربری یافت نشد.")
    
    cost_txt = ""
    if role == 'agent':
        ainf = await asyncio.to_thread(_db_get_agent_info, ag_id)
        v2_vol_bp = ainf[17] if ainf and len(ainf)>17 and ainf[17] else '4000'
        base_price_dec = _parse_price_to_decimal(v2_vol_bp, Decimal("4000"))
        retail_dec = base_price_dec * Decimal(gb)
        cost_txt = f"\n💳 هزینهٔ این افزایش حجم: {int(retail_dec):,} تومان"

    txt = f"➕ <b>تایید افزایش حجم V2Ray</b>\n\n👤 اکانت: <code>{esc(un)}</code>\n📦 حجم افزایشی: {gb} گیگابایت{cost_txt}\n\nآیا تایید می‌کنید؟"
    kb = [
        [InlineKeyboardButton("✅ بله، انجام شود", callback_data="v2addvol_conf_yes")],
        [InlineKeyboardButton("❌ خیر، انصراف", callback_data=f"v2act_addvol_{un}")]
    ]
    if is_edit:
        await message_or_query.edit_text(txt, reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
    else:
        await message_or_query.reply_text(txt, reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")

async def _show_v2_vol_confirm(message_or_query, context, gb, role, ag_id, is_edit=False):
    context.user_data['v2_vol_gb'] = gb
    customer_name = context.user_data.get('v2_customer_name', 'ثبت نشده')
    cost_txt = ""
    if role == 'agent':
        ainf = await asyncio.to_thread(_db_get_agent_info, ag_id)
        v2_vol_bp = ainf[17] if ainf and len(ainf)>17 and ainf[17] else '4000'
        base_price_dec = _parse_price_to_decimal(v2_vol_bp, Decimal("4000"))
        retail_dec = base_price_dec * Decimal(gb)
        cost_txt = f"\n💳 هزینهٔ این خرید: {int(retail_dec):,} تومان"

    txt = f"🪐 <b>تایید ساخت اکانت V2Ray حجمی</b>\n\n👤 نشانه/نام: {esc(customer_name)}\n📦 حجم اکانت: {gb} گیگابایت\n⏳ انقضا: نامحدود (بدون محدودیت زمان)\n👥 تعداد کاربر: نامحدود{cost_txt}\n\nآیا از ساخت این اکانت مطمئن هستید؟"
    kb = [
        [InlineKeyboardButton("✅ بله، ساخته شود", callback_data="v2conf_vol_yes")],
        [InlineKeyboardButton("❌ خیر، انصراف", callback_data="v2r_type_vol")]
    ]
    if is_edit:
        await message_or_query.edit_text(txt, reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
    else:
        await message_or_query.reply_text(txt, reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")

async def _show_v2_renew_confirm(target, context, un, days):
    role, ag_id = context.user_data.get('role'), context.user_data.get('agent_id', 0)
    context.user_data['v2_renew_days'] = days
    mode = context.user_data.get('v2_renew_mode', 'extend')
    cur = await asyncio.to_thread(_db_get_user, un)
    if not cur: return await target.reply_text("❌ اکانت یافت نشد.")
    
    base_dt = datetime.strptime(cur[1], "%Y-%m-%d")
    if base_dt < datetime.now(): base_dt = datetime.now()
    
    if mode == 'extend':
        new_exp_dt = base_dt + timedelta(days=days)
        rem_days = (new_exp_dt - datetime.now()).days
        if rem_days > 70:
            return await target.reply_text(f"❌ <b>خطا:</b> مجموع زمان باقیمانده و تمدیدی اکانت نمی‌تواند بیشتر از ۷۰ روز باشد (مجموع درخواست شما: {rem_days} روز).\n(حداکثر زمان مجاز اکانت‌ها ۶۰ روز است).", parse_mode="HTML")
    
    cost_txt = ""
    if role == 'agent':
        ainf = await asyncio.to_thread(_db_get_agent_info, ag_id)
        if ainf:
            limit = cur[3]
            v2_bp = ainf[16] if len(ainf)>16 and ainf[16] else '160000'
            base_price_dec = _parse_price_to_decimal(v2_bp, Decimal("160000"))
            import math
            daily_price = float(base_price_dec) / 30.0
            retail_dec = Decimal(math.ceil(daily_price * days * limit))
            if mode == 'reduce':
                cost_txt = f"\n💰 مبلغی که به کیف‌پول شما بازمی‌گردد: {int(retail_dec):,} تومان"
            else:
                cost_txt = f"\n💳 هزینهٔ این تمدید: {int(retail_dec):,} تومان"
    
    if mode == 'reduce':
        txt = f"🔻 آیا مطمئنید که می‌خواهید <b>{days} روز</b> از زمان اکانت V2Ray <code>{esc(un)}</code> کم کنید؟{cost_txt}"
    else:
        txt = f"🔄 آیا مطمئنید که می‌خواهید اکانت V2Ray <code>{esc(un)}</code> را <b>{days} روز</b> تمدید کنید؟{cost_txt}"
        
    kb = [[InlineKeyboardButton("✅ بله، انجام شود", callback_data="v2rnyes")], [InlineKeyboardButton("❌ خیر", callback_data=f"udet_{un}")]]
    if hasattr(target, 'edit_message_text'):
        await target.edit_message_text(txt, reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
    else:
        await target.reply_text(txt, reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")

async def callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_auth(context): return
    query = update.callback_query; await query.answer(); d = query.data
    role, ag_id = context.user_data.get('role'), context.user_data.get('agent_id', 0)

    # 🚨 گارد اجباری بودن برند نماینده در کالبک‌ها (بررسی مستقیم از دیتابیس)
    if role == 'agent':
        ainf = await asyncio.to_thread(_db_get_agent_info, ag_id)
        if ainf and not ainf[10]:
            allowed_cbs = ['confirm_logout_yes', 'confirm_logout_no']
            if d not in allowed_cbs:
                await query.message.reply_text("⛔️ <b>کاربر گرامی، ابتدا باید نام برند خود را تعیین کنید (مثلاً: AliVpn).</b>\nلطفاً از منوی اصلی ربات روی دکمه «✏️ تغییر نام برند» کلیک کنید.", parse_mode="HTML")
                return
    # 🚨 گارد جامع وضعیت فروش سرویس‌ها (جلوگیری از کلیک روی دکمه‌های منقضی‌شده در تمامی مراحل خرید)
    if d.startswith(("bm_", "bu_", "blkc_", "buyfav_", "cm_set_")) or d in ("buy_direct", "buy_bulk_start", "buy_yes", "buy_emergency_yes"):
        ssh_en = await asyncio.to_thread(_db_get_setting, 'sell_ssh', '1') == '1'
        if not ssh_en:
            return await query.edit_message_text("❌ <b>قابلیت متوقف شده است</b>\n\nفروش سرویس SSH در حال حاضر متوقف است.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="buy_back_start")]]), parse_mode="HTML")
            
        if context.user_data.get('bulk_mode') or d in ("buy_bulk_start",) or d.startswith("blkc_"):
            bulk_en = await asyncio.to_thread(_db_get_setting, 'sell_bulk', '1') == '1'
            if not bulk_en:
                return await query.edit_message_text("❌ <b>قابلیت متوقف شده است</b>\n\nساخت اکانت عمده SSH در حال حاضر متوقف است.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="buy_back_start")]]), parse_mode="HTML")
                
    elif d.startswith(("v2r_type_", "v2ru_")) or d in ("v2ray_buy_menu", "v2conf_yes", "v2_buy_emergency_yes", "v2conf_vol_yes", "v2_vol_buy_emergency_yes"):
        v2_unlimit_en = await asyncio.to_thread(_db_get_setting, 'sell_v2ray_unlimit', '1') == '1'
        v2_vol_en = await asyncio.to_thread(_db_get_setting, 'sell_v2ray_vol', '1') == '1'
        
        if d == "v2ray_buy_menu":
            if not v2_unlimit_en and not v2_vol_en:
                return await query.edit_message_text("❌ <b>قابلیت متوقف شده است</b>\n\nفروش تمامی سرویس‌های V2Ray در حال حاضر متوقف است.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="buy_back_start")]]), parse_mode="HTML")
        else:
            is_vol_flow = "vol" in d
            if is_vol_flow and not v2_vol_en:
                return await query.edit_message_text("❌ <b>قابلیت متوقف شده است</b>\n\nفروش سرویس V2Ray حجمی در حال حاضر متوقف است.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="buy_back_start")]]), parse_mode="HTML")
            elif not is_vol_flow and not v2_unlimit_en:
                return await query.edit_message_text("❌ <b>قابلیت متوقف شده است</b>\n\nفروش سرویس V2Ray نامحدود در حال حاضر متوقف است.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="buy_back_start")]]), parse_mode="HTML")

    # 🆕 تاییدیهٔ خروج (مشترک بین پنل ادمین و پنل نمایندگی)
    if d == "confirm_logout_yes":
        # 🆕 پاک کردن از لیست ادمین‌ها هنگام خروج
        await asyncio.to_thread(_db_remove_admin_chat_id, update.effective_chat.id)
        context.user_data.clear()
        await query.edit_message_text("👋 با موفقیت خارج شدید.")
        await context.bot.send_message(chat_id=query.message.chat_id, text="برای ورود مجدد /start را بفرستید.",
                                        reply_markup=ReplyKeyboardMarkup([['/start']], resize_keyboard=True))
        return
    elif d == "confirm_logout_no":
        await query.edit_message_text("✅ انصراف داده شد؛ همچنان وارد سیستم هستید.")
        return

    # 💳 بخش تایید رسیدها — منحصراً ادمین
    # 🔧 رفع باگ امنیتی مهم: نسخهٔ قبلی این دو شاخه اصلاً role را چک نمی‌کرد؛ یعنی تئوریاً هر
    # نمایندهٔ لاگین‌کرده‌ای (اگر callback_data را حدس/بازتولید می‌کرد) می‌توانست رسید هرکسی
    # از جمله رسید خودش را «تایید» و کیف پول را شارژ کند. الان این عملیات یا برای ادمین مجاز
    # است، یا برای همان نماینده‌ای که کارت اختصاصی‌اش برای این واریزی استفاده شده (card_owner_agent_id) —
    # که همیشه از خودِ دیتابیس (نه از callback_data قابل‌جعل) خوانده می‌شود.
    if d.startswith("c2c_acc_") or d.startswith("c2c_rej_"):
        _receipt_id_check = int(d.split("_")[2])
        with db_conn() as _conn:
            _row = _conn.execute("SELECT card_owner_agent_id FROM receipts WHERE id=?", (_receipt_id_check,)).fetchone()
        _owner_aid_check = _row[0] if _row else None
        _is_owner = (role == 'agent' and _owner_aid_check is not None and context.user_data.get('agent_id') == _owner_aid_check)
        if role != 'admin' and not _is_owner:
            await query.message.reply_text("⛔️ شما اجازهٔ تایید/رد این رسید را ندارید."); return

    if d.startswith("c2c_acc_"):
        parts = d.split("_"); receipt_id, aid, amt = int(parts[2]), int(parts[3]), float(parts[4])
        with db_conn() as conn:
            status = conn.execute("SELECT status FROM receipts WHERE id=?", (receipt_id,)).fetchone()
            if status and status[0] == 'pending':
                conn.execute("UPDATE agents SET balance = balance + ? WHERE id=?", (amt, aid))
                _apply_emergency_repayment(conn, aid, amt)
                conn.execute("UPDATE receipts SET status='approved' WHERE id=?", (receipt_id,))
                
                # ثبت در دیتابیس حسابداری
                ag_name_row = conn.execute("SELECT name FROM agents WHERE id=?", (aid,)).fetchone()
                ag_name = ag_name_row[0] if ag_name_row else str(aid)
                try:
                    with sqlite3.connect(ACCOUNTING_DB_PATH) as acc_conn:
                        acc_conn.execute("INSERT INTO finance_logs (date, agent_name, action_type, service, amount, details) VALUES (?, ?, ?, ?, ?, ?)",
                                         (datetime.now(IRAN_TZ).strftime("%Y-%m-%d %H:%M:%S"), ag_name, "واریز بانکی (تایید شده)", "-", amt, f"شناسه رسید: {receipt_id}"))
                        acc_conn.commit()
                except: pass

                log.info(f"رسید {receipt_id} تایید و حساب نماینده {aid} مبلغ {amt} شارژ شد.")
                await query.edit_message_caption(caption=query.message.caption + f"\n\n✅ <b>تایید شد و حساب نماینده شارژ گردید.</b>", parse_mode="HTML")
                # اطلاع به نماینده
                ag_tid = conn.execute("SELECT telegram_id FROM agents WHERE id=?", (aid,)).fetchone()
                if ag_tid and ag_tid[0]:
                    try: await context.bot.send_message(chat_id=ag_tid[0], text=f"🎉 <b>تاییدیه واریز</b>\nرسید شما تایید شد و مبلغ {int(amt):,} تومان به کیف پول شما اضافه گردید.", parse_mode="HTML")
                    except: pass
                
                await _notify_super_admin(context.application, f"💰 <b>تایید رسید بانکی</b>\nحساب نماینده (کد {aid}) مبلغ {int(amt):,} تومان توسط ادمین شارژ شد.", tg_user=update.effective_user)
            else: await query.message.reply_text("❌ این رسید قبلاً بررسی شده است.")
        return
        
    elif d.startswith("c2c_rej_"):
        parts = d.split("_"); receipt_id, aid = int(parts[2]), int(parts[3])
        with db_conn() as conn:
            status = conn.execute("SELECT status FROM receipts WHERE id=?", (receipt_id,)).fetchone()
            if status and status[0] == 'pending':
                conn.execute("UPDATE receipts SET status='rejected' WHERE id=?", (receipt_id,))
                await query.edit_message_caption(caption=query.message.caption + "\n\n❌ <b>رسید رد شد.</b>", parse_mode="HTML")
                ag_tid = conn.execute("SELECT telegram_id FROM agents WHERE id=?", (aid,)).fetchone()
                if ag_tid and ag_tid[0]:
                    try: await context.bot.send_message(chat_id=ag_tid[0], text="❌ <b>رد رسید</b>\nرسید پرداختی شما توسط مدیریت تایید نشد. لطفا با پشتیبانی تماس بگیرید.", parse_mode="HTML")
                    except: pass
            else: await query.message.reply_text("❌ این رسید قبلاً بررسی شده است.")
        return

    # جستجو و منو
    if d == "usearch":
        await query.edit_message_text("🔍 نام کاربری (مثال: 0350) را بفرستید:", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="uact_back")]]))
        context.user_data['state'] = 'USER_SEARCH_INPUT'
    #---------------------------------------------------------------------
    elif d == "umanage_ssh":
        context.user_data['manage_type'] = 'ssh'
        await _show_users_panel(update, context, page=0)
    elif d == "umanage_v2ray":
        context.user_data['manage_type'] = 'v2ray'
        await _show_users_panel(update, context, page=0)
    elif d == "umanage_v2ray_vol":
        context.user_data['manage_type'] = 'v2ray_vol'
        await _show_users_panel(update, context, page=0)

    elif d.startswith("v2act_sub_"):
        un = d.split("_", 2)[2]
        with db_conn() as conn:
            row = conn.execute("SELECT sub_url FROM ssh_accounts WHERE username=?", (un,)).fetchone()
        sub_url = row[0] if row else ""
        await query.answer("🔗 در حال تولید بارکد...", show_alert=False)
        qr_buf = await asyncio.to_thread(v2ray_engine.generate_qr, sub_url)
        await context.bot.send_photo(chat_id=query.message.chat_id, photo=qr_buf, caption=f"🔗 <b>لینک اتصال:</b>\n<code>{esc(sub_url)}</code>", parse_mode="HTML")

    elif d.startswith("v2act_tg_"):
        un = d.split("_", 2)[2]
        cur = await asyncio.to_thread(_db_get_user, un)
        will_lock = (cur[4] == "🟢 فعال")
        new_status = 'disabled' if will_lock else 'active'
        db_status = "🔴 غیرفعال" if will_lock else "🟢 فعال"
        m_url = await asyncio.to_thread(_db_get_setting, 'marzban_url', '')
        m_user = await asyncio.to_thread(_db_get_setting, 'marzban_username', '')
        m_pwd = await asyncio.to_thread(_db_get_setting, 'marzban_password', '')
        await v2ray_engine.modify_user(m_url, m_user, m_pwd, un, status=new_status)
        with db_conn() as conn: conn.execute("UPDATE ssh_accounts SET status=? WHERE username=?", (db_status, un))
        await query.answer("✅ وضعیت تغییر کرد")
        await _show_user_detail(update, un, context)

    elif d.startswith("v2act_rn_"):
        un = d.split("_", 2)[2]
        context.user_data['v2_renew_un'] = un
        context.user_data['v2_renew_mode'] = 'extend'
        kb = [[InlineKeyboardButton("۱ ماهه", callback_data="v2rn_30"), InlineKeyboardButton("۲ ماهه", callback_data="v2rn_60")],
              [InlineKeyboardButton("🔹 مقدار دلخواه (به روز)", callback_data=f"v2rnd_custom_{un}")],
              [InlineKeyboardButton("🔙 بازگشت", callback_data=f"udet_{un}")]]
        await query.edit_message_text(f"🔄 تمدید اکانت V2Ray <code>{esc(un)}</code>\nچه مقدار تمدید شود؟", reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")

    elif d.startswith("v2act_rd_") and role == 'admin':
        un = d.split("_", 2)[2]
        context.user_data['v2_renew_un'] = un
        context.user_data['v2_renew_mode'] = 'reduce'
        kb = [[InlineKeyboardButton("۱ ماهه", callback_data="v2rn_30"), InlineKeyboardButton("۲ ماهه", callback_data="v2rn_60")],
              [InlineKeyboardButton("🔹 مقدار دلخواه (به روز)", callback_data=f"v2rdd_custom_{un}")],
              [InlineKeyboardButton("🔙 بازگشت", callback_data=f"udet_{un}")]]
        await query.edit_message_text(f"🔻 کاهش زمان اکانت V2Ray <code>{esc(un)}</code>\nچه مقدار کم شود؟", reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")

    elif d.startswith("v2rnd_custom_") or d.startswith("v2rdd_custom_"):
        un = d.split("_", 2)[2]
        context.user_data['v2_renew_un'] = un
        context.user_data['state'] = 'V2_RENEW_DAYS_INPUT'
        kb = [[InlineKeyboardButton("🔙 بازگشت", callback_data=f"udet_{un}")]]
        if d.startswith("v2rnd_custom_"):
            context.user_data['v2_renew_mode'] = 'extend'
            await query.edit_message_text(f"✍️ تعداد روزی که می‌خواهید اکانت {esc(un)} تمدید شود را بفرستید:", reply_markup=InlineKeyboardMarkup(kb))
        else:
            context.user_data['v2_renew_mode'] = 'reduce'
            await query.edit_message_text(f"✍️ تعداد روزی که می‌خواهید از زمان اکانت {esc(un)} کم شود را بفرستید:", reply_markup=InlineKeyboardMarkup(kb))

    elif d.startswith("v2rn_") and d != "v2rn_emergency_yes":
        days = int(d.split("_")[1])
        un = context.user_data.get('v2_renew_un')
        if not un: return await query.message.reply_text("❌ تراکنش منقضی شده است.")
        await _show_v2_renew_confirm(query, context, un, days)

    elif d in ("v2rnyes", "v2rn_emergency_yes"):
        if d == "v2rn_emergency_yes":
            context.user_data['emergency_approved'] = True
            
        days = context.user_data.get('v2_renew_days')
        un = context.user_data.get('v2_renew_un')
        mode = context.user_data.get('v2_renew_mode', 'extend')
        if not days or not un: return await query.message.reply_text("❌ تراکنش منقضی شده است.")
        
        cur = await asyncio.to_thread(_db_get_user, un)
        if not cur: return await query.edit_message_text("❌ اکانت یافت نشد.")

        try:
            cost = 0.0
            retail_dec = Decimal("0")
            ainf = None
            if role == 'agent':
                ainf = await asyncio.to_thread(_db_get_agent_info, ag_id)
                if not ainf: return await query.edit_message_text("❌ خطا: اطلاعات نمایندگی یافت نشد.")
                
                limit = cur[3]
                v2_bp = ainf[16] if len(ainf)>16 and ainf[16] else '160000'
                base_price_dec = _parse_price_to_decimal(v2_bp, Decimal("160000"))
                import math
                daily_price = float(base_price_dec) / 30.0
                retail_dec = Decimal(math.ceil(daily_price * days * limit))
                cost = float(retail_dec)

                if mode == 'extend' and ainf[2] < cost and not context.user_data.get('emergency_approved'):
                    has_opt, remaining_em, shortfall, used_em, req_cnt = _check_emergency_option(ainf, cost)
                    can_use_em, active_count = _agent_can_use_emergency_credit(ag_id)
                    if has_opt and can_use_em:
                        kb_em = [[InlineKeyboardButton("🆘 استفاده از شارژ اضطراری", callback_data="v2rn_emergency_yes")],
                                 [InlineKeyboardButton("↩️ انصراف", callback_data=f"udet_{un}")]]
                        await query.edit_message_text(
                            f"❌ <b>موجودی ناکافی برای تمدید V2Ray!</b>\n\n💰 موجودی شما: {int(ainf[2]):,} تومان\n💳 هزینه تمدید {days} روزه: {int(cost):,} تومان\n\n"
                            f"🆘 می‌توانید از <b>شارژ اضطراری</b> استفاده کنید (سقف کل: {int(EMERGENCY_CREDIT_LIMIT):,} تومان).",
                            reply_markup=InlineKeyboardMarkup(kb_em), parse_mode="HTML")
                        return
                    return await query.edit_message_text(f"❌ <b>موجودی ناکافی برای تمدید V2Ray!</b>\n\n💰 موجودی: {int(ainf[2]):,} تومان\n💳 هزینه تمدید: {int(cost):,} تومان", parse_mode="HTML")

            base_dt = datetime.strptime(cur[1], "%Y-%m-%d")
            if mode == 'extend' and base_dt < datetime.now(): 
                base_dt = datetime.now()
            
            signed_days = days if mode == 'extend' else -days
            new_exp_dt = base_dt + timedelta(days=signed_days)
            
            if mode == 'reduce' and new_exp_dt <= datetime.now():
                return await query.edit_message_text(f"❌ کاهش {days} روز باعث می‌شود اکانت به گذشته/امروز برود و منقضی شود. لطفاً عدد کمتری وارد کنید.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data=f"udet_{un}")]]))

            new_exp_db = new_exp_dt.strftime("%Y-%m-%d")
            
            m_url = await asyncio.to_thread(_db_get_setting, 'marzban_url', '')
            m_user = await asyncio.to_thread(_db_get_setting, 'marzban_username', '')
            m_pwd = await asyncio.to_thread(_db_get_setting, 'marzban_password', '')
            
            # اگر اکانت قبلاً منقضی/آفلاین بوده، با تمدید دوباره فعال می‌شود.
            new_status = 'active' if mode == 'extend' else None
            
            kwargs = {'expire': int(new_exp_dt.timestamp())}
            if new_status:
                kwargs['status'] = new_status
                
            await v2ray_engine.modify_user(m_url, m_user, m_pwd, un, **kwargs)
            
            db_status_update = ", status='🟢 فعال'" if mode == 'extend' else ""
            with db_conn() as conn: 
                conn.execute(f"UPDATE ssh_accounts SET expire_date=?{db_status_update} WHERE username=?", (new_exp_db, un))
            
            if role == 'agent':
                if mode == 'extend':
                    with db_conn() as conn: conn.execute("UPDATE agents SET balance = balance - ? WHERE id=?", (cost, ag_id))
                    await asyncio.to_thread(_db_distribute_commission, ag_id, retail_dec)
                    await _apply_agent_cashback_if_eligible(ag_id, retail_dec)
                    emergency_shortfall = max(0.0, cost - ainf[2])
                    if emergency_shortfall > 0:
                        await asyncio.to_thread(_db_agent_register_emergency_use, ag_id, emergency_shortfall)
                        with contextlib.suppress(Exception):
                            await _notify_admins(context.application, f"🆘 نمایندهٔ «{esc(ainf[0])}» برای تمدید V2Ray <code>{esc(un)}</code> مبلغ {int(emergency_shortfall):,} تومان از شارژ اضطراری استفاده کرد.")
                else:
                    # کاهش تمدید: بازگرداندن پول به نماینده
                    with db_conn() as conn: conn.execute("UPDATE agents SET balance = balance + ? WHERE id=?", (cost, ag_id))

            action_str = f"{days} روز تمدید" if mode == 'extend' else f"{days} روز کسر"
            await query.answer(f"✅ {action_str} با موفقیت انجام شد!")
            
            try:
                actor = f"نماینده: {esc(ainf[0])}" if (role == 'agent' and ainf) else "ادمین"
                act_str = "تمدید زمان" if mode == 'extend' else "کاهش زمان"
                await _notify_super_admin(context.application, f"🔄 <b>{act_str} V2Ray</b>\nشخص: {actor}\nمیزان اعمال شده: {days} روز", tg_user=update.effective_user)
                await asyncio.to_thread(_db_log_activity, ag_id if role=='agent' else 0, un, mode, 'v2ray', f"{days} روز", cost if role=='agent' else 0)
            except: pass
            
            safe_clear_context(context)
            await _show_user_detail(update, un, context)
        except Exception as e:
            log.exception("خطا در تغییر زمان v2ray")
            await query.message.reply_text(f"❌ خطا:\n<code>{esc(str(e))}</code>", parse_mode="HTML")
            safe_clear_context(context)
        
    elif d.startswith("v2act_ul_"):
        un = d.split("_", 2)[2]
        cur = await asyncio.to_thread(_db_get_user, un)
        new_limit = 2 if cur[3] == 1 else 1
        new_gb = 20 if new_limit == 2 else 10
        m_url = await asyncio.to_thread(_db_get_setting, 'marzban_url', '')
        m_user = await asyncio.to_thread(_db_get_setting, 'marzban_username', '')
        m_pwd = await asyncio.to_thread(_db_get_setting, 'marzban_password', '')
        await v2ray_engine.modify_user(m_url, m_user, m_pwd, un, note=f"IP_LIMIT:{new_limit}", data_limit=new_gb*1024**3)
        with db_conn() as conn: conn.execute("UPDATE ssh_accounts SET users_limit=?, data_limit=? WHERE username=?", (new_limit, new_gb*1024**3, un))
        await query.answer(f"✅ تبدیل به {new_limit} کاربره شد (سقف {new_gb} گیگ)")
        await _show_user_detail(update, un, context)
        
    elif d.startswith("v2act_lim_"):
        if role != 'admin': return await query.answer("⛔️ دسترسی غیرمجاز")
        un = d.split("_", 2)[2]
        with db_conn() as conn: row = conn.execute("SELECT data_limit FROM ssh_accounts WHERE username=?", (un,)).fetchone()
        cur_limit_bytes = row[0] if row and row[0] else 10*1024**3
        new_gb = 20 if cur_limit_bytes == 10*1024**3 else 10
        new_limit_bytes = new_gb * 1024**3
        m_url = await asyncio.to_thread(_db_get_setting, 'marzban_url', '')
        m_user = await asyncio.to_thread(_db_get_setting, 'marzban_username', '')
        m_pwd = await asyncio.to_thread(_db_get_setting, 'marzban_password', '')
        await v2ray_engine.modify_user(m_url, m_user, m_pwd, un, data_limit=new_limit_bytes)
        with db_conn() as conn: conn.execute("UPDATE ssh_accounts SET data_limit=? WHERE username=?", (new_limit_bytes, un))
        await query.answer(f"✅ محدودیت روزانه به {new_gb} گیگ تغییر کرد")
        await _show_user_detail(update, un, context)

    elif d.startswith("v2act_addvol_"):
        un = d.split("_", 2)[2]
        context.user_data['v2_vol_un'] = un
        vols = [10, 20, 30, 40, 50]
        kb = []
        for i in range(0, len(vols), 2):
            row = [InlineKeyboardButton(f"{vols[i]} گیگ", callback_data=f"v2addvol_gb_{vols[i]}")]
            if i+1 < len(vols): row.append(InlineKeyboardButton(f"{vols[i+1]} گیگ", callback_data=f"v2addvol_gb_{vols[i+1]}"))
            kb.append(row)
        kb.append([InlineKeyboardButton("✏️ حجم دلخواه", callback_data="v2addvol_gb_custom")])
        kb.append([InlineKeyboardButton("🔙 بازگشت", callback_data=f"udet_{un}")])
        await query.edit_message_text(f"➕ <b>افزایش حجم اکانت {esc(un)}</b>\n\nمقدار حجم مورد نظر برای اضافه شدن را انتخاب کنید:\n(بازه مجاز دلخواه: 10 تا 100 گیگ)", reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")

    elif d.startswith("v2addvol_gb_"):
        val = d.split("_")[2]
        if val == "custom":
            context.user_data['state'] = 'V2_ADD_VOL_INPUT'
            kb = [[InlineKeyboardButton("🔙 بازگشت", callback_data=f"v2act_addvol_{context.user_data.get('v2_vol_un')}")] ]
            await query.edit_message_text("✏️ حجم دلخواه برای افزایش را به عدد وارد کنید (بین 10 تا 100 گیگ):", reply_markup=InlineKeyboardMarkup(kb))
            return
        gb = int(val)
        await _show_v2_addvol_confirm(query.message, context, gb, role, ag_id, is_edit=True)

    elif d in ("v2addvol_conf_yes", "v2addvol_emergency_yes"):
        if d == "v2addvol_emergency_yes":
            context.user_data['emergency_approved'] = True
        
        un = context.user_data.get('v2_vol_un')
        gb = context.user_data.get('v2_vol_add_gb')
        if not un or not gb:
            return await query.message.reply_text("❌ تراکنش منقضی شده است.")
        
        try:
            cost = 0.0
            retail_dec = Decimal("0")
            ainf = None
            if role == 'agent':
                ainf = await asyncio.to_thread(_db_get_agent_info, ag_id)
                if not ainf: return await query.edit_message_text("❌ خطا: اطلاعات نمایندگی شما یافت نشد.")
                
                v2_vol_bp = ainf[17] if len(ainf)>17 and ainf[17] else '4000'
                base_price_dec = _parse_price_to_decimal(v2_vol_bp, Decimal("4000"))
                retail_dec = base_price_dec * Decimal(gb)
                cost = float(retail_dec)
                
                if ainf[2] < cost and not context.user_data.get('emergency_approved'):
                    has_opt, remaining_em, shortfall, used_em, req_cnt = _check_emergency_option(ainf, cost)
                    can_use_em, active_count = _agent_can_use_emergency_credit(ag_id)
                    if has_opt and can_use_em:
                        kb_em = [[InlineKeyboardButton("🆘 استفاده از شارژ اضطراری", callback_data="v2addvol_emergency_yes")],
                                 [InlineKeyboardButton("↩️ انصراف", callback_data=f"udet_{un}")]]
                        await query.edit_message_text(
                            f"❌ <b>موجودی ناکافی!</b>\n\n💰 موجودی شما: {int(ainf[2]):,} تومان\n💳 هزینه این افزایش حجم: {int(cost):,} تومان\n\n"
                            f"🆘 می‌توانید از <b>شارژ اضطراری</b> استفاده کنید (سقف کل: {int(EMERGENCY_CREDIT_LIMIT):,} تومان).",
                            reply_markup=InlineKeyboardMarkup(kb_em), parse_mode="HTML")
                        return
                    extra = ""
                    if req_cnt >= EMERGENCY_MAX_CONSECUTIVE_REQUESTS: extra = "\n\n🆘 سقف درخواست‌های پیاپی شارژ اضطراری پر شده."
                    elif used_em > 0: extra = f"\n\n🆘 شارژ اضطراری باقی‌مانده ({int(remaining_em):,} تومان) کافی نیست."
                    return await query.edit_message_text(f"❌ <b>موجودی ناکافی!</b>\n\n💰 موجودی: {int(ainf[2]):,} تومان\n💳 هزینه: {int(cost):,} تومان{extra}", parse_mode="HTML")

            await query.edit_message_text("⏳ در حال اعمال در NVL V2RAY...")
            m_url = await asyncio.to_thread(_db_get_setting, 'marzban_url', '')
            m_user = await asyncio.to_thread(_db_get_setting, 'marzban_username', '')
            m_pwd = await asyncio.to_thread(_db_get_setting, 'marzban_password', '')
            
            ok_get, m_data = await v2ray_engine.get_user(m_url, m_user, m_pwd, un)
            if not ok_get or not isinstance(m_data, dict):
                return await query.edit_message_text("❌ خطا در ارتباط با سرور V2Ray.")
            
            cur_limit_bytes = m_data.get('data_limit', 0)
            add_bytes = int(gb) * 1024**3
            new_limit_bytes = cur_limit_bytes + add_bytes
            
            ok_mod, _ = await v2ray_engine.modify_user(m_url, m_user, m_pwd, un, data_limit=new_limit_bytes)
            if not ok_mod:
                return await query.edit_message_text("❌ خطا در اعمال حجم روی سرور.")
            
            with db_conn() as conn:
                conn.execute("UPDATE ssh_accounts SET data_limit=? WHERE username=?", (new_limit_bytes, un))
                
            if role == 'agent':
                try:
                    with db_conn() as conn: conn.execute("UPDATE agents SET balance = balance - ? WHERE id=?", (cost, ag_id))
                    await asyncio.to_thread(_db_distribute_commission, ag_id, retail_dec)
                    await _apply_agent_cashback_if_eligible(ag_id, retail_dec)
                    emergency_shortfall = max(0.0, cost - ainf[2])
                    if emergency_shortfall > 0:
                        await asyncio.to_thread(_db_agent_register_emergency_use, ag_id, emergency_shortfall)
                        with contextlib.suppress(Exception):
                            await _notify_admins(context.application, f"🆘 نمایندهٔ «{esc(ainf[0])}» برای افزایش حجم V2Ray <code>{esc(un)}</code> مبلغ {int(emergency_shortfall):,} تومان از شارژ اضطراری استفاده کرد.")
                except Exception: log.exception("خطا در کسر کیف‌پول افزایش حجم V2Ray")

            try:
                actor = f"نماینده: {esc(ainf[0])}" if (role == 'agent' and ainf) else "ادمین"
                await _notify_super_admin(context.application, f"➕ <b>افزایش حجم V2Ray</b>\nشخص: {actor}\nمیزان اضافه شده: {gb} گیگابایت", tg_user=update.effective_user)
                await asyncio.to_thread(_db_log_activity, ag_id if role=='agent' else 0, un, 'extend', 'v2ray_vol', f"{gb} گیگ", cost if role=='agent' else 0)
            except: pass

            await query.answer(f"✅ {gb} گیگ به اکانت اضافه شد!")
            safe_clear_context(context)
            await _show_user_detail(update, un, context)

        except Exception as e:
            log.exception("خطا در افزایش حجم")
            await query.edit_message_text(f"❌ خطا:\n<code>{esc(str(e))}</code>", parse_mode="HTML")

    elif d.startswith("v2act_decvol_"):
        if role != 'admin': return await query.answer("⛔️ دسترسی غیرمجاز")
        un = d.split("_", 2)[2]
        context.user_data['v2_vol_un'] = un
        context.user_data['state'] = 'V2_DEC_VOL_INPUT'
        kb = [[InlineKeyboardButton("🔙 بازگشت", callback_data=f"udet_{un}")]]
        await query.edit_message_text(f"➖ <b>کاهش حجم اکانت {esc(un)}</b>\n\nچه مقدار از حجم کاربر کم شود؟ (فقط عدد به گیگابایت):", reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")

    elif d == "v2decvol_conf_yes" and role == 'admin':
        un = context.user_data.get('v2_vol_un')
        gb = context.user_data.get('v2_vol_dec_gb')
        if not un or not gb: return await query.message.reply_text("❌ تراکنش منقضی شده است.")
        
        await query.edit_message_text("⏳ در حال اعمال در NVL V2RAY...")
        m_url = await asyncio.to_thread(_db_get_setting, 'marzban_url', '')
        m_user = await asyncio.to_thread(_db_get_setting, 'marzban_username', '')
        m_pwd = await asyncio.to_thread(_db_get_setting, 'marzban_password', '')
        
        ok_get, m_data = await v2ray_engine.get_user(m_url, m_user, m_pwd, un)
        if not ok_get or not isinstance(m_data, dict):
            return await query.edit_message_text("❌ خطا در ارتباط با سرور V2Ray.")
            
        cur_limit_bytes = m_data.get('data_limit', 0)
        dec_bytes = int(gb) * 1024**3
        new_limit_bytes = max(0, cur_limit_bytes - dec_bytes)
        
        ok_mod, _ = await v2ray_engine.modify_user(m_url, m_user, m_pwd, un, data_limit=new_limit_bytes)
        if not ok_mod:
            return await query.edit_message_text("❌ خطا در کاهش حجم روی سرور.")
            
        with db_conn() as conn:
            conn.execute("UPDATE ssh_accounts SET data_limit=? WHERE username=?", (new_limit_bytes, un))
        
        await query.answer(f"✅ {gb} گیگ از اکانت کسر شد!")
        safe_clear_context(context)
        await _show_user_detail(update, un, context)

    elif d.startswith("v2act_dl_"):
        un = d.split("_", 2)[2]
        await query.edit_message_text(f"⚠️ آیا مطمئنید می‌خواهید اکانت V2Ray <code>{esc(un)}</code> را کاملاً حذف کنید؟", parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("✅ بله، حذف شود", callback_data=f"v2delyes_{un}"), InlineKeyboardButton("❌ خیر", callback_data=f"udet_{un}")]]))
            
    elif d.startswith("v2delyes_"):
        un = d.split("_", 1)[1]
        owner = await asyncio.to_thread(_db_get_user, un)
        if not owner: return await query.edit_message_text("❌ این کاربر دیگر وجود ندارد.")
        
        owner_agent_id = owner[5]
        refund = 0.0
        refund_note = ""
        if owner_agent_id and owner_agent_id != 0:
            try:
                refund, refund_desc = await _calc_account_refund(un)
                if refund > 0:
                    with db_conn() as conn:
                        conn.execute("UPDATE agents SET balance = balance + ? WHERE id=?", (refund, owner_agent_id))
                        used_before_row = conn.execute("SELECT emergency_used FROM agents WHERE id=?", (owner_agent_id,)).fetchone()
                        used_before = (used_before_row[0] or 0.0) if used_before_row else 0.0
                        _apply_emergency_repayment(conn, owner_agent_id, refund)
                        emergency_repaid = min(used_before, refund) if used_before > 0 else 0.0
                    refund_note = f"\n💸 {refund_desc}"
                    if emergency_repaid > 0:
                        refund_note += f"\n🆘 از همین مبلغ، {int(emergency_repaid):,} تومان بدهیِ شارژ اضطراری نماینده نیز پاک شد."
            except Exception:
                log.exception("خطا در اعمال بازپرداخت حذف اکانت V2Ray %s", un)

        m_url = await asyncio.to_thread(_db_get_setting, 'marzban_url', '')
        m_user = await asyncio.to_thread(_db_get_setting, 'marzban_username', '')
        m_pwd = await asyncio.to_thread(_db_get_setting, 'marzban_password', '')
        
        await v2ray_engine.delete_user(m_url, m_user, m_pwd, un)
        await asyncio.to_thread(_db_delete_user, un)
        
        await query.edit_message_text(f"✅ اکانت <code>{esc(un)}</code> به‌طور کامل از ربات و nevelv2ray حذف شد.{refund_note}", parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت به لیست", callback_data="uact_back")]]))
    #---------------------------------------------------------------------
    elif d == "uact_back_to_menu": await query.delete_message(); await show_main_menu(query, context)
    elif d == "uact_back": await _show_users_panel(update, context, page=context.user_data.get('user_page', 0))

    # 📢 پیام همگانی به نمایندگان
    elif d == "bcast_menu" and role == 'admin':
        context.user_data.pop('bcast_pending_text', None)
        kb = await _bcast_build_menu_kb()
        await query.edit_message_text(
            "📢 <b>پیام همگانی به نمایندگان</b>\n"
            "برای اطلاع‌رسانی سریع (مثلاً هنگام قطعی سرور) یک پیام جدید بنویسید یا یکی از پیام‌های آماده را انتخاب کنید.",
            reply_markup=kb, parse_mode="HTML")
    elif d == "bcast_new" and role == 'admin':
        context.user_data['state'] = 'BCAST_CUSTOM_INPUT'
        await query.edit_message_text("✍️ متن پیامی که می‌خواهید برای همهٔ نمایندگان ارسال شود را بفرستید:",
                                       reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 انصراف", callback_data="bcast_menu")]]))
    elif d.startswith("bcast_preset_") and role == 'admin':
        pid = int(d.split("_")[-1])
        preset = await asyncio.to_thread(_db_get_broadcast_preset, pid)
        if not preset:
            await query.message.reply_text("❌ این پیام آماده دیگر وجود ندارد."); return
        await _bcast_show_preview(query, context, preset[2])
    elif d == "bcast_confirm_send" and role == 'admin':
        body = context.user_data.get('bcast_pending_text')
        if not body:
            await query.edit_message_text("❌ چیزی برای ارسال پیدا نشد؛ دوباره از منو شروع کنید.",
                                           reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="bcast_menu")]])); return
        await query.edit_message_text("⏳ در حال ارسال...")
        ok_n, fail_n = await _bcast_send_now(context.application, body)
        context.user_data.pop('bcast_pending_text', None)
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت به منوی پیام همگانی", callback_data="bcast_menu")]])
        await query.edit_message_text(f"✅ پیام ارسال شد.\n📤 موفق: {fa_digits(ok_n)} نماینده\n❌ ناموفق: {fa_digits(fail_n)} نماینده",
                                       reply_markup=kb)
    elif d == "bcast_cancel" and role == 'admin':
        context.user_data.pop('bcast_pending_text', None)
        kb = await _bcast_build_menu_kb()
        await query.edit_message_text("📢 <b>پیام همگانی به نمایندگان</b>\nارسال لغو شد.", reply_markup=kb, parse_mode="HTML")
    elif d == "bcast_add_preset" and role == 'admin':
        context.user_data['state'] = 'BCAST_PRESET_TITLE_INPUT'
        await query.edit_message_text("✍️ یک عنوان کوتاه برای این پیامِ آماده بفرستید (فقط برای نمایش روی دکمه، مثلاً «قطعی سرور»):",
                                       reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 انصراف", callback_data="bcast_menu")]]))
    elif d == "bcast_manage_presets" and role == 'admin':
        presets = await asyncio.to_thread(_db_get_broadcast_presets)
        if not presets:
            await query.edit_message_text("هیچ پیام آماده‌ای ثبت نشده.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="bcast_menu")]])); return
        kb = [[InlineKeyboardButton(f"🗑 {title}", callback_data=f"bcast_delpreset_{pid}")] for pid, title, _b in presets]
        kb.append([InlineKeyboardButton("🔙 بازگشت", callback_data="bcast_menu")])
        await query.edit_message_text("🗑 برای حذف یک پیام آماده، روی آن بزنید:", reply_markup=InlineKeyboardMarkup(kb))
    elif d.startswith("bcast_delpreset_") and role == 'admin':
        pid = int(d.split("_")[-1])
        await asyncio.to_thread(_db_delete_broadcast_preset, pid)
        presets = await asyncio.to_thread(_db_get_broadcast_presets)
        if not presets:
            await query.edit_message_text("✅ حذف شد. هیچ پیام آماده‌ای باقی نماند.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="bcast_menu")]])); return
        kb = [[InlineKeyboardButton(f"🗑 {title}", callback_data=f"bcast_delpreset_{pid2}")] for pid2, title, _b in presets]
        kb.append([InlineKeyboardButton("🔙 بازگشت", callback_data="bcast_menu")])
        await query.edit_message_text("✅ حذف شد.\n\n🗑 برای حذف یک پیام آماده، روی آن بزنید:", reply_markup=InlineKeyboardMarkup(kb))

    # ⚙️ زیرمنوی تنظیمات سرور
    elif d == "srv_menu_back" and role == 'admin':
        kb = _build_server_settings_kb()
        await query.edit_message_text("⚙️ <b>تنظیمات سرور</b>\nیکی از گزینه‌های زیر را انتخاب کنید:", reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")

    # 🖥 پنل وضعیت و نقش سرورها (Core/Edge)
    elif d == "srv_status" and role == 'admin':
        await _render_server_status_panel(query, context)

    elif d.startswith("srv_optimize_") and role == 'admin':
        target_ip = d.replace("srv_optimize_", "")
        context.user_data['srv_target_ip'] = target_ip
        context.user_data['state'] = 'SRV_OPTIMIZE_PORT'
        default_port = await asyncio.to_thread(_db_get_setting, 'port', '2252')
        await query.edit_message_text(
            f"🚀 <b>بهینه‌سازی سرعت و شبکه: {target_ip}</b>\n\n"
            f"این عملیات موارد زیر را انجام می‌دهد:\n"
            f"✅ فعال‌سازی <b>BBR</b> برای کاهش اتلاف پکت\n"
            f"✅ تنظیم <b>MTU 1380</b> برای عبور بهتر از فیلترینگ\n"
            f"✅ بهینه‌سازی بافرهای لینوکس برای ترافیک بالا\n\n"
            f"🔌 پورت SSH همین سرور مقصد (<code>{target_ip}</code>) را بفرستید — اگر با پورت "
            f"مشتری‌های ربات ({esc(default_port)}) یکی است، همون رو بزنید:",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton(f"✅ استفاده از {default_port}", callback_data=f"srv_optport_default_{target_ip}")],
                [InlineKeyboardButton("🔙 انصراف", callback_data="srv_status")]]),
            parse_mode="HTML"
        )
    elif d.startswith("srv_optport_default_") and role == 'admin':
        target_ip = d.replace("srv_optport_default_", "")
        default_port = await asyncio.to_thread(_db_get_setting, 'port', '2252')
        context.user_data['srv_target_ip'] = target_ip
        context.user_data['srv_target_port'] = default_port
        context.user_data['state'] = 'SRV_OPTIMIZE_PASS'
        await query.edit_message_text(
            f"🚀 بهینه‌سازی <code>{target_ip}:{esc(default_port)}</code>\n\n🔑 لطفاً <b>رمز روت</b> سرور مقصد را بفرستید:",
            parse_mode="HTML")

    elif d.startswith("srv_promote_") and role == 'admin':
        target_ip = d.replace("srv_promote_", "")
        context.user_data['srv_target_ip'] = target_ip
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("✅ بله، شروع ویزارد ارتقا", callback_data="srv_wiz_promote_start")],
            [InlineKeyboardButton("🔙 بازگشت", callback_data="srv_status")]
        ])
        await query.edit_message_text(
            f"🚀 <b>ارتقای سرور Edge به Core</b>\n\n"
            f"آیا مطمئن هستید که می‌خواهید سرور <code>{target_ip}</code> را به نقش <b>Core</b> ارتقا دهید؟\n\n"
            f"⚠️ این عملیات حساس است — سرویس فعلی روی سرور {target_ip} متوقف و نقشش عوض می‌شود. "
            f"فایل‌های لازم (دیتابیس، کلیدها، گواهی‌ها) را خودِ ربات از Core می‌سازد و منتقل می‌کند، نیازی به کار دستی نیست.",
            reply_markup=kb, parse_mode="HTML"
        )
    
    # 🎯 تبدیل یک سرور Edge آماده‌به‌کار به رله فعال (Active Edge)
    elif d.startswith("srv_mkactive_") and role == 'admin':
        target_ip = d.replace("srv_mkactive_", "").strip()
        await query.edit_message_text(f"⏳ در حال انتقال دامنه و ترافیک به سرور <code>{esc(target_ip)}</code>...\nلطفاً چند لحظه صبر کنید.", parse_mode="HTML")
        
        async def _make_edge_active():
            # ۱. آپدیت دیتابیس (روشن کردن فلگ و ست کردن دیفالت)
            await asyncio.to_thread(_db_set_default_host, target_ip)
            await asyncio.to_thread(_db_update_setting, 'tls_passthrough', '1')
            
            # ۲. آپدیت کلودفلر (انتقال دامنه)
            cf_ok, cf_msg = await asyncio.to_thread(_cf_update_dns_record_sync, target_ip)
            if not cf_ok:
                with contextlib.suppress(Exception):
                    await context.bot.send_message(query.message.chat_id, f"❌ خطا در انتقال دامنه روی کلودفلر:\n<code>{esc(cf_msg)}</code>", parse_mode="HTML")
                return
            await asyncio.to_thread(_db_update_setting, "dns_current_ip", target_ip)
            
            # ۳. آپدیت پورت‌ها (NAT) روی سرور Edge انتخاب شده
            tls_port = await asyncio.to_thread(_db_get_setting, 'tls_port', '2088')
            port_map = await asyncio.to_thread(_db_get_host_ssh_port_map)
            ssh_port = port_map.get(target_ip, 22)
            
            try:
                def _run_iptables():
                    ssh = None
                    try:
                        ssh = paramiko.SSHClient()
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        pkey = paramiko.Ed25519Key.from_private_key_file(DO_SSH_KEY_PATH)
                        ssh.connect(target_ip, port=ssh_port, username='root', pkey=pkey, timeout=15)
                        cmd = (
                            f"iptables -t nat -C PREROUTING -p tcp --dport {tls_port} -j DNAT --to-destination 10.77.0.1:{tls_port} 2>/dev/null || "
                            f"iptables -t nat -A PREROUTING -p tcp --dport {tls_port} -j DNAT --to-destination 10.77.0.1:{tls_port} ; "
                            "(command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1) || iptables-save > /etc/iptables/rules.v4"
                        )
                        ssh.exec_command(cmd, timeout=20)
                    finally:
                        if ssh is not None:
                            try:
                                ssh.close()
                            except Exception:
                                pass
                await asyncio.to_thread(_run_iptables)
                
                # ۴. پایان و موفقیت
                with contextlib.suppress(Exception):
                    await context.bot.send_message(
                        query.message.chat_id, 
                        f"✅ <b>سرور {esc(target_ip)} با موفقیت به عنوان رله فعال تنظیم شد!</b>\n"
                        f"ترافیک دامنه هم‌اکنون به این سرور منتقل گردید.", 
                        parse_mode="HTML"
                    )
            except Exception as e:
                with contextlib.suppress(Exception):
                    await context.bot.send_message(query.message.chat_id, f"⚠️ دامنه به {target_ip} منتقل شد اما تنظیم NAT با خطای SSH روبرو شد:\n<code>{esc(str(e))}</code>", parse_mode="HTML")

        spawn_bg_task(_make_edge_active())
        return

    elif d == "srv_wiz_promote_start" and role == 'admin':
        target_ip = context.user_data.get('srv_target_ip')
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("⚡ اجرای اسکریپت Promote (از طریق SSH)", callback_data="srv_run_promote")],
            [InlineKeyboardButton("🔙 انصراف", callback_data="srv_status")]
        ])
        await query.edit_message_text(
            f"🛠 <b>مرحله نهایی ارتقا: {target_ip}</b>\n\n"
            f"از این‌جا به بعد کاملاً خودکار است — نیازی به انتقال دستی هیچ فایلی نیست:\n"
            f"۱. ربات خودش کلید خصوصی وایرگارد، Peerهای فعلی، نسخهٔ سالم دیتابیس، و (در صورت وجود) "
            f"گواهی‌های TLS/Cloudflare را از همین Core می‌سازد و از طریق همان اتصال SSH به مقصد آپلود می‌کند.\n"
            f"۲. پورت SSH مشتری را در مرحله بعد وارد خواهید کرد.\n"
            f"۳. با زدن دکمه زیر، اسکریپت <code>promote_edge_to_core.sh</code> روی مقصد اجرا می‌شود.",
            reply_markup=kb, parse_mode="HTML"
        )

    elif d == "srv_run_promote" and role == 'admin':
        context.user_data['state'] = 'SRV_PROMOTE_PORT_INPUT'
        await query.edit_message_text(
            "🔢 <b>پورت SSH مشتری (Customer SSH Port)</b> را وارد کنید:\n"
            "(مثلاً 8443 یا هر پورتی که می‌خواهید کاربران به آن وصل شوند)",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 انصراف", callback_data="srv_status")]]),
            parse_mode="HTML"
        )

    elif d.startswith("srv_installkey_") and role == 'admin':
        target_ip = d.replace("srv_installkey_", "")
        context.user_data['srv_target_ip'] = target_ip
        context.user_data['state'] = 'SRV_INSTALLKEY_PASS'
        await query.edit_message_text(
            f"🔑 <b>نصب دسترسی دائمی SSH روی {esc(target_ip)}</b>\n\n"
            f"این کار فقط یک‌بار لازم است — رمز روت الان استفاده می‌شود ولی جایی ذخیره نمی‌شود؛ "
            f"به‌جایش کلید عمومی دائمیِ Core به <code>authorized_keys</code> این سرور اضافه می‌شود. "
            f"بعد از این، CPU/RAM واقعیِ همین سرور در صفحهٔ هر اکانتی که رویش باشد نشان داده می‌شود.\n\n"
            f"لطفاً <b>رمز روت</b> این سرور را بفرستید:",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 انصراف", callback_data="srv_status")]]),
            parse_mode="HTML")

    elif d.startswith("srv_demote_") and role == 'admin':
        target_ip = d.replace("srv_demote_", "")
        context.user_data['srv_target_ip'] = target_ip
        context.user_data['state'] = 'SRV_DEMOTE_NEW_CORE_IP'
        await query.edit_message_text(
            f"📉 <b>تنزل سرور Core به Edge</b>\n\n"
            f"شما در حال تنزل سرور <code>{target_ip}</code> هستید.\n\n"
            f"لطفاً <b>IP عمومی سرور Core جدید</b> را وارد کنید:",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 انصراف", callback_data="srv_status")]]),
            parse_mode="HTML"
        )

    elif d.startswith("srv_update_ep_") and role == 'admin':
        target_ip = d.replace("srv_update_ep_", "")
        context.user_data['srv_target_ip'] = target_ip
        context.user_data['state'] = 'SRV_UPDATE_EP_NEW_CORE'
        await query.edit_message_text(
            f"🔄 <b>به‌روزرسانی Endpoint در Edge</b>\n\n"
            f"سرور مقصد: <code>{target_ip}</code>\n\n"
            f"لطفاً <b>IP عمومی Core جدید</b> را وارد کنید:",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 انصراف", callback_data="srv_status")]]),
            parse_mode="HTML"
        )
    # 🎯 زیرمنوی جدید «تنظیمات مستقیم» — شامل تنظیمات هاست و تغییر پورت که قبلاً مستقیماً توی
    # منوی اصلی «تنظیمات سرور» بودند؛ حالا زیر یک دکمه‌ی جمع‌وجورتر دسته‌بندی شده‌اند.
    elif d == "srv_direct_menu" and role == 'admin':
        kb = [[InlineKeyboardButton("🌐 تنظیمات هاست", callback_data="srv_hosts")],
              [InlineKeyboardButton("🔌 تغییر پورت", callback_data="srv_port")],
              [InlineKeyboardButton("🔙 بازگشت", callback_data="srv_menu_back")]]
        await query.edit_message_text("🎯 <b>تنظیمات مستقیم</b>\nتنظیمات مربوط به اتصال مستقیم (بدون TLS) — هاست و پورت واقعی سرور.", reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
    # 🧹 کاربران یتیم: یوزرنیم‌هایی که روی خودِ لینوکس وجود دارند (و هنوز قابل اتصال‌اند) ولی هیچ
    # رکوردی در دیتابیس ربات ندارند — معمولاً باقی‌ماندهٔ حذف‌های ناقص (userdel ناموفق) در گذشته.
    elif d == "orphan_menu" and role == 'admin':
        await query.edit_message_text("⏳ در حال مقایسهٔ کاربران لینوکسی با دیتابیس ربات...")
        os_users, os_err = await _get_os_bot_users()
        kb_back = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="srv_menu_back")]])
        if os_users is None:
            await query.edit_message_text(f"❌ خطا در خواندن کاربران لینوکسی:\n({esc(os_err)})", reply_markup=kb_back); return
        db_rows = await asyncio.to_thread(_db_get_all_users)
        db_users = {r[0] for r in db_rows}
        orphans = sorted(os_users - db_users)
        if not orphans:
            await query.edit_message_text("✅ هیچ کاربر یتیمی (موجود روی لینوکس ولی بدون رکورد در ربات) پیدا نشد.", reply_markup=kb_back); return
        context.user_data['orphan_list'] = orphans
        lines = "\n".join(f"• <code>{esc(u)}</code>" for u in orphans[:40])
        more_note = f"\n… و {len(orphans) - 40} مورد دیگر" if len(orphans) > 40 else ""
        kb = [[InlineKeyboardButton("🔒 قفل کردن همه (قطع دسترسی فوری)", callback_data="orphan_lock_all")],
              [InlineKeyboardButton("🗑 حذف کامل همه", callback_data="orphan_del_all")],
              [InlineKeyboardButton("🔙 بازگشت", callback_data="srv_menu_back")]]
        await query.edit_message_text(
            f"🧹 <b>کاربران یتیم پیدا شد: {len(orphans)}</b>\n"
            f"(این یوزرنیم‌ها روی سرور لینوکس وجود دارند ولی هیچ رکوردی در دیتابیس ربات ندارند — "
            f"احتمالاً قبلاً از ربات حذف شده‌اند ولی حذف واقعی‌شان روی لینوکس ناموفق بوده و همچنان قابل اتصال‌اند.)\n\n"
            f"{lines}{more_note}",
            reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
    elif d == "orphan_lock_all" and role == 'admin':
        orphans = context.user_data.get('orphan_list') or []
        if not orphans:
            await query.edit_message_text("❌ لیست منقضی شده؛ لطفاً دوباره از «کاربران یتیم» شروع کنید."); return
        await query.edit_message_text(f"⏳ در حال قفل کردن {len(orphans)} کاربر و قطع اتصالات زندهٔ آن‌ها...")
        ok_n, fail_n = 0, 0
        for un in orphans:
            ok1, _, _ = await run_cmd("sudo", "usermod", "-L", un)
            await run_cmd("sudo", "pkill", "-u", un)  # قطع فوری اتصال‌های زندهٔ همین کاربر، تا قفل بلافاصله اثر کند
            if ok1: ok_n += 1
            else: fail_n += 1
        await query.edit_message_text(
            f"🔒 عملیات قفل‌سازی تمام شد.\n✅ موفق: {ok_n} | ❌ ناموفق: {fail_n}\n\n"
            f"💡 این اکانت‌ها فقط قفل شدند (نه حذف)؛ اگر مطمئن هستید دیگر لازم نیستند، از «کاربران یتیم» دوباره وارد شوید و «حذف کامل همه» را بزنید.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="srv_menu_back")]]))
    elif d == "orphan_del_all" and role == 'admin':
        orphans = context.user_data.get('orphan_list') or []
        if not orphans:
            await query.edit_message_text("❌ لیست منقضی شده؛ لطفاً دوباره از «کاربران یتیم» شروع کنید."); return
        kb = [[InlineKeyboardButton("✅ بله، همه حذف شوند", callback_data="orphan_del_all_conf"),
               InlineKeyboardButton("↩️ خیر، انصراف", callback_data="srv_menu_back")]]
        await query.edit_message_text(
            f"⚠️ آیا مطمئنید می‌خواهید {len(orphans)} کاربر یتیم را به‌طور کامل و غیرقابل‌بازگشت از روی لینوکس حذف کنید؟",
            reply_markup=InlineKeyboardMarkup(kb))
    elif d == "orphan_del_all_conf" and role == 'admin':
        orphans = context.user_data.get('orphan_list') or []
        if not orphans:
            await query.edit_message_text("❌ لیست منقضی شده؛ لطفاً دوباره از «کاربران یتیم» شروع کنید."); return
        await query.edit_message_text(f"⏳ در حال حذف {len(orphans)} کاربر...")
        ok_n, fail_n = 0, 0
        for un in orphans:
            ok1, _, _ = await run_cmd("sudo", "userdel", "-f", un)
            if ok1: ok_n += 1
            else: fail_n += 1
        context.user_data.pop('orphan_list', None)
        await query.edit_message_text(
            f"🗑 عملیات حذف تمام شد.\n✅ موفق: {ok_n} | ❌ ناموفق: {fail_n}",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="srv_menu_back")]]))
    # 🩺 ابزار عیب‌یابی: خروجی خام ps و ss مربوط به SSH/dropbear را دقیقاً همان‌طور که روی سرور
    # است نشان می‌دهد تا بدون نیاز به دسترسی ترمینال، علت غلط بودن شمارش آنلاین/آفلاین پیدا شود.
    elif d == "srv_ssh_debug" and role == 'admin':
        await query.edit_message_text("⏳ در حال جمع‌آوری خروجی خام و تشخیص خودکار محل مشکل...")
        prt = await asyncio.to_thread(_db_get_setting, 'port', '22')
        # 🔧 هر بخش با یک برچسب منحصربه‌فرد جدا اجرا می‌شود تا خروجی هرکدام جداگانه پارس شود و
        # تشخیص خودکار زیر بتواند دقیقاً بگوید مشکل از کدام لایه است. سه بخش جدید (##SVC##،
        # ##SSHDT##، ##AUTHFAIL##) عمداً اضافه شدند تا سناریوی «تغییر PAM باعث قطع کامل همهٔ
        # کاربران شده» هم قابل‌تشخیص خودکار باشد — چون چک‌های قبلی (ps/ss) فقط لایهٔ شبکه را
        # می‌بینند، نه لایهٔ احراز هویت (PAM) که خودِ همین سناریو دقیقاً از همان‌جا خراب می‌شود:
        #   • ##SSHDT##: نتیجهٔ «sshd -t» — اگر فایل pam.d/sshd یا sshd_config خراب/ناقص باشد،
        #     دقیقاً همین دستور خط خطای واقعی را چاپ می‌کند (حتی وقتی خودِ دیمون هنوز بالاست چون
        #     ری‌استارت نشده، یا حتی اگر بالا نیست).
        #   • ##SVC##: وضعیت واقعیِ سرویس از دید systemd (فعال/متوقف/failed) — گاهی پردازه در ps
        #     هست ولی systemd آن را «failed» می‌داند چون در حال crash-loop است.
        #   • ##AUTHFAIL##: چند خط آخر لاگ احراز هویت که شامل کلمهٔ pam + fail/error/denied باشد؛
        #     اگر بعد از تغییرات PAM همهٔ تلاش‌های ورود رد می‌شوند، دقیقاً همین‌جا ثبت می‌شود.
        cmd = (
            "echo '##PS##'; sudo -n ps -eo pid,comm:32,euser:32,args 2>&1 | grep -Ei 'sshd|dropbear' | head -n 20; "
            f"echo '##PORTPROC##'; sudo -n ss -Htlnp 2>&1 | grep -E \":{prt}\\b\"; "
            f"echo '##ESTPORT##'; sudo -n ss -Htnp state established '( sport = :{prt} or dport = :{prt} )' 2>&1 | head -n 20; "
            "echo '##ESTALL##'; sudo -n ss -Htnp state established 2>&1 | head -n 20; "
            "echo '##SVC##'; for s in ssh sshd dropbear; do printf '%s=' \"$s\"; sudo -n systemctl is-active \"$s\" 2>&1; done; "
            "echo '##SSHDT##'; sudo -n sshd -t 2>&1; sudo -n /usr/sbin/sshd -t 2>&1; "
            "echo '##AUTHFAIL##'; { sudo -n journalctl -u ssh -u sshd --since '15 min ago' --no-pager 2>&1; "
            "sudo -n tail -n 200 /var/log/auth.log 2>&1; sudo -n tail -n 200 /var/log/secure 2>&1; } | grep -iE 'pam|fail|denied|error' | tail -n 15"
        )
        diag_lines = []
        try:
            p = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            out, err = await asyncio.wait_for(p.communicate(), MONITOR_TIMEOUT * 2)
            raw_out = out.decode(errors='ignore')
            err_txt = err.decode(errors='ignore').strip()

            def _section(tag, nxt_tags):
                if tag not in raw_out: return ""
                chunk = raw_out.split(tag, 1)[1]
                for t in nxt_tags:
                    if t in chunk: chunk = chunk.split(t, 1)[0]
                return chunk.strip()

            all_tags = ["##PORTPROC##", "##ESTPORT##", "##ESTALL##", "##SVC##", "##SSHDT##", "##AUTHFAIL##"]
            ps_out = _section("##PS##", all_tags)
            portproc_out = _section("##PORTPROC##", all_tags[1:])
            estport_out = _section("##ESTPORT##", all_tags[2:])
            estall_out = _section("##ESTALL##", all_tags[3:])
            svc_out = _section("##SVC##", all_tags[4:])
            sshdt_out = _section("##SSHDT##", all_tags[5:])
            authfail_out = _section("##AUTHFAIL##", [])

            low_err = err_txt.lower()
            sudo_blocked = "a password is required" in low_err or "no tty present" in low_err or ("sudo:" in low_err and "password" in low_err)

            # --- تشخیص خودکار: هر خط یعنی یک لایهٔ محتمل مشکل، به ترتیب از پایه‌ای‌ترین علت ---
            if sudo_blocked:
                diag_lines.append(
                    "🔴 <b>علت اصلی: دسترسی sudo برای ربات فراهم نیست.</b> دستورات ps/ss بدون رمز اجرا نشدند، "
                    "پس نتیجهٔ زیر لایه‌های بعدی قابل‌اعتماد نیست.\n"
                    "🔧 راه‌حل: خط زیر را به sudoers کاربر ربات اضافه کنید:\n"
                    "<code>botuser ALL=(ALL) NOPASSWD: /bin/ps, /usr/bin/ps, /usr/sbin/ss, /sbin/ss, /usr/sbin/sshd, /sbin/sshd, /bin/systemctl, /usr/bin/systemctl, /usr/bin/journalctl</code>")
            else:
                # 🆕 لایهٔ صفر (قبل از هرچیز): آیا خودِ فایل کانفیگ/PAM سالم است؟ این چک باید اول از
                # همه دیده شود چون اگر اینجا خطا باشد، دقیقاً همان توضیحی است که کاربر دنبالش است
                # (تغییرات PAM باعث قطع کامل شده).
                if sshdt_out.strip():
                    diag_lines.append(
                        "🔴 <b>علت اصلی — پیکربندی SSH/PAM خراب است:</b> دستور «sshd -t» روی این کانفیگ خطا داد؛ "
                        "یعنی خیلی محتمل است همان تغییراتی که روی PAM دادید، سینتکسش را خراب کرده یا به فایل/ماژولی "
                        "اشاره می‌کند که وجود ندارد. تا این خطا برطرف نشود، هیچ اتصال جدیدی (حتی با IP/پورت درست) "
                        "قبول نمی‌شود — این دقیقاً همان چیزی است که الان می‌بینید.\n"
                        f"🔧 پیام دقیق خطا:\n<code>{esc(sshdt_out.strip()[:500])}</code>\n"
                        "🔧 پیشنهاد فوری: تغییرات اخیر روی <code>/etc/pam.d/sshd</code> یا <code>/etc/ssh/sshd_config</code> را به نسخهٔ قبلی برگردانید "
                        "(اگر بکاپ گرفته‌اید) و دوباره <code>sudo sshd -t</code> را چک کنید تا خروجی خالی شود، سپس سرویس را ری‌استارت کنید.")
                else:
                    diag_lines.append("🟢 تست پیکربندی <code>sshd -t</code> بدون خطا بود؛ فایل‌های کانفیگ/PAM از نظر سینتکسی سالم‌اند.")

                if svc_out.strip():
                    failed_svcs = [ln for ln in svc_out.splitlines() if ln.strip() and not ln.strip().endswith('=active')]
                    if failed_svcs and not any('=active' in ln for ln in svc_out.splitlines()):
                        diag_lines.append(f"🔴 <b>هیچ سرویس SSH از دید systemd فعال نیست:</b> <code>{esc(', '.join(failed_svcs))}</code>\n"
                                           "🔧 پیشنهاد: <code>sudo systemctl restart ssh</code> را بزنید و دوباره <code>sudo systemctl status ssh</code> را چک کنید تا دلیل failed شدن مشخص شود.")
                    elif failed_svcs:
                        diag_lines.append(f"🟡 برخی سرویس‌ها فعال نیستند ولی حداقل یکی فعال است: <code>{esc(', '.join(failed_svcs))}</code> (احتمالاً طبیعی است اگر فقط یکی از OpenSSH/Dropbear را استفاده می‌کنید.)")

                if authfail_out.strip():
                    diag_lines.append(
                        "🔴 <b>خطاهای احراز هویت (PAM) اخیر در لاگ سرور پیدا شد</b> — یعنی تلاش‌های اتصال کاربران واقعاً به سرور می‌رسند ولی PAM رد می‌کند "
                        "(دقیقاً همین باعث می‌شود که هم از اپ کاربر، هم با تست مستقیم IP، اتصال کار نکند در حالی که IP/پورت درست است):\n"
                        f"<code>{esc(authfail_out.strip()[:600])}</code>")

                daemon_running = bool(ps_out)
                port_listening = bool(portproc_out)
                est_on_port = len([l for l in estport_out.splitlines() if l.strip()])
                est_all = len([l for l in estall_out.splitlines() if l.strip()])

                if not daemon_running:
                    diag_lines.append("🔴 <b>مشکل از لایهٔ دیمون:</b> هیچ پردازهٔ sshd/dropbear در حال اجرا روی سرور پیدا نشد. "
                                       "سرویس SSH احتمالاً پایین است یا کرش کرده.\n🔧 پیشنهاد: <code>sudo systemctl status ssh</code> یا <code>dropbear</code> را چک کنید.")
                else:
                    diag_lines.append(f"🟢 دیمون SSH/Dropbear در حال اجراست ({len(ps_out.splitlines())} پردازه).")

                if not port_listening:
                    diag_lines.append(f"🔴 <b>مشکل از لایهٔ پورت:</b> هیچ پردازه‌ای روی پورت {esc(prt)} در حالت LISTEN نیست، "
                                       "یعنی سرویس اصلاً روی این پورت گوش نمی‌دهد (پورت اشتباه در تنظیمات، یا فایروال قبل از رسیدن به این مرحله بلاک کرده).\n"
                                       f"🔧 پیشنهاد: در «تنظیمات سرور» مطمئن شوید پورت ثبت‌شده ({esc(prt)}) با پورت واقعیِ sshd/دیمون یکی است.")
                else:
                    diag_lines.append(f"🟢 پورت {esc(prt)} در حالت LISTEN است.")

                if daemon_running and port_listening and est_on_port == 0:
                    diag_lines.append("🟡 <b>مشکل از لایهٔ اتصال:</b> دیمون بالاست و پورت گوش می‌دهد، اما هیچ اتصال ESTABLISHED روی این پورت نیست. "
                                       "یعنی الان کاربری واقعاً وصل نیست (نه اینکه وصل نمی‌شود) — اگر کاربر ادعای قطعی دارد، مشکل احتمالاً سمت شبکهٔ خودِ کاربر یا فایروال بین کلاینت و سرور است.")
                elif daemon_running and port_listening and est_on_port > 0:
                    diag_lines.append(f"🟢 {est_on_port} اتصال ESTABLISHED روی پورت {esc(prt)} برقرار است؛ لایهٔ شبکه/پورت سالم به نظر می‌رسد.")

                if port_listening and est_on_port == 0 and est_all > 0:
                    diag_lines.append(f"ℹ️ نکته: {est_all} اتصال ESTABLISHED دیگر روی سرور برقرار است (روی پورت‌های دیگر) — یعنی خودِ سرور مشکلی در برقراری اتصال شبکه ندارد؛ فقط پورت {esc(prt)} خلوت است.")

                if not diag_lines:
                    diag_lines.append("🟢 هیچ نشانهٔ مشخصی از مشکل در این چک پیدا نشد.")

            diag_txt = "🔍 <b>تشخیص خودکار</b>\n" + "\n".join(f"• {ln}" for ln in diag_lines)

            raw = (f"[ps] {ps_out or '(خالی)'}\n\n"
                   f"[listen روی پورت {prt}] {portproc_out or '(خالی)'}\n\n"
                   f"[established روی پورت {prt}] {estport_out or '(خالی)'}\n\n"
                   f"[established کل سرور] {estall_out or '(خالی)'}\n\n"
                   f"[وضعیت سرویس‌ها] {svc_out or '(خالی)'}\n\n"
                   f"[تست sshd -t] {sshdt_out or '(بدون خطا)'}\n\n"
                   f"[لاگ خطاهای اخیر PAM] {authfail_out or '(خالی)'}")
            if err_txt and not sudo_blocked: raw += ("\n\n[stderr]\n" + err_txt)
        except asyncio.TimeoutError:
            diag_txt = f"⏱ اجرای دستورات بیش از {MONITOR_TIMEOUT * 2} ثانیه طول کشید (Timeout) — خودِ سرور کند پاسخ می‌دهد."
            raw = ""
        except Exception as e:
            diag_txt = f"❌ خطا در اجرای عیب‌یابی: {esc(str(e))}"
            raw = ""
        raw = raw[:3500]
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔄 بروزرسانی", callback_data="srv_ssh_debug")], [InlineKeyboardButton("🔙 بازگشت", callback_data="srv_menu_back")]])
        body = diag_txt + (f"\n\n🩺 <b>خروجی خام</b>\n<code>{esc(raw)}</code>" if raw else "")
        await query.edit_message_text(body, parse_mode="HTML", reply_markup=kb)

    # 🩹 خودتشخیصی و رفع خودکار «باگ پورت SSH» (دقیقاً همان دسته باگی که امروز چند بار پیش آمد:
    # کدهای مختلف ربات پورتی که فکر می‌کنند sshd رویش گوش می‌دهد، فرض می‌کنند — بدون این‌که
    # واقعاً چک کنند sshd الان واقعاً روی چه پورت/آدرسی گوش می‌دهد). این پنل هر دو را می‌خواند،
    # مقایسه می‌کند، و اگر ناهماهنگ بودند، با یک تپ روی دکمه، تنظیمات دیتابیس ربات را با واقعیتِ
    # سرور یکی می‌کند — بدون نیاز به ادیت دستی فایل یا SSH با دست زدن.
    elif d == "srv_ssh_diag" and role == 'admin':
        await query.edit_message_text("⏳ در حال بررسی پورت واقعی sshd و مقایسه با تنظیمات ربات...")

        configured_port_raw = await asyncio.to_thread(_db_get_setting, 'port', '2252')
        try:
            configured_port = int(configured_port_raw)
        except (TypeError, ValueError):
            configured_port = None

        # چک محلی (subprocess مستقیم، بدون SSH — چون خودِ ربات همین الان روی همین سرور اجرا
        # می‌شود) که واقعاً sshd/dropbear الان روی چه پورت‌ها و روی چه آدرسی (0.0.0.0 یا فقط
        # 127.0.0.1) گوش می‌دهد.
        cmd = "sudo -n ss -Htlnp 2>&1 | grep -Ei 'sshd|dropbear'"
        ok, raw_out, _ = await asyncio.to_thread(_shell_capture, cmd)

        detected_ports = []
        loopback_only_ports = []
        if ok and raw_out.strip():
            for line in raw_out.splitlines():
                # ستون آدرس معمولاً چیزی مثل "0.0.0.0:8443" یا "127.0.0.1:2222" است.
                m = re.search(r'(\S+):(\d+)\s', line + " ")
                if m:
                    addr, prt = m.group(1), m.group(2)
                    detected_ports.append(prt)
                    if addr in ("127.0.0.1", "[::1]"):
                        loopback_only_ports.append(prt)
        detected_ports = sorted(set(detected_ports), key=int) if detected_ports else []

        lines = ["🩹 <b>خودتشخیصی اتصال SSH</b>\n"]
        lines.append(f"⚙️ پورتی که در تنظیمات ربات ثبت شده: <code>{configured_port if configured_port else 'نامعتبر/خالی'}</code>")
        if detected_ports:
            lines.append(f"🖥 پورت(های) واقعی که sshd/dropbear الان رویش گوش می‌دهد: <code>{', '.join(detected_ports)}</code>")
        else:
            lines.append("🖥 پورت واقعی: ❌ هیچ پردازهٔ sshd/dropbearی که گوش بدهد پیدا نشد (یا دسترسی sudo بدون رمز برای ربات فراهم نیست).")

        kb_rows = []
        if detected_ports and configured_port is not None and str(configured_port) not in detected_ports:
            lines.append(f"\n🔴 <b>ناهماهنگی پیدا شد:</b> تنظیمات ربات می‌گوید {configured_port}، ولی sshd واقعاً روی {', '.join(detected_ports)} گوش می‌دهد. "
                          "همین ناهماهنگی دقیقاً باعث خطاهایی مثل «Unable to connect to port X» در بخش‌هایی مثل «بهینه‌سازی سرعت و شبکه» می‌شود.")
            # فقط اولین پورت واقعی را برای اصلاح خودکار پیشنهاد می‌دهیم (رایج‌ترین حالت: یک پورت).
            fix_port = detected_ports[0]
            kb_rows.append([InlineKeyboardButton(f"🔧 اصلاح خودکار (تنظیم پورت روی {fix_port})", callback_data=f"srv_ssh_fixport:{fix_port}")])
        elif detected_ports and configured_port is not None:
            lines.append("\n🟢 تنظیمات ربات با پورت واقعی sshd هماهنگ است — مشکلی از این جهت نیست.")

        if loopback_only_ports:
            lines.append(f"\n⚠️ توجه: پورت(های) <code>{', '.join(loopback_only_ports)}</code> فقط روی <code>127.0.0.1</code> (لوپ‌بک) گوش می‌دهند، نه روی آدرس عمومی. "
                          "یعنی این پورت‌ها از بیرون سرور (از جمله از اینترنت) اصلاً قابل‌دسترس نیستند — طبیعیه اگه عمداً HAProxy/TPROXY جلوش تنظیم کرده باشید، "
                          "ولی اگه غیرمنتظره‌ست، به این معنیه که هیچ مشتری‌ای فعلاً نمی‌تونه مستقیم بهش وصل بشه.")

        kb_rows.append([InlineKeyboardButton("🔄 بررسی دوباره", callback_data="srv_ssh_diag")])
        kb_rows.append([InlineKeyboardButton("🔙 بازگشت", callback_data="srv_menu_back")])
        await query.edit_message_text("\n".join(lines), parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb_rows))

    elif d.startswith("srv_ssh_fixport:") and role == 'admin':
        new_port = d.split(":", 1)[1]
        if not new_port.isdigit():
            await query.edit_message_text("❌ مقدار پورت نامعتبر است.")
            return
        await asyncio.to_thread(_db_update_setting, 'port', new_port)
        _diag_core_ip = await asyncio.to_thread(_get_core_public_ip_cached)
        if _diag_core_ip:
            await asyncio.to_thread(_db_set_host_ssh_port, _diag_core_ip, new_port)
        await query.edit_message_text(
            f"✅ تنظیمات ربات به‌روزرسانی شد — پورت SSH الان روی <code>{esc(new_port)}</code> ثبت شده (مطابق با چیزی که sshd واقعاً رویش گوش می‌دهد).",
            parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🩹 بررسی دوباره", callback_data="srv_ssh_diag")],
                                                 [InlineKeyboardButton("🔙 بازگشت", callback_data="srv_menu_back")]]))


    elif d == "srv_health" and role == 'admin':
        await query.edit_message_text("⏳ در حال بررسی وضعیت سرور...")
        health, herr = await _get_server_health()
        conn_counts, conn_err = await _get_live_connection_counts()
        prt_for_conn = await asyncio.to_thread(_db_get_setting, 'port', '22')
        sock_count, sock_err = await _get_established_socket_count(prt_for_conn)
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔄 بروزرسانی", callback_data="srv_health")], [InlineKeyboardButton("🔙 بازگشت", callback_data="srv_menu_back")]])
        if not health:
            await query.edit_message_text(f"❌ خطا در بررسی وضعیت سرور:\n({esc(herr)})", reply_markup=kb); return
        proc_total = sum(conn_counts.values()) if conn_counts else 0
        # 🆕 عدد اصلیِ «اتصالات SSH زنده» فقط از روی شمارش پردازه (همان روش تأییدشده و دقیقی که در
        # «مشاهده کاربران آنلاین» استفاده می‌شود) محاسبه می‌شود، نه بیشترین مقدار بین آن و شمارش سوکت.
        # چون شمارش خام سوکت‌های TCP در وضعیت ESTABLISHED می‌تواند شامل اتصالات نیمه‌باز/راکد باشد —
        # مثلاً وقتی کلاینت موبایل بدون بستن تمیز اتصال (FIN/RST) از شبکه خارج می‌شود، سوکت تا رسیدن
        # زمان keepalive (که می‌تواند ساعت‌ها طول بکشد) هنوز ESTABLISHED نشان داده می‌شود، در حالی که
        # آن کاربر واقعاً دیگر متصل/آنلاین نیست. این باعث می‌شد عدد «زنده» خیلی بیشتر از تعداد واقعیِ
        # کاربران آنلاینِ همان لحظه نمایش داده شود.
        total_conns = proc_total
        mismatch_note = ""
        if sock_count is not None and sock_count != proc_total:
            mismatch_note = (f"\nℹ️ شمارش بر اساس پردازه (زنده): {proc_total} | بر اساس سوکت TCP کل (شامل احتمالاً اتصالات راکد/نیمه‌باز): {sock_count}")
        elif sock_count is None and not conn_err:
            mismatch_note = (f"\n⚠️ شمارش جایگزین (سوکت TCP) ناموفق بود: {esc(sock_err)}"
                              f"\n🔧 برای فعال‌شدنش این خط را هم به sudoers کاربر ربات اضافه کنید: NOPASSWD: /sbin/ss, /usr/sbin/ss")
        warns = []
        if health['cpu_pct'] >= 85: warns.append("⚠️ مصرف CPU بسیار بالاست.")
        if health['ram_pct'] >= 85: warns.append("⚠️ مصرف RAM بسیار بالاست.")
        if health['load1'] >= health['cpu_count'] * 1.5: warns.append("⚠️ Load Average نسبت به تعداد هسته‌ها بالاست؛ سرور زیر فشار است.")
        warn_txt = ("\n\n" + "\n".join(warns) + "\n💡 در صورت افت سرعت، می‌توانید از بخش «تنظیمات سرور ← 🌐 سرویس IP» بخشی از کاربران (یا حتی همه) را به هاست دیگری منتقل کنید؛ یا از همان‌جا دکمهٔ «انجام خودکار» را بزنید.") if warns else "\n\n✅ وضعیت سرور طبیعی است."
        disk_txt = esc(health['disk_line']) if health['disk_line'] else "در دسترس نیست"
        txt = (f"🖥 <b>وضعیت لحظه‌ای سرور</b>\n\n"
               f"⚙️ CPU: {health['cpu_pct']}٪ مصرف (از {health['cpu_count']} هسته)\n"
               f"🧠 RAM: {health['ram_used_mb']:,} / {health['ram_total_mb']:,} مگابایت ({health['ram_pct']}٪)\n"
               f"📈 Load Average: {health['load1']} / {health['load5']} / {health['load15']} (۱ / ۵ / ۱۵ دقیقه)\n"
               f"💾 دیسک (/): <code>{disk_txt}</code>\n"
               f"🔌 اتصالات SSH زنده: {total_conns}" + (f" ({esc(conn_err)})" if conn_err else "") + mismatch_note +
               warn_txt)
        await query.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    elif d == "srv_brand" and role == 'admin':
        context.user_data['state'] = 'BRAND_INPUT'
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="srv_menu_back")]])
        await query.edit_message_text("✍️ لطفاً نام برند جدید خود را وارد نمایید:", reply_markup=kb)
    elif d == "srv_hosts" and role == 'admin':
        ch = await asyncio.to_thread(_db_get_setting, 'hosts', LAST_RESORT_HOST_IP)
        context.user_data['state'] = 'HOSTS_INPUT'
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("➕ افزودن IP جدید (بدون حذف بقیه)", callback_data="srv_hosts_add")], [InlineKeyboardButton("🔙 بازگشت", callback_data="srv_direct_menu")]])
        await query.edit_message_text(f"🌐 هاست فعلی:\n<code>{esc(ch)}</code>\n\n✍️ لیست جدید را با کاما (,) جدا کرده و بفرستید (کل لیست جایگزین می‌شود):", parse_mode="HTML", reply_markup=kb)
    elif d == "srv_hosts_add" and role == 'admin':
        context.user_data['state'] = 'HOSTS_APPEND_INPUT'
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="srv_direct_menu")]])
        await query.edit_message_text("✍️ فقط IP جدید را بفرستید؛ به لیست فعلی اضافه می‌شود (بقیهٔ IPها دست‌نخورده می‌مانند):", reply_markup=kb)
    elif d == "srv_port" and role == 'admin':
        await _render_ssh_port_panel(query)

    elif d.startswith('sshport_edit:') and role == 'admin':
        target_host = d.split(':', 1)[1].strip()
        if not target_host or not await asyncio.to_thread(_db_host_exists, target_host):
            await query.answer('این IP دیگر در استخر نیست.', show_alert=True)
            return
        current_port = await asyncio.to_thread(_db_get_host_ssh_port, target_host, 22)
        context.user_data['ssh_port_target_host'] = target_host
        context.user_data['ssh_port_current'] = current_port
        context.user_data['state'] = 'SSH_PORT_NEW_INPUT'
        await query.edit_message_text(
            f"✏️ <b>تغییر واقعی پورت SSH</b>\n\n"
            f"IP: <code>{esc(target_host)}</code>\n"
            f"پورت فعلی: <code>{current_port}</code>\n\n"
            "پورت جدید را فقط به‌صورت عدد بین 1 تا 65535 بفرستید. سپس رمز root را می‌گیریم و ربات خودش تغییر، بازکردن فایروال و آزمون اتصال را انجام می‌دهد.",
            parse_mode='HTML', reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton('🔙 انصراف', callback_data='srv_port')]]))
    # 🆕 تنظیمات دامنه/پورتِ سرور TLS واقعی (مثلاً stunnel با گواهیِ معتبر) — این مقادیر هستند که
    # در کد اتصال SSH-TLS نپسترنت (و فاکتور اکانت‌های حالت TLS) استفاده می‌شوند. هیچ نصب/تغییری
    # روی خودِ سرور انجام نمی‌دهد؛ فقط آدرسی که ربات به مشتری می‌دهد را عوض می‌کند — پس قبل از
    # تغییر، مطمئن شوید سرور TLS واقعاً روی همان دامنه/پورت جدید در حال گوش‌دادن است.
    elif d == "srv_tls" and role == 'admin':
        cd = await asyncio.to_thread(_db_get_setting, 'tls_domain', 'ws.nvlsup.com')
        cp = await asyncio.to_thread(_db_get_setting, 'tls_port', '2088')
        context.user_data['state'] = 'TLS_INPUT'
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="srv_menu_back")]])
        await query.edit_message_text(
            f"🔐 دامنهٔ TLS فعلی: <code>{esc(cd)}</code>\n🔌 پورت TLS فعلی: <code>{esc(cp)}</code>\n\n"
            f"✍️ دامنه و پورت جدید را به‌صورت <code>دامنه:پورت</code> بفرستید (مثال: <code>ws.example.com:2088</code>).\n\n"
            f"⚠️ این دامنه/پورت باید دقیقاً همانی باشد که سرور TLS شما (مثلاً stunnel) واقعاً روی آن "
            f"در حال گوش‌دادن است و گواهیِ معتبر دارد — وگرنه کد اتصال SSH-TLS برای مشتری کار نمی‌کند.",
            parse_mode="HTML", reply_markup=kb)

    # 🆕 پنل «تنظیمات UDPGW» — به‌جای این‌که مستقیم وارد حالت ورودی متن بشه، حالا یه پنل کامله:
    # وضعیت فعلی (پورت + Transparent DNS) رو نشون می‌ده، یه دکمهٔ تست زنده داره (چون خودِ ربات
    # روی همین سرور اجرا می‌شه، می‌تونه مستقیماً چک کنه badvpn-udpgw واقعاً روی اون پورت گوش
    # می‌ده یا نه — بدون این‌که ادمین مجبور باشه دستی SSH بزنه)، و دکمهٔ تغییر پورت/DNS جداست.
    elif d == "srv_udpgw" and role == 'admin':
        await _render_udpgw_panel(query)

    elif d == "udpgw_test" and role == 'admin':
        cu = await asyncio.to_thread(_db_get_setting, 'udpgw_port', '7300')
        try:
            port_i = int(cu)
        except Exception:
            port_i = 7300
        await query.answer("⏳ در حال تست...")
        ok, err = await _tcp_health_check('127.0.0.1', port_i, timeout=4)
        if ok:
            await query.message.reply_text(f"✅ badvpn-udpgw روی پورت {port_i} در حال گوش‌دادن است.")
        else:
            await query.message.reply_text(f"🔴 هیچ سرویسی روی 127.0.0.1:{port_i} پاسخ نداد. خطا: {err}")

    elif d == "udpgw_toggle_dns" and role == 'admin':
        cur = (await asyncio.to_thread(_db_get_setting, 'udpgw_transparent_dns', '1')) == '1'
        await asyncio.to_thread(_db_update_setting, 'udpgw_transparent_dns', '0' if cur else '1')
        await _render_udpgw_panel(query)

    elif d == "udpgw_edit_port" and role == 'admin':
        cu = await asyncio.to_thread(_db_get_setting, 'udpgw_port', '7300')
        context.user_data['state'] = 'UDPGW_INPUT'
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 انصراف", callback_data="srv_udpgw")]])
        await query.edit_message_text(
            f"🔌 پورت UDPGW فعلی: <code>{esc(cu)}</code>\n\n"
            f"✍️ پورت جدید را فقط به‌صورت عدد بفرستید (مثال: <code>7300</code>).\n\n"
            f"⚠️ این باید دقیقاً همان پورتی باشد که <code>badvpn-udpgw</code> روی سرور با آن اجرا شده "
            f"(با دستور <code>sudo ss -lunp | grep badvpn</code> چک کنید) — وگرنه کد اتصالِ کاربرانِ "
            f"جدید، پورت UDPGW اشتباه خواهد داشت.",
            parse_mode="HTML", reply_markup=kb)

    # 🔴🔵 RED & BLUE: عملیات سراسری روی همه کاربران سرور
    elif d == "srv_rb" and role == 'admin':
        locked = (await asyncio.to_thread(_db_get_setting, 'server_locked', '0')) == '1'
        status_line = "🔴 در حال حاضر سرور به‌صورت سراسری قطع است" if locked else "🟢 در حال حاضر سرور متصل و فعال است"
        kb = [[InlineKeyboardButton("🔵 افزودن روز به همه کاربران", callback_data="rb_extend")],
              [InlineKeyboardButton("🔴 قطع کامل سرور", callback_data="rb_lock")],
              [InlineKeyboardButton("🟢 اتصال مجدد سرور", callback_data="rb_unlock")],
              [InlineKeyboardButton("🔙 بازگشت", callback_data="srv_menu_back")]]
        await query.edit_message_text(
            f"🔴🔵 <b>RED & BLUE</b>\n{status_line}\n\n"
            f"🔵 <b>افزودن روز به همه کاربران</b>: تاریخ انقضای تمام اکانت‌های سرور را به‌یک‌باره چند روز عقب می‌اندازد "
            f"(مثلاً برای جبران قطعی اینترنت).\n"
            f"🔴 <b>قطع کامل سرور</b>: تمام کاربران را بدون تغییر در وضعیت ثبت‌شده‌شان در دیتابیس، غیرفعال می‌کند.\n"
            f"🟢 <b>اتصال مجدد سرور</b>: فقط کاربرانی که وضعیت‌شان «فعال» ثبت شده را دوباره وصل می‌کند "
            f"(کاربرانی که خودتان قبلاً جداگانه غیرفعال کرده بودید، غیرفعال باقی می‌مانند).\n\n"
            f"⚠️ هر سه گزینه ابتدا رمز تایید مدیر را می‌خواهند.",
            reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
    elif d == "rb_extend" and role == 'admin':
        context.user_data['state'] = 'RB_PASS_EXTEND'
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 انصراف", callback_data="srv_rb")]])
        await query.edit_message_text("🔐 برای افزودن روز به همه کاربران، رمز تایید مدیر را بفرستید:", reply_markup=kb)
    elif d == "rb_lock" and role == 'admin':
        context.user_data['state'] = 'RB_PASS_LOCK'
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 انصراف", callback_data="srv_rb")]])
        await query.edit_message_text("🔐 برای قطع کامل سرور، رمز تایید مدیر را بفرستید:", reply_markup=kb)
    elif d == "rb_unlock" and role == 'admin':
        context.user_data['state'] = 'RB_PASS_UNLOCK'
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 انصراف", callback_data="srv_rb")]])
        await query.edit_message_text("🔐 برای اتصال مجدد سرور، رمز تایید مدیر را بفرستید:", reply_markup=kb)
    elif d == "rb_extend_cancel" and role == 'admin':
        safe_clear_context(context); await query.edit_message_text("❌ عملیات لغو شد.")
    elif d == "rb_lock_cancel" and role == 'admin':
        safe_clear_context(context); await query.edit_message_text("❌ عملیات لغو شد.")
    elif d == "rb_unlock_cancel" and role == 'admin':
        safe_clear_context(context); await query.edit_message_text("❌ عملیات لغو شد.")
    elif d == "rb_extend_confirm" and role == 'admin':
        days = context.user_data.get('rb_days')
        if not days: safe_clear_context(context); return await query.edit_message_text("❌ درخواست منقضی شده؛ دوباره تلاش کنید.")
        await query.edit_message_text("⏳ در حال اعمال روی همه اکانت‌ها در پس‌زمینه... (ممکن است کمی طول بکشد)")
        
        async def _bg_extend():
            accounts = await asyncio.to_thread(_db_get_all_accounts_full)
            sem = asyncio.Semaphore(8)
            ok_count, fail_count = 0, 0
            async def _extend_one(un, old_exp, host, stype):
                nonlocal ok_count, fail_count
                async with sem:
                    try:
                        base_dt = datetime.strptime(old_exp, "%Y-%m-%d")
                    except Exception:
                        base_dt = datetime.now()
                    new_exp_dt = base_dt + timedelta(days=days)
                    new_exp = new_exp_dt.strftime("%Y-%m-%d")
                    
                    if stype == 'v2ray':
                        m_url = await asyncio.to_thread(_db_get_setting, 'marzban_url', '')
                        m_user = await asyncio.to_thread(_db_get_setting, 'marzban_username', '')
                        m_pwd = await asyncio.to_thread(_db_get_setting, 'marzban_password', '')
                        ok, _ = await v2ray_engine.modify_user(m_url, m_user, m_pwd, un, expire=int(new_exp_dt.timestamp()))
                        if ok:
                            await asyncio.to_thread(_db_extend_user, un, new_exp); ok_count += 1
                        else:
                            fail_count += 1
                    else:
                        ok, _err, _kind = await run_cmd(
                            "sudo", "usermod", "-e", new_exp, un
                        )
                        if ok:
                            await asyncio.to_thread(_db_extend_user, un, new_exp); ok_count += 1
                        else:
                            fail_count += 1
                            
            await asyncio.gather(*[_extend_one(u, exp, host, stype) for u, exp, _st, host, stype in accounts])
            await context.bot.send_message(query.message.chat_id, f"✅ عملیات افزودن زمان تمام شد.\n🔵 {ok_count} اکانت (SSH و V2Ray) با موفقیت {days} روز تمدید شدند.\n" + (f"⚠️ {fail_count} اکانت با خطا مواجه شدند." if fail_count else ""))
            
        spawn_bg_task(_bg_extend())
        safe_clear_context(context)

    elif d == "rb_lock_confirm" and role == 'admin':
        await query.edit_message_text("⏳ در حال قطع تمام کاربران سرور در پس‌زمینه... (نتیجه ارسال خواهد شد)")
        async def _bg_lock():
            accounts = await asyncio.to_thread(_db_get_all_accounts_full)
            sem = asyncio.Semaphore(8)
            ok_count, fail_count = 0, 0
            async def _lock_one(un, host, stype):
                nonlocal ok_count, fail_count
                async with sem:
                    if stype == 'v2ray':
                        m_url = await asyncio.to_thread(_db_get_setting, 'marzban_url', '')
                        m_user = await asyncio.to_thread(_db_get_setting, 'marzban_username', '')
                        m_pwd = await asyncio.to_thread(_db_get_setting, 'marzban_password', '')
                        ok, _ = await v2ray_engine.modify_user(m_url, m_user, m_pwd, un, status='disabled')
                        if ok: ok_count += 1
                        else: fail_count += 1
                    else:
                        ok, _err, _kind = await run_cmd(
                            "sudo", "usermod", "-L", un
                        )
                        if ok: ok_count += 1
                        else: fail_count += 1
            await asyncio.gather(*[_lock_one(u, host, stype) for u, _exp, _st, host, stype in accounts])
            await asyncio.to_thread(_db_update_setting, 'server_locked', '1')
            await context.bot.send_message(query.message.chat_id, f"🔴 سرور به‌صورت سراسری قطع شد.\n{ok_count} کاربر غیرفعال شدند." + (f"\n⚠️ {fail_count} مورد با خطا مواجه شد." if fail_count else ""))
            
        spawn_bg_task(_bg_lock())
        safe_clear_context(context)

    elif d == "rb_unlock_confirm" and role == 'admin':
        await query.edit_message_text("⏳ در حال اتصال مجدد کاربران فعال در پس‌زمینه... (نتیجه ارسال خواهد شد)")
        async def _bg_unlock():
            accounts = await asyncio.to_thread(_db_get_all_accounts_full)
            targets = [(u, host, stype) for u, _exp, st, host, stype in accounts if st == '🟢 فعال']
            sem = asyncio.Semaphore(8)
            ok_count, fail_count = 0, 0
            async def _unlock_one(un, host, stype):
                nonlocal ok_count, fail_count
                async with sem:
                    if stype == 'v2ray':
                        m_url = await asyncio.to_thread(_db_get_setting, 'marzban_url', '')
                        m_user = await asyncio.to_thread(_db_get_setting, 'marzban_username', '')
                        m_pwd = await asyncio.to_thread(_db_get_setting, 'marzban_password', '')
                        ok, _ = await v2ray_engine.modify_user(m_url, m_user, m_pwd, un, status='active')
                        if ok: ok_count += 1
                        else: fail_count += 1
                    else:
                        ok, _err, _kind = await run_cmd(
                            "sudo", "usermod", "-U", un
                        )
                        if ok: ok_count += 1
                        else: fail_count += 1
            await asyncio.gather(*[_unlock_one(u, host, stype) for u, host, stype in targets])
            await asyncio.to_thread(_db_update_setting, 'server_locked', '0')
            skipped = len(accounts) - len(targets)
            await context.bot.send_message(query.message.chat_id, f"🟢 سرور دوباره متصل شد.\n{ok_count} کاربر (فعال) وصل شدند." + (f"\nℹ️ {skipped} کاربری که از قبل غیرفعال بودند، دست‌نخورده باقی ماندند." if skipped else "") + (f"\n⚠️ {fail_count} مورد با خطا مواجه شد." if fail_count else ""))
            
        spawn_bg_task(_bg_unlock())
        safe_clear_context(context)

    # بخش نمایندگان
    elif d == "agm_add" and role == 'admin':
        context.user_data['state'] = 'AGENT_NEW_USER'
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="agm_menu_back")]])
        await query.edit_message_text("✍️ یوزرنیم برای نماینده را بفرستید:", reply_markup=kb)
    elif d == "agm_menu_back" and role == 'admin':
        kb = [[InlineKeyboardButton("➕ افزودن نماینده جدید", callback_data="agm_add")], [InlineKeyboardButton("📋 لیست نمایندگان", callback_data="agm_list")],
              [InlineKeyboardButton("📊 گزارش مالی نمایندگان", callback_data="agm_finlist")],
              [InlineKeyboardButton("🔙 بازگشت", callback_data="uact_back_to_menu")]]
        await query.edit_message_text("💼 <b>پنل مدیریت نمایندگان فروش</b>", reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
    elif d == "agm_list" and role == 'admin':
        agents = await asyncio.to_thread(_db_get_all_agents)
        kb = [[InlineKeyboardButton(f"💼 {a[1]} ({a[2]})", callback_data=f"agm_det_{a[0]}")] for a in agents]
        kb.append([InlineKeyboardButton("🔙 بازگشت", callback_data="agm_menu_back")])
        await query.edit_message_text("لیست نمایندگان:", reply_markup=InlineKeyboardMarkup(kb))
    # 🆕 گزارش مالی نمایندگان: لیست نام همهٔ نمایندگان (مشابه لیست معمولی)، ولی با زدن روی هرکدام
    # به‌جای پنل جزئیات، فقط واریزی‌های تاییدشدهٔ (کارت‌به‌کارت) همان نماینده با تاریخ/ساعت دقیق نشان داده می‌شود.
    elif d == "agm_finlist" and role == 'admin':
        agents = await asyncio.to_thread(_db_get_all_agents)
        if not agents:
            kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="agm_menu_back")]])
            await query.edit_message_text("هنوز هیچ نماینده‌ای ثبت نشده.", reply_markup=kb); return
        kb = [[InlineKeyboardButton(f"💼 {a[1]}", callback_data=f"agm_findet_{a[0]}")] for a in agents]
        kb.append([InlineKeyboardButton("🔙 بازگشت", callback_data="agm_menu_back")])
        await query.edit_message_text("📊 گزارش مالی نمایندگان — یک نماینده را برای دیدن واریزی‌هایش انتخاب کنید:", reply_markup=InlineKeyboardMarkup(kb))
    elif d.startswith("agm_findet_") and role == 'admin':
        a_id = int(d.split("_", 2)[2])
        info = await asyncio.to_thread(_db_get_agent_info, a_id)
        if not info:
            kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت به لیست", callback_data="agm_finlist")]])
            await query.edit_message_text("❌ این نماینده دیگر وجود ندارد.", reply_markup=kb); return
        rows = await asyncio.to_thread(_db_get_agent_receipts, a_id)
        if not rows:
            txt = f"📊 <b>گزارش مالی «{esc(info[0])}»</b>\n\nهنوز هیچ واریزی تاییدشده‌ای از این نماینده ثبت نشده."
        else:
            shown = rows[:50]
            lines = []
            for amt, dt, sub_aid, sub_name in shown:
                tag = f" (زیرمجموعه: {esc(sub_name)})" if sub_aid != a_id else ""
                lines.append(f"💰 {int(amt):,} تومان — {format_db_datetime_to_jalali(dt)}{tag}")
            more_note = f"\n\n… و {len(rows) - 50} واریزی قدیمی‌تر (نمایش داده نشد)" if len(rows) > 50 else ""
            total = sum(r[0] for r in rows)
            txt = (f"📊 <b>گزارش مالی «{esc(info[0])}»</b>\n\n" + "\n".join(lines) + more_note +
                   f"\n\n💵 جمع کل: {int(total):,} تومان ({len(rows)} واریزی)")
        # 🆕 دکمهٔ صدور/لغو مجوزِ «کارت اختصاصی خودگردان» — فقط همین‌جا (گزارش مالی نمایندگان)
        # در دسترس ادمینه. با صدور مجوز، دکمهٔ «کارت اختصاصی من» توی پنل خودِ این نماینده ظاهر
        # می‌شود (و فقط برای همین نماینده؛ بقیهٔ نمایندگان همچنان چیزی نمی‌بینند).
        has_perm = await asyncio.to_thread(_db_get_agent_card_permission, a_id)
        perm_btn_txt = "🔒 لغو مجوز کارت اختصاصی" if has_perm else "🔓 صدور مجوز کارت اختصاصی"
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton(perm_btn_txt, callback_data=f"agm_cardperm_{a_id}")],
            [InlineKeyboardButton("🔙 بازگشت به لیست", callback_data="agm_finlist")]])
        await query.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    # 🆕 صدور/لغو مجوز کارت اختصاصی خودگردان یک نماینده (toggle) — پیام را با وضعیت جدید بازسازی می‌کند.
    elif d.startswith("agm_cardperm_") and role == 'admin':
        a_id = int(d.split("_", 2)[2])
        info = await asyncio.to_thread(_db_get_agent_info, a_id)
        if not info:
            kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت به لیست", callback_data="agm_finlist")]])
            await query.edit_message_text("❌ این نماینده دیگر وجود ندارد.", reply_markup=kb); return
        new_state = await asyncio.to_thread(_db_toggle_agent_card_permission, a_id)
        await query.message.reply_text("✅ مجوز صادر شد." if new_state else "🔒 مجوز لغو شد.")
        # 🔁 همون صفحهٔ گزارش مالی همین نماینده را با وضعیت تازهٔ دکمه دوباره نمایش می‌دهیم
        rows = await asyncio.to_thread(_db_get_agent_receipts, a_id)
        if not rows:
            txt = f"📊 <b>گزارش مالی «{esc(info[0])}»</b>\n\nهنوز هیچ واریزی تاییدشده‌ای از این نماینده ثبت نشده."
        else:
            shown = rows[:50]
            lines = []
            for amt, dt, sub_aid, sub_name in shown:
                tag = f" (زیرمجموعه: {esc(sub_name)})" if sub_aid != a_id else ""
                lines.append(f"💰 {int(amt):,} تومان — {format_db_datetime_to_jalali(dt)}{tag}")
            more_note = f"\n\n… و {len(rows) - 50} واریزی قدیمی‌تر (نمایش داده نشد)" if len(rows) > 50 else ""
            total = sum(r[0] for r in rows)
            txt = (f"📊 <b>گزارش مالی «{esc(info[0])}»</b>\n\n" + "\n".join(lines) + more_note +
                   f"\n\n💵 جمع کل: {int(total):,} تومان ({len(rows)} واریزی)")
        perm_btn_txt = "🔒 لغو مجوز کارت اختصاصی" if new_state else "🔓 صدور مجوز کارت اختصاصی"
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton(perm_btn_txt, callback_data=f"agm_cardperm_{a_id}")],
            [InlineKeyboardButton("🔙 بازگشت به لیست", callback_data="agm_finlist")]])
        await query.edit_message_text(txt, reply_markup=kb, parse_mode="HTML")
    elif d.startswith("agm_det_") and role == 'admin':
        a_id = int(d.split("_")[2])
        await _show_agent_detail(query, context, a_id)
    elif d.startswith("agm_users_") and role == 'admin':
        a_id = int(d.split("_")[2])
        await _show_users_panel(update, context, page=0, agent_filter=a_id)
    elif d.startswith("agm_prefix_") and role == 'admin':
        a_id = int(d.split("_")[2])
        info = await asyncio.to_thread(_db_get_agent_info, a_id)
        if not info: await query.edit_message_text("❌ وجود ندارد."); return
        context.user_data['edit_ag_id'] = a_id; context.user_data['state'] = 'AGENT_EDIT_PREFIX'
        cur_prefix = info[10] if len(info) > 10 and info[10] else "پیش‌فرض سیستم"
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data=f"agm_det_{a_id}")]])
        await query.message.reply_text(
            f"🏷 پیشوند فعلی «{esc(info[0])}»: <code>{esc(cur_prefix)}</code>\n\n"
            f"پیشوند جدید را بفرستید (فقط حروف/عدد انگلیسی)، یا 0 برای بازگشت به پیش‌فرض سیستم:", parse_mode="HTML", reply_markup=kb)
    elif d.startswith("agm_topup_") and role == 'admin':
        a_id = int(d.split("_")[2])
        info = await asyncio.to_thread(_db_get_agent_info, a_id)
        if not info: await query.edit_message_text("❌ وجود ندارد."); return
        context.user_data['topup_ag_id'] = a_id; context.user_data['state'] = 'AGENT_MANUAL_TOPUP'
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data=f"agm_det_{a_id}")]])
        emergency_used = info[12] if len(info) > 12 and info[12] else 0.0
        emergency_note = ""
        if emergency_used > 0:
            emergency_note = (f"\n🆘 این نماینده <b>{int(emergency_used):,} تومان</b> از شارژ اضطراری استفاده کرده؛ "
                               f"این مبلغ خودکار از همین شارژ کسر خواهد شد.\n")
        await query.message.reply_text(
            f"💰 مبلغی که می‌خواهید مستقیماً به کیف‌پول «{esc(info[0])}» اضافه شود را بفرستید (فقط عدد، به تومان).\n"
            f"موجودی فعلی: {int(info[2]):,} تومان\n{emergency_note}\n"
            f"⚠️ این شارژ بدون نیاز به رسید کارت‌به‌کارت، بلافاصله اعمال می‌شود.", reply_markup=kb, parse_mode="HTML")
    # ➖ کاهش شارژ کیف‌پول یک نماینده — برای اصلاح شارژهای اشتباهی (مثلاً تایپی در مبلغ).
    elif d.startswith("agm_deduct_") and role == 'admin':
        a_id = int(d.split("_")[2])
        info = await asyncio.to_thread(_db_get_agent_info, a_id)
        if not info: await query.edit_message_text("❌ وجود ندارد."); return
        context.user_data['deduct_ag_id'] = a_id; context.user_data['state'] = 'AGENT_MANUAL_DEDUCT'
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data=f"agm_det_{a_id}")]])
        await query.message.reply_text(
            f"➖ مبلغی که می‌خواهید مستقیماً از کیف‌پول «{esc(info[0])}» کم شود را بفرستید (فقط عدد، به تومان).\n"
            f"موجودی فعلی: {int(info[2]):,} تومان\n\n"
            f"⚠️ این کاهش بلافاصله اعمال می‌شود و برای اصلاح شارژهای اشتباهی است.", reply_markup=kb, parse_mode="HTML")
    # ==========================================
    # 🧾 لیست درخواست‌های برداشت یک نماینده (نمای ادمین) + ارسال رسید واریز
    # ==========================================
    elif d.startswith("agm_wdlist_") and role == 'admin':
        a_id = int(d.split("_")[2])
        info = await asyncio.to_thread(_db_get_agent_info, a_id)
        if not info: await query.edit_message_text("❌ وجود ندارد."); return
        rows = await asyncio.to_thread(_db_get_agent_pending_withdrawals, a_id)
        kb = [[InlineKeyboardButton("🔙 بازگشت", callback_data=f"agm_det_{a_id}")]]
        if not rows:
            await query.edit_message_text(f"«{esc(info[0])}» هیچ درخواست برداشت در انتظاری ندارد.", reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML"); return
        lines = [f"🧾 <b>درخواست‌های برداشت در انتظار «{esc(info[0])}»:</b>\n"]
        req_buttons = []
        for rid, amount, card, full_name, created_at in rows:
            lines.append(f"• #{rid} — {int(amount):,} تومان — {esc(full_name)} — <code>{esc(card)}</code> — {esc(created_at)}")
            req_buttons.append([InlineKeyboardButton(f"📤 ارسال رسید #{rid} ({int(amount):,} تومان)", callback_data=f"agm_sendrcpt_{rid}")])
        await query.edit_message_text("\n".join(lines), reply_markup=InlineKeyboardMarkup(req_buttons + kb), parse_mode="HTML")
    elif d.startswith("agm_sendrcpt_") and role == 'admin':
        req_id = int(d.split("_")[2])
        req = await asyncio.to_thread(_db_get_withdrawal_request, req_id)
        if not req or req[5] != 'pending':
            await query.message.reply_text("❌ این درخواست دیگر معتبر نیست (شاید قبلاً پردازش شده)."); return
        _, a_id, amount, card, full_name, status, created_at = req
        context.user_data['state'] = 'ADMIN_SEND_RECEIPT_PHOTO'
        context.user_data['pending_receipt_req_id'] = req_id
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data=f"agm_wdlist_{a_id}")]])
        await query.message.reply_text(
            f"📤 در حال ارسال رسید برای درخواست #{req_id}:\n💰 مبلغ: {int(amount):,} تومان\n👤 نام: {esc(full_name)}\n💳 کارت: <code>{esc(card)}</code>\n\n"
            f"📸 لطفاً عکس رسید واریز را همین‌جا ارسال کنید تا مستقیماً برای نماینده فرستاده شود:", reply_markup=kb, parse_mode="HTML")
    # 🆕 تغییر یوزرنیم/پسورد ورود یک نماینده توسط ادمین — مثل تغییر پسورد کاربران، قبل از اعمال
    # واقعی یک تاییدیهٔ بله/خیر گرفته می‌شود تا تایپ اشتباهی حساب یک نماینده را قفل نکند.
    elif d.startswith("agm_edituser_") and role == 'admin':
        a_id = int(d.split("_", 2)[2])
        info = await asyncio.to_thread(_db_get_agent_info, a_id)
        if not info: return await query.edit_message_text("❌ این نماینده دیگر وجود ندارد.")
        cur_username = info[11] if len(info) > 11 and info[11] else "-"
        context.user_data['edit_ag_id'] = a_id; context.user_data['state'] = 'AGENT_EDIT_USERNAME'
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data=f"agm_det_{a_id}")]])
        await query.message.reply_text(
            f"👤 یوزرنیم ورود فعلی «{esc(info[0])}»: <code>{esc(cur_username)}</code>\n\n"
            f"یوزرنیم جدید را بفرستید:", parse_mode="HTML", reply_markup=kb)
    elif d.startswith("agm_editpass_") and role == 'admin':
        a_id = int(d.split("_", 2)[2])
        info = await asyncio.to_thread(_db_get_agent_info, a_id)
        if not info: return await query.edit_message_text("❌ این نماینده دیگر وجود ندارد.")
        context.user_data['edit_ag_id'] = a_id; context.user_data['state'] = 'AGENT_EDIT_PASSWORD'
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data=f"agm_det_{a_id}")]])
        await query.message.reply_text(f"🔑 پسورد ورود جدید برای نمایندهٔ «{esc(info[0])}» را بفرستید:", reply_markup=kb)
    elif d == "aguserconf_yes" and role == 'admin':
        a_id = context.user_data.get('edit_ag_id'); new_u = context.user_data.get('pending_new_agent_username')
        if not a_id or not new_u:
            return await query.edit_message_text("❌ تراکنش منقضی شده است.")
        info = await asyncio.to_thread(_db_get_agent_info, a_id)
        if not info: return await query.edit_message_text("❌ این نماینده دیگر وجود ندارد.")
        ok = await asyncio.to_thread(_db_update_agent_username, a_id, new_u)
        context.user_data.pop('pending_new_agent_username', None)
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت به پنل نماینده", callback_data=f"agm_det_{a_id}")]])
        if ok:
            await query.edit_message_text(f"✅ یوزرنیم ورود «{esc(info[0])}» به <code>{esc(new_u)}</code> تغییر کرد.", reply_markup=kb, parse_mode="HTML")
        else:
            await query.edit_message_text(f"❌ این یوزرنیم قبلاً توسط نمایندهٔ دیگری استفاده شده. یوزرنیم دیگری امتحان کنید.", reply_markup=kb)
        safe_clear_context(context)
    elif d == "aguserconf_no" and role == 'admin':
        a_id = context.user_data.get('edit_ag_id')
        context.user_data.pop('pending_new_agent_username', None)
        safe_clear_context(context)
        if a_id: await _show_agent_detail(query, context, a_id)
        else: await query.edit_message_text("↩️ لغو شد.")
    elif d == "agpassconf_yes" and role == 'admin':
        a_id = context.user_data.get('edit_ag_id'); new_p = context.user_data.get('pending_new_agent_pass')
        if not a_id or not new_p:
            return await query.edit_message_text("❌ تراکنش منقضی شده است.")
        info = await asyncio.to_thread(_db_get_agent_info, a_id)
        if not info: return await query.edit_message_text("❌ این نماینده دیگر وجود ندارد.")
        await asyncio.to_thread(_db_update_agent_password, a_id, new_p)
        context.user_data.pop('pending_new_agent_pass', None)
        safe_clear_context(context)
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت به پنل نماینده", callback_data=f"agm_det_{a_id}")]])
        await query.edit_message_text(f"✅ پسورد ورود «{esc(info[0])}» با موفقیت تغییر کرد.", reply_markup=kb)
    elif d == "agpassconf_no" and role == 'admin':
        a_id = context.user_data.get('edit_ag_id')
        context.user_data.pop('pending_new_agent_pass', None)
        safe_clear_context(context)
        if a_id: await _show_agent_detail(query, context, a_id)
        else: await query.edit_message_text("↩️ لغو شد.")
    elif d.startswith("ag_p_") and role == 'admin':
        a_id = int(d.split("_")[2]); context.user_data['edit_ag_id'] = a_id; context.user_data['state'] = 'AGENT_EDIT_PRICE'
        await query.message.reply_text("💵 قیمت پایهٔ SSH این نماینده را بفرستید (فقط عدد، به تومان).\n\n⚠️ این عدد «نرخ هر کاربر در هر ماه» است؛ هزینهٔ نهایی هر خرید (بدون هیچ تخفیفی) به‌صورت خودکار برابر است با:\nقیمت پایه × تعداد ماه × تعداد کاربر\n\nمثال: اگر اینجا 100000 بفرستید، یک اکانت «۲ ماهه ۳ کاربره» برای این نماینده دقیقاً 600,000 تومان محاسبه می‌شود.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data=f"agm_det_{a_id}")]]))
    elif d.startswith("ag_pv2_") and role == 'admin':
        a_id = int(d.split("_")[2]); context.user_data['edit_ag_id'] = a_id; context.user_data['state'] = 'AGENT_EDIT_PRICE_V2'
        await query.message.reply_text("🚀 قیمت پایهٔ V2Ray این نماینده را بفرستید (فقط عدد، به تومان).\nپیش‌فرض: 160000", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data=f"agm_det_{a_id}")]]))
    elif d.startswith("ag_pv2v_") and role == 'admin':
        a_id = int(d.split("_")[2]); context.user_data['edit_ag_id'] = a_id; context.user_data['state'] = 'AGENT_EDIT_PRICE_V2_VOL'
        await query.message.reply_text("🪐 قیمت پایهٔ V2Ray حجمی (به ازای هر گیگابایت) این نماینده را بفرستید (فقط عدد، به تومان).\nپیش‌فرض: 4000", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data=f"agm_det_{a_id}")]]))
    elif d.startswith("ag_c1_") and role == 'admin':
        a_id = int(d.split("_")[2]); context.user_data['edit_ag_id'] = a_id; context.user_data['state'] = 'AGENT_EDIT_PCT1'
        await query.message.reply_text("📉 درصد لایه ۱ را بفرستید:", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data=f"agm_det_{a_id}")]]))
    elif d.startswith("ag_c2_") and role == 'admin':
        a_id = int(d.split("_")[2]); context.user_data['edit_ag_id'] = a_id; context.user_data['state'] = 'AGENT_EDIT_PCT2'
        await query.message.reply_text("📉 درصد لایه ۲ را بفرستید:", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data=f"agm_det_{a_id}")]]))
    elif d.startswith("ag_c3_") and role == 'admin':
        a_id = int(d.split("_")[2]); context.user_data['edit_ag_id'] = a_id; context.user_data['state'] = 'AGENT_EDIT_PCT3'
        await query.message.reply_text("📉 درصد لایه ۳ را بفرستید:", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data=f"agm_det_{a_id}")]]))
    elif d.startswith("agm_del_") and role == 'admin':
        # 🆕 قبل از حذف واقعی نماینده، تاییدیهٔ بله/خیر گرفته می‌شود (مشابه حذف اکانت)
        a_id = int(d.split("_")[2])
        info = await asyncio.to_thread(_db_get_agent_info, a_id)
        if not info: return await query.edit_message_text("❌ این نماینده دیگر وجود ندارد.")
        kb = [[InlineKeyboardButton("✅ بله، حذف شود", callback_data=f"agmdelconf_yes_{a_id}"), InlineKeyboardButton("↩️ خیر، انصراف", callback_data=f"agmdelconf_no_{a_id}")]]
        await query.edit_message_text(f"⚠️ آیا مطمئنید می‌خواهید نمایندهٔ «{esc(info[0])}» را به‌طور کامل حذف کنید؟\nاین عملیات قابل بازگشت نیست.", reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
    elif d.startswith("agmdelconf_yes_") and role == 'admin':
        a_id = int(d.split("_", 2)[2])
        await asyncio.to_thread(_db_delete_agent, a_id)
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت به لیست نمایندگان", callback_data="agm_list")]])
        await query.edit_message_text("✅ نماینده حذف شد.", reply_markup=kb)
    elif d.startswith("agmdelconf_no_") and role == 'admin':
        a_id = int(d.split("_", 2)[2])
        info = await asyncio.to_thread(_db_get_agent_info, a_id)
        if not info: return await query.edit_message_text("❌ این نماینده دیگر وجود ندارد.")
        t, w, m, act, total = await asyncio.to_thread(_db_get_sales_stats, a_id)
        referral_income = info[9] if len(info) > 9 and info[9] is not None else 0
        txt = (f"💼 نماینده: {esc(info[0])}\n🔑 رفرال: <code>{esc(info[1])}</code>\n💰 موجودی: {int(info[2]):,} تومان\n"
               f"💹 درآمد از زیرمجموعه: {int(referral_income):,} تومان\n\n"
               f"📉 <b>درصدهای شبکه:</b>\nلایه 1: {info[3]}%\nلایه 2: {info[5]}%\nلایه 3: {info[6]}%\n\n"
               f"📦 کل اکانت‌های فروخته‌شده: {total}\nفروش امروز: {t} | فروش هفته: {w} | فروش ماه: {m}\nاکانت فعال: {act}")
        kb = [[InlineKeyboardButton("👥 مشاهده کاربران این نماینده", callback_data=f"agm_users_{a_id}")],
              [InlineKeyboardButton("💰 شارژ مستقیم کیف‌پول", callback_data=f"agm_topup_{a_id}")],
              [InlineKeyboardButton("💵 تنظیم قیمت پایه", callback_data=f"ag_p_{a_id}"), InlineKeyboardButton("📉 تخفیف مستقیم", callback_data=f"ag_c1_{a_id}")],
              [InlineKeyboardButton("📉 تخفیف پدر", callback_data=f"ag_c2_{a_id}"), InlineKeyboardButton("📉 تخفیف پدربزرگ", callback_data=f"ag_c3_{a_id}")],
              [InlineKeyboardButton("🗑 حذف نماینده", callback_data=f"agm_del_{a_id}")],
              [InlineKeyboardButton("🔙 بازگشت به لیست", callback_data="agm_list")]]
        await query.edit_message_text(txt, reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")

    # گزارش‌ها و مانیتورینگ
    elif d == "info_general":
        if role == 'agent':
            info = await asyncio.to_thread(_db_get_agent_info, ag_id)
            if not info: return
            t, w, m_val, act, total = await asyncio.to_thread(_db_get_sales_stats, ag_id)
            t_ssh, w_ssh, m_ssh, act_ssh, total_ssh = await asyncio.to_thread(_db_get_sales_stats, ag_id, 'ssh')
            t_v2, w_v2, m_v2, act_v2, total_v2 = await asyncio.to_thread(_db_get_sales_stats, ag_id, 'v2ray')
            
            referral_income = info[9] if len(info) > 9 and info[9] is not None else 0
            my_prefix = info[10] if len(info) > 10 and info[10] else None
            withdrawable = info[14] if len(info) > 14 and info[14] is not None else 0.0
            cashback_income = info[15] if len(info) > 15 and info[15] is not None else 0.0
            
            v2_base_price = info[16] if len(info) > 16 and info[16] else '160000'
            try: ssh_bp_fmt = f"{int(str(info[4]).replace(',', '')):,}"
            except: ssh_bp_fmt = str(info[4])
            try: v2_bp_fmt = f"{int(str(v2_base_price).replace(',', '')):,}"
            except: v2_bp_fmt = str(v2_base_price)
            v2_vol_bp = info[17] if len(info) > 17 and info[17] else '4000'
            try: v2_vol_bp_fmt = f"{int(str(v2_vol_bp).replace(',', '')):,}"
            except: v2_vol_bp_fmt = str(v2_vol_bp)
            
            prefix_line = f"<code>{esc(my_prefix)}</code>" if my_prefix else "پیش‌فرض سیستم (تنظیم‌نشده)"
            cashback_note = ""
            if act >= AGENT_CASHBACK_MIN_ACTIVE_ACCOUNTS:
                cashback_note = f"🎁 شما به‌خاطر {act} اکانت فعال، از این پس {int(AGENT_CASHBACK_PCT)}٪ کش‌بک هر خرید را دریافت می‌کنید!\n"
            else:
                remain_for_cashback = AGENT_CASHBACK_MIN_ACTIVE_ACCOUNTS - act
                cashback_note = f"🎁 با {remain_for_cashback} اکانت فعال دیگر (مجموع {AGENT_CASHBACK_MIN_ACTIVE_ACCOUNTS}+)، {int(AGENT_CASHBACK_PCT)}٪ کش‌بک هر خرید را دریافت می‌کنید.\n"
            
            txt = (f"📊 <b>اطلاعات حساب نمایندگی</b>\n\n"
                   f"🔑 کد رفرال شما: <code>{esc(info[1])}</code>\n"
                   f"💰 موجودی کیف‌پول (شارژ باقی‌مانده): {int(info[2]):,} تومان\n"
                   f"💵 نرخ پایه SSH (هر کاربر/ماه): {ssh_bp_fmt} تومان\n"
                   f"🚀 نرخ پایه V2Ray (هر کاربر/ماه): {v2_bp_fmt} تومان\n"
                   f"🪐 نرخ پایه V2Ray حجمی (هر گیگ): {v2_vol_bp_fmt} تومان\n"
                   f"💹 درآمد از زیرمجموعه‌گیری (پورسانت شبکه): {int(referral_income):,} تومان\n"
                   f"🎁 مجموع کش‌بک دریافتی: {int(cashback_income):,} تومان\n"
                   f"💵 <b>استخر قابل‌برداشت (پورسانت + کش‌بک):</b> {int(withdrawable):,} تومان\n"
                   f"{cashback_note}"
                   f"🏷 پیشوند یوزرنیم اکانت‌های شما: {prefix_line}\n\n"
                   f"📦 <b>آمار کل فروش شما:</b>\n"
                   f"کل فروخته‌شده: {total} | اکانت فعال: {act}\n"
                   f"فروش امروز: {t} | فروش هفته: {w} | فروش ماه: {m_val}\n\n"
                   f"🔹 <b>تفکیک SSH:</b>\n"
                   f"کل فروخته‌شده: {total_ssh} | اکانت فعال: {act_ssh}\n"
                   f"فروش امروز: {t_ssh} | فروش هفته: {w_ssh} | فروش ماه: {m_ssh}\n\n"
                   f"🚀 <b>تفکیک V2Ray:</b>\n"
                   f"کل فروخته‌شده: {total_v2} | اکانت فعال: {act_v2}\n"
                   f"فروش امروز: {t_v2} | فروش هفته: {w_v2} | فروش ماه: {m_v2}")
            kb = []
            if withdrawable > 0:
                kb.append([InlineKeyboardButton("💵 برداشت وجه از استخر", callback_data="wd_request"), InlineKeyboardButton("➕ افزودن به کیف‌پول", callback_data="wd_towallet")])
            pending_wds = await asyncio.to_thread(_db_get_agent_pending_withdrawals, ag_id)
            if pending_wds:
                kb.append([InlineKeyboardButton(f"🧾 درخواست‌های برداشت در انتظار ({len(pending_wds)})", callback_data="wd_mylist")])
            kb.append([InlineKeyboardButton("👥 زیرمجموعه‌های من", callback_data="mysubs_1")])
            kb.append([InlineKeyboardButton("🔙 بازگشت", callback_data="info_back")])
        else:
            bp = await asyncio.to_thread(_db_get_setting, 'base_price', '50,000 تومان')
            t, w, m_val, act, total = await asyncio.to_thread(_db_get_sales_stats, None)
            t_ssh, w_ssh, m_ssh, act_ssh, total_ssh = await asyncio.to_thread(_db_get_sales_stats, None, 'ssh')
            t_v2, w_v2, m_v2, act_v2, total_v2 = await asyncio.to_thread(_db_get_sales_stats, None, 'v2ray')
            txt = (f"📊 <b>آمار کل سیستم</b>\n💵 قیمت پایه مرکزی: {esc(bp)}\n\n"
                   f"📦 <b>مجموع کل فروش:</b>\n"
                   f"کل فروخته‌شده: {total} | اکانت فعال: {act}\n"
                   f"فروش امروز: {t} | فروش هفته: {w} | فروش ماه: {m_val}\n\n"
                   f"🔹 <b>تفکیک SSH:</b>\n"
                   f"کل فروخته‌شده: {total_ssh} | اکانت فعال: {act_ssh}\n"
                   f"فروش امروز: {t_ssh} | فروش هفته: {w_ssh} | فروش ماه: {m_ssh}\n\n"
                   f"🚀 <b>تفکیک V2Ray:</b>\n"
                   f"کل فروخته‌شده: {total_v2} | اکانت فعال: {act_v2}\n"
                   f"فروش امروز: {t_v2} | فروش هفته: {w_v2} | فروش ماه: {m_v2}")
            kb = [[InlineKeyboardButton("🔙 بازگشت", callback_data="info_back")]]
        await query.edit_message_text(txt, reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
    elif d == "ag_self_prefix" and role == 'agent':
        context.user_data['state'] = 'AGENT_SELF_PREFIX_INPUT'
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="info_general")]])
        await query.message.reply_text(
            "🏷 پیشوند دلخواه برای یوزرنیم اکانت‌هایی که از این پس می‌سازید را بفرستید (فقط حروف/عدد انگلیسی، بدون فاصله).\n"
            "این پیشوند فقط مخصوص خودتان است و روی ادمین یا نمایندگان دیگر هیچ اثری ندارد.\n"
            "برای بازگشت به حالت پیش‌فرض سیستم، عدد 0 را بفرستید.", reply_markup=kb)
    # 🆕 ثبت/ویرایش خودگردانِ کارت اختصاصی توسط خودِ نماینده — فقط اگر مجوزش صادر شده باشد
    # (چک دیتابیسی مجدد اینجا هم انجام می‌شود، چون کلیک روی یه کیبورد قدیمی/کش‌شده هم ممکنه).
    elif d == "agself_card_set" and role == 'agent':
        ag_id = context.user_data.get('agent_id', 0)
        if not ag_id or not await asyncio.to_thread(_db_get_agent_card_permission, ag_id):
            await query.message.reply_text("❌ شما مجوز این بخش را ندارید."); return
        context.user_data['state'] = 'AGSELF_CARD_NUM'
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 انصراف", callback_data="uact_back_to_menu")]])
        await query.message.reply_text("💳 لطفاً شمارهٔ کارت بانکی خودتان را بفرستید (فقط عدد، بدون خط تیره):", reply_markup=kb)
    elif d == "agself_card_clear" and role == 'agent':
        ag_id = context.user_data.get('agent_id', 0)
        if not ag_id or not await asyncio.to_thread(_db_get_agent_card_permission, ag_id):
            await query.message.reply_text("❌ شما مجوز این بخش را ندارید."); return
        await asyncio.to_thread(_db_clear_agent_card, ag_id)
        await query.edit_message_text(
            "✅ کارت اختصاصی شما حذف شد.\n\nاز این پس زیرمجموعه‌های شما دوباره کارت سیستم (یا کارت یکی از نمایندگان بالادستی‌تان، در صورت وجود) را می‌بینند.")
    elif d == "info_online":
        counts, monitor_error = await _get_live_connection_counts()

        if monitor_error:
            log.error("مانیتورینگ کاربران آنلاین شکست خورد: %s", monitor_error)
            warn_txt = f"⚠️ <b>شمارش کاربران آنلاین ناموفق بود:</b>\n{esc(monitor_error)}\n\nاعداد زیر ممکن است نادرست (صفر) باشند."
        else:
            warn_txt = None

        all_u = await asyncio.to_thread(_db_get_users_with_agents)
        if role == 'agent':
            my_users = [u for u, aid in all_u if aid == ag_id]
            online_users = sorted(u for u in my_users if counts.get(u.lower(), 0) > 0)
            conns = sum(counts.get(u.lower(), 0) for u in my_users)
            my_active = await asyncio.to_thread(_db_get_active_accounts_count_by_agent, ag_id)
            
            total_my_ssh = sum(counts.users_detail[u.lower()]['ssh'] for u in my_users)
            total_my_tls = sum(counts.users_detail[u.lower()]['tls'] for u in my_users)

            txt = (f"⚡️ <b>کاربران آنلاین شما:</b>\n"
                   f"👤 تعداد کاربران آنلاین: {len(online_users)} نفر (از مجموع {len(my_users)} اکانت شما)\n"
                   f"✅ تعداد کاربران فعال (غیرمنقضی): {my_active} نفر\n"
                   f"🔌 تعداد کل اتصالات هم‌زمان: {conns} (مستقیم: {total_my_ssh} | TLS: {total_my_tls})")
            if online_users:
                shown = online_users[:40]
                txt += "\n\n📋 <b>لیست دقیق کاربران آنلاین شما:</b>\n" + "\n".join(
                    f"• <code>{esc(u)}</code> (مستقیم: {counts.users_detail[u.lower()]['ssh']} | TLS: {counts.users_detail[u.lower()]['tls']})" for u in shown)
                if len(online_users) > 40:
                    txt += f"\n… و {len(online_users) - 40} مورد دیگر"
            if warn_txt: txt = warn_txt + "\n\n" + txt
        else:
            agents = {a[0]: a[1] for a in await asyncio.to_thread(_db_get_all_agents)}
            total_users, total_conns, adm_u, adm_c, ag_u, ag_c = 0, 0, 0, 0, {}, {}
            online_list = []
            for u, aid in all_u:
                c = counts.get(u.lower(), 0)
                if c > 0:
                    total_users += 1; total_conns += c
                    online_list.append((u, aid, c))
                    if aid == 0: adm_u += 1; adm_c += c
                    else:
                        ag_u[aid] = ag_u.get(aid, 0) + 1
                        ag_c[aid] = ag_c.get(aid, 0) + c
            b_txt = f"• مستقیم: {adm_u} کاربر ({adm_c} اتصال)\n" + "".join(
                [f"• نماینده {esc(agents.get(i, '?'))}: {ag_u.get(i, 0)} کاربر ({ag_c.get(i, 0)} اتصال)\n" for i in ag_u])
            
            # کل اکانت‌های فروخته شده فارغ از نوع سرویس
            total_active_accounts = await asyncio.to_thread(_db_get_active_accounts_count)
            
            global_ssh = getattr(counts, 'global_ssh', 0)
            global_tls = getattr(counts, 'global_tls', 0)

            # --- بخش جدید دریافت آمار V2Ray ---
            with db_conn() as conn:
                v2ray_db_count_row = conn.execute("SELECT COUNT(*) FROM ssh_accounts WHERE status='🟢 فعال' AND service_type IN ('v2ray', 'v2ray_vol')").fetchone()
                v2ray_db_count = v2ray_db_count_row[0] if v2ray_db_count_row else 0
                ssh_db_count = total_active_accounts - v2ray_db_count

            v2_online_count = 0
            m_url = await asyncio.to_thread(_db_get_setting, 'marzban_url', '')
            m_user = await asyncio.to_thread(_db_get_setting, 'marzban_username', '')
            m_pwd = await asyncio.to_thread(_db_get_setting, 'marzban_password', '')
            if m_url and m_user:
                try:
                    ok_v2, v2_online = await v2ray_engine.get_online_users_count(m_url, m_user, m_pwd)
                    if ok_v2:
                        v2_online_count = v2_online
                    else:
                        v2_online_count = "نامشخص"
                except Exception as e:
                    log.error(f"خطا در دریافت آمار آنلاین V2Ray: {e}")
                    v2_online_count = "خطا"

            txt = (f"⚡️ <b>رادار زنده سرور</b>\n"
                   f"📦 <b>کل اکانت های فروخته شده:</b> {total_active_accounts} نفر\n"
                   f"────────────────\n"
                   f"🔹 <b>بخش SSH</b>\n"
                   f"✅ کاربران فعال در دیتابیس: {ssh_db_count} نفر\n"
                   f"👤 کاربران آنلاین لحظه‌ای: {total_users} نفر\n"
                   f"🔌 کل اتصالات: {total_conns} (مستقیم: {global_ssh} | TLS/گاست: {global_tls})\n\n"
                   f"تفکیک آنلاین‌های SSH به ازای نماینده:\n{b_txt or '—'}\n"
                   f"────────────────\n"
                   f"🚀 <b>بخش V2Ray</b>\n"
                   f"✅ کل کاربران V2Ray: {v2ray_db_count} نفر\n"
                   f"🟢 کاربران آنلاین V2Ray: {v2_online_count} نفر")
                   
            if online_list:
                shown = sorted(online_list)[:40]
                txt += "\n\n📋 <b>لیست کاربران آنلاین SSH:</b>\n" + "\n".join(
                    f"• <code>{esc(u)}</code> — {esc(agents.get(aid, 'مستقیم')) if aid else 'مستقیم'} (مستقیم: {counts.users_detail[u.lower()]['ssh']} | TLS: {counts.users_detail[u.lower()]['tls']})" for u, aid, c in shown)
                if len(online_list) > 40:
                    txt += f"\n… و {len(online_list) - 40} مورد دیگر"
            if warn_txt: txt = warn_txt + "\n\n" + txt
        await query.edit_message_text(txt, reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="info_back")]]), parse_mode="HTML")
    elif d == "info_chart" and MATPLOTLIB_AVAILABLE and role == 'admin':
        buf = await asyncio.to_thread(_generate_sales_chart_buffer)
        if buf:
            await query.delete_message()
            await context.bot.send_photo(chat_id=update.effective_chat.id, photo=InputFile(buf, filename="chart.png"), caption="📈 نمودار فروش 7 روز گذشته")
        else: await query.message.reply_text("❌ خطا در رسم نمودار")
    elif d == "info_back":
        kb = [[InlineKeyboardButton("📊 اطلاعات کلی حساب", callback_data="info_general")], [InlineKeyboardButton("⚡️ مشاهده کاربران آنلاین", callback_data="info_online")]]
        if MATPLOTLIB_AVAILABLE and role == 'admin': kb.append([InlineKeyboardButton("📈 نمودار فروش ۷ روز گذشته", callback_data="info_chart")])
        await query.edit_message_text("📊 <b>پورتال گزارشات</b>", reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")

    # ==========================================
    # 💵 استخر «قابل‌برداشت» نماینده — برداشت نقدی یا انتقال به کیف‌پول قابل‌خرج
    # ==========================================
    elif d == "wd_towallet" and role == 'agent':
        info = await asyncio.to_thread(_db_get_agent_info, ag_id)
        withdrawable = info[14] if info and len(info) > 14 and info[14] is not None else 0.0
        if withdrawable <= 0:
            await query.message.reply_text("موجودی استخر قابل‌برداشت صفر است."); return
        context.user_data['state'] = 'WD2W_AMOUNT'
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("💯 کل مبلغ", callback_data="wd2w_all")], [InlineKeyboardButton("🔙 بازگشت", callback_data="info_general")]])
        await query.edit_message_text(
            f"➕ <b>افزودن به کیف‌پول</b>\n"
            f"ℹ️ این مبلغ نقداً به حساب شما واریز نمی‌شود؛ فقط از «استخر قابل‌برداشت» به «کیف‌پول قابل‌خرج» شما منتقل می‌شود تا بتوانید بدون نیاز به شارژ کارت‌به‌کارت جدید، مستقیم از همین‌جا اکانت بخرید یا تمدید کنید.\n\n"
            f"چه مبلغی از استخر قابل‌برداشت ({int(withdrawable):,} تومان) به کیف‌پول قابل‌خرج شما منتقل شود؟ (عدد بفرستید یا «کل مبلغ» را بزنید)",
            reply_markup=kb, parse_mode="HTML")
    elif d == "wd2w_all" and role == 'agent':
        info = await asyncio.to_thread(_db_get_agent_info, ag_id)
        withdrawable = info[14] if info and len(info) > 14 and info[14] is not None else 0.0
        if withdrawable <= 0:
            await query.message.reply_text("موجودی استخر قابل‌برداشت صفر است."); return
        ok = await asyncio.to_thread(_db_move_withdrawable_to_wallet, ag_id, withdrawable)
        safe_clear_context(context)
        if ok:
            await query.edit_message_text(f"✅ مبلغ {int(withdrawable):,} تومان به کیف‌پول قابل‌خرج شما منتقل شد.")
        else:
            await query.edit_message_text("❌ خطا: موجودی استخر تغییر کرده بود. دوباره تلاش کنید.")
    elif d == "wd_request" and role == 'agent':
        info = await asyncio.to_thread(_db_get_agent_info, ag_id)
        withdrawable = info[14] if info and len(info) > 14 and info[14] is not None else 0.0
        if withdrawable <= 0:
            await query.message.reply_text("موجودی استخر قابل‌برداشت صفر است."); return
        context.user_data['state'] = 'WD_AMOUNT'
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("💯 کل مبلغ", callback_data="wd_all")], [InlineKeyboardButton("🔙 بازگشت", callback_data="info_general")]])
        await query.edit_message_text(
            f"💵 <b>برداشت وجه از استخر</b>\n"
            f"ℹ️ این گزینه برای وقتی است که می‌خواهید پول واقعی به حساب بانکی‌تان بگیرید: مبلغ را و شماره کارت خودتان را وارد می‌کنید، مدیریت رسید واریز کارت‌به‌کارت را برایتان می‌فرستد. (اگر فقط می‌خواهید این مبلغ را برای خرید/تمدید اکانت در ربات خرج کنید، به‌جایش «➕ افزودن به کیف‌پول» را بزنید.)\n\n"
            f"چه مبلغی از استخر قابل‌برداشت ({int(withdrawable):,} تومان) می‌خواهید برداشت کنید؟ (عدد بفرستید یا «کل مبلغ» را بزنید)",
            reply_markup=kb, parse_mode="HTML")
    elif d == "wd_all" and role == 'agent':
        info = await asyncio.to_thread(_db_get_agent_info, ag_id)
        withdrawable = info[14] if info and len(info) > 14 and info[14] is not None else 0.0
        if withdrawable <= 0:
            await query.message.reply_text("موجودی استخر قابل‌برداشت صفر است."); return
        context.user_data['wd_amount'] = withdrawable
        context.user_data['state'] = 'WD_CARD'
        await query.edit_message_text(f"💳 مبلغ برداشت: {int(withdrawable):,} تومان\n\nلطفاً شمارهٔ کارت بانکی مقصد را بفرستید:")
    elif d == "wd_mylist" and role == 'agent':
        rows = await asyncio.to_thread(_db_get_agent_pending_withdrawals, ag_id)
        if not rows:
            await query.edit_message_text("شما درخواست برداشت در انتظاری ندارید.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="info_general")]])); return
        lines = ["🧾 <b>درخواست‌های برداشت در انتظار شما:</b>\n"]
        for rid, amount, card, full_name, created_at in rows:
            lines.append(f"• #{rid} — {int(amount):,} تومان — {esc(full_name)} — <code>{esc(card)}</code> — {esc(created_at)}")
        await query.edit_message_text("\n".join(lines), reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="info_general")]]), parse_mode="HTML")

    # 🆕 لیست زیرمجموعه‌های مستقیم یک نماینده (فرزندانی که parent_id آن‌ها این نماینده است)
    elif d.startswith("mysubs_") and role == 'agent':
        page = int(d.split("_")[1]) if d.split("_")[1].isdigit() else 1
        subs = await asyncio.to_thread(_db_get_sub_agents, ag_id)
        kb_back = [[InlineKeyboardButton("🔙 بازگشت", callback_data="info_general")]]
        if not subs:
            await query.edit_message_text(
                "👥 <b>زیرمجموعه‌های من</b>\n\nهنوز هیچ نماینده‌ای با کد رفرال شما ثبت‌نام نکرده است.",
                parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb_back)); return
        PER_PAGE = 10
        total_pages = (len(subs) + PER_PAGE - 1) // PER_PAGE
        page = max(1, min(page, total_pages))
        chunk = subs[(page - 1) * PER_PAGE: page * PER_PAGE]
        lines = [f"👥 <b>زیرمجموعه‌های من</b> ({len(subs)} نفر)\n"]
        for sub_id, name, username, balance, ref_income, lifetime_sold in chunk:
            lines.append(
                f"• <b>{esc(name)}</b> (@{esc(username) if username else '—'})\n"
                f"   💰 موجودی: {int(balance or 0):,} تومان | 📦 کل فروش: {lifetime_sold or 0} | "
                f"💹 پورسانتی که از او گرفته‌اید: {int(ref_income or 0):,} تومان")
        nav = []
        if page > 1: nav.append(InlineKeyboardButton("◀️ قبلی", callback_data=f"mysubs_{page-1}"))
        if page < total_pages: nav.append(InlineKeyboardButton("بعدی ▶️", callback_data=f"mysubs_{page+1}"))
        kb = ([nav] if nav else []) + kb_back
        await query.edit_message_text("\n\n".join(lines), parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))

    # 🆕 «تنظیمات مالی» ادمین: دو زیرگزینه — کارت مدیر (سیستم) / کارت هرکدام از نمایندگان
    elif d == "fin_menu" and role == 'admin':
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("💳 شماره کارت مدیر", callback_data="fin_admin_card")],
            [InlineKeyboardButton("💳 شماره کارت نمایندگان", callback_data="fin_agents_1")]])
        await query.edit_message_text("💳 <b>تنظیمات مالی</b>\n\nکدام کارت را می‌خواهید مدیریت کنید؟", parse_mode="HTML", reply_markup=kb)

    elif d == "fin_admin_card" and role == 'admin':
        card = await asyncio.to_thread(_db_get_setting, 'bank_card', 'تنظیم نشده')
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="fin_menu")]])
        await query.edit_message_text(f"💳 اطلاعات کارت فعلی مدیر (سیستم):\n<code>{esc(card)}</code>\n\n✍️ لطفاً شماره کارت جدید و نام صاحب حساب را ارسال کنید:", parse_mode="HTML", reply_markup=kb)
        context.user_data['state'] = 'SET_BANK_CARD'

    elif d.startswith("fin_agents_") and role == 'admin':
        page = int(d.split("_")[2]) if d.split("_")[2].isdigit() else 1
        rows = await asyncio.to_thread(_db_get_all_agents)
        kb_back = [[InlineKeyboardButton("🔙 بازگشت", callback_data="fin_menu")]]
        if not rows:
            await query.edit_message_text("هیچ نماینده‌ای ثبت نشده است.", reply_markup=InlineKeyboardMarkup(kb_back)); return
        PER_PAGE = 8
        total_pages = (len(rows) + PER_PAGE - 1) // PER_PAGE
        page = max(1, min(page, total_pages))
        chunk = rows[(page - 1) * PER_PAGE: page * PER_PAGE]
        kb = []
        for r in chunk:
            aid_r, name_r = r[0], r[1]
            card_row = await asyncio.to_thread(_db_get_agent_card, aid_r)
            has_card = "💳" if (card_row and card_row[0]) else "▫️"
            kb.append([InlineKeyboardButton(f"{has_card} {name_r}", callback_data=f"fin_agent_{aid_r}")])
        nav = []
        if page > 1: nav.append(InlineKeyboardButton("◀️ قبلی", callback_data=f"fin_agents_{page-1}"))
        if page < total_pages: nav.append(InlineKeyboardButton("بعدی ▶️", callback_data=f"fin_agents_{page+1}"))
        if nav: kb.append(nav)
        kb.extend(kb_back)
        await query.edit_message_text(
            f"💳 <b>شماره کارت نمایندگان</b> ({len(rows)} نفر)\n\nیک نماینده را انتخاب کنید (💳 یعنی از قبل کارت ثبت شده):",
            parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))

    elif d.startswith("fin_agent_") and not d.startswith("fin_agent_card") and role == 'admin':
        target_aid = int(d.split("_")[2])
        ainf = await asyncio.to_thread(_db_get_agent_info, target_aid)
        if not ainf:
            await query.message.reply_text("❌ این نماینده دیگر وجود ندارد."); return
        card_row = await asyncio.to_thread(_db_get_agent_card, target_aid)
        card_num, card_name = (card_row if card_row else (None, None))
        kb = [[InlineKeyboardButton("✏️ ثبت/ویرایش کارت", callback_data=f"fin_agent_card_set_{target_aid}")]]
        if card_num:
            kb.append([InlineKeyboardButton("🗑 حذف کارت این نماینده", callback_data=f"fin_agent_card_clear_{target_aid}")])
        kb.append([InlineKeyboardButton("🔙 بازگشت به لیست", callback_data="fin_agents_1")])
        if card_num:
            txt = (f"💳 <b>کارت نماینده «{esc(ainf[0])}»</b>\n\n"
                   f"شمارهٔ کارت: <code>{esc(card_num)}</code>\n👤 به‌نام: {esc(card_name or '—')}\n\n"
                   f"از این پس، زیرمجموعه‌های این نماینده هنگام شارژ کیف‌پول همین کارت را می‌بینند، نه کارت مدیر.")
        else:
            txt = (f"💳 <b>کارت نماینده «{esc(ainf[0])}»</b>\n\n"
                   f"هنوز برای این نماینده کارتی ثبت نشده — زیرمجموعه‌های او فعلاً کارت مدیر را می‌بینند.")
        await query.edit_message_text(txt, parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))

    elif d.startswith("fin_agent_card_set_") and role == 'admin':
        target_aid = int(d.rsplit("_", 1)[1])
        context.user_data['fin_target_agent_id'] = target_aid
        context.user_data['state'] = 'ADMIN_SET_AGENT_CARD_NUM'
        await query.edit_message_text("💳 لطفاً شمارهٔ کارت این نماینده را بفرستید (فقط عدد، ۱۲ تا ۱۹ رقم):")
    elif d.startswith("fin_agent_card_clear_") and role == 'admin':
        target_aid = int(d.rsplit("_", 1)[1])
        await asyncio.to_thread(_db_clear_agent_card, target_aid)
        await query.edit_message_text("✅ کارت این نماینده حذف شد؛ زیرمجموعه‌هایش دوباره کارت مدیر را می‌بینند.",
                                        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="fin_agents_1")]]))

    elif d == "wdconf_no" and role == 'agent':
        a_id_local = context.user_data.get('agent_id', ag_id); amount = context.user_data.get('pending_wd_amount', 0)
        card = context.user_data.get('wd_card'); full_name = context.user_data.get('wd_full_name')
        # انصراف قبل از ثبت نهایی؛ چون هنوز چیزی از استخر کسر نشده، فقط context پاک می‌شود
        for k in ('wd_amount', 'pending_wd_amount', 'wd_card', 'wd_full_name'): context.user_data.pop(k, None)
        context.user_data['state'] = None
        await query.edit_message_text("✅ انصراف داده شد؛ درخواست برداشتی ثبت نشد.")
    elif d == "wdconf_yes" and role == 'agent':
        amount = context.user_data.get('pending_wd_amount'); card = context.user_data.get('wd_card'); full_name = context.user_data.get('wd_full_name')
        if not amount or not card or not full_name:
            await query.edit_message_text("❌ اطلاعات درخواست ناقص است؛ دوباره تلاش کنید."); safe_clear_context(context); return
        req_id = await asyncio.to_thread(_db_create_withdrawal_request, ag_id, amount, card, full_name)
        for k in ('wd_amount', 'pending_wd_amount', 'wd_card', 'wd_full_name'): context.user_data.pop(k, None)
        context.user_data['state'] = None
        if req_id is None:
            await query.edit_message_text("❌ موجودی استخر شما تغییر کرده؛ لطفاً دوباره تلاش کنید."); return
        await query.edit_message_text(f"✅ درخواست برداشت شما (#{req_id}) به مبلغ {int(amount):,} تومان ثبت و برای مدیریت ارسال شد.\nپس از واریز توسط مدیریت، رسید برای شما ارسال خواهد شد.")
        agent_info = await asyncio.to_thread(_db_get_agent_info, ag_id)
        agent_name = agent_info[0] if agent_info else "نامشخص"
        admin_ids = await asyncio.to_thread(_db_get_admin_chat_ids)
        cap = (f"🧾 <b>درخواست برداشت وجه جدید</b>\n\n👤 نماینده: {esc(agent_name)} (کد: {ag_id})\n"
               f"💰 مبلغ: {int(amount):,} تومان\n👤 نام صاحب کارت: {esc(full_name)}\n💳 شماره کارت: <code>{esc(card)}</code>\n\n"
               f"پس از واریز، از پنل «مدیریت نماینده‌ها ← این نماینده ← درخواست‌های برداشت» عکس رسید را برای نماینده ارسال کنید.")
        for admin_chat_id in admin_ids:
            with contextlib.suppress(Exception):
                await context.bot.send_message(chat_id=admin_chat_id, text=cap, parse_mode="HTML")

    # صدور اکانت (خرید)
    elif d == "buy_direct":
        context.user_data['state'] = 'BUY_MONTHS'
        kb = [[InlineKeyboardButton(f"{i} ماهه", callback_data=f"bm_{i}") for i in range(1, 4)],
              [InlineKeyboardButton("🔙 بازگشت", callback_data="buy_back_start")]]
        await query.edit_message_text("📅 چند ماهه؟", reply_markup=InlineKeyboardMarkup(kb))
    elif d == "v2ray_buy_menu":
        v2_unlimit_en = await asyncio.to_thread(_db_get_setting, 'sell_v2ray_unlimit', '1') == '1'
        v2_vol_en = await asyncio.to_thread(_db_get_setting, 'sell_v2ray_vol', '1') == '1'
        kb = []
        if v2_unlimit_en:
            kb.append([InlineKeyboardButton("♾ نامحدود (زمان‌دار)", callback_data="v2r_type_unlimit")])
        if v2_vol_en:
            kb.append([InlineKeyboardButton("📦 حجمی (بدون انقضای زمان)", callback_data="v2r_type_vol")])
        kb.append([InlineKeyboardButton("🔙 بازگشت", callback_data="buy_back_start")])
        
        await query.edit_message_text("🚀 نوع اکانت V2Ray را انتخاب کنید:", reply_markup=InlineKeyboardMarkup(kb))

    elif d == "v2r_type_unlimit":
        kb = [[InlineKeyboardButton("👤 ۱ کاربره (۱ ماهه)", callback_data="v2ru_1_1"), InlineKeyboardButton("👤 ۱ کاربره (۲ ماهه)", callback_data="v2ru_2_1")],
              [InlineKeyboardButton("👥 ۲ کاربره (۱ ماهه)", callback_data="v2ru_1_2"), InlineKeyboardButton("👥 ۲ کاربره (۲ ماهه)", callback_data="v2ru_2_2")],
              [InlineKeyboardButton("✏️ ساخت با مقادیر دلخواه", callback_data="v2ru_custom_users")],
              [InlineKeyboardButton("🔙 بازگشت", callback_data="v2ray_buy_menu")]]
        await query.edit_message_text("♾ پلن نامحدود :", reply_markup=InlineKeyboardMarkup(kb))

    elif d == "v2ru_custom_users":
        kb = [[InlineKeyboardButton("👤 ۱ کاربره", callback_data="v2ru_cu_1"), InlineKeyboardButton("👥 ۲ کاربره", callback_data="v2ru_cu_2")],
              [InlineKeyboardButton("🔙 بازگشت", callback_data="v2r_type_unlimit")]]
        await query.edit_message_text("👥 لطفاً محدودیت تعداد کاربر را انتخاب کنید:", reply_markup=InlineKeyboardMarkup(kb))

    elif d.startswith("v2ru_cu_"):
        u = d.split("_")[2]
        context.user_data['v2_users'] = u
        context.user_data['state'] = 'V2_CUSTOM_DAYS_INPUT'
        kb = [[InlineKeyboardButton("🔙 بازگشت", callback_data="v2ru_custom_users")]]
        await query.edit_message_text("📅 لطفاً تعداد روزهای اعتبار اکانت را وارد کنید (بازه مجاز: ۱ تا ۶۰ روز):", reply_markup=InlineKeyboardMarkup(kb))
        
    elif d == "v2r_type_vol":
        vols = [10, 15, 20, 25, 30, 35, 40, 45, 50, 100]
        kb = []
        for i in range(0, len(vols), 2):
            row = [InlineKeyboardButton(f"{vols[i]} گیگ", callback_data=f"v2ru_vol_{vols[i]}")]
            if i+1 < len(vols): row.append(InlineKeyboardButton(f"{vols[i+1]} گیگ", callback_data=f"v2ru_vol_{vols[i+1]}"))
            kb.append(row)
        kb.append([InlineKeyboardButton("✏️ حجم دلخواه", callback_data="v2ru_vol_custom")])
        kb.append([InlineKeyboardButton("🔙 بازگشت", callback_data="v2ray_buy_menu")])
        await query.edit_message_text("📦 حجم موردنظر را انتخاب کنید:\n\nبازه مجاز: 10 تا 100 گیگ", reply_markup=InlineKeyboardMarkup(kb))

    elif d.startswith("v2ru_vol_"):
        val = d.split("_")[2]
        if val == "custom":
            context.user_data['state'] = 'V2_VOL_CUSTOM_INPUT'
            await query.edit_message_text("✏️ حجم دلخواه را فقط به‌صورت عدد وارد کنید.\n\nبازه مجاز: 10 تا 100 گیگ", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="v2r_type_vol")]]))
            return
        context.user_data['v2_vol_gb'] = int(val)
        context.user_data['state'] = 'V2_VOL_CUSTOMER_NAME'
        kb = [[InlineKeyboardButton("🔙 بازگشت", callback_data="v2r_type_vol")]]
        await query.edit_message_text("👤 <b>مرحله بعد:</b>\nلطفاً نام مشتری (یا یک نشانه برای تشخیص این اکانت) را بفرستید:", reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
        return

    elif d in ("v2conf_vol_yes", "v2_vol_buy_emergency_yes"):
        if d == "v2_vol_buy_emergency_yes":
            context.user_data['emergency_approved'] = True
        
        gb = context.user_data.get('v2_vol_gb')
        if not gb:
            return await query.message.reply_text("❌ تراکنش منقضی شده است.")

        if context.user_data.get('purchase_in_progress'):
            return await query.message.reply_text("⏳ درخواست قبلی هنوز در حال پردازش است...")
        context.user_data['purchase_in_progress'] = True

        try:
            cost = 0.0
            retail_dec = Decimal("0")
            ainf = None
            if role == 'agent':
                ainf = await asyncio.to_thread(_db_get_agent_info, ag_id)
                if not ainf: return await query.edit_message_text("❌ خطا: اطلاعات نمایندگی شما یافت نشد.")
                
                v2_vol_bp = ainf[17] if len(ainf)>17 and ainf[17] else '4000'
                base_price_dec = _parse_price_to_decimal(v2_vol_bp, Decimal("4000"))
                retail_dec = base_price_dec * Decimal(gb)
                cost = float(retail_dec)
                
                if ainf[2] < cost and not context.user_data.get('emergency_approved'):
                    has_opt, remaining_em, shortfall, used_em, req_cnt = _check_emergency_option(ainf, cost)
                    can_use_em, active_count = _agent_can_use_emergency_credit(ag_id)
                    if has_opt and can_use_em:
                        kb_em = [[InlineKeyboardButton("🆘 استفاده از شارژ اضطراری", callback_data="v2_vol_buy_emergency_yes")],
                                 [InlineKeyboardButton("↩️ انصراف", callback_data="buy_no")]]
                        await query.edit_message_text(
                            f"❌ <b>موجودی ناکافی!</b>\n\n💰 موجودی شما: {int(ainf[2]):,} تومان\n💳 هزینه این اکانت حجمی: {int(cost):,} تومان\n\n"
                            f"🆘 می‌توانید از <b>شارژ اضطراری</b> استفاده کنید (سقف کل: {int(EMERGENCY_CREDIT_LIMIT):,} تومان).",
                            reply_markup=InlineKeyboardMarkup(kb_em), parse_mode="HTML")
                        context.user_data['_skip_purchase_clear'] = True
                        return
                    extra = ""
                    if req_cnt >= EMERGENCY_MAX_CONSECUTIVE_REQUESTS: extra = "\n\n🆘 سقف درخواست‌های پیاپی شارژ اضطراری پر شده."
                    elif used_em > 0: extra = f"\n\n🆘 شارژ اضطراری باقی‌مانده ({int(remaining_em):,} تومان) کافی نیست."
                    return await query.edit_message_text(f"❌ <b>موجودی ناکافی!</b>\n\n💰 موجودی: {int(ainf[2]):,} تومان\n💳 هزینه اکانت حجمی: {int(cost):,} تومان{extra}", parse_mode="HTML")

            await query.edit_message_text("⏳ در حال ساخت اکانت V2Ray حجمی در NVL V2RAY...")
            m_url = await asyncio.to_thread(_db_get_setting, 'marzban_url', '')
            m_user = await asyncio.to_thread(_db_get_setting, 'marzban_username', '')
            m_pwd = await asyncio.to_thread(_db_get_setting, 'marzban_password', '')

            br = _resolve_username_prefix(role, ainf)
            if br is None:
                br = (await asyncio.to_thread(_db_get_setting, 'brand', 'NeVeL')).lower().strip()
                br = re.sub(r'[^a-z0-9]', '', br) or "nevel"
            c_start = await asyncio.to_thread(_db_get_prefix_start_counter, br)
            un, c = await asyncio.to_thread(_db_reserve_username, br, c_start)
            if un is None: return await query.message.reply_text("❌ خطا در یافتن یوزرنیم آزاد.")

            expire_timestamp = 0 # نامحدود زمانی
            data_limit_bytes = int(gb) * 1024**3
            reset_strategy = "no_reset"

            retries = 0
            ok, sub_url = False, ""
            while True:
                # No Note (unlimited user)
                ok, sub_url = await v2ray_engine.create_user(m_url, m_user, m_pwd, un, expire_timestamp, data_limit_bytes, reset_strategy, None)
                if ok: break
                if "already exists" in str(sub_url).lower() and retries < 50:
                    await asyncio.to_thread(_db_cancel_reservation, un)
                    un, c = await asyncio.to_thread(_db_reserve_username, br, c + 1)
                    retries += 1
                else: break

            if ok:
                cr_db = datetime.now().strftime("%Y-%m-%d")
                exp_db = "نامحدود"
                await asyncio.to_thread(_db_finalize_v2ray_user, un, "-", exp_db, cr_db, 0, c + 1, br, ag_id, data_limit_bytes, sub_url, None, None)
                
                c_name = context.user_data.get('v2_customer_name')
                def _update_extras():
                    with db_conn() as conn:
                        conn.execute("UPDATE ssh_accounts SET service_type='v2ray_vol' WHERE username=?", (un,))
                        if c_name:
                            try: conn.execute("UPDATE ssh_accounts SET customer_name=? WHERE username=?", (c_name, un))
                            except: pass
                await asyncio.to_thread(_update_extras)

                if role == 'agent':
                    with contextlib.suppress(Exception): await asyncio.to_thread(_db_increment_lifetime_sold, ag_id)
                    try:
                        with db_conn() as conn: conn.execute("UPDATE agents SET balance = balance - ? WHERE id=?", (cost, ag_id))
                        await asyncio.to_thread(_db_distribute_commission, ag_id, retail_dec)
                        await _apply_agent_cashback_if_eligible(ag_id, retail_dec)
                        emergency_shortfall = max(0.0, cost - ainf[2])
                        if emergency_shortfall > 0:
                            await asyncio.to_thread(_db_agent_register_emergency_use, ag_id, emergency_shortfall)
                            with contextlib.suppress(Exception):
                                await _notify_admins(context.application, f"🆘 نمایندهٔ «{esc(ainf[0])}» برای ساخت V2Ray حجمی <code>{esc(un)}</code> مبلغ {int(emergency_shortfall):,} تومان از شارژ اضطراری استفاده کرد.")
                    except Exception: log.exception("خطا در کسر کیف‌پول V2Ray حجمی")

                qr_buf = await asyncio.to_thread(v2ray_engine.generate_qr, sub_url)
                
                try:
                    actor = f"نماینده: {esc(ainf[0])}" if (role == 'agent' and ainf) else "ادمین"
                    c_txt = f"\nهزینه: {int(cost):,} تومان" if role == 'agent' else ""
                    await _notify_super_admin(context.application, f"🆕 <b>ساخت اکانت جدید</b>\nنوع اکانت: V2Ray حجمی\nتوسط: {actor}\nحجم: {gb} گیگابایت{c_txt}", tg_user=update.effective_user)
                    await asyncio.to_thread(_db_log_activity, ag_id if role=='agent' else 0, un, 'create', 'v2ray_vol', f"{gb} گیگ", cost if role=='agent' else 0)
                except: pass

                txt = f"✅ <b>فاکتور سرویس V2Ray حجمی</b>\n\n👤 یوزرنیم: <code>{esc(un)}</code>\n🔗 لینک اتصال:\n<code>{esc(sub_url)}</code>\n\n📦 حجم: {gb} گیگابایت\n📅 انقضا: نامحدود (بدون انقضای زمان)\n👥 تعداد کاربر: نامحدود"
                await context.bot.send_photo(chat_id=query.message.chat_id, photo=qr_buf, caption=txt, parse_mode="HTML")
                try: await query.delete_message()
                except: pass
            else:
                await asyncio.to_thread(_db_cancel_reservation, un)
                await query.message.reply_text(f"❌ خطا در ساخت کاربر NVL V2RAY:\n{sub_url}")

        except Exception as e:
            log.exception("خطا در خرید V2Ray حجمی")
            await query.message.reply_text(f"❌ خطا:\n<code>{esc(str(e))}</code>", parse_mode="HTML")
        finally:
            if context.user_data.pop('_skip_purchase_clear', False): context.user_data['purchase_in_progress'] = False
            else: safe_clear_context(context)

    elif d.startswith("v2ru_") and not d.startswith("v2ru_vol") and not d.startswith("v2ru_cu") and not d.startswith("v2ru_custom"):
        # مرحله نمایش تاییدیه و هزینه (پلن‌های پیش‌فرض ماهانه که به روز تبدیل می‌شوند)
        _, m, u = d.split("_")
        days = int(m) * 30
        context.user_data['v2_days'] = days
        context.user_data['v2_users'] = u
        
        cost_txt = ""
        if role == 'agent':
            ainf = await asyncio.to_thread(_db_get_agent_info, ag_id)
            v2_bp = ainf[16] if ainf and len(ainf)>16 and ainf[16] else '160000'
            base_price_dec = _parse_price_to_decimal(v2_bp, Decimal("160000"))
            import math
            daily_price = float(base_price_dec) / 30.0
            retail_dec = Decimal(math.ceil(daily_price * days * int(u)))
            cost_txt = f"\n💳 هزینهٔ این خرید: {int(retail_dec):,} تومان"
            
        txt = f"🚀 <b>تایید ساخت اکانت V2Ray</b>\n\n📅 مدت اکانت: {days} روزه\n👥 تعداد کاربر: {u}{cost_txt}\n\nآیا از ساخت این اکانت مطمئن هستید؟"
        kb = [
            [InlineKeyboardButton("✅ بله، ساخته شود", callback_data="v2conf_yes")],
            [InlineKeyboardButton("❌ خیر، انصراف", callback_data="v2r_type_unlimit")]
        ]
        await query.edit_message_text(txt, reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
        return

    elif d in ("v2conf_yes", "v2_buy_emergency_yes"):
        # مرحله ساخت واقعی بعد از تایید
        if d == "v2_buy_emergency_yes":
            context.user_data['emergency_approved'] = True
        
        days = context.user_data.get('v2_days')
        u = context.user_data.get('v2_users')

        if not days or not u:
            return await query.message.reply_text("❌ تراکنش منقضی شده است.")

        if context.user_data.get('purchase_in_progress'):
            return await query.message.reply_text("⏳ درخواست قبلی هنوز در حال پردازش است...")
        context.user_data['purchase_in_progress'] = True

        try:
            cost = 0.0
            retail_dec = Decimal("0")
            ainf = None
            if role == 'agent':
                ainf = await asyncio.to_thread(_db_get_agent_info, ag_id)
                if not ainf: return await query.edit_message_text("❌ خطا: اطلاعات نمایندگی شما یافت نشد.")
                
                v2_bp = ainf[16] if len(ainf)>16 and ainf[16] else '160000'
                base_price_dec = _parse_price_to_decimal(v2_bp, Decimal("160000"))
                import math
                daily_price = float(base_price_dec) / 30.0
                retail_dec = Decimal(math.ceil(daily_price * days * int(u)))
                cost = float(retail_dec)
                
                if ainf[2] < cost and not context.user_data.get('emergency_approved'):
                    has_opt, remaining_em, shortfall, used_em, req_cnt = _check_emergency_option(ainf, cost)
                    can_use_em, active_count = _agent_can_use_emergency_credit(ag_id)
                    if has_opt and can_use_em:
                        kb_em = [[InlineKeyboardButton("🆘 استفاده از شارژ اضطراری", callback_data="v2_buy_emergency_yes")],
                                 [InlineKeyboardButton("↩️ انصراف", callback_data="buy_no")]]
                        await query.edit_message_text(
                            f"❌ <b>موجودی ناکافی!</b>\n\n💰 موجودی شما: {int(ainf[2]):,} تومان\n💳 هزینه این اکانت V2Ray: {int(cost):,} تومان\n\n"
                            f"🆘 می‌توانید از <b>شارژ اضطراری</b> استفاده کنید (سقف کل: {int(EMERGENCY_CREDIT_LIMIT):,} تومان).",
                            reply_markup=InlineKeyboardMarkup(kb_em), parse_mode="HTML")
                        context.user_data['_skip_purchase_clear'] = True
                        return
                    extra = ""
                    if req_cnt >= EMERGENCY_MAX_CONSECUTIVE_REQUESTS: extra = "\n\n🆘 سقف درخواست‌های پیاپی شارژ اضطراری پر شده."
                    elif used_em > 0: extra = f"\n\n🆘 شارژ اضطراری باقی‌مانده ({int(remaining_em):,} تومان) کافی نیست."
                    return await query.edit_message_text(f"❌ <b>موجودی ناکافی!</b>\n\n💰 موجودی: {int(ainf[2]):,} تومان\n💳 هزینه اکانت V2Ray: {int(cost):,} تومان{extra}", parse_mode="HTML")

            await query.edit_message_text("⏳ در حال ساخت اکانت V2Ray در v2panel...")
            m_url = await asyncio.to_thread(_db_get_setting, 'marzban_url', '')
            m_user = await asyncio.to_thread(_db_get_setting, 'marzban_username', '')
            m_pwd = await asyncio.to_thread(_db_get_setting, 'marzban_password', '')

            br = _resolve_username_prefix(role, ainf)
            if br is None:
                br = (await asyncio.to_thread(_db_get_setting, 'brand', 'NeVeL')).lower().strip()
                br = re.sub(r'[^a-z0-9]', '', br) or "nevel"
            c_start = await asyncio.to_thread(_db_get_prefix_start_counter, br)
            un, c = await asyncio.to_thread(_db_reserve_username, br, c_start)
            if un is None: return await query.message.reply_text("❌ خطا در یافتن یوزرنیم آزاد.")

            exp_days = days
            expire_timestamp = (datetime.now() + timedelta(days=exp_days)).timestamp()
            limit_gb = 20 if int(u) == 2 else 10
            data_limit_bytes = limit_gb * 1024**3
            reset_strategy = "day"

            retries = 0
            ok, sub_url = False, ""
            while True:
                ok, sub_url = await v2ray_engine.create_user(m_url, m_user, m_pwd, un, expire_timestamp, data_limit_bytes, reset_strategy, int(u))
                if ok: break
                if "already exists" in str(sub_url).lower() and retries < 50:
                    await asyncio.to_thread(_db_cancel_reservation, un)
                    un, c = await asyncio.to_thread(_db_reserve_username, br, c + 1)
                    retries += 1
                else: break

            if ok:
                cr_db = datetime.now().strftime("%Y-%m-%d")
                exp_db = (datetime.now() + timedelta(days=exp_days)).strftime("%Y-%m-%d")
                await asyncio.to_thread(_db_finalize_v2ray_user, un, "-", exp_db, cr_db, int(u), c + 1, br, ag_id, data_limit_bytes, sub_url, None, None)

                if role == 'agent':
                    with contextlib.suppress(Exception): await asyncio.to_thread(_db_increment_lifetime_sold, ag_id)
                    try:
                        with db_conn() as conn: conn.execute("UPDATE agents SET balance = balance - ? WHERE id=?", (cost, ag_id))
                        await asyncio.to_thread(_db_distribute_commission, ag_id, retail_dec)
                        await _apply_agent_cashback_if_eligible(ag_id, retail_dec)
                        emergency_shortfall = max(0.0, cost - ainf[2])
                        if emergency_shortfall > 0:
                            await asyncio.to_thread(_db_agent_register_emergency_use, ag_id, emergency_shortfall)
                            with contextlib.suppress(Exception):
                                await _notify_admins(context.application, f"🆘 نمایندهٔ «{esc(ainf[0])}» برای ساخت V2Ray <code>{esc(un)}</code> مبلغ {int(emergency_shortfall):,} تومان از شارژ اضطراری استفاده کرد.")
                    except Exception: log.exception("خطا در کسر کیف‌پول V2Ray")

                exp_jalali = format_db_date_to_jalali(exp_db)
                qr_buf = await asyncio.to_thread(v2ray_engine.generate_qr, sub_url)
                dur_txt = f"{days // 30} ماهه" if days % 30 == 0 else f"{days} روزه"
                
                try:
                    actor = f"نماینده: {esc(ainf[0])}" if (role == 'agent' and ainf) else "ادمین"
                    c_txt = f"\nهزینه: {int(cost):,} تومان" if role == 'agent' else ""
                    await _notify_super_admin(context.application, f"🆕 <b>ساخت اکانت جدید</b>\nنوع اکانت: V2Ray نامحدود\nتوسط: {actor}\nمدت زمان: {dur_txt}\nتعداد کاربر: {u} کاربره{c_txt}", tg_user=update.effective_user)
                    await asyncio.to_thread(_db_log_activity, ag_id if role=='agent' else 0, un, 'create', 'v2ray', f"{days} روز - {u} کاربر", cost if role=='agent' else 0)
                except: pass

                txt = (f"✅ <b>فاکتور سرویس V2Ray</b>\n\n"
                       f"👤 یوزرنیم: <code>{esc(un)}</code>\n"
                       f"🔗 لینک اتصال:\n<code>{esc(sub_url)}</code>\n\n"
                       f"👥 تعداد کاربر: {u}\n"
                       f"📅 مدت اشتراک: {dur_txt}\n"
                       f"تاریخ انقضا: {exp_jalali}")
                await context.bot.send_photo(chat_id=query.message.chat_id, photo=qr_buf, caption=txt, parse_mode="HTML")
                try: await query.delete_message()
                except: pass
            else:
                await asyncio.to_thread(_db_cancel_reservation, un)
                await query.message.reply_text(f"❌ خطا در ساخت کاربر v2panel:\n{sub_url}")

        except Exception as e:
            log.exception("خطا در خرید V2Ray")
            await query.message.reply_text(f"❌ خطا:\n<code>{esc(str(e))}</code>", parse_mode="HTML")
        finally:
            if context.user_data.pop('_skip_purchase_clear', False): context.user_data['purchase_in_progress'] = False
            else: safe_clear_context(context)

    # 📦 ساخت اکانت عمده (Bulk) — انتخاب تعداد اکانت‌ها؛ بعد از این، دقیقاً همان مسیر مشترک
    # انتخاب ماه/تعداد کاربر/تاییدیهٔ نهایی (bm_/bu_/buy_yes) طی می‌شود، فقط با پرچم bulk_mode
    # که در _show_buy_summary و در «buy_yes» تشخیص داده می‌شود.
    elif d == "buy_bulk_start":
        context.user_data['state'] = 'BULK_COUNT'
        kb = [[InlineKeyboardButton(str(n), callback_data=f"blkc_{n}") for n in (5, 10, 20)],
              [InlineKeyboardButton("🔢 عدد دلخواه", callback_data="blkc_custom")],
              [InlineKeyboardButton("🔙 بازگشت", callback_data="buy_back_start")]]
        await query.edit_message_text("📦 <b>ساخت اکانت عمده</b>\n\nچند اکانت می‌خواهید بسازید؟", reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
    # 🔙 دکمه‌های بازگشت گام‌به‌گام مسیر خرید — هرکدام دقیقاً یک مرحله به عقب برمی‌گردانند
    # (نه لغو کامل عملیات)، درست مطابق الگوی ربات Rad.
    elif d == "buy_back_start":
        context.user_data.pop('bulk_mode', None); context.user_data.pop('bulk_count', None)
        context.user_data.pop('months', None); context.user_data.pop('users', None)
        await _show_buy_start(update, context)
    elif d == "buy_back_bulkcount":
        context.user_data['state'] = 'BULK_COUNT'
        kb = [[InlineKeyboardButton(str(n), callback_data=f"blkc_{n}") for n in (5, 10, 20)],
              [InlineKeyboardButton("🔢 عدد دلخواه", callback_data="blkc_custom")],
              [InlineKeyboardButton("🔙 بازگشت", callback_data="buy_back_start")]]
        await query.edit_message_text("📦 <b>ساخت اکانت عمده</b>\n\nچند اکانت می‌خواهید بسازید؟", reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
    elif d == "buy_back_toMonths":
        context.user_data['state'] = 'BUY_MONTHS'
        if context.user_data.get('bulk_mode'):
            n = context.user_data.get('bulk_count', 1)
            kb = [[InlineKeyboardButton(f"{i} ماهه", callback_data=f"bm_{i}") for i in range(1, 4)],
                  [InlineKeyboardButton("🔙 بازگشت", callback_data="buy_back_bulkcount")]]
            await query.edit_message_text(f"📦 تعداد اکانت عمده: {n}\n\n📅 چند ماهه؟", reply_markup=InlineKeyboardMarkup(kb))
        else:
            kb = [[InlineKeyboardButton(f"{i} ماهه", callback_data=f"bm_{i}") for i in range(1, 4)],
                  [InlineKeyboardButton("🔙 بازگشت", callback_data="buy_back_start")]]
            await query.edit_message_text("📅 چند ماهه؟", reply_markup=InlineKeyboardMarkup(kb))
    elif d.startswith("blkc_"):
        val = d.split("_", 1)[1]
        if val == "custom":
            kb = [[InlineKeyboardButton("🔙 بازگشت", callback_data="buy_back_bulkcount")]]
            await query.edit_message_text("🔢 لطفاً تعداد اکانت‌های موردنظر را به‌صورت عدد ارسال کنید (حداکثر ۲۰۰):", reply_markup=InlineKeyboardMarkup(kb))
            context.user_data['state'] = 'BULK_COUNT'
        else:
            n = int(val)
            context.user_data['bulk_count'] = n; context.user_data['bulk_mode'] = True
            context.user_data['state'] = 'BUY_MONTHS'
            kb = [[InlineKeyboardButton(f"{i} ماهه", callback_data=f"bm_{i}") for i in range(1, 4)],
                  [InlineKeyboardButton("🔙 بازگشت", callback_data="buy_back_bulkcount")]]
            await query.edit_message_text(f"📦 تعداد اکانت عمده: {n}\n\n📅 چند ماهه؟", reply_markup=InlineKeyboardMarkup(kb))
    elif d.startswith("bm_"):
        context.user_data['months'] = int(d.split("_")[1])
        kb = [[InlineKeyboardButton(str(i) + " کاربره", callback_data=f"bu_{i}") for i in range(1, 4)],
              [InlineKeyboardButton("🔙 بازگشت", callback_data="buy_back_toMonths")]]
        await query.edit_message_text("👥 تعداد کاربران مجاز؟", reply_markup=InlineKeyboardMarkup(kb))
    elif d.startswith("bu_"):
        context.user_data['users'] = int(d.split("_")[1])
        await _show_buy_summary(query.message, context, edit=True)
    elif d.startswith("buyfav_"):
        _, m, u = d.split("_"); context.user_data['months'], context.user_data['users'] = int(m), int(u)
        await _show_buy_summary(query.message, context, edit=True)
    elif d.startswith("fav_add_"):
        m, u = d[len("fav_add_"):].split("_"); await asyncio.to_thread(_db_add_fav, int(m), int(u))
        await _show_buy_summary(query.message, context, edit=True)
    elif d.startswith("fav_rem_"):
        m, u = d[len("fav_rem_"):].split("_"); await asyncio.to_thread(_db_rem_fav, int(m), int(u))
        await _show_buy_summary(query.message, context, edit=True)

    # 🛒 فاکتور نهایی و صدور در لینوکس — بازنویسی کامل (V26)
    # مراحل به‌صورت گام‌به‌گام و با Rollback کامل انجام می‌شود تا هرگز اکانت «نیمه‌کاره»
    # (فقط در دیتابیس یا فقط در لینوکس) باقی نماند:
    #   1) رزرو اتمیک یوزرنیم در دیتابیس (بدون Race Condition، به‌جای چک-سپس-ساخت)
    #   2) ساخت کاربر لینوکسی → اگر شکست خورد: لغو رزرو دیتابیس
    #   3) تنظیم پسورد لینوکسی → اگر شکست خورد: حذف کاربر لینوکسی + لغو رزرو دیتابیس
    #   4) تکمیل نهایی ردیف دیتابیس با اطلاعات واقعی
    #   5) فقط در صورت موفقیت تمام مراحل بالا، کسر کیف‌پول/کمیسیون و ارسال فاکتور انجام می‌شود
    # 🆕 دکمه‌های «حالت اتصال» روی صفحهٔ تاییدیهٔ خرید — بین 'direct' و 'tls' مستقیماً مقصد
    # انتخاب‌شده را ست می‌کنند و همان صفحهٔ تاییدیه را با برچسب/متن به‌روزشده دوباره می‌سازند؛
    # months/users دست‌نخورده می‌مانند.
    elif d in ("cm_set_direct", "cm_set_tls"):
        context.user_data['conn_mode'] = d[len("cm_set_"):]
        await _show_buy_summary(query.message, context, edit=True)

    elif d in ("buy_yes", "buy_emergency_yes"):
        if d == "buy_emergency_yes":
            # 🆘 کاربر روی دکمهٔ «استفاده از شارژ اضطراری» زده؛ این تاییدیه اجازه می‌دهد موجودی
            # نماینده برای همین یک خرید تا سقف EMERGENCY_CREDIT_LIMIT منفی شود.
            context.user_data['emergency_approved'] = True
        # 📦 اگر این تاییدیه مربوط به «ساخت اکانت عمده» باشد، کل جریان به تابع اختصاصی
        # _handle_bulk_purchase سپرده می‌شود (منطق تکی زیر برای حالت bulk اجرا نمی‌شود).
        if context.user_data.get('bulk_mode'):
            await _handle_bulk_purchase(query, context, role, ag_id)
            return
        # 🛡️ محافظت در برابر دابل‌تپ/ارسال دوبارهٔ همین دکمه: اگر یک درخواست ساخت اکانت برای
        # همین کاربر همین الان در حال پردازش است، درخواست دوم رد می‌شود تا هرگز دو اکانت/دو بار
        # کسر کیف‌پول برای یک تاییدیه اتفاق نیفتد.
        if context.user_data.get('purchase_in_progress'):
            await query.message.reply_text("⏳ درخواست قبلی هنوز در حال پردازش است؛ چند لحظه صبر کنید.")
            return
        context.user_data['purchase_in_progress'] = True
        try:
            m, u = context.user_data.get('months'), context.user_data.get('users')
            if not m or not u:
                await query.message.reply_text("❌ تراکنش منقضی شده است.")
                return
            # 🆕 حالت اتصال انتخاب‌شده (توسط دکمهٔ «حالت اتصال» روی همین صفحهٔ تاییدیه) — پیش‌فرض 'direct'
            chosen_conn_mode = context.user_data.get('conn_mode', 'direct')

            # گام ۰: بررسی کیف پول نماینده قبل از هر عملیات سیستمی
            ainf = None
            if role == 'agent':
                ainf = await asyncio.to_thread(_db_get_agent_info, ag_id)
                if not ainf:
                    await query.edit_message_text("❌ خطا: اطلاعات نمایندگی شما یافت نشد. لطفاً دوباره وارد شوید.")
                    return
                # 💵 فرمول قیمت‌گذاری: «قیمت پایه» به‌عنوان نرخ واحد (هر کاربر در هر ماه) در نظر گرفته
                # می‌شود و هزینهٔ نهایی، متناسب با مدت (ماه) و تعداد کاربر همزمان محاسبه می‌شود:
                #   هزینه = قیمت‌پایه × ماه × تعداد کاربر  (دقیقاً، بدون هیچ تخفیفی)
                # 🔧 رفع باگ مالی: قبلاً درصد کمیسیون (commission_pct) به‌عنوان یک «تخفیف مستقیم»
                # از هزینهٔ خرید خودِ نماینده کسر می‌شد. طبق درخواست صریح، هزینهٔ کسرشده از کیف‌پول
                # خودِ نماینده باید همیشه دقیقاً برابر با قیمت پایه × ماه × تعداد کاربر باشد؛
                # commission_pct دیگر در این محاسبه دخیل نیست (کمیسیون‌های شبکه‌ای/override برای
                # والد و پدربزرگ نماینده کماکان طبق l2_pct/l3_pct از روی همین مبلغ محاسبه می‌شود).
                base_price_dec = _parse_price_to_decimal(ainf[4])
                retail_dec = base_price_dec * Decimal(m) * Decimal(u)
                cost_dec = retail_dec
                cost = float(cost_dec)
                if ainf[2] < cost and not context.user_data.get('emergency_approved'):
                    has_opt, remaining_em, shortfall, used_em, req_cnt = _check_emergency_option(ainf, cost)
                    can_use_em, active_count = _agent_can_use_emergency_credit(ag_id)
                    if has_opt and can_use_em:
                        kb_em = [[InlineKeyboardButton("🆘 استفاده از شارژ اضطراری", callback_data="buy_emergency_yes")],
                                 [InlineKeyboardButton("↩️ انصراف", callback_data="buy_no")]]
                        await query.edit_message_text(
                            f"❌ <b>موجودی ناکافی!</b>\n\n💰 موجودی شما: {int(ainf[2]):,} تومان\n💳 هزینه این اکانت: {int(cost):,} تومان\n\n"
                            f"🆘 می‌توانید از <b>شارژ اضطراری</b> استفاده کنید (سقف کل: {int(EMERGENCY_CREDIT_LIMIT):,} تومان، "
                            f"باقی‌ماندهٔ شما: {int(remaining_em):,} تومان). این مبلغ در اولین شارژ بعدی حساب شما به‌طور خودکار کسر می‌شود.",
                            reply_markup=InlineKeyboardMarkup(kb_em), parse_mode="HTML")
                        # 🐛🔧 رفع باگ اصلی «دکمهٔ شارژ اضطراری در خرید تکی عمل نمی‌کند»: این تابع یک
                        # finally در انتهای خودش دارد که همیشه safe_clear_context را صدا می‌زد — یعنی
                        # همین‌جا، درست بعد از نمایش دکمهٔ «شارژ اضطراری»، months/users از context پاک
                        # می‌شدند. با کلیک روی آن دکمه، هندلر با m/u خالی دوباره اجرا می‌شد و فقط یک
                        # toast «تراکنش منقضی شده» (بدون تغییر ظاهری در پیام) نشان می‌داد که در نگاه
                        # اول شبیه «دکمه اصلاً کار نمی‌کند» به نظر می‌رسید. حالا این پرچم به finally
                        # می‌گوید که context را پاک نکند، چون months/users هنوز برای اجرای واقعی بعد
                        # از کلیک روی «شارژ اضطراری» لازم هستند.
                        context.user_data['_skip_purchase_clear'] = True
                        return
                    extra = ""
                    if req_cnt >= EMERGENCY_MAX_CONSECUTIVE_REQUESTS:
                        extra = "\n\n🆘 سقف درخواست‌های پیاپی شارژ اضطراری (۲ بار) شما پر شده؛ لطفاً منتظر شارژ حساب توسط مدیریت بمانید."
                    elif used_em > 0:
                        extra = f"\n\n🆘 شارژ اضطراری باقی‌ماندهٔ شما ({int(remaining_em):,} تومان) برای این خرید کافی نیست."
                    await query.edit_message_text(f"❌ <b>موجودی ناکافی!</b>\n\n💰 موجودی شما: {int(ainf[2]):,} تومان\n💳 هزینه این اکانت: {int(cost):,} تومان\n\nلطفاً از منوی اصلی ابتدا حساب خود را شارژ کنید.{extra}", parse_mode="HTML")
                    return

            br = _resolve_username_prefix(role, ainf)
            if br is None:
                br = (await asyncio.to_thread(_db_get_setting, 'brand', 'NeVeL')).lower().strip()
                br = re.sub(r'[^a-z0-9]', '', br) or "nevel"
            c_start = await asyncio.to_thread(_db_get_prefix_start_counter, br)

            # گام ۱: رزرو اتمیک یوزرنیم (این خودش هم‌زمانی دو خرید را بدون تداخل مدیریت می‌کند)
            un, c = await asyncio.to_thread(_db_reserve_username, br, c_start)
            if un is None:
                await query.message.reply_text("❌ خطا: امکان یافتن یوزرنیم آزاد وجود ندارد. لطفاً شمارنده را از «⚙️ تنظیمات سرور» بازبینی کنید.")
                return

            # اگر یوزرنیم به‌صورت دستی یا در اثر خطای قبلی از قبل روی خودِ سرور لینوکس ساخته شده،
            # رزرو را آزاد کرده و یوزرنیم بعدی را رزرو می‌کنیم.
            # 🔧 رفع باگ «useradd: user ... already exists»: سقف تلاش مجدد قبلاً فقط ۲۰ بود؛ اگر
            # به هر دلیلی (مثلاً برند عوض شده و شمارندهٔ قدیمی با بازهٔ بزرگی از یوزرهای واقعی
            # از‌قبل‌ساخته‌شدهٔ لینوکس همپوشانی داشت) بیش از ۲۰ یوزرنیم پشت‌سرهم از قبل اشغال
            # بودند، ربات تسلیم می‌شد و خطای خام useradd را به کاربر نشان می‌داد. الان سقف
            # بسیار بالاتر است (تا آزادشدن یک یوزرنیم واقعاً خالی).
            MAX_OS_RETRIES = 500
            os_retries = 0
            # endpoint عمومی این اکانت یک‌بار انتخاب می‌شود؛ عملیات Linux در توپولوژی Relay
            # روی Core انجام می‌شود و target_host فقط برای routing/invoice metadata باقی می‌ماند.
            target_host = await asyncio.to_thread(_pick_target_host_for_new_account)
            target_port = await asyncio.to_thread(_db_get_host_ssh_port, target_host, 22)
            while await _os_user_exists(un, target_host, target_port) and os_retries < MAX_OS_RETRIES:
                await asyncio.to_thread(_db_cancel_reservation, un)
                un, c = await asyncio.to_thread(_db_reserve_username, br, c + 1)
                if un is None:
                    await query.message.reply_text("❌ خطا: امکان یافتن یوزرنیم آزاد وجود ندارد.")
                    return
                os_retries += 1

            pw = "".join(random.choices(string.digits, k=5))
            now = datetime.now(); exp_days = m * 30
            # 🆕 آنهولد پنهان (V88): استفاده از ماژول متمرکز
            hold_sched = await asyncio.to_thread(_prepare_hidden_hold_for_new_account, un, exp_days)
            os_exp_db = hold_sched.linux_expire_date
            exp_db, cr_db = hold_sched.visible_expire_date, now.strftime("%Y-%m-%d")
            hold_deadline_db = hold_sched.hold_deadline  # برای ثبت در دیتابیس (finalize)

            # گام ۲: ساخت کاربر لینوکسی
            useradd_retries = 0
            while True:
                ok1, err1, kind1 = await run_cmd("sudo", "useradd", "-s", "/bin/false", "-e", os_exp_db, un)
                if ok1:
                    break
                is_duplicate = "already exists" in (err1 or "").lower()
                if is_duplicate and useradd_retries < MAX_OS_RETRIES:
                    log.warning("useradd برای %s با «already exists» شکست خورد؛ تلاش خودکار با یوزرنیم بعدی...", un)
                    await asyncio.to_thread(_db_cancel_reservation, un)
                    un, c = await asyncio.to_thread(_db_reserve_username, br, c + 1)
                    if un is None:
                        await query.message.reply_text("❌ خطا: امکان یافتن یوزرنیم آزاد وجود ندارد.")
                        return
                    useradd_retries += 1
                    continue
                await asyncio.to_thread(_db_cancel_reservation, un)  # 🔙 Rollback رزرو دیتابیس
                log.error("ساخت اکانت %s شکست خورد در مرحله useradd؛ رزرو دیتابیس لغو شد.", un)
                await query.message.reply_text(_fmt_linux_error("ساخت کاربر لینوکسی", err1, kind1), parse_mode="HTML")
                return

            # گام ۳: تنظیم پسورد لینوکسی
            ok2, err2, kind2 = await run_cmd("sudo", "chpasswd", input_data=f"{un}:{pw}\n".encode())
            if not ok2:
                ok_del, err_del, _ = await run_cmd("sudo", "userdel", "-f", un)  # 🔙 Rollback کاربر لینوکسی
                await asyncio.to_thread(_db_cancel_reservation, un)              # 🔙 Rollback رزرو دیتابیس
                if not ok_del:
                    log.error("Rollback ناقص برای %s: userdel شکست خورد: %s — نیاز به بررسی دستی روی سرور.", un, err_del)
                await query.message.reply_text(_fmt_linux_error("تنظیم پسورد", err2, kind2), parse_mode="HTML")
                return

            # گام ۴: تکمیل نهایی رکورد دیتابیس (فقط پس از موفقیت کامل مراحل لینوکسی)
            try:
                await asyncio.to_thread(_db_finalize_reserved_user, un, pw, exp_db, cr_db, u, str(c + 1).zfill(4), br, ag_id, chosen_conn_mode, hold_deadline_db, exp_days)
                await asyncio.to_thread(_db_set_account_host, un, target_host)  # 🆕 ثبتِ Edgeِ صاحبِ این اکانت
            except Exception:
                log.exception("خطا در ثبت نهایی اکانت %s در دیتابیس؛ کاربر لینوکسی حذف می‌شود (Rollback).", un)
                await run_cmd("sudo", "userdel", "-f", un)
                await asyncio.to_thread(_db_cancel_reservation, un)
                await query.message.reply_text("❌ خطا در ثبت نهایی اکانت در دیتابیس. عملیات به‌طور کامل لغو (Rollback) شد؛ سرور تغییری نکرد.")
                return

            # اکانت از این نقطه به بعد کاملاً و به‌صورت پایدار ساخته شده است ✅
            log.info("اکانت %s با موفقیت ساخته شد (نماینده: %s).", un, ag_id if role == 'agent' else 'ادمین')
            await _sync_user_limit_file(un, u)  # فایل سقف اتصال PAM روی Core نوشته می‌شود
            
            try:
                actor = f"نماینده: {esc(ainf[0])}" if (role == 'agent' and ainf) else "ادمین"
                c_txt = f"\nهزینه: {int(cost):,} تومان" if role == 'agent' else ""
                await _notify_super_admin(context.application, f"🆕 <b>ساخت اکانت جدید</b>\nنوع اکانت: SSH\nتوسط: {actor}\nمدت زمان: {m * 30} روزه\nتعداد کاربر: {u} کاربره{c_txt}", tg_user=update.effective_user)
                await asyncio.to_thread(_db_log_activity, ag_id if role=='agent' else 0, un, 'create', 'ssh', f"{m*30} روز - {u} کاربر", cost if role=='agent' else 0)
            except: pass

            # 🛡️ شمارندهٔ صرفاً‌افزایشیِ «کل فروش تابه‌حال» (مبنای کش‌بک) — مستقل از کسر کیف‌پول
            if role == 'agent':
                with contextlib.suppress(Exception):
                    await asyncio.to_thread(_db_increment_lifetime_sold, ag_id)

            # گام ۵: کسر هزینه از کیف پول نماینده و توزیع پورسانت لایه‌ای (خطای احتمالی اینجا اکانت را باطل نمی‌کند)
            if role == 'agent':
                try:
                    with db_conn() as conn: conn.execute("UPDATE agents SET balance = balance - ? WHERE id=?", (cost, ag_id))
                    await asyncio.to_thread(_db_distribute_commission, ag_id, retail_dec)
                    # 🎁 کش‌بک ترغیبی نمایندگان پرفروش (۵۰+ اکانت فعال): ۷٪ از هزینهٔ همین خرید
                    await _apply_agent_cashback_if_eligible(ag_id, retail_dec)
                    log.info("مبلغ %s از کیف پول نماینده %s کسر شد.", cost, ag_id)
                    # 🆘 اگر این خرید با کمک شارژ اضطراری تکمیل شد، مصرف ثبت و به همهٔ ادمین‌ها اطلاع داده می‌شود
                    emergency_shortfall = max(0.0, cost - ainf[2])
                    if emergency_shortfall > 0:
                        await asyncio.to_thread(_db_agent_register_emergency_use, ag_id, emergency_shortfall)
                        with contextlib.suppress(Exception):
                            await _notify_admins(context.application,
                                f"🆘 <b>استفاده از شارژ اضطراری</b>\nنمایندهٔ «{esc(ainf[0])}» برای ساخت اکانت <code>{esc(un)}</code> "
                                f"مبلغ {int(emergency_shortfall):,} تومان از شارژ اضطراری استفاده کرد.")
                except Exception:
                    log.exception("خطا در کسر کیف‌پول/توزیع کمیسیون برای اکانت %s (اکانت ساخته شده باقی می‌ماند).", un)

            # گام ۶: ارسال فاکتور
            try:
                out = await _build_invoice_text(un)
            except Exception:
                log.exception("ساخت متن فاکتور برای اکانت %s با خطا مواجه شد؛ اکانت با موفقیت ساخته شده اما نمایش فاکتور ناموفق بود.", un)
                out = None
            inv_kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔗 دریافت کد نپسترنت (قابل کپی)", callback_data=f"uact_niinv_{un}")]])
            if out is None:
                with contextlib.suppress(Exception):
                    await context.bot.send_message(
                        chat_id=query.message.chat_id,
                        text=f"✅ اکانت <code>{esc(un)}</code> با موفقیت ساخته شد، اما ساخت متن فاکتور با خطا مواجه شد.\n"
                             f"با دکمهٔ زیر می‌توانید دوباره فاکتور کامل را دریافت کنید 👇",
                        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🧾 دریافت فاکتور کامل", callback_data=f"uact_inv_{un}")]]),
                        parse_mode="HTML")
                return
            try:
                await query.edit_message_text(out, reply_markup=inv_kb, parse_mode="HTML")
            except Exception as e1:
                log.warning("ویرایش پیام برای ارسال فاکتور %s ناموفق بود (%s)؛ تلاش با send_message...", un, e1)
                try:
                    await context.bot.send_message(chat_id=query.message.chat_id, text=out, reply_markup=inv_kb, parse_mode="HTML")
                except Exception:
                    log.exception("ارسال فاکتور اکانت %s به هر دو روش (edit و send) ناموفق بود. متن کامل فاکتور برای ثبت/بازیابی دستی:\n%s", un, out)
                    with contextlib.suppress(Exception):
                        await context.bot.send_message(
                            chat_id=query.message.chat_id,
                            text=f"✅ اکانت <code>{esc(un)}</code> با موفقیت ساخته شد، اما ارسال خودکار فاکتور با خطا مواجه شد.\n"
                                 f"فاکتور کامل در لاگ سرور ثبت شد و همچنین با دکمهٔ زیر همیشه قابل دریافت مجدد است 👇",
                            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🧾 دریافت فاکتور کامل", callback_data=f"uact_inv_{un}")]]),
                            parse_mode="HTML")
        except Exception as e:
            # 💡 در اینجا ارور اصلی پرینت می‌شود
            log.exception("خطای پیش‌بینی‌نشده در فرآیند ساخت اکانت")
            with contextlib.suppress(Exception):
                await query.message.reply_text(f"❌ خطای غیرمنتظره‌ای رخ داد:\n<code>{esc(str(e))}</code>\nلطفاً این ارور را کپی کرده و بفرستید.", parse_mode="HTML")
        finally:
            if context.user_data.pop('_skip_purchase_clear', False):
                context.user_data['purchase_in_progress'] = False
            else:
                safe_clear_context(context)
    elif d == "buy_no": await query.edit_message_text("❌ عملیات لغو شد."); safe_clear_context(context)

    # مدیریت کاربر
    elif d.startswith("upage_"): await _show_users_panel(update, context, page=int(d.split("_")[1]))
    elif d.startswith("udet_"): await _show_user_detail(update, d.split("_")[1], context)
    elif d.startswith("uact_dl_"):
        # 🆕 قبل از حذف واقعی، تاییدیهٔ بله/خیر گرفته می‌شود (حذف اکانت غیرقابل‌بازگشت است)
        un = d.split("_")[2]
        owner = await asyncio.to_thread(_db_get_user, un)
        if not owner: return await query.edit_message_text("❌ این کاربر دیگر وجود ندارد.")
        if not _can_manage_user(role, ag_id, owner[5]): return await query.message.reply_text("⛔️ شما مجاز به مدیریت این اکانت نیستید.")
        kb = [[InlineKeyboardButton("✅ بله، حذف شود", callback_data=f"udelconf_yes_{un}"), InlineKeyboardButton("↩️ خیر، انصراف", callback_data=f"udelconf_no_{un}")]]
        await query.edit_message_text(f"⚠️ آیا مطمئنید می‌خواهید اکانت {esc(un)} را به‌طور کامل حذف کنید؟\nاین عملیات قابل بازگشت نیست.", reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
    elif d.startswith("udelconf_yes_"):
        un = d.split("_", 2)[2]
        owner = await asyncio.to_thread(_db_get_user, un)
        if not owner: return await query.edit_message_text("❌ این کاربر دیگر وجود ندارد.")
        if not _can_manage_user(role, ag_id, owner[5]): return await query.message.reply_text("⛔️ شما مجاز به مدیریت این اکانت نیستید.")

        # 💸 بازپرداخت متناسب: اگر این اکانت متعلق به یک نماینده باشد، بخشِ استفاده‌نشدهٔ هزینه
        # (روزهای باقی‌مانده تا انقضا × تعداد کاربر مجاز، به نسبت قیمت پایهٔ فعلی همان نماینده)
        # به کیف‌پولِ قابل‌خرج (balance) او برگردانده می‌شود — نه به استخر قابل‌برداشت
        # (withdrawable_balance). این تفکیک عمدی است: بازپرداخت فقط سرمایهٔ خودِ نماینده را که
        # قبلاً بابت همین اکانت پرداخته بود برمی‌گرداند تا صرفِ خریدهای بعدی شود، و هرگز مستقیماً
        # قابل برداشتِ نقدی نیست؛ به این ترتیب چرخهٔ «ساخت اکانت‌های الکی → واجدشرایط کش‌بک شدن →
        # برداشت نقدی کش‌بک → حذف اکانت‌ها → بازپرداخت هزینه» نمی‌تواند پول واقعی اضافه تولید کند.
        owner_agent_id = owner[5]
        refund = 0.0
        refund_note = ""
        if owner_agent_id and owner_agent_id != 0:
            try:
                refund, refund_desc = await _calc_account_refund(un)
                if refund > 0:
                    with db_conn() as conn:
                        conn.execute("UPDATE agents SET balance = balance + ? WHERE id=?", (refund, owner_agent_id))
                        used_before_row = conn.execute("SELECT emergency_used FROM agents WHERE id=?", (owner_agent_id,)).fetchone()
                        used_before = (used_before_row[0] or 0.0) if used_before_row else 0.0
                        _apply_emergency_repayment(conn, owner_agent_id, refund)
                        emergency_repaid = min(used_before, refund) if used_before > 0 else 0.0
                    refund_note = f"\n💸 {refund_desc}"
                    if emergency_repaid > 0:
                        refund_note += f"\n🆘 از همین مبلغ، {int(emergency_repaid):,} تومان بدهیِ شارژ اضطراری نماینده نیز پاک شد."
            except Exception:
                log.exception("خطا در اعمال بازپرداخت حذف اکانت %s", un)

        # Linux account lives on Core; owner.host is endpoint/routing metadata only.
        ok, err, kind = await run_cmd("sudo", "userdel", "-f", un)
        await asyncio.to_thread(_db_delete_user, un)
        await _remove_user_limit_file(un)  # پاک‌سازی فایل PAM روی Core
        if ok: await query.edit_message_text(f"✅ اکانت {esc(un)} حذف شد. (آمار فروش کسر گردید){refund_note}")
        else:
            extra = _fmt_linux_error("حذف اکانت", err, kind)
            await query.edit_message_text(f"⚠️ اکانت {esc(un)} از دیتابیس حذف شد اما حذف یوزر لینوکسی ناموفق بود:\n\n{extra}\nپیشنهاد می‌شود دستی بررسی شود.{refund_note}", parse_mode="HTML")
    elif d.startswith("udelconf_no_"):
        un = d.split("_", 2)[2]
        await _show_user_detail(update, un, context)
    # 🆕 تغییر حالت اتصال یک اکانت از قبل‌ساخته‌شده بین «مستقیم» و «TLS». هیچ عملیات لینوکسی
    # لازم ندارد (سرور TLS مستقل و همیشه در حال گوش‌دادن است)؛ فقط ستون conn_mode در دیتابیس
    # عوض می‌شود تا کد نپسترنتِ بعدی که برای این اکانت گرفته شود، مقصد درست را بسازد.
    # callback_data به‌صورت uact_cm_<direct|tls>_<username> است.
    elif d.startswith("uact_cm_"):
        _, _, new_mode, un = d.split("_", 3)
        cur = await asyncio.to_thread(_db_get_user, un)
        if not cur: return await query.edit_message_text("❌ این کاربر دیگر وجود ندارد.")
        if not _can_manage_user(role, ag_id, cur[5]): return await query.message.reply_text("⛔️ شما مجاز به مدیریت این اکانت نیستید.")
        await asyncio.to_thread(_db_set_conn_mode, un, new_mode)
        await query.answer("✅ حالت اتصال عوض شد — کد نپسترنت جدید را از همین پنل بگیرید.")
        await _show_user_detail(query, un, context)

    elif d.startswith("uact_tg_"):
        un = d.split("_")[2]
        cur = await asyncio.to_thread(_db_get_user, un)
        if not cur: return await query.edit_message_text("❌ این کاربر دیگر وجود ندارد.")
        if not _can_manage_user(role, ag_id, cur[5]): return await query.message.reply_text("⛔️ شما مجاز به مدیریت این اکانت نیستید.")
        cur_status = cur[4]
        will_lock = (cur_status == "🟢 فعال")  # اگر الان فعال است، می‌خواهیم غیرفعالش کنیم

        # اطمینان از وجود واقعی کاربر روی سیستم لینوکس، پیش از تلاش برای قفل/بازکردن آن؛
        # اگر کاربر فقط در دیتابیس وجود دارد ولی روی لینوکس نیست، usermod با خطای مبهم شکست
        # می‌خورد و کاربر گمان می‌کند دکمه اصلاً کار نمی‌کند.
        if not await _os_user_exists(un):
            await query.message.reply_text(
                f"❌ اکانت <code>{esc(un)}</code> در دیتابیس هست اما روی خودِ سرور لینوکس یافت نشد.\n"
                f"این یعنی اکانت به‌صورت ناقص ساخته شده؛ پیشنهاد می‌شود آن را حذف و دوباره بسازید.",
                parse_mode="HTML")
            return

        # 🔧 ابتدا دستور لینوکسی اجرا و بررسی می‌شود؛ فقط در صورت موفقیتِ قطعی، وضعیت دیتابیس
        # تغییر می‌کند — تا دیتابیس و وضعیت واقعی سرور همیشه هم‌خوان بمانند.
        ok, err, kind = await run_cmd("sudo", "usermod", "-L" if will_lock else "-U", un)
        if not ok:
            await query.message.reply_text(_fmt_linux_error("تغییر وضعیت فعال/غیرفعال", err, kind), parse_mode="HTML")
            return

        log.info("وضعیت لینوکسی %s با موفقیت به %s تغییر کرد.", un, "قفل" if will_lock else "باز")

        try:
            nxt = await asyncio.to_thread(_db_toggle_status, un)
        except Exception:
            # 🔙 Rollback: چون لینوکس با موفقیت تغییر کرد ولی ثبت آن در دیتابیس شکست خورد،
            # برای هم‌خوان‌ماندن دو طرف، تغییر لینوکس را به حالت قبل برمی‌گردانیم.
            log.exception("ثبت تغییر وضعیت %s در دیتابیس شکست خورد؛ تلاش برای Rollback وضعیت لینوکس...", un)
            ok_rb, err_rb, _ = await run_cmd("sudo", "usermod", "-U" if will_lock else "-L", un)
            if not ok_rb:
                log.error("Rollback لینوکس برای %s هم شکست خورد: %s — وضعیت دیتابیس و لینوکس ممکن است ناهم‌خوان باشند و نیاز به بررسی دستی دارد.", un, err_rb)
            await query.message.reply_text("❌ خطا در ثبت تغییر وضعیت در دیتابیس. تغییر روی سرور لینوکس نیز بازگردانده شد (Rollback) تا وضعیت دو طرف ناهم‌خوان نماند.")
            return

        if nxt is None: return await query.edit_message_text("❌ این کاربر دیگر وجود ندارد.")
        await _show_user_detail(update, un, context)
    elif d.startswith("uact_pw_"):
        un = d.split("_")[2]
        owner = await asyncio.to_thread(_db_get_user, un)
        if not owner: return await query.edit_message_text("❌ این کاربر دیگر وجود ندارد.")
        if not _can_manage_user(role, ag_id, owner[5]): return await query.message.reply_text("⛔️ شما مجاز به مدیریت این اکانت نیستید.")
        context.user_data['target_pw'] = un; context.user_data['state'] = 'USER_NEW_PASS'
        # 🆕 دکمهٔ «بازگشت» به همان صفحهٔ کاربر (بدون تغییر پسورد) اضافه شد
        kb = [[InlineKeyboardButton("🔙 بازگشت", callback_data=f"udet_{un}")]]
        await query.message.reply_text(f"✏️ پسورد جدید برای {esc(un)} را بفرستید:", reply_markup=InlineKeyboardMarkup(kb))
    elif d == "pwconf_yes":
        # 🆕 تاییدیهٔ نهایی تغییر پسورد؛ فقط الان (بعد از تایید) واقعاً روی لینوکس/دیتابیس اعمال می‌شود
        un = context.user_data.get('target_pw'); new_pw = context.user_data.get('pending_new_pw')
        if not un or not new_pw:
            await query.edit_message_text("❌ تراکنش منقضی شده است."); safe_clear_context(context); return
        owner = await asyncio.to_thread(_db_get_user, un)
        if not owner:
            await query.edit_message_text("❌ این کاربر دیگر وجود ندارد."); safe_clear_context(context); return
        if not _can_manage_user(role, ag_id, owner[5]):
            await query.message.reply_text("⛔️ شما مجاز به مدیریت این اکانت نیستید."); safe_clear_context(context); return
        ok, err, kind = await run_cmd(
            "sudo", "chpasswd",
            input_data=f"{un}:{new_pw}\n".encode()
        )
        if ok:
            await asyncio.to_thread(_db_update_password, un, new_pw)
            await query.edit_message_text(f"✅ پسورد {esc(un)} تغییر کرد.")
        else:
            await query.edit_message_text(_fmt_linux_error("تغییر پسورد", err, kind), parse_mode="HTML")
        safe_clear_context(context); await _show_user_detail(update, un, context)
    elif d == "pwconf_no":
        un = context.user_data.get('target_pw')
        safe_clear_context(context)
        if un: await _show_user_detail(update, un, context)
        else: await query.edit_message_text("✅ انصراف داده شد.")

    # 💰 تاییدیهٔ نهایی شارژ مستقیم کیف‌پول یک نماینده از پنل ادمین
    elif d == "topupconf_yes":
        a_id = context.user_data.get('topup_ag_id'); amount = context.user_data.get('pending_topup_amount')
        if not a_id or not amount:
            await query.edit_message_text("❌ تراکنش منقضی شده است."); safe_clear_context(context); return
        info = await asyncio.to_thread(_db_get_agent_info, a_id)
        if not info:
            await query.edit_message_text("❌ این نماینده دیگر وجود ندارد."); safe_clear_context(context); return
        await asyncio.to_thread(_db_admin_topup_agent, a_id, amount)
        new_balance = info[2] + amount
        await query.edit_message_text(f"✅ مبلغ {int(amount):,} تومان به کیف‌پول «{esc(info[0])}» اضافه شد.\n💰 موجودی جدید: {int(new_balance):,} تومان")
        if info[8]:  # telegram_id نماینده — در صورت وجود، به او هم اطلاع داده می‌شود
            with contextlib.suppress(Exception):
                await context.bot.send_message(chat_id=info[8], text=f"🎉 <b>شارژ کیف‌پول</b>\nمبلغ {int(amount):,} تومان توسط مدیریت به کیف‌پول شما اضافه شد.\n💰 موجودی جدید: {int(new_balance):,} تومان", parse_mode="HTML")
        
        await _notify_super_admin(context.application, f"💰 <b>شارژ دستی کیف‌پول</b>\nحساب نماینده «{esc(info[0])}» مبلغ {int(amount):,} تومان توسط ادمین شارژ شد.", tg_user=update.effective_user)
        safe_clear_context(context)
    elif d == "topupconf_no":
        a_id = context.user_data.get('topup_ag_id')
        safe_clear_context(context)
        await query.edit_message_text("✅ انصراف داده شد؛ هیچ مبلغی شارژ نشد.")

    # ➖ تاییدیهٔ نهایی کاهش شارژ کیف‌پول یک نماینده از پنل ادمین (برای اصلاح شارژهای اشتباهی)
    elif d == "deductconf_yes":
        a_id = context.user_data.get('deduct_ag_id'); amount = context.user_data.get('pending_deduct_amount')
        if not a_id or not amount:
            await query.edit_message_text("❌ تراکنش منقضی شده است."); safe_clear_context(context); return
        info = await asyncio.to_thread(_db_get_agent_info, a_id)
        if not info:
            await query.edit_message_text("❌ این نماینده دیگر وجود ندارد."); safe_clear_context(context); return
        await asyncio.to_thread(_db_admin_deduct_agent, a_id, amount)
        new_balance = info[2] - amount
        await query.edit_message_text(f"✅ مبلغ {int(amount):,} تومان از کیف‌پول «{esc(info[0])}» کم شد.\n💰 موجودی جدید: {int(new_balance):,} تومان")
        if info[8]:  # telegram_id نماینده — در صورت وجود، به او هم اطلاع داده می‌شود
            with contextlib.suppress(Exception):
                await context.bot.send_message(chat_id=info[8], text=f"⚠️ <b>اصلاح کیف‌پول</b>\nمبلغ {int(amount):,} تومان توسط مدیریت از کیف‌پول شما کسر شد.\n💰 موجودی جدید: {int(new_balance):,} تومان", parse_mode="HTML")
        safe_clear_context(context)
    elif d == "deductconf_no":
        a_id = context.user_data.get('deduct_ag_id')
        safe_clear_context(context)
        await query.edit_message_text("✅ انصراف داده شد؛ هیچ مبلغی کم نشد.")

    # 👥 «تعداد کاربر» — منوی واسط که بین افزایش و کاهش تعداد کاربر مجاز یک اکانت انتخاب می‌کند
    elif d.startswith("uact_uc_"):
        un = d.split("_", 2)[2]
        cur = await asyncio.to_thread(_db_get_user, un)
        if not cur: return await query.edit_message_text("❌ این کاربر دیگر وجود ندارد.")
        if not _can_manage_user(role, ag_id, cur[5]): return await query.message.reply_text("⛔️ شما مجاز به مدیریت این اکانت نیستید.")
        cur_limit = cur[3]
        kb = [[InlineKeyboardButton("➕ افزایش تعداد کاربر", callback_data=f"uact_ul_{un}"), InlineKeyboardButton("➖ کاهش تعداد کاربر", callback_data=f"uact_ud_{un}")],
              [InlineKeyboardButton("🔙 بازگشت", callback_data=f"udet_{un}")]]
        await query.edit_message_text(
            f"👥 تعداد کاربر همزمان اکانت {esc(un)}\nتعداد فعلی: {cur_limit}\n\nیکی از گزینه‌های زیر را انتخاب کنید:",
            reply_markup=InlineKeyboardMarkup(kb))

    # ➕ افزایش تعداد کاربر همزمان مجاز یک اکانت (هم پنل ادمین، هم پنل نمایندگان)
    # 🆕 حالا به‌جای پرسیدن مستقیم عدد در چت، سه دکمهٔ آمادهٔ +۱/+۲/+۳ + یک گزینهٔ «دلخواه»
    # (برای هر عدد دیگری) + دکمهٔ «بازگشت» به همان صفحهٔ کاربر نمایش داده می‌شود.
    elif d.startswith("uact_ul_"):
        un = d.split("_", 2)[2]
        cur = await asyncio.to_thread(_db_get_user, un)
        if not cur: return await query.edit_message_text("❌ این کاربر دیگر وجود ندارد.")
        if not _can_manage_user(role, ag_id, cur[5]): return await query.message.reply_text("⛔️ شما مجاز به مدیریت این اکانت نیستید.")
        cur_limit = cur[3]
        kb = [[InlineKeyboardButton(f"+{i} کاربر ({cur_limit + i})", callback_data=f"uinc_{i}_{un}") for i in (1, 2, 3)],
              [InlineKeyboardButton("🔹 دلخواه (هر تعداد کاربر)", callback_data=f"uinc_custom_{un}")],
              [InlineKeyboardButton("🔙 بازگشت", callback_data=f"uact_uc_{un}")]]
        await query.edit_message_text(
            f"➕ افزایش تعداد کاربر همزمان اکانت {esc(un)}\n"
            f"👥 تعداد فعلی: {cur_limit}\n\nیکی از گزینه‌های زیر را انتخاب کنید:",
            reply_markup=InlineKeyboardMarkup(kb))
    elif d.startswith("uinc_custom_"):
        un = d.split("_", 2)[2]
        cur = await asyncio.to_thread(_db_get_user, un)
        if not cur: return await query.edit_message_text("❌ این کاربر دیگر وجود ندارد.")
        if not _can_manage_user(role, ag_id, cur[5]): return await query.message.reply_text("⛔️ شما مجاز به مدیریت این اکانت نیستید.")
        cur_limit = cur[3]
        context.user_data['target_ul'] = un
        context.user_data['state'] = 'USER_INC_LIMIT'
        kb = [[InlineKeyboardButton("🔙 بازگشت", callback_data=f"uact_uc_{un}")]]
        await query.edit_message_text(
            f"✍️ عدد «تعداد کاربر جدید» اکانت {esc(un)} را بفرستید (باید بزرگ‌تر از {cur_limit} باشد):",
            reply_markup=InlineKeyboardMarkup(kb))
    elif d == "uinc_emergency_yes":
        # 🆘 کاربر روی دکمهٔ «استفاده از شارژ اضطراری» (در جریان افزایش تعداد کاربر) زده است.
        # این شاخه باید پیش از «elif d.startswith("uinc_")» چک شود، وگرنه آن شاخهٔ عمومی‌تر
        # (که با startswith("uinc_") مچ می‌شود) زودتر این callback را (اشتباهاً) می‌قاپد.
        un = context.user_data.get('ul_emergency_un')
        new_limit = context.user_data.get('ul_emergency_new_limit')
        if not un or not new_limit:
            return await query.message.reply_text("❌ تراکنش منقضی شده است.")
        ok, msg, kb = await _apply_user_limit_increase(context, role, ag_id, un, new_limit, emergency_approved=True)
        await query.edit_message_text(msg, parse_mode="HTML", reply_markup=kb)
        if kb is None:
            context.user_data.pop('ul_emergency_un', None)
            context.user_data.pop('ul_emergency_new_limit', None)
            await _show_user_detail(update, un, context)
    elif d.startswith("uinc_"):
        # uinc_{n}_{username} — دکمه‌های آمادهٔ +۱/+۲/+۳
        parts = d.split("_", 2)
        n_str, un = parts[1], parts[2]
        if not n_str.isdigit():
            return await query.message.reply_text("❌ درخواست نامعتبر.")
        cur = await asyncio.to_thread(_db_get_user, un)
        if not cur: return await query.edit_message_text("❌ این کاربر دیگر وجود ندارد.")
        if not _can_manage_user(role, ag_id, cur[5]): return await query.message.reply_text("⛔️ شما مجاز به مدیریت این اکانت نیستید.")
        new_limit = cur[3] + int(n_str)
        ok, msg, kb = await _apply_user_limit_increase(context, role, ag_id, un, new_limit)
        await query.message.reply_text(msg, parse_mode="HTML", reply_markup=kb)
        if kb is None:
            await _show_user_detail(update, un, context)

    # ➖ کاهش تعداد کاربر همزمان مجاز یک اکانت — دقیقاً همان الگوی افزایش، با بازگشت مبلغ متناسب
    elif d.startswith("uact_ud_"):
        un = d.split("_", 2)[2]
        cur = await asyncio.to_thread(_db_get_user, un)
        if not cur: return await query.edit_message_text("❌ این کاربر دیگر وجود ندارد.")
        if not _can_manage_user(role, ag_id, cur[5]): return await query.message.reply_text("⛔️ شما مجاز به مدیریت این اکانت نیستید.")
        cur_limit = cur[3]
        opts = [i for i in (1, 2, 3) if cur_limit - i >= 1]
        row = [InlineKeyboardButton(f"-{i} کاربر ({cur_limit - i})", callback_data=f"udec_{i}_{un}") for i in opts]
        kb = ([row] if row else []) + [[InlineKeyboardButton("🔹 دلخواه (هر تعداد کاربر)", callback_data=f"udec_custom_{un}")],
              [InlineKeyboardButton("🔙 بازگشت", callback_data=f"uact_uc_{un}")]]
        await query.edit_message_text(
            f"➖ کاهش تعداد کاربر همزمان اکانت {esc(un)}\n"
            f"👥 تعداد فعلی: {cur_limit}\n\nیکی از گزینه‌های زیر را انتخاب کنید:",
            reply_markup=InlineKeyboardMarkup(kb))
    elif d.startswith("udec_custom_"):
        un = d.split("_", 2)[2]
        cur = await asyncio.to_thread(_db_get_user, un)
        if not cur: return await query.edit_message_text("❌ این کاربر دیگر وجود ندارد.")
        if not _can_manage_user(role, ag_id, cur[5]): return await query.message.reply_text("⛔️ شما مجاز به مدیریت این اکانت نیستید.")
        cur_limit = cur[3]
        context.user_data['target_ul'] = un
        context.user_data['state'] = 'USER_DEC_LIMIT'
        kb = [[InlineKeyboardButton("🔙 بازگشت", callback_data=f"uact_uc_{un}")]]
        await query.edit_message_text(
            f"✍️ عدد «تعداد کاربر جدید» اکانت {esc(un)} را بفرستید (باید کوچک‌تر از {cur_limit} و حداقل ۱ باشد):",
            reply_markup=InlineKeyboardMarkup(kb))
    elif d.startswith("udec_"):
        # udec_{n}_{username} — دکمه‌های آمادهٔ -۱/-۲/-۳
        parts = d.split("_", 2)
        n_str, un = parts[1], parts[2]
        if not n_str.isdigit():
            return await query.message.reply_text("❌ درخواست نامعتبر.")
        cur = await asyncio.to_thread(_db_get_user, un)
        if not cur: return await query.edit_message_text("❌ این کاربر دیگر وجود ندارد.")
        if not _can_manage_user(role, ag_id, cur[5]): return await query.message.reply_text("⛔️ شما مجاز به مدیریت این اکانت نیستید.")
        new_limit = cur[3] - int(n_str)
        ok, msg = await _apply_user_limit_decrease(context, role, ag_id, un, new_limit)
        await query.message.reply_text(msg, parse_mode="HTML")
        await _show_user_detail(update, un, context)

    # ==========================================
    # 🌐 سرویس IP (فقط ادمین) — جایگزین قابلیت قدیمی «انتقال به IP دیگر» که از پنل هر اکانت
    # (چه ادمین چه نماینده) حذف شد؛ الان همه‌چیز فقط از «تنظیمات سرور ← سرویس IP» و فقط برای
    # ادمین در دسترس است. امکانات: انتقال یک یا چند کاربر انتخابی، انتقال همهٔ کاربران، و یک
    # حالت «انجام خودکار» که فشار CPU/RAM سرور را می‌سنجد و در صورت نیاز خودش تصمیم می‌گیرد.
    # ==========================================
    elif d == "ipsvc_menu" and role == 'admin':
        context.user_data.pop('ipsvc_selected', None); context.user_data.pop('ipsvc_results', None)
        # 🆕 V89: اضافه کردن گزینههای تقسیم کاربران و سیستم فیلتر
        filter_enabled = await asyncio.to_thread(_db_get_filter_detect_enabled)
        filter_icon = "🟢" if filter_enabled else "🔴"
        filter_threshold = await asyncio.to_thread(_db_get_filter_detect_threshold)
        kb = [[InlineKeyboardButton("🔍 انتخاب و انتقال کاربر(ها)", callback_data="ipsvc_search")],
              [InlineKeyboardButton("👥 انتقال همهٔ کاربران", callback_data="ipsvc_allusers")],
              [InlineKeyboardButton("⚖️ تقسیم متوازن کاربران بین IPها (Round-Robin)", callback_data="ipsvc_distribute")],
              [InlineKeyboardButton("🤖 انجام خودکار (بر اساس فشار سرور)", callback_data="ipsvc_auto")],
              [InlineKeyboardButton("🛡 وضعیت و مسدودسازی IPها / 📡خرید سرور جدید(دستی)", callback_data="hp_menu")],
              [InlineKeyboardButton(f"{filter_icon} شناسایی خودکار فیلتر ({'\u0641\u0639\u0627\u0644' if filter_enabled else '\u063a\u06cc\u0631\u0641\u0639\u0627\u0644'}) — آستانه: {filter_threshold:.0f}\u066a", callback_data="ipsvc_filter_settings")],
              [InlineKeyboardButton("🔙 بازگشت", callback_data="srv_menu_back")]]
        await query.edit_message_text(
            "🌐 <b>سرویس IP</b>\n\n"
            "از این بخش می‌توانید هاستِ ثبت‌شده برای فاکتور/کد اتصال یک یا چند کاربر خاص، یا همهٔ "
            "کاربران را به یکی دیگر از IPهای «تنظیمات هاست» تغییر دهید.\n\n"
            "⚖️ <b>تقسیم متوازن (Round-Robin):</b> همهٔ کاربران فعال را به‌صورت متوازن بین تمام IPهای فعال تقسیم می‌کند.\n\n"
            "🤖 <b>انجام خودکار:</b> وضعیت لحظه‌ای CPU/RAM سرور را می‌سنجد و فقط در صورت وجود "
            "فشار، بخشی از کاربران تازه (۷ روز اخیر) را بی‌سروصدا به هاست دیگری منتقل می‌کند.\n\n"
            f"🛰 <b>پایش خودکار پس‌زمینه (بدون نیاز به فشردن دکمه):</b> ربات هر {IP_PRESSURE_CHECK_INTERVAL_SECONDS // 60} "
            f"دقیقه وضعیت سرور را می‌سنجد (با نمونه‌گیری ۳ ثانیه‌ای برای دقت بیشتر، نه یک لحظه‌ی آنی). "
            f"اگر CPU یا RAM از {IP_PRESSURE_WARN_PCT}٪ رد شود و این وضعیت در {IP_PRESSURE_CONFIRM_TICKS} بررسیِ "
            f"متوالی هم تکرار شود (یعنی واقعاً حداقل چند دقیقه ادامه‌دار بوده، نه یک اسپایک لحظه‌ای)، "
            f"ابتدا فقط یک هشدار برای شما ارسال می‌کند؛ اگر تا {IP_PRESSURE_AUTOBALANCE_AFTER_HOURS} ساعت بعد "
            f"همچنان فشار ادامه داشت، خودش بدون نیاز به تایید شما همهٔ کاربران را بین IPهای ثبت‌شده بالانس می‌کند.\n\n"
            f"🛡 <b>پایش خودکار در‌دسترس‌بودن IPها:</b> هر {HOST_HEALTH_CHECK_INTERVAL_SECONDS // 60} دقیقه هر IP با یک "
            f"تست اتصال ساده بررسی می‌شود. اگر {HOST_HEALTH_FAIL_THRESHOLD} بار متوالی پاسخ ندهد، خودش از لیست "
            f"IPهای فعال حذف می‌شود (بدون این‌که هیچ سروری نابود شود) و به شما اطلاع می‌دهد. جزئیات و مسدودسازی "
            f"دستی از دکمهٔ «🛡 وضعیت و مسدودسازی IPها».",
            reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")

    elif d == "hp_menu" and role == 'admin':
        await _render_host_pool_panel(query)

    elif d.startswith("hpblk_") and role == 'admin':
        host = d[len("hpblk_"):]
        active_now = await asyncio.to_thread(_db_get_active_hosts_from_pool)
        if len(active_now) <= 1:
            await query.message.reply_text("⛔️ این تنها IP فعال شماست؛ اول یک IP دیگر اضافه کنید تا فاکتورسازی متوقف نشود."); return
        await asyncio.to_thread(_db_set_host_active, host, False, "مسدودسازی دستی توسط ادمین")
        await asyncio.to_thread(_db_rebuild_hosts_from_pool)
        remaining_active = await asyncio.to_thread(_db_get_active_hosts_from_pool)
        if remaining_active:
            await _cf_switch_public_domain(remaining_active[0], app=context.application)
        await query.message.reply_text(f"🚫 {host} غیرفعال شد.")
        await _render_host_pool_panel(query)

    elif d.startswith("hpact_") and role == 'admin':
        host = d[len("hpact_"):]
        stored_port = await asyncio.to_thread(_db_get_host_ssh_port, host, 22)
        await query.answer("⏳ در حال تست اتصال...", show_alert=False)

        # 🐛🔧 رفع باگ: قبلاً این تست فقط دقیقاً همون پورتِ ذخیره‌شده در دیتابیس رو امتحان
        # می‌کرد. اگه پورت واقعیِ سرور (مثلاً بعد از یک تغییر دستی یا یک «تغییر پورت» که موفق
        # شده ولی دیتابیس رو هماهنگ نکرده بود) با مقدار ذخیره‌شده فرق داشت، این تست همیشه شکست
        # می‌خورد و دکمه هیچ‌وقت IP رو فعال نمی‌کرد — حتی وقتی سرور کاملاً سالم و در دسترس بود.
        # الان اگه پورت ذخیره‌شده جواب نداد، پورت پیش‌فرض ۲۲ و پورت سراسریِ ربات رو هم امتحان
        # می‌کنه؛ اگه هرکدوم جواب داد، هم IP رو فعال می‌کنه هم دیتابیس رو با پورت واقعی هماهنگ.
        global_port = _normalize_ssh_port(await asyncio.to_thread(_db_get_setting, 'port', '2252'), 8443)
        candidate_ports = [stored_port] + [p for p in (22, global_port) if p != stored_port]

        working_port = None
        last_err = None
        t0 = time.monotonic()
        for cp in candidate_ports:
            ok, err = await _tcp_health_check(host, cp)
            if ok:
                working_port = cp
                break
            last_err = err

        if working_port is not None:
            await asyncio.to_thread(_db_record_host_latency, host, (time.monotonic() - t0) * 1000)
            await asyncio.to_thread(_db_set_host_active, host, True)
            if working_port != stored_port:
                await asyncio.to_thread(_db_set_host_ssh_port, host, working_port)
                await asyncio.to_thread(_db_rebuild_hosts_from_pool)
                await query.message.reply_text(
                    f"✅ {host} سالم است و دوباره فعال شد.\n"
                    f"⚠️ توجه: پورت واقعی <code>{working_port}</code> بود، نه <code>{stored_port}</code> که در دیتابیس ثبت شده بود — "
                    f"دیتابیس خودکار هماهنگ شد.", parse_mode="HTML")
            else:
                await asyncio.to_thread(_db_rebuild_hosts_from_pool)
                await query.message.reply_text(f"✅ {host} سالم است و دوباره فعال شد.")
        else:
            tried = ", ".join(str(p) for p in candidate_ports)
            await query.message.reply_text(f"❌ همچنان پاسخ نمی‌دهد (پورت‌های امتحان‌شده: {tried}): {last_err}")
        await _render_host_pool_panel(query)

    elif d.startswith("hpdelconfirm_") and role == 'admin':
        host = d[len("hpdelconfirm_"):]
        active_now = await asyncio.to_thread(_db_get_active_hosts_from_pool)
        if host in active_now and len(active_now) <= 1:
            await query.answer("⛔️ این تنها IP فعال شماست؛ حذف نمی‌شود.", show_alert=True); return
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("✅ بله، کاملاً حذف کن", callback_data=f"hpdelyes_{host}"),
                                     InlineKeyboardButton("❌ انصراف", callback_data="hp_menu")]])
        await query.edit_message_text(
            f"⚠️ <b>حذف کامل {esc(host)}</b>\n\n"
            f"این کار هم ردیف این IP را از دیتابیس ربات پاک می‌کند، هم (اگر این IP یک Edge با تونل WireGuard بود) "
            f"Peer متناظرش را از wg0.conf همین Core و از رابط زندهٔ WireGuard حذف می‌کند — یعنی دیگر هیچ ترافیکی "
            f"از این سرور به Core راه پیدا نمی‌کند.\n\n"
            f"ℹ️ خودِ VPS همچنان روشن/فعال می‌ماند (اگر دیگر لازمش ندارید، باید جدا از پیش این سرویس‌دهنده‌اش کنسل/حذفش کنید).\n\n"
            f"مطمئنید؟",
            parse_mode="HTML", reply_markup=kb)
    elif d.startswith("hpdelyes_") and role == 'admin':
        host = d[len("hpdelyes_"):]
        active_now = await asyncio.to_thread(_db_get_active_hosts_from_pool)
        if host in active_now and len(active_now) <= 1:
            await query.answer("⛔️ این تنها IP فعال شماست؛ حذف نمی‌شود.", show_alert=True); return
        was_default = await asyncio.to_thread(_db_get_default_host)
        wg_ok, wg_msg = await asyncio.to_thread(_remove_edge_wg_peer_sync, host)
        await asyncio.to_thread(_db_remove_host_pool, host)
        await asyncio.to_thread(_db_rebuild_hosts_from_pool)
        note = ""
        if was_default == host:
            # 🆕 اگر همین IP پیش‌فرض کل سیستم بود، بعد از حذفش دیگر هیچ پیش‌فرضی نمانده — یکی از
            # بقیهٔ IPهای فعال (اگر باشد) خودکار جایگزین می‌شود تا سیستم بدون پیش‌فرض نماند.
            remaining_active = await asyncio.to_thread(_db_get_active_hosts_from_pool)
            if remaining_active:
                await asyncio.to_thread(_db_set_default_host, remaining_active[0])
                note = f"\n⭐ چون این IP پیش‌فرض سیستم بود، حالا <code>{esc(remaining_active[0])}</code> پیش‌فرض جدید شد."
        await query.edit_message_text(f"🗑 {esc(host)} کاملاً حذف شد.\n{esc(wg_msg)}{note}", parse_mode="HTML")
        await _render_host_pool_panel(query)

    elif d == "hp_speedtest_all" and role == 'admin':
        # 🆕 V89 — تست سرعت همه IPها به‌صورت یکجا
        await query.edit_message_text(
            "⏳ <b>در حال تست سرعت همه IPها...</b>\n\n"
            f"تعداد نمونه برای هر IP: {IP_SPEED_TEST_SAMPLES} بار\n"
            "لطفاً چند ثانیه صبر کنید...",
            parse_mode="HTML")
        results = await _run_speed_test_all_hosts()
        if not results:
            await query.edit_message_text("❌ هیچ IP فعالی برای تست وجود ندارد.")
            return
        lines = []
        for i, (host, avg_ms, ok) in enumerate(results, 1):
            if ok and avg_ms is not None:
                medal = "🥇" if i == 1 else ("🥈" if i == 2 else ("🥉" if i == 3 else f"{i}."))
                lines.append(f"{medal} <code>{esc(host)}</code> — ⚡ {avg_ms:.0f}ms")
            else:
                lines.append(f"🔴 <code>{esc(host)}</code> — پاسخ نداد")
        fastest = results[0] if results and results[0][2] else None
        fastest_host = results[0][0] if fastest else None
        current_default = await asyncio.to_thread(_db_get_default_host)
        kb = []
        if fastest_host and fastest_host != current_default:
            kb.append([InlineKeyboardButton(
                f"🏆 پیش‌فرض سیستم = سریع‌ترین ({fastest_host})",
                callback_data=f"hpdef_{fastest_host}")])
        kb.append([InlineKeyboardButton("🔄 تست مجدد", callback_data="hp_speedtest_all")])
        kb.append([InlineKeyboardButton("🔙 بازگشت به وضعیت IPها", callback_data="hp_menu")])
        result_text = "\n".join(lines)
        summary = f"""
⚡ <b>نتیجهٔ تست سرعت IPها</b>

{result_text}

ℹ️ هرچه تاخیر کمتر باشد بهتر است. نتایج در دیتابیس ذخیره شدند.
اگر می‌خواهید سریع‌ترین IP را به‌عنوان پیش‌فرض کل سیستم تنظیم کنید، روی دکمهٔ زیر بزنید."""
        await query.edit_message_text(summary, reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
        return

    elif d == "hp_add" and role == 'admin':
        context.user_data['state'] = 'HOSTPOOL_ADD_INPUT'
        await query.message.reply_text("➕ آدرس/دامنهٔ IP جدید را بفرستید (بدون فاصله، فقط یک مورد):")
        return

    elif d == "hp_addedge":
        # 🔧 رفع باگ اصلی: چون بالای callback_handler همیشه یک‌بار await query.answer() خالی زده
        # می‌شود، هر تلاش دوم برای answer-کردن همان کوئری (حتی با show_alert=True) توسط تلگرام
        # نادیده گرفته می‌شود — API با 200 OK برمی‌گردد ولی هیچ popup ای به کاربر نشان داده
        # نمی‌شود (این خودِ چیزی بود که باعث می‌شد این دکمه کاملاً بی‌صدا به‌نظر برسد). به‌جایش از
        # query.message.reply_text استفاده می‌کنیم که یک پیام واقعی توی چت می‌فرستد و همیشه دیده می‌شود.
        try:
            if role != 'admin':
                await query.message.reply_text(f"⛔️ دسترسی نداری. role فعلی شما: {role!r}")
                return
            if paramiko is None:
                await query.message.reply_text("❌ کتابخانهٔ paramiko روی Core نصب نیست.")
                return
            context.user_data['state'] = 'EDGE_NEW_IP'
            await query.message.reply_text(
                "🚀 <b>افزودن خودکار Edge جدید</b>\n\n"
                "این کار یک VPS خام (که خودتان جداگانه خریده‌اید و فقط IP + رمز روتش را دارید) را "
                "به‌طور کامل به یک رلهٔ WireGuard تبدیل می‌کند: نصب، ساخت کلید، اتصال به Core، و افزودن "
                "خودکار به «سرویس IP» — بدون نیاز به ترمینال دستی.\n\n"
                "۱) آی‌پی عمومی سرور Edge جدید (خام و تازه‌خریداری‌شده) را بفرستید:",
                parse_mode="HTML")
        except Exception:
            log.exception("خطای غیرمنتظره در دکمهٔ hp_addedge")
            tb = traceback.format_exc()[-3000:]
            await query.message.reply_text(f"❌ <b>خطای داخلی هنگام باز کردن «افزودن Edge»:</b>\n\n<code>{esc(tb)}</code>", parse_mode="HTML")
        return

    elif d.startswith("hpdef_migrate_") and role == 'admin':
        host = d[len("hpdef_migrate_"):]
        active_now = await asyncio.to_thread(_db_get_active_hosts_from_pool)
        if host not in active_now:
            await query.message.reply_text("⛔️ این IP دیگر در لیست فعال نیست؛ عملیات لغو شد."); return
        kb = [[InlineKeyboardButton("✅ بله، همهٔ کاربران فعلی هم منتقل شوند", callback_data=f"hpdefmig_yes_{host}"),
               InlineKeyboardButton("↩️ نه، فقط پیش‌فرض جدید کافیه", callback_data="hp_menu")]]
        await query.edit_message_text(
            f"⚠️ آیا مطمئنید می‌خواهید هاستِ <b>همهٔ</b> اکانت‌های موجود (نه فقط تازه‌ساخته‌ها) هم به "
            f"<code>{esc(host)}</code> تغییر کند؟\nاین کار روی فاکتور/کد اتصالی که هر کاربر قبلاً دریافت کرده هم اثر می‌گذارد.",
            reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")

    elif d.startswith("hpdefmig_yes_") and role == 'admin':
        host = d[len("hpdefmig_yes_"):]
        # 🐛🔧 همان گاردِ بالا اینجا هم لازم است — این دکمه دقیقاً همان قدمی است که در عمل باعث
        # قطع‌شدن کاربران واقعی می‌شود (چون host همهٔ اکانت‌های موجود را عوض می‌کند)، پس حتی اگر
        # مرحلهٔ «پیش‌فرض‌کردن» زودتر رد شده باشد، اینجا هم دوباره و مستقل چک می‌کنیم — چون ممکن
        # است بین آن مرحله و این تایید نهایی، فاصله زمانی افتاده و وضعیت IP عوض شده باشد.
        port_to_check = await asyncio.to_thread(_db_get_host_ssh_port, host, 22)
        reachable, reach_detail = await _check_ssh_reachable(host, port_to_check)
        if not reachable:
            await query.message.reply_text(
                f"⛔️ <b>انتقال انجام نشد.</b>\n\n"
                f"دوباره یک اتصال SSH واقعی به <code>{esc(host)}:{port_to_check}</code> امتحان شد و جواب نداد:\n"
                f"<code>{esc(reach_detail)}</code>\n\n"
                f"اگر همهٔ کاربران به این IP منتقل می‌شدند، دقیقاً همه قطع می‌شدند — برای همین این عملیات متوقف شد.",
                parse_mode="HTML")
            return
        await asyncio.to_thread(_db_set_all_accounts_host, host)
        await asyncio.to_thread(_db_mark_ip_switch_now)  # 🆕 شروع دورهٔ خنک‌شدن برای پایش خودکار
        cf_ok, cf_msg = await _update_cloudflare_dns(host)
        cf_suffix = f"\n\n☁️ <b>وضعیت کلودفلر:</b> {cf_msg}" if cf_ok else f"\n\n⚠️ <b>هشدار کلودفلر:</b> {cf_msg}"
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت به سرویس IP", callback_data="ipsvc_menu")]])
        await query.edit_message_text(f"✅ اتصال SSH زنده تأیید شد و هاستِ همهٔ اکانت‌های موجود به <code>{esc(host)}</code> منتقل شد." + cf_suffix, reply_markup=kb, parse_mode="HTML")

    elif d.startswith("hpdef_") and role == 'admin':
        host = d[len("hpdef_"):]
        active_now = await asyncio.to_thread(_db_get_active_hosts_from_pool)
        if host not in active_now:
            await query.message.reply_text("⛔️ فقط یک IP فعال می‌تواند پیش‌فرض شود؛ اول آن را فعال کنید."); return

        # 🐛🔧 رفع باگ واقعی: قبلاً اینجا بدون هیچ چکی، IP به‌عنوان پیش‌فرض ثبت و آمادهٔ انتقال
        # همهٔ کاربران می‌شد، حتی اگر سرویس SSH واقعی رویش هنوز درست بالا نیامده باشد (مثلاً درست
        # همان مشکلی که با ssh.socket پیش آمد: پورت توی دیتابیس یک چیز بود، پورت واقعی گوش‌داده‌شده
        # چیز دیگر). نتیجه: انتقال کور به یک IP که واقعاً آماده نیست و قطعی کامل کاربران. الان قبل
        # از هرچیز، با یک چک سبک (بدون نیاز به رمز) مطمئن می‌شویم واقعاً یک SSH زنده آن‌جا هست.
        port_to_check = await asyncio.to_thread(_db_get_host_ssh_port, host, 22)
        reachable, reach_detail = await _check_ssh_reachable(host, port_to_check)
        if not reachable:
            await query.message.reply_text(
                f"⛔️ <b>پیش‌فرض نشد.</b>\n\n"
                f"قبل از پیش‌فرض‌کردن، یک اتصال SSH واقعی به <code>{esc(host)}:{port_to_check}</code> امتحان شد و جواب نداد:\n"
                f"<code>{esc(reach_detail)}</code>\n\n"
                f"اگر این IP تازه اضافه شده، اول مطمئن شوید SSH رویش کامل بالا آمده (و پورت ثبت‌شده در "
                f"«سرویس IP» با پورت واقعی سرور یکی است)، بعد دوباره امتحان کنید.",
                parse_mode="HTML")
            return

        await asyncio.to_thread(_db_set_default_host, host)
        await asyncio.to_thread(_db_rebuild_hosts_from_pool)
        await asyncio.to_thread(_db_mark_ip_switch_now)  # 🆕 شروع دورهٔ خنک‌شدن برای پایش خودکار
        # 🆕 قبلاً فقط اکانت‌های تازه/فاکتورهای بدون هاست مشخص را تحت‌تاثیر قرار می‌داد؛ حالا صراحتاً
        # می‌پرسد آیا اکانت‌های موجود هم به همین IP جدید منتقل شوند («کل کاربران منتقل شوند»).
        kb = [[InlineKeyboardButton("👥 بله، اکانت‌های موجود هم به این IP منتقل شوند", callback_data=f"hpdef_migrate_{host}")],
              [InlineKeyboardButton("🔙 بازگشت به سرویس IP", callback_data="ipsvc_menu")]]
        await query.edit_message_text(
            f"⭐ <code>{esc(host)}</code> به‌عنوان پیش‌فرض کل سیستم ثبت شد (اتصال SSH زنده هم تأیید شد ✅)؛ از این پس اکانت‌های جدید و هر "
            f"فاکتور بدون هاست مشخص، اول همین IP را نشان می‌دهند.\n\n"
            f"می‌خواهید هاستِ اکانت‌های <b>از قبل ساخته‌شده</b> هم به همین IP جدید منتقل شود؟",
            reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")

    # 🗑 حذف‌شده: خریدِ خودکارِ VPS از DigitalOcean + خریدِ دستی/مدیریتِ سرورهای Cloudzy.
    # طبقِ معماریِ جدید، افزودنِ Edge فقط دستی (🚀 افزودن Edge جدید) و Failover فقط با
    # سرورهای Standbyِ از‌قبل‌ثبت‌شده در host_pool انجام می‌شود.

    # 🆕 علامت‌گذاری/برداشتنِ Standby (بندِ ۴) — این Edge عمداً بدونِ مشتریِ فعال نگه داشته
    # می‌شود تا در Failover دستی/خودکار جایگزینِ یک Edgeِ فیلترشده شود.
    elif d.startswith("hpstandby_") and role == 'admin':
        host = d[len("hpstandby_"):]
        pool = await asyncio.to_thread(_db_get_host_pool)
        current = next((r[10] for r in pool if r[0] == host), 0)
        await asyncio.to_thread(_db_set_host_standby, host, not current)
        await query.answer("✅ به‌روزرسانی شد.", show_alert=False)
        await _render_host_pool_panel(query)

    # 🆕 روشن/خاموش‌کردنِ حالتِ خودکارِ Failover (بندِ ۴)
    elif d == "hp_failover_toggle" and role == 'admin':
        current = (await asyncio.to_thread(_db_get_setting, 'auto_failover_mode', '0')) == '1'
        await asyncio.to_thread(_db_update_setting, 'auto_failover_mode', '0' if current else '1')
        await query.answer("✅ به‌روزرسانی شد.", show_alert=False)
        await _render_host_pool_panel(query)

    # 🆕 فعال‌سازیِ دستیِ یک Standبی مشخص (دکمه‌ای که در پیامِ هشدارِ فیلترشدن به ادمین نشان
    # داده می‌شود، وقتی auto_failover_mode خاموش است)
    elif d.startswith("standby_act_") and role == 'admin':
        _, _, rest = d.partition("standby_act_")
        filtered_host, _, target_host = rest.partition("_")
        await query.edit_message_text(
            f"⏳ در حالِ بازسازیِ کاربرانِ <code>{esc(filtered_host)}</code> روی <code>{esc(target_host)}</code>...",
            parse_mode="HTML")
        spawn_bg_task(_activate_standby_for_filtered_edge(
            app=context.application, filtered_host=filtered_host, target_host=target_host))

    elif d.startswith("hpdns_") and role == 'admin':
        host = d[len("hpdns_"):]
        cf_cfg = await asyncio.to_thread(_cf_get_config)
        if not _cf_configured(cf_cfg):
            await query.message.reply_text("⚠️ اول باید تنظیمات Cloudflare را از «🌍 دامنهٔ ثابت + Cloudflare» کامل کنید.")
            return
        await query.answer("⏳ در حال سوییچ دامنه...", show_alert=False)
        ok, err = await asyncio.to_thread(_cf_update_dns_record_sync, host)
        if ok:
            await query.message.reply_text(f"✅ دامنه اکنون به {host} اشاره می‌کند.")
        else:
            await query.message.reply_text(f"❌ خطا: {err}")
        await _render_host_pool_panel(query)

    elif d == "hp_cf_settings" and role == 'admin':
        try:
            cf_cfg = await asyncio.to_thread(_cf_get_config)
            # 🐛🔧 رفع باگ: این پنل قبلاً به کلیدهای قدیمی cf_api_token/cf_zone_id/cf_record_id
            # دسترسی داشت که در نسخهٔ یکپارچه‌شدهٔ _cf_get_config دیگر وجود ندارند (الان token/zone
            # هستند و record_id اصلاً حذف شده چون رکورد به‌طور خودکار پیدا می‌شود) — همین KeyError
            # بی‌صدا باعث می‌شد کل دکمه هیچ واکنشی نشان ندهد.
            masked_token = (cf_cfg['token'][:6] + "…") if cf_cfg['token'] else "تنظیم نشده"
            kb = InlineKeyboardMarkup([
                [InlineKeyboardButton("✏️ دامنهٔ ثابت", callback_data="hp_cf_set_domain")],
                [InlineKeyboardButton("✏️ Cloudflare API Token", callback_data="hp_cf_set_token")],
                [InlineKeyboardButton("✏️ Zone ID", callback_data="hp_cf_set_zone")],
                [InlineKeyboardButton("🔙 بازگشت", callback_data="hp_menu")],
            ])
            await query.edit_message_text(
                "🌍 <b>دامنهٔ ثابت + Cloudflare</b>\n\n"
                "این تنظیمات باعث می‌شود کدهای نپسترنت مشتریان به‌جای IP خام، یک دامنهٔ ثابت داشته باشند. "
                "وقتی یک IP فیلتر/قطع شود، ربات خودکار (یا شما دستی) رکورد DNS همین دامنه را به IP سالم بعدی "
                "سوییچ می‌کند — بدون این‌که مشتری هیچ کد جدیدی نیاز داشته باشد. رکورد A دامنه به‌طور خودکار "
                "پیدا می‌شود، نیازی به تنظیم دستی Record ID نیست.\n\n"
                f"دامنهٔ فعلی: <code>{esc(cf_cfg['public_domain'] or 'تنظیم نشده')}</code>\n"
                f"Zone: <code>{esc(cf_cfg['zone'] or 'تنظیم نشده')}</code>\n"
                f"API Token: <code>{esc(masked_token)}</code>\n"
                f"IP فعلیِ سوییچ‌شده: <code>{esc(cf_cfg['dns_current_ip'] or 'هنوز سوییچی انجام نشده')}</code>\n\n"
                "⚠️ رکورد A این دامنه در Cloudflare باید روی حالت DNS only (ابر خاکستری) باشد، نه Proxied.",
                reply_markup=kb, parse_mode="HTML")
        except Exception:
            log.exception("خطای غیرمنتظره در پنل تنظیمات Cloudflare")
            tb = traceback.format_exc()[-3000:]
            await query.message.reply_text(f"❌ <b>خطای داخلی در باز کردن تنظیمات Cloudflare:</b>\n\n<code>{esc(tb)}</code>", parse_mode="HTML")

    elif d == "hp_cf_set_domain" and role == 'admin':
        context.user_data['state'] = 'CF_DOMAIN_INPUT'
        await query.message.reply_text("✍️ دامنهٔ ثابت را بفرستید (مثال: N1.nvlsup.com):")
    elif d == "hp_cf_set_token" and role == 'admin':
        context.user_data['state'] = 'CF_TOKEN_INPUT'
        await query.message.reply_text("✍️ Cloudflare API Token را بفرستید (با دسترسی Zone.DNS Edit):")
    elif d == "hp_cf_set_zone" and role == 'admin':
        context.user_data['state'] = 'CF_ZONE_INPUT'
        await query.message.reply_text("✍️ Zone ID را بفرستید:")
    elif d == "hp_cf_set_record" and role == 'admin':
        context.user_data['state'] = 'CF_RECORD_INPUT'
        await query.message.reply_text("✍️ Record ID رکورد A مربوط به دامنهٔ ثابت را بفرستید:")

    # 🐛🔧 رفع دوبارهٔ همان باگ قبلی (که ظاهراً در این نسخه دوباره برگشته بود): خط «elif» این
    # بلوک جا افتاده بود، پس این ۳ خط به‌اشتباه همیشه داخل بلوکِ «hp_cf_set_record» (بالا) هم
    # اجرا می‌شدند — یعنی با هر بار زدن دکمهٔ تنظیم Record ID کلادفلر، وضعیت/پیام اشتباه این‌جا
    # (مربوط به جستجوی کاربر) رونویسی می‌شد، و هم‌زمان دکمهٔ «🔍 انتخاب و انتقال کاربر(ها)»
    # (callback_data="ipsvc_search") اصلاً هیچ هندلری نداشت و کلیک روش هیچ اتفاقی نمی‌افتاد.
    elif d == "ipsvc_search" and role == 'admin':
        context.user_data['state'] = 'IPSVC_SEARCH_INPUT'
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="ipsvc_menu")]])
        await query.edit_message_text("🔍 بخشی از نام کاربری را بفرستید؛ برای دیدن همهٔ کاربران، فقط عدد 0 را بفرستید:", reply_markup=kb)

    elif d.startswith("ipsel_") and role == 'admin':
        selected = context.user_data.setdefault('ipsvc_selected', set())
        results = context.user_data.get('ipsvc_results', [])
        action = d[len("ipsel_"):]
        if action == "all":
            selected.update(results)
        elif action == "clear":
            selected.clear()
        elif action == "go":
            if not selected:
                await query.message.reply_text("❌ هنوز هیچ کاربری انتخاب نکرده‌اید."); return
            hl = [h.strip() for h in (await asyncio.to_thread(_db_get_setting, 'hosts', LAST_RESORT_HOST_IP)).split(',') if h.strip()]
            if len(hl) < 2:
                kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="ipsvc_menu")]])
                await query.edit_message_text("❌ حداقل باید ۲ هاست در «تنظیمات هاست» ثبت شده باشد.", reply_markup=kb); return
            context.user_data['ipsvc_hosts'] = hl
            rows = [[InlineKeyboardButton(h, callback_data=f"iphost_{i}")] for i, h in enumerate(hl)]
            rows.append([InlineKeyboardButton("🔙 بازگشت", callback_data="ipsvc_search")])
            names = "، ".join(esc(u) for u in sorted(selected))
            await query.edit_message_text(f"👥 کاربران انتخاب‌شده ({len(selected)}):\n{names}\n\n🌐 هاست مقصد را انتخاب کنید:", reply_markup=InlineKeyboardMarkup(rows), parse_mode="HTML")
            return
        else:
            un = action
            if un in selected: selected.discard(un)
            else: selected.add(un)
        rows = [[InlineKeyboardButton(("✅ " if u in selected else "⬜️ ") + u, callback_data=f"ipsel_{u}")] for u in results]
        rows.append([InlineKeyboardButton("☑️ انتخاب همه", callback_data="ipsel_all"), InlineKeyboardButton("🔲 پاک‌کردن انتخاب", callback_data="ipsel_clear")])
        rows.append([InlineKeyboardButton(f"▶️ ادامه ({len(selected)} انتخاب‌شده)", callback_data="ipsel_go")])
        rows.append([InlineKeyboardButton("🔙 بازگشت", callback_data="ipsvc_menu")])
        await query.edit_message_text("🔍 نتایج جستجو — روی هرکدام بزنید تا انتخاب/لغو شود:", reply_markup=InlineKeyboardMarkup(rows))

    elif d.startswith("iphost_") and role == 'admin':
        hl = context.user_data.get('ipsvc_hosts', [])
        selected = context.user_data.get('ipsvc_selected', set())
        idx_str = d[len("iphost_"):]
        if not idx_str.isdigit() or int(idx_str) >= len(hl) or not selected:
            await query.message.reply_text("❌ درخواست نامعتبر یا منقضی‌شده؛ دوباره از «سرویس IP» شروع کنید."); return
        new_host = hl[int(idx_str)]
        await asyncio.to_thread(_db_set_hosts_bulk, list(selected), new_host)
        n = len(selected)
        context.user_data.pop('ipsvc_selected', None); context.user_data.pop('ipsvc_results', None); context.user_data.pop('ipsvc_hosts', None)
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت به سرویس IP", callback_data="ipsvc_menu")]])
        await query.edit_message_text(f"✅ {n} اکانت با موفقیت به هاست <code>{esc(new_host)}</code> منتقل شدند.", reply_markup=kb, parse_mode="HTML")

    elif d == "ipsvc_allusers" and role == 'admin':
        hl = [h.strip() for h in (await asyncio.to_thread(_db_get_setting, 'hosts', LAST_RESORT_HOST_IP)).split(',') if h.strip()]
        if len(hl) < 2:
            kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="ipsvc_menu")]])
            await query.edit_message_text("❌ حداقل باید ۲ هاست در «تنظیمات هاست» ثبت شده باشد.", reply_markup=kb); return
        context.user_data['ipsvc_hosts'] = hl
        rows = [[InlineKeyboardButton(h, callback_data=f"ipallhost_{i}")] for i, h in enumerate(hl)]
        rows.append([InlineKeyboardButton("🔙 بازگشت", callback_data="ipsvc_menu")])
        await query.edit_message_text("⚠️ هاست مقصد برای <b>همهٔ</b> کاربران سرور را انتخاب کنید:", reply_markup=InlineKeyboardMarkup(rows), parse_mode="HTML")

    elif d.startswith("ipallhost_") and role == 'admin':
        hl = context.user_data.get('ipsvc_hosts', [])
        idx_str = d[len("ipallhost_"):]
        if not idx_str.isdigit() or int(idx_str) >= len(hl):
            await query.message.reply_text("❌ درخواست نامعتبر یا منقضی‌شده؛ دوباره تلاش کنید."); return
        new_host = hl[int(idx_str)]
        kb = [[InlineKeyboardButton("✅ بله، همه منتقل شوند", callback_data=f"ipallconf_yes_{idx_str}"), InlineKeyboardButton("↩️ خیر، انصراف", callback_data="ipsvc_menu")]]
        await query.edit_message_text(f"⚠️ آیا مطمئنید می‌خواهید هاستِ <b>همهٔ</b> کاربران سرور به <code>{esc(new_host)}</code> تغییر کند؟", reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")

    elif d.startswith("ipallconf_yes_") and role == 'admin':
        hl = context.user_data.get('ipsvc_hosts', [])
        idx_str = d[len("ipallconf_yes_"):]
        if not idx_str.isdigit() or int(idx_str) >= len(hl):
            await query.message.reply_text("❌ درخواست منقضی‌شده؛ دوباره تلاش کنید."); return
        new_host = hl[int(idx_str)]
        await asyncio.to_thread(_db_set_all_accounts_host, new_host)
        cf_ok, cf_msg = await _update_cloudflare_dns(new_host)
        cf_suffix = f"\n\n☁️ <b>وضعیت کلودفلر:</b> {cf_msg}" if cf_ok else f"\n\n⚠️ <b>هشدار کلودفلر:</b> {cf_msg}"
        context.user_data.pop('ipsvc_hosts', None)
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت به سرویس IP", callback_data="ipsvc_menu")]])
        await query.edit_message_text(f"✅ هاست همهٔ کاربران به <code>{esc(new_host)}</code> تغییر کرد." + cf_suffix, reply_markup=kb, parse_mode="HTML")

    elif d == "ipsvc_auto" and role == 'admin':
        await query.edit_message_text("⏳ در حال بررسی وضعیت سرور و انتقال خودکار در صورت نیاز...")
        health, note, moved = await _run_ip_service_auto_migrate()
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="ipsvc_menu")]])
        if not health:
            await query.edit_message_text(f"❌ خطا در بررسی وضعیت سرور:\n{esc(note)}", reply_markup=kb); return
        head = f"🖥 CPU: {health['cpu_pct']}٪ | RAM: {health['ram_pct']}٪ | Load: {health['load1']}\n\n"
        if not moved:
            await query.edit_message_text(head + f"ℹ️ {esc(note)}", reply_markup=kb, parse_mode="HTML"); return
        lines = "\n".join(f"• {esc(u)} → <code>{esc(h)}</code>" for u, h in moved)
        await query.edit_message_text(
            head + f"⚠️ سرور زیر فشار بود؛ {len(moved)} اکانت تازه به‌صورت خودکار منتقل شدند:\n{lines}\n\n"
                   f"ℹ️ فقط هاستِ ثبت‌شده برای فاکتور/کد اتصالِ بعدیِ این کاربران عوض شد؛ نیازی به اطلاع‌رسانی به آن‌ها نیست.",
            reply_markup=kb, parse_mode="HTML")

    # ==========================================
    # 🆕 V89 — تقسیم متوازن کاربران بین IPها (Round-Robin)
    # ==========================================
    elif d == "ipsvc_distribute" and role == 'admin':
        pool = await asyncio.to_thread(_db_get_host_pool)
        active_hosts = [r[0] for r in pool if r[1]]
        if len(active_hosts) < 2:
            kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="ipsvc_menu")]])
            await query.edit_message_text("❌ حداقل باید ۲ IP فعال برای تقسیم وجود داشته باشد.", reply_markup=kb)
            return
        hosts_text = "\n".join(f"• <code>{esc(h)}</code>" for h in active_hosts)
        kb = [
            [InlineKeyboardButton("✅ بله، تقسیم متوازن انجام شود", callback_data="ipsvc_distribute_confirm")],
            [InlineKeyboardButton("↩️ خیر، انصراف", callback_data="ipsvc_menu")]
        ]
        await query.edit_message_text(
            f"⚖️ <b>تقسیم متوازن کاربران (Round-Robin)</b>\n\n"
            f"همهٔ کاربران فعال بین {len(active_hosts)} IP فعال به‌صورت متوازن تقسیم می‌شوند:\n{hosts_text}\n\n"
            f"⚠️ این عملیات هاست ثبت‌شده در فاکتور/کد اتصال تمام کاربران را تغییر می‌دهد.\n"
            f"آیا مطمئنید?",
            reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")

    elif d == "ipsvc_distribute_confirm" and role == 'admin':
        pool = await asyncio.to_thread(_db_get_host_pool)
        active_hosts = [r[0] for r in pool if r[1]]
        if len(active_hosts) < 2:
            await query.edit_message_text("❌ حداقل باید ۲ IP فعال برای تقسیم وجود داشته باشد.")
            return
        await query.edit_message_text("⏳ در حال تقسیم کاربران بین IPها...")
        # دریافت تمام کاربران فعال
        all_accounts = await asyncio.to_thread(_db_get_all_active_accounts_with_host)
        if not all_accounts:
            kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="ipsvc_menu")]])
            await query.edit_message_text("❌ هیچ کاربر فعالی وجود ندارد.", reply_markup=kb)
            return
        # Round-Robin: تقسیم متوازن بین IPها
        assignments = {}
        for i, (username, _) in enumerate(all_accounts):
            host = active_hosts[i % len(active_hosts)]
            assignments[username] = host
        # اعمال تغییرات در دیتابیس
        def _apply_distribution():
            with db_conn() as conn:
                for username, host in assignments.items():
                    conn.execute("UPDATE ssh_accounts SET host=? WHERE username=?", (host, username))
        await asyncio.to_thread(_apply_distribution)
        # آمار توزیع
        host_counts = {}
        for h in assignments.values():
            host_counts[h] = host_counts.get(h, 0) + 1
        stats_lines = "\n".join(f"• <code>{esc(h)}</code>: {c} کاربر" for h, c in sorted(host_counts.items(), key=lambda x: -x[1]))
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت به سرویس IP", callback_data="ipsvc_menu")]])
        await query.edit_message_text(
            f"✅ <b>تقسیم متوازن انجام شد</b>\n\n"
            f"👥 تعداد کل کاربران: {len(assignments)}\n\n"
            f"📊 توزیع بین IPها:\n{stats_lines}\n\n"
            f"ℹ️ هاست ثبت‌شده در فاکتور/کد اتصال بعدی هر کاربر تغییر کرد.",
            reply_markup=kb, parse_mode="HTML")

    # ==========================================
    # 🆕 V89 — تنظیمات سیستم شناسایی خودکار فیلتر
    # ==========================================
    elif d == "ipsvc_filter_settings" and role == 'admin':
        enabled = await asyncio.to_thread(_db_get_filter_detect_enabled)
        threshold = await asyncio.to_thread(_db_get_filter_detect_threshold)
        status_icon = "🟢" if enabled else "🔴"
        status_text = "فعال" if enabled else "غیرفعال"
        toggle_text = "❌ غیرفعال کردن" if enabled else "✅ فعال کردن"
        toggle_cb = "ipsvc_filter_disable" if enabled else "ipsvc_filter_enable"
        kb = [
            [InlineKeyboardButton(toggle_text, callback_data=toggle_cb)],
            [InlineKeyboardButton("⚙️ تغییر آستانه (فعلی: {:.0f}\u066a)".format(threshold), callback_data="ipsvc_filter_threshold")],
            [InlineKeyboardButton("🔙 بازگشت", callback_data="ipsvc_menu")]
        ]
        await query.edit_message_text(
            f"🛡 <b>سیستم شناسایی خودکار فیلتر</b>\n\n"
            f"{status_icon} وضعیت: <b>{status_text}</b>\n"
            f"📊 آستانه تشخیص فیلتر: <b>{threshold:.0f}\u066a</b> از کاربران فعال\n\n"
            f"📝 <b>نحوهٔ کار:</b>\n"
            f"• هر {FILTER_DETECT_CHECK_INTERVAL_SECONDS // 60} دقیقه یک‌بار تعداد کاربران آنلاین چک می‌شود.\n"
            f"• اگر {FILTER_DETECT_CONFIRM_TICKS} بار متوالی زیر آستانه بودند → IP فیلتر تشخیص داده می‌شود.\n"
            f"• سیستم خودکار به سریع‌ترین IP فعال تغییر می‌کند.\n"
            f"• حداقل {FILTER_DETECT_MIN_ACTIVE_ACCOUNTS} کاربر فعال برای فعال‌شدن سیستم لازم است.\n\n"
            f"⚠️ بعد از تشخیص فیلتر، همهٔ کاربران به سریع‌ترین IP موجود منتقل می‌شوند و به ادمین اطلاع داده می‌شود.",
            reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")

    elif d == "ipsvc_filter_enable" and role == 'admin':
        await asyncio.to_thread(_db_set_filter_detect_enabled, True)
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="ipsvc_filter_settings")]])
        await query.edit_message_text(f"✅ سیستم شناسایی خودکار فیلتر <b>فعال</b> شد.\n\nربات هر {FILTER_DETECT_CHECK_INTERVAL_SECONDS // 60} دقیقه یک‌بار تعداد کاربران آنلاین را بررسی می‌کند.", reply_markup=kb, parse_mode="HTML")

    elif d == "ipsvc_filter_disable" and role == 'admin':
        await asyncio.to_thread(_db_set_filter_detect_enabled, False)
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="ipsvc_filter_settings")]])
        await query.edit_message_text("❌ سیستم شناسایی خودکار فیلتر <b>غیرفعال</b> شد.", reply_markup=kb, parse_mode="HTML")

    elif d == "ipsvc_filter_threshold" and role == 'admin':
        context.user_data['state'] = 'FILTER_THRESHOLD_INPUT'
        threshold = await asyncio.to_thread(_db_get_filter_detect_threshold)
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="ipsvc_filter_settings")]])
        await query.edit_message_text(
            f"⚙️ <b>تغییر آستانه فیلتر</b>\n\n"
            f"آستانه فعلی: <b>{threshold:.0f}\u066a</b>\n\n"
            f"عدد درصد جدید را بفرستید (\u06f1 تا \u06f9\u06f9):\n"
            f"مثال: 5 یعنی اگر کمتر از \u06f5\u066a کاربران آنلاین باشند → فیلتر تشخیص داده می‌شود",
            reply_markup=kb, parse_mode="HTML")

    # ==========================================
    # 🌍 مدیریت دامنه‌ها (فقط ادمین)
    # ==========================================
    elif d == "dom_menu" and role == 'admin':
        kb = [[InlineKeyboardButton("➕ افزودن دامنه", callback_data="dom_add")],
              [InlineKeyboardButton("📋 لیست دامنه‌ها", callback_data="dom_list")],
              [InlineKeyboardButton("🔙 بازگشت", callback_data="srv_menu_back")]]
        await query.edit_message_text("🌍 <b>مدیریت دامنه‌ها</b>", reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
    elif d == "dom_add" and role == 'admin':
        context.user_data['state'] = 'DOM_ADD_NAME'
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="dom_menu")]])
        await query.edit_message_text("✍️ نام دامنه را بفرستید (مثال: example.com):", reply_markup=kb)
    elif d == "dom_list" and role == 'admin':
        doms = await asyncio.to_thread(_db_get_domains)
        if not doms:
            kb = InlineKeyboardMarkup([[InlineKeyboardButton("➕ افزودن دامنه", callback_data="dom_add")], [InlineKeyboardButton("🔙 بازگشت", callback_data="dom_menu")]])
            await query.edit_message_text("📭 هنوز هیچ دامنه‌ای ثبت نشده.", reply_markup=kb); return
        rows = [[InlineKeyboardButton(f"🌍 {dm[1]}", callback_data=f"dom_view_{dm[0]}")] for dm in doms]
        rows.append([InlineKeyboardButton("🔙 بازگشت", callback_data="dom_menu")])
        await query.edit_message_text("📋 لیست دامنه‌های ثبت‌شده:", reply_markup=InlineKeyboardMarkup(rows))
    elif d.startswith("dom_view_") and role == 'admin':
        did = int(d.split("_")[2])
        info = await asyncio.to_thread(_db_get_domain, did)
        if not info: await query.edit_message_text("❌ این دامنه دیگر وجود ندارد."); return
        domain, host, reg_date, expire_date, notes = info
        exp_line = f"{esc(expire_date)} | ({get_remaining_days(expire_date)})" if expire_date else "ثبت‌نشده"
        txt = (f"🌍 دامنه: <code>{esc(domain)}</code>\n🌐 هاست/مقصد: {esc(host) if host else 'ثبت‌نشده'}\n"
               f"📅 تاریخ ثبت: {esc(reg_date) if reg_date else 'ثبت‌نشده'}\n⏳ تاریخ انقضا: {exp_line}\n"
               f"📝 یادداشت: {esc(notes) if notes else '-'}")
        kb = [[InlineKeyboardButton("🗑 حذف دامنه", callback_data=f"dom_del_{did}")], [InlineKeyboardButton("🔙 بازگشت", callback_data="dom_list")]]
        await query.edit_message_text(txt, reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
    elif d.startswith("dom_del_") and role == 'admin':
        did = int(d.split("_")[2])
        kb = [[InlineKeyboardButton("✅ بله، حذف شود", callback_data=f"domdelconf_yes_{did}"), InlineKeyboardButton("↩️ خیر، انصراف", callback_data=f"dom_view_{did}")]]
        await query.edit_message_text("⚠️ آیا از حذف این دامنه مطمئنید؟", reply_markup=InlineKeyboardMarkup(kb))
    elif d.startswith("domdelconf_yes_") and role == 'admin':
        did = int(d.split("_", 2)[2])
        await asyncio.to_thread(_db_delete_domain, did)
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت به لیست", callback_data="dom_list")]])
        await query.edit_message_text("✅ دامنه حذف شد.", reply_markup=kb)

    elif d.startswith("uact_ni_") or d.startswith("uact_niinv_"):
        from_invoice = d.startswith("uact_niinv_")
        un = d.split("_", 2)[2]
        r = await asyncio.to_thread(_db_get_user, un)
        if not r: return await query.message.reply_text("❌ این کاربر دیگر وجود ندارد.")
        if not _can_manage_user(role, ag_id, r[5]): return await query.message.reply_text("⛔️ شما مجاز به مشاهده این اکانت نیستید.")
        p, _, _, _, _, _, acc_host, acc_conn_mode = r
        prt = await asyncio.to_thread(_db_get_setting, 'port', '22')
        hl = [h.strip() for h in (await asyncio.to_thread(_db_get_setting, 'hosts', LAST_RESORT_HOST_IP)).split(',') if h.strip()]
        primary_host = acc_host if acc_host else (hl[0] if hl else _hosts_fallback_with_warning())
        link = await _build_napsternet_link(primary_host, prt, un, p, acc_conn_mode or 'direct')
        out = f"🔗 <b>لینک اتصال (روی کد لمس کنید تا کپی شود):</b>\n\n<code>{link}</code>"
        # 🔧 رفع باگ ناوبری (دور دوم): «بازگشت» باید به همان نوع پیامی برگردد که دکمهٔ نپسترنت
        # رویش بود، نه همیشه به یک قالب ثابت. اگر این دکمه زیر فاکتورِ اکانتِ تازه‌ساخته‌شده (تکی یا
        # دسته‌ای؛ قالب host/username/password/port) بود، بازگشت باید همان فاکتور را دوباره بسازد؛
        # اگر زیر پنل «جزئیات اکانت» در مدیریت کاربران بود (قالب مالک/تعداد کاربر/وضعیت/اتصال)،
        # بازگشت باید به همان پنل برود — این حالت دوم از قبل درست کار می‌کرد و تغییری نکرده.
        back_cb = f"uact_invview_{un}" if from_invoice else f"udet_{un}"
        back_kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data=back_cb)]])
        # 🔧 رفع باگ ناوبری: قبلاً با reply_text یک پیام کاملاً جدید در انتهای چت ارسال می‌شد و از
        # همان پیام/دکمه‌ای که رویش کلیک شده بود فاصله می‌گرفت. حالا همان پیام (چه پنل جزئیات
        # اکانت باشد، چه فاکتور تکی/دسته‌ای) مستقیماً ویرایش می‌شود تا کد دقیقاً همان‌جا ظاهر شود؛
        # اگر پیام قابل ویرایش نبود (مثلاً خیلی قدیمی بود)، به‌صورت پشتیبان پیام جدید ارسال می‌شود.
        try:
            await query.edit_message_text(out, parse_mode="HTML", reply_markup=back_kb)
        except Exception:
            await query.message.reply_text(out, parse_mode="HTML", reply_markup=back_kb)

    # 🆕 «بازگشت» از کد نپسترنتِ یک فاکتورِ تازه‌ساخته‌شده — همان فاکتور را از روی دیتابیس فعلی
    # دوباره می‌سازد و دقیقاً با همان دکمهٔ نپسترنتِ نوع «فاکتور» (نه نوع «پنل مدیریت») نمایش می‌دهد.
    elif d.startswith("uact_invview_"):
        un = d.split("_", 2)[2]
        r = await asyncio.to_thread(_db_get_user, un)
        if not r: return await query.edit_message_text("❌ این کاربر دیگر وجود ندارد.")
        if not _can_manage_user(role, ag_id, r[5]): return await query.message.reply_text("⛔️ شما مجاز به مشاهده این اکانت نیستید.")
        out = await _build_invoice_text(un)
        if out is None: return await query.edit_message_text("❌ این کاربر دیگر وجود ندارد.")
        inv_kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔗 دریافت کد نپسترنت (قابل کپی)", callback_data=f"uact_niinv_{un}")]])
        await query.edit_message_text(out, reply_markup=inv_kb, parse_mode="HTML")

    # 🧾 ارسال مجدد فاکتور کامل — همیشه در دسترس، چون از روی دیتابیس فعلی ساخته می‌شود.
    # 🔧 رفع باگ ناوبری (مشابه دکمهٔ «دریافت کد نپسترنت»): قبلاً با reply_text یک پیام کاملاً
    # جدید در انتهای چت ارسال می‌شد و کاربر برای دیدنش باید صفحه را پایین می‌برد. حالا همان پیامِ
    # پنل «جزئیات کاربر» مستقیماً ویرایش می‌شود تا فاکتور دقیقاً همان‌جا ظاهر شود، به‌همراه دکمهٔ
    # «بازگشت» به همان پنل؛ اگر پیام قابل ویرایش نبود (مثلاً خیلی قدیمی بود)، به‌صورت پشتیبان پیام
    # جدید ارسال می‌شود.
    elif d.startswith("uact_inv_"):
        un = d.split("_", 2)[2]
        r = await asyncio.to_thread(_db_get_user, un)
        if not r: return await query.edit_message_text("❌ این کاربر دیگر وجود ندارد.")
        if not _can_manage_user(role, ag_id, r[5]): return await query.message.reply_text("⛔️ شما مجاز به مشاهده این اکانت نیستید.")
        inv = await _build_invoice_text(un)
        if inv is None: return await query.edit_message_text("❌ این کاربر دیگر وجود ندارد.")
        back_kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data=f"udet_{un}")]])
        try:
            await query.edit_message_text(inv, parse_mode="HTML", reply_markup=back_kb)
        except Exception:
            await query.message.reply_text(inv, parse_mode="HTML", reply_markup=back_kb)

    # 📜 تاریخچهٔ اتصالات — آخرین ورود همیشه ردیف اول است (last خروجی را از جدید به قدیم می‌دهد)
    # 🆕 حالا کاملاً فارسی/شمسی نمایش داده می‌شود (هم برای ادمین، هم برای نماینده)، اولین و
    # آخرین اتصالِ موجود در لاگ + تعداد کل اتصالات را هم نشان می‌دهد، و یک دکمهٔ «نمودار» دارد.
    elif d.startswith("uact_hist_"):
        un = d.split("_", 2)[2]
        cur = await asyncio.to_thread(_db_get_user, un)
        if not cur: return await _safe_edit_or_send(query, "❌ این کاربر دیگر وجود ندارد.")
        if not _can_manage_user(role, ag_id, cur[5]): return await query.message.reply_text("⛔️ شما مجاز به مشاهده این اکانت نیستید.")
        await _safe_edit_or_send(query, "⏳ در حال خواندن تاریخچهٔ اتصالات از سرور...")
        # 🔧 برای اینکه «اولین اتصال» و «تعداد کل» معنادار باشند، تا ۲۰۰ رکورد آخر (نه فقط ۸ تا)
        # از wtmp خوانده می‌شود؛ فقط ۱۰ تای اول در متن نمایش داده می‌شوند، بقیه فقط برای آمار.
        lines, herr = await _get_connection_history(un, n=200)
        # 🗑 دکمه‌های «نمودار اتصالات» (تصویر ثابت) و «نمودار زنده» (که گیج‌کننده بودند) حذف شدند.
        # 🎬 طبق درخواست بعدی، به‌جایشان یک نسخهٔ «انیمیشنی» (GIF) اضافه شد که خودش را می‌کشد/رشد
        # می‌دهد — یک نمایش یک‌باره و روشن، نه پایشِ زندهٔ پیوسته که قبلاً گیج‌کننده بود.
        kb_rows = [[InlineKeyboardButton("🔄 بروزرسانی", callback_data=f"uact_hist_{un}")]]
        if ANIMATION_AVAILABLE:
            kb_rows.append([InlineKeyboardButton("🎬 نمودار انیمیشنی", callback_data=f"uact_histanim_{un}")])
        kb_rows.append([InlineKeyboardButton("🔙 بازگشت", callback_data=f"udet_{un}")])
        kb = InlineKeyboardMarkup(kb_rows)
        if herr:
            await _safe_edit_or_send(query,
                f"❌ خطا در خواندن تاریخچهٔ اتصالات:\n<code>{esc(herr)}</code>\n\n"
                f"🔧 اگر پیام بالا دربارهٔ رمز/دسترسی sudo است، این خط را هم به sudoers کاربر ربات اضافه کنید:\n"
                f"<code>NOPASSWD: /usr/bin/journalctl</code>",
                parse_mode="HTML", reply_markup=kb)
            return
        if not lines:
            await _safe_edit_or_send(query,
                f"📜 <b>تاریخچهٔ اتصالات اکانت {esc(un)}</b>\n\n"
                f"هیچ اتصال موفقی برای این یوزرنیم در لاگ sshd پیدا نشد — یعنی این اکانت هنوز واقعاً "
                f"با هیچ کلاینتی وارد نشده. (این بخش دیگر از wtmp/دستور last نمی‌خواند، بلکه مستقیم "
                f"لاگ sshd را پارس می‌کند، پس محدودیت قبلیِ دراپبیر/بدون-pty دیگر وجود ندارد.)",
                parse_mode="HTML", reply_markup=kb)
            return
        context.user_data[f'hist_records_{un}'] = None  # پاک‌سازی کش قبلی همین یوزر (اگر بود)
        records = _parse_last_lines(lines)
        if not records:
            await _safe_edit_or_send(query,
                f"📜 <b>تاریخچهٔ اتصالات اکانت {esc(un)}</b>\n\n"
                f"خروجی سرور خوانده شد ولی هیچ رکورد قابل‌تفسیری در آن پیدا نشد.",
                parse_mode="HTML", reply_markup=kb)
            return
        context.user_data[f'hist_records_{un}'] = records  # برای استفادهٔ دکمهٔ نمودار انیمیشنی (بدون خواندن دوبارهٔ سرور)
        last_record = records[0]          # آخرین اتصال (چون last از جدید به قدیم می‌دهد)
        first_record = records[-1]        # قدیمی‌ترین اتصالِ موجود در همین بازهٔ خوانده‌شده
        rows_txt = []
        for r in records[:10]:
            login_fa = fmt_jalali_datetime(r['login'])
            if r['still_active']:
                status = "🟢 هنوز متصل است"
            elif r['logout']:
                dur = r['logout'] - r['login']
                total_min = int(dur.total_seconds() // 60)
                status = f"⏱ مدت اتصال: {fa_digits(total_min // 60)} ساعت و {fa_digits(total_min % 60)} دقیقه"
            else:
                status = "⚪️ مدت نامشخص (قطع غیرمنتظره)"
            rows_txt.append(f"🔸 {login_fa}\n   {status}")
        body = "\n\n".join(rows_txt)
        summary = (
            f"📊 <b>تعداد کل اتصالات ثبت‌شده در لاگ:</b> {fa_digits(len(records))}\n"
            f"🟢 <b>آخرین اتصال:</b> {fmt_jalali_datetime(last_record['login'])}\n"
            f"🕰 <b>اولین اتصالِ موجود در لاگ:</b> {fmt_jalali_datetime(first_record['login'])}\n"
        )
        await _safe_edit_or_send(query,
            f"📜 <b>تاریخچهٔ اتصالات اکانت {esc(un)}</b>\n\n{summary}\n"
            f"— — — — — — — — — —\n\n{body}",
            parse_mode="HTML", reply_markup=kb)

    # 🎬 نمودار انیمیشنی (GIF) — از رکوردهای همان لحظهٔ «تاریخچهٔ اتصالات» (کش‌شده) استفاده می‌کند؛
    # اگر کش موجود نبود (مثلاً بعد از ری‌استارت ربات)، دوباره از سرور می‌خواند.
    elif d.startswith("uact_histanim_"):
        un = d.split("_", 2)[2]
        cur = await asyncio.to_thread(_db_get_user, un)
        if not cur: return await _safe_edit_or_send(query, "❌ این کاربر دیگر وجود ندارد.")
        if not _can_manage_user(role, ag_id, cur[5]): return await query.message.reply_text("⛔️ شما مجاز به مشاهده این اکانت نیستید.")
        if not ANIMATION_AVAILABLE: return await query.message.reply_text("⚠️ ماژول ساخت GIF روی سرور نصب نیست.")
        await query.answer("⏳ در حال ساخت انیمیشن... (چند ثانیه طول می‌کشد)")
        records = context.user_data.get(f'hist_records_{un}')
        if not records:
            lines, herr = await _get_connection_history(un, n=200)
            if herr or not lines:
                return await query.message.reply_text("❌ رکورد اتصالی برای رسم نمودار یافت نشد.")
            records = _parse_last_lines(lines)
        if not records:
            return await query.message.reply_text("❌ رکورد اتصالی برای رسم نمودار یافت نشد.")
        buf = await asyncio.to_thread(_generate_connection_history_animation_buffer, un, records)
        if buf is None:
            return await query.message.reply_text("❌ ساخت انیمیشن ناموفق بود.")
        back_kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت به تاریخچه", callback_data=f"uact_hist_{un}")]])
        await query.message.reply_animation(
            animation=InputFile(buf, filename=f"{un}_connections.gif"),
            caption=f"🎬 <b>نمودار انیمیشنی اتصالات اکانت {esc(un)}</b>\nتعداد کل: {fa_digits(len(records))} اتصال",
            parse_mode="HTML", reply_markup=back_kb)

    # 📈 کدِ نمودار ثابت/زندهٔ قدیمی (uact_histchart_ / uact_livechart_*) از اینجا به بعد فقط
    # به‌عنوان بازمانده (بی‌ضرر و دست‌نخورده) باقی مانده؛ دیگر هیچ دکمه‌ای به آن‌ها اشاره نمی‌کند —
    # دکمهٔ نمودار ثابت با نسخهٔ انیمیشنیِ بالا جایگزین شد و دکمهٔ نمودار زنده کلاً حذف شد.
    elif d.startswith("uact_histchart_"):
        un = d.split("_", 2)[2]
        cur = await asyncio.to_thread(_db_get_user, un)
        if not cur: return await query.edit_message_text("❌ این کاربر دیگر وجود ندارد.")
        if not _can_manage_user(role, ag_id, cur[5]): return await query.message.reply_text("⛔️ شما مجاز به مشاهده این اکانت نیستید.")
        if not MATPLOTLIB_AVAILABLE: return await query.message.reply_text("⚠️ ماژول رسم نمودار روی سرور نصب نیست.")
        await query.answer("⏳ در حال ساخت نمودار...")
        records = context.user_data.get(f'hist_records_{un}')
        if not records:
            lines, herr = await _get_connection_history(un, n=200)
            if herr or not lines:
                return await query.message.reply_text("❌ رکورد اتصالی برای رسم نمودار یافت نشد.")
            records = _parse_last_lines(lines)
        if not records:
            return await query.message.reply_text("❌ رکورد اتصالی برای رسم نمودار یافت نشد.")
        buf = await asyncio.to_thread(_generate_connection_history_chart_buffer, un, records)
        if buf is None:
            return await query.message.reply_text("❌ ساخت نمودار ناموفق بود.")
        back_kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت به تاریخچه", callback_data=f"uact_hist_{un}")]])
        await query.message.reply_photo(
            photo=InputFile(buf, filename=f"{un}_connections.png"),
            caption=f"📈 <b>نمودار اتصالات اکانت {esc(un)}</b>\nتعداد کل: {fa_digits(len(records))} اتصال",
            parse_mode="HTML", reply_markup=back_kb)

    # ⏹ توقف «نمودار زنده» — چون پیشوند این کالبک‌دیتا ادامهٔ پیشوند «uact_livechart_» است،
    # حتماً باید در elif‌چین قبل از آن چک شود، وگرنه هیچ‌وقت به این شاخه نمی‌رسد.
    elif d.startswith("uact_livechart_stop_"):
        un = d.split("uact_livechart_stop_", 1)[1]
        tasks_map = context.application.bot_data.get('live_chart_tasks', {})
        key = (query.message.chat_id, query.message.message_id)
        task = tasks_map.get(key)
        if task and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        stop_kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("▶️ شروع دوباره", callback_data=f"uact_livechart_{un}")],
            [InlineKeyboardButton("🔙 بازگشت به تاریخچه", callback_data=f"uact_hist_{un}")]])
        with contextlib.suppress(Exception):
            await query.edit_message_caption(caption=f"⏹ پایش زندهٔ اکانت {esc(un)} متوقف شد.", parse_mode="HTML", reply_markup=stop_kb)
        await query.answer("⏹ پایش زنده متوقف شد.")

    # 🔴 نمودار «زنده»: نمودار را می‌فرستد و بعد یک تسک پس‌زمینه (فقط برای همین یک پیام) راه‌اندازی
    # می‌کند که هر LIVE_CHART_INTERVAL_SECONDS ثانیه خودکار همان عکس را با داده‌های تازه جایگزین می‌کند.
    elif d.startswith("uact_livechart_"):
        un = d.split("_", 2)[2]
        cur = await asyncio.to_thread(_db_get_user, un)
        if not cur: return await query.edit_message_text("❌ این کاربر دیگر وجود ندارد.")
        if not _can_manage_user(role, ag_id, cur[5]): return await query.message.reply_text("⛔️ شما مجاز به مشاهده این اکانت نیستید.")
        if not MATPLOTLIB_AVAILABLE: return await query.message.reply_text("⚠️ ماژول رسم نمودار روی سرور نصب نیست.")
        await query.answer("⏳ در حال شروع پایش زنده...")
        lines, herr = await _get_connection_history(un, n=200)
        if herr or not lines:
            return await query.message.reply_text("❌ رکورد اتصالی برای رسم نمودار یافت نشد.")
        records = _parse_last_lines(lines)
        if not records:
            return await query.message.reply_text("❌ رکورد اتصالی برای رسم نمودار یافت نشد.")
        buf = await asyncio.to_thread(_generate_connection_history_chart_buffer, un, records)
        if buf is None:
            return await query.message.reply_text("❌ ساخت نمودار ناموفق بود.")
        stop_kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("⏹ توقف پایش زنده", callback_data=f"uact_livechart_stop_{un}")],
            [InlineKeyboardButton("🔙 بازگشت به تاریخچه", callback_data=f"uact_hist_{un}")]])
        sent = await query.message.reply_photo(
            photo=InputFile(buf, filename=f"{un}_connections_live.png"),
            caption=(f"📈🔴 <b>نمودار زندهٔ اتصالات اکانت {esc(un)}</b>\n"
                     f"تعداد کل: {fa_digits(len(records))} اتصال | شروع شد: {datetime.now().strftime('%H:%M:%S')}\n"
                     f"(هر {LIVE_CHART_INTERVAL_SECONDS} ثانیه خودکار بروزرسانی می‌شود)"),
            parse_mode="HTML", reply_markup=stop_kb)
        tasks_map = context.application.bot_data.setdefault('live_chart_tasks', {})
        key = (sent.chat_id, sent.message_id)
        old_task = tasks_map.get(key)
        if old_task and not old_task.done():
            old_task.cancel()  # 🛡️ احتیاطی: اگر به هر دلیلی تسک قبلی برای همین پیام هنوز زنده بود
        tasks_map[key] = asyncio.create_task(_live_chart_loop(context.application, sent.chat_id, sent.message_id, un))

    # 🔄 تمدید اکانت
    elif d.startswith("uact_rn_"):
        un = d.split("_", 2)[2]
        cur = await asyncio.to_thread(_db_get_user, un)
        if not cur: return await query.edit_message_text("❌ این کاربر دیگر وجود ندارد.")
        if not _can_manage_user(role, ag_id, cur[5]): return await query.message.reply_text("⛔️ شما مجاز به مدیریت این اکانت نیستید.")
        
        # ⛔️ توقف تمدید برای اکانت‌های TLS قدیمی
        if cur[7] == 'tls':
            kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data=f"udet_{un}")]])
            return await query.edit_message_text(
                f"⛔️ <b>تمدید غیرمجاز</b>\n\n"
                f"کاربر گرامی، ارائه و تمدید سرویس‌های <b>TLS</b> به‌طور کامل متوقف شده است و این اکانت دیگر قابل تمدید نیست.\n\n"
                f"🌟 سرویس پایدار و پرسرعت <b>V2Ray</b> جایگزین این سرویس شده است. لطفاً پس از اتمام اعتبار، برای کاربران خود از منوی اصلی اقدام به تهیه اشتراک V2Ray نمایید.",
                reply_markup=kb, parse_mode="HTML"
            )
            
        context.user_data['renew_target'] = un
        # 🔧 رفع باگ: قبلاً renew_mode اینجا صراحتاً به 'extend' ست نمی‌شد. اگر نماینده قبل‌ترِ
        # همین سشن یک‌بار وارد «کاهش تمدید» شده و بدون تکمیل/لغو (رفتن به همان udet_ به‌جای
        # rnyes/rnno) از آن خارج شده بود، مقدار قدیمیِ renew_mode='reduce' در context.user_data
        # باقی می‌ماند. مسیر ماه‌های آماده (rnm_) چون خودش صراحتاً mode='extend' پاس می‌دهد مشکلی
        # نداشت، ولی مسیر «تعداد روز دلخواه» (rnd_custom_) این مقدار را ست نمی‌کرد، پس این حالت
        # قدیمی را به ارث می‌برد و کل تمدید را به‌جای شارژ، به‌اشتباه به‌صورت «کاهش/بازگشت وجه»
        # اجرا می‌کرد — و چون گزینهٔ شارژ اضطراری فقط برای mode=='extend' چک می‌شود، برای حالت
        # کاستوم اصلاً نمایش داده نمی‌شد. الان اینجا هم مثل uact_rd_ صراحتاً ست می‌شود.
        context.user_data['renew_mode'] = 'extend'
        # 🆕 علاوه بر گزینه‌های آماده ۱/۲/۳ ماهه، یک گزینهٔ «تعداد روز دلخواه» هم اضافه شد تا
        # بشود اکانت را دقیقاً به‌اندازهٔ هر تعداد روز دلخواه (نه فقط ماه کامل) تمدید کرد.
        kb = [[InlineKeyboardButton(f"{i} ماهه", callback_data=f"rnm_{i}") for i in range(1, 4)],
              [InlineKeyboardButton("🔹 تعداد روز دلخواه", callback_data=f"rnd_custom_{un}")],
              [InlineKeyboardButton("🔙 بازگشت", callback_data=f"udet_{un}")]]
        await query.edit_message_text(f"🔄 تمدید اکانت {esc(un)}\n📅 چند ماه تمدید شود؟", reply_markup=InlineKeyboardMarkup(kb))
    elif d.startswith("rnd_custom_"):
        un = d.split("_", 2)[2]
        cur = await asyncio.to_thread(_db_get_user, un)
        if not cur: return await query.edit_message_text("❌ این کاربر دیگر وجود ندارد.")
        if not _can_manage_user(role, ag_id, cur[5]): return await query.message.reply_text("⛔️ شما مجاز به مدیریت این اکانت نیستید.")
        context.user_data['renew_target'] = un
        # 🔧 رفع همان باگ بالا در نقطهٔ ورودی خودِ حالت کاستوم — این خط اصلیِ رفع مشکل «شارژ
        # اضطراری برای تمدید با روز دلخواه اعمال نمی‌شود» است؛ صراحتاً و بدون وابستگی به اینکه
        # uact_rn_ زودتر صدا زده شده باشد یا نه، mode را 'extend' می‌کند.
        context.user_data['renew_mode'] = 'extend'
        context.user_data['state'] = 'RENEW_DAYS_INPUT'
        kb = [[InlineKeyboardButton("🔙 بازگشت", callback_data=f"udet_{un}")]]
        await query.edit_message_text(f"✍️ تعداد روزی که می‌خواهید اکانت {esc(un)} تمدید شود را بفرستید (فقط عدد صحیح مثبت):", reply_markup=InlineKeyboardMarkup(kb))
    elif d.startswith("rnm_"):
        months = int(d.split("_")[1])
        un = context.user_data.get('renew_target')
        if not un: return await query.message.reply_text("❌ تراکنش منقضی شده است.")
        cur = await asyncio.to_thread(_db_get_user, un)
        if not cur: return await query.edit_message_text("❌ این کاربر دیگر وجود ندارد.")
        if not _can_manage_user(role, ag_id, cur[5]): return await query.message.reply_text("⛔️ شما مجاز به مدیریت این اکانت نیستید.")
        # 🔧 برای اینکه یک مسیر واحد اجرا/تاییدیه هم برای «X ماهه» و هم برای «تعداد روز دلخواه»
        # استفاده شود، انتخاب ماهانه هم به تعداد روز معادل (ماه × ۳۰) تبدیل می‌شود.
        days = months * 30
        await _show_renew_confirm(query, context, un, days, f"{months} ماه", mode='extend')

    # 🔻 کاهش تمدید اکانت — برای مواقعی که اشتباهی اکانت بیش‌ازحد تمدید شده و باید تعداد
    # روز/ماه آن کم شود. دقیقاً همان منوی ۱/۲/۳ ماهه + «تعداد روز دلخواه» را نمایش می‌دهد،
    # اما در انتها به‌جای افزودن، از تاریخ انقضا کم می‌کند.
    elif d.startswith("uact_rd_") and role == 'admin':
        un = d.split("_", 2)[2]
        cur = await asyncio.to_thread(_db_get_user, un)
        if not cur: return await query.edit_message_text("❌ این کاربر دیگر وجود ندارد.")
        if not _can_manage_user(role, ag_id, cur[5]): return await query.message.reply_text("⛔️ شما مجاز به مدیریت این اکانت نیستید.")
        
        # ⛔️ توقف تغییرات زمانی برای اکانت‌های TLS قدیمی
        if cur[7] == 'tls':
            kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data=f"udet_{un}")]])
            return await query.edit_message_text(
                f"⛔️ <b>تغییر غیرمجاز</b>\n\n"
                f"سرویس‌های <b>TLS</b> از رده خارج شده‌اند و تغییر زمان (کاهش/تمدید) برای آن‌ها امکان‌پذیر نیست.",
                reply_markup=kb, parse_mode="HTML"
            )
            
        context.user_data['renew_target'] = un
        context.user_data['renew_mode'] = 'reduce'
        kb = [[InlineKeyboardButton(f"{i} ماهه", callback_data=f"rdm_{i}") for i in range(1, 4)],
              [InlineKeyboardButton("🔹 تعداد روز دلخواه", callback_data=f"rdd_custom_{un}")],
              [InlineKeyboardButton("🔙 بازگشت", callback_data=f"udet_{un}")]]
        await query.edit_message_text(f"🔻 کاهش تمدید اکانت {esc(un)}\n📅 چند ماه از انقضا کم شود؟", reply_markup=InlineKeyboardMarkup(kb))
    elif d.startswith("rdd_custom_"):
        un = d.split("_", 2)[2]
        cur = await asyncio.to_thread(_db_get_user, un)
        if not cur: return await query.edit_message_text("❌ این کاربر دیگر وجود ندارد.")
        if not _can_manage_user(role, ag_id, cur[5]): return await query.message.reply_text("⛔️ شما مجاز به مدیریت این اکانت نیستید.")
        context.user_data['renew_target'] = un
        context.user_data['renew_mode'] = 'reduce'
        context.user_data['state'] = 'RENEW_DAYS_INPUT'
        kb = [[InlineKeyboardButton("🔙 بازگشت", callback_data=f"udet_{un}")]]
        await query.edit_message_text(f"✍️ تعداد روزی که می‌خواهید از انقضای اکانت {esc(un)} کم شود را بفرستید (فقط عدد صحیح مثبت):", reply_markup=InlineKeyboardMarkup(kb))
    elif d.startswith("rdm_"):
        months = int(d.split("_")[1])
        un = context.user_data.get('renew_target')
        if not un: return await query.message.reply_text("❌ تراکنش منقضی شده است.")
        cur = await asyncio.to_thread(_db_get_user, un)
        if not cur: return await query.edit_message_text("❌ این کاربر دیگر وجود ندارد.")
        if not _can_manage_user(role, ag_id, cur[5]): return await query.message.reply_text("⛔️ شما مجاز به مدیریت این اکانت نیستید.")
        days = months * 30
        await _show_renew_confirm(query, context, un, days, f"{months} ماه", mode='reduce')
    elif d == "rnno":
        await query.edit_message_text("❌ عملیات لغو شد."); safe_clear_context(context)
    elif d in ("rnyes", "rnyes_emergency"):
        if d == "rnyes_emergency":
            context.user_data['emergency_approved'] = True
        days = context.user_data.get('renew_days')
        un = context.user_data.get('renew_target')
        mode = context.user_data.get('renew_mode', 'extend')  # 🆕 'extend' یا 'reduce'
        if not days or not un: return await query.message.reply_text("❌ تراکنش منقضی شده است.")
        cur = await asyncio.to_thread(_db_get_user, un)
        if not cur: return await query.edit_message_text("❌ این کاربر دیگر وجود ندارد.")
        if not _can_manage_user(role, ag_id, cur[5]): return await query.message.reply_text("⛔️ شما مجاز به مدیریت این اکانت نیستید.")

        try:
            cost = 0.0
            cost_dec = Decimal("0")
            if role == 'agent':
                ainf = await asyncio.to_thread(_db_get_agent_info, ag_id)
                if not ainf:
                    await query.edit_message_text("❌ خطا: اطلاعات نمایندگی شما یافت نشد."); safe_clear_context(context); return
                account_users_limit = cur[3]  # تعداد کاربر همزمان مجاز همین اکانت (در تمدید/کاهش تغییر نمی‌کند)
                base_price_dec = _parse_price_to_decimal(ainf[4])
                # 💵 هزینه/بازگشتِ متناسب با تعداد روز واقعی محاسبه می‌شود (نرخ پایه به‌صورت
                # ماهانه تعریف شده، پس به‌نسبت روز/۳۰ اعمال می‌شود).
                retail_dec = base_price_dec * (Decimal(days) / Decimal(30)) * Decimal(account_users_limit)
                # 🔧 رفع باگ مالی: مشابه بخش خرید اکانت جدید، دیگر هیچ درصد تخفیف/کمیسیونی از هزینهٔ
                # تمدید کسر نمی‌شود؛ هزینهٔ تمدید همیشه دقیقاً برابر قیمت پایه × (روز/۳۰) × تعداد کاربر است.
                cost_dec = retail_dec
                cost = float(cost_dec)
                if mode == 'extend' and ainf[2] < cost and not context.user_data.get('emergency_approved'):
                    has_opt, remaining_em, shortfall, used_em, req_cnt = _check_emergency_option(ainf, cost)
                    can_use_em, active_count = _agent_can_use_emergency_credit(ag_id)
                    if has_opt and can_use_em:
                        kb_em = InlineKeyboardMarkup([[InlineKeyboardButton("🆘 استفاده از شارژ اضطراری", callback_data="rnyes_emergency")],
                                                       [InlineKeyboardButton("↩️ انصراف", callback_data="rnno")]])
                        await query.edit_message_text(
                            f"❌ <b>موجودی ناکافی برای تمدید!</b>\n\n💰 موجودی شما: {int(ainf[2]):,} تومان\n💳 هزینه تمدید {days} روزه: {int(cost):,} تومان\n\n"
                            f"🆘 می‌توانید از <b>شارژ اضطراری</b> استفاده کنید (سقف کل: {int(EMERGENCY_CREDIT_LIMIT):,} تومان، "
                            f"باقی‌ماندهٔ شما: {int(remaining_em):,} تومان). این مبلغ در اولین شارژ بعدی حساب شما به‌طور خودکار کسر می‌شود.",
                            reply_markup=kb_em, parse_mode="HTML")
                        # 🔧 برخلاف حالت رد قطعی، اینجا context عمداً پاک نمی‌شود چون renew_target/renew_days
                        # برای اجرای واقعی بعد از کلیک روی «شارژ اضطراری» هنوز لازم هستند.
                        return
                    extra = ""
                    if req_cnt >= EMERGENCY_MAX_CONSECUTIVE_REQUESTS:
                        extra = "\n\n🆘 سقف درخواست‌های پیاپی شارژ اضطراری (۲ بار) شما پر شده؛ لطفاً منتظر شارژ حساب توسط مدیریت بمانید."
                    elif used_em > 0:
                        extra = f"\n\n🆘 شارژ اضطراری باقی‌ماندهٔ شما ({int(remaining_em):,} تومان) برای این تمدید کافی نیست."
                    await query.edit_message_text(f"❌ <b>موجودی ناکافی برای تمدید!</b>\n\n💰 موجودی شما: {int(ainf[2]):,} تومان\n💳 هزینه تمدید {days} روزه: {int(cost):,} تومان{extra}", parse_mode="HTML")
                    safe_clear_context(context); return

            _, old_exp, _, _, _, _, _, _ = cur
            try:
                base_dt = datetime.strptime(old_exp, "%Y-%m-%d")
                # 🔧 «اگر منقضی شده از امروز حساب کن» فقط برای تمدید معنا دارد؛ برای کاهش همیشه
                # باید از همان تاریخ انقضای فعلی کم شود.
                if mode == 'extend' and base_dt < datetime.now():
                    base_dt = datetime.now()
            except Exception:
                base_dt = datetime.now()

            signed_days = days if mode == 'extend' else -days
            new_exp_dt = base_dt + timedelta(days=signed_days)

            # 🛡 جلوگیری از کاهش بیش‌ازحد که باعث شود تاریخ انقضا به گذشته برود
            if mode == 'reduce' and new_exp_dt <= datetime.now():
                await query.edit_message_text(
                    f"❌ کاهش {days} روز باعث می‌شود انقضای اکانت به گذشته/امروز برود.\n"
                    f"📅 انقضای فعلی: {format_db_date_to_jalali(old_exp)}\nعدد کوچک‌تری وارد کنید.")
                safe_clear_context(context); return

            new_exp_db = new_exp_dt.strftime("%Y-%m-%d")

            # Linux lifecycle is Core-local; cur.host remains endpoint/routing metadata.

            # 🛠 Self-heal فقط برای تمدید: بعضی اکانت‌های منقضیِ قدیمی بعد از Migration در DB
            # باقی مانده‌اند ولی Linux user آن‌ها بازسازی نشده است. قبل از usermod، در صورت
            # نبودن user آن را از اطلاعات DB بازسازی می‌کنیم؛ مسیر «کاهش تمدید» عمداً user
            # مفقود را ایجاد نمی‌کند چون قرار نیست یک سرویس غیرفعال را احیا کند.
            if mode == 'extend':
                heal_ok, heal_err, heal_kind, _recreated = await _ensure_ssh_linux_user_for_renewal(
                    un, cur, new_exp_db
                )
                if not heal_ok:
                    await query.message.reply_text(
                        _fmt_linux_error("بازسازی خودکار اکانت برای تمدید", heal_err, heal_kind),
                        parse_mode="HTML"
                    )
                    safe_clear_context(context); return

            ok, err, kind = await run_cmd(
                "sudo", "usermod", "-e", new_exp_db, un
            )
            if not ok:
                await query.message.reply_text(_fmt_linux_error("تمدید اکانت" if mode == 'extend' else "کاهش تمدید اکانت", err, kind), parse_mode="HTML")
                safe_clear_context(context); return

            # فعال‌سازی خودکار اکانت در لینوکس (باز کردن قفل)
            if mode == 'extend':
                await run_cmd("sudo", "usermod", "-U", un)

            try:
                if mode == 'extend':
                    def _db_extend_and_activate():
                        with db_conn() as conn:
                            conn.execute("UPDATE ssh_accounts SET expire_date=?, hold_active=0, status='🟢 فعال' WHERE username=?", (new_exp_db, un))
                    await asyncio.to_thread(_db_extend_and_activate)
                else:
                    await asyncio.to_thread(_db_extend_user, un, new_exp_db)
            except Exception:
                log.exception("ثبت %s %s در دیتابیس شکست خورد؛ بازگردانی تاریخ انقضا روی لینوکس...", "کاهش تمدید" if mode == 'reduce' else "تمدید", un)
                await run_cmd("sudo", "usermod", "-e", old_exp, un)  # 🔙 Rollback
                await query.message.reply_text("❌ خطا در ثبت تغییرات در دیتابیس. تغییر روی سرور لینوکس نیز بازگردانده شد.")
                safe_clear_context(context); return

            if role == 'agent':
                if mode == 'extend':
                    with db_conn() as conn: conn.execute("UPDATE agents SET balance = balance - ? WHERE id=?", (cost, ag_id))
                    await asyncio.to_thread(_db_distribute_commission, ag_id, retail_dec)
                    # 🎁 کش‌بک ترغیبی نمایندگان پرفروش (۵۰+ اکانت فعال): ۷٪ از هزینهٔ همین تمدید
                    await _apply_agent_cashback_if_eligible(ag_id, retail_dec)
                    # 🆘 اگر این تمدید با کمک شارژ اضطراری تکمیل شد، مصرف ثبت و به ادمین‌ها اطلاع داده می‌شود
                    emergency_shortfall = max(0.0, cost - ainf[2])
                    if emergency_shortfall > 0:
                        await asyncio.to_thread(_db_agent_register_emergency_use, ag_id, emergency_shortfall)
                        with contextlib.suppress(Exception):
                            await _notify_admins(context.application,
                                f"🆘 <b>استفاده از شارژ اضطراری</b>\nنمایندهٔ «{esc(ainf[0])}» برای تمدید اکانت <code>{esc(un)}</code> "
                                f"مبلغ {int(emergency_shortfall):,} تومان از شارژ اضطراری استفاده کرد.")
                else:
                    # 💰 در حالت کاهش، مبلغ متناظر با روزهای کم‌شده به موجودی نماینده بازگردانده می‌شود
                    # (بدون دست‌کاری کمیسیون زیرمجموعه‌ها که قبلاً هنگام تمدید اشتباه پرداخت شده بود).
                    with db_conn() as conn: conn.execute("UPDATE agents SET balance = balance + ? WHERE id=?", (cost, ag_id))

            # 🆕 طبق درخواست: به‌جای یک پیام کوتاهِ «با موفقیت تمدید شد»، همان فاکتور/پنل کامل
            # اکانت (شبیه صفحهٔ جزئیات اکانت) نمایش داده می‌شود تا اطلاعات کامل (مالک، تعداد
            # کاربر، انقضای جدید، وضعیت و ...) یک‌جا دیده شود. خبر موفقیت به‌صورت toast می‌آید.
            toast = f"✅ تمدید اکانت {un} کاهش یافت." if mode == 'reduce' else f"✅ اکانت {un} با موفقیت تمدید شد."
            await query.answer(toast)
            
            try:
                actor = f"نماینده: {esc(ainf[0])}" if (role == 'agent' and ainf) else "ادمین"
                act_str = "تمدید زمان" if mode == 'extend' else "کاهش زمان"
                await _notify_super_admin(context.application, f"🔄 <b>{act_str} SSH</b>\nشخص: {actor}\nمیزان اعمال شده: {days} روز", tg_user=update.effective_user)
                await asyncio.to_thread(_db_log_activity, ag_id if role=='agent' else 0, un, mode, 'ssh', f"{days} روز", cost if role=='agent' else 0)
            except: pass
            
            safe_clear_context(context)
            await _show_user_detail(update, un, context)
        except Exception as e:
            # 💡 در اینجا ارور اصلی چاپ می‌شود
            log.exception("خطای غیرمنتظره در تمدید/کاهش اکانت")
            await query.message.reply_text(f"❌ خطا در انجام عملیات:\n<code>{esc(str(e))}</code>", parse_mode="HTML")
            safe_clear_context(context)

# 👑 پنل سوپر ادمین
    elif d == "super_admin_back" and update.effective_chat.id == SUPER_ADMIN_ID:
        kb = [[InlineKeyboardButton("📊 فعالیت‌های سیستم (ادمین)", callback_data="super_admin_stats")],
              [InlineKeyboardButton("💼 سوابق مالی نمایندگان", callback_data="super_agent_list")],
              [InlineKeyboardButton("⚙️ مدیریت فروش سرویس‌ها", callback_data="super_admin_sales_manage")],
              [InlineKeyboardButton("👥 مدیریت کاربران و ادمین‌های ربات", callback_data="super_admin_users_menu")],
              [InlineKeyboardButton("🔙 بستن", callback_data="uact_back_to_menu")]]
        await query.edit_message_text("👑 <b>پنل تنظیمات اختصاصی سوپر ادمین</b>\n\nبخش مورد نظر را انتخاب کنید:", reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")

    elif d == "super_admin_sales_manage" and update.effective_chat.id == SUPER_ADMIN_ID:
        ssh_en = await asyncio.to_thread(_db_get_setting, 'sell_ssh', '1') == '1'
        bulk_en = await asyncio.to_thread(_db_get_setting, 'sell_bulk', '1') == '1'
        v2_unlimit_en = await asyncio.to_thread(_db_get_setting, 'sell_v2ray_unlimit', '1') == '1'
        v2_vol_en = await asyncio.to_thread(_db_get_setting, 'sell_v2ray_vol', '1') == '1'
        kb = [
            [InlineKeyboardButton("🟢 فروش SSH (فعال)" if ssh_en else "🔴 فروش SSH (غیرفعال)", callback_data="tsell_ssh")],
            [InlineKeyboardButton("🟢 ساخت عمده SSH (فعال)" if bulk_en else "🔴 ساخت عمده SSH (غیرفعال)", callback_data="tsell_bulk")],
            [InlineKeyboardButton("🟢 فروش V2Ray نامحدود (فعال)" if v2_unlimit_en else "🔴 فروش V2Ray نامحدود (غیرفعال)", callback_data="tsell_v2ray_unlimit")],
            [InlineKeyboardButton("🟢 فروش V2Ray حجمی (فعال)" if v2_vol_en else "🔴 فروش V2Ray حجمی (غیرفعال)", callback_data="tsell_v2ray_vol")],
            [InlineKeyboardButton("🔙 بازگشت", callback_data="super_admin_back")]
        ]
        await query.edit_message_text("⚙️ <b>مدیریت فروش و ساخت سرویس‌ها</b>\n\nبا خاموش کردن هر بخش، دکمهٔ آن از منوی «🛒 خرید اشتراک» برای تمامی کاربران (ادمین و نماینده) پنهان می‌شود.", reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")

    elif d.startswith("tsell_") and update.effective_chat.id == SUPER_ADMIN_ID:
        target = d.split("tsell_")[1]
        key = f"sell_{target}"
        cur = await asyncio.to_thread(_db_get_setting, key, '1')
        new_val = '0' if cur == '1' else '1'
        await asyncio.to_thread(_db_update_setting, key, new_val)
        
        ssh_en = await asyncio.to_thread(_db_get_setting, 'sell_ssh', '1') == '1'
        bulk_en = await asyncio.to_thread(_db_get_setting, 'sell_bulk', '1') == '1'
        v2_unlimit_en = await asyncio.to_thread(_db_get_setting, 'sell_v2ray_unlimit', '1') == '1'
        v2_vol_en = await asyncio.to_thread(_db_get_setting, 'sell_v2ray_vol', '1') == '1'
        kb = [
            [InlineKeyboardButton("🟢 فروش SSH (فعال)" if ssh_en else "🔴 فروش SSH (غیرفعال)", callback_data="tsell_ssh")],
            [InlineKeyboardButton("🟢 ساخت عمده SSH (فعال)" if bulk_en else "🔴 ساخت عمده SSH (غیرفعال)", callback_data="tsell_bulk")],
            [InlineKeyboardButton("🟢 فروش V2Ray نامحدود (فعال)" if v2_unlimit_en else "🔴 فروش V2Ray نامحدود (غیرفعال)", callback_data="tsell_v2ray_unlimit")],
            [InlineKeyboardButton("🟢 فروش V2Ray حجمی (فعال)" if v2_vol_en else "🔴 فروش V2Ray حجمی (غیرفعال)", callback_data="tsell_v2ray_vol")],
            [InlineKeyboardButton("🔙 بازگشت", callback_data="super_admin_back")]
        ]
        await query.edit_message_reply_markup(reply_markup=InlineKeyboardMarkup(kb))

    elif d == "super_admin_stats" and update.effective_chat.id == SUPER_ADMIN_ID:
        cr_tdy, cr_yest, cr_wk, cr_mo, rn_tdy, rn_yest, rn_wk, rn_mo, rn_lmo = await asyncio.to_thread(_get_super_admin_stats, None)
        txt = (f"👑 <b>فعالیت‌های سیستم (توسط شخص ادمین)</b>\n\n"
               f"🆕 <b>ساخت اکانت:</b>\n"
               f"امروز: {cr_tdy} | دیروز: {cr_yest}\nاین هفته: {cr_wk} | این ماه (شمسی): {cr_mo}\n\n"
               f"🔄 <b>تمدید اکانت:</b>\n"
               f"امروز: {rn_tdy} | دیروز: {rn_yest}\nاین هفته: {rn_wk}\nاین ماه (شمسی): {rn_mo} | ماه گذشته: {rn_lmo}")
        kb = [[InlineKeyboardButton("🔙 بازگشت", callback_data="super_admin_back")]]
        await query.edit_message_text(txt, reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
        
    elif d == "super_agent_list" and update.effective_chat.id == SUPER_ADMIN_ID:
        agents = await asyncio.to_thread(_db_get_all_agents)
        if not agents: return await query.edit_message_text("نماینده‌ای یافت نشد.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="super_admin_back")]]))
        kb = [[InlineKeyboardButton(f"💼 {a[1]}", callback_data=f"super_agent_det_{a[0]}")] for a in agents]
        kb.append([InlineKeyboardButton("🔙 بازگشت", callback_data="super_admin_back")])
        await query.edit_message_text("👑 <b>سوابق مالی نمایندگان</b>\nنماینده مورد نظر را انتخاب کنید:", reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")
        
    elif d.startswith("super_agent_det_") and update.effective_chat.id == SUPER_ADMIN_ID:
        a_id = int(d.split("_")[3])
        info = await asyncio.to_thread(_db_get_agent_info, a_id)
        if not info: return await query.edit_message_text("نماینده یافت نشد.")
        s1, s2, s3, s6, r_this, r_last, receipts = await asyncio.to_thread(_get_super_admin_stats, a_id)
        
        try: ssh_bp = f"{int(str(info[4]).replace(',', '')):,}"
        except: ssh_bp = str(info[4])
        try: v2_bp = f"{int(str(info[16]).replace(',', '')):,}"
        except: v2_bp = str(info[16])
        try: v2_vol_bp = f"{int(str(info[17]).replace(',', '')):,}"
        except: v2_vol_bp = str(info[17])
        
        rec_txt = "\n".join(f"• 💰 {int(amt):,} تومان - {esc(dt)}" for amt, dt in receipts) if receipts else "هیچ واریزی بانکی یافت نشد."
        
        txt = (f"💼 <b>سوابق نماینده «{esc(info[0])}»</b>\n\n"
               f"💵 <b>قیمت‌های پایه ثبت شده:</b>\n"
               f"SSH: {ssh_bp} تومان\nV2Ray نامحدود: {v2_bp} تومان\nV2Ray حجمی (هر گیگ): {v2_vol_bp} تومان\n\n"
               f"📈 <b>سوابق فروش:</b>\n"
               f"۱ ماه گذشته: {s1}\n۲ ماه گذشته: {s2}\n۳ ماه گذشته: {s3}\n۶ ماه گذشته: {s6}\n\n"
               f"🔄 <b>سوابق تمدید:</b>\n"
               f"این ماه (شمسی): {r_this}\nماه گذشته (شمسی): {r_last}\n\n"
               f"💳 <b>۵ واریزی بانکی اخیر:</b>\n{rec_txt}")
        kb = [[InlineKeyboardButton("🔙 بازگشت به لیست", callback_data="super_agent_list")]]
        await query.edit_message_text(txt, reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")

    elif d == "super_admin_users_menu" and update.effective_chat.id == SUPER_ADMIN_ID:
        kb = [
            [InlineKeyboardButton("👮‍♂️ ادمین‌های ربات", callback_data="super_admin_list_admins")],
            [InlineKeyboardButton("💼 فروشنده‌های ربات", callback_data="super_admin_list_agents")],
            [InlineKeyboardButton("🔙 بازگشت", callback_data="super_admin_back")]
        ]
        await query.edit_message_text("👥 <b>مدیریت کاربران و ادمین‌های ربات</b>\n\nبخش مورد نظر را انتخاب کنید:", reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")

    elif d == "super_admin_list_admins" and update.effective_chat.id == SUPER_ADMIN_ID:
        await query.answer("⏳ در حال دریافت اطلاعات از تلگرام...", show_alert=False)
        active_ids = await asyncio.to_thread(_db_get_admin_chat_ids)
        historical_ids = await asyncio.to_thread(_db_get_historical_admin_chat_ids)
        historical_ids.add(SUPER_ADMIN_ID) # همیشه سوپر ادمین را نشان بده
        
        # 🆕 اضافه کردن حسابدارها به لیست نمایش
        for acc in ACCOUNTANT_IDS:
            historical_ids.add(acc)
        
        lines = ["👮‍♂️ <b>لیست تمام مدیران و حسابداران ربات:</b>\n"]
        for cid in historical_ids:
            # تشخیص نقش کاربر برای نمایش مرتب‌تر
            if cid == SUPER_ADMIN_ID:
                role_label = "👑 <b>سوپر ادمین</b>"
            elif cid in ACCOUNTANT_IDS:
                role_label = "📊 <b>حسابدار</b>"
            else:
                role_label = "🔹 <b>ادمین</b>"

            is_active = "🟢 (آنلاین)" if (cid in active_ids or cid == SUPER_ADMIN_ID or cid in ACCOUNTANT_IDS) else "🔴 (خارج شده)"
            
            if cid == SUPER_ADMIN_ID:
                lines.append(f"{role_label} {is_active}\nآیدی: <code>{cid}</code>")
            else:
                try:
                    chat = await context.bot.get_chat(cid)
                    name = chat.first_name or "بدون نام"
                    un = f"@{chat.username}" if chat.username else "بدون یوزرنیم"
                    lines.append(f"{role_label} | {esc(name)} {is_active}\nیوزرنیم: {un}\nآیدی: <code>{cid}</code>")
                except Exception:
                    lines.append(f"{role_label} | آیدی: <code>{cid}</code> {is_active} (عدم دسترسی)")
                    
        kb = [[InlineKeyboardButton("🔙 بازگشت", callback_data="super_admin_users_menu")]]
        full_text = "\n\n".join(lines)
        if len(full_text) > 3800:
            full_text = full_text[:3800] + "\n\n... (لیست به دلیل طولانی بودن برش خورد)"
        await query.edit_message_text(full_text, reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")

    elif d == "super_admin_list_agents" and update.effective_chat.id == SUPER_ADMIN_ID:
        await query.answer("⏳ در حال دریافت اطلاعات از تلگرام...", show_alert=False)
        def _get_all_agents_raw():
            with db_conn() as conn:
                return conn.execute("SELECT id, name, username, telegram_id FROM agents ORDER BY id").fetchall()
        
        agents = await asyncio.to_thread(_get_all_agents_raw)
        if not agents:
            await query.edit_message_text("هیچ فروشنده‌ای در دیتابیس ثبت نشده است.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 بازگشت", callback_data="super_admin_users_menu")]]))
            return
        
        lines = ["💼 <b>لیست فروشنده‌های ربات:</b>\n"]
        current_len = len(lines[0])
        
        for aid, name, portal_un, tid in agents:
            base_info = f"<b>{esc(name)}</b> (یوزر ورود: <code>{esc(portal_un)}</code>)"
            block = ""
            if tid and tid != 0:
                try:
                    chat = await context.bot.get_chat(tid)
                    t_name = chat.first_name or "بدون نام"
                    t_un = f"@{chat.username}" if chat.username else "بدون یوزرنیم"
                    block = f"🔹 {base_info}\nتلگرام: {esc(t_name)} | {t_un}\nآیدی: <code>{tid}</code>"
                except Exception:
                    block = f"🔹 {base_info}\nآیدی: <code>{tid}</code> (عدم دسترسی)"
            else:
                block = f"🔹 {base_info}\nتلگرام: هنوز وارد ربات نشده."
                
            if current_len + len(block) > 3800:
                lines.append("\n... (لیست به دلیل محدودیت تلگرام برش خورد)")
                break
                
            lines.append(block)
            current_len += len(block) + 2
                
        full_text = "\n\n".join(lines)
        kb = [[InlineKeyboardButton("🔙 بازگشت", callback_data="super_admin_users_menu")]]
        await query.edit_message_text(full_text, reply_markup=InlineKeyboardMarkup(kb), parse_mode="HTML")

# ==========================================
# 🧯 مدیریت خطای سراسری
# ==========================================
async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE):
    log.error("خطای پردازش‌نشده در آپدیت %s:", update, exc_info=context.error)

# ==========================================
# 🛡️ حلقهٔ پس‌زمینهٔ پایش تخطی از ظرفیت مجاز
# ==========================================
async def _notify_capacity(app, agent_id, text: str):
    """پیام پایش ظرفیت (تخطی/قفل خودکار) را فقط به صاحبِ همان اکانت ارسال می‌کند:
    - اگر اکانت متعلق به یک نماینده باشد، فقط همان نماینده مطلع می‌شود — نه ادمین، نه هیچ
      نمایندهٔ دیگری. او خودش می‌تواند از «👥 مدیریت کاربران» پسورد را تغییر و اکانت را دوباره
      فعال کند.
    - اگر اکانت مستقیماً توسط ادمین ساخته شده (بدون نماینده، agent_id=0) یا نمایندهٔ صاحبش هنوز
      هرگز وارد ربات نشده (پس telegram_id او هنوز ثبت نشده)، چون هیچ مقصد دیگری برای اطلاع‌رسانی
      وجود ندارد، به‌عنوان راه‌حل جایگزین به مدیریت ارسال می‌شود — وگرنه قفل شدن اکانت بی‌صاحب
      برای همیشه بی‌اطلاع می‌ماند و کسی نمی‌داند باید بازش کند."""
    targets = set()
    if agent_id:
        agent_tid = await asyncio.to_thread(_db_get_agent_telegram_id, agent_id)
        if agent_tid:
            with contextlib.suppress(Exception):
                targets.add(int(agent_tid))
    if not targets:
        targets = await asyncio.to_thread(_db_get_admin_chat_ids)
    for chat_id in targets:
        with contextlib.suppress(Exception):
            await app.bot.send_message(chat_id=chat_id, text=text, parse_mode="HTML")

async def _capacity_monitor_tick(app):
    """
    یک دور بررسی: تعداد اتصالات زندهٔ هر اکانت فعال را با ظرفیت مجازش مقایسه می‌کند.
    - اگر تخطی تازه شروع شده: فقط زمانش ثبت می‌شود (هنوز کاری انجام نمی‌شود).
    - اگر تخطی مستمر به CAPACITY_SUSPEND_AFTER_MINUTES رسید: اکانت خودکار قفل و فقط خودِ صاحب
      اکانت (نمایندهٔ فروشنده، یا در نبود نماینده، مدیریت) مطلع می‌شود — نه ادمین و نه هیچ
      نمایندهٔ دیگری.
    - اگر تلاش برای قفل روی لینوکس شکست بخورد، هر CAPACITY_RENOTIFY_HOURS ساعت یک‌بار یادآوری
      می‌شود (نه هر دور، تا اسپم نشود).
    - اگر اکانت به زیر ظرفیت مجاز برگشت: تایمر تخطی‌اش ریست می‌شود (نوسان لحظه‌ای را نادیده می‌گیریم).
    """
    counts, monitor_error = await _get_live_connection_counts()
    if monitor_error:
        log.warning("پایش ظرفیت: شمارش اتصالات زنده ناموفق بود (%s) — این دور رد شد.", monitor_error)
        return

    accounts = await asyncio.to_thread(_db_get_active_accounts_for_monitor)
    now = datetime.now()

    for un, lim, agid, violation_since, last_notified, host in accounts:
        live = counts.get(un.lower(), 0)
        if lim and live > lim:
            if not violation_since:
                # تخطی تازه شروع شده — فقط زمانش را ثبت می‌کنیم، هنوز اقدامی نمی‌کنیم
                await asyncio.to_thread(_db_set_violation_since, un, now.isoformat())
                log.info("پایش ظرفیت: تخطی اکانت %s شروع شد (اتصال زنده=%s، مجاز=%s).", un, live, lim)
                continue
            try:
                started = datetime.fromisoformat(violation_since)
            except Exception:
                await asyncio.to_thread(_db_set_violation_since, un, now.isoformat())  # مقدار خراب/قدیمی؛ از الان دوباره بشمار
                continue
            elapsed_min = (now - started).total_seconds() / 60
            if elapsed_min >= CAPACITY_SUSPEND_AFTER_MINUTES:
                # Sessionهای SSH مشتری در معماری فعلی روی خود Core terminate می‌شوند؛
                # بنابراین قفل Capacity نیز باید مستقیماً روی Core اعمال شود، نه از مسیر
                # Edge:customer_port که ممکن است با DNAT دوباره به Core برگردد.
                ok, err, kind = await run_cmd("sudo", "usermod", "-L", un)
                if not ok:
                    log.error("پایش ظرفیت: قفل‌کردن خودکار %s شکست خورد: %s", un, err)
                    # یادآوری دوره‌ای فقط اگر قفل مدام شکست بخورد — تا ادمین متوجه بشه و دستی رسیدگی کنه
                    should_notify = True
                    if last_notified:
                        with contextlib.suppress(Exception):
                            should_notify = (now - datetime.fromisoformat(last_notified)).total_seconds() >= CAPACITY_RENOTIFY_HOURS * 3600
                    if should_notify:
                        await asyncio.to_thread(_db_set_violation_last_notified, un, now.isoformat())
                        # 🔧 این یکی عمداً از _notify_capacity استفاده نمی‌کند: چون خودِ تلاش ربات
                        # برای قفل‌کردن روی سرور (سطح لینوکس) شکست خورده، این یک مشکل فنی/زیرساختی
                        # است که فقط ادمین (با دسترسی سرور) می‌تواند رفعش کند؛ نمایندهٔ مالک اکانت
                        # نه دسترسی سرور دارد و نه کاری از دستش برمی‌آید، پس صرفاً به مدیریت می‌رود.
                        await _notify_admins(app,
                            f"⚠️ اکانت <code>{esc(un)}</code> بیش از {int(elapsed_min)} دقیقه با {live} اتصال هم‌زمان "
                            f"(سقف مجاز: {lim}) کار می‌کند، اما تلاش ربات برای قفل خودکار آن روی سرور شکست خورده:\n\n"
                            f"{_fmt_linux_error('قفل خودکار اکانت', err, kind)}")
                    continue
                try:
                    changed = await asyncio.to_thread(_db_force_disable_for_violation, un)
                except Exception:
                    log.exception(
                        "پایش ظرفیت: ثبت غیرفعال‌سازی %s در دیتابیس شکست خورد؛ "
                        "تلاش برای Rollback قفل لینوکس...",
                        un
                    )

                    rb_ok, rb_err, _rb_kind = await run_cmd(
                        "sudo", "usermod", "-U", un
                    )

                    if not rb_ok:
                        log.error(
                            "پایش ظرفیت: Rollback قفل لینوکس برای %s نیز شکست خورد: %s",
                            un, rb_err
                        )

                    continue

                if not changed:
                    continue  # احتمالاً هم‌زمان توسط ادمین دستی تغییر کرده؛ کاری لازم نیست

                # usermod -L فقط ورود بعدی را می‌بندد؛ sessionهای فعلی را قطع نمی‌کند.
                # بعد از ثبت موفق وضعیت غیرفعال در DB، اتصال‌های زنده همین کاربر را terminate می‌کنیم.
                pk_ok, pk_err, _pk_kind = await run_cmd("sudo", "pkill", "-u", un)
                if not pk_ok:
                    log.warning("پایش ظرفیت: اکانت %s قفل شد اما قطع sessionهای زنده با خطا مواجه شد: %s", un, pk_err)

                log.warning("پایش ظرفیت: اکانت %s به‌خاطر تخطی مستمر (%s دقیقه) خودکار قفل شد.", un, int(elapsed_min))
                await _notify_capacity(app, agid,
                    f"🚫 <b>غیرفعال‌سازی خودکار اکانت</b>\n\n"
                    f"👤 یوزرنیم: <code>{esc(un)}</code>\n"
                    f"📊 ظرفیت مجاز: {lim} کاربر\n"
                    f"🔌 اتصال هم‌زمان مشاهده‌شده: {live}\n"
                    f"⏱ مدت تخطی مستمر: {int(elapsed_min)} دقیقه\n\n"
                    f"این اکانت به‌صورت خودکار قفل شد. برای فعال‌سازی مجدد، از «👥 مدیریت کاربران» "
                    f"می‌توانید ابتدا پسورد را تغییر دهید و سپس اکانت را دوباره فعال کنید.")
        else:
            if violation_since:
                # به زیر ظرفیت مجاز برگشته — ریست تایمر (نوسان لحظه‌ای را جریمه نمی‌کنیم)
                await asyncio.to_thread(_db_set_violation_since, un, None)

async def _capacity_monitor_loop(app):
    log.info("🛡️ حلقهٔ پایش تخطی از ظرفیت مجاز آغاز شد (بازهٔ چک: %s ثانیه، آستانهٔ قفل: %s دقیقه).",
              CAPACITY_CHECK_INTERVAL_SECONDS, CAPACITY_SUSPEND_AFTER_MINUTES)
    while True:
        try:
            await _capacity_monitor_tick(app)
        except Exception:
            log.exception("خطای غیرمنتظره در حلقهٔ پایش ظرفیت — دور بعدی ادامه می‌یابد.")
        await asyncio.sleep(CAPACITY_CHECK_INTERVAL_SECONDS)

async def _hold_activation_tick(app):
    """🆕 فعال‌سازی هوشمند آنهولد (V88): پایش هم‌زمانِ اتصال اول و مهلت سه‌روزه."""

    def _set_hold_linux_expiry_sync(u, e):
        # activate_on_first_connection / activate_expired_holds توابع sync هستند و
        # callback را مستقیماً فراخوانی می‌کنند؛ بنابراین callback نیز باید sync باشد.
        # مکانیزم Hidden Hold فعلی فقط برای SSH است و Sessionهای SSH روی Core
        # terminate می‌شوند. مقدار host در DB مسیر ورودی/Data-Plane اکانت است و
        # الزاماً محل واقعی Linux user نیست.
        with db_conn() as conn:
            row = conn.execute(
                "SELECT service_type FROM ssh_accounts WHERE username=?",
                (u,)
            ).fetchone()

        if not row:
            raise RuntimeError(f"اکانت {u} در دیتابیس پیدا نشد.")

        if row[0] != "ssh":
            raise RuntimeError(
                f"Hidden Hold برای service_type={row[0]!r} پشتیبانی نمی‌شود."
            )

        try:
            proc = subprocess.run(
                ["sudo", "-n", "usermod", "-e", e, u],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=SUBPROCESS_TIMEOUT,
            )
        except subprocess.TimeoutExpired as ex:
            raise RuntimeError("usermod برای تغییر تاریخ انقضا Timeout شد.") from ex

        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip()
            raise RuntimeError(err or f"usermod با exit={proc.returncode} شکست خورد.")

    # ۱. پایش اتصالات زنده
    conn_counts, _ = await _get_live_connection_counts()
    if conn_counts:
        for un, count in conn_counts.items():
            if count > 0:
                try:
                    act = await asyncio.to_thread(
                        _activate_hidden_hold_at_first_connection,
                        un,
                        set_linux_expiry=_set_hold_linux_expiry_sync
                    )
                except Exception as e:
                    # callback قبل از UPDATE دیتابیس اجرا می‌شود؛ بنابراین با شکست Linux،
                    # hold_active دست‌نخورده باقی می‌ماند و دور بعد دوباره تلاش خواهد شد.
                    log.error(
                        "آنهولد: فعال‌سازی %s با اولین اتصال شکست خورد؛ "
                        "Hold فعال باقی ماند: %s",
                        un, e
                    )
                    continue

                if act:
                    log.info("اکانت %s با اولین اتصال فعال شد. انقضا: %s", un, act.expire_date)
                    # اطلاع‌رسانی به نماینده (اختیاری)
                    with contextlib.suppress(Exception):
                        aid = await asyncio.to_thread(_db_get_agent_id_by_username, un)
                        if aid:
                            await _notify_capacity(
                                app, aid,
                                f"✅ اکانت <code>{esc(un)}</code> با اولین اتصال فعال شد.\n"
                                f"📅 انقضا: {format_db_date_to_jalali(act.expire_date)}"
                            )

    # ۲. پایش مهلت‌های منقضی‌شده (بدون اتصال)
    expired_acts = await asyncio.to_thread(
        _activate_expired_hidden_holds,
        set_linux_expiry=_set_hold_linux_expiry_sync
    )

    for act in expired_acts:
        log.info(
            "اکانت %s به دلیل پایان مهلت آنهولد فعال شد. انقضا: %s",
            act.username, act.expire_date
        )

async def _hold_activation_loop(app):
    log.info("⏳ حلقهٔ پایش آنهولد اکانت‌ها آغاز شد (بازهٔ چک: %s ثانیه، مهلت: %s روز).",
              HOLD_CHECK_INTERVAL_SECONDS, ACCOUNT_HOLD_DAYS)
    while True:
        try:
            await _hold_activation_tick(app)
        except Exception:
            log.exception("خطای غیرمنتظره در حلقهٔ پایش آنهولد — دور بعدی ادامه می‌یابد.")
        await asyncio.sleep(HOLD_CHECK_INTERVAL_SECONDS)
# ==========================================
# 🧹 پایش خودکار انقضای اکانت‌ها (زمان و حجم)
# ==========================================
async def _expiry_monitor_tick(app):
    """
    بررسی و غیرفعال‌سازی خودکار اکانت‌های منقضی شده در دیتابیس.
    ۱. اکانت‌هایی که تاریخ انقضای آن‌ها گذشته است (SSH و V2Ray زمان‌دار).
    ۲. همگام‌سازی وضعیت اکانت‌های حجمی V2Ray با سرور مرزبان.
    """
    now_str = datetime.now().strftime("%Y-%m-%d")
    
    # ۱. غیرفعال کردن اکانت‌های زمان‌دار که تاریخشان گذشته است
    def _db_mark_time_expired():
        with db_conn() as conn:
            conn.execute(
                "UPDATE ssh_accounts SET status='🔴 غیرفعال' "
                "WHERE status='🟢 فعال' AND expire_date != 'نامحدود' AND expire_date != '-' AND expire_date != '' AND expire_date < ?",
                (now_str,)
            )
    await asyncio.to_thread(_db_mark_time_expired)

    # ۲. همگام‌سازی وضعیت با مرزبان برای اکانت‌های V2Ray (مخصوصاً حجمی‌ها)
    m_url = await asyncio.to_thread(_db_get_setting, 'marzban_url', '')
    m_user = await asyncio.to_thread(_db_get_setting, 'marzban_username', '')
    m_pwd = await asyncio.to_thread(_db_get_setting, 'marzban_password', '')
    
    if m_url and m_user:
        try:
            token = await v2ray_engine.get_token(m_url, m_user, m_pwd)
            if token:
                headers = {"Authorization": f"Bearer {token}", "accept": "application/json"}
                async with aiohttp.ClientSession() as session:
                    async with session.get(f"{m_url}/api/users", headers=headers, params={"limit": 100000}, timeout=20) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            user_list = data.get('users', data) if isinstance(data, dict) else data
                            
                            # پیدا کردن کاربرانی که در مرزبان غیرفعال/لیمیت/منقضی شده‌اند
                            disabled_usernames = [
                                u.get('username') for u in user_list 
                                if isinstance(u, dict) and u.get('status') in ('disabled', 'limited', 'expired')
                            ]
                            
                            if disabled_usernames:
                                def _db_sync_marzban_status(usernames):
                                    with db_conn() as conn:
                                        conn.executemany(
                                            "UPDATE ssh_accounts SET status='🔴 غیرفعال' WHERE status='🟢 فعال' AND username=?",
                                            [(u,) for u in usernames]
                                        )
                                await asyncio.to_thread(_db_sync_marzban_status, disabled_usernames)
        except Exception as e:
            log.error(f"خطا در همگام‌سازی وضعیت انقضای مرزبان: {e}")

async def _expiry_monitor_loop(app):
    log.info("🧹 حلقهٔ پایش انقضای اکانت‌ها آغاز شد (بازهٔ چک: ۱ ساعت).")
    while True:
        try:
            await _expiry_monitor_tick(app)
        except Exception:
            log.exception("خطای غیرمنتظره در حلقهٔ پایش انقضا — دور بعدی ادامه می‌یابد.")
        await asyncio.sleep(3600)  # هر یک ساعت چک می‌کند

async def _notify_admins(app, text: str):
    """پیام را به تمام chat_idهای ثبت‌شدهٔ ادمین (بدون نیاز به agent_id) ارسال می‌کند."""
    ids = await asyncio.to_thread(_db_get_admin_chat_ids)
    for chat_id in ids:
        with contextlib.suppress(Exception):
            await app.bot.send_message(chat_id=chat_id, text=text, parse_mode="HTML")

async def _notify_admins_with_markup(app, text: str, reply_markup):
    """🆕 مثلِ _notify_admins، ولی با دکمه‌های اینلاین (برایِ مثلاً انتخابِ دستیِ Standby)."""
    ids = await asyncio.to_thread(_db_get_admin_chat_ids)
    for chat_id in ids:
        with contextlib.suppress(Exception):
            await app.bot.send_message(chat_id=chat_id, text=text, parse_mode="HTML", reply_markup=reply_markup)

# ============================================================================
# 🆕 معماریِ Control-Plane/Data-Plane — اجرایِ از راه دور و Mirroring (بندِ ۲)
# ============================================================================

async def _run_linux_cmd_on_host(host, ssh_port, *args, input_data: bytes = None, timeout: float = None):
    """
    مشابهِ run_cmd، ولی به‌جایِ اجرای محلی، از طریقِ SSH (با همان کلیدِ دائمیِ DO_SSH_KEY_PATH
    که ربات برایِ مدیریتِ Edgeها استفاده می‌کند) روی یک سرورِ مشخص اجرا می‌کند.
    اگر host دقیقاً همان IPِ عمومیِ خودِ Core باشد، بدونِ SSH، مستقیماً run_cmd محلی صدا زده
    می‌شود. خروجی: (ok: bool, err: str, err_kind: str) — دقیقاً هم‌شکلِ run_cmd.
    """
    core_public_ip = await asyncio.to_thread(_get_core_public_ip_cached)
    if core_public_ip and host == core_public_ip:
        return await run_cmd(*args, input_data=input_data, timeout=timeout)

    if paramiko is None:
        return False, "کتابخانهٔ paramiko نصب نیست.", "other"
    if not os.path.exists(DO_SSH_KEY_PATH):
        return False, "کلیدِ دائمیِ SSH برایِ Edgeها هنوز نصب نشده.", "other"

    _timeout = timeout or SUBPROCESS_TIMEOUT

    def _sync():
        ssh = None
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            pkey = paramiko.Ed25519Key.from_private_key_file(DO_SSH_KEY_PATH)
            ssh.connect(host, port=ssh_port, username='root', pkey=pkey,
                        timeout=_timeout, banner_timeout=_timeout)
            cmd_str = " ".join(shlex.quote(a) for a in args)
            stdin, stdout, stderr = ssh.exec_command(cmd_str, timeout=_timeout)
            if input_data is not None:
                stdin.write(input_data)
                stdin.channel.shutdown_write()
            err_txt = stderr.read().decode(errors='ignore').strip()
            exit_code = stdout.channel.recv_exit_status()
            if exit_code != 0:
                low = err_txt.lower()
                if "a password is required" in low or "no tty present" in low or ("sudo:" in low and "password" in low):
                    return False, err_txt or "sudo نیازمند رمز است.", "sudo_password"
                return False, err_txt, "other"
            return True, "", ""
        except Exception as e:
            return False, str(e), "other"
        finally:
            if ssh is not None:
                try:
                    ssh.close()
                except Exception:
                    pass

    return await asyncio.to_thread(_sync)


async def _mirror_linux_cmd(primary_host, primary_port, *args, input_data: bytes = None, timeout: float = None):
    """
    🆕 قلبِ بندِ ۲ (Edge + Core Mirroring): دستورِ حساسِ لینوکسی را هم روی Edgeِ اصلیِ صاحبِ
    اکانت اجرا می‌کند (primary — نتیجه‌اش تعیین‌کننده و بلوکه‌کننده است) و هم، به‌صورتِ
    best-effort، روی خودِ Core (برایِ Mirror طبقِ طراحیِ فیل‌اوور). شکستِ مرحلهٔ Core هرگز
    باعثِ شکستِ کلِ عملیات نمی‌شود — فقط هشدار در لاگ.
    خروجی: (ok, err, kind) — همیشه دقیقاً نتیجهٔ primary_host.
    """
    ok, err, kind = await _run_linux_cmd_on_host(primary_host, primary_port, *args,
                                                  input_data=input_data, timeout=timeout)
    core_public_ip = await asyncio.to_thread(_get_core_public_ip_cached)
    if core_public_ip and core_public_ip != primary_host:
        core_ok, core_err, _ = await _run_linux_cmd_on_host(
            core_public_ip, 22, *args, input_data=input_data, timeout=timeout)
        if not core_ok:
            log.warning("Mirrorِ Core شکست خورد (غیربحرانی، Edgeِ اصلی %s موفق بود): %s",
                        primary_host, core_err)
    return ok, err, kind


STANDBY_SCRIPT_PATH = os.path.join(_SCRIPT_DIR, "promote_standby_for_filtered_edge.py")

async def _activate_standby_for_filtered_edge(app, filtered_host: str, target_host: str = None):
    """
    گامِ دومِ Failover (بندِ ۴). اگر target_host داده نشود، طبقِ auto_failover_mode تصمیم
    می‌گیرد: خودکار → اولین Standbyِ سالم؛ دستی → فقط پیام با دکمهٔ «فعال‌سازیِ این Edge»
    برایِ هر Standby (فراخوانیِ بعدی با target_host مشخص، از هندلرِ همان دکمه می‌آید).
    گامِ اول (سوییچِ فوریِ دامنه به Core) پیش از این تابع، در _filter_detect_tick انجام شده.
    """
    auto_mode = (await asyncio.to_thread(_db_get_setting, 'auto_failover_mode', '0')) == '1'

    if target_host is None:
        standbys = await asyncio.to_thread(_db_get_standby_hosts)
        if not auto_mode:
            if not standbys:
                await _notify_admins(app,
                    "⚠️ حالتِ Failoverِ خودکار خاموش است و هیچ سرورِ Standbyِ سالمی هم ثبت نشده. "
                    "دامنه فعلاً روی Core باقی می‌ماند تا دستی یک Standby اضافه/فعال کنید.")
                return
            kb = [[InlineKeyboardButton(f"⚡️ فعال‌سازیِ این Edge ({h})",
                                          callback_data=f"standby_act_{filtered_host}_{h}")]
                  for h in standbys]
            await _notify_admins_with_markup(app,
                f"🚨 Edgeِ <code>{esc(filtered_host)}</code> فیلتر شد؛ دامنه موقتاً روی Core تنظیم شد.\n\n"
                f"برایِ انتقالِ دائمیِ کاربرانِ این Edge به یکی از سرورهایِ Standby، یکی را انتخاب کنید:",
                InlineKeyboardMarkup(kb))
            return
        if not standbys:
            await _notify_admins(app,
                "⚠️ حالتِ خودکار روشن است ولی هیچ Standbyِ سالمی پیدا نشد. دامنه رویِ Core باقی می‌ماند.")
            return
        target_host = standbys[0]

    target_port = await asyncio.to_thread(_db_get_host_ssh_port, target_host, 22)
    if not os.path.exists(STANDBY_SCRIPT_PATH):
        await _notify_admins(app,
            f"❌ اسکریپتِ promote_standby_for_filtered_edge.py کنارِ خودِ بات پیدا نشد "
            f"(<code>{esc(STANDBY_SCRIPT_PATH)}</code>). دامنه همچنان رویِ Core باقی می‌ماند.")
        return
    try:
        proc = await asyncio.create_subprocess_exec(
            sys.executable, STANDBY_SCRIPT_PATH,
            "--filtered-host", filtered_host, "--target-host", target_host,
            "--target-port", str(target_port),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await proc.communicate()
        returncode = proc.returncode
    except Exception as e:
        await _notify_admins(app, f"❌ اجرایِ اسکریپتِ بازسازیِ Standby شکست خورد: <code>{esc(str(e))}</code>")
        return

    if returncode != 0:
        await _notify_admins(app,
            f"❌ بازسازیِ کاربرانِ <code>{esc(filtered_host)}</code> رویِ Standby (<code>{esc(target_host)}</code>) "
            f"با خطا مواجه شد:\n<code>{esc(err.decode(errors='ignore')[-800:])}</code>\n\n"
            f"دامنه همچنان رویِ Core باقی می‌ماند (کاربران قطع نیستند).")
        return

    await asyncio.to_thread(_db_set_default_host, target_host)
    await asyncio.to_thread(_db_set_all_accounts_host, target_host)
    cf_ok, cf_msg = await _update_cloudflare_dns(target_host)
    cf_suffix = f"\n\n☁️ <b>وضعیتِ کلودفلر:</b> {cf_msg}" if cf_ok else f"\n\n⚠️ <b>هشدارِ کلودفلر:</b> {cf_msg}"
    await _notify_admins(app,
        f"✅ دامنه با موفقیت روی سرورِ Edge با آی‌پیِ <code>{esc(target_host)}</code> تنظیم شد.{cf_suffix}")

async def _ip_pressure_monitor_tick(app):
    """
    یک دور بررسیِ فشار CPU/RAM سرور، مستقل از حلقهٔ «پایش تخطی ظرفیت هر اکانت»:
    - 🆕 برای جلوگیری از هشدار کاذب سرِ یک اسپایک لحظه‌ای (که واقعاً هم دیده شد: یک بررسی CPU=۹۲٪
      نشان داد ولی دو دقیقه بعد کاملاً عادی بود)، فشار باید در IP_PRESSURE_CONFIRM_TICKS بررسیِ
      متوالی (پیش‌فرض ۲ بررسی = حداقل ۵ دقیقه واقعی) دیده شود تا اصلاً به‌عنوان «فشار تاییدشده»
      حساب و هشدار اول ارسال شود.
    - بعد از تاییدشدن، اگر فشار همچنان ادامه داشت و از زمان همان هشدار بیش از
      IP_PRESSURE_AUTOBALANCE_AFTER_HOURS ساعت گذشت (یعنی کسی از «سرویس IP» اقدامی نکرده که فشار
      را برطرف کند)، ربات با _run_ip_service_full_balance خودش کاربران را بین تمام هاست‌های
      ثبت‌شده بالانس می‌کند.
    - اگر فشار (حتی یک بررسیِ تک) برطرف شد، هم شمارندهٔ تایید و هم وضعیت پایش کامل ریست می‌شوند تا
      دور بعدی فشار از صفر و با همان قاعدهٔ تاییدِ دومرحله‌ای دوباره حساب شود.
    """
    health, herr = await _get_server_health()
    if not health:
        log.warning("پایش فشار IP: بررسی وضعیت سرور ناموفق بود (%s) — این دور رد شد.", herr)
        return
    raw_pressure = health['cpu_pct'] >= IP_PRESSURE_WARN_PCT or health['ram_pct'] >= IP_PRESSURE_WARN_PCT
    since_raw = await asyncio.to_thread(_db_get_setting, 'ip_pressure_since', None)
    autobalanced_raw = await asyncio.to_thread(_db_get_setting, 'ip_pressure_autobalanced', None)
    now = datetime.now()

    # 🆕 شمارندهٔ بررسی‌های متوالیِ «زیر فشار» — مستقل از since_raw (که فقط از لحظهٔ تاییدشدنِ
    # فشار شروع می‌شود). این شمارنده در دیتابیس نگه‌داری می‌شود تا حتی با ری‌استارت ربات هم از
    # دست نرود و یک ری‌استارت باعث نشود شمارش از نو با یک بررسی معتبر اشتباه گرفته شود.
    streak_raw = await asyncio.to_thread(_db_get_setting, 'ip_pressure_streak', '0')
    try: streak = int(streak_raw)
    except Exception: streak = 0

    if not raw_pressure:
        if streak:
            await asyncio.to_thread(_db_update_setting, 'ip_pressure_streak', '0')
        if since_raw:
            await asyncio.to_thread(_db_update_setting, 'ip_pressure_since', '')
            await asyncio.to_thread(_db_update_setting, 'ip_pressure_autobalanced', '')
            log.info("پایش فشار IP: فشار سرور برطرف شد؛ پایش ریست شد.")
        return

    streak += 1
    await asyncio.to_thread(_db_update_setting, 'ip_pressure_streak', str(streak))
    if streak < IP_PRESSURE_CONFIRM_TICKS:
        # هنوز فشار به‌اندازهٔ کافی ادامه‌دار نبوده تا مطمئن شویم اسپایکِ لحظه‌ای نیست — فعلاً فقط لاگ
        log.info("پایش فشار IP: نمونهٔ زیر فشار دیده شد (CPU=%s٪, RAM=%s٪) ولی هنوز تاییدنشده (%s/%s)؛ هشدار ارسال نمی‌شود.",
                  health['cpu_pct'], health['ram_pct'], streak, IP_PRESSURE_CONFIRM_TICKS)
        return
    under_pressure = True

    if not since_raw:
        # اولین باری که فشار دیده می‌شود — فقط هشدار؛ هیچ اقدامی روی کاربران انجام نمی‌شود
        await asyncio.to_thread(_db_update_setting, 'ip_pressure_since', now.isoformat())
        await _notify_admins(app,
            f"🟠 <b>هشدار فشار سرور</b>\n\n"
            f"⚙️ CPU: {health['cpu_pct']}٪ | 🧠 RAM: {health['ram_pct']}٪ | Load: {health['load1']}\n\n"
            f"مصرف سرور به مرز بحرانی رسیده است (بالای {IP_PRESSURE_WARN_PCT}٪). اگر ظرف "
            f"{IP_PRESSURE_AUTOBALANCE_AFTER_HOURS} ساعت آینده از «🌐 سرویس IP» اقدامی انجام نشود "
            f"و فشار همچنان ادامه داشته باشد، ربات خودش کاربران را به‌صورت خودکار بین IPهای ثبت‌شده "
            f"بالانس می‌کند.\n\n"
            f"برای اقدام دستی: تنظیمات سرور ← 🌐 سرویس IP")
        log.info("پایش فشار IP: فشار جدید تشخیص داده شد (CPU=%s٪, RAM=%s٪)؛ هشدار ارسال شد.",
                  health['cpu_pct'], health['ram_pct'])
        return

    try:
        since = datetime.fromisoformat(since_raw)
    except Exception:
        await asyncio.to_thread(_db_update_setting, 'ip_pressure_since', now.isoformat())  # مقدار خراب/قدیمی؛ از الان دوباره بشمار
        return

    elapsed_hours = (now - since).total_seconds() / 3600
    if elapsed_hours < IP_PRESSURE_AUTOBALANCE_AFTER_HOURS or autobalanced_raw:
        return  # هنوز مهلت تمام نشده، یا در همین دورهٔ فشار قبلاً یک‌بار بالانس خودکار انجام شده

    moved, berr = await _run_ip_service_full_balance()
    await asyncio.to_thread(_db_update_setting, 'ip_pressure_autobalanced', now.isoformat())
    if berr:
        await _notify_admins(app,
            f"⚠️ فشار سرور {IP_PRESSURE_AUTOBALANCE_AFTER_HOURS} ساعت برطرف نشد و تلاش ربات برای بالانس خودکار "
            f"هم ناموفق بود:\n{esc(berr)}")
        log.warning("پایش فشار IP: بالانس خودکار ناموفق بود (%s).", berr)
        return
    if not moved:
        await _notify_admins(app,
            f"⚠️ فشار سرور {IP_PRESSURE_AUTOBALANCE_AFTER_HOURS} ساعت ادامه داشت، ولی هیچ اکانتی برای بالانس پیدا نشد.")
        return
    lines = "\n".join(f"• {esc(u)} → <code>{esc(h)}</code>" for u, h in moved[:30])
    more = f"\n… و {len(moved) - 30} اکانت دیگر" if len(moved) > 30 else ""
    await _notify_admins(app,
        f"🤖 <b>بالانس خودکار کاربران بین IPها</b>\n\n"
        f"فشار سرور {IP_PRESSURE_AUTOBALANCE_AFTER_HOURS} ساعت متوالی ادامه داشت و اقدامی ثبت نشد، "
        f"پس ربات خودش {len(moved)} اکانت را بین IPهای ثبت‌شده بالانس کرد:\n{lines}{more}")
    log.warning("پایش فشار IP: بالانس خودکار %s اکانت را جابه‌جا کرد.", len(moved))

async def _ip_pressure_monitor_loop(app):
    log.info("🌐 حلقهٔ پایش فشار IP آغاز شد (بازهٔ چک: %ss، آستانهٔ هشدار: %s٪، مهلت بالانس خودکار: %sساعت).",
              IP_PRESSURE_CHECK_INTERVAL_SECONDS, IP_PRESSURE_WARN_PCT, IP_PRESSURE_AUTOBALANCE_AFTER_HOURS)
    while True:
        try:
            await _ip_pressure_monitor_tick(app)
        except Exception:
            log.exception("خطای غیرمنتظره در حلقهٔ پایش فشار IP — دور بعدی ادامه می‌یابد.")
        await asyncio.sleep(IP_PRESSURE_CHECK_INTERVAL_SECONDS)

async def _tcp_health_check(host: str, port: int, timeout: float = HOST_HEALTH_TCP_TIMEOUT_SECONDS):
    """تست ساده و سریع: آیا می‌شود به host:port یک اتصال TCP باز کرد؟ فقط «بالا بودن سرویس» را
    می‌سنجد؛ تشخیص فیلترینگ از دید کاربران داخل ایران را نمی‌تواند تضمین کند چون خودِ ربات
    معمولاً روی سروری خارج از محدودهٔ فیلترینگ اجرا می‌شود — برای همین در کنارش دکمهٔ دستی
    «این IP بلاکه» هم در پنل ادمین وجود دارد تا با گزارش واقعی مشتری/نماینده هم بشود اقدام کرد."""
    writer = None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        return True, None
    except Exception as e:
        return False, str(e)
    finally:
        if writer:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

async def _host_health_tick(app):
    await asyncio.to_thread(_db_sync_host_pool)
    pool = await asyncio.to_thread(_db_get_host_pool)
    port_map = await asyncio.to_thread(_db_get_host_ssh_port_map)

    # 🐛🔧 رفع باگ واقعی: از وقتی ستون is_default به _db_get_host_pool اضافه شد (۸ ستون برمی‌گرداند)،
    # این حلقه هنوز فقط ۷ مقدار unpack می‌کرد و با ValueError («too many values to unpack») در هر
    # دور کرش می‌کرد — یعنی پایش خودکار سلامت IPها عملاً هرگز واقعاً اجرا نمی‌شد (فقط لاگ خطا
    # می‌ریخت و رد می‌شد). is_default اینجا لازم نیست، فقط باید در unpack حساب شود.
    for host, active, fails, last_check, last_status, disabled_reason, disabled_at, _is_default, _avg_latency_ms, added_at, _is_standby in pool:
        if not active:
            continue  # IPهای غیرفعال‌شده خودکار تست نمی‌شوند؛ فقط با دکمهٔ دستی ادمین دوباره تست می‌شوند
        # 🆕 دورهٔ مهلتِ IP تازه‌افزوده‌شده — اگر هنوز داخل این بازه‌ایم، این IP را کلاً رد می‌کنیم
        # (نه فقط شکست را نادیده می‌گیریم) تا سرور تازه‌بالاآمده فرصت کامل بوت‌شدن را داشته باشد.
        if added_at:
            try:
                age_minutes = (datetime.now() - datetime.strptime(added_at, "%Y-%m-%d %H:%M:%S")).total_seconds() / 60
                if age_minutes < HOST_HEALTH_GRACE_PERIOD_MINUTES:
                    continue
            except ValueError:
                pass  # فرمت غیرمنتظره — برای احتیاط طوری رفتار می‌کنیم که انگار مهلت گذشته (رفتار قبلی)
        t0 = time.monotonic()
        host_port = port_map.get(host, 22)
        ok, err = await _tcp_health_check(host, host_port)
        if ok:
            # 🆕 «کدام VPS سرعتش بهتره»: تاخیر همین اتصال موفق را ثبت می‌کنیم (میانگین هموارشده)
            # تا مقایسهٔ IPهای فعال با هم و پیشنهاد سریع‌ترین‌شان ممکن شود.
            await asyncio.to_thread(_db_record_host_latency, host, (time.monotonic() - t0) * 1000)
        new_fails = await asyncio.to_thread(_db_record_host_check, host, ok, err)
        if ok or new_fails < HOST_HEALTH_FAIL_THRESHOLD:
            continue
        active_now = await asyncio.to_thread(_db_get_active_hosts_from_pool)
        if len(active_now) <= 1:
            # 🛡️ آخرین IP فعال را هرگز خودکار غیرفعال نمی‌کنیم — فقط هشدار بحرانی می‌دهیم
            await _notify_admins(app,
                f"🔴 <b>هشدار بحرانی — تنها IP فعال پاسخ نمی‌دهد</b>\n\n"
                f"IP <code>{esc(host)}</code> در {new_fails} بررسی متوالی پاسخ نداد، ولی چون تنها هاست فعال شماست "
                f"به‌صورت خودکار غیرفعال نشد (تا فاکتورسازی کاملاً متوقف نشود).\n"
                f"آخرین خطا: <code>{esc(err)}</code>\n\n"
                f"⚠️ لطفاً فوراً یک IP دیگر اضافه کنید: تنظیمات سرور ← 🌐 سرویس IP ← 🛡 وضعیت IPها")
            continue
        await asyncio.to_thread(_db_set_host_active, host, False, f"غیرفعال خودکار پس از {new_fails} شکست متوالی: {err}")
        await asyncio.to_thread(_db_rebuild_hosts_from_pool)
        # 🆕 اگر دامنهٔ ثابت عمومی تنظیم شده، خودکار به یکی از IPهای سالمِ باقی‌مانده سوییچ می‌کنیم
        # تا مشتریانی که با همان دامنه (نه IP خام) وصل می‌شوند بدون هیچ اقدامی خودکار منتقل شوند.
        remaining_active = await asyncio.to_thread(_db_get_active_hosts_from_pool)
        if remaining_active:
            await _cf_switch_public_domain(remaining_active[0], app=app)
        await _notify_admins(app,
            f"🔴 <b>یک IP به‌صورت خودکار از سرویس خارج شد</b>\n\n"
            f"IP <code>{esc(host)}</code> در {new_fails} بررسی متوالی (هر {HOST_HEALTH_CHECK_INTERVAL_SECONDS // 60} دقیقه) "
            f"پاسخ نداد و از لیست IPهای فعال حذف شد.\n"
            f"آخرین خطا: <code>{esc(err)}</code>\n\n"
            f"مشتریانی که با این IP وصل بودند را از «🌐 سرویس IP» به IP دیگری منتقل کنید.\n"
            f"برای تست دوباره و بازگردانی: تنظیمات سرور ← 🌐 سرویس IP ← 🛡 وضعیت IPها")
        log.warning("IP %s پس از %s شکست متوالی به‌صورت خودکار غیرفعال شد: %s", host, new_fails, err)

async def _host_health_loop(app):
    log.info("🛡️ حلقهٔ پایش سلامت/در دسترس‌بودن IPها آغاز شد (بازهٔ چک: %ss، آستانهٔ غیرفعال‌سازی: %s شکست متوالی).",
              HOST_HEALTH_CHECK_INTERVAL_SECONDS, HOST_HEALTH_FAIL_THRESHOLD)
    while True:
        try:
            await _host_health_tick(app)
        except Exception:
            log.exception("خطای غیرمنتظره در حلقهٔ پایش سلامت IPها — دور بعدی ادامه می‌یابد.")
        await asyncio.sleep(HOST_HEALTH_CHECK_INTERVAL_SECONDS)

async def _udpgw_health_tick(app):
    """
    🆕 چون badvpn-udpgw روی خودِ همین سرور اجرا می‌شود (نه یک هاست دوردست)، پایشش یک اتصال TCP
    محلی به 127.0.0.1:udpgw_port است. هدف: به‌جای این‌که از شکایتِ مشتری («فلان بازی بالا نمیاد»)
    بفهمیم این سرویس کرش کرده، خودِ ربات با شکست‌های متوالی به ادمین هشدار بدهد — و وقتی سرویس
    برگشت هم یک پیام «برطرف شد» بفرستد تا ادمین مجبور نباشد دستی چک کند.
    """
    cu = await asyncio.to_thread(_db_get_setting, 'udpgw_port', '7300')
    try:
        port_i = int(cu)
    except Exception:
        port_i = 7300
    ok, err = await _tcp_health_check('127.0.0.1', port_i, timeout=4)
    fails = int(await asyncio.to_thread(_db_get_setting, 'udpgw_fail_count', '0'))
    was_down = (await asyncio.to_thread(_db_get_setting, 'udpgw_alert_active', '0')) == '1'
    if ok:
        if was_down:
            await _notify_admins(app,
                f"🟢 <b>سرویس UDPGW برگشت</b>\n\n"
                f"badvpn-udpgw دوباره روی پورت <code>{port_i}</code> پاسخ می‌دهد.")
        await asyncio.to_thread(_db_update_setting, 'udpgw_fail_count', '0')
        await asyncio.to_thread(_db_update_setting, 'udpgw_alert_active', '0')
        return
    fails += 1
    await asyncio.to_thread(_db_update_setting, 'udpgw_fail_count', str(fails))
    if fails >= UDPGW_HEALTH_FAIL_THRESHOLD and not was_down:
        await asyncio.to_thread(_db_update_setting, 'udpgw_alert_active', '1')
        await _notify_admins(app,
            f"🔴 <b>سرویس UDPGW پاسخ نمی‌دهد</b>\n\n"
            f"در {fails} بررسی متوالی (هر {UDPGW_HEALTH_CHECK_INTERVAL_SECONDS // 60} دقیقه)، هیچ سرویسی روی "
            f"127.0.0.1:{port_i} پاسخ نداد. آخرین خطا: <code>{esc(err)}</code>\n\n"
            f"یعنی احتمالاً سرویس <code>badvpn-udpgw</code> کرش کرده یا بالا نیامده — تونل SSH/TLS خودش "
            f"مشکلی ندارد، ولی کاربرهایی که به فوروارد UDP (بازی/تماس صوتی‌تصویری) نیاز دارند دچار "
            f"مشکل می‌شوند.\n\n"
            f"روی سرور بررسی کنید: <code>systemctl status badvpn-udpgw</code> و در صورت لزوم "
            f"<code>sudo systemctl restart badvpn-udpgw</code>.")
        log.warning("سرویس UDPGW روی پورت %s پس از %s شکست متوالی پاسخ نداد: %s", port_i, fails, err)

async def _udpgw_health_loop(app):
    log.info("🔌 حلقهٔ پایش سلامت UDPGW آغاز شد (بازهٔ چک: %ss، آستانهٔ هشدار: %s شکست متوالی).",
              UDPGW_HEALTH_CHECK_INTERVAL_SECONDS, UDPGW_HEALTH_FAIL_THRESHOLD)
    while True:
        try:
            await _udpgw_health_tick(app)
        except Exception:
            log.exception("خطای غیرمنتظره در حلقهٔ پایش سلامت UDPGW — دور بعدی ادامه می‌یابد.")
        await asyncio.sleep(UDPGW_HEALTH_CHECK_INTERVAL_SECONDS)

async def _build_daily_sales_report_csv(report_date_str: str):
    """
    گزارش فروش روزانهٔ همهٔ نمایندگان (+ فروش مستقیم ادمین) را برای یک روز مشخص (report_date_str،
    فرمت YYYY-MM-DD) به‌صورت یک فایل CSV می‌سازد. خروجی: (bytes فایل با BOM برای نمایش صحیح فارسی
    در اکسل، تعداد کل اکانت‌های ساخته‌شده در آن روز، تعداد نمایندگان دارای حداقل یک فروش).
    """
    def _build():
        agents = _db_get_all_agents()  # [(id, name, referral_code), ...]
        with db_conn() as conn:
            c = conn.cursor()
            rows = []
            grand_total_today = 0
            active_sellers = 0
            # ردیف مخصوص فروش مستقیم ادمین (agent_id = 0)
            for aid, name in [(0, "مستقیم توسط ادمین")] + [(a[0], a[1]) for a in agents]:
                today_cnt = c.execute(
                    "SELECT COUNT(*) FROM ssh_accounts WHERE creation_date = ? AND agent_id = ? AND status != '⏳ درحال ساخت'",
                    (report_date_str, aid)).fetchone()[0]
                total_cnt = c.execute(
                    "SELECT COUNT(*) FROM ssh_accounts WHERE agent_id = ? AND status != '⏳ درحال ساخت'", (aid,)).fetchone()[0]
                active_cnt = c.execute(
                    "SELECT COUNT(*) FROM ssh_accounts WHERE agent_id = ? AND status = '🟢 فعال'", (aid,)).fetchone()[0]
                if today_cnt > 0 or total_cnt > 0:
                    rows.append((name, today_cnt, total_cnt, active_cnt))
                    grand_total_today += today_cnt
                    if today_cnt > 0:
                        active_sellers += 1
            rows.sort(key=lambda r: r[1], reverse=True)
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(["ردیف", "نام نماینده", f"فروش {report_date_str}", "فروش کل (تاریخی)", "اکانت فعال فعلی"])
            for i, (name, tcnt, tot, act) in enumerate(rows, 1):
                writer.writerow([i, name, tcnt, tot, act])
            writer.writerow([])
            writer.writerow(["", "مجموع کل فروش این روز", grand_total_today, "", ""])
            return buf.getvalue().encode("utf-8-sig"), grand_total_today, active_sellers
    return await asyncio.to_thread(_build)

async def _daily_sales_report_loop(app):
    """
    هر شب دقیقاً راس ساعت ۰۰:۰۰ به‌وقت ایران (Asia/Tehran — نه لزوماً وقت سیستم سرور، چون
    اکثر سرورهای خارج از ایران روی UTC تنظیم‌اند)، یک فایل CSV حاوی آمار فروش تمام نمایندگان
    (به‌علاوه فروش مستقیم ادمین) برای روزی که تازه تمام شده را می‌سازد و فقط برای ادمین‌ها
    (نه نمایندگان) ارسال می‌کند.
    🔧 عمداً به‌جای JobQueue/APScheduler از همان الگوی حلقهٔ پس‌زمینهٔ خودِ پروژه استفاده شده تا
    وابستگی اضافه‌ای به requirements.txt اضافه نشود (مطابق همان اصلی که برای بقیهٔ حلقه‌ها رعایت شده).
    """
    log.info("📊 حلقهٔ گزارش روزانهٔ فروش نمایندگان آغاز شد (ارسال راس ساعت ۰۰:۰۰ به‌وقت ایران برای ادمین‌ها).")
    while True:
        now = datetime.now(IRAN_TZ)
        tomorrow_midnight = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        seconds_until_midnight = (tomorrow_midnight - now).total_seconds()
        await asyncio.sleep(max(seconds_until_midnight, 1))
        try:
            report_date = (datetime.now(IRAN_TZ) - timedelta(days=1)).strftime("%Y-%m-%d")
            csv_bytes, grand_total, seller_count = await _build_daily_sales_report_csv(report_date)
            admin_ids = await asyncio.to_thread(_db_get_admin_chat_ids)
            report_date_fa = fmt_jalali_date_only(datetime.strptime(report_date, "%Y-%m-%d"))
            caption = (f"📊 <b>گزارش فروش روزانه — {esc(report_date_fa)}</b>\n"
                       f"🕛 ارسال‌شده راس ساعت ۰۰:۰۰ به‌وقت ایران\n\n"
                       f"🧾 مجموع فروش این روز: {grand_total} اکانت\n"
                       f"👥 تعداد نمایندگان دارای فروش: {seller_count}")
            for chat_id in admin_ids:
                with contextlib.suppress(Exception):
                    await app.bot.send_document(
                        chat_id=chat_id,
                        document=InputFile(io.BytesIO(csv_bytes), filename=f"sales_report_{report_date}.csv"),
                        caption=caption, parse_mode="HTML")
            log.info("📊 گزارش فروش روزانهٔ %s برای %s ادمین ارسال شد (مجموع فروش: %s).", report_date, len(admin_ids), grand_total)
            
            # 📊 ارسال گزارش حسابداری برای حسابدارها
            try:
                acc_csv_bytes = await _generate_accounting_csv(days=1)
                for acc_id in ACCOUNTANT_IDS:
                    with contextlib.suppress(Exception):
                        await app.bot.send_document(
                            chat_id=acc_id,
                            document=InputFile(io.BytesIO(acc_csv_bytes), filename=f"Accounting_Daily_{report_date}.csv"),
                            caption=f"📊 <b>گزارش مالی حسابداری — {esc(report_date_fa)}</b>\n(ارسال خودکار روزانه)", parse_mode="HTML")
            except Exception as e:
                log.error(f"خطا در ارسال گزارش روزانه حسابدار: {e}")
                
        except Exception:
            log.exception("خطای غیرمنتظره در ساخت/ارسال گزارش فروش روزانه — فردا شب دوباره تلاش می‌شود.")

async def _weekly_accounting_report_loop(app):
    log.info("📅 حلقه گزارش هفتگی حسابدار آغاز شد (ارسال شنبه‌ها ۰۰:۰۰).")
    while True:
        now = datetime.now(IRAN_TZ)
        tomorrow_midnight = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        seconds_until_midnight = (tomorrow_midnight - now).total_seconds()
        await asyncio.sleep(max(seconds_until_midnight, 1))
        new_now = datetime.now(IRAN_TZ)
        if new_now.weekday() == 5: # شنبه بامداد
            try:
                report_date_fa = fmt_jalali_date_only(new_now)
                acc_csv_bytes = await _generate_accounting_csv(days=7)
                for acc_id in ACCOUNTANT_IDS:
                    with contextlib.suppress(Exception):
                        await app.bot.send_document(
                            chat_id=acc_id,
                            document=InputFile(io.BytesIO(acc_csv_bytes), filename=f"Accounting_Weekly.csv"),
                            caption=f"📅 <b>گزارش مالی هفتگی حسابداری — منتهی به {esc(report_date_fa)}</b>\n(ارسال خودکار هفتگی)", parse_mode="HTML")
            except Exception as e:
                log.error(f"خطا در ارسال گزارش هفتگی حسابدار: {e}")

async def _welcome_sales_report_delayed(app, chat_id):
    """
    🆕 وقتی یک ادمین برای اولین‌بار با یوزرنیم/پسورد مدیریت وارد ربات می‌شود (یعنی این چت هنوز
    هیچ‌وقت جزو ادمین‌های ثبت‌شده نبوده)، دقیقاً ۱۰ دقیقه بعد، یک گزارش فروش «امروز تا همین
    لحظه» فقط برای همین چت ارسال می‌شود. این فقط یک ارسال یک‌بارهٔ خوش‌آمدگویی است؛ از همان شب
    اول، حلقهٔ همیشگیِ نیمه‌شب (۰۰:۰۰ به‌وقت ایران) هم به‌طور خودکار شامل همین چت خواهد شد، چون
    chat_id از قبل به admin_chat_ids اضافه شده.
    """
    try:
        await asyncio.sleep(10 * 60)  # ۱۰ دقیقه
        today_str = datetime.now(IRAN_TZ).strftime("%Y-%m-%d")
        csv_bytes, grand_total, seller_count = await _build_daily_sales_report_csv(today_str)
        today_fa = fmt_jalali_date_only(datetime.now(IRAN_TZ))
        caption = (f"👋 <b>گزارش خوش‌آمدگویی فروش</b>\n"
                   f"این پیام ۱۰ دقیقه پس از اولین ورود شما به پنل مدیریت ارسال شد.\n\n"
                   f"📊 آمار فروش امروز ({esc(today_fa)}) تا همین لحظه:\n"
                   f"🧾 مجموع فروش تاکنون: {grand_total} اکانت\n"
                   f"👥 تعداد نمایندگان دارای فروش: {seller_count}\n\n"
                   f"⏰ از این پس، گزارش کامل فروش هر شب راس ساعت ۰۰:۰۰ به‌وقت ایران برایتان ارسال خواهد شد.")
        with contextlib.suppress(Exception):
            await app.bot.send_document(
                chat_id=chat_id,
                document=InputFile(io.BytesIO(csv_bytes), filename=f"sales_report_{today_str}.csv"),
                caption=caption, parse_mode="HTML")
        log.info("👋 گزارش خوش‌آمدگویی فروش (۱۰ دقیقه پس از اولین ورود) برای چت %s ارسال شد.", chat_id)
    except asyncio.CancelledError:
        raise
    except Exception:
        log.exception("خطا در ساخت/ارسال گزارش خوش‌آمدگویی فروش (۱۰ دقیقه پس از اولین ورود ادمین).")

# ==========================================
# 🆕 V89 — حلقهٔ پایش شناسایی خودکار فیلتر شدن بر اساس کاربران آنلاین
# ==========================================
_filter_detect_low_ticks = 0  # تعداد دفعات متوالی که کاربران آنلاین زیر آستانه بودند

async def _filter_detect_tick(app):
    """
    🆕 V89 — یک دور بررسی سیستم شناسایی خودکار فیلتر شدن:
    - تعداد کاربران آنلاین را با کل کاربران فعال مقایسه می‌کند.
    - اگر FILTER_DETECT_CONFIRM_TICKS بار متوالی زیر آستانه بود → فیلتر تشخیص داده می‌شود.
    - خودکار به سریع‌ترین IP فعال تغییر می‌کند و به ادمین اطلاع می‌دهد.
    """
    global _filter_detect_low_ticks
    # بررسی فعال بودن سیستم
    enabled = await asyncio.to_thread(_db_get_filter_detect_enabled)
    if not enabled:
        _filter_detect_low_ticks = 0
        return
    # دریافت تعداد کاربران فعال
    total_active = await asyncio.to_thread(_db_get_total_active_accounts_count)
    if total_active < FILTER_DETECT_MIN_ACTIVE_ACCOUNTS:
        log.debug("پایش فیلتر: تعداد کاربران فعال (%s) کمتر از حداقل لازم (%s) — این دور رد شد.", total_active, FILTER_DETECT_MIN_ACTIVE_ACCOUNTS)
        return
    # دریافت تعداد کاربران آنلاین
    counts, err = await _get_live_connection_counts()
    if err:
        log.warning("پایش فیلتر: خطا در دریافت اتصالات زنده: %s", err)
        return
    online_count = sum(1 for c in counts.values() if c > 0)
    threshold = await asyncio.to_thread(_db_get_filter_detect_threshold)
    online_pct = (online_count / total_active) * 100 if total_active > 0 else 0
    log.debug("پایش فیلتر: آنلاین=%s از کل=%s (درصد=%.1f\u066a، آستانه=%.1f\u066a)", online_count, total_active, online_pct, threshold)
    # 🆕 دورهٔ خنک‌شدن: اگه به‌تازگی سوییچ IP انجام شده (خودکار یا دستی)، این دور رو نادیده بگیر —
    # چون افت موقتِ درصد آنلاین بلافاصله بعد از سوییچ طبیعیه (اتصال‌های در حال reconnect) و
    # نباید باعث یه سوییچ دیگه بشه.
    since_switch = await asyncio.to_thread(_db_seconds_since_last_ip_switch)
    if since_switch < FILTER_DETECT_SWITCH_COOLDOWN_SECONDS:
        log.debug("پایش فیلتر: در دورهٔ خنک‌شدنِ بعد از آخرین سوییچ (%.0f از %s ثانیه گذشته) — این دور رد شد.",
                   since_switch, FILTER_DETECT_SWITCH_COOLDOWN_SECONDS)
        _filter_detect_low_ticks = 0
        return
    if online_pct < threshold:
        _filter_detect_low_ticks += 1
        log.warning("پایش فیلتر: درصد آنلاین %.1f\u066a — زیر آستانه %.1f\u066a (دفعهٔ %s از %s)", online_pct, threshold, _filter_detect_low_ticks, FILTER_DETECT_CONFIRM_TICKS)
        if _filter_detect_low_ticks >= FILTER_DETECT_CONFIRM_TICKS:
            # فیلتر تشخیص داده شد!
            _filter_detect_low_ticks = 0
            log.warning("🚨 فیلتر تشخیص داده شد! درصد آنلاین: %.1f\u066a — در حال تغییر IP...", online_pct)
            # 🆕 ☁️ همان IPای که تا همین لحظه پیش‌فرض بود، احتمالاً همان چیزیه که فیلتر شده —
            # قبل از هر جابه‌جایی نگهش می‌داریم تا در ادامه، گامِ اولِ Failover و سپس (پس‌زمینه)
            # فعال‌سازیِ یک Standby دقیقاً همین Edge را هدف بگیرند.
            old_default_host = await asyncio.to_thread(_db_get_default_host)
            # 🆕 گامِ اولِ Failover (بندِ ۴): فوراً دامنه را روی خودِ Core می‌بریم — چون طبقِ
            # طراحیِ Mirroring، کاربرانِ *همهٔ* Edgeها روی Core هم وجود دارند، این تضمین‌شده‌ترین
            # و سریع‌ترین راهِ نجاتِ آنیِ مشتریان است؛ برخلافِ «سریع‌ترین Edgeِ دیگر» که ممکن است
            # اصلاً کاربرانِ همین Edgeِ فیلترشده رویش نباشد.
            core_public_ip = await asyncio.to_thread(_get_core_public_ip_cached)
            if core_public_ip and core_public_ip != old_default_host:
                ok_core_reach, _core_detail = await _check_ssh_reachable(core_public_ip, 22)
                if ok_core_reach:
                    await asyncio.to_thread(_db_set_default_host, core_public_ip)
                    await asyncio.to_thread(_db_mark_ip_switch_now)
                    cf_ok, cf_msg = await _update_cloudflare_dns(core_public_ip)
                    cf_suffix = f"\n\n☁️ <b>وضعیتِ کلودفلر:</b> {cf_msg}" if cf_ok else f"\n\n⚠️ <b>هشدارِ کلودفلر:</b> {cf_msg}"
                    await _notify_admins(app,
                        f"🚨 <b>سرورِ Edge با آی‌پیِ {esc(old_default_host)} فیلتر شد.</b>\n"
                        f"📊 کاربران آنلاین: {online_count} از {total_active} ({online_pct:.1f}\u066a)\n\n"
                        f"دامنه موقتاً روی سرورِ Core (<code>{esc(core_public_ip)}</code>) تنظیم شد؛ "
                        f"مشتریان (که رویِ Core هم Mirror شده‌اند) نباید قطع شوند.{cf_suffix}")
                    if old_default_host:
                        spawn_bg_task(_activate_standby_for_filtered_edge(app, old_default_host))
                    return
                log.warning("پایش فیلتر: Core (%s) هم SSH زنده نداد (%s) — ادامه با منطقِ قدیمیِ انتخابِ سریع‌ترین Edge.",
                            core_public_ip, _core_detail)
            # پیدا کردن سریع‌ترین IP فعال (fallback اگر خودِ Core در دسترس نبود)
            fastest_host = await asyncio.to_thread(_db_get_fastest_active_host)
            current_hosts_raw = await asyncio.to_thread(_db_get_setting, 'hosts', '')
            current_hosts = [h.strip() for h in current_hosts_raw.split(',') if h.strip()]
            pool = await asyncio.to_thread(_db_get_host_pool)
            active_hosts = [r[0] for r in pool if r[1]]
            if not fastest_host and active_hosts:
                # اگر تست سرعت انجام نشده، اولین IP فعال را بگیر
                fastest_host = active_hosts[0]
            if not fastest_host:
                await _notify_admins(app,
                    f"🚨 <b>فیلتر IP تشخیص داده شد!</b>\n\n"
                    f"📊 کاربران آنلاین: {online_count} از {total_active} ({online_pct:.1f}\u066a)\n"
                    f"❌ هیچ IP فعالی برای تعویض وجود ندارد! لطفاً دستی بررسی کنید.")
                # 🆕 دقیقاً همین حالت (هیچ IP فعالی نمانده، حتی خودِ Core در گامِ قبل جواب نداد)
                # بیشترین نیاز به فعال‌سازیِ یک Standby را دارد.
                if old_default_host:
                    spawn_bg_task(_activate_standby_for_filtered_edge(app, old_default_host))
                return

            # 🐛🔧 رفع باگ واقعی: قبلاً بدون هیچ چکی، «سریع‌ترین IP» (که فقط بر اساس آخرین تست
            # تأخیر انتخاب شده، نه اینکه SSH رویش الان واقعاً زنده است یا نه) به‌عنوان پیش‌فرض
            # ثبت و همهٔ کاربران کورکورانه بهش منتقل می‌شدند. اگر همان IP به هر دلیلی (پورت هنوز
            # درست نشده، سرور تازه اضافه شده و ناقص، و ...) واقعاً SSH زنده نداشته باشد، این یعنی
            # قطعیِ کامل کاربران دقیقاً در بدترین لحظه (وسط یک رخداد فیلترینگ). الان قبل از
            # سوییچ، هر کاندید را با یک چک زندهٔ سبک (بدون رمز) امتحان می‌کنیم و اگر رد شد، سراغ
            # کاندید بعدی می‌رویم؛ فقط وقتی یکی واقعاً جواب داد، سوییچ واقعی انجام می‌شود.
            candidates = [fastest_host] + [h for h in active_hosts if h != fastest_host]
            chosen_host, chosen_detail = None, ''
            for cand in candidates:
                cand_port = await asyncio.to_thread(_db_get_host_ssh_port, cand, 22)
                ok_reach, reach_detail = await _check_ssh_reachable(cand, cand_port)
                if ok_reach:
                    chosen_host = cand
                    break
                log.warning("پایش فیلتر: کاندید %s رد شد (SSH زنده نبود): %s", cand, reach_detail)
                chosen_detail = reach_detail
            if not chosen_host:
                await _notify_admins(app,
                    f"🚨 <b>فیلتر IP تشخیص داده شد، ولی سوییچ خودکار انجام نشد!</b>\n\n"
                    f"📊 کاربران آنلاین: {online_count} از {total_active} ({online_pct:.1f}\u066a)\n"
                    f"❌ هیچ‌کدام از {len(candidates)} IP فعال، اتصال SSH زنده نداشتند (آخرین خطا: {chosen_detail}).\n"
                    f"لطفاً دستی بررسی کنید — سوییچ به یک IP غیرقابل‌اتصال انجام نشد تا کاربران بی‌دلیل قطع نشوند.")
                # 🆕 هیچ IP موجودی زنده نبود — این هم دقیقاً یک موردِ نیاز به فعال‌سازیِ Standby است
                if old_default_host:
                    spawn_bg_task(_activate_standby_for_filtered_edge(app, old_default_host))
                return
            fastest_host = chosen_host
            # تغییر IP پیش‌فرض کل سیستم
            await asyncio.to_thread(_db_set_default_host, fastest_host)
            # انتقال همهٔ کاربران به سریع‌ترین IP
            await asyncio.to_thread(_db_set_all_accounts_host, fastest_host)
            await asyncio.to_thread(_db_mark_ip_switch_now)  # 🆕 شروع دورهٔ خنک‌شدن
            cf_ok, cf_msg = await _update_cloudflare_dns(fastest_host)
            cf_suffix = f"\n\n☁️ <b>وضعیت کلودفلر:</b> {cf_msg}" if cf_ok else f"\n\n⚠️ <b>هشدار کلودفلر:</b> {cf_msg}"
            await _notify_admins(app,
                f"🚨 <b>فیلتر IP تشخیص داده شد و IP تعویض شد!</b>\n\n"
                f"📊 کاربران آنلاین: {online_count} از {total_active} ({online_pct:.1f}\u066a)\n"
                f"🔴 آستانه تشخیص: {threshold:.0f}\u066a\n\n"
                f"✅ سیستم خودکار IP را به <code>{esc(fastest_host)}</code> تغییر داد و همهٔ کاربران منتقل شدند." + cf_suffix + "\n\n"
                f"⚠️ لطفاً وضعیت شبکه را بررسی کنید و در صورت نیاز، IP جدیدی اضافه کنید.")
            # 🆕 سوییچِ بالا فقط یک تسکینِ فوری با یک IP از قبل موجود بود؛ حالا (در پس‌زمینه،
            # بدون معطل‌کردنِ این حلقه) اگر یک Standby سالم ثبت شده باشد، کاربرانِ همان Edgeِ
            # فیلترشده رویش بازسازی و دامنه به آن منتقل می‌شود (طبقِ auto_failover_mode).
            if old_default_host and old_default_host != fastest_host:
                spawn_bg_task(_activate_standby_for_filtered_edge(app, old_default_host))
    else:
        if _filter_detect_low_ticks > 0:
            log.info("پایش فیلتر: وضعیت بهبود یافت (%.1f\u066a) — شمارنده ریست شد.", online_pct)
        _filter_detect_low_ticks = 0

async def _filter_detect_loop(app):
    log.info("🛡 حلقهٔ پایش فیلتر خودکار آغاز شد (بازهٔ چک: %s ثانیه، آستانه: %s\u066a، تایید: %s بار متوالی).",
              FILTER_DETECT_CHECK_INTERVAL_SECONDS, FILTER_DETECT_ONLINE_PCT_THRESHOLD, FILTER_DETECT_CONFIRM_TICKS)
    while True:
        try:
            await _filter_detect_tick(app)
        except Exception:
            log.exception("خطای غیرمنتظره در حلقهٔ پایش فیلتر — دور بعدی ادامه می‌یابد.")
        await asyncio.sleep(FILTER_DETECT_CHECK_INTERVAL_SECONDS)

async def _post_init(app):
    # 🔧 عمداً از asyncio.create_task به‌جای JobQueue استفاده شده تا وابستگی اضافه‌ای
    # (اکستنشن job-queue / APScheduler) به requirements.txt پروژه اضافه نشود.
    app.bot_data['capacity_monitor_task'] = asyncio.create_task(_capacity_monitor_loop(app))
    app.bot_data['hold_activation_task'] = asyncio.create_task(_hold_activation_loop(app))
    app.bot_data['expiry_monitor_task'] = asyncio.create_task(_expiry_monitor_loop(app))
    app.bot_data['ip_pressure_monitor_task'] = asyncio.create_task(_ip_pressure_monitor_loop(app))
    app.bot_data['host_health_task'] = asyncio.create_task(_host_health_loop(app))
    app.bot_data['udpgw_health_task'] = asyncio.create_task(_udpgw_health_loop(app))
    app.bot_data['daily_sales_report_task'] = asyncio.create_task(_daily_sales_report_loop(app))
    app.bot_data['filter_detect_task'] = asyncio.create_task(_filter_detect_loop(app))  # 🆕 V89
    app.bot_data['weekly_accounting_task'] = asyncio.create_task(_weekly_accounting_report_loop(app))

async def _post_shutdown(app):
    # 🔧 رفع باگ «Task was destroyed but it is pending!» که هنگام systemctl stop در لاگ سرور
    # دیده می‌شد: قبلاً هیچ post_shutdown ثبت نشده بود، پس وقتی ربات متوقف می‌شد، تسک پس‌زمینهٔ
    # _capacity_monitor_loop به‌جای لغو تمیز (cancel)، به‌طور ناگهانی توسط event loop نابود می‌شد.
    # این کار عملکردی را خراب نمی‌کرد ولی خطای گمراه‌کننده در لاگ ثبت می‌کرد و می‌توانست در بدترین
    # حالت باعث شود یک دور نیمه‌کارهٔ بررسی/قفل‌کردن اکانت به‌طور ناقص قطع شود.
    # 🐛🔧 رفع باگِ واقعیِ «systemctl stop تا ~۹۰ ثانیه طول می‌کشد و در نهایت با SIGKILL بسته
    # می‌شود»: این تسک («🛰️ حلقهٔ پایش سلامت UDPGW») توی _post_init ساخته می‌شد ولی این‌جا از
    # قلم افتاده بود — پس هیچ‌وقت cancel نمی‌شد و روی asyncio.sleep(...) منتظر می‌ماند، پروسه
    # واقعاً خارج نمی‌شد تا systemd صبرش تمام شود و به‌زور بکشدش (که همان قطعیِ طولانی و نیازِ
    # نماینده‌ها به ورودِ مجدد را رقم می‌زد).
    for key, label in (('capacity_monitor_task', '🛡️ حلقهٔ پایش ظرفیت'), ('hold_activation_task', '⏳ حلقهٔ پایش آنهولد'), ('expiry_monitor_task', '🧹 حلقهٔ پایش انقضا'), ('ip_pressure_monitor_task', '🌐 حلقهٔ پایش فشار IP'), ('host_health_task', '🛡️ حلقهٔ پایش سلامت IPها'), ('udpgw_health_task', '🛰️ حلقهٔ پایش سلامت UDPGW'), ('daily_sales_report_task', '📊 حلقهٔ گزارش روزانهٔ فروش'), ('filter_detect_task', '🛡 حلقهٔ پایش فیلتر خودکار'), ('weekly_accounting_task', '📅 حلقه گزارش هفتگی حسابدار')):
        task = app.bot_data.get(key)
        if task and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
            log.info("%s به‌صورت تمیز متوقف شد.", label)
    # 🆕 تسک‌های یک‌بارهٔ «گزارش خوش‌آمدگویی ۱۰ دقیقه‌ای» هم باید تمیز لغو شوند (اگر ربات درست
    # همان ۱۰ دقیقهٔ اول بعد از یک ورود جدید ادمین خاموش شود).
    for task in app.bot_data.get('welcome_report_tasks', []):
        if task and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
    # 🆕 تسک‌های «نمودار زنده» (یکی به‌ازای هر پیام عکسِ در حال پایش) هم باید تمیز لغو شوند.
    for task in list(app.bot_data.get('live_chart_tasks', {}).values()):
        if task and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

if __name__ == '__main__':
    init_db()
    # 🆕 Persistence: فقط user_data (وضعیت لاگین هر چت) روی دیسک ذخیره می‌شود تا بعد از هر
    # ری‌استارت سرویس، ادمین/نماینده‌ها مجبور به ورود مجدد نشوند. عمداً bot_data/chat_data/
    # callback_data خاموش نگه داشته شده‌اند: bot_data شامل آبجکت‌های asyncio.Task زندهٔ حلقه‌های
    # پس‌زمینه (پایش ظرفیت، پایش فشار IP) است که اصلاً قابل pickle‌شدن نیستند و فعال‌کردن
    # persistence رویشان باعث خطا/کرش می‌شد.
    persistence = PicklePersistence(
        filepath=PERSISTENCE_PATH,
        store_data=PersistenceInput(bot_data=False, chat_data=False, user_data=True, callback_data=False))
    app = ApplicationBuilder().token(TOKEN).persistence(persistence).post_init(_post_init).post_shutdown(_post_shutdown).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, text_handler))
    app.add_handler(MessageHandler(filters.PHOTO, photo_handler))
    app.add_handler(CallbackQueryHandler(callback_handler))
    app.add_error_handler(error_handler)
    print(f"🏷️ نسخهٔ در حال اجرا: {BOT_VERSION_TAG}")
    print("🚀 سیستم تجاری NeVeL (V24 Enterprise) با سیستم کیف پول و رسید فعال شد.")
    if MATPLOTLIB_AVAILABLE: print("📈 ماژول رسم نمودار فروش (Matplotlib) فعال است.")
    else: print("⚠️ ماژول رسم نمودار غیرفعال است (جهت فعال‌سازی: pip3 install matplotlib)")
    print(f"🛡️ پایش تخطی ظرفیت اکانت‌ها فعال است (هر {CAPACITY_CHECK_INTERVAL_SECONDS}s چک، آستانه {CAPACITY_SUSPEND_AFTER_MINUTES} دقیقه).")
    print(f"🌐 پایش خودکار فشار IP فعال است (هر {IP_PRESSURE_CHECK_INTERVAL_SECONDS}s چک، آستانهٔ هشدار {IP_PRESSURE_WARN_PCT}٪، بالانس خودکار بعد از {IP_PRESSURE_AUTOBALANCE_AFTER_HOURS} ساعت بدون واکنش).")
    print(f"🛡️ پایش سلامت IPها فعال است (هر {HOST_HEALTH_CHECK_INTERVAL_SECONDS}s چک، غیرفعال‌سازی خودکار بعد از {HOST_HEALTH_FAIL_THRESHOLD} شکست متوالی).")
    print(f"🛡 پایش فیلتر خودکار فعال است (هر {FILTER_DETECT_CHECK_INTERVAL_SECONDS}s چک، آستانه پیش‌فرض {FILTER_DETECT_ONLINE_PCT_THRESHOLD}\u066a، تایید {FILTER_DETECT_CONFIRM_TICKS} بار متوالی). [از منوی سرویس IP قابل تنظیم است]")
    app.run_polling()