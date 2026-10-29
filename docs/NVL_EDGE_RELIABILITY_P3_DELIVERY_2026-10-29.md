# NVL — فاز سوم: تحویل ویزارد Edge دستی با DNS خودکار Cloudflare

**تاریخ:** 2026-10-29  
**وضعیت:** **SOURCE_MERGED** — [PR #239](https://github.com/DenaSon/nvl-bot/pull/239)، Squash Merge در `master`: `bd468e8b1795a3c826a9de818078de726361ffa6` (2026-10-29). سه Workflow Python / Legacy Core / Edge stage موفق؛ ۳۰۶۹ تست در بسته Root موفق (۳ مورد skipped)؛ Review Thread باز: صفر. **CORE_DEPLOYMENT_NOT_VERIFIED / PRODUCTION_ACCEPTED=NO؛ هیچ VPS واقعی به‌موجب این PR نصب یا منتقل نشده است.**
**قرارداد:** [فاز سوم تأییدشده](NVL_EDGE_MANUAL_CLOUDFLARE_WIZARD_PHASE3_2026-10-29.md) و [نقشه پنج‌فازی](NVL_EDGE_RELIABILITY_MANUAL_RECOVERY_5_PHASE_PLAN_2026-10-29.md).

## خروجی اجرایی

**مسیر:** «برنامه‌ها → مدیریت Edge → افزودن دستی (اضطراری)». 
- فرم امن HTTPS/Telegram WebApp برای IP و پورت مدیریت SSH، سپس تأیید Host Key مستقل و فرم جداگانه ورود رمز. ورود رمز به پیام متنی تلگرام ممنوع است.
- تمام صفحات وضعیت، Preview، تأیید انتقال و خطای ویزارد **Native Rich Messages** هستند، نه پیام HTML یا InlineKeyboard قدیمی؛ فرم HTTPS صرفاً برای ورود اطلاعات محرمانه حفظ شده است. اعلان‌های پس‌زمینه نصب نیز Rich هستند.
- `ManualFormStore` فقط در حافظه پروسه، nonce/TTL=۱۸۰ ثانیه، اعتبارسنجی HMAC `initData` تلگرام، مالک/گفتگوی ثابت، مصرف یک‌باره، بدون ذخیره رمز در SQLite/Pickle/ارسال پیام/توکن URL. Listener فقط `127.0.0.1` روی پورت اختصاصی و پشت HTTPS Reverse Proxy است.
- ثبت عملیات و شواهد مستقل در `manual_edge_operations` و `manual_edge_events`، با `provider='manual'` و `provider_instance_id IS NULL`. **هیچ رسید خرید Cloudzy، Provider Server ID یا عملیات Cloudzy API ساخته نمی‌شود.**
- Reuse از Legacy Installer موجود، با اتصال روی **همان پورت مدیریت SSH داده‌شده**، Host Key پین‌شده، عدم بازکردن ورود Root با رمز و نصب کلید مدیریت Core. نصب non-idempotent پس از شروع `INSTALLING` بدون شواهد مجدداً راه‌اندازی نمی‌شود.
- `EDGE_READY → STANDBY`: probe واقعی SSH management/customer + WG + NAT و ثبت جداگانه Standby در transaction محافظت‌شده؛ DNS، Default و حساب‌های مشتری تا آن زمان بدون تغییر.
- `STANDBY → ROUTING`: preview همراه تأیید مدیر، ثبت Job در **همان CZ07 durable queue**؛ **همان** `CloudflareExactDNS.snapshot()/set_all()/postcheck` و 6G lease، route CAS، checkpoint و Batchهای CZ04B. مسیر Cloudzy برای خرید/VPS حذف دست‌نخورده است. Provider verification برای Cloudzy روی پذیرش اولیه باقی است اما **برای manual هیچ Cloudzy GET/POST نداریم**.
- `VERIFYING → MOVED`: اثبات مسیر زنده، تکمیل فنی و نمایش رله فعال؛ `DONE` تا ثبت مستقل CREATE/RENEW/ISP client witness ممنوع. Edge قبلی حذف نمی‌شود.

## فایل‌های تحویل

- `manual_edge_secure_form.py`: HTTPS-terminated WebApp intake، validation و secret one-use.
- `manual_edge_journal.py`: جدول و تاریخچه دستی با CAS، گیت Standby و نصب Core WG.
- `manual_edge_identity.py`: هویت پین‌شده مستقل Manual/Cloudzy و `manual:<op>` صرفاً مرجع داخلی، نه Provider ID.
- `manual_edge_wizard.py`: ویزارد فارسی و Callbackهای فقط مدیر؛ صفحات با **Rich Messages** و بدون HTML fallback.
- `manual_edge_rich.py`: تبدیل صفحه‌های مدیریتی به `InputRichMessage` استاندارد Bot API 10.3؛ CTAها با `RichMessageButton` و دریافت رمز با دکمه Rich Web App؛ ارسال/ویرایش از `RichBotAPI` موجود، فقط یک کارت برای هر نشست و جلوگیری از بازپخش پیام با نتیجه نامطمئن.
- `tests/test_manual_edge_rich_phase3.py`: تست ساختار Rich، دکمه Web App امن، مجوز Callbackها، ارسال/ویرایش و نبود مسیر جایگزین HTML.
- `cloudzy_cz04b.py`، `cloudzy_cz07_queue.py`: استفاده مشترک از route/DNS/6G و Batch، بدون جعل رسید خرید.
- `cloudzy_quick_edge.py`: جلوگیری از تداخل هم‌زمان نصب Cloudzy و Manual روی IP/WG.
- `cloudzy_admin_panel.py`: دو دکمه جدا «افزودن با Cloudzy» و «افزودن دستی».
- `bot_final_v49-2.py`: سیم‌کشی ویزارد، اتصال پورت مدیریت، URL فرم و Flagهای محافظتی.
- `tests/test_manual_edge_phase3.py` و رگرسیون Manual داخل `tests/test_cloudzy_cz04b.py`.

## مرزهای امنیت و عدم تداخل

1. برخورد IP مقصد با `host_pool` یا رسید Cloudzy قبلی رد می‌شود. هیچ Cloudzy VPS برای manual حذف/تغییر نمی‌کند.
2. نصب WireGuard روی Core **منبع مشترک** است؛ Manual `INSTALLING/INSTALL_HOLD` یا Cloudzy `PROVISIONING/HOLD_PROVISION` مانع نصب هم‌زمان می‌شوند؛ این محافظ فقط هنگام اجرای Installer مشترک است. قفل‌های DNS/route/6G همان محافظ‌های قدیمی‌اند.
3. **Cloudflare API الزامی و خودکار** است؛ با قطع/عدم‌قطعیت PUT مسیر fail closed و نیازمند بررسی می‌شود. گزینه تغییر DNS دستی وجود ندارد.
4. رمز فقط در RAM همان پروسه تا زمان مصرف/انقضا نگهداری می‌شود؛ نمی‌توان پاک‌سازی قطعی رشته Python از حافظه را تضمین کرد. خروجی خطای خام SSH در مسیر Manual برای UI ممنوع است.
5. برای Host Key ناشناخته، تأیید اثرانگشت از کنسول مستقل VPS قبل از ورود رمز لازم است. اگر Host Key تغییر کند، نصب رد می‌شود.
6. در صورت Crash/Timeout هنگام نصب غیر idempotent، وضعیت `INSTALL_HOLD` است؛ نصب مجدد خودکار **عمداً ممنوع**. Recovery از مرحله نصب نیمه‌تمام و Rollback پیچیده، گام Hardening فاز چهارم است؛ بدون شواهد، قفل باز نمی‌شود.

## راهنمای انتشار (بدون تغییر خودکار Production)

۱. `master` و SHA نسخه نصب‌شده Core را تطبیق دهید؛ ابتدا فازهای ۱ و ۲ باید در Core هم‌نسخه باشند. بکاپ آنلاین SQLite + `PRAGMA quick_check` + snapshot DNS و WireGuard/host_pool/CZ07/6G و تست بازیابی بکاپ الزامی.

۲. یک نام میزبان **HTTPS اختصاصی** برای فرم امن با reverse proxy محدود به `127.0.0.1:3107` آماده کنید. تنها `/manual-edge/form` و `/manual-edge/api/submit` به listener داخلی Route شوند؛ دسترسی مستقیم عمومی به پورت ۳۱۰۷ مسدود بماند. Proxy یا Access Log نباید Query ticket، body password، Authorization یا Telegram initData را ذخیره کند. HTTPS معتبر و محدودیت نرخ در Proxy الزامی.

۳. بعد از تست روی Edge **آزمایشی و بدون کاربر** Flagهای زیر را تنظیم کنید:

```dotenv
NVL_EDGE_MANUAL_ENABLED=1
NVL_MANUAL_FORM_PUBLIC_URL=https://<secure-form-origin>
NVL_MANUAL_FORM_PORT=3107
NVL_CZ04B_ENABLE=1
NVL_CZ07_ENABLE=1
```

Cloudflare zone/token با سطح دسترسی محدود همان تنظیمات موجود NVL است. این فرم به Cloudzy Token هیچ نیاز ندارد. **فقط بعد از تست اسکریپت Installer، SSH identity و محافظ‌های اصلی با Edge آزمایشی** فعال شود. لازم نیست Cloudzy Token حذف شود تا عدم‌وابستگی تأیید گردد؛ تست mock provider forbidden اجرا شود.

۴. Smoke-test: فرم IP/port → تأیید fingerprint از کنسول → ورود رمز → نصب → Standby بدون تغییر DNS → Preview انتقال → Cloudflare خودکار → batch → MOVED → شاهد مستقل سرویس. اگر خطا شد، از state واقعی گزارش بگیرید؛ عملیات خرید جدید، نصب مجدد یا تغییر دستی DNS خودسرانه نکنید.

## آزمون‌های ضروری

- عدم پذیرش IPهای خصوصی، چندپخشی، رزرو و هویت مدیریتی نامعتبر؛ یک‌بارمصرف بودن رمز، HMAC، TTL و عدم ذخیره SQLite.
- Edge دستی بدون Cloudzy receipt در Standby ثبت شود؛ جلوگیری از اشتباه Provider ID.
- `_run_route` و `_run_users` دستی با provider stub `raise AssertionError` و Cloudflare fake؛ موفقیت مسیر 6G/CAS و عدم تماس Cloudzy.
- Cloudflare جزئی/قطع: در صورت rollback موفق، DNS/Default به مبدا برگردند، کاربر منتقل نشود؛ در حالت نامطمئن عملیات HOLD بماند.
- Shared WG نصب، Host collision، K2 محافظت‌شده، Worker/callback تکراری، timeout و Resume.
- تست `manual_edge_rich`: دکمه Web App با `web_app`، نمایش RTL و callbackهای فارسی در Rich blocks؛ بدون `parse_mode=HTML`، `reply_markup` یا تکرار پیام در خطای ارسال نامعلوم.
- اجرای کامل CI (Python checks + Legacy Core Migration Safety + Edge egress stage-only) قبل از Merge. **Merge ≠ Deploy**.

**تعهد محدود:** این فاز در Source توسعه یافته است؛ تا زمانی که CI و آزمون روی Edge واقعی انجام نشده‌اند، نباید «آماده Production» خوانده شود.
