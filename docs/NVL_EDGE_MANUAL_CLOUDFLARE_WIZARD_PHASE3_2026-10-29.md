# NVL — قرارداد فاز سوم: ویزارد افزودن دستی Edge و انتقال خودکار با Cloudflare

**تاریخ:** 2026-10-29  
**وضعیت:** تصمیم معماری و معیار پذیرش؛ **پیاده‌سازی نشده است**.  
**دامنه:** مسیر دستی اضطراری از «برنامه‌ها» تا Relay فعال، **بدون حتی یک تماس با Cloudzy API**؛ تغییر DNS **صرفاً خودکار از Cloudflare API**.  
**مبنای پیاده‌سازی:** [برنامه پنج‌فازی](NVL_EDGE_RELIABILITY_MANUAL_RECOVERY_5_PHASE_PLAN_2026-10-29.md)؛ فازهای ۱ و ۲ قبلاً در Source مرج شده‌اند، اما Merge مساوی استقرار Core نیست.

## ۱. تصمیم‌های نهایی بدون ابهام

1. ویزارد از «برنامه‌ها → مدیریت Edge → افزودن دستی» آغاز می‌شود و **همه مراحل تا Relay فعال را در یک پرونده ادامه‌پذیر** نمایش می‌دهد؛ مسیر دستی در میانه کار به منوهای Cloudzy هدایت نمی‌شود.
2. تنها **Cloudzy API ممنوع است**. Cloudflare API برای خواندن، مقایسه، تغییر خودکار رکوردهای A و تأیید تغییر DNS **الزامی** است. **هیچ مرحله‌ای برای DNS دستی یا تغییر از پنل Cloudflare وجود ندارد.** اگر Cloudflare قطع باشد، نصب/Standby ممکن است کامل شود ولی Cutover به حالت «در انتظار اتصال DNS» می‌رود؛ کاربر به انجام تغییر دستی هدایت نمی‌شود.
3. **دو راه ورود، یک موتور اجرا:** خرید Cloudzy یا معرفی IP دستی، هر دو پس از ثبت هویت معتبر وارد قرارداد مستقل Edge Registry + Verify + Standby می‌شوند و از همان موتور Route/Cloudflare/6G/Batch/CAS/Acceptance استفاده می‌کنند. **کد انتقال کپی نشود.**
4. Edge دستی `provider='manual'` دارد و یک `manual_edge_operation_id` مستقل و fingerprint SSH معتبر؛ نباید رسید خرید `cloudzy_edge_operations`، `cloudzy_cz06_runs`، `provider_server_id` ساختگی یا پذیرش Cloudzy تولید شود. عملیات Cloudzy existing بدون تغییر منطق خرید/حذف باقی بماند.
5. **تداخل صفر در هویت و پرونده‌ها:** هر IP / SSH identity تنها به یک Edge Registry معتبر قابل انتساب است. Manual و Cloudzy می‌توانند نصب‌های مستقلی روی IPهای متفاوت داشته باشند؛ اما یک IP مشترک، install هم‌زمان متعارض، تغییر مسیر/DNS هم‌زمان و انتقال روی منابع مشترک با lock واقعی رد شوند. HOLD تاریخی نامرتبط هیچ فلو را قفل نکند.
6. مسیر دستی نباید `CloudzyService`، `get_server`، `list_servers`، خرید/حذف Cloudzy یا وابستگی غیرمستقیم از `CZ04A/CZ04B/CZ07` صدا بزند. **آزمون end-to-end با توکن Cloudzy حذف‌شده و provider stub منفجرشونده الزامی است**.
7. صفحه‌های کاربر **فارسی کوتاه**؛ نام فاز، CZ، code، stacktrace، نام ماژول و جزئیات توسعه فقط در «جزئیات فنی»؛ در صفحه اصلی هر مرحله فقط عنوان، IP/وضعیت/پیشرفت معتبر، یک Guide Tip و اقدام اصلی/انصراف.

## ۲. تجربه ویزارد (یک پرونده و شناسه پایدار)

```text
برنامه‌ها → مدیریت Edge
  ├─ افزودن با Cloudzy         (مسیر موجود؛ جدا)
  ├─ افزودن دستی (اضطراری)     (ویزارد جدید)
  ├─ سرورهای من
  └─ عملیات و بازیابی

افزودن دستی
   ۱. مشخصات: IP عمومی + پورت SSH مدیریت + رمز ورود [فرم HTTPS کوتاه‌عمر]
       ↓ بررسی IP غیرتکراری، Core و مجوز مدیر
   ۲. اتصال و تأیید هویت: OS/SSH root یا sudo + اثرانگشت Host Key
       ↓ تأیید مستقل از کنسول VPS، قبل از ارسال رمز
   ۳. نصب: SSH bootstrap → کلید اختصاصی محدود → نصب WG/Relay/ports/NAT
       ↓ چک مرحله‌ای، بدون اجرای مجدد غیرایمن
   ۴. آماده Standby: WG/Core handshake + admin/customer ports
       ↓ ثبت Edge دستی، بدون تغییر DNS/default/users
   ۵. بررسی انتقال: Source → Target، DNS snapshot، 6G، حساب‌ها، تست مشتری
       ↓ تأیید جداگانه مدیر + nonce کوتاه‌عمر
   ۶. تغییر مسیر خودکار: Cloudflare exact A records (GET/CAS/PUT/postcheck)
       ↓ DNS و Default CAS، با حفظ Edge قدیم و شواهد
   ۷. انتقال Batchهای کاربران: حداکثر ۲۰۰ حساب/Batch با Journal
       ↓ Checkpoint/Stop/Resume؛ بدون Cloudzy GET
   ۸. رله فعال: Transport MOVED پس از کنترل واقعی شبکه/حساب‌ها
       ↓ پذیرش نهایی سرویس (CREATE/RENEW/ISP E2E) جدا از MOVED
```

- پیش از Standby **هیچ تغییر مسیر مشتری رخ ندهد**؛ در مرحله Cutover، تغییر Default ممکن است قبل از تمام‌شدن انتقال Batchها رخ دهد. بنابراین UI در این بازه «مسیر روی سرور جدید، انتقال حساب‌ها در جریان» را نشان می‌دهد، نه «همه کاربران منتقل شدند».
- پس از `MOVED` سرور جدید **رله فعال** است؛ تا شواهد واقعی CREATE/RENEW/ISP ثبت نشده، وضعیت پذیرش کامل `DONE` ادعا نشود. سرور قبلی به‌صورت خودکار خاموش یا حذف نمی‌شود.
- «توقف پس از مرحله جاری»، «ادامه امن»، «لغو پرونده بدون حذف سرور» فقط در وضعیت‌هایی که واقعاً مجازند؛ برای DNS با اثر نامطمئن **تلاش مجدد کورکورانه، rollback اتوماتیک یا آزادسازی قفل ممنوع**.

## ۳. تفکیک فنی آداپترها و موتور مشترک

```text
Cloudzy purchase adapter ─────┐
                              ├→ Edge Registry / identity / capabilities
Manual SSH adoption adapter ──┘     [verified host identity & permissions]
                                       │
                           Shared Legacy Provision / Verify
                                       │
                              Standby registration
                                       │
       Shared guarded route (6G + CloudflareExactDNS + route CAS)
                                       │
                     Shared CZ07-style checkpointed SSH batches
                                       │
                               MOVED / business E2E
```

**محدوده استخراج مشترک واقعی:** `cloudzy_quick_edge.py` هم‌اکنون `provision/verify`های Legacy دارد، اما قبل و بعد از نصب Cloudzy `get_server` انجام می‌دهد؛ فقط بدنه مستقل **provision/verify** پس از استخراج صحیح قابل reuse است. `cloudzy_cz04a.py` در ثبت Standby، `cloudzy_cz04b.py` در انتخاب/ثبت route و تایید default/receipt، و `cloudzy_cz07_queue.py` در candidate/reserve/transport به `provider='cloudzy'` و receiptهای CZ03/CZ06 سخت وابسته‌اند؛ **باید یک `EdgeIdentityVerifier` قابل تزریق طراحی و تست شود** تا دستی را با هویت SSH/ثبت محلی و Cloudzy را با receipt خرید معتبر بررسی کند. **نباید برای عبور از Guard از شناسه Provider جعلی استفاده شود.** مسیر Cloudflare DNS موجود در `cloudzy_cz04b_dns.py` برای هر دو مشترک می‌ماند.

**Legacy installer:** `setup_edge_relay.sh` را همان‌طور خام و چندبار اجرا نکنید: قواعد iptables آن فعلاً با `-A` اضافه می‌شوند و اجرای دوباره می‌تواند Rule تکراری بسازد؛ اسکریپت WG را restart می‌کند و کلید می‌سازد. باید عملیات به Checkpointهای قابل ممیزی و تکرارپذیر تقسیم شود (probe/read-only قبل از commit، اثر هر مرحله فقط یک‌بار، repair مرحله‌ای)، پورت SSH مدیریت را حفظ کند و Core/Edge WG address unique را اتمیک رزرو کند. فقط تغییردهی idempotentِ اثبات‌شده، یا تعمیر مشخصِ با تأیید مدیر مجاز است.

**SSH secret security:** ورود رمز فقط در یک فرم HTTPS Web App متصل به همان مدیر؛ nonce/HMAC/Telegram initData محلی، TTL کوتاه، CSRF/rate-limit، Password تنها در حافظه و بدون چاپ، DB/log/Telegram callback یا Git. Host Key باید قبل از احراز هویت رمز و اجرای نصب با مرجع مستقل تأیید شود. پس از نصب کلید مدیریتی محدود مخصوص NVL مبنای ادامه و بازیابی قرار می‌گیرد؛ رمز دائماً لازم نیست.

## ۴. وضعیت عملیات و ایزولاسیون

**Manual journal مجزا:** `manual_edge_operations` به همراه `manual_edge_events` و ledger نصب/Cutover/Batch. خرید و حذف Cloudzy فقط `cloudzy_edge_operations` و guard خودشان را دارند. برای manual هیچ شماره فاکتور/Cloudzy instance id نوشته نشود.

**Locks و نگهداری:**
- `host/IP + fingerprint`: منع reuse در هر دو مسیر، حتی اگر پرونده دیگری HOLD شده؛ بررسی مالکیت/اثر واقعی قبل از جایگزینی.
- `wg_peer + tunnel_ip`: جلوگیری از تداخل tunnel/routing.
- `core_route + Cloudflare record set + 6G lease`: فقط یک Cutover مؤثر در هر لحظه.
- `source-target + cohort`: نقل‌وانتقال با checkpoint و CAS؛ حساب جدید مقصد خارج از cohort اولیه.
- قفل `install` محدود به سرور هدف؛ Cloudzy `HOLD` روی سرور دیگر قفل مسیر Manual نیست؛ `HOLD` Manual نیز Cloudzy مستقل را قفل نمی‌کند.

**Cloudflare DNS:** `CloudflareExactDNS.snapshot()` همان رکوردهای A مشخص را با ID/IP/TTL و `proxied=false` تأیید می‌کند، سپس `set_all()` با compare-before-write و postcheck آنها را تغییر می‌دهد. خطای HTTP/Timeout یا اثر ناقص `DNS_UNCERTAIN`، هیچ انتقال کاربری را شروع نمی‌کند؛ رسید اثر خارجی و وضعیت 6G را نگه می‌دارد. **بدون fallback دستی و بدون ادعای موفقیت کاذب.**

## ۵. ملاک پذیرش و تست‌های الزامی

| سناریو | ملاک |
|---|---|
| Cloudzy token از env حذف/نامعتبر است | Manual تا Standby و Relay فعال با Cloudflare سالم کار کند؛ **صفر Cloudzy calls** |
| Cloudflare موجود و درست | همان adapter و همان رکوردهای exact تغییر خودکار و postcheck شوند |
| Cloudflare API Timeout/partial write | انتقال شروع نشود؛ recovery از همان intent؛ **بدون دستور DNS دستی** |
| manual و cloudzy IP متفاوت | آماده‌سازی مستقل، inventory هر دو معتبر، هیچ receipt یا lock مشترک بی‌دلیل ساخته نشود |
| manual و cloudzy IP یکسان | تضاد ثبت و عملیات نصب، **قبل از SSH write** رد شود |
| نصب مجدد، restart، callback تکراری | هیچ iptables/WG duplicate یا provisioning غیر idempotent |
| SSH Host Key عوض شده/رمز نامعتبر | توقف فارسیِ اقدام‌پذیر؛ هیچ نصب یا پسورد در log |
| بعد از Standby و قبل از تأیید انتقال | DNS/default/حساب‌ها دست‌نخورده |
| 468=200+200+68 با یک خریدار تازه مقصد | cohort اولیه مستقل؛ Batch تکراری صفر و همه حساب‌ها در هدف |
| خطای NAT/WG/6G/DNS هنگام هر Batch | توقف امن، عدم انتقال ناسازگار |
| پایان انتقال با مشتری واقعی تأیید نشده | MOVED در صورت کنترل فنی؛ DONE ممنوع؛ سرور قدیم حفظ |
| قطع Cloudzy هنگام نصب/تغییر DNS/انتقال | هیچ تأثیری بر مسیر manual ندارد؛ تست spy/assertion در تمام stack |

## ۶. مرزبندی فازهای باقی‌مانده

**فاز ۳ (End-to-end Manual Wizard):** پیاده‌سازی **همین مسیر کامل** از IP/SSH/Password تا نصب/Standby و Cutover خودکار Cloudflare و انتقال کاربران/Relay فعال. ویزارد ساده و فارسی باید از همین فاز قابل استفاده باشد؛ این کار صرفاً نمایش فرم نیست.

**فاز ۴ (Hardening & Recovery):** تست خرابی DNS جزئی، قطع Worker در نصب/Batch، fencing/race/rollback مدیریتی، تکرار فرمان‌ها، اجرای هم‌زمان دستی و Cloudzy و مقابله با ناسازگاری واقعی سرور. «DNS دستی» در این فاز اضافه نمی‌شود.

**فاز ۵ (UX/Release):** پالایش رابط، فهرست عملیات و راهنمای خطاهای فارسی، پوشش regressions، آزمایش واقعی با Edge تست و انتشار مرحله‌ای با بکاپ و rollback.

**این سند تنها تصمیم معماری است؛ هیچ Source، DNS، سرور یا حساب زنده به موجب آن تغییر نکرده است.**
