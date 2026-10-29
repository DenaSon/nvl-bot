# NVL — گزارش فاز ۱: خواندن مقاوم Cloudzy و محدودسازی قفل‌ها

**تاریخ:** 2026-10-29  
**وضعیت:** تغییرات Source در PR #236؛ اجرای CI و Merge باید مستقل تأیید شوند. **عدم استقرار Production**.  
**سند مبنا:** [برنامه پنج‌فازی](NVL_EDGE_RELIABILITY_MANUAL_RECOVERY_5_PHASE_PLAN_2026-10-29.md).  
**هدف:** قطع تبدیل شکست موقت GET و عملیات نامرتبط به بن‌بست در خرید و آماده‌سازی Edge، بدون تغییر وضعیت کاربران، DNS و 6G.

## ۱. شواهد و علت انتخاب راهکار

در PowerShell و Core، درخواست‌های `GET /services/{id}` و `GET /regions` به `dash.cloudzy.com/api/v1` گاهی با وجود تکمیل DNS/TCP/TLS در کمتر از ۵۰ میلی‌ثانیه، تا ۱۵/۳۰/۴۵ ثانیه هیچ پاسخ HTTP ندادند. درخواست‌های موفق معمولاً زیر یک ثانیه بودند. این داده‌ها منشأ قطعی خطا در Cloudflare یا Backend را ثابت نمی‌کنند؛ افزایش timeout راه‌حل اصلی انتخاب نشد.

در Source:
- `cloudzy_service.py` برای GET یک timeout ۱۵ ثانیه‌ای بدون Retry داشت.
- `cloudzy_edge_one_unfinished` در CZ03 یک index سراسری روی تمام رسیدهای باز بود؛ `CREATE_UNCERTAIN` و `HOLD_PROVISION` خرید بعدی مستقل را مسدود می‌کرد.
- `cloudzy_cz06_one_open` و `cloudzy_cz04a_one_pending` قفل‌های سراسری بودند.
- بخشی از CZ04B/CZ07 بدون توجه به Host هدف، وجود هر پرونده CZ04A نیمه‌تمام را مانع انجام عملیات می‌دانست.

## ۲. تغییرات پیاده‌سازی‌شده در Source

### CloudzyService

`cloudzy_service.py`:
- `GET/HEAD` به‌صورت پیش‌فرض حداکثر **دو تلاش** با timeout هر تلاش **۱۵ ثانیه** و وقفه پیش‌فرض **۲۵۰ میلی‌ثانیه** دارد؛ سقف کل برابر جمع زمان تلاش‌ها و وقفه محدود می‌شود. `read_max_attempts` در بازه ۱ تا ۳ قابل تنظیم است.
- فقط شکست شبکه/Timeout و کدهای HTTP `429,500,502,503,504` قابل Retry هستند؛ 401/403/404، JSON نامعتبر و عدم تطابق هویت مجوز Retry ندارند.
- درخواست‌های پولی و تغییر‌دهنده (`POST/PATCH/DELETE`) **هرگز Retry خودکار نمی‌شوند** و semantics نتیجه نامعلوم و idempotency key حفظ شده‌اند.
- `CloudzyReadError` با `kind` و `attempts` به‌عنوان زیرنوع `CloudzyError` اضافه شده تا مصرف‌کننده‌های قبلی نشکنند.
- لاگ امن: `CLOUDZY_READ result=... route=... attempt=... latency_ms=... code=...` بدون Authorization، شناسه VPS، query string و متن خام exception؛ داده‌های حساس موجود در token/exception فقط در حافظه باقی می‌مانند.

**محدودیت:** Retry یک لایه تحمل خطای خواندن است؛ هیچ تضمینی نمی‌دهد API همیشه پاسخ دهد. در صورت دو شکست متوالی، خطای واقعی به مصرف‌کننده برمی‌گردد. خطای احراز هویت bypass نمی‌شود.

### قفل خرید/آماده‌سازی

`cloudzy_quick_edge.py`:
- حذف index سراسری قدیمی `cloudzy_edge_one_unfinished` و جایگزینی با `cloudzy_edge_active_owner_v2` روی `(actor_id,chat_id)`، فقط برای وضعیت‌های اجرای فعال `CREATING,CREATED,WAITING,PROVISIONING`.
- `HOLD_*`، `CREATE_UNCERTAIN` و انتظار تأیید دستی Host Key دیگر مالک قفل خرید سراسری نیستند. سوابق تاریخی، hostname و idempotency key تغییری نمی‌کنند؛ هر خرید مستقل همچنان تأیید جداگانه لازم دارد.
- `reserve()` داخل `BEGIN IMMEDIATE` فقط عملیات فعال همان مدیر و گفتگو را کنترل می‌کند. هر رسید id/hostname/idempotency یکتای خود را دارد.

`cloudzy_cz06_orchestrator.py`:
- index قدیمی `cloudzy_cz06_one_open` حذف و `cloudzy_cz06_active_owner_v2` برای `PURCHASING,WAITING_PROVIDER,INSTALLING,STANDBY_VERIFYING`، به‌ازای مدیر و گفتگو، ایجاد شده است.
- وضعیت `HOLD` و تأیید دستی `HOSTKEY_PENDING` عملیات مستقل را مسدود نمی‌کند.

`cloudzy_cz04a.py`:
- index سراسری `cloudzy_cz04a_one_pending` با `cloudzy_cz04a_pending_per_vps_v2` جایگزین شده است: هر `provider_id` یک عملیات نیمه‌تمام.
- بررسی عملیات نامشخص و Reserve برای همان VPS انجام می‌شود؛ HOLD یک VPS دیگر تأثیر ندارد.

`cloudzy_cz04b.py` و `cloudzy_cz07_queue.py`:
- بررسی وجود CZ04A نیمه‌تمام برای Cutover، آغاز انتقال، Recovery و بستن Transport به **host مبدأ/مقصد همان عملیات** محدود شده است. قفل واقعی `6G`، DNS/default CAS، هویت SSH و کنترل حذف VPS مقصد همچنان برقرار است.
- **هیچ GET داخل Batch حذف نشده**؛ این تغییر طبق برنامه به فاز ۲ تعلق دارد.

## ۳. سازگاری و حفاظت از داده‌های Production

- این PR **هیچ داده موجودی را در زمان Merge تغییر نمی‌دهد**. `DROP INDEX/CREATE INDEX` روی دیتابیس واقعی هنگام اولین `initialize()` بعد از استقرار رخ می‌دهد؛ اجرای آن باید با بکاپ و تطبیق دقیق نسخه انجام شود.
- Migrationهای index در محدوده transaction اتصال SQLite انجام می‌شوند؛ در صورت خطای SQLite باید عملیات متوقف و علت بررسی شود، نه اینکه قفل قبلی به‌صورت دستی پاک شود.
- **محدودیت Rollback:** پس از ایجاد چند operation موازی یا HOLD تاریخی، نسخه قبلی با unique index سراسری ممکن است هنگام startup دوباره نتواند schema را بسازد. بنابراین Rollback پس از استفاده از schema جدید نیازمند بررسی Live DB و برنامه سازگاری مستقل است؛ روی Production بدون بررسی نسخه قدیمی را جایگزین نکنید.
- یک `CREATING` واقعاً اجراشده برای همان مدیر هنوز تا تبدیل به وضعیت قابل رسیدگی قفل می‌ماند؛ در این فاز lease/heartbeat و بسته‌شدن Jobهای نیمه‌تمام پیاده نشده است. این موضوع در فاز ۲/۵ باید حل شود.
- `CZ07 HOLD` جاریِ حادثه `a0b997e06a92ca35` **با این Patch بسته نمی‌شود**. شمارش واقعی ۴۶۹ کاربر روی IP جدید و بررسی اتصال اپراتور به‌جای تأیید اداری Job تلقی نمی‌شود. بازیابی Journal و تفکیک cohort/حساب جدید هدف فاز ۲ است.

## ۴. تست‌های هدفمند و ممانعت از رگرسیون

- Timeout یک GET سپس ۲۰۰: دقیقاً ۲ بار GET؛ بدون POST.
- Timeout دوگانه: پایان با `CloudzyReadError` و `attempts=2`.
- HTTP 503 سپس ۲۰۰: Retry؛ HTTP 401/403/404: بدون Retry.
- درخواست paid POST پس از Timeout: یک‌بار ارسال و نتیجه `CloudzyUncertainError`، بدون تکرار پولی.
- لاگ‌ها فاقد توکن و متن خام خطای شامل اطلاعات حساس باشند.
- دو اپراتور می‌توانند خریدهای مستقل داشته باشند؛ خرید جدید همان اپراتور هنگام `CREATING` دوم رد می‌شود.
- `CREATE_UNCERTAIN` و `HOLD_PROVISION` قدیمی، خرید مستقل بعدی را قفل نمی‌کنند.
- مهاجرت index سراسری سابق به v2، بدون حذف رسید HOLD قدیمی.
- `CZ06` HOLD قدیمی مانع فعال‌شدن run جدید نباشد؛ اجرای هم‌زمان برای همان صاحب جلوگیری شود.
- CZ04A HOLD روی VPS غیرمرتبط مانع Standby هدف دیگر نباشد؛ عملیات باز روی همان VPS همچنان مسدود است.
- تست‌های موجود CZ03/04A/04B/06/07/6G، Legacy و Egress در CI باید سبز شوند.

## ۵. چک‌لیست پیش از انتشار روی Core

1. بازخوانی commit SHA واقعی از GitHub و `master`؛ صرف Merge نشان‌دهنده انتشار نیست.
2. Snapshot read-only از `cloudzy_edge_operations`, `cloudzy_cz06_runs`, `cloudzy_cz04a_actions`, `cloudzy_cz04b_operations`, `cloudzy_cz07_jobs`، index SQL، `host_pool`، `settings` و تعداد حساب‌های فعال؛ شناسایی Workerهای در حال اجرا.
3. بکاپ SQLite با ابزار Backup API، نسخه تست‌شده قابل بازیابی و نسخه فایل‌های Python روی Core. هیچ استقرار در میانه خرید/نصب/انتقال فعال.
4. بازبینی سازگاری Schema با هر سه index جدید و مسیرهای legacy؛ برنامه Rollback مخصوص Schema بعد از تغییر حالت.
5. انتشار کد و راه‌اندازی کنترل‌شده فقط با تأیید اپراتور؛ smoke test read-only Cloudzy (بدون خرید)، UI ادمین و گزارش خطای فارسی موجود؛ بدون تغییر DNS یا انتقال حساب.
6. آزمون با شبیه‌ساز Timeout (نه تزریق Timeout به Provider زنده) و بررسی اینکه سایر بخش‌های فروش/پشتیبانی/SSH بدون رگرسیون باشند.

## ۶. وضعیت فازهای بعدی

- فاز ۲: حذف کامل GETهای Provider از loop انتقال، Journal/Worker recovery، ادامه از Checkpoint، پرونده تاریخی ۴۰۰/۴۶۸ به MOVED با شواهد معتبر.
- فاز ۳: Edge دستی با IP/SSH port/password و Standby بدون Cloudzy API.
- فاز ۴: انتقال و DNS دستی/بدون Cloudzy از موتور یکسان.
- فاز ۵: رابط کاربری ساده فارسی، کاتالوگ همه خطاها، Cancel/Stop/Recovery شفاف، تست عملی و انتشار.

**این گزارش Source-level است: هیچ تغییر Production یا Cloudzy/DNS/WireGuard/SSH/customer در جریان ایجاد PR انجام نشده است.**
