# NVL — گزارش توسعه فاز ۲: انتقال بدون Cloudzy GET و بازیابی امن صف

**تاریخ:** 2026-10-29  
**وضعیت:** **SOURCE_MERGED** — [PR #237](https://github.com/DenaSon/nvl-bot/pull/237)، commit `038d6c2ddd53a76108eccd28880a66b63b1ae64f`. [CI موفق #40865995415](https://github.com/DenaSon/nvl-bot/actions/runs/40865995415): **۳۰۳۹ تست Python موفق** (۱۳ مورد skip در اجرای اصلی)، بازآزمایی در بسته Root با **۳۰۳۹ تست موفق** (۳ مورد skip). **CORE_DEPLOYED=NO / PRODUCTION_ACCEPTED=NO**. هیچ تغییر Production، DNS، VPS یا حساب کاربر در زمان توسعه انجام نشده است.  
**مرجع:** [برنامه پنج‌فازی NVL](NVL_EDGE_RELIABILITY_MANUAL_RECOVERY_5_PHASE_PLAN_2026-10-29.md) و [تحویل فاز ۱](NVL_EDGE_RELIABILITY_P1_DELIVERY_2026-10-29.md).

## ۱. تفکیک وابستگی API و مسیر داده

در `cloudzy_cz04b.py` تابع `_fresh(state,check_provider=True)` پیش‌فرض سابق را حفظ می‌کند. فقط موتور CZ07 برای عملیات **پس از Cutover اولیه و دریافت رسید معتبر Cloudzy** مقدار `check_provider=False` را استفاده می‌کند. `_run_users(...,check_provider=False)` برای Batchهای CZ07:
- هویت مقصد را از پذیرش اصلی CZ03، `host_pool`, `cloudzy_edge_operations` و pinned host key بازخوانی می‌کند؛
- سلامت تازه SSH مدیریت، سرویس مشتری و مسیر WireGuard را با `probe` بررسی می‌کند؛
- NAT/iptables و Host Key ثبت‌شده را با `nat` بررسی می‌کند؛
- DNS واقعی Cloudflare و منبع حقیقت Default/Route، محافظ K2/6H و **lease اصلی 6G** را پیش از هر CAS بررسی می‌کند؛
- نام کاربران و fingerprint حساب‌های **باقی‌مانده** را قبل و حین تراکنش کنترل می‌کند.

هیچ `GET /services/{id}` از Cloudzy در loop Batch یا کنترل فنی پایان انتقال لازم نیست. **قبل از خرید، نصب، پذیرش Standby و شروع Cutover اولیه، کنترل ارائه‌دهنده برای مسیر Cloudzy حفظ شده است.** حالت `check_provider=False` یک bypass سراسری نیست و باید تنها در دامنه رله پذیرفته‌شده و انتقال پس از Cutover استفاده شود.

در `cloudzy_cz07_queue.py` فاز تأیید Transport `VERIFYING→MOVED` بدون GET Cloudzy انجام می‌شود ولی DNS زنده، SSH/WG/NAT پین‌شده و Snapshot مستقل همچنان بررسی می‌شوند. `MOVED` به معنی **اتمام فنی ثبت انتقال حساب‌ها** و بازشدن قفل عملیات بعدی است، نه `DONE` یا گواه واقعی CREATE/RENEW و ISP مشتری.

## ۲. بازیابی بدون انتقال مجدد

### حالت نیمه‌تمام: `HOLD` با باقی‌مانده مبدأ

از بات، «🔎 بررسی و ادامه انتقال» ابتدا یک `review_hold()` **فقط خواندنی** اجرا می‌کند: مالک/گفتگو، نبود Worker، مسیر و DNS واقعی، health شبکه/Host Key/NAT، lease 6G و شاهد Batchهای واقعاً `DONE` در CZ04B را بررسی می‌کند. `_hold_evidence()` مقدار انتقال واقعی را از **تعداد اولیه − حساب‌های هنوز روی مبدأ** محاسبه می‌کند و باید برابر مجموع Batchهای `DONE` تأییدشده و Audit اضطراری معتبر باشد؛ **نه تعداد کل کاربران مقصد**.

پس از تأیید دوم با nonce و انقضای ۱۸۰ ثانیه، `reconcile_hold()` در `BEGIN IMMEDIATE` یک CAS/Journal append-only انجام می‌دهد. اگر باقی‌مانده هنوز وجود داشته باشد، `HOLD→MIGRATING` و فقط حساب‌های منبع از آخرین Checkpoint به‌صورت batch منتقل می‌شوند؛ هیچ Route/DNS/Batch قبلی replay نمی‌شود. اگر Worker یا داده تغییر کرده باشد، عملیات متوقف می‌ماند.

### حالت انتقال اضطراری تکمیل‌شده

پرونده واقعی `a0b997e06a92ca35` با انتقال اولیه ۴۰۰/۴۶۸، سپس جابه‌جایی ۶۸ حساب با اسکریپت اضطراری و اضافه‌شدن یک حساب جدید مقصد، باید **در زمان استقرار از DB زنده بازخوانی شود**. اسکریپت قدیمی Audit زیر را ثبت کرد:
- `nvl_emergency_migration_audit(job_id,source,target,affected,previous_status,previous_code,event_code,at_utc)`
- رویداد `cloudzy_cz07_events` با `stage=HOLD`, `code=EMERGENCY_LOCAL_CAS_E2E_PENDING`, `moved=468`, `remaining=0`.

در recovery جدید، شرط `400` رسید Batchهای `DONE` + `68` Audit اضطراری معتبر = `468` حساب اصلی است؛ **حساب شماره ۴۶۹ خارج از cohort و منتقل‌شده نیست**. تغییر بی‌سابقه/بدون Audit، تغییر Host Key، ناسازگاری DNS، route، 6G یا حساب خارج از مقصد توقف امنیتی ایجاد می‌کند.

بعد از تأییدهای دوگانه و اثبات شواهد، `HOLD→VERIFYING` تنها Journal را تصحیح می‌کند؛ **هیچ حساب، DNS یا سرویس‌دهنده تغییری نمی‌کند**. مدیر سپس «بررسی تکمیل انتقال حساب‌ها» را انجام می‌دهد تا با controls فنی جدا `MOVED` ثبت شود. بدون شواهد مستقل CREATE/RENEW و اتصال مشتری، `DONE` ممنوع است.

### سایر وضعیت‌ها

- `QUEUED` مانده از ری‌استارت، پیش از هر Route write، فقط با تطبیق Snapshot اولیه مبدأ قابل اجرای مجدد است. وضعیت `ROUTING` با اثر احتمالی DNS، **هرگز کورکورانه اجرا نمی‌شود**؛ همان مسیر بررسی/بستن امن قبلی می‌ماند.
- `MIGRATING` و `PAUSED_SAFE` پس از ری‌استارت فقط با DNS/6G/Route verified، از باقی‌مانده ادامه دارند؛ restart به‌خودی‌خود خرید/Route جدید ایجاد نمی‌کند.
- Stop/Cancel در مرز Batch باقی می‌ماند. درخواست توقف، توقف اجباری وسط CAS یا بازگردانی خودکار کاربران نیست.

## ۳. UI و خطاهای فارسی

در صفحه وضعیت انتقال، دکمه «🔎 بررسی و ادامه انتقال» برای `HOLD` در دسترس مالک اصلی است، با preview واقعی حساب‌ها و تأیید یک‌بارمصرف؛ برای `QUEUED` نیز ادامه پس از ری‌استارت قابل درخواست است. خطاهای جدید بازیابی (نبود Audit، تغییر source cohort، DNS/Route mismatch، کاربر خارج از محدوده و منقضی‌شدن preview) توضیح فارسی همراه اقدام روشن دارند. جزئیات فنی داخلی و ساده‌سازی همه صفحات برنامه‌ها، موضوع فاز ۵ است؛ اما دکمه‌های فعلی باید قابل‌استفاده و ایمن باشند.

## ۴. محدودیت‌ها و دفاع در برابر تناقض

- عملیات قدیمی با اثر ناشناخته و **بدون audit معتبر** خودکار آزاد نمی‌شود؛ نمایش «نیازمند بررسی شواهد» درست است، نه `MOVED` جعلی.
- `GET` Cloudzy در فرآیند اولیه **مسیر خرید Cloudzy** هنوز وجود دارد. فاز دوم فقط استقلال صف Migration پس از Admission را پیاده کرده است؛ **فاز سوم** برای مسیر دستی مستقل از Cloudzy و با DNS خودکار Cloudflare تعریف شده است.
- محاسبه `actual_moved=total−remaining` باید با receipts `DONE` همان source-target، مدیر، گفتگو و شناسه VPS از زمان شروع Job و Audit اصلی تطبیق داشته باشد. اگر کاربران حذف، غیرفعال یا جابه‌جا شده‌اند و شواهد ناسازگار شد، fail closed؛ تصحیح نیازمند ممیزی جدا است.
- چک‌های DNS و سلامت سرویس بعد از Preview و پیش از تأیید مجدداً اجرا می‌شوند؛ تغییر خارجی ناگهانی بعد از snapshot همچنان ریسک `time-of-check/time-of-use` است که با CAS DB/lease و توقف روی شواهد ناسازگار کاهش یافته، اما تضمین اتمیک DNS خارجی ممکن نیست.
- `MOVED` و `DONE` متفاوت‌اند. تا زمان رسید معتبر پس از انتقال، حذف Edge قدیمی خودکار ممنوع است.

## ۵. ماتریس تست و پذیرش

| سناریو | نتیجه مورد انتظار |
|---|---|
| Cloudzy GET در Batch timeout یا قطع | هیچ Cloudzy GET در کد فراخوانی نمی‌شود؛ Probe/SSH/NAT/DNS/6G برقرار باشد، انتقال ادامه یابد |
| NAT خراب یا SSH fingerprint نامعتبر | قطع قبل از نوشتن حساب و حفظ اطلاعات موجود |
| ۴۰۰ از ۴۶۸ منتقل شده، مبدأ ۶۸، مقصد +۱ جدید | Replay صفر Batch قبلی؛ انتقال فقط ۶۸ باقی‌مانده |
| ۴۰۰ Batch DONE + ۶۸ Audit معتبر + ۱ حساب جدید | HOLD→VERIFYING، سپس MOVED بعد از کنترل فنی؛ کاربران بدون تغییر |
| ۶۸ حساب بدون Audit معتبر جابه‌جا شده | رد Recovery؛ عدم جعل نتیجه |
| Callback مجدد، nonce منقضی/مالک دیگر | رد بدون هیچ mutation |
| Worker بعد از Batch از بین می‌رود | از DB+Journal بدون Route دوباره، با preflight |
| Source/DNS/Default/6G تغییر کرده | STOP و نیازمند بررسی؛ بدون bypass |
| گواه مستقل CREATE/RENEW/ISP موجود نیست | MOVED قابل ثبت پس از کنترل فنی؛ DONE ممنوع |

## ۶. انتشار و Rollback

**فقط پس از CI سبز و Merge:** نسخه کد P1 نیز باید روی Core باشد؛ استقرار نامنسجم P2 با کد P1 قدیمی مجاز نیست. پیش از هر استقرار، بکاپ SQLite Online/Restore قابل‌اعتبار، `PRAGMA quick_check`، Snapshot جدول‌های CZ04B/CZ06/CZ07، `nvl_emergency_migration_audit`، users/default/hosts/DNS/6G، و مقایسه SHA ماژول‌ها. Worker فعال و عملیات نامعلوم نداشته باشیم. در اولین smoke test فقط وضعیت را بخوانیم، سپس مدیر جداگانه روی پرونده متوقف‌شده دکمه Recovery را تأیید کند. **Merge = تغییر Production نیست**.

هیچ اجرای اسکریپت اضطراری قدیمی مجدد مجاز نیست. پس از `HOLD→VERIFYING` یا `MOVED`، Rollback به کد قبلی باید با سازگاری schema/journal بررسی شود؛ حذف Audit یا پاک‌کردن تاریخچه مجاز نیست.

## ۷. کارهای باز بعد از فاز ۲

- فاز ۳ (تصمیم اصلاح‌شده 2026-10-29): [ویزارد دستی کامل](NVL_EDGE_MANUAL_CLOUDFLARE_WIZARD_PHASE3_2026-10-29.md) از IP/SSH port/password تا Standby، تغییر خودکار Cloudflare DNS و Relay فعال؛ صفر Cloudzy API.
- فاز ۴: سخت‌سازی Recovery و مدیریت تداخل Manual/Cloudzy، خطای جزئی Cloudflare و Rollback کنترل‌شده؛ **DNS دستی از دامنه حذف شد**.
- فاز ۵: UI/UX فارسی، خطاها و دکمه‌های لغو/بازیابی کامل، آزمایش عملی Production.

**برنامه فعلی هیچ تغییری در وضعیت واقعی Core یا کاربران ایجاد نکرده است.**
