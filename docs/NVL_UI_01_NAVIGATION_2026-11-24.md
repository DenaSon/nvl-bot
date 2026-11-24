# UI-01 — Navigation and architecture

Status: initial implementation; review and CI pending.

- Administrator home is reduced to six domains; server settings become the infrastructure hub.
- Finance and settings use shared renderers; role-specific permissions and the accounting feature flag remain enforced.
- Resellers retain mandatory brand onboarding, wallet/charge, and permission-gated dedicated cards.
- Broadcasts move to Representatives; direct Marzban management and online users move to Users.
- Legacy reply-keyboard labels and operational callbacks are retained; no schema or networking changes.
- Existing programs subhub and accountant export workflow are retained for compatibility. Further drill-down/return-path review and Telegram smoke tests are required before merge.
- Replace brittle Phase 5.6 decoration/source-string checks with executable menu and permission contracts. Retain operational tests and hidden-menu regression coverage.

## Changelog

- بازطراحی منوی اصلی مدیریت و دسته‌بندی بخش‌های مالی، زیرساخت و تنظیمات.
- سامان‌دهی پنل نمایندگی و انتقال تنظیمات برند و کارت اختصاصی.
- انتقال اطلاعیه‌ها به بخش نمایندگان و حذف دکمه‌های تکراری کاربران.
- یکپارچه‌سازی مسیرهای ناوبری و به‌روزرسانی تست‌های مرتبط.
