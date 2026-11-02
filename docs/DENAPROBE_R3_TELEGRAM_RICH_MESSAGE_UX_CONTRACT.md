# NVLBot DenaProbe — Telegram Rich Message admin dashboard contract
**Product scope:** Owner-approved 2026-11-02. **Design only; not implemented.** Native **Telegram Bot API 10.3 Rich Messages** are a firm requirement for both the dashboard and notifications; do not substitute a plain long text dump, a web dashboard/Mini App, or an HTML fallback.

## Entry / permission
- Entry in the existing **administrative bot**: `📡 پایش DenaProbe`. Only authorized configured admin roles/Chat IDs can request dashboard, incident details or history; recheck authorization on every callback, reject unauthorized deep-links. No customer notifications.
- An admin sees only registered authorized probes. No physical device secret, HMAC key, SSH credentials, raw client IP, customer identity, or private key in any card/callback.
- Do not introduce a second Telegram poller or parallel bot application; use the current bot Rich Message adapter and existing auth/event framework where compatible.

## Top-level Rich Message (editable summary, short)
Header: `📡 پایش اتصال · DenaProbe`.
Compact table-like rich rows (avoid excessive padding):
`وضعیت کل | سالم / اختلال / نامشخص`
`رله‌ها | N under watch / M incident`
`بردهای فعال | K fresh / J stale`
`آخرین داده | HH:MM:SS IRST (age)`
`اپراتور | همراه اول (declared hotspot)`
`کنترل HTTPS مستقیم | PASS / SLOW / STALE`
`اعتماد تحلیل | SUSPECTED/HIGH_CONFIDENCE/INCONCLUSIVE` (only when incident exists).
Never render a bare `SERVICE_ACCEPT_PASS` as customer VPN healthy.
Contextual, useful footer tip, e.g. `آخرین نمونه ۲۵ ثانیه پیش ثبت شد؛ وضعیت نامشخص به معنی فیلترینگ نیست.`; keep footer by design and vary by state.

Buttons (inline, non-mutating): `🔴 اختلال‌های فعال`, `📋 تاریخچه`, `🔄 بروزرسانی`, `🔎 جزئیات` (where context permits). Avoid irrelevant buttons/empty menu items. Refresh must read recent server state and update same message when Telegram API permits; no unsafe network actions.

## One incident detail Rich Message
Short header `🔴 اختلال احتمالی · D0/D1/D2` with manager-visible unique incident ID, target label (no unnecessary raw IP), declared ISP, observed code, stage, fresh probes n/m, `tcp_ms/auth_ms/session_ms` as measured, first/second transfer `received/expected`, control HTTPS status+age, `آخرین اندازه‌گیری`, `زمان دریافت سرور`, and current `سطح اطمینان` with reasons. A table/rich multi-row structure with restrained icons is required; avoid walls of text. When metric unmeasured, show `اندازه‌گیری نشد`, not zero.
Footer: a short contextual observation with known scope, e.g. `تأیید TCP به معنی سلامت کانال NPV نیست.`.

Buttons: `جزئیات شواهد`, `تاریخچه همین رله`, `بازگشت به پایش`. Evidence drill-down is read-only; pagination for long histories. Admin actions must not switch relays, restart services or toggle customers.

## New incident / escalation / recovery Rich Message
- On incident onset send ONE meaningful alert to each authorized admin with observed class and short reason; subsequent samples update incident state, not spam the chat.
- Escalation sends a separate update only on material change (type/severity/confidence) and after cooldown; delivery idempotency key `incident_id:transition:recipient_id`.
- Recovery sends one `🟢 اتصال بازیابی شد` Rich Message only after consecutive current fresh confirmations; include incident duration, recovered time and new samples. Not from missing telemetry or a stale sample.
- On collector delivery gap/board offline show `⚪ پایش نامشخص` independently, not a red filtering alert. Distinguish source state and actor time.
- Persist send outcome, Telegram message ID where available, retry attempt and failure reason without printing secrets; avoid duplicate messages after a restart.

## UI sample (illustrative, not actual event)
**📡 DenaProbe | وضعیت شبکه**
`وضعیت      🔴 اختلال احتمالی`
`اپراتور    همراه اول (اعلام‌شده)`
`نوع        D1 · نشست SSH`
`TCP        موفق`
`SSH        احراز هویت موفق`
`داده       انتقال ۱ کامل · انتقال ۲ Timeout`
`HTTPS      مستقل و سالم`
`اطمینان     مشکوک؛ منشأ نامشخص`
`آخرین ثبت   ۱۱:۱۱:۳۵`
`💡 نکته: منشأ قطع نشست فقط با این نمونه مشخص نمی‌شود.`

## Acceptance / QA
- Rich Message and table-like layout checked on Telegram iOS and Android; Persian RTL, column alignment, 2-digit time, compact spacing, contextual footer preserved.
- 3 distinct incident cards (D0/D1/D2), one healthy, one monitoring unknown, one recovered; no inherited data from a previous target/incident after navigation; stale badges explicit.
- Telegram API errors, rate limits, callback expiry and message editing fallback are handled without broken buttons or repeated alerts.
- Unauthorized callbacks and forwarded cards cannot reveal restricted data; all deep-links reauthorize.
- Integration is read-only with respect to NPV/Edge/GOST; no admin relay-change logging/events.

**Prerequisites:** valid fresh DPT2 data + completed Phase 1 telemetry continuity + approved Core incident engine and explicit operator activation. No live Rich Message changes during this documentation stage.
