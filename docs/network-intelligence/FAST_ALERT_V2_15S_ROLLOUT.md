# Fast Alert V2 — 15-second monitoring

## Changelog

- کاهش فاصله هدف نمونه‌برداری و پردازش هشدار به ۱۵ ثانیه.
- ارسال هشدار اولیه با نخستین نمونه معتبر افزایش CLOSE-WAIT.
- تأیید اختلال پس از دو نمونه متوالی چندشاخصی و اعلام بازیابی پس از پنج نمونه سالم متوالی.
- حذف اعلان تشدید اختلال و جلوگیری از ارسال مجدد هر مرحله در یک رخداد.
- افزودن تگ دو مدیر به هشدار اولیه و تأیید اختلال.
- حفظ خط پایه تطبیقی ۴۵ دقیقه‌ای و ثبت شواهد تشخیصی.

## Contract

- INFO: valid UDPGW remote CLOSE-WAIT >= max(2 × healthy reference, reference + 10). Other missing measurements do not invalidate CW-only evidence. INFO is not proof of ISP filtering.
- Confirmation: two consecutive complete multi-signal candidates (SUSPECTED or DEGRADED); gaps >25 seconds or invalid samples break the live streak. No 3-of-5 fallback. Other multi-signal failures can confirm without INFO.
- DEGRADED remains a recorded candidate, not a notification. Pending legacy escalation messages are suppressed on the next tick and retained for audit. Existing incident IDs and outbox keys remain compatible; SUSPECTED is the internal confirmation label.
- Five consecutive valid recovery candidates without a CW spike close the incident. INFO-only incidents close silently. Unknown telemetry cannot recover an incident. Monitor fault notices remain separate.
- Fixed verified baseline remains the fallback; adaptive healthy history covers up to 45 minutes (180 × 15s), 5-minute short window, minimum 11 minutes of eligible history, frozen during an incident. No baseline file rewrite.
- Mentions are fixed in source and sent only on INFO/confirmation. Telegram device notification delivery depends on users' settings.
- Durable outbox preserves chronological ordering across retries; no blanket 20-minute recurrence suppression. Transport failures can delay delivery.

## Before deployment (not performed by this PR)

The sampler implementation is installed on Core and not present in the reviewed repository. Inspect the effective sampler timer/service, runtime, output schema, and kernel rate calculation (must use actual elapsed time, not a hard-coded 60-second divisor). Verify that collection completes within 15 seconds and resource/storage impact is acceptable; do not change the network or bot services. The supplied sampler timer drop-in is a template, not automatically applied by the alert installer.

Prepare a pinned code-only deployment and validate both effective timers. Coordinate timer/source changes so the 25-second confirmation gap is not used with a 60-second sampler. Preserve the existing SQLite state, verified baseline, Telegram config and backups; do not reset them. Never use the prior V1 hotpatch as a V2 rollout procedure. Inspect old pending events and the current incident before rollout. Validate systemd timer scheduling and run a synthetic group delivery test only when explicitly authorized. Roll back timer overrides and alert module together if verification fails.

## Replay and acceptance

Replay existing 60-second history with the offline script's default --sample-interval 60; use --sample-interval 15 for fast recordings. Compare INFO lead time, confirmed warning lead time, false positives, missed incidents and recovery chatter across independently labeled normal and disrupted periods. Historical 60-second data cannot establish a 15-second production detection SLA. Target INFO 15–30s and confirmation 30–45s, conditional on the relevant signals crossing thresholds, collection runtime, scheduler and Telegram availability.

No production changes, merge or deployment in this draft.
