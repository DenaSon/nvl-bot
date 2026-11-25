# NVL Fast Alert — False-positive guard

## Changelog
- جلوگیری از ارسال هشدار تلگرامی بر اساس جهش منفرد CLOSE-WAIT؛ این شاخص صرفاً در سوابق داخلی ثبت می‌شود.
- حذف مسیر تأیید قدیمی مبتنی بر افزایش SSH و CLOSE-WAIT بدون شواهد مستقل.
- الزام به سه نمونه معتبر و متوالی برای اعلام اختلال، همراه با شواهد مستقل افت ارتباط یا ترافیک.
- حفظ زمان‌بندی عملیاتی ۱۵ ثانیه‌ای و بازنشانی پنجره تأیید در صورت وقفه نمونه‌برداری.
- افزودن آزمون بازپخش رخداد واقعی ۲۵ نوامبر با فاصله تاریخی نمونه‌ها.

## Detection policy
- CLOSE-WAIT spikes may set the internal INFO state but never queue a Telegram message by themselves.
- A confirmed incident requires three consecutive valid samples.
- Connection collapse: SSH and UDPGW both fall to at most 75% of their adaptive reference, with absolute decreases of at least 12 and 10.
- Traffic collapse: AWG TX falls to at most 60% of its adaptive reference (reference at least 8 Mbps, absolute fall at least 8 Mbps) and either SSH or UDPGW also falls by at least 15% and 10 connections.
- CLOSE-WAIT and the legacy SSH/CLOSE-WAIT heuristic are never sufficient confirmation evidence.
- Invalid telemetry and sample gaps reset the confirmation window.
- Production sampling remains at 15 seconds with a 25-second maximum accepted gap; historical 60-second replay uses an explicit test-only 75-second gap.
- Existing recovery behavior and 15-second timers remain unchanged.

## State compatibility
The detector state schema and SQLite tables remain unchanged. A policy-version migration clears only the old two-sample confirmation window; it preserves incident identity, phase, sent/pending outbox messages, baseline and adaptive history.

## Rollout
This PR changes code and synthetic regression tests only. It does not edit production state or deploy to Core. Run the offline replay against the archived 2026-11-25 incident before production rollout.
