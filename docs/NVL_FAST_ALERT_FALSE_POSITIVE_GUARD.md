# NVL Fast Alert — False-positive guard

## Changelog
- جلوگیری از تأیید اختلال صرفاً بر اساس افزایش CLOSE-WAIT یا افزایش SSH.
- الزام به شواهد مستقل افت ارتباط یا افت ترافیک در سه نمونه متوالی.
- حفظ هشدار اولیه INFO با یک نمونه CLOSE-WAIT و حفظ زمان‌بندی ۱۵ ثانیه‌ای.
- مهاجرت امن وضعیت تشخیص بدون پاک‌کردن رخداد، خط پایه یا صف اعلان‌ها.

## Detection policy
- INFO remains a one-sample early signal from CLOSE-WAIT.
- A confirmed incident requires three consecutive valid samples.
- Connection collapse: SSH and UDPGW both fall to at most 75% of their adaptive reference, with absolute decreases of at least 12 and 10.
- Traffic collapse: AWG TX falls to at most 60% of its adaptive reference (reference at least 8 Mbps, absolute fall at least 8 Mbps) and either SSH or UDPGW also falls by at least 15% and 10 connections.
- CLOSE-WAIT and the legacy SSH/CLOSE-WAIT heuristic are never sufficient confirmation evidence.
- Invalid telemetry and sample gaps reset the confirmation window.
- Existing recovery behavior and 15-second timers remain unchanged.

## State compatibility
The detector state schema and SQLite tables remain unchanged. A policy-version migration clears only the old two-sample confirmation window; it preserves incident identity, phase, sent/pending outbox messages, baseline and adaptive history.

## Rollout
This PR changes code and synthetic regression tests only. It does not edit production state or deploy to Core. Run the offline replay against the archived 2026-11-25 incident before production rollout.
