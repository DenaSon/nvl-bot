# K2 Telegram UX contract — binding now, final polish separately

**Date:** 2026-10-14. **Status:** living admin UI contract, applies to M4 and every later M5–M7 feature. The final cross-feature UI/UX polish is a distinct **UX-POLISH** milestone **after M7**, not a substitute for functional or physical acceptance.

## Identity (preserve the existing NVL admin bot)

- **One existing Telegram bot**, one existing admin callback handler, one Admin role policy. Do not create a second Telegram bot, shadow router, undocumented slash commands or alternate 6G Executor.
- Persian, **simple, minimal, maximum two buttons per row**. Short titles and clear status, minimal user-facing technical vocabulary.
- Keep the existing Edge dashboard/details, single-user operations, Legacy and Marzban actions, Phase1 wizard and monitoring accessible. New K2 migration lives under **سرورها → انتقال کاربران**.
- Use code-formatted copyable usernames, Edge IDs and destination IPs; escape every user-controlled string before HTML output. Never print passwords, SSH keys, HMAC, raw CLI, Linux UID debug, SQL, nonce, 6G operation data or internal flag names in user-facing UI.
- Every screen has a route back. A text-input wizard provides **انصراف**. Clear stale wizard state on navigation. A selection is an unauthoritative preview only, even when persisted in Telegram `user_data`.
- **Only authenticated admin** receives migration functionality. Recheck role BEFORE any UID enumeration or privileged source scan. Any eventual execute call requires a separately attested root-side actor/chat and signed short-lived exact wave approval.
- Button data remains ≤64 UTF-8 bytes; do not embed signed tickets, secrets, full usernames or large cohorts in Callback data.
- The wording distinguishes **آماده بررسی**, **نیازمند بررسی**, **مسیر ثبت‌شده**, **تأیید اتصال واقعی**, **توقف محافظت‌شده**, and **در انتظار**. Never claim real public Edge egress because a DB row says PROTECTED or a namespace's IP test succeeded.
- Be frugal with notifications; operations status is a pull dashboard by default. No speculative yellow/recovery push alerts. Only truly critical explicit operator events may notify.
- Reuse the existing bot's back/cancel/button icons and shorten not only new text but surrounding screens in the final polish. Do not surface the internal work schedule or phase names in Telegram.

## Current functional M4 wireframes (implemented in code)

```text
[سرورها] → [جزئیات Edge] → [انتقال کاربران]
┌─────────────────────────────────┐
│ 👥 انتقال کاربران               │
│ مقصد: e9                       │
│ انتخاب تکی یا گروهی...          │
│ [👤 انتقال تکی][👥 انتقال گروهی] │
│ [◀️ سرور]                      │
└─────────────────────────────────┘

[انتقال تکی]
نام کاربری را بفرستید: nvl0555
[❌ انصراف]

[انتقال گروهی]
نام‌ها را با ویرگول جدا کنید.
حداکثر ۱۰ حساب: nvl0555, nvl0557
[❌ انصراف]

[پیش‌نمایش]
✅/⛔️ user — آماده بررسی / نیازمند بررسی
[🔄 بررسی دوباره][📋 وضعیت]
[👥 انتخاب جدید][◀️ سرور]

[وضعیت]
⚪️ شروع نشده / 🟡 مسیر ثبت شده؛ اتصال باید تأیید شود
⛔️ متوقف و محافظت‌شده / ⛔️ نیازمند بررسی
[🔄 بررسی دوباره][📋 وضعیت]
[👥 انتخاب جدید][◀️ سرور]
```

**No execute button currently exists** because there is no independent field-approved F4/root provider or F3→F4/SSH/SOCKS packet acceptance. Do not add a misleading green operation button. The M4 root portal is default OFF until separate vetted M5/M6 gates.

## Functional acceptance required before final polish milestone

- M4: exact signed per-wave approval, no-secret/persistent Telegram memory, root service binding, guarded dispatch, operator-readable per-UID status, safe replay/HOLD, previous/next page, all via Telegram with no routine CLI.
- M5–M7: real e9 SSH/SOCKS IPv4 and DNS/IPv6 no-leak, reboot/WG-down, guard/6G console rescue; Single UID canary; mixed Legacy isolation; approved Batch waves; exact real receipts after restart; no unsafe global mode flip or legacy customer disruption.
- **UX-POLISH milestone after M7**: cross-feature navigation/content audit, consistent status taxonomy, breadcrumb/back/cancel, two-column button grids, input example tap-to-copy, Telegram message length/callback-limit, HTML escape, admin vs representative permissions, accessibility/screen density and snapshot tests. Functional actions and permissions **must not regress**.

## Definition of UX-POLISH Done

One documented style guide applied to all existing Edge management + UID transfer screens, verified against existing UI snapshot/handler/security tests; no feature is removed, hidden behind dead controls, or replaced by a nonfunctional visual mock. Polish has its **own review and PR**, and does not claim physical acceptance.
