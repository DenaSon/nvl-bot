# UI-02 — Design system and polish

Draft, dependent on UI-01. No deployment or approval implied.

## Changes

- Simplify principal landing screens, sales selectors, user lists, Marzban dashboard, UDPGW, representative detail and server inventory.
- Native Telegram button styles for an explicit set of actions (primary, success, danger). The repository pins python-telegram-bot 22.8, which supports style. All other buttons use the client theme.
- Separate agent wallet from sales reports. Keep existing ownership checks, wallet actions, sales-stat queries, old reply-keyboard aliases and callback guards.
- Preserve sensitive operation warnings, prices, confirmation callbacks and existing infrastructure safety gates.
- Avoid duplicate automatic-login welcome messages.
- Correct remaining superadmin access-menu parent and mandatory-brand logout return.

## Acceptance

CI and staging/Telegram verification are required. This is a targeted polish of the main operational surfaces, not a claim that every legacy wizard and notification has been visually inspected. No changes to schema, network or settlement logic. No global rewrite of labels or test suite. Existing safety tests remain required.

## Changelog

- ساده‌سازی ظاهر منوها، فهرست کاربران و صفحات مدیریتی.
- تفکیک کیف پول از گزارش فروش نمایندگان.
- یکپارچه‌سازی رنگ دکمه‌های عملیاتی و کاهش پیام‌های اضافی.
- بهبود نمایش مبالغ، وضعیت‌ها و مسیرهای بازگشت.
