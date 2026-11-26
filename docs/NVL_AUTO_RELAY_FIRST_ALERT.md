# NVL — First-alert automatic relay switch

## Changelog
- افزودن فعال‌سازی و غیرفعال‌سازی تعویض خودکار رله از مدیریت Edge.
- انتقال خودکار به Standby منتخب با ثبت نخستین هشدار اختلال احتمالی، مستقل از تحویل پیام تلگرام.
- حفظ الگوریتم تشخیص، موتور انتقال موجود و اطلاعات کاربران.
- جلوگیری از اجرای مجدد همان انتقال با ثبت مجوز و رخداد در تراکنش موجود.

## Runtime contract
Default OFF. An active superadmin explicitly selects a tested existing manual Standby.
The setting binds the current source, exact target, authorizing administrator and
activation timestamp. The bot reads the monitor's SQLite database in read-only
mode every two seconds while enabled; only a newly queued SUSPECTED event of
the current open incident can trigger. Delivery status is irrelevant. DEGRADED,
RECOVERED, monitor faults, past alerts and a changed source cannot trigger.
No additional confirmation, notification, cooldown before the first attempt,
or route mutex is introduced. Existing Quick Switch target, Cloudflare and
account checks, lease and recovery rules remain mandatory.

The opt-in is consumed in the same transaction that reserves the existing
Quick Switch DNS intent. The original lease mode remains MANUAL for compatibility;
job evidence explicitly records AUTO_FIRST_ALERT and the incident key, not a
fabricated client witness. A pre-reservation failure may retry after five seconds
while the incident is open; an uncertain write is never automatically repeated.
After a reservation the switch is OFF; select a fresh tested Standby to arm again.
Turning OFF prevents new reservations, not an already-reserved DNS operation.
The old relay is not automatically rearmed or restored. No extra Telegram
message is sent by this automation; existing alerts and route history remain.

## Deployment and acceptance
Source only. No live DNS or account changes. Deploy bot entrypoint,
manual_quick_switch.py, manual_quick_switch_ui.py and manual_quick_switch_auto.py
together; the new module may require inventory enrollment or controlled manual
publication. Verify actual hashes, existing manual Quick Switch feature flag,
and read access to the existing detector database. No detector restart needed.
After CI and explicit merge, test the OFF state and UI on Core, then deliberately
arm the already-tested Standby. Use existing recovery UI for any uncertain
transfer. DNS propagation and end-user reconnection are not guaranteed by
local completion; verify actual customer reachability separately.
