# R2-D1 NVLBot dashboard polish — readable telemetry and metric guide

**2026-10-31. Source-only polish** based on `feature/r2d1-metrics-nvl-dashboard-20261031`, whose owner-run production smoke already displayed the DenaProbe page with live `dp-mci-01` data. This change is **not yet deployed**. No collector, firmware, DPT/1 protocol or metrics calculation changes.

## Motivation from real UI screenshot

The initial screen exposed ambiguous raw numbers and mixed English/Persian fields. In the owner's live 24-hour snapshot: 186 stored events, 70 history-only, zero observed internal sequence gaps, sender age p50/p95 32,817/92,584ms, 107 qualifying SSH PASS and 5 path non-PASS, HTTPS 15 PASS/1 SLOW and two fresh channel sequence IDs (#99/#94). The presence of 70 history-only does not contradict zero observed sequence gaps: they answer different questions.

## Presentation rules and meaning

- Summary first: current device, selected window and **fresh/contiguous telemetry confidence**. Never say SSH/VPN healthy from receipt recency alone.
- Show client-reported sender age in human-friendly ms/seconds; it is NOT network RTT or full end-to-end delivery time. Show n for every P50/P95 sample group.
- Distinguish **sequence gaps within stored events by boot/window** from **current live monitoring_gap** and **history-only**. An event can be stored without advancing live state; event-count is not SSH-sample-count.
- Show SSH PASS as `X of eligible observed SSH samples`; path failure, device/local errors and trust failures separately. Successful DPT/1 SSH only establishes Service Accept after transport/host-key verification, not user login or VPN.
- Present HTTPS independently from SSH; Cloudflare 64KiB sample over direct hotspot is not a VPN throughput test.
- Translate freshness status to plain Persian: تازه / قدیمی / ثبت‌نشده / اختلاف زمان. Do not turn stale/missing data into an outage alert or censorship verdict.
- Short always-visible **راهنمای سریع تفسیر** at bottom of report; **📖 راهنمای کامل شاخص‌ها** inline button opens a separate read-only page defining each visible metric. **↩️ بازگشت به گزارش** preserves 24h/7d context.
- Telegram HTML output is safely escaped for device id; content stays well below Telegram 4096-character limit; unchanged-message refresh remains idempotent.
- Every help/report callback is a fixed ID, passes the existing `apps_*` role gate and rechecks fresh active-admin membership, actor==private-chat ID. Help has **no SQLite read**. No new timer, API, jobs, alerts or automated actions.

## Changed files

- `denaprobe_admin_dashboard.py`: refined summary, _coverage_status, formatted percentiles, static full guide and navigation keyboard.
- `bot_final_v49-2.py`: extend **only the existing read-only DenaProbe callback tuple** with `apps_dpt_help_24` and `apps_dpt_help_168`.
- `tests/test_denaprobe_metrics_dashboard.py`: human status, no overclaim of network health, glossary coverage, HTML length, private callback authorization, 24h/7d round-trip.
- `.github/workflows/denaprobe-r2d1.yml`: install pinned `python-telegram-bot==22.8` to test real InlineKeyboardMarkup on Python 3.11/3.12.

## Operator release (when PR-specific CI passes)

This polish is designed as a **two-file NVLBot-only update** after the original R2-D1 panel is confirmed live. Do not publish `denaprobe_ingest/collector.py`, overwrite SQLite, rotate keys, update ESP32, change GOST/DNS/6G, or restart the isolated Collector. Validate actual root-bot unit path and exact pre-polish source hashes before replacing anything. Back up `/root/bot_final_v49-2.py` and `/root/denaprobe_admin_dashboard.py`; compile and test all source in an isolated worktree; update only these two files; restart only `nvlbot`; verify role denial, 24h, 7d, help/back, refresh and telemetry freshness. Rollback both files atomically as a pair on any error.

## Post-release manual acceptance

1. NVLBot → Programs → DenaProbe → 24h: readable sections, 0/70 semantics, no unauthorized health verdict.
2. Read full guide and return to the same selected period; repeat from 7d.
3. Refresh multiple times, no noisy Telegram `Message is not modified` error.
4. Non-admin, group-chat and revoked-admin callbacks never reveal metrics.
5. Collector remains independently healthy, bot data intact and no automatic notifications.
