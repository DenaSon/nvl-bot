# K2 Phase 3 — Telegram UI/UX and source release handoff

Date: 2026-10-16 (Asia/Tehran). Branch
`feature/k2-phase3-telegram-ux-20261016`, stacked on Phase 2 / PR #151 at
`673625cd7a7973b97e3faba5aa4f57d01cc9bbc4`.

Source implementation only. No master merge, server session, deployment,
profile enablement or real customer IP acceptance was performed. The owner
will deploy manually over SSH after this development phase; green source CI
is not a physical network or Telegram acceptance result.

## Operator journey

Main menu → **برنامه‌ها → مدیریت خروجی**. The old host-pool entry is removed;
old `hpeg_*` messages/callbacks still reach their original guarded handlers.
Dashboard back goes to Programs. The inbound default/DNS is not displayed as
an active outbound relay: the separate `k2_active_egress_edge` setting is used.
This is the last committed operator selection, not a continuous packet test.

A server's primary screen has two columns: **انتقال کاربران / انتخاب خروجی
فعال**, connection/IP checks, then **جزئیات و نگهداری**. Existing diagnostics,
transport preparation, account inspection and guarded metadata retirement
remain reachable there. New isolated candidates use the existing P1 pinned,
two-sided read-only IP test without joining the legacy host pool or relaxing
its probe gate. No second provisioning/migration implementation.

Transfer → Single / explicit group (up to 10 names) / all eligible → fresh
review → final review → one-shot 90-second confirmation → progress/results.
The active-output confirmation has its own heading and states that all active
accounts must pass. A marker-only result does not claim accounts were moved.
Tips explain Core account retention, changed Internet egress, active-session
skips and the fact that the active marker does not enroll future accounts.

The existing three-input Edge wizard is reused. It explains when installation
starts, supports cancellation, validates public IPv4/port before installation,
keeps the password out of persistence and does not falsely promise successful
Telegram message deletion. Partial/timeout reports advise against replaying an
installation. Success links directly to transfer and active-output review.

## Responsive UI, progress and complete account details

The existing bot task helper runs long all-user inventory, selected-user
review, PREPARE and CONFIRM without blocking PTB's serial update handler.
STOP can therefore reach the same original client during review or migration.
Inventory reports measured progress and stops between reviews without issuing
a partial selection/approval. PREPARE honors STOP after its current host work.
Transfer STOP remains between UIDs; it never cancels an in-flight host mutation.
No new daemon, poller, socket or migration journal is introduced.

Process-private display snapshots are bounded to 32 actor/chat entries and
bound to the message and Edge. They contain display DTOs and usernames only,
never root secrets, request IDs or tickets. Navigation discards late screens;
it does not cancel host execution or resurrect an invalidated approval.
Persistent Telegram data retains only a username selection for the last
confirmed transfer, so its original root status remains reachable after
navigation/restart. This selector is not execution/recovery authority.

Account detail pages show 15 rows, cover all 10,000 scoped accounts and expose
plain Persian skip reasons. A result distinguishes VERIFIED / HOLD / DEFERRED;
unknown or inconsistent result states cannot be rendered as success. Status
reads the original checkpoint/6G receipts and does not claim an independent
external client observation. Details after restart require a fresh status;
volatile preview/confirmation screens are intentionally not restored.

Recovery remains the existing **settled-cohort reconciliation only**. It can
close a stopped projection after original receipts and guards agree, without
repeating transfers. Ambiguous RUNNING/RECOVERY or partial host mutations
remain held with explicit technical-inspection guidance. No blind unlock,
forced disconnection, auto-repair or retry is added by UI text.

## Release package and validation

[Manual release/rollback and field sequence](K2_PHASE3_MANUAL_RELEASE_2026-10-16.md)
uses `ops/k2_release_bundle.py`: reproducible immutable Git-source packaging,
exact critical-file release manifest and read-only whole-package validation.
The two UI modules are included in the reviewed runtime source pin set. The
tool never changes a live service/profile/PAM/UID/route/DB or enables features.

Validation covers real extracted bot task/callback helpers with fake Telegram
and root I/O, actor/chat/message navigation, late completion, non-admin denial,
restart status selector, all-account pagination, unknown/partial results,
active-output copy, real immutable Git packaging and tamper/symlink rejection.
Original SQLite/P3/6G cohort tests cover STOP during native inventory,
per-account progress and unchanged execution journal. No real bot was contacted.
Exact-commit full Python and Python 3.11/3.12 stage results belong in the PR.

Next: review/integrate the stacked source, pin the final tested commit, then
manual SSH baseline/backup/stage and real bot smoke. Qualify the release once
on disposable/controlled hosts before customer trial; Single acceptance must
precede independently enabled Batch. Preserve every Phase-2 trust boundary.
