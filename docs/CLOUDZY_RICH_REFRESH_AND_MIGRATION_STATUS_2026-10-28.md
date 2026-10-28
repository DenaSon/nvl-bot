# NVL — Edge operations dashboard refresh and migration status

**Date:** 2026-10-28  
**Baseline:** master `1803cbe6a23d92c9ffc3e93f9d6935f2faaf2cda` (merged PR #226)  
**Scope:** Python Telegram admin **read-only presentation** only; no Core deployment, Cloudzy POST, Cloudflare PUT, user move, SSH account rewrite, 6G lease release or business acceptance.

## Production evidence received

Rich outbox has UO `bbb3ca778d55...` at version 13, `SENT/ACKNOWLEDGED`, `SEND` and `EDIT` all pointing to Telegram message 57264. CZ07 `97ae84fa4475...` is `SENT/ACKNOWLEDGED` at version 220, message 57087; CZ07 `fd6ffb5ae191...` at version 213, message 57067. This **confirms a Telegram delivery receipt**, not that the latest admin click always produced a visible updated card. The Phase-7 bridge returned `UNCHANGED` for identical versions and generated the noisy “کارت قبلاً ارسال شده” plain message.

The separate operator-reported CZ07 transfer `45.61.180.119 → 104.194.141.63` recorded **485/485 moved** while remaining `VERIFYING`. That is not a verified all-client connectivity success or business-accepted `DONE`. A new Edge `144.172.119.190` has `EDGE_READY`, CZ06 `READY`; linked Unified `CLIENT_E2E / NEEDS_ATTESTATION` is an internal state and does not mean traffic was routed to this new Edge.

## Changes in this UI-only patch

1. The Programs entry is named **📊 مرکز عملیات Edge**. Its click issues a fresh `sendRichMessage`, so the requested card appears at the bottom of the admin's chat, rather than silently returning `UNCHANGED` for a previously acknowledged message.
2. A second Programs entry **📦 گزارش انتقال کاربران SSH** selects the active admin's latest **CZ07** migration, independently of the latest UO paid Edge purchase. The same owner, active-admin, authenticated private-chat checks apply.
3. **🔄 تازه‌سازی** and **🔎 جزئیات فنی** edit the latest acknowledged Rich card on every permitted click, even at the same journal version. A unique harmless 8-hex review reference in collapsed technical details makes the Telegram edit payload distinct and prevents “message is not modified” responses. No extra plain text is sent on `UNCHANGED`.
4. One durable outbox intent still precedes each Telegram network effect. `INTENT/UNCERTAIN` holds remain fail-closed. Every new card supersedes the acknowledged message pointer; callbacks from older Rich cards are rejected. A card is validated **before** creating an intent.
5. Unify the Cloudzy menu descriptions, formal operation titles, Persian state captions and details labels. The visible 8-stage timeline uses **بازبینی آمادگی تغییر مسیر** instead of a standalone *manual customer E2E test* milestone. Internals and permissions are not changed.

### Unchanged safety contracts

The internal UO `CLIENT_E2E` state and `CZ07.accept_business` independent CREATE + RENEW + affected-ISP client verification are **not** removed. The latter still requires independently verified references. Removing the user-facing milestone is **not a license to cut over before customer-path proof**. If automated trusted telemetry is implemented later, it can replace the manual attestation mechanism only after validating real customer-path evidence. `VERIFYING` remains unresolved and the legacy Relay remains protected.

Rich callbacks perform read-only projections; they do not run CZ07 migrations or provider purchases, and never automatically replay an unknown Telegram delivery. The Rich API transport still has **no HTML fallback**.

## Previous eight phases — source-level delivery summary

| Phase | Merged work | Remaining production signoff |
|---|---|---|
| 1 | Canonical SELECT-only route snapshot and diagnostic codes (PR #212) | Verify against present Core route |
| 2 | Durable coordinator, journal, fencing/recovery models (PR #213) | Verify deployed release integration and restart scenarios |
| 3 | Cloudzy purchase policy, POST-idempotency and provider error classification (PR #214) | Reconcile against actual purchase receipt and price |
| 4 | Same-VPS installer evidence and Standby reattestation (PR #216) | Independent host-key, SSH, WG, NAT and customer path |
| 5 | Guarded CZ04B DNS saga and strict route reconciliation (PR #217) | Live Cloudflare/default/6G verification, staging vs live callback boundaries |
| 6 | CZ07 bounded 200-account batches, pause/resume, VERIFYING acceptance (PR #219) | CREATE/RENEW/affected-ISP verification and trusted independent verifier |
| 7 | Rich admin view, transport, menu wiring and safe private feedback (PRs #220, #221, #222, #226) | Actual Telegram client and repeat-click tests |
| 8 | 25-scenario offline fault matrix and read-only pilot tooling (PR #224) | Real paid pilot and independent production signoff |

PR #223 integrates native paid CZ03/CZ06/CZ07 receipts with the UO journal; this is separate from a completed real-world customer-path acceptance.

**Operational versus code truth:** A green GitHub CI or a merged PR does not prove a production deploy. The user supplied live outbox receipts, but the current runtime SHA, delivery of this patch, the current source/target route and independent customer-path evidence must be checked on Core.

## Acceptance / rollout

- Run isolated unit tests `tests.test_cloudzy_rich_admin_phase7`, `tests.test_cloudzy_rich_bridge_phase7` and full release CI.
- After review, deploy exactly the changed Python files with a pinned SHA, runtime backup, compilation, service restart and journal check. The 1.5 MB main bot file must be deployed atomically with `cloudzy_rich_bridge.py`, `cloudzy_rich_transport.py` and `cloudzy_rich_admin.py` to avoid a mismatch; `cloudzy_admin_panel.py` has presentation-only renames.
- Press the Edge operations button twice: both should create a fresh card, without any “already sent” plain message. From the latest card, press Refresh twice: both should edit the same message with newly read data. Attempt old-card callback: must fail. Check outbox SENT rows and absence of new UNCERTAIN intents.
- Open the separate SSH transfer report: it must show the **same owning admin's** CZ07 status, preserved as VERIFYING unless its authoritative journal has independently changed. Do not assert DONE based solely on 485/485.
- Read-only Core inspection of `cloudzy_cz07_jobs`, the current route/DNS/active SSH assignments and acceptance table is mandatory before any final business report. No automatic infrastructure mutation in this release.

## Rollback

Revert **only the UI source deployment** using the saved exact runtime copies. Never roll back Cloudflare records, customer host assignments, provider orders or 6G leases as a side effect of a Rich UI failure. Existing acknowledged Rich messages may remain in the chat; they cannot bypass the message-pointer and owner guards.
