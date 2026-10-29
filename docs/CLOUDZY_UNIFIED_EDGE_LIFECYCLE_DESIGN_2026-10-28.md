> **Supersession note (2026-10-29):** For future development of API resilience, independent manual Edge onboarding, operation locks/cancellation, transfer recovery, and simplified Persian Telegram UI, the newer [five-phase reliability & emergency recovery plan](NVL_EDGE_RELIABILITY_MANUAL_RECOVERY_5_PHASE_PLAN_2026-10-29.md) is authoritative. This 2026-10-28 design remains historical architecture evidence and continues to inform compatible safety invariants. Documentation change only; no implementation or runtime activation.

# NVL — Unified Cloudzy / Legacy Ingress Edge Lifecycle (design v1)

**Date:** 2026-10-28  
**Status:** APPROVED DESIGN BASELINE / DOCUMENTATION ONLY; no code, DB, Telegram bot, Cloudzy order, Cloudflare DNS, Core or Edge change in this document.  
**Audience:** admin-only: three trusted administrators using current Telegram clients. Rich Messages are the **sole intended operation dashboard format**. No legacy/plain HTML presentation fallback is requested or planned for this new admin workflow. This does **not** remove systemd/SQLite observability or existing Legacy menu UI before accepted retirement.  
**Implementation:** see [eight-phase roadmap](CLOUDZY_UNIFIED_EDGE_REFACTOR_ROADMAP_2026-10-28.md).  
**Previous source evidence:** CZ-03/04A/04B/05/06/07/08 implementation/delivery docs, [smart recovery](CLOUDZY_SMART_RECOVERY_PHASE2_2026-10-27.md), [Legacy mutation freeze](LEGACY_IP_MUTATION_FREEZE_2026-10-27.md). Historical docs remain evidence, not the future design authority.

## 1. Purpose and non-negotiable boundaries

Replace unreliable operator handoffs from Cloudzy purchase through Legacy ingress Relay provisioning, Standby acceptance, public-DNS/default routing and SSH-account endpoint migration with **one recoverable operation lifecycle**. The *old manual route must remain available, unmodified, until live acceptance proves the replacement*. Do not mistake Edge ingress/DNAT/WireGuard forwarding for accepted per-UID K2 internet Egress: K2 is out of scope and not production accepted.

Desired UX: one authorized start, an auditable live timeline, minimum interruption, precise Persian explanation and permitted action for every error, always-available **request safe cancellation**, and **no orphaned permanent workflow deadlock**. The word cancel is never a promise to undo a charged Cloudzy POST, installed WireGuard, or committed Cloudflare DNS change.

Retain the original Phase 6G shared lease/guard, protected routing gates, verified SSH host-key identity, no unauthorized DNS mutation, no Linux SSH-user rebuild during host metadata move, exact Cloudflare DNS checks, account CAS, provider/instance identity and audit history. No global unlock/reset to escape HOLD; no double-purchase, blind installer retry, Cloudflare write retry or VPS deletion. No secrets in Telegram/logs/commits.

## 2. Production evidence and known gaps (read-only audit, not assertions of current live state)

- 2026-10-28 owner DB snapshot: active default, cached DNS and 488 active SSH customers at 45.59.113.249; however settings.hosts listed that IP **last**, and included multiple other Edges. The guarded CZ-04B code requires hosts[0] == current default and raises LEGACY_HOSTS_ORDER_MISMATCH. Repeated DEFAULT_CUSTOMER_RELAY_NOT_ELIGIBLE was recorded when selling SSH. **Root cause of renewal failure was not independently established**.
- CZ-07 job 0f25a1b707bee923 remained in ROUTING with moved=0 for an attempted 495-customer migration, then closed as SAFE_STALE_ROUTING_CLOSED; another later job transferred 493 account-host records. A successful metadata migration is **not** customer ISP E2E acceptance.
- Historical CZ-07 Cloudzy read timeout before route write was persisted badly when a mixed-case exception name failed the strict journal code validator; PR #210 patched that specific case. It is not a generic crash-recovery solution.
- CZ-07 reserve persists QUEUED before asyncio.create_task(worker): process loss in that interval may strand QUEUED with no Resume button; in-process _running is not durable.
- Seven CZ-06 HOLD entries were stock/price pre-purchase rejections, with CZ-03 REJECTED; these do **not** prove paid orders. CZ-08 provider deletion for 45.61.180.126 remained HOLD / PROVIDER_RESULT_UNCERTAIN as of owner's audit, not proof of actual deletion.
- Legacy hpdef_ and hpdef_migrate_ are separate non-atomic changes; _db_rebuild_hosts_from_pool mixes inventory and customer-eligible route picker. Existing read-only safeguards often detect inconsistency **after** a manual mutation. Separate these semantics in the replacement.
- A Telegram send_photo ReadTimeout in the V2Ray purchase path is a **delivery error**, not evidence of an underlying Cloudzy provisioning failure.

These observations justify redesign; they do not authorize production repair or guessed updates to existing host data.

## 3. Scope and canonical operation identity

A single durable **EdgeOperation** spans provider request through acceptance; retain source journal IDs as linked children. Stable identity is operation_id + provider_server_id + verified host-key identity, **not the public IPv4 alone** (IP recycling exists). Manual existing Edge is a separate provider adapter with no invented Cloudzy receipt or purchase.

Proposed fields, to be finalized via versioned additive migrations in implementation:
- id, actor_telegram_id, chat_id, workflow_kind {CLOUDZY_NEW, MANUAL_ADOPT}, schema_version, release_version, created_at, updated_at.
- step (purchase/preparation/cutover/migration/verification), execution_state, attempt_number, event_version, owner/worker_id, fencing_generation, lease_expires_at, last_heartbeat_at.
- provider_server_id, verified_ipv4, host_key_fingerprint, source_edge_id, target_edge_id; no token, key, password or raw API response.
- billing authorization: approved SKU/region/OS Ubuntu 24.04/known base rate, total upper limit / surcharge uncertainty; purchase request idempotency key; final reconciliation outcome.
- customer cohort snapshot/version, moved/remaining from authoritative DB, client E2E evidence reference, 6G lease reference, DNS intent/result reference, last_error_code.
- Telegram render pointers (per-admin chat+message_id), last_rendered_event_version, delivery error/backoff separately from workflow state.

**Do not replace historical CZ-03/04A/04B/06/07/08 tables destructively.** First construct a unified read projection from their journals, then a versioned coordinator with migration adapters. Events are append-only and stable across retries, cancellation and later corrections.

## 4. State machine and timeline

Separate three concepts: **step**, **execution_state**, **error/recovery disposition**. Do not conflate a failed stage with a permanently active lock.

Proposed execution states:
- PLANNED: validated selection, no external mutation.
- RUNNING: worker with valid renewable fenced lease.
- WAITING_EXTERNAL: an operation is known submitted; polling a read-only provider outcome.
- NEEDS_ATTESTATION: independent host-key or affected-network actual-client proof absent; no unsafe bypass.
- RETRYABLE: only a known read-only/transient step can rerun within bounded budget.
- RECONCILE_REQUIRED: write outcome uncertain; observe provider/DNS/Core journals **before** deciding a next action.
- CANCELLATION_REQUESTED: durable operator intent; stop at next safe checkpoint; no false DONE/ABORTED.
- PAUSED_SAFE: no worker currently mutating; exact safe resumption criteria recorded.
- COMPLETED: all required postconditions including new-account create/renew after cutover and external-client acceptance are verified.
- CANCELLED_SAFE: business workflow closed only after reconciliation proves no unsafe in-flight effect; external assets may remain and have explicit disposition.
- NEEDS_OPERATOR: constraints cannot currently be proven; inspection UI stays accessible and does not block unrelated work by default.

Suggested visible steps (each keeps started/completed timestamps and proof pointer):
1. انتخاب/اعتبارسنجی موجودی، قیمت و سقف هزینه
2. خرید VPS و تأیید هویت Cloudzy
3. آماده‌سازی VPS / دریافت IP / گواهی SSH
4. نصب Edge و آزمون WireGuard، NAT و سرویس
5. ثبت و تأیید Standby (بدون تغییر کاربران)
6. آزمون اتصال واقعی مشتری از ISP هدف
7. تغییر کنترل‌شده DNS و Relay پیش‌فرض
8. انتقال Batchهای کاربران و تأیید نهایی فروش/تمدید/اتصال

A checkmark means a **durable completed stage with evidence**, not predicted progress. Display exact migration x/y independently of completed-step count; elapsed time is **not ETA**. If callback/UI is lost, re-render from the journal after restart.

## 5. Crash safety, leases, attempts, and cancellation

The durable journal is authoritative; a Python task, Telegram message, and in-memory set are never authoritative. Every state transition is guarded with expected state/version (CAS) and an append-only event, in one local DB transaction where possible. A worker owns a bounded **lease with fencing generation**, heartbeat, and deadline. A new worker can claim only an expired, reconciled lease; an old worker is fenced out and cannot commit stale results.

On process restart, classify outstanding work by **external side-effect boundary**:
- Before any provider POST: rerun bounded preflight or cancel.
- Provider create/delete POST sent or response ambiguous: never issue a new paid or destructive POST; reconcile exact provider identity/hostname/idempotency key via read APIs, preserving original intent.
- Provider known created: await/get same VPS, not buy another.
- SSH install partial: inspect exact host key, provider ID, Core identity, WG/NAT/iptables and installation manifest. Adopt verified complete installation; otherwise operator repair or safely resumable idempotent installer only **after separate tested implementation**. No blind rerun of existing setup_edge_relay.sh.
- Before DNS mutation: recheck default, exact Cloudflare record set, customer cohort and original 6G lease; cancel may close after zero-effect proof.
- DNS write intent or unclear commit: do not repeat/rollback DNS blindly. Reconcile Cloudflare live DNS + CZ-04B journal + Core default + 6G; keep fence until consistent.
- After route verified, migration runs 50-account CAS batches with persisted evidence; resume only after exact target route and provider checks. Stop at batch boundary for cancellation; already moved rows stay moved until a separately approved, guarded reversal operation.
- A failed Telegram update never changes execution status and never replays business effects.

**Cancellation UX contract:** every screen offers “درخواست لغو امن” or “توقف پس از مرحله جاری”; the callback durably records intent. Button style/label changes based on effect boundary. The UI must show the real end result: awaiting stop, reconciliation required, cancelled-safe, or needing human action. The ability to request cancellation does **not** mean immediate unlock or an unsafe forced CANCELLED state. A stuck global lock has a discoverable owner, code, age and safe repair path.

**Lock scope:** use keyed, compatible constraints (chargeable purchase intent per actor/provider order; source-route mutation per Core/6G; target/delete identity; single active customer cutover). A historic unrelated CZ-08 HOLD must not freeze all Cloudzy purchases or routes. Never weaken original 6G safety to maximize concurrency.

## 6. Canonical routing consistency

Define separate data concepts:
- INVENTORY: all known Core / Edge / retired VPS records and their immutable identity.
- ELIGIBLE CUSTOMER RELAYS: active, verified customer-facing non-Core, non-Standby relay endpoints.
- ROUTING CURRENT: one authenticated default relay with exact Cloudflare public/TLS DNS-only A record cohort and customer-domain settings.
- CUSTOMER ASSIGNMENT: ssh_accounts.host endpoint metadata, distinct from Linux account home on Core.
- TARGET STANDBY: provisioned candidate, isolated from customer hosts and with zero migrated customer assignments.

`settings.hosts` is an old projection, **not** a global inventory table and never a second source of truth. A new guarded writer projects exactly eligible target(s) and reconciles legacy drift without assuming default and DNS may be rewritten unilaterally. Read-only drift detection provides a Persian explanation; automatic repair is allowed only where postconditions and absence of conflicting references can be proved.

A cutover is a **Saga**, not a transaction spanning Cloudflare and SQLite: record intent → guarded DNS write → independent DNS observation → DB CAS default → postchecks → release original 6G only after verified final state. Never announce route success before live DNS and DB agree. Preserve old relay for rollback/readiness, do not delete it as part of cutover.

Old Legacy callbacks remain usable during development and must not write conflicting fields unnoticed; add explicit convergence/guard integration before their eventual retirement. No silent modification of customer SSH shell, WireGuard peer, K2 flags, 6H, payment ledger or Marzban.

## 7. Persian error system and action policy

Create a versioned **ErrorCatalog** keyed by stable machine code with:
`domain` {CLOUDZY_API, BILLING_PREFLIGHT, PROVISIONING, HOST_IDENTITY, EDGE_HEALTH, DNS_ROUTE, CUSTOMER_MIGRATION, CUSTOMER_BUSINESS, TELEGRAM_DELIVERY, SECURITY},
`severity`, `retry_class` {READ_RETRY, RESUME_AFTER_PROOF, RECONCILE_FIRST, USER_ACTION, TERMINAL},
`title_fa`, `what_happened_fa`, `impact_fa`, `next_step_fa`, `allowed_actions`, `operator_diagnostic`, `safe_log_fields`.
Unknown codes use a **generic Persian error** and always expose exact code + correlation ID inside details; never pretend an unknown cause is a provider outage.

| Technical code | Persian title | Allowed next action |
| --- | --- | --- |
| CZ05_STOCK_OR_PRICE_UNVERIFIED | قیمت یا موجودی سرور تأیید نشد | تازه‌سازی پیشنهاد / انتخاب پلن؛ هیچ POST خریدی تکرار نشود |
| CLOUDZY_HTTP_401 / 403 | دسترسی حساب Cloudzy تأیید نشد | بررسی مجوز و اعتبار اتصال؛ بدون خرید مجدد |
| CLOUDZY_HTTP_429 | سرویس‌دهنده درخواست‌ها را محدود کرده است | انتظار/بازخوانی با Backoff طبق پاسخ معتبر |
| CLOUDZY_READ_TIMEOUT | پاسخ بررسی Cloudzy به‌موقع نرسید | تکرار محدود GET، نه POST |
| CREATE_RESULT_UNCERTAIN | نتیجه ثبت سفارش Cloudzy مشخص نیست | بررسی همان سفارش و هویت VPS |
| PROVIDER_RESULT_UNCERTAIN | نتیجه حذف سرور از Cloudzy نامشخص است | فقط بررسی وضعیت سرور؛ حذف دوم ممنوع |
| EDGE_APT_LOCK_BUSY | مدیر بسته‌های سرور مشغول است | بررسی مجدد وضعیت نصب همان VPS |
| HOST_KEY_CHANGED | هویت SSH سرور با تأیید قبلی یکسان نیست | توقف امنیتی، بررسی مستقل اثرانگشت |
| LEGACY_HOSTS_ORDER_MISMATCH | مسیر پیش‌فرض با فهرست مسیرها هماهنگ نیست | بررسی سازگاری Routing؛ هیچ تغییر DNS خودسرانه |
| DEFAULT_CUSTOMER_RELAY_NOT_ELIGIBLE | مسیر فعلی برای ارائه سرویس جدید تأیید نمی‌شود | بررسی وضعیت Relay پیش‌فرض و منبع حقیقت |
| DNS_OR_DEFAULT_UNCERTAIN_LOCK_HELD | نتیجه تغییر مسیر شبکه هنوز قطعی نیست | Reconcile واقعی DNS/DB/6G؛ بدون بازگشت کور |
| SHARED_6G_BUSY | عملیات محافظت‌شده دیگری در حال اجراست | نمایش صاحب قفل/مرحله، انتظار یا بررسی ایمن |
| CZ07_JOB_QUEUED_STALE | انتقال در صف مانده ولی Worker معتبر ندارد | بازیابی Job با lease/fencing و تأیید عدم اثر خارجی |
| TELEGRAM_DELIVERY_TIMEOUT | نمایش وضعیت در تلگرام موقتاً ناموفق بود | تلاش مجدد صرفاً برای نمایش؛ Workflow تغییر نمی‌کند |

Do **not** misleadingly translate e.g. a Cloudzy **GET timeout** as an unpaid/failed VPS creation. Provider error class must retain operation {READ, CREATE, DELETE}, definitive/uncertain response, safe HTTP status and sanitized request identifier. Map unknown Cloudzy API responses to cause UNKNOWN, not PRICE_CHANGED.

## 8. Telegram admin UI contract — Rich Messages only

Target: Telegram Bot API **10.3 (2026-08-24)**, current clients, exactly three admin operators. **No parallel plain-HTML fallback screens, no Mini App, no sendRichMessageDraft as an operation tracker.** Verify native Bot API rendering on their actual Telegram clients in an isolated test chat before enabling. Python runtime currently pins python-telegram-bot 22.8; build one narrow isolated adapter for sendRichMessage and editMessageText.rich_message (PTB do_api_request or a reviewed compatible interface), rather than teaching every business handler raw HTTP. Existing Legacy UI untouched until retirement.

Official references:
- https://core.telegram.org/bots/api (InputRichMessage, InputRichBlockDetails, InputRichBlockTable, InputRichBlockButtons, RichMessageButton, sendRichMessage, editMessageText)
- https://core.telegram.org/bots/api-changelog (Bot API 10.1/10.2/10.3)
- https://docs.python-telegram-bot.org/en/latest/telegram.inlinekeyboardbutton.html (PTB 22.8 button style)

Recommended one stable **operation card message** per operation/recipient, with: heading + operation short ID; provider/target/source; current stage badge/text; 8-step compact timeline; exact moved/total accounts; latest event; elapsed since last durable stage; optional 2–3 contextual actions; **details disclosure** with technical code, timestamps, safe audit references and last cause. Rich is_rtl=true; render IPs and IDs in code/isolated spans; avoid overly dense tables on phone.

Use InputRichMessage.blocks, paragraph/heading/list/table compact/details, and one row of RichMessageButton or inline keyboard as appropriate. Use success/primary/danger styles semantically; NOT decorative. Keep persistent DB chat/message ID and last rendered event version; edit only on meaningful state changes and bounded intervals, coalesce rapid batches, handle message-not-modified/rate-limit separately. Telegram acknowledgement is best-effort; failures go to delivery audit/outbox with retry, **not operation error**.

Buttons are **eligible actions computed on server from current journal and guards**, not rendered promises:
- running: «🔄 تازه‌سازی» «📋 جزئیات» «⏸ درخواست توقف امن»
- read retryable: «🔍 بررسی دوباره» «📋 جزئیات» «✕ درخواست لغو»
- uncertain write: «🩺 بررسی نتیجه واقعی» «⏸ توقف امن» «📋 گزارش»
- partially migrated: «▶️ ادامه از آخرین Batch» only after fresh route readiness; «⏸ توقف پس از Batch»; «📋 گزارش»
- terminal: «📄 گزارش نهایی» with source/target, final checks, no false success.

Use a single paid purchase confirmation **after** displaying approved max charge/price uncertainty. Noncharged routine checks and Standby should auto-run. Preserve independent SSH host-key evidence unless trustworthy independent attestation exists; preserve real affected-ISP client acceptance before DNS cutover. If reliable automation for that acceptance is absent, one human check remains. No confirmation loops for refresh/reconcile (guarded, read-only); dangerous irreversible decisions require narrow authorization and fresh server-side policy.

### Example operation card (conceptual copy, not a production state)

**🚀 راه‌اندازی Edge | عملیات EG-2048**  
وضعیت: نصب Edge در حال انجام است | مرحله ۴ از ۸  
✅ تأیید قیمت و ثبت خرید | ✅ دریافت IP و هویت VPS | ✅ تأیید SSH  
⏳ نصب و آزمون WireGuard | ▫️ Standby | ▫️ آزمون مشتری | ▫️ DNS | ▫️ انتقال  
آخرین رویداد: «بسته‌های لازم نصب شده‌اند؛ بررسی مسیر Relay در جریان است.»  
کاربران منتقل‌شده: — (هنوز وارد مرحله انتقال نشده)  
[🔄 تازه‌سازی] [📋 جزئیات] [⏸ درخواست توقف امن]

### Example failed card

**⛔ انتقال فعلاً متوقف شد**  
علت: «مسیر پیش‌فرض با فهرست مسیرها هماهنگ نیست.»  
اثر: «هیچ انتقال جدیدی آغاز نشده است؛ وضعیت فعلی کاربران تغییر داده نشده است» **only if journal proves so**.  
راهکار: «بررسی سازگاری مسیرهای Core و Cloudflare»  
Details: exact code LEGACY_HOSTS_ORDER_MISMATCH / phase ROUTE_PREFLIGHT / short operation id / last timestamp  
[🩺 بررسی سازگاری] [✕ درخواست لغو امن] [📋 گزارش]

Never show a success check until the corresponding journal+external evidence has been accepted. Do not use Telegram animation or typing/status drafts as a substitute for real event tracking.

## 9. Acceptance and legacy retirement

Required tests: cloudzy transient/read failures, HTTP 4xx/429, changed catalog price, uncertain charge and delete, recycled IP, SSH key mismatch, APT lock, partial installer, worker crash at EVERY step (including QUEUED before launch), stale process fencing, lost Telegram edit, DNS intent/write/verify crash, shared 6G collision, mismatched default/settings.hosts, active customer cohort mutation, 1/50/51/493/495 accounts, one interrupted batch, lost client E2E proof, cancel at every stage, and any submitted action replay.

**No forced unlock** even after timeouts. Must show an actionable read-only diagnostic and safe next step. Final live signoff requires: independent affected-ISP real SSH client acceptance, correct public DNS/default, no user on unexpected relay, accurate journal, ability to CREATE **and RENEW** a real new/representative SSH service after cutover, correct Telegram timeline, old relay preserved, and approved rollback plan. A UI/CI green run is not production proof.

Retire Legacy **operator mutation entry points only after** new path proves E2E, manual fallback is no longer needed, and the operator explicitly approves retirement. Retire via feature flags and reversible navigation deprecation first; do not delete historical callbacks or data in this refactor. **This plan is future design, not permission to modify production.**
