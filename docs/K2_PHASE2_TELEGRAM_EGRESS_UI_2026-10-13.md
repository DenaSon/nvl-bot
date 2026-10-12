# NVL K2 — Phase 2 Telegram Egress UI / Controller Handoff

**Status (2026-10-13):** Phase 2 **UI/read-only-controller implementation increment**, no Core operator testing yet (intentionally deferred by operator). **Not** live host/persistence acceptance. Next phase still requires full Phase 1 F4 acceptance before enabling writes.

## What this GitHub change implements

1. Reuses the existing admin flow: `مدیریت IP / استخر` → `🛡 مدیریت Egress` (`hpeg_status`). No parallel Edge registry or alternate activation workflow.
2. **Unified dashboard:** merges the root-owned H ingress registry `/etc/nvl-egress/v1-ingress-peers.json`, `host_pool`, independent `host_pool.is_default`, `settings.dns_current_ip`, F3 allocation/readiness and separately operator-pinned Stage SHA256. The previously invisible *e7* (`172.86.105.67`) now renders **INGRESS_ONLY** when its H registry identity is trusted—even if no `edge_egress_allocations` DB row exists.
3. Separates **default public Ingress**, **Cloudflare DNS target** and **actual UID-specific Linux Egress**, which are NOT equivalent. A mismatch has an explicit ⚠️ label, not two ambiguous active-relay badges.
4. Individual Edge actions are `📋 جزئیات`, `🔎 بازرسی تونل`, `🧭 وضعیت آمادگی عملیات`, and existing `🌍 تست زنده IP خروجی` **only after** trusted ingress, active pool membership, a recorded Egress allocation and an independently pinned SHA256. The probe still checks only the pinned pre-existing Core namespace; it never installs/starts a tunnel or sets F4 READY.
5. **Safe action preview:** displays precise missing gates, always **HOLD** for activation/customer routing, even when F4 DB status is valid; this is intentional until PAM, boot, failure injection and 6G-controlled admission have passed. No implementation of protected assign/freeze/unfreeze, PAM installation or domain migration occurs from the new buttons.
6. Each new callback requires `role == 'admin'`, validates the Edge ID, catches HOLD without revealing raw secrets, and only uses bounded read-only inspection. The new component never touches `wg0`, changes IP routes, UID, SQLite data, Cloudflare or server configuration.
7. Unit tests reproduce the real e7 missing allocation, stale/expired F4 evidence, trusted/untrusted ingress registry, role mismatch, pinned transport `UP/ABSENT/HOLD`, HTML escaping, and static checks that the existing bot callback branch has no network/DB mutations.

## UX — operator-visible flow

```text
🛡 مرکز کنترل Egress
  ⭐ پیش‌فرض ورودی: 144.172.84.76
  🌐 مقصد DNS: 144.172.84.76
  🔐 حالت محافظت: خاموش
  ⏳ e7 · 172.86.105.67 · INGRESS_ONLY
  [⏳ e7 · 172.86.105.67]
  [🔄 بروزرسانی وضعیت]
  [🚀 افزودن Edge]
  [🧭 مراحل راه‌اندازی]
        ↓
🛡 جزئیات Edge e7
  📥 Ingress: شناسه ثبت‌شده (زنده‌بودن هنوز نامشخص)
  ⭐ پیش‌فرض ورودی: خیر
  🌐 مقصد DNS: خیر
  📤 Egress: NOT_STAGED (در DB؛ Stage مستقل ممکن است روی دیسک موجود باشد)
  🔏 SHA Pin: ثبت نشده
  🧾 F4: NO_EVIDENCE
  🧯 Fail-Closed: بررسی نشده
  🗝 PAM/Boot: بررسی نشده
  🧬 DNS/IPv6: بررسی نشده
  [🔎 بازرسی تونل]
  [🧭 وضعیت آمادگی عملیات]
  [📋 جزئیات Edge]
  [🔙 مدیریت Egress]
```

**Important:** `NOT_STAGED` is explicitly the **Allocation state in DB**, not an assertion that manually staged e7 files are absent; e7 operator evidence proves staged files and successful iPhone public IPv4. Until dedicated F3/6G release ledger is written, UI must not infer Allocation from the host disk.

## Role/authority and safety invariants

- **Data boundary:** H ingress peer registry is root-owned and validated by the existing reader; untrusted/missing registry cannot confer `ingress_verified`. Host-pool membership is **not** live WG status. Only separately approved F4 `READY` witness with nonexpired `observed_ip == edge_ip` is presented as valid evidence—never as automatic authorization.
- **Trust pins:** the Stage SHA `settings.edge_egress_v1_stage_sha256_<edge_id>` must already be attested by the independent operator. This UI never sets it. The read-only inspector calls only `pinned()`/`observe()`; intentionally does **not** call `ensure()`, `up.sh`, `down.sh` or shell.
- **Probe scope:** existing `live_ip_probe` requires an allocation row in addition to a pin; operator's previous manual e7 probe/phone trace is recorded in K2 memory but **not automatically converted** into F3/F4 DB proof by Telegram.
- **Global safety:** no changes to `edge_egress_protected_mode`, `edge_egress_v1_onboard_enabled`, `hpdef_*`, `srv_mkactive_*`, `ssh_accounts.host`, `settings.dns_current_ip` or the existing 6G/6H lock/journal.
- **Telegram size:** overview is bounded to eight recognized Edge entries; an invalid/contradictory registry/DB mapping is conservatively flagged. A later enhancement can add explicit pagination without relaxing identity verification.

## Phase 2 remaining actions (later PR, only after F4 acceptance)

- Add a privileged **guarded** Edge operator installer/controller based on existing F1/F2/H/K HostActions, with exact Stage/host-key digest pins, independent rescue, dry-run plan, transaction journal and *per-resource recovery*. This is not a simple `/bin/bash up.sh` button.
- Add tested single-UID attach/detach/freeze semantics under owner-only manifests and existing shared 6G lock, verified PAM session binding, no whole-Edge route deletion. Prevent button-driven ready flags.
- Add normalized, fresh Core/Edge service health observability and optional bounded status cache without poll-spam.
- Add confirmation UX with explicit affected user counts, protected/legacy population and rollback plan before any operation.
- Only then Phase 3: guarded protected Edge→Edge relay + Cloudflare CAS, never old `hpdef_` or `srv_mkactive_` direct operation for protected customers.

## Operator-deferred end-of-implementation tests

No production shell commands or reboots now. At the end of implementation, reconcile live Core e7/UID1644 status and timed freeze; validate the deployed bot version; inspect the real Telegram callback rendering and authorization; complete F4/PAM/boot/DNS/IPv6/WG-loss acceptance in an authorized window. **Production UI may not show these code changes until the bot has been deployed.** Preserve all current customers and default relay.

## Sources

- [K2 phase 1 plan](K2_PHASE1_PROTECTED_FOUNDATION_2026-10-13.md)
- [K2 actual e7 iPhone evidence](SSH_EGRESS_K2_E7_MEMORY_2026-10-13.md)
- [K2 end-of-phase live release-gate checklist, Issue #106](https://github.com/DenaSon/nvl-bot/issues/106)

## Phase 2 — B2 incremental checkpoint (2026-10-13)

The next safely deployable source step after PR #107 is **B2: exact Edge Stage inspection, paginated inventory and selected-user preview**. This is intentionally a **read-only operator workflow** until Phase 1 Issue #106 is accepted and a separate, reviewed privileged action controller exists.

- **Pagination:** `hpeg_status` now has `hpeg_page_<n>` back/forward buttons; per-page list size stays 8; Edge detail direct lookup is independent of the visible page, and all pages enforce admin-only, bounded page index and strict `edge_id`.
- **Existing e7 local Stage:** `📦 بازرسی Stage محلی` reads only root-owned files using `ops.edge_egress_v1_transport.stage_hash/pinned/observe` (no raw `wg.conf` or private keys). Correct `core-e7` Stage can now be inspected even when F3 allocation is absent. Reports computed SHA and runtime state as **LOCAL_UNATTESTED** unless the SHA matches an independently attested DB pin. A mismatch is **PIN_MISMATCH / HOLD**; the UI **never writes** the SHA to settings, starts the tunnel or claims READY. Neither this inspect nor legacy `live_ip_probe` constitutes F4 evidence.
- **Selected UID preview:** from the chosen Edge select `👤 پیش‌نمایش تخصیص کاربر`, then type only the SSH username (e.g. `nvl0557`). A one-shot admin-only TTL (120 sec) stores only Edge ID/time in `context.user_data`; the handler rechecks the trusted ingress identity, active pool membership and exact `ssh_accounts` status/recorded host, then gives F3/F4 and existing 6G RUNNING-lease diagnostics. No password/PAM inspection or UID changes. After a reply, cancellation, timeout or access rejection, pending state is cleared. Never expose direct callback `assign` / `unfreeze` / `READY` paths.
- **Safe discrepancy reporting:** public-default IP and Cloudflare DNS remain separate, F4 evidence is timestamp/expiry-sensitive and is **not equivalent to active tunnel or safety-certified SSH client egress**. `NOT_STAGED` in the UI refers only to the allocation database; Stage inspection can independently prove locally staged files without committing allocation.
- **Tests:** kernel/transport reads mocked, no external network action; >8 Edge list pages, direct deep-page Edge lookup, wrong/missing Stage pin, untrusted identity, 6G lease busy, invalid username before DB, one-shot/expired/nonadmin Telegram Handler, SQL no-mutation trace and legacy callback fixtures.
- **Operational policy remains unchanged:** Core tests are deferred until all source phases are complete; do not modify Core, `wg0`, live accounts, DNS, default relay, PAM, or reboot. A GitHub merge or successful CI is not E2E acceptance. `nvl0557` temporary UID guard/freeze remains unknown until a later read-only reconciliation.

### Phase 2 next source increment

A **reviewed, disabled-by-default command-intent/controller** for pinned Edge provisioning and per-UID `freeze/attach/release`, with state-machine, TTL/nonce, 6G lease, root-owned PAM/DoH/boot admission and rollback. **Do not wire execute callbacks** before testable authority and Phase 1 release gates. Track via Issue #108.

## Phase 2 — B3 operator review intents (source checkpoint, 2026-10-13)

**Implementation PR:** Phase 2 B3 adds an immutable, read-only `edge_egress_phase2_review.py` and Telegram callbacks **inside** the existing `🛡 مدیریت Egress` panel. The UI is designed as a safe prerequisite for a future privileged controller; **NO live apply/ensure/attach/freeze/CLI command exists in this increment**.

### Telegram interaction

- Edge details → **🧭 طرح آماده‌سازی Edge (بدون اجرا)** → operator plan with current trusted identity, F3 allocation state, independent Stage pin/runtime observation, F4 acceptance and existing 6G RUNNING status.
- Edge details → **👤 پیش‌نمایش تخصیص کاربر**, input one username within 120 seconds → choose **📋 طرح تخصیص (بدون اجرا)** or **🧊 طرح توقف امن (بدون اجرا)**. User selection is held briefly in `context.user_data` (username/Edge/actor/chat/expiry), not a password/UID token. It is consumed **before** any asynchronous review building. `ssh_accounts.host` is shown explicitly as the *existing DB ingress host*, not confused with the selected egress.
- Each plan is **HOLD** regardless of staged files, `wg-nvl-e7 UP` or a claimed READY flag: additional blockers always include independently accepted PAM/Boot/rescue, DNS/IPv6/transport-loss safety, and a valid shared 6G privileged executor. An independent Stage hash/local observation is not permitted to write the DB pin.
- **👁 تأیید مطالعه طرح (بدون اجرا)** issues a cryptographically random, 120-second **read-only receipt** bound to Telegram actor ID + chat ID + action + Edge + username + SHA256 fingerprint of the inspected F3/F4/Stage/account/6G snapshot. Upon click, the stored ticket is popped **before** any await; the evidence is re-read and the digest must match. Expiry, username change, changed 6G lease, changed F4/Stage evidence, replay, another chat or forged token all return HOLD. A successful receipt says **REVIEW_ACKNOWLEDGED_NO_EXECUTION**; this is NOT approval/authorization to mutate the system.
- **Source guarantee:** `EXECUTOR_ENABLED = False`; no apply API, routes, PAM, systemd, DNS or Cloudflare updater. Telegram code only reads the existing DB and root-owned pre-existing Stage, invokes the pure planner and renders markup. Neither receipt nor private chat message creates a 6G lease or stores an action journal. This UI *cannot* be used to change live customer state.
- Offline tests: invalid actions/usernames, e7 ingress-only, synthetic forged F4 READY still HOLD, read-only SQL traces, running 6G operation drift, expiring nonce, cross-user/chat denial, replay, stale operator plan and Telegram callback role gates.

### Remaining before enabling actual execution

The **next** source milestone is a separate privileged `6G`-journaled executor with a sealed root-only command allowlist and deterministic recovery, tested against disposable hosts before integrating *any* Telegram execute callback. It must re-read F4/PAM/Boot/DoH/UID/host key evidence **inside** the acquired shared lease; this B3 receipt must never be treated as its authority. Phase 1 [Issue #106](https://github.com/DenaSon/nvl-bot/issues/106) real-host acceptance remains OPEN, as does Phase 2 [Issue #108](https://github.com/DenaSon/nvl-bot/issues/108). Operator requested all Core and Edge real-world tests only at the end of implementations, not now.
