> **2026-10-14 CURRENT STATE OVERRIDE:** This is a historical acceptance design first written while PR #120 was Draft. PR #120 and #139 are now **MERGED into master** (source checkpoint 331fd86e399bd18e2f524071edb7f14d099e00de prior to docs update). A root-only first-UID PAM/BootGuard installer, pinned Python module stage and original 6G/Linux UID worker are now implemented as **explicit opt-in source**, but multi-UID roster CAS, independently validated live kernel/PAM/SSH/SOCKS DNS/NSS/IPv6 packet/WG-loss/cold-boot F4 and automatic Telegram execute binding are NOT accepted. **Use the newer canonical [controlled SSH deployment runbook](NVL_K2_PRODUCTION_SSH_DEPLOY_RUNBOOK_2026-10-14.md)** for executable steps. Master merge is NOT an SSH VPS deploy. The Gate 0–3 design below remains reference guidance; dated phrases about a Draft PR or absent source worker are superseded. Issues #106/#108 remain OPEN.

---
# NVL K2 — Final Integration and New-Edge VPS Acceptance Runbook

**Status:** Draft code integration, **NOT production deploy, NOT customer transfer ready**. Branch `feat/k2-final-integration-20261013`; [PR #120](https://github.com/DenaSon/nvl-bot/pull/120). Reconfirm exact merged master/CI SHA before any release.

## Goal, locked scope

Retain the original SSH Edge onboarding and customer host migration UX. The new path adds a dedicated protected per-UID Egress so that, for each admitted SSH/SOCKS user, **actual public egress IPv4 == that user's verified real ingress Edge public IPv4**. `ssh_accounts.host`, pool default and Cloudflare A record **alone do not change** the Linux UID Egress route. Old Legacy customers must continue working; no global `wg0`, Core default route, public SSH service, DNS or Cloudflare write as a side effect of simply staging an Edge.

The target experience is existing `🛡 مدیریت Egress → ➕ افزودن سرور` → trusted ingress → pinned dedicated Stage → operator safety review → bounded per-user/batch transfer → external SSH/SOCKS probes → expansion. Migration must be a 6G-journaled **fence-first** saga; no call to legacy `hpdefmig_yes_`, `_db_set_all_accounts_host` or Cloudflare bulk update can substitute for protected UID routing.

## Verified Legacy vs protected traffic semantics

[Legacy traffic switch analysis](NVL_K2_LEGACY_TRAFFIC_SWITCH_2026-10-13.md) is the canonical explanation. The old `hpdef_` chooses an active relay for new account connection addresses, while the separate `hpdefmig_yes_` updates existing `ssh_accounts.host` + Cloudflare ingress. Neither moves Unix users off Core, and neither proves the real SSH/SOCKS internet Egress IPv4. **The K2 primary operator action is now `🔀 تغییر مسیر ترافیک`**; it presents source default, target Edge and existing DNS read-only. The P3-C isolated UID attach and source-only one-user host CAS in this draft remain a **canary building block**, not a replacement for the final all-affected-user ingress+egress Relay cutover. Do not call emergency 6G Core-fallback Failover for this routine action.

## Source state and gaps (do not misrepresent)

- Original `hpeg_wizard` invokes real ingress installer, then opt-in `onboard_after_ingress`. It creates `STAGED_NOT_READY` files/registry, not a 6G-committed allocation or independently pinned F4 READY.
- K2 P3-A–F modules and fake-port unit tests were merged to master. P3-A uses the **single existing 6G persisted lock and journal**; P3-B/C concrete safety protocols and P3-D handoff are release-disabled and **no reviewed live Worker** is registered.
- PR #120 adds the Telegram **read-only transfer preview** entrypoints and restores a missing Legacy Round-Robin protected account guard. An opt-in one-user execution/confirmation callback consumes an independent P3-A execution ticket (not Phase2 ACK) **only if** a separately accepted root-owned `GuardedK2TelegramTransferService` is explicitly registered in application `bot_data`; there is **no default registration/host worker**, so ordinary deployed UI remains non-mutating. The opt-in `edge_egress_k2_customer_move.GuardedCustomerIngressBindingPort` composes the existing P3-A/UID route with one exact protected `ssh_accounts.host` CAS **only after the UID route, fresh F4 and independent ingress proof** are confirmed under the same 6G nonce/intent. It defaults to disabled and is **not registered in Telegram**. It does not enable bulk cutover or replace live F4 acceptance.
- The old K positive handoff in `edge_egress_v1_handoff_adapter.py` requires **every active SSH user already to have a matching protected UID runtime and binding on the source**, and checks DNS/default/source/target identity. It cannot safely migrate arbitrary existing Legacy users merely by being enabled.
- Existing full protected ingress+egress handoff also requires source/target F4, PAM admission, drained sessions, all affected UIDs fenced, owned route repin, IPv4 and negative DNS/IPv6 proofs, and controlled Cloudflare updates.
- Previous real **Miami** `nvl-egc1` and former **e7** `nvl0557` canaries proved real same-Edge external SSH/SOCKS IPv4; Miami route-removal fail-closed passed. None proves fresh boot, WG-loss, DNS/IPv6, batch or current VPS release. e7 provider VPS was removed; leave its Core remnants fenced and untouched.

## Gate 0 — before committing a deploy version

1. PR's exact head CI must pass on Python and Edge stage-only workflows. Review both source and operations delta. Resolve PR review failures **before** merge; record merged `master` commit SHA. Never deploy branch tips or guessed versions.
2. Confirm Core's *actual running* bot/version and persistent DB/schema/6G state read-only. The older documented production pin `2988d0d71f8c65d10a1fb1c7e133ddf0bc7fc698` is historical; do not assume parity.
3. Obtain independently tested out-of-band root/console rescue, encrypted verified backup and rehearsed restore. Pin VPS SSH host key, exact Core/Edge Stage SHA and owner-only manifests.
4. Before connecting any execute callback, implement and review a **real root-only** P3 `BootSafetyPort` / `UIDIndependentSafety` and Worker, registration in the approved release configuration, 6G-journaled stage→F3 allocation/pin→F4 acceptance, and protected transfer of either isolated UID or a carefully enumerated cohort. No setting flag may impersonate measured acceptance.
5. Prove that the new Edge Wizard will not be globally disabled by mixed legacy/protected populations. The current `legacy_new_edge_gate` blocks onboarding in global protected mode and the wizard also blocks when any binding exists: a dedicated protected-aware onboarding path is needed before enabling multiple protected Edges.
6. Keep `edge_egress_protected_mode` and `phase6h_auto_failover_enabled` unchanged until fully reviewed; the current P3-A UID attach gate requires global protected mode, so this mixed-mode incompatibility is a **release blocker**, not a reason to flip global mode.

## Gate 1 — isolated disposable new VPS

- Use a **new, empty, independently recoverable VPS** with one public IPv4. Confirm provider web console and non-root rescue, correct SSH host fingerprint and Core connectivity.
- From admin Telegram, open existing `hpeg_wizard`. Provide IP, one-time Root credentials and customer SSH port. Check real ingress WireGuard peer and root-owned Core/Edge dedicated Egress Stage. On partial failure **do not rerun Wizard blindly**.
- In Edge detail, inspect local Stage and `👥 انتقال کاربران` preview. Expect **HOLD**, not READY, before operator safety acceptance. Check existing Legacy users and default ingress/DNS are unchanged.
- After a separately authorized pinned **code-only** Core deploy, run the read-only inventory: `python3 -m ops.k2_final_readiness --edge-id <verified-edge-id>`. It opens SQLite in `mode=ro` with `query_only=ON`, reports aggregate (not per-customer) data, and exits nonzero while execution is not released. The report is not F4 packet evidence; NEVER turn nonzero into an automatic release.
- Perform independent root-only admission/roster/PAM, boot systemd ordering, per-UID IPv4+IPv6 OUTPUT deny and terminal blackhole validation in the disposable lab, with dedicated transport recovery.

## Gate 2 — actual test account before any batch

- Use only a specifically approved **disposable SSH user** with an observed and verified current ingress via the newly-added Edge. Do not reuse historical `nvl0557` or Miami UID1690 without a separate signed review.
- Acquire **existing 6G RUNNING** operation, persist immutable intent, arm deny before kernel/DB changes; attach exactly that UID to the pinned Edge, then independent external SSH/SOCKS `direct-tcpip` and public IPv4 probes. Assert observed IPv4 equals new Edge's IPv4, NOT Core's. Recheck without HTTP proxy environment.
- Independently capture DNS UDP+TCP/NSS/DoH and IPv6, including negative proof of Core egress leakage. Test **loss of dedicated WG**, controlled recovery, failed-Edge cold boot, reboot login admission ordering, cancellation and lease/journal recovery. Keep other users, `wg0`, default, local admin SSH and Cloudflare stable.
- If any proof fails, leave the UID **FROZEN** with IPv4/IPv6 REJECT and blackhole. Do **not** release to Core or apply Legacy account host/DNS migration as rollback.

## Gate 3 — operator-approved release and cohort migration

Only after a reviewed, measured lab PASS: deploy exactly one pinned and backed-up commit separately from enabling execution; keep execution disabled initially. Verify live version, webhook/Telegram bot, DB migration status, dashboard and Legacy controls. Approve one protected canary before expanding. For existing account batches, enumerate exact source accounts, ingress owners, sessions and live UID/PAM guards, obtain explicit affected-count confirmation, use the **same 6G** journal/fence and a deterministic HOLD/rollback per account; update public address/Cloudflare only as required for full Ingress+Egress migration and never before protected data-plane proofs. Do not re-use old unjournaled `hpdefmig_yes_`.

## Acceptance record template

Record: date/time; exact commit SHA; Core/Edge image/kernel; trusted public Edge IPv4/SSH fingerprint and Stage SHA; client username/UID; source and target ingress; 6G operation ID and no competing RUNNING; F4 witness hash and expiry; new SSH public login/SOCKS `direct-tcpip` results; independently observed remote IP; Core nonleak captures for IPv4/DNS UDP/TCP/NSS/IPv6; dedicated WG loss/recovery; boot failed/healthy; root rescue/restore; other-user unaffected result; final state (`PROTECTED`, `FROZEN`, or `HOLD`); approver.

**GO** requires every real full-system acceptance PASS and an audited executable worker. Source green + a UI click + Stage UP != GO. **NO-GO** means keep the old path intact and do not migrate customers.

References: [canonical handoff](NVL_K2_AGENT_HANDOFF_2026-10-13.md), [F4 acceptance #106](https://github.com/DenaSon/nvl-bot/issues/106), [privileged guarded lifecycle #108](https://github.com/DenaSon/nvl-bot/issues/108), [e7 memory](SSH_EGRESS_K2_E7_MEMORY_2026-10-13.md).
