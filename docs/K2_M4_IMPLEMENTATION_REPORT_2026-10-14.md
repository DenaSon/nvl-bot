# K2 M4 — existing Telegram admin + guarded root portal

**2026-10-14 — M4 currently IN PROGRESS.** Source features wired: admin-only read-only Single/Batch UI and status; trusted root portal source completed with default execution OFF. **Do not classify this as an end-to-end operationally completed phase.** Distinguish: source authored / CI verified / PR merged / deployed / real F4 accepted.

## Before → after M4 work

| Subject | Before M4 | After M4 (feature branch) |
| --- | --- | --- |
| Operator entry | Edge panel had generic read-only transfer preview, one legacy manual user review; no unified Single/Batch | Existing `hpeg_transfer_<edge>` now includes **انتقال کاربران**, launching the existing bot's own CallbackQueryHandler. 2-column admin-only Single/Batch menu; user enters 1 or ≤10 explicit usernames |
| Selection | No bound admin chat selection for M3 waves | Strict validation of names, duplicates, count ≤10, callback data ≤64 bytes, target Edge; only **non-authoritative** username/edge/mode in persisted Telegram user_data (no secret/approval/ticket) |
| Readiness | No M1/M2-backed view for a selected operator UID set | New read-only `inspect_telegram_migration` uses real OS passwd and M2 root PAM/WG source journal when trusted; absent/expired source, F4 or session evidence becomes **HOLD**, never guesses history or claims online readiness. Caller may supply a separately independently attested session counter in a future root service |
| Operator status | No one-vs-group status page under new flow | `edge_egress_k2_m4_status.py` reads original 6G RUNNING plus UID runtime/binding tables, shows each user's metadata state, does **not** call DB PROTECTED a verified public route, never mutates or unlocks |
| Privileged service | M3 had callbacks for preview/ticket/6G execution but no root boundary | `edge_egress_k2_m4_root_portal.py` has typed root-scoped `prepare/execute`, exact superadmin actor/chat, plan-digest HMAC, ≤10 UIDs, physical-F4 witness required, fresh plan before execution, one-shot consumption, existing P3 tickets/6G worker and original durable 6G commit. **Explicitly disabled** (`M4_ROOT_PORTAL_ENABLED=False`, M3 flags still OFF) and NOT linked from Telegram |
| UI/UX consistency | New features risk separate UI language | `docs/K2_M4_TELEGRAM_UX_CONTRACT_2026-10-14.md`: minimal Persian, 2-column, short messages, safe-copy HTML, one bot, backward-compatible actions; **separate final UX-POLISH phase after M7** with its own PR and regression gates |

## Source changes

- `edge_egress_k2_m4_telegram.py` — canonical callback/input parser and UI.
- `edge_egress_k2_m4_operator.py` — read-only actual source identity preview.
- `edge_egress_k2_m4_status.py` — read-only original 6G + runtime projection.
- `edge_egress_k2_m4_root_portal.py` — disabled root-only operator/physical witness gateway.
- `bot_final_v49-2.py` — surgical import + callback + text state branches inside the existing bot, no added Handler, separate bot, global protected-mode toggle, ad hoc routing or credentials stored.
- `edge_egress_k2_final_integration.py` — one new submenu link without replacing prior transfer/health actions.
- `tests/test_edge_egress_k2_m4_telegram.py`, `tests/test_edge_egress_k2_m4_status.py`, `tests/test_edge_egress_k2_m4_root_portal.py` — admin guard, user validation, source/session evidence HOLD, original-6G busy, no false packet READY, replay/actor/F4 and existing handler binding.
- `docs/K2_M4_TELEGRAM_UX_CONTRACT_2026-10-14.md` — current identity and planned separate final polish.

## Incomplete M4 functional gates — explicit HOLD

1. **Root IPC/privilege boundary**: the real existing production Telegram process has not been connected to a deployed attested root worker/socket. Its live handler intentionally calls **only** the read-only preview/status modules. No execute/confirmation button exists and no secret is passed into Telegram Pickle or callback data. Need root-owned secret file (0600), verified module release hash, authenticated actor/chat binding and exact scoped client-to-worker protocol, no generic shell execution.
2. **Independent session attestation**: read-only bot preview leaves `session_provider=None`, hence `SESSION_STATE_NOT_ATTESTED` makes every selection HOLD until an independently vetted SSH session source is bound. Do not infer zero sessions from missing UID-owned processes.
3. **Durable wave UI recovery**: current per-UID 6G status is read-only; no root-owned durable intent/progress projection across Telegram/process restart or trusted UI reconciliation/retry/approval flow yet. The original 6G is the sole authoritative operation lease/receipt; a dashboard checkpoint must not act as another lock.
4. **First/Nth UID guarded bootstrap binding**: M2 source port exists but Telegram cannot automatically stage/replay host modules yet. M5 must independently accept real guard/PAM/Boot/DNS/IPv6 and enable only after off-host rescue/immutable SHA review. Routine operators must eventually use Telegram only.
5. **End-to-end physical safety**: e9 F3 transport STAGED is NOT F4 accepted, canary `nvl0555` not e9-routed. P3 cross-Edge with legacy global mode `0` is still correctly HOLD. No global protected mode flip, manual ip rule, unauthorized DNS/host rewrite, blanket customer migration or silent 6G release.
6. **Unmerged dependency chain:** M1 PR #145 → M2 PR #146 → M3 PR #147 → M4 stacked source PR; parent docs PR #144 remains separate. All must be reviewed before any controlled Production deployment; `master` auto-deploys.

## M4 remaining implementation sequence

- Bind a narrow authenticated UI↔root **typed** transport with no dynamic command execution; immutable original 6G ticket and root session/F4 attestation; no extra bot instance. Expose only after independently reviewed M5 proof.
- Add root-owned bounded/restart-safe wave checkpoint projection (NOT a new 6G lock), proof audit, per-UID recovery/HOLD and admin approval confirmation UI. A lost/unknown 6G state must STOP until explicit safe reconciliation, never auto-unlock.
- Extend status polling to actual P3 durable operation results, no false VERIFIED, no ping spam.
- Complete M4 acceptance on staged disposable VPS with Bounded Single selection → approval → real Worker → 6G receipt → UI status, while all other Legacy users remain untouched. Defer production enable to M6/M7.

## CI and release register

All source tests use mock worker/physical gates and **cannot** attest real root/PAM/WG/SSH/SOCKS routing. Exact-head GitHub Actions full suite and stage-only Python 3.11/3.12 must be independently verified; attach their run URLs to the M4 PR when completed.

**User-visible operator behavior today if safely reviewed/deployed:** admin can browse and preview one/ten account status, with protected transfer execution **disabled**. There is **no** claim of end-to-end M4 or full zero-CLI migration yet.

**Next UI phase after M7:** UX-POLISH, documented above, without changing the seven existing technical phase scope.
