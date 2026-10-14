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

## Continued M4 implementation checkpoint (2026-10-14)

**Two new safety capabilities implemented in the same source PR, still default OFF:**

1. `edge_egress_k2_m4_checkpoint.py`: an independent **root-only durable operator projection** stored in the original SQLite Core DB. Its schema is installed explicitly by a reviewed root migration, never from a bot callback. It records immutable plan hash, actor/chat, usernames, approval **hash only**, PREPARED → RUNNING → SUCCEEDED/HOLD, timestamps and per-UID original-6G receipt IDs. Atomic `BEGIN IMMEDIATE`/CAS, one globally RUNNING wave via partial unique index, and a consumed-approval hash persist across root/bot restarts. A crashed RUNNING wave is **UNKNOWN_INFLIGHT**, not silently resumed, unguarded or declared READY. Original `failover_operations` remains the sole migration/lease authority.
2. `edge_egress_k2_m4_ipc.py`: explicit **Unix AF_UNIX / SO_PEERCRED trusted peer** protocol skeleton for a separately reviewed root daemon. Strong framing (4 KiB), duplicate-field rejection, typed PREPARE/CONFIRM/CANCEL only, peer UID and root process checks, no generic CLI commands, F4 booleans, HMAC tokens or real passwords in Telegram requests. PREPARE returns a short-lived opaque request ID; CONFIRM consumes it before awaiting the original P3/6G executor. Pending IDs exist only in root RAM, so a restart cannot replay them; consumed approvals are checked persistently in the Core checkpoint DB.
3. `edge_egress_k2_m3_waves.py` and `edge_egress_k2_m4_root_portal.py` now commit each UID's **verified original 6G receipt into that durable operator projection BEFORE starting the next UID**. Checkpoint failure is a stopped wave; final state must reconcile the ordered persisted per-UID prefix. A verified DB receipt is not an independent customer packet/no-leak proof.
4. Regression fixtures `tests/test_edge_egress_k2_m4_checkpoint.py` and `tests/test_edge_egress_k2_m4_ipc.py`: real local SQLite persistence/restart, double-confirm denial, wrong actor/chat, stale expiration, foreign 6G RUNNING, one wave at a time, preserved 6G on HOLD, source/UI frames, parser injection rejection, and real AF_UNIX socketpair SO_PEERCRED on Linux. **Only synthetic packet/F4 and root executor callbacks.**

**Operational status:** This is a reviewed-API **transport and projection**, **not** a running socket service. No systemd/root socket has been installed, no bot callback invokes CONFIRM, no root secret on disk, no user routed, no Master merge. Adding a real root service without F4/boot/packet rescue would be premature. **Keep the M4 PR Draft.**

### Remaining implementation chain before M4 field closure

- Deploy and validate a **separate reviewed root-side service loop and 0600/0660 AF_UNIX socket** with explicit service UID, systemd sandbox and root-only key read; no shell executor. Expose client PREPARE/CONFIRM/CANCEL from existing bot only after role/chat + physically accepted F4 proof and sound credentials, with two-step operator confirmation UI. Do not expose live execution in this source PR alone.
- Bind an independent per-user SSH-session counter (current bot preview intentionally always holds when session proof is missing), current PAM/WG proof and original 6G root executor factory; no guess from user process absence.
- Provide read-only UI inspection of durable checkpoint by root-owned ID/projection after restart; a lost root request cannot be re-used. Unknown RUNNING state must remain HOLD until reviewed original 6G and packet evidence reconciliation.
- M5/M6: physical F4, actual SSH/SOCKS IPv4/DNS/NSS/IPv6 no-Core-leak, guard boot/WG loss, independent off-host console recovery. For the mixed-Legacy cohort do not flip protected mode globally; direct cross-Edge UID_ATTACH is still guarded HOLD. No PROD enable/merge without approval.

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


## M4.1 Root Worker source-only continuation — 2026-10-15

See [K2 M4.1 Root Worker source checkpoint](K2_M4_1_ROOT_WORKER_SOURCE_2026-10-15.md). Source now adds a sealed, root-only default-OFF Unix socket host, exact SHA256 manifest and 0600 HMAC file policies, non-root SO_PEERCRED caller UID, bounded framed IPC and tests. **Root daemon entrypoint remains inert:** no trusted P3 factory, independent F4/session witness, production bot non-root UID cutover or live root socket installation. This implements M4.1 code scaffolding, **not** operational M4 execution; M4.2–M4.5 gates remain HOLD. Do not toggle any flags or merge to auto-deploying master.


## M4.2 trusted root evidence and original-6G binding (2026-10-15)

Source integration adapters added on the stacked M4 branch; see [M4.2 evidence/worker handoff](K2_M4_2_TRUSTED_ROOT_BINDINGS_2026-10-15.md). M1/M2 PAM+WG source, root-only actor policy, separately signed session/F4 report, P3-A ticket/original 6G terminal receipt and M2 first/Nth bootstrap under 6G have bounded fail-closed ports. **NOT** an operationally installed worker: trusted real host factory, external probe/signing service, non-root bot split and disposable physical F4 remain HOLD; execution flags still OFF. M4.3/M4.4 are not secretly completed.


## M4.3 two-tap Telegram PREPARE/CONFIRM/CANCEL (2026-10-15)

Source implements a non-root fixed Unix socket client, an actor/chat/message/exact-selection-bound volatile one-shot approval store, root-side M7-only batch gate, and guarded existing `hpeg_m4_*` Telegram callbacks. The root request ID never enters PicklePersistence or callback_data; ambiguous IPC confirmation remains HOLD without replay. Default execution flags remain OFF, current bot is still root and live Root/physical F4 acceptance is unavailable. See [M4.3 handoff](K2_M4_3_TELEGRAM_EXECUTION_2026-10-15.md). SOURCE/CI is not operational deployment.


## M4.4 restart-safe root status source checkpoint — 2026-10-15

An explicit, independently gated `STATUS` IPC action and root-owned SELECT-only checkpoint/6G receipt reconciliation projection were added on the M4 PR branch. `RUNNING` or `HOLD` blocks all fresh checkpoint prepare/begin, even if 6G looks idle; original 6G remains untouched. New Telegram status projection is conservative, actor/chat scoped and does not label original P3 receipts as physical client packet success. See [M4.4 recovery handoff](K2_M4_4_RESTART_RECOVERY_2026-10-15.md). All root/IPC/TG status release flags remain OFF, physical M4.2 blockers and M4.5 integration acceptance remain open.


## M4.5 end-to-end synthetic integration (2026-10-15)

The stage-only full AF_UNIX socket and original P3/6G SQLite checkpoint integration is covered by [M4.5 acceptance document](K2_M4_5_E2E_INTEGRATION_2026-10-15.md) and `tests/test_edge_egress_k2_m45_end_to_end.py`. The exact HEAD CI evidence is linked in PR #148. **Source/CI checks are not real root/PAM/WG/F4 acceptance**; do not merge or deploy. M4.2 trusted live factory and physical test remain unresolved.


## Package A: backend source-hardening checkpoint (2026-10-15)

The *existing* 6G SQL is centralized, a reviewed Root assembly contract, explicit non-root unit/process preflight and signed F4 report snapshot verification are implemented. Read [Package A handoff](K2_PACKAGE_A_BACKEND_2026-10-15.md). **Do not mark Package A operational DONE:** the actual live M2 RootFilePort/P3 factory, production non-root service split and independently deployed offhost F4 observer are not installed, and cross-Edge Legacy mode 0 remains HOLD. No merge/Production/UID changes.
