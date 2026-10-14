# K2 M2 — Shared Protected Infrastructure: final source handoff

**2026-10-14 | Branch:** `feature/k2-m2-multiuid-guard-20261014` | **PR #146** (stacked on M1 PR #145; canonical M1–M7 contract is docs PR #144).

## Scope and exact acceptance language

**M2 infrastructure source is candidate-complete subject to exact-head CI and code review.** This does **not** say M2 was operated on Production, that F4 is physically accepted, or that Telegram currently has an operational migration button. Those are independent M4/M5/M6 acceptance gates. The default executable switches are OFF; production unchanged.

**Operator product goal:** after all M1–M7, normal Edge onboarding, first and Nth UID admission, partial-stage replay, selection, migration and safe recovery must be driven from the existing Telegram admin UI **without operator CLI**. The trusted root worker is the automated implementation behind Telegram; this PR supplies guarded function ports and stages, **not** the M4 bot binding.

## Before → after M2 engineering work

| Contract | Before | After — guarded source API |
| --- | --- | --- |
| First UID | `k2_p3_guard_installer` was a root-only, manual-review first-user installer with no per-mutation existing-6G port and no replay | `ops/k2_m2_first_uid.py` offers gated `guarded_first_uid_bootstrap` and forward-only `resume_first_uid_bootstrap`. Original 6G P3 ticket is asserted before **every** root mutation and before/after PAM CAS. Global PAM changed only after independent deny, DNS/IPv6, F4, rescue, idle and mixed-Legacy witnesses; **PAM remains last** |
| UID #2..N | Bootstrap installer refused all attempts with a nonempty roster | `ops/k2_m2_guard_append.py`: append under the **same existing 6G**, preserve all prior manifest hashes and users, reject UID/priority/DNS-port/spec collisions, stage isolated per-user guard/DNS units, assert deny-first+DNS/IPv6 **True** before CAS of root-owned roster |
| Crash/retry | Interrupted stages needed manual diagnosis and could tempt dangerous unguard | `ops/k2_m2_guard_recovery.py`: read-only first/append stage inspector; precise `HOLD` for untrusted/missing/corrupt bytes and `ROSTERED_DENY_ONLY` for completed immutable stage. Guarded first/next UID resume supports **exact-byte forward-only replay** inside unchanged original 6G with fresh physical gates. No roster removal, no old-UID unprotect, no autonomous lease release |
| Authentic inbound Edge | Unpooled historical `ssh_accounts.host` was not trusted; M1 interface had no concrete source evidence | `edge_egress_k2_m2_ingress_observer.py` checks PAM account-phase username/UID and source `wg0` /32 with root-only registry and key ownership. `edge_egress_k2_m2_ingress_journal.py` implements root-owned exact CAS observation history (max 2000), 300-second expiry, fresh WG/registry/UID re-check and a read-only M1 source callback; **no host metadata fallback** |
| Anti-leak admission | Installer could use a callable guard verification whose return value was ignored | All M2 append root authorization requires affirmative **`guard_verify(manifest) is True` AND `dns_ipv6_verify(manifest) is True` before adding a roster identity. First-UID PAM CAS requires corresponding independent affirmative checks. Default release OFF |
| Other customers | Global SSH/PAM, default host, WG0 and existing UID routes could be a blast radius | M2 never registers a global bot handler or modifies `wg0`/host_pool/Cloudflare/DNS/route rules by itself. Mixed Legacy and independent rescue are mandatory gates in the privileged wrappers. No customer route is attached by these modules |

## Source files

- `ops/k2_m2_guard_append.py` and `ops/k2_m2_guard_recovery.py` — guarded multi-UID roster and conservative stage recovery.
- `ops/k2_m2_first_uid.py` — original-6G-scoped first bootstrap and staged PAM-last recovery.
- `edge_egress_k2_m2_ingress_observer.py` and `edge_egress_k2_m2_ingress_journal.py` — trusted current PAM/WG identity observation and time-bounded root journal interface.
- `tests/test_edge_egress_k2_m2_guard_append.py`, `tests/test_edge_egress_k2_m2_guard_recovery.py`, `tests/test_edge_egress_k2_m2_first_uid.py`, `tests/test_edge_egress_k2_m2_ingress_observer.py`, `tests/test_edge_egress_k2_m2_ingress_journal.py`.
- The existing one-UID first installer, P3-A 6G executor, F4 physical preflight/evidence, DNS, BootGuard and VM lab modules remain distinct and reused; there is no replacement kernel engine or duplicate 6G lock.

## Explicit unfinished **operational** gates — NEVER misreport as M2 production done

1. **Bot/root service binding (M4)**: trust actor/chat/nonce, scoped typed operation dispatch, automatic root module stage/backup, source evidence capture from actual PAM, normal installer resume and F4 display in Telegram. Current source ports are not callable from the bot and flags `M2_APPEND_ENABLED=False`, `M2_FIRST_UID_ENABLED=False`. No operator-CLI rollout until this is integrated/accepted.
2. **F4 independent acceptance (M5/M6)**: disposable clone mixed Legacy/protected SSH and SOCKS, live packet DNS/NSS/IPv6 egress capture, external no-Core-leak, verified WG loss/cold boot, offhost restore, console rescue, Edge and Core capacity. Operator-entered checkmarks and synthetic CI callbacks alone cannot create accepted F4. **e9 is still F3 STAGED, F4 STAGED; UID1636 not routed**.
3. **Recent actual ingress attribution**: the root journal records *real* PAM traffic only, and expires after 300 seconds. It **cannot infer** a currently offline customer's historical source Edge (especially 419 unpooled-host DB rows). Future M3/M4 must provide a safe in-bot source reconciliation/proof handshake or actionable HOLD, never a forged witness/host-field rewrite.
4. **Orchestration (M3)**: the original 6G guarded per-UID worker exists, but one-vs-N migration batching, wave progress, per-UID hold and source+target scope binding must be implemented and revalidated under the lease. A tested stage is **not** a migrated customer.
5. **Operator recovery**: normal, known, exact-pinned partial stages now have guarded replay functions; M4 still must expose approved retry/reconcile safely inside Telegram and report genuine external rescue requirements. An unknown compromised/orphaned stage remains `HOLD`, not an automated unsafe cleanup.
6. **Dependencies**: PR #146 is stacked on unmerged M1 #145; M1–M7 master roadmap is PR #144; M3 experimental branch started earlier must be reconciled **after** M2 code review. Do not merge onto auto-deploying `master` without user authorization.

## Verified source CI checkpoint

- Code/document checkpoint `ec7f6a4cc0fc6776024e697c1685bc3188bec10c`
- [GitHub Actions Python checks](https://github.com/DenaSon/nvl-bot/actions/runs/38622417576): **1,668 tests PASS**.
- [GitHub Actions Edge stage-only checks](https://github.com/DenaSon/nvl-bot/actions/runs/38622424673): **926 tests PASS under Python 3.11** and **926 PASS under Python 3.12**.
- These are synthetic/source CI tests; **not** a real F4/packet witness, deploy confirmation or proof that M2's root service has been bound to Telegram. The documentation-only final checkpoint is independently rerun by GitHub.
- Implementation code review/CI is ready for PR review; the runtime acceptance remains **HOLD** until M4/M5/M6.

## Source acceptance and negative regressions

Offline/unprivileged CI exercises first→second→third UID, duplicate UID/priority/DNS port, old manifest drift, stage byte mismatch, PAM-last ordering, root/PAM/WG spoofing, exact /32 key overlap, journal stale/UID reuse, first/next bootstrap 6G-loss, corrupt roster, runtime readiness and no-release defaults. All host ports and independent F4 proof callbacks are synthetic; physical acceptance not asserted.

**CI results:** Record the **exact PR HEAD SHA** and GitHub Actions `Python checks` + `Edge egress stage-only checks` after both finish. Prior intermediate revisions contained test-fixture errors and **do not** count. Full CI green + reviewed source may close **M2 implementation**, but not the operational F4 field gate.

## Handoff to M3 and M4

M3 must implement one engine for `SINGLE` and `BATCH`, with immutable batch selection under same original 6G, per-UID consent, journal and denial fencing; no unsafe global cohort promotion. M4 binds these now-off guarded M2 ports to the existing Telegram interface (no extra bot, no routine CLI). M5/M6 close the independent physical/e9 per-user packet acceptance; M7 closes controlled Batch. Always report **implemented / CI / merged / deployed / physically accepted** as five separate states.

**Explicit safety invariant:** Under no conditions patch `F4 READY`, globally set `edge_egress_protected_mode=1`, attach `UID1636` with ad hoc `ip rule`, mutate PAM without independent rescue, or drop the original 6G RUNNING lease to make a screen show PASS.
