# K2 M1 — Unified Single/Batch Inventory & Migration Contract

**Checkpoint: 2026-10-14.** Implementation branch `feature/k2-m1-migration-inventory-20261014`, based on verified `master` `e2726994b9b2389d25f8f1794eda7cef09be7724`. This is the FIRST of seven phases in [the unified M1–M7 specification](https://github.com/DenaSon/nvl-bot/pull/144) (canonical document `docs/K2_UNIFIED_MIGRATION_M1_M7_RELEASE_CONTRACT_2026-10-14.md` in documentation PR #144). PR #144 is still open; don't confuse it with a code release.

## Operator summary: before vs after M1

| Dimension | Before M1 | After M1 (source-level only) |
| --- | --- | --- |
| Single / batch contract | Separate legacy default-host cohort and per-user P3 customer host code; no common selection contract | `select_migration("SINGLE" or "BATCH", exact users, edge_id)` with type, size, name, duplicate validation. Single has exactly one user; batch is an explicit list. No invisible broad selection |
| All-active inventory | Default-cohort helper and legacy enrollment required a unique default and many users on one source | Full active-SSH SELECT scan, stable per-account classification for host_pool active/inactive, unpooled historical, unresolved and target metadata. Other Edge accounts are not included in a selected action without explicit choice |
| Historical ownership | `ssh_accounts.host` could mislead as current ingress source | Historical host stored **only as metadata**; actual ingress is untrusted until a separately supplied fresh live `LiveIngressWitness` agrees with managed Edge identity |
| Linux/account identity | Existing source group audit checks some Linux UID constraints | Full active-account UID and uniqueness scan with duplicate user/UID, partial/orphan protected runtime and binding detection |
| F3, F4, 6G | Existing checks mainly on group/default relay | Target F3 Edge ID, public IP, route table, unique allocation, independently accepted fresh F4 DB receipt and existing RUNNING 6G query; stale or conflicting checks give exact error codes |
| Sessions | Not part of a common single/batch inventory | Exact selected `session_count(name,uid)` evidence required; positive/unknown count yields HOLD before future worker operations |
| Snapshot and safety | No unified selection fingerprint | Deterministic SHA-256 snapshot of selected mode/user list, all active accounts, pool, Edge allocations, target F4 witness identity, UID mappings and selected source/session evidence. Must be RECHECKED later inside original 6G; never a live ticket |
| Activation | Various feature flags OFF | **M1_EXECUTION_ENABLED=False**; all returned `can_execute=False`; zero DB, Linux, PAM, routes, Cloudflare, DNS or bot mutations |

## Code added

- `edge_egress_k2_migration_inventory.py`: immutable `MigrationSelection`, `LiveIngressWitness`, `UserInventory`, `MigrationInventory`; `select_migration` and `preview_migration` functions. No worker, root shell, write SQL, routing or Telegram execute callback is registered.
- `tests/test_edge_egress_k2_migration_inventory.py`: offline, synthetic F3/F4/OS/session tests, including 425-entry coverage example (not production DB snapshot), zero-write trace, single and batch parity, invalid selection, unpooled host, false/stale witness, orphan/partial protected state, duplicate UID, active sessions and existing 6G lock.
- `docs/K2_M1_IMPLEMENTATION_REPORT_2026-10-14.md`: this per-phase before/after and next work report.

## Known limitations, deliberately M2–M5 (not “completed” by M1)

1. No automatically connected **trusted root/WireGuard live ingress observer** exists yet. `LiveIngressWitness` is only a strict contract for a later authenticated provider; **an arbitrary caller returning INDEPENDENT_LIVE is not sufficient for F4/root attestation**. Accounts without it remain `SOURCE_INGRESS_NOT_ATTESTED`.
2. Historic source `ssh_accounts.host` absent from host_pool is classified rather than misused as proven source. Reconciliation of 419 unpooled historical rows is an M2/M3/M4 system integration obligation, not solved by claiming an IP is their source.
3. No per-UID protected Kernel/BootGuard/PAM/multi-UID roster writer, no trusted live external packet/no-Core-leak F4 witness, no M3 existing-6G executor integration, no UI batch execute, and no fleet capacity acceptance yet.
4. This is a *preview*, not a lease or reserve. A future executor must reread and compare every selected identity/evidence and hold a single original 6G persisted lease before any mutation; a valid snapshot fingerprint is never an authorization.
5. M1 inventories account metadata and live evidence only where verified. A nonselected row is explicitly marked `needs_review` rather than given a fabricated ingress. A missing real Edge/F4/witness is an actionable HOLD, not proof that the user is safely transferable.
6. M1 does not require CLI in its eventual Telegram operator interface; M4 must wire the preview, selection/filter and detailed reasons into the existing admin bot. No user-visible functionality or Production migration is claimed yet.

## Required test/release process

```bash
python3 -m unittest -v tests.test_edge_egress_k2_migration_inventory
python3 -m unittest discover -s tests -p 'test_*.py'
```

Review the exact latest GitHub Actions **Python checks** run at this PR HEAD. These commands are documented for CI/developers, **not operational CLI steps** in the final bot workflow.

**Acceptance status at code submission:** source implementation and synthetic tests authored; no physical E2E, no F4 approval, no Production deployment, no authorized real SSH/SOCKS user transfer. Mark M1 source-complete only after the exact-head test suite is observed green.

## Next development step: M2

Build a trustworthy, opt-in **zero-CLI protected infrastructure service** for both one UID and N UIDs: authentic ingress identity provider, versioned multi-UID roster CAS, mixed Legacy PAM admission protection, consistent IPv4/IPv6/DNS/NSS guards, dedicated transport boot persistence, separate independent F4 packet witness/Edge capacity evidence and safe non-root rescue checks. Preserve original `wg0`, e7 UID1644, mia1 UID1690, all nonselected accounts and the original 6G journal. M2 must not bypass safety just to clear M1 holds.

## Hand-off rule for future chats

**Start from M1 PR + canonical M1–M7 document**; do not repeat e9 P1 Telegram wizard or Core SSH troubleshooting. After M1 CI/review, move on to M2 (shared protection including multiple UIDs), not back to a sequential single-only plan. Every future phase must provide a **before/after** report, update essential docs, separate `code/CI/deployment/physical acceptance` and preserve the final requirement of **no routine operator SSH/CLI and no product-side functional blockers after verified M7**.
