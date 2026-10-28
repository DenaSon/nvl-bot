# NVL — Phase 5 Guarded DNS / Default Cutover (Staged Only)

**Date:** 2026-10-28. **Release gate:** no production deployment or route mutation. The existing CZ04B Telegram flow remains unchanged until a jointly approved P4/P5 lab and operator-controlled promotion.

## What is built

- `cloudzy_route_reconcile.py`: strict, pure SQLite customer-route projection, rejecting default / cached DNS drift, `settings.hosts` misordering, unknown or inactive listed hosts, Standby leakage, duplicated hosts and source/target drift. Read-only classification of exact Cloudflare record observations (all source, all target, mixed, unverifiable) and local default + settings values. This module never writes DNS, DB or lease state.
- `cloudzy_cz04b_guarded.py`: opt-in subclass of existing Cloudzy04B using the **same** original 6G acquire/journal methods, same CZ04B operations table, provider/SSH/WG/NAT guards, Cloudflare exact-record adapter and guarded SQLite route CAS. It is **not yet bound to the production bot menu**.
- Precisely separates pre-effect failure (can ABORT and release its own newly acquired 6G lease with documented no-external-effect evidence) from a durable `DNS_WRITE_INTENT` (always HOLD with original 6G still RUNNING if the result is uncertain, never any automatic Cloudflare rollback or a second PUT).
- After the original preflight and protected 6G acquisition, recheck route projection, source account fingerprint, provider/SSH/WG/NAT, and the Cloudflare record IDs/TTL/current source prior to any write. After the one intended multi-record write, verify external exact identity and target IP **before** DB route CAS; then verify again after CAS. A post-commit failure keeps HOLD; it does not invent a source rollback.
- `reconcile_evidence` is classification only, including SOURCE/SOURCE needing independent proof the prior worker is truly quiescent, and TARGET/TARGET still needing live provider/6G/operator acceptance. Neither label alone releases a lease.
- No account host migration, K2, DNS change on production, Cloudzy purchase, default repair, global unlock, or customer operation was executed during this phase.

## Deliberate promotion boundary

The existing `cloudzy_cz04b.py` Legacy callback still contains historical automatic DNS rollback on an error. **Do not deploy Phase 5 as if that existing callback had been replaced.** The guarded class is source-staged and needs explicit, controlled wiring and operator acceptance after laboratory P4/P5 failure drills; the original Legacy route must remain available under its existing opt-in feature gate until then. This is a **staged implementation**, not completion of the full production-integrated Phase-5 exit.

Cloudflare DNS is an external non-transactional system; the local SQLite 6G lock protects NVL's writes, not arbitrary external Cloudflare console changes. A read-only snapshot does not certify the prior worker has stopped or delayed requests cannot still complete. Do not use automatic lock clearing, second DNS PUT, blind rollback, `_db_rebuild_hosts_from_pool`, or guessed repair based on snapshot alone.

## Joint P4+P5 test matrix

1. Validate exact Cloudzy provider ID/IP/hostname, SSH host-key and Core port/key before Edge installation; verify post-install identity/SSH/Core again.
2. Test APT busy, disconnected SSH, partial wg0, missing or duplicate SSH/TLS DNAT or MASQUERADE, missing persisted NAT; preserve HOLD_PROVISION and avoid installer replay.
3. Verify CZ04A/CZ06 Standby has no customers or DNS binding and fresh provider+SSH/WG probe; test post-commit probe failure, then adopt SAME VPS only after verified live evidence.
4. Simulate Cloudflare GET 401/429/timeout prior to acquiring 6G: no DNS writes or new unresolved Journal.
5. Simulate first and second DNS PUT uncertain failure: partial/complete remote outcome, CZ04B HOLD and original 6G RUNNING, **no automatic rollback or retry**, DB stays at source until a verified commit.
6. Simulate Cloudflare record ID / TTL / source IP changes after preview or during PUT; no unverified DB commit; report reconciliation.
7. Simulate SQLite source-account fingerprint or default/hosts drift, conflicting original 6G lock, failing database CAS, and post-commit read timeout. Never claim READY and never silently clear a protected 6G.
8. For a successful lab route only, exact live target DNS + DB target + CZ04B READY + original 6G SUCCEEDED must agree; source remains intact and customers are not moved by Phase 5.
9. Before any actual Core cutover require independently evidenced affected-ISP SSH E2E connectivity and explicit authorization; Phase 6 handles customer moves and new account CREATE/RENEW checks.

**Release sequencing:** deploy P4+P5 modules for isolated smoke / read-only inspections, then perform controlled failure injection in a disposable provider sandbox or VPS. Do not mutate production Cloudflare DNS, default relay, or customer mappings as a smoke test.
