# NVL — Legacy/Cloudzy customer route compatibility hotfix

**Date:** 2026-10-28. **Scope:** last operator-confirmed default switch was made through the Legacy bot menu. Historical CZ04B/CZ07 last READY/DONE transferred to 144.172.69.2; observed current default, cached DNS and 488 active SSH assignments were 45.61.180.119. Legacy settings.hosts still led with 144.172.69.2 and included Cloudzy Standby 45.59.113.161. **Cloudflare live DNS was not independently verified.**

## Code changes and boundaries

1. Modify existing bot `_db_rebuild_hosts_from_pool`: under BEGIN IMMEDIATE + original protected legacy/account guards, build customer host list from **existing** customer-listed, active, non-Standby inventory only, with the **unique eligible** default first. Rebuilding does not add unrelated active host_pool inventory (or Cloudzy Standbys), modify DNS, change a default, migrate customers, or rewrite/disable host_pool. An explicitly activated host can be appended only through verified `hpact` activation.
2. The legacy text editor can only select already advertised eligible hosts (unique default first; no unknown/Standby/Core) and does **not** disable or activate host_pool entries as a side effect. Unknown or unverified IP append is refused rather than adding it to the active customer path. Old `HOSTPOOL_ADD_INPUT` direct-unverified activation is denied with a helpful message; use verified Edge onboarding instead.
3. Existing stale Telegram buttons `hpdef_*`, `hpdef_migrate_*`, `hpdefmig_yes_*`, `ipallconf_yes_*` are recognized but blocked from unjournaled default and mass customer moves; route through authorized CZ04B/CZ07 and original 6G gate. Do **not** remove the rest of the Legacy menu or auto-migrate customers.
4. Standby cannot be newly marked if its host still appears in customer-facing settings.hosts; the prior role remains until a separately authorized data correction. No automatic Standby demotion.
5. `legacy_route_compat.py` includes an **operator-only** compare-and-swap metadata repair building the exact expected list. It checks the expected original raw list, unique eligible default, cached DNS agreement, existing SSH account assignment, and absence of unresolved 6G/CZ04B/CZ07 workers. It is **not called automatically by the bot or CLI**. The operator must first independently verify real Cloudflare DNS and keep a recoverable SQLite backup before authorizing any live repair. No code here guesses or changes a Cloudflare record.

## What is not included

- No production deployment, no database patch applied to current Core, no Cloudflare API invocation, DNS PUT, default update, WireGuard/iptables, SSH customer mapping, server purchase/delete or altered CZ04B/07 journal.
- Historical Legacy routes other than these callbacks may still have independent DNS/default writes. This patch prevents the reproduced stale-list failure paths and protects the setting, **not** a claim of complete universal route-authority unification across all old flows. All real cutovers must remain subject to protected 6G+provider/SSH/WG and actual external-client acceptance.
- An existing route drift remains recorded until an operator verifies provider DNS records and approves the separate CAS-only metadata correction. Do not call `_db_rebuild_hosts_from_pool` as an unconditional self-heal or `_db_resync_host_pool_from_full_list` to bulk deactivate relays.

## Test/Deploy sequencing

Source tests use synthetic SQLite, AST extraction of the actual monolithic bot function, no network or provider access. Must pass repository CI before merge. Master source bot is ~1.5MB and the deployed runtime historically is not exactly the git checkout: stage the **pinned** source and inspect exact deployed hash/diff before publication. Do not blindly replace `/root/bot_final_v49-2.py`; this change is primarily inside the large bot entrypoint and requires a safe, separately controlled merge into the running file. A failed exact match must HOLD.

Real Core acceptance after operator-approved publication:
- `/start`, Cloudzy/Edge menus, old legacy host panel read-only, 3 admin access.
- Old default/mass migration callbacks refuse with friendly message, no DNS or accounts changed.
- Standby IP never joins `settings.hosts` through a permitted refresh.
- Inspect exact host/default/active SSH/CZ04B/CZ07 state, then read-only live Cloudflare DNS; verify they align before CAS metadata repair.
- Repeat P4/P5 existing staged failure injection tests; do not start a customer cutover just to test the guard.
