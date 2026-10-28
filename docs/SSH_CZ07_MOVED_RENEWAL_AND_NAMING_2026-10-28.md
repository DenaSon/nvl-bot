# NVL SSH — post-CZ07 renewal and naming compatibility

**Date:** 2026-10-28. **Scope:** Python business-path patch only; no live SQL, DNS, VPS, SSH account rename or customer cutover.

## Observed production case

Current Core recorded the latest cutover `144.172.119.190 → 144.172.119.120` as `MOVED`, 490/490, with 490 **active** SSH accounts assigned to the new Edge. Older hosts retained 482 and 1 **inactive** accounts. The operator confirmed successful customer SSH-tunnel connectivity and new SSH account creation, but encountered `SSH_REACTIVATION_CZ07_UNRESOLVED` when attempting renewal/reactivation of an inactive account. Newly issued SSH user names were observed with prefix `test` rather than the requested `nevel-{number}`.

## Cause and implementation

- `ssh_reactivation.resolve_ssh_reactivation_host` had an outdated unresolved-job predicate that treated **MOVED** as an active migration. Now only genuinely open statuses block renewal/reactivation. It treats sources from `MOVED` and `DONE` as retired for host-selection purposes. Existing guards still require a single legitimate active/default customer Relay, validated settings `hosts` and `dns_current_ip`, no Core/Standby target, and the existing account-write/legacy-host mutation fences. A lapsed account on an old Edge can therefore be assigned to the currently valid Edge in the same BEGIN IMMEDIATE transaction as status and expiry update, with `ssh_reactivation_audit`. On invalid route, no account change occurs.
- SSH single and bulk creation now use a fixed **default SSH brand `nevel`**, independent of the legacy global `settings.brand` (which can be `test`). New reserved user names are formatted `nevel-NNNN` (example `nevel-0491`) with the existing monotonic per-brand counter, atomic DB reservation and Linux duplicate retry. Numeric formatting uses **at least** four digits; numbers beyond 9999 are preserved.
- A representative with an explicit `username_prefix` retains their existing custom format; V2Ray timed/volume creation is unchanged. Old usernames, passwords, Linux accounts, invoices and active sessions are **not renamed**. When the initial per-brand counter is missing, the lookup scans both legacy `nevelNNNN` and new `nevel-NNNN`. Existing `counter_nevel` settings are respected.

## Verification

- Unit test the real production `_db_preflight_ssh_reactivation`, `_db_activate_ssh_account_tx` and `_db_toggle_status` SQLite lifecycle via AST, for MOVED renewal, earlier old-host redirection, concurrent MIGRATING/VERIFYING/HOLD/PAUSED_SAFE denial, DNS drift and no partial write.
- Extract real bot naming/reservation functions via AST: DB unique reservation, counter compatibility, agent brand and V2Ray unchanged, six SSH call sites opting into new naming and four V2Ray sites unchanged.
- Run the complete Python/release CI plus Legacy and Edge safety CI before merge.

## Core rollout constraints

**Do not blindly overwrite production `bot_final_v49-2.py`** (large and subject to hotfix drift). Deploy `ssh_reactivation.py` and `bot_final_v49-2.py` together as the exact tested SHA only after staged copy, checksum/diff validation, production backups, compilation, private SQLite backup, and a controlled service restart. The full bot file may have local modifications; hold for review rather than overwriting. No migration/schema update is required.

Smoke test **one** inactive historical SSH account renewal using the bot, verify its DB status, expiry and host `144.172.119.120`, and confirm the Linux account and SSH login. Next create **one** SSH account; expect `nevel-<digits>` on the current Default. Do not require recreation of the 490 migrated accounts.

**Code merged is not the same as Core deployed, and DB-level host correctness is not an authenticated customer-path test.**
