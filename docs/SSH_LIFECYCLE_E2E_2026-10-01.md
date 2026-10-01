# SSH Lifecycle Production Verification — 2026-10-01

## Status

The production SSH lifecycle incident is closed for the normal account-management paths.

Active production topology is **Edge-as-Relay / Core-as-SSH-Data-Plane**:

- `ssh_accounts.host` is endpoint/routing metadata.
- Customer-facing Edge nodes remain relays.
- Linux SSH users, PAM user-limit files, account expiry and password operations live on Core.
- Normal SSH lifecycle code must not treat the endpoint Edge as the authoritative Linux host.

## Incident summary

New SSH-account creation could fail after Linux `useradd` had already succeeded on Core.

The previous code treated the selected Edge as the authoritative execution host and Core as a best-effort mirror. In the active relay topology this was reversed: the real Linux user exists on Core, while the Edge is only the customer endpoint.

This could leave a Linux-only orphan after the database reservation was rolled back.

## Production patch

Production source SHA before the lifecycle patch:

`21e4eeb50793f16ec2880e8e2ee64f77303d3870a1867b383ed1559744327d1d`

Production source SHA after the lifecycle patch:

`4d02d2fd3fad35e9f131910addee9195c25ffd2775fd6b9e0e70216f2fb9ef4f`

Production backup created before the change:

`/root/bot_final_v49-2.py.bak-core-ssh-lifecycle-20261001-063953`

The production service restarted successfully with the new source, `NRestarts=0`, and Telegram Application startup completed without startup exceptions.

## Corrected normal SSH lifecycle

The following Linux operations are now Core-local:

- single account create: `useradd`, `chpasswd`, rollback `userdel`
- bulk account create
- enable / disable
- password change
- renewal / expiry update
- delete
- renewal self-heal
- PAM user-limit sync / cleanup
- SSH branches of RED & BLUE operations

The endpoint selected by `_pick_target_host_for_new_account()` is still stored in `ssh_accounts.host` and remains available for invoice/routing/endpoint behavior.

Legacy helpers such as `_mirror_linux_cmd()` remain in the source for failover/alternate-topology work, but normal SSH lifecycle paths no longer call them.

## Production consistency preflight

Before the patch:

- 383 active SSH rows existed in the database.
- all 383 active SSH users existed on Core.
- 0 active DB SSH users were missing on Core.
- historical inactive DB-only accounts remained from earlier migration/rebuild behavior and were not bulk-rebuilt as part of this incident.

This supported the Core-local lifecycle invariant without migrating `ssh_accounts.host`.

## E2E verification

The following paths were tested through the Telegram bot against production and passed:

- single SSH account creation
- disable then enable
- password change followed by successful SSH login
- renewal with matching Linux and database expiry
- delete with Linux user, DB row and PAM file cleanup
- bulk creation of two SSH accounts
- PAM user-limit files matched the database `users_limit`
- endpoint metadata remained on the selected public endpoint while Linux users existed on Core

## Not separately E2E-tested in this incident

These branches were changed to the same Core-local invariant but were not independently exercised end-to-end during this verification:

- renewal self-heal for a deliberately missing Linux user
- RED & BLUE bulk SSH operations
- reduce-expiry path

Treat these as statically validated but not independently runtime-validated.

## GitHub synchronization

GitHub sanitized source was updated with the equivalent lifecycle correction in commit:

`cdc84a9d391f18bf0ac536be21dd3b23f3cccf17`

The repository remains a sanitized development/review baseline. Production can still differ in runtime configuration and production-only hotfix details such as access-control changes; do not blindly deploy the repository over production without an explicit convergence review.
