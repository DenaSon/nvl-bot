# D1-C2B1 — Manual Edge entry points and resource registry

**Status: implementation in Draft PR #80 only. No production deployment, no customer routing, no protected-mode enablement.** Existing `edge_egress_protected_mode=0` remains the safe default for current NVL operation. The legacy management paths continue to work unchanged with that flag; those paths are not yet a safe protected Relay migration.

## Why this change

NVL has multiple independent ways to register, activate, delete, and switch an Edge, in addition to Phase 6G/6H:
- `hp_addedge` → `EDGE_NEW_IP` → `EDGE_NEW_ROOTPASS` → `EDGE_NEW_PORT` → `_provision_new_edge`: ingress-only WireGuard and immediate `host_pool` activation.
- `srv_mkactive_<host>`: **writes default-host DB and TLS flag before Cloudflare and NAT**. A later DNS or remote NAT failure can leave inconsistent state.
- `hpdef_<host>`, `hpdef_migrate_<host>`, `hpdefmig_yes_<host>`: manual default and bulk account transfer; legacy operations do not use the Phase 6G transactional journal.
- `hpblk_`, `hpact_`, `hpstandby_`, `hpdelyes_`: change host availability and may delete the operational `wg0` peer.
- `HOSTS_INPUT`, `HOSTS_APPEND_INPUT`, `HOSTPOOL_ADD_INPUT`, and legacy `tlstoedge`: other host/DNS mutation entry points.

These are real bypasses of the new protected Relay handoff unless covered before any external side effects.

## What changed

### Early shared gating in live callback/text functions

`edge_egress_entrypoints.py` classifies all the above manual actions by a stable `EdgeOperation` enum and evaluates the same `edge_egress_protected_mode` setting. The real bot `callback_handler` and `text_handler` now invoke this **at the beginning**.

| Setting | Admin manual Edge callbacks/text | Behavior |
| --- | --- | --- |
| `0` (default) | Legacy permitted | Existing behavior preserved, **not protected** |
| `1` | Legacy denied | No DB, remote SSH, cloud DNS, WG or account mutation attempted by these entry points |
| Invalid | Denied | Fail closed |
| Non-admin | Denied on guarded Edge actions | Do not authorize Edge changes |

If an Edge/role migration wizard is already waiting for a password while the setting switches to protected, its state is cleared; Edge provision secrets are removed from RAM, and password messages are deleted when possible. No password is ever included in the refusal message.

**These guards are safety fences, not the final operational solution.** `_db_assert_legacy_host_mutation_allowed` in D1-C2A is retained as a second line of defense for several DB setters. Other undocumented mutation paths and raw SQL writes still need an exhaustive final audit before the flag may be enabled. A protected-mode flag forcibly set to 1 right now will block emergency Edge management and **must not be used in production**.

### Per-Edge reservation registry (SQLite; not live bot-integrated)

`edge_egress_inventory.py` defines a separate, transaction-scoped `edge_egress_allocations` table:
- Unique Edge ID and IP; unique tunnel/veth CIDR allocations and route table.
- Validated distinct WireGuard **public** keys; never private keys, SSH user records, API tokens or VPN account passwords.
- Subnet-overlap checks across all existing tunnel and veth allocations, not just string equality.
- Idempotent identical reservation; disallow reassigning a filtered Edge ID to a new IP, and disallow reusing another Edge's keys.
- Caller must hold the existing Phase 6G operation lock and an immediate SQLite transaction before reserving. The registry **does not add a separate failover lock**.
- Only `RESERVED` and `STAGED` can be set by this code. There is no `READY` or `ACTIVE` transition until external-IP proof, fail-closed, and policy checks are implemented.

`ensure_schema()` is deliberately NOT invoked by production `init_db()` in this phase, because no live provisioning adapter consumes the table. Migration and lifecycle adapter must be reviewed together.

## Verification

- `tests/test_edge_egress_manual_entrypoints.py`: prefix collisions, protected/admin gates, callback extraction of real bot functions, intercepted text password wizard, untouched admin menus.
- `tests/test_edge_egress_inventory.py`: real in-memory SQLite transactions, duplicate/cross-overlapping CIDRs, route table/IP/key collision, idempotency and immutable reassignment, stage-only status.
- Existing regression suite and disposable Linux namespace kernel lab remain in CI. The latter verifies an isolated WireGuard/NAT packet path, not true production egress or bot failover.

## Next: D1-C2B2, not Production

1. Create the real bot-owned adapter that *under Phase 6G's persisted lock* reserves an Edge, stages keys on separate hosts, validates admin SSH host keys, safely provisions and rekeys only the **dedicated** WireGuard interface.
2. Add explicit lifecycle state `RESERVED → STAGED → VERIFIED` based on a **fresh end-to-end external-IP probe**, plus durable journal and operator reconciliation after crashes.
3. Make old manual/default/activation/bulk-account flows call the same protected handoff transaction, instead of merely vetoing them. Preserve the existing source-set CAS and global-domain multi-Edge guard; never switch DNS to Core.
4. Complete terminal fail-closed UID + IPv6/DNS policy in D1-C3, isolated Linux VM/systemd reboot/rollback tests in D1-D, encrypted offsite Core+Active Edge backup, restore rehearsal and production read-only preflight.
5. **Do not merge or deploy PR #80**, do not run the staged `up.sh`, and do not enable `edge_egress_protected_mode` until the above release gates pass.

**Safety conclusion:** current Core/Edge and all existing SSH users remain untouched.
