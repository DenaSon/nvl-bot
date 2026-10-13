# K2 Phase 2 — Guarded Edge retirement (source-integrated)

## Implemented
The existing Telegram Egress Edge detail page now has **🗑 حذف ایمن Edge**.
The admin-only `hpeg_retire_open_<id>` presents a blocker preview and, only
when all ownership and safety checks pass, issues a 120-second actor/chat/
edge/fingerprint-bound confirmation for `hpeg_retire_yes_<id>`.
The confirmation is removed from Telegram session state before awaiting
execution. On failure, the UI fails closed as HOLD with internal logging.

The source integration gates both legacy `hpdelconfirm_` and
`hpdelyes_`: K2-registered Edge objects cannot bypass the new lifecycle.
An old DB with no K2 schema or trusted registry retains legacy behavior,
but malformed/incomplete K2 state refuses to proceed.

The new `edge_egress_phase2_retire.py` is strictly a **backup-first
metadata-only finalizer**. It checks exact ingress peer keys, live and
persistent WG0 peer, namespace, interfaces, route table, systemd/firewall,
local Stage, protected UID/SSH account bindings, the public DNS/default
host, global mode and active 6G journal. If anything remains, including
missing/inconclusive evidence, it returns HOLD. It never alters
WireGuard, network namespaces, kernel routes, SSH users or Cloudflare.
This avoids deleting a network component while any subscriber could fall
back to the Core uplink.

## Deliberately not part of Phase 2
- Live network decommission/removal of namespace/veth/routing is a
  Phase-3 executor task with owner-verified detach/freeze.
- Protected mode 1 deletion stays HOLD until a reviewed guarded
  transactional executor can coordinate it.
- Existing e7 Production metadata was manually retired and disappears
  from the panel. Old e7 routing and UID1644 firewall deny must remain
  untouched until later approved e7 resource reconciliation.
- F4 disposable-VPS acceptance still gates production activation.
- This PR is source-only; no Production install, restart or network edit.

## Verification / safety
- Run `python -m unittest tests.test_edge_egress_phase2_retire`
  and existing `test_edge_egress_*.py` in CI; run syntax validation
  of the large bot entrypoint on the PR branch.
- Test: active/default/DNS, assigned SSH, running 6G, Stage on disk,
  UID bindings, missing kernel inventory, wg0 persistent/live peer,
  multi-actor replay and ticket expiry, registry drift.
- Receipt is metadata-only; **does NOT claim complete disposal** of
  server/kernel resources. File+DB updates use a registry flock,
  SQLite IMMEDIATE transaction, backup and best-effort compensating
  rollback on exceptions. Crash recovery must use the root-only backup.
- `e7` metadata was already manually retired on Production (2026-10-13).
  It is NOT a valid production acceptance target for this new callback.
  Its namespace/veth/UID1644 route are still present and must be
  separately decommissioned after independent guarded acceptance.

## Ordering for the project
1. Finalize bot integration + tests in Phase 2 branch (no production cutover).
2. Phase 3: 6G/6H-locked executor, exact resource ownership,
   account drain, Edge-to-Edge handoff, Cloudflare CAS.
3. Disposable VPS F4/PAM/boot/fail-closed acceptance and dry-run.
4. Reviewed merge, single pinned Production deploy, smoke/E2E.
