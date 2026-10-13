# K2 Phase 2 — Guarded Edge deletion (source staging)

## Scope
This branch introduces `edge_egress_phase2_retire.py` and offline tests.
**Not production-enabled:** the large Telegram bot entrypoint has NOT been
updated to import or invoke the new controller. Do not merge/announce the
feature as available until that integration is code-reviewed and CI-green.

This is intentionally a **metadata-only finalizer**, not a live decommission
executor. Under a current Edge Stage, wg0 peer, namespace, veth, route
table, UID binding, systemd reference, firewall reference, active host,
DNS target, SSH host assignment, active 6G lease, missing trusted registry,
or protected-mode configuration, the controller returns **HOLD**.
The operator must first use the future guarded Phase-3 executor to
freeze/detach and remove those owned resources safely and independently.
No legacy `hpdelyes_` behavior may be reused for protected K2 deletion.

## Required bot integration before Phase 2 can close
- Import `plan_retirement`, `issue_ticket`, `retire_metadata`,
  `legacy_delete_managed`, `plan_html`, `RetireHold`.
- In the existing `hpeg_edge_<id>` panel, add exactly one button
  `hpeg_retire_open_<id>` → read-only blockers preview.
- If and only if the preflight is allowed, create a 120-second,
  actor/chat/edge/fingerprint-bound one-shot confirmation ticket; the
  `hpeg_retire_yes_<id>` handler consumes it before any await and calls
  `retire_metadata`, never direct kernel commands.
- All exception paths display HOLD; full errors logged internally,
  no private keys sent to Telegram. On success return to `hpeg_status`.
- Hard-gate legacy `hpdelconfirm_` and `hpdelyes_`: if
  `legacy_delete_managed(db_conn,host)`, block with a link to K2
  management; if safety preflight fails, fail closed.
- Add static integration tests for callback names/role and no
  unprotected legacy bypass.

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
