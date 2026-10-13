# K2 Phase 3-A — Guarded Executor and existing 6G transaction

**Status:** Source-only P3-A implementation, no Production release. No Telegram
execute callback. No live host command execution. F4 release remains BLOCKED
pending the separate real-world acceptance issue #106.

## Objective
One *shared* Phase-6G persisted SQLite lock/journal for bounded protected
operations. Implement no second daemon, lock, durable replay table, or default
route mechanism. `edge_egress_p3_executor.Existing6GGuardedExecutor` is an
explicitly injected orchestration shell for later **P3-B/C** lifecycle work.

### Precise wiring and guarded contract
- `db_conn`, `acquire_fn`, `journal_fn` MUST be the existing Phase 6G
  storage callbacks. New code neither creates tables nor guesses operation IDs.
- No `subprocess`, SSH, network, systemd, database write or Cloudflare API
  is called by P3-A. Concrete host actions are injected exclusively via
  `GuardedHostPort` and are NOT supplied from Telegram.
- The allowlist is limited to `EDGE_PREPARE`, `UID_ATTACH`, `UID_FREEZE`.
  These are contracts, not enabled Production commands. Adding `DECOMMISSION`
  or `EDGE_HANDOFF` requires later bounded review in P3-D/E.
- Execution requires **explicit** `release_enabled=True`, root
  (`geteuid() == 0`), a non-null driver, a short-lived actor/chat-bound
  one-shot ticket, unchanged reviewed evidence and a fresh independently
  attested safety-gate set (resource ownership, stage+SSH host pins,
  rescue, no Core fallback; for `UID_ATTACH` F4/PAM/boot/DNS/idle-frozen).
  Default `EXECUTOR_ENABLED=False`. No bot callback constructs the executor.
- Recheck evidence *after* 6G lease acquisition, with a second live guard
  check after writing protected intent. Do not trust preflight authority
  alone. In future P3-B/C, evidence review must be implemented by actual
  independently verified source gates, not a permissive stub.
- Before the first host-port call, **persist**
  `failover_operations.detail_json.phase=EGRESS_P3_EXECUTE_INTENT`
  with `status=RUNNING` and one request nonce hash. Both INTENT and
  `EGRESS_P3_RECOVERY_REQUIRED` are classified as protected phases by the
  existing `is_egress_recovery_hold` stale-lock classifier.
- Operations are one-shot per instance; repeated nonce hash cannot cross
  a 6G transaction, because historical `failover_operations.detail_json`
  carries it. 6G's single lock fences concurrent requests.
- On partial host write, uncertainty, lost attestation, or verification
  failure: invoke the injected `freeze_or_hold` best-effort, persist
  protected RECOVERY_REQUIRED if possible, keep the 6G lock RUNNING.
  **Never** set FAILED or unlock it after possible host mutation.
- On success, only verified effect permits `SUCCEEDED` via existing 6G
  CAS/journal; do not use a raw exception in the journal. Never silently
  fail over to Core. A journaling uncertainty stays HOLD.
- Crash recovery is **operator-driven only** in P3-A: inspect 6G and owned
  resources under an independent approved recovery plan. Never rerun a
  previously interrupted action or auto-release a protected stale lock.

### Increment acceptance
- Offline tests exercise disabled-by-default, root/port/ticket gates,
  scope restriction, evidence drift before/under lock, shared-lock BUSY,
  journal-before-host-write, replay, verified success, partial failure,
  frozen failure, failed journal, and 6G stale lease HOLD.
- This is **not** proof of F4 READY, PAM installation, boot protection,
  DNS leak prevention or a live Cloudflare CAS cutover.
- Do not set `edge_egress_phase2_review.EXECUTOR_ENABLED=True`; it is still
  a read-only preview controller. P3-F may later add a separate reviewed,
  audited and disabled-by-default command endpoint only after B/C/D/E tests.

### Crash / cancellation reconciliation
`inspect_execution_recovery(db_conn, operation_id)` reads only the existing
6G `failover_operations` journal, rejects another operation's identity or
an unknown phase, and distinguishes a verified terminal SUCCEEDED receipt
from `RUNNING` protected INTENT/RECOVERY_REQUIRED. It has **no** retry,
rollback, CAS override or unlock API. Process cancellation after a possible
host mutation still attempts `freeze_or_hold`, records protected recovery,
then propagates cancellation; an ungraceful power loss leaves the durable
protected INTENT marker for operator inspection.

The source executor's generic injected HostPort is a **P3-A contract**.
It must not be instantiated by Telegram or a long-lived bot handler.
P3-B/P3-C must implement fresh operator-approved host-pinned reviews and
an independently tested per-resource privileged worker, with lease
re-validation INSIDE each privileged command. Mocked gate sets only
exercise the offline protocol, not real F4/boot/packet evidence.

### Next source phases
P3-B pinned provisioning/PAM/boot, P3-C per-UID attach/freeze/release,
P3-D 6G/6H Edge-to-Edge+Cloudflare CAS, P3-E owned decommission,
P3-F Telegram operations UI. Finish code and CI *before* disposable
VM F4/PAM/reboot/WG-loss acceptance, then a single pinned Production deploy
and separate canary activation. Original `wg0`, SSHD, global routes, active
customers and `e7` UID1644 deny rules remain untouched.

## Issue ownership
- [#108](https://github.com/DenaSon/nvl-bot/issues/108) — guarded
  lifecycle source work continues for P3-B/C/D/E.
- [#106](https://github.com/DenaSon/nvl-bot/issues/106) — live F4
  release evidence **must** remain open.
