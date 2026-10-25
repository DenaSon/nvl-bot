# Cloudzy CZ-03/CZ-06 — Safe operation cancellation

Date: 2026-10-25

## What changed

An admin can choose `❌ لغو عملیات و آزادسازی قفل` from the Cloudzy operation status page for a paused/failed CZ03 or CZ06 purchase/install receipt. A second, actor/chat-scoped 180-second confirmation is mandatory. On success, a **single SQLite transaction** marks the primary `cloudzy_edge_operations` receipt `CANCELLED`, marks its optional `cloudzy_cz06_runs` journal `CANCELLED`, and writes `cloudzy_edge_cancel_events` with actor, chat, previous status/reason and timestamp.

The old partial unique indexes are upgraded lazily so `CANCELLED` does not hold the global purchase/quick-run lease. The next authorized purchase is a **new**, separately confirmed provider operation; cancellation itself does not call Cloudzy API or initiate a purchase.

## Which states are cancellable?

Allowed (if no worker is active, host unused, and routes validated): `HOSTKEY_PENDING`, `HOLD_WAIT`, `HOLD_IP`, `HOLD_SSH`, `HOLD_PROVISION`, `HOLD_PREFLIGHT`, `HOLD_PROVIDER`, `HOLD_UNKNOWN`.

Not eligible: `CREATING`, `CREATE_UNCERTAIN`, `CREATED`, `WAITING`, `PROVISIONING`, `EDGE_READY`, `REJECTED`, `CANCELLED`. An uncertain charged provider create must **first be reconciled**, not forgotten. A ready Edge must be managed through the guarded Edge/Relay workflows.

The cancellation guard refuses any Edge found in `host_pool` (by IP or Cloudzy provider ID), any target IP referenced in `settings.hosts`, `dns_current_ip` or `core_wg_public_ip`, unresolved CZ04B/CZ07 target operations, unknown current route settings, or a pending local async worker. The state and safety conditions are rechecked under `BEGIN IMMEDIATE`; confirmation is one-use and time-limited.

Cancellation has **no** Cloudzy DELETE or power operation, no installation replay, no Core WireGuard cleanup, no host reassignment, no DNS/default/Relay change, no customer migration, and no implicit rollback. VPS charges can continue if the provider resource still exists. A partly installed WireGuard peer can remain and requires a separate operator inventory/reconciliation. This is cancellation of **NVL's operation journal** only.

## Production recovery: observed HOLD_PROVISION

Operator-reported receipt:

- op: `ea84f7a336984fdfb97b12b76273949d`
- primary: `HOLD_PROVISION`
- quick: `HOLD`
- VPS ID: `db46564a-71e8-4ed3-b1f4-e6b2dafd6b07`
- IP: `144.172.119.72`
- reason: `PARTIAL_OR_UNVERIFIED_LEGACY_INSTALL`
- prior read-only inventory: no `host_pool` entry for this IP or provider ID
- operator independently reports VPS no longer exists

After the reviewed release is deployed, open **Cloudzy → وضعیت عملیات → لغو عملیات و آزادسازی قفل → تأیید**. The button is shown only when local worker finished. In case of rejection, consult the safe error code and recheck route/WireGuard state without hand-editing DB records. Never delete the receipt, edit an index or manually set `REJECTED`.

Post-cancel read-only audit:

```sh
sqlite3 -readonly -header -column /root/master_bot.db "
SELECT id,status,hold_reason FROM cloudzy_edge_operations
WHERE id='ea84f7a336984fdfb97b12b76273949d';
SELECT operation_id,stage,detail_code FROM cloudzy_cz06_runs
WHERE operation_id='ea84f7a336984fdfb97b12b76273949d';
SELECT actor_id,chat_id,previous_status,previous_reason,created_at
FROM cloudzy_edge_cancel_events
WHERE operation_id='ea84f7a336984fdfb97b12b76273949d';
"
```

## Validation and rollout

Unit coverage includes failed CZ06 Legacy install, both atomic terminal journals, unique-index release, new selection without another provider POST, actor/TTL, active worker, attached Edge/route, and uncertain-create refusal. Run:

```sh
python -m unittest tests.test_cloudzy_quick_edge tests.test_cloudzy_cz06_orchestrator tests.test_cloudzy_cz08_vps_delete -v
python -m unittest discover -s tests -p 'test_*.py'
```

Use pinned-master SHA staging, Python compilation, regression, Core SQLite backup, production cutover and service verification per the NVL production runbook. This commit does NOT deploy to the live Core by itself.

## Further scope

CZ04B and CZ07 route/migration HOLD states are deliberately outside this purchase cancellation feature: their cancel/rollback requires separately verified DNS, Core routing and per-account invariants. Do not use this feature to bypass migration safety fences.
