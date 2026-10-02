# Phase 6G — Safe Manual Failover Engine

Status: implementation branch `feature/phase6g-safe-manual-failover`

## Goal

Phase 6G turns the diagnostic filtering stack into a **manual-only**, explicit,
lock-protected failover workflow.

Phase 6G does **not** enable automatic failover. Phase 6H is the only phase that
may connect high-confidence filtering decisions to automatic actions.

## Safety boundary

Allowed in Phase 6G:

- admin explicitly selects a source Edge;
- admin explicitly selects a Standby target;
- live preflight checks run;
- admin receives a second confirmation screen;
- one manual failover operation executes under a persisted lock.

Still forbidden:

- filtering transitions triggering failover automatically;
- Traffic Anomaly Signal triggering failover;
- broad account migration;
- moving all accounts to one host;
- choosing a Standby automatically.

`auto_failover_mode` remains forced to `0`.

## Critical scope fix

The legacy path used:

```python
_db_set_all_accounts_host(target_host)
```

after rebuilding only accounts from one filtered Edge.

That could rewrite **every account** in `ssh_accounts`, including accounts that
did not belong to the filtered Edge.

Phase 6G removes this from the manual failover path.

The new mutation is compare-and-swap scoped:

```sql
UPDATE ssh_accounts
SET host = :target
WHERE username = :username
  AND host = :source
  AND service_type = 'ssh'
```

Every account from the initial snapshot must still match the source host. If even
one row does not match, the transaction aborts and rolls back.

## Rebuild helper contract

`promote_standby_for_filtered_edge.py` is now rebuild-only by default.

The helper:

1. reads only active SSH accounts whose `host == source`;
2. rebuilds those users on the selected Standby;
3. emits a final JSON summary;
4. does **not** mutate the NVL database.

The helper can mutate DB only with the explicit legacy flag:

```text
--commit-db
```

The Phase 6G bot never passes this flag.

The orchestrator validates:

- exact source host;
- exact target host;
- expected account count;
- exact username set;
- zero failed users;
- no duplicate rebuilt usernames;
- `db_committed == false`.

Any mismatch stops the failover before DB or final routing mutation.

## Persisted lock and operation journal

Phase 6G adds:

```text
failover_operations
```

with:

- operation id;
- mode;
- source;
- target;
- status;
- timestamps;
- account counts;
- previous default host;
- previous DNS IP;
- Core fallback IP;
- error;
- detail JSON.

Only one `RUNNING` failover may exist.

The lock is acquired using SQLite `BEGIN IMMEDIATE`.

Default stale-lock recovery:

```text
30 minutes
```

A stale RUNNING operation becomes:

```text
ABORTED_STALE
```

before a new operation can acquire the lock.

Optional overrides:

- `NVL_FAILOVER_LOCK_STALE_SECONDS`
- `NVL_FAILOVER_HELPER_TIMEOUT_SECONDS`

## Required live preflight

Before a failover can reach the confirmation screen, all relevant checks must
pass.

### Source

- source exists in `host_pool`;
- source is not Core;
- source is the current default host;
- source owns at least one active SSH account.

### Standby target

- target exists;
- target is active;
- target is explicitly marked Standby;
- target is not Core;
- target is not the source;
- target is not currently POSSIBLE or LIKELY filtered;
- customer `service_port` answers live;
- management SSH answers live;
- WireGuard peer is healthy;
- Core-path tunnel evidence is healthy.

### Port invariance

Cloudflare A-record failover only changes the IP address. It does not change the
client port.

Therefore:

```text
source.service_port == target.service_port
```

is mandatory.

The Core fallback must also answer on the exact same customer-facing service
port.

If it does not, failover is blocked with:

```text
CORE_FALLBACK_SERVICE_DOWN
```

## Global-domain multi-Edge guard

The current NVL code defines `public_domain` as a **single global domain** used
in all direct customer configs.

Therefore moving that global A record to a Standby containing only one Edge's
accounts is unsafe when another Edge explicitly owns active SSH accounts.

Phase 6G intentionally fails closed in that state:

```text
GLOBAL_DOMAIN_MULTI_EDGE_CONFLICT:<count>
```

This is not a temporary test restriction. It protects other Edge customers from
being routed to a Standby where their accounts were not rebuilt.

A future per-Edge routing/domain design can remove this constraint safely. Do not
remove this guard while `public_domain` remains global.

Legacy rows with `host IS NULL` or empty are not considered explicit conflicting
Edge assignments; they follow the system default.

## DNS preflight

Cloudflare fixed-domain configuration must be complete.

Current DNS may be:

- the source Edge; or
- the Core fallback IP from a previous failed/retryable operation.

Any unrelated third IP blocks the operation.

This supports safe retries after an earlier operation left customers on the Core
fallback.

## Execution sequence

```text
Admin chooses source Edge
        |
        v
Admin chooses Standby
        |
        v
Live preflight
        |
        v
Second explicit confirmation
        |
        v
Acquire persisted failover lock
        |
        v
Re-run live preflight
        |
        v
DNS: Source -> Core
        |
        v
Rebuild exact source account snapshot on Standby
        |
        v
Validate exact helper JSON/result set
        |
        v
Verify Standby service + admin again
        |
        v
Atomic scoped DB/default commit
        |
        v
DNS: Core -> Standby
        |
        v
Target leaves Standby role
        |
        v
SUCCEEDED
```

The preflight is intentionally run again after lock acquisition. The confirmation
screen is informative; execution never trusts stale UI-time evidence.

## Failure behavior

### Failure before DB commit

Examples:

- Core fallback DNS switch fails;
- helper fails;
- partial rebuild;
- helper JSON mismatch;
- post-rebuild target verification fails.

Result:

- no account DB ownership changes;
- no default-host DB change;
- if Core fallback already became active, DNS remains on Core for customer safety;
- operation becomes FAILED or rollback-safe terminal state.

### Final DNS switch failure after DB commit

Phase 6G atomically restores:

- migrated account `host` values to source;
- previous default host.

DNS remains on Core fallback.

Operation becomes:

```text
ROLLED_BACK
```

### DB rollback failure

This is treated as a critical condition.

The operation is marked FAILED with explicit rollback error and all admins receive
an urgent notification containing the operation id.

## Idempotency

The helper rebuild behavior is retry-safe:

- existing target users are updated;
- missing target users are created;
- DB is not changed by default.

Persisted locking prevents two manual failovers from running concurrently.

Exact source ownership checks prevent a stale retry from rewriting users already
moved by another operation.

## UI

Filtering Monitor is now labeled:

```text
Filtering Monitor — Phase 6G
```

Runtime mode:

```text
Detection: AUTO MONITOR
Failover: MANUAL ONLY
Auto Failover: OFF
```

Each Edge detail can expose:

```text
⚡ Safe Manual Failover
```

when a Standby is available.

Flow:

1. select target Standby;
2. wait for live preflight;
3. inspect source/target/account count/service port/Core fallback;
4. press `✅ تأیید و اجرا`;
5. receive operation completion/failure notification.

The monitor also shows the latest manual failover operation id/status/counts.

## Status values

- `RUNNING`
- `SUCCEEDED`
- `FAILED`
- `ROLLED_BACK`
- `ABORTED_STALE`

## Staging validation

Use a detached worktree from the Phase 6G branch.

Compile:

```bash
/root/venv/bin/python3 -m py_compile \
  bot_final_v49-2.py \
  edge_observability.py \
  checkhost_probe.py \
  regional_filtering.py \
  filtering_runtime.py \
  safe_failover.py \
  promote_standby_for_filtered_edge.py
```

Focused tests:

```bash
/root/venv/bin/python3 -m unittest \
  tests.test_phase6c_regressions \
  tests.test_phase6d_checkhost \
  tests.test_phase6e_filtering \
  tests.test_phase6f_runtime \
  tests.test_phase6g_failover \
  -v
```

Full regression:

```bash
/root/venv/bin/python3 -m unittest discover -s tests -v
```

## DB migration test

Run `init_db()` against a SQLite copy and confirm:

```sql
SELECT name
FROM sqlite_master
WHERE type='table'
  AND name='failover_operations';
```

Expected:

```text
failover_operations
```

## Manual staging scenarios

Do not test destructive routing against production customers.

Use an isolated test database / isolated test Edge and Standby.

Required cases:

1. **Preflight reject: target not Standby**
   - no helper run;
   - no DNS change;
   - no DB account move.

2. **Preflight reject: service port mismatch**
   - returns `SERVICE_PORT_MISMATCH`.

3. **Preflight reject: global-domain multi-Edge conflict**
   - returns `GLOBAL_DOMAIN_MULTI_EDGE_CONFLICT`.

4. **Helper partial failure**
   - no DB account move;
   - final target DNS switch not attempted.

5. **Successful scoped move**
   - only usernames from source snapshot change host;
   - unrelated account hosts remain unchanged.

6. **Final DNS failure**
   - account hosts roll back to source;
   - previous default is restored;
   - operation status is `ROLLED_BACK`.

7. **Concurrent operation**
   - second operation is rejected as `FAILOVER_BUSY`.

8. **Stale lock**
   - old RUNNING operation becomes `ABORTED_STALE`;
   - new operation receives the lock.

## Production gate

Phase 6G may be deployed only after:

- full CI is green;
- staging migration passes;
- isolated manual failover tests pass;
- the global-domain guard behavior is understood and accepted.

After deployment:

1. verify release marker:
   `V117.0-2026-10-03-phase6g-safe-manual-failover`;
2. verify `auto_failover_mode=0`;
3. verify `failover_operations` exists;
4. open Filtering Monitor;
5. verify Manual-only mode is shown;
6. verify no regional transition calls the failover engine;
7. do not perform a production failover unless a real incident and a compatible
   topology require it.

Phase 6H must not start until Phase 6G manual behavior is proven in runtime.
