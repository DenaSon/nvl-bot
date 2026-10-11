# D1-C2B2 — Shared 6G staging adapter and manual-Edge visibility

**Implementation status:** Stage-only coordinator and real SQLite/journal bridge are implemented, unit-tested and kept behind **unregistered host transports**. Read-only Egress admin status is integrated into NVL bot. **No protected Edge is activated, no customer has been migrated, and no deployment to Production has occurred.** PR #80 remains **Draft**.

## Changes

### 1. Prepare candidate using the same Phase 6G operation lock

`edge_egress_prepare.py` sequences the Core + replacement Edge without installing any active network interfaces:

1. Validate immutable candidate `EgressSpec`; source and target must be distinct public Edge IPs and neither may be Core.
2. Acquire the **existing 6G persisted lock**. If another failover or Edge operation is running, return busy.
3. Recheck current default, source active, target active **Standby**, matching customer service port, DNS pointing to source Edge and absence of conflicting explicitly assigned SSH accounts.
4. Read-only preflight of both Core and candidate Edge. **Never** infer readiness from TCP alone.
5. Generate per-Edge dedicated WireGuard keypairs **on the owner host only** and exchange **public keys only**. No private key is returned to the bot or stored in the registry.
6. Reserve unique Edge identity/subnet/table/public keys in `edge_egress_allocations`, under the existing lock and an SQLite `BEGIN IMMEDIATE` transaction. Refuse retired IDs and incompatible re-staging.
7. Stage generated configs on **Edge first**, then **Core**, without `wg-quick up`, systemd enablement or UID routing.
8. Recheck the exact active source SSH account snapshot and source/default/target/DNS invariants. Reject concurrent account changes.
9. Mark `STAGED` **only**, release the shared 6G lock as `SUCCEEDED` with `customers_moved=0`.

On error, remove **only newly created staging files** through host ports. If cleanup cannot be confirmed, journal `EGRESS_PREPARE_RECOVERY_REQUIRED` and retain the shared `RUNNING` lock for manual reconciliation; **never delete production wg0** or roll customer DNS to Core.

**Important:** The coordinator uses injected host ports; current PR does **not** ship a trusted live SSH/SFTP host transport. The default `NoLiveHostTransport` explicitly rejects attempts. The production bot does **not** register or call the coordinator. It is therefore impossible for this version to provision a real VPS through this code path.

### 2. Real Phase 6G DB contract, still stage-only

`edge_egress_6g_bridge.py` accepts the existing `_db_acquire_failover_lock`, `_db_update_failover_operation` and `db_conn`. It reuses the actual `failover_operations` journal; no second lock is added. SQLite source/target revalidation and registry writes are transactional.

The legacy `_db_update_failover_operation` accepts a **new optional** `require_running=True` for the staging adapter. The SQL update is a compare-and-swap against the existing `RUNNING` status: if another operation already took the lock, stale/aborted staging cannot subsequently mark itself successful. Existing 6G callers retain their original behavior when the optional argument is omitted.

The existing 6G stale-lock code now refuses to auto-release unresolved staging phases as well as cutover phases, including `STAGE_CORE` and `EGRESS_PREPARE_RECOVERY_REQUIRED`. This avoids concurrent resource use after a crash but may require an explicit operator recovery, even when a host is urgently filtered. A durable startup reconciler is a mandatory follow-up.

`edge_egress_allocations` remains a separately declared migration, **not installed in production by `init_db()`**. The bridge refuses a missing schema; it never creates one behind the operator's back.

### 3. Real bot admin read-only screen

A new **«🔐 وضعیت Egress (فقط مشاهده)»** button is included on the existing IP Service/Host Pool admin panel, routed to `hpeg_status`. It reads the protected flag and optionally the reservations **without changing SQLite, DNS, WG, routes or users**.

- Admin only, with a return button to IP Service.
- If no registry schema exists, it displays «نصب نشده».
- Reservation states `RESERVED`, `STAGED`, `RETIRED` do **not** mean `READY` or `ACTIVE`; a clear non-ready warning is shown.
- Unknown protected flag values show a warning; no enable/toggle button is offered.
- No private keys, WireGuard or SSH credentials are displayed.

### 4. Manual and auto lifecycle alignment

Phase 6G manual + Phase 6H automated failover keep their old functional paths as long as `edge_egress_protected_mode=0`. They are **not yet redirected to a protected Relay handoff**.

The existing manual callbacks `hp_addedge`, `srv_mkactive_`, `hpdef_`, `hpdefmig_yes_`, `hpdelyes_`, `hpstandby_`, legacy DNS and host-input wizard are already guarded by D1-C2B1 in protected mode. **This phase adds preparation/visibility, NOT a new protected-mode executor.** Turning the flag on now would block essential manual and emergency actions and is forbidden until the missing adapters and tests are complete.

## Verification and release gates

Tests added:
- `tests/test_edge_egress_prepare.py`: stage sequencing, 6G busy lock, no customer movement, per-host public key exchange, failed preflight, bad keys, stage file rollback, cleanup failure and existing stage collision.
- `tests/test_edge_egress_6g_bridge.py`: real temporary SQLite and 6G-shaped `failover_operations`, ownership rechecks, schema-presence enforcement, stale lock CAS, rollback, account mutation during stage, key/inventory checks.
- `tests/test_edge_egress_status.py`: read-only no-schema behavior, HTML escaping and the *actual* bot callback via AST mock.
- `tests/test_edge_egress_shared_lock.py`: the actual updated journal function can only transition a currently RUNNING record when `require_running=True`; staging phases are protected from automatic stale lock release.

CI: the Edge Egress stage-only matrix runs Python 3.11 and 3.12; integration with the giant bot AST runs 3.12 only. The independent real-kernel WireGuard/NAT lab remains unchanged and non-production.

## Remaining before claiming **D1-C2B2 operationally complete**

1. Write a **pinned-host-key** SSH/SFTP transport for both hosts with bounded commands, secure known_hosts verification, atomic file upload, private keys generated and retained only on host, and a separately reviewed allowlist of remote actions.
2. Build a crash-safe recovery/reconciliation handler for 6G-held staging locks and orphaned reserved files. Include stage timeout/heartbeat and explicit break-glass operator procedure.
3. Implement **live** WG service activation/rekey, new Edge IP/ingress/egress verification, per-UID fail-closed routing, IPv6/DNS controls, and authenticated Edge-to-Edge DNS/CAS cutover. None is present in this phase.
4. Connect *both* manual actions and Phase 6G/6H automated handlers to the same protected handoff transaction, with a tested public-domain multi-Edge restriction. No unguarded old callback may bypass.
5. Run two disposable Linux VMs with real systemd, SSH host-key pinning, reboot/crash injection, IP echo from an actual client and final independent rollback; never use live Core/Edge for these first tests.
6. Confirm **encrypted offsite** Core and active Edge snapshots and an isolated restore rehearsal. Existing snapshots are **local-only**, and Standby backup was deferred at the operator's request.

**Production restrictions:** Do not merge PR #80, do not flip `edge_egress_protected_mode` to `1`, do not execute staged `up.sh/down.sh`, do not change `wg0`, Core routes, nft/iptables, Cloudflare DNS or any existing SSH account. The new stage coordinator is tested against fake host ports, not live VPS infrastructure.
