# D1-C2A — Protected Relay handoff transaction + legacy mutation fences

**Review status:** Code complete for the **abstract transaction contract, failure simulation and shared-lock fencing**. **NOT production-ready.** There is **no live HandoffPorts adapter**, no bot action invoking `run_protected_handoff`, no selected-UID policy, no systemd deployment, no Cloudflare handoff, and no update to real SSH users. Keep PR #80 **Draft** and setting `edge_egress_protected_mode=0`.

## Why another engine is NOT being added

The transaction coordinator in `edge_egress_handoff.py` requires `HandoffPorts.acquire_6g_lock()` and `HandoffPorts.update_6g_journal()`. These are **ports for the existing persisted Phase 6G lock and journal**, not a new independent lock. The repository intentionally provides no production implementation yet. A future adapter must call the existing `_db_acquire_failover_lock` and `_db_update_failover_operation`, preserve source-account CAS, and implement a recoverable network/DNS transaction.

Legacy 6G/6H must stay unchanged while the protected feature is default-OFF; the existing legacy DNS→Core fallback remains blocked when the protected flag is on. In protected mode the target should be a **Core-terminated SSH Relay**; do **not** rebuild Linux SSH accounts on Standby.

## Strict transaction order (mocked ports, not live operations)

| Order | Journal phase | Required evidence / action |
| --- | --- | --- |
| 1 | LOCKED | Acquire the **same 6G persisted operation lock**, reject busy operations |
| 2 | Preflight | Immutable source usernames + Core **numeric UIDs**; target active Standby; default ownership; identical service port; unique tunnel allocation; `public_domain` not shared with other explicitly active account owners; DNS currently on source Edge, never on Core |
| 3 | CANDIDATE_STAGE | Stage independent Core namespace and target Edge Egress |
| 4 | DEDICATED_PEER_REKEY | Reconcile only the dedicated Egress WireGuard peer, never production `wg0` |
| 5 | EXTERNAL_EGRESS_PROOF | Observe actual Core→target Edge TCP exit IP; require match to target public IP, fresh evidence (≤30s) and all ingress/WG/NAT/IPv6/fail-closed gates |
| 6 | REVALIDATE_OWNERSHIP_AND_ALLOCATION | Repeat exact source username+UID/host ownership, DNS, health and allocation checks after provisioning, while 6G lock is held |
| 7 | ARM_FAIL_CLOSED | Install terminal reject/unreachable path **before changing routes**; exception from this point requires freeze + operator reconciliation |
| 8 | SELECT_TARGET_EGRESS | Select target Edge only for the exact protected UIDs; don't touch Core default route or global routing |
| 9 | VERIFY_CUSTOMER_EGRESS | Verify selected UID outbound TCP and observed external IP again |
| 10 | SOURCE_ACCOUNT_CAS | Perform scoped DB assignment with exact source-set compare-and-swap; SQLite cannot atomically update Linux routing or Cloudflare |
| 11 | EDGE_ONLY_DNS_CUTOVER | Public DNS changes directly from old Edge → new Edge, **never via Core** |
| 12 | VERIFY_FINAL | Verify customer SSH, external Egress IP, DB and DNS after switch |
| 13 | SUCCEEDED | Mark 6G operation succeeded; release shared lock only after all checks pass |

### Failure behavior (intentional availability/security tradeoff)

- **Before ARM_FAIL_CLOSED:** mark 6G operation `FAILED` and leave customer route/DB/DNS untouched; separate unused shadow resources may remain and require later cleanup.
- **At or after ARM_FAIL_CLOSED:** attempt **freeze_customer_egress** and record `EGRESS_RECOVERY_REQUIRED` with status `RUNNING`. Even if freezing fails, the lock remains held. This avoids silently exposing Core as the public Egress, but users may experience an outage until the fault is reconciled.
- Automatic rollback of uncertain DNS/DB/user-routing changes to an unhealthy old Edge is deliberately **not** implemented. A separate reconciliation procedure must prove a healthy Edge and guard policy before undoing any step.
- **No Core fallback** is available through the coordinator's ports. Never change DNS or UID routing to Core when an Edge is filtered.
- Reacquiring 6G lock now checks `detail_json.phase` and refuses **stale-lock auto-recovery** for `ARM_FAIL_CLOSED`, `SELECT_TARGET_EGRESS`, `VERIFY_CUSTOMER_EGRESS`, `SOURCE_ACCOUNT_CAS`, `EDGE_ONLY_DNS_CUTOVER`, `VERIFY_FINAL`, and `EGRESS_RECOVERY_REQUIRED`. This protection is tested on an in-memory SQLite instance using the actual extracted bot function.

**Important crash recovery limitation:** If the database/journal volume is unavailable or the system is abruptly halted *between* network mutation and journal persistence, a robust real adapter needs durable write-ahead semantics, process fencing and startup reconciliation. The current pure coordinator does **not** supply that and must not be enabled. A still-running `RUNNING` operation intentionally blocks legacy manual/auto 6G/6H until recovery is explicitly completed.

## Legacy bypasses blocked conditionally

In `bot_final_v49-2.py`, `_db_assert_legacy_host_mutation_allowed(conn)` reads the `edge_egress_protected_mode` flag in the **same DB transaction** and refuses unjournaled host changes when it is `1` or invalid. The check is now applied in:

- `_db_set_default_host`, `_db_set_all_accounts_host` — protects common administrative default and bulk transfer actions.
- `_db_add_host_pool`, `_db_set_host_active`, `_db_set_host_standby`, `_db_resync_host_pool_from_full_list` — protects critical legacy host inventory state changes.
- `_db_update_setting` for legacy `hosts`, `dns_current_ip`, and `tls_passthrough` keys.
- Existing D1-C1 checks on `_safe_manual_failover_preflight`, `_provision_new_edge`, and the shared legacy Cloudflare DNS updater remain enforced.

**These protections are not a comprehensive audited capability system:** other bulk/legacy SQL and manual management entry points may bypass these setters, and future protected mode must still centralize all writes under a privileged, fenced adapter. The new flag has no UI switch, is default `0`, and **must never be manually flipped to 1 on a production bot** until the implementation is proven.

## Tests / validation

- `tests/test_edge_egress_handoff.py`: success ordering, busy shared lock, conflicting account/UID/global domain states, missing external proof, stale observations, failures before/after protection, forced freeze, failed freeze, journal failure. No real network or database writes.
- `tests/test_edge_egress_shared_lock.py`: uses **real SQLite in-memory transactions** and the actual bot's AST-extracted lock and host setters to test stale protected lock fencing, ordinary legacy stale recovery, concurrent lock denial, default-off legacy behavior, and protected write rejection.
- All new suites are included in `.github/workflows/edge-egress-staging.yml` with Python 3.11/3.12. The large NVL bot itself uses Python 3.12 syntax; relevant AST tests run on 3.12 only.
- Prior isolated Linux CI lab separately proved new kernel WireGuard, namespace-veth NAT, simulated Edge exit IP, Edge outage/rekey and Core tunnel restart. **No actual production Edge endpoints or clients used**.

## Mandatory next step: D1-C2B / D1-C3

1. Build and review a **production adapter** for the existing shared lock + journal, Core and Edge SSH provisioning, WireGuard peer regeneration/rekey, IP-based health proofs, bounded timeouts, and cancel-safe operation fencing.
2. Implement and test the **terminal fail-closed UID policy** and protected system DNS/IPv6 on disposable Linux VMs, before any real account uses it.
3. Add explicit post-crash startup reconciliation and a reviewed/manual break-glass procedure for `EGRESS_RECOVERY_REQUIRED`—never automatically clear a lock from a clock timeout.
4. Make all host/DNS/account state mutations use a single authorized, version-fenced management pathway; review alternate callbacks `hpdef_`, `hpdefmig_yes_`, `srv_mkactive_`, `tlstoedge`, background host checks and legacy `--commit-db` helper. Verify candidate identity keys/certs and secret handling; no private keys in GitHub.
5. Exercise actual separate disposable VMs with a working provider UDP firewall, real `systemd` stop/reboot, SSH client continuity, DNS propagation/failure, SQLite rollback, stale peer rekey, IPv6, BadVPN/UDP.
6. Require encrypted offsite Core and active Edge backups and isolated restore rehearsal before any production network mutation. The operator confirmed valid **local** backups, but offsite backup is still pending.

**Current 406 existing SSH accounts remain unmodified. This PR must not be merged/deployed or tested against production routes in D1-C2A.**
