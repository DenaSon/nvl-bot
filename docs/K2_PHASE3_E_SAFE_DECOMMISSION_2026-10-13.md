# K2 P3-E — Safe Decommission / Orphan Cleanup (source-only)

## What this closes

Adds a guarded, fail-closed **orphan-transport retirement** contract for
the case where an Edge VPS and its registry/F3 metadata have already been
retired but Core still retains that Edge's dedicated namespace, VETH,
WireGuard interface, policy table and persistent systemd units.

**Release remains blocked** until an independent root-only host worker and
real F4/lab + recovery drills are accepted. The present module exports
**no installer**, no arbitrary shell wrapper, no network executable and
no Telegram execute callback. `P3E_RETIRE_EXECUTOR_ENABLED=False`.

## Contracts and owner isolation

Existing `edge_egress_phase2_retire.py` remains the **separate** root-only
registry/F3/host-pool *metadata-only* delete path, backed up, signed and
held if any dedicated kernel resource remains. Do not change that to
"delete everything". `edge_egress_p3_retire.py` only handles the dedicated
Kernel/systemd orphan when **metadata is already detached**.

The source-only `ExecutionScope(action="EDGE_RETIRE")` uses the **same P3-A
6G persisted lock**, actor/chat/TTL-bound ticket, nonce and
`EGRESS_P3_EXECUTE_INTENT` journal, with six additional review gates:
`BACKUP_VERIFIED`, `ORPHAN_OWNERSHIP`, `NO_CUSTOMER_DEPENDENCIES`,
`UID_FENCES_PRESERVED`, `PERSISTENCE_AUDITED`, `WG0_UNTOUCHED`.
Existing 6G cannot be bypassed by clicking the legacy delete callback.
After any uncertain action, 6G remains `RUNNING` with protected
`EGRESS_P3_RECOVERY_REQUIRED` and the worker must re-arm exactly the
previously owned UID fences for operator-only reconciliation.

Read-only preflight MUST establish:
- Root-trusted, SHA256-pinned **fixed** Core Stage path\n  `/root/nvl-egress-v1/core-<edge_id>` using the existing
  `ops.edge_egress_v1_transport.pinned` API; exact Edge ID, Core IP and
  public Edge IP. No stage/no pin is HOLD (never infer from `e7` alone).
- Required K2 schema present. NO active/default host entry, SSH account
  hosted on old Edge, DNS default on Edge, F3 candidate, allocation,
  readiness, protected UID mapping/runtime dependency or competing 6G
  RUNNING operation. Protected mode for unrelated UIDs is not changed.
- Trusted registry snapshot with no conflicting ID/IP; if its entry
  remains, **P3-E does not edit it**. The independent Phase2 metadata
  retirement remains necessary when eligible.
- Independent read-only kernel inspector must prove complete ownership,
  no foreign interfaces/routes/policies, no WG0 runtime or persisted
  peer reference, no session, exact UID rule+priority+table and OS
  ownership, and **IPv4 REJECT, IPv6 REJECT and terminal metric-4096
  blackhole** for every potentially affected orphan UID. Unknown probe
  result is HOLD.

## Mutation order (injected exact-resource host port, never generic CLI)

1. Persist the shared 6G P3-A retire intent **before** any host mutation.
2. Disable ONLY verified Edge-specific auto-start/services and reobserve.
3. With same 6G lease and complete kernel inventory, delete ONLY
   the exact stale preferred Edge next hop for each authorized UID.
   **Never** delete RPDB UID selector, its table's blackhole, its REJECTs
   or any other UID's policy, even if the UID is a disposable test user.
4. Recheck no selected UID is routed through the removed Edge; only
   then retire the dedicated namespace/WireGuard/VETH and exact owned
   service references. **Never run `wg-quick down wg0`, `iptables -F`,
   `ip rule flush`, table-wide route flushing, or `ssh restart`.**
5. Verify orphan namespace, root VETH, dedicated WG interface and
   owned unit enablement are absent, while all UID selectors/REJECTs/
   blackholes remain intact. No account deletion is performed.

Partial failure, lost 6G lease, stage mismatch, active login, foreign
reference or missing firewall/IPv6/blackhole condition => protected HOLD.
The operator must independently reconcile stage, inventory and backup
before an explicit **new** approved attempt. Never auto-release UID
traffic to Core or treat a removed VPS as evidence of an unused route.

## Case e7 (previous operator evidence, NOT live rechecked by CI)

- e7 public Edge `172.86.105.67` deleted by provider.
- P2 registry and F3 metadata were retired with a saved DB+registry
  backup at `/root/nvl-backups/e7-retire-pRfWH19n`.
- Namespace `nvl-egress-e7`, root VETH `vnh-e7`, RPDB UID1644
  priority 1782 table 20007 and Edge next hop were last observed present.
- Account `nvl0557` exists with different recorded `ssh_accounts.host`;
  it is a test account, but must **not** escape to the unprotected Core.
- Prior IPv4 REJECT proof exists. **IPv6 REJECT, boot persistence and
  full root-owned Stage hash still require new independent observation.**
  P3-E must HOLD unless these conditions are actually proved. The
  code does not claim e7 was physically cleaned up.

## Tests / continuation

`tests/test_edge_egress_p3_retire.py` exercises 17 fake-host
and real SQLite shared-6G scenarios, including orphan e7, preserving
UID fence/blackhole and default host, metadata conflict, foreign
resource, forgotten session, Stage/registry drift, missing 6G gates,
partial transport failure and unverified finish, including forged review identity. This is **not** a real
Linux teardown or proof that a live system is safe.

P3-F should expose a minimal admin preview with explicit
`METADATA_ONLY` vs `ORPHAN_CLEANUP` and HOLD blockers.
Do not wire root execution until independent release gate #106 passes
and the exact pinned worker is tested on a disposable VPS.
The separate regular Edge with STAGED allocation and protected
active users must first be drained/rebound and administratively detached;
P3-E intentionally refuses implicit deletion of those records.

All code merged only after both exact-head GitHub CI suites pass.
No Production deploy, SSH, WireGuard, DNS or Cloudflare mutation here.
