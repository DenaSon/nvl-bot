# Cloudzy / Quick Relay — Smart Recovery Phase 2

**Scope:** Continue the **existing** Cloudzy VPS operation after a partial/uncertain step.
No replacement purchase, blind re-provision, automatic DNS move, customer migration,
WireGuard mutation or shortcut around CZ-06/CZ-07 is permitted.

## Entry

From the same owner/chat's `📋 وضعیت عملیات`, choose
`🩺 مسیر بازیابی همین VPS`. The screen chooses only actions justified by
the durable `cloudzy_edge_operations` receipt and, when applicable,
`cloudzy_cz06_runs`.

## Supported paths

| State | Option | Real effect |
| --- | --- | --- |
| `CREATING`, `CREATE_UNCERTAIN`, `CREATED`, `WAITING`, `HOLD_WAIT`, `HOLD_IP`, `HOLD_SSH` | Existing VPS reconciliation | Existing protected Cloudzy GET/unique-hostname flow; never POST create |
| `HOSTKEY_PENDING` | Original independent SSH fingerprint approval | No install until operator confirmation |
| `HOLD_PROVISION` | Validate existing installation | Requires local exact inactive Cloudzy host identity, no customer bindings, unchanged Core identity, pinned host-key, Cloudzy live identity, original postcheck, fresh SSH/WG/Core-path probe; only then atomically move receipt to EDGE_READY and CZ-06 HOLD to EDGE_READY |
| `EDGE_READY` plus `CZ-06 HOLD` | Confirm Standby recovery | Owner-bound single-use confirmation, Core preflight, atomic journal CAS HOLD -> STANDBY_VERIFYING, existing CZ-04A guarded standby routine; no install |
| `EDGE_READY` manual | Existing manual Standby / CZ-04B | Navigation to legacy protected flow |
| `PROVISIONING` / unknown | Inspection only | No installer retry; do not infer no worker from restart |
| `CANCELLED` | Existing VPS inventory | Closed journal stays closed; VPS not deleted |

## Safety

- The two actions that can update journals require a **fresh confirmation nonce**,
  current role, original operator/chat, and current expected journal states.
- Verified-existing-install adoption uses two separate checks: the read-only local
  preview and a second `BEGIN IMMEDIATE` guarded database check **after** the
  live provider/SSH/WG evidence and before atomic CAS.
- Any mismatched provider id, recycled IP, bound users, DNS/route reference,
  concurrent failover, K2 or unresolved CZ-04A/B/07 lease fails closed.
- `cloudzy_edge_recovery_audit` records successful adoption and standby resume.
  No secret, password, public key or raw remote response is stored in this audit.
- If the installation is not provably complete, recovery **does not run setup_edge_relay.sh**.
  A qualified manual infrastructure review is needed; cancellation never
  removes a VPS or clears partial WG changes.
- A recovered `EDGE_READY` with CZ-06 `EDGE_READY` is **not** automatically
  Standby `READY`. Standby activation still requires the original independent
  checks. CZ-07 candidate predicate remains unchanged.

## Verification

Unit/integration tests cover owner mismatch, stolen/expired callback, same-VPS
reconciliation without Cloudzy create, existing-install acceptance, missing
evidence, concurrent journal status, duplicate IP/provider, bound SSH users,
DNS/route locks, and successful/refused standby rechecks.

**Staging E2E checklist (after Phase 1 + Phase 2 deployment):**
1. Ensure Core DB backup and exact Git commit; confirm the new module imports.
2. Exercise one Quick Relay with a fake provider/test VPS and one successful run.
3. Induce an SSH/WG failure *after installation* in an isolated lab, inspect
   HOLD screen and recovery path, confirm install command is never replayed.
4. Induce `CZ-06 HOLD` before standby commit; continue via explicit approval,
   confirm exactly one successful CZ-04A standby action.
5. Confirm CZ-07 still blocks non-READY and non-owner candidates; verify no
   DNS/default/user move before the separate external real-client acceptance.
6. Verify stale/duplicate callbacks and bot restarts do not create a new VPS.
