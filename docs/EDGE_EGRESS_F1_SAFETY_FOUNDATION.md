# NVL Edge Egress F1 — Safety Foundation

**Status:** Code-only safety hardening on `feature/egress-f1-safety-foundation-20261011`.
**Source:** V124 / merged PR #80. **No runtime activation, network changes,
`ssh.service` drop-in installation, account reassignment or protected-mode enablement.**

## Purpose and baseline

Core still terminates SSH. Edge supplies ingress relay; a separate WireGuard
Egress staging namespace on Core has already demonstrated outbound public IP
`216.126.229.12`, but the normal `nvl0557` SSH account still egresses via
Core `209.200.246.198`. This PR is **F1 of four**; it cannot make customers
Edge-egress-ready, and F2 must add a durable per-UID session gate.

The current production observation has `phase6h_auto_failover_enabled=1`,
`auto_failover_mode=0`, and `edge_egress_protected_mode=0`. The first is a
separate opt-in; legacy 6G/6H can still perform Core-first DNS handoff.

## F1 changes and invariants

1. **One owned route validator:** `edge_egress_uid_route_state.py` accepts
   only terminal `blackhole default metric 4096` and optionally one exact
   `default via <Edge namespace veth IP> dev <allocated root veth>
   src <allocated root source IP> metric 100`. Foreign routes, duplicates,
   missing blackhole, and partial identity are denied. This is route-table
   ownership validation, not packet-level leak attestation.
2. **DNS restart correctness:** `edge_egress_uid_dns.ensure_terminal_policy`
   now permits a known attached Edge next-hop *with* terminal blackhole.
   Rendered UID DNS services receive validated identity fields and run as
   the selected UID. No resolver or plaintext Core fallback is added.
   Old callers without Edge identity can start **only** with blackhole-only
   routing.
3. **Boot deny-only recovery:** `BootGuardApplier.preflight` permits only
   an exact owned route table. `apply` installs IPv6/direct-local-DNS guards,
   UID-specific DNS redirect and terminal blackhole, then removes an attached
   *owned* Edge next-hop before selecting a previously unguarded UID.
   Unknown routes, rule priority conflicts and foreign UID bindings remain
   hard failures. Never flush main routing or touch operational `wg0`.
4. **Remove global SSH blast radius:** the offline systemd renderer produces
   isolated per-UID guard/DNS services. `ssh_dropin` is deliberately empty.
   A per-UID DNS crash MUST NOT be able to stop the host's shared
   `ssh.service`. Generated services have **no auto-install target** and
   **do not authorize a protected login**.
5. **Honest recovery assessment:** read-only recovery refuses to infer a
   per-UID session gate from `ssh.service Requires/BindsTo`; it explicitly
   flags old shared-SSH coupling and reports unsafe/unverified until F2
   implements an independently attested per-account launch gate.
6. **Legacy 6G/6H fence:** `edge_egress_legacy_fence.py` detects any live
   `PROTECTED` rows in the dedicated `edge_egress_uid_bindings` table.
   The bot denies old host writes inside their SQLite transaction, plus
   refuses legacy DNS changes, shared 6G/6H preflight and Edge remote
   provisioning while such rows exist, even when the global protected
   flag is still 0. No-table and empty-table cases keep legacy behavior.
   Malformed mapping schema fails closed. The F2 protected controller MUST
   hold the same persisted 6G lock while creating protected mappings.

## Tested in this PR

- Isolated owned route observation; foreign Core next-hop, collisions,
  duplicates, absent blackhole, cosmetic kernel route output variants.
- DNS starts under frozen or exact attached Edge policy, rejects unknown
  next-hops; unit is no longer coupled to global SSH.
- Boot apply idempotence, exact owned freeze to blackhole-only, UID mismatch,
  priority conflict and unsupported routing inventory.
- Recovery never reports customer-ready and never promotes an SSH unit
  dependency into a per-user session gate.
- Bot 6G/6H, DNS and Edge onboarding fences triggered with active protected
  mapping; no regressions in legacy behavior while protected bindings absent.

CI and local unit tests may validate these properties **only at code/lab
level**. They do not validate a real VPS reboot or deployed Linux rules.

## Release gates deliberately still BLOCKED

- **F2** must implement one per-user session/forwarding admission gate so a
  protected identity cannot run before its UID guard is armed, without global
  SSH dependency; durable pinned Edge controller, UID/table/DNS-port allocation,
  journaled attach/freeze/recovery and actual ordinary SSH proof.
- **F3** must integrate verified Egress into bot Edge onboarding, mapping,
  readiness, provisioning, and administrator UI.
- **F4** must rehearse fresh **disposable-VPS reboot** with out-of-band console,
  actual `ssh.service` availability, independent administrator recovery,
  DNS/IPv6/UDP and Edge failures, multi-user conflicts, offsite encrypted
  backup/restore. The legacy D1-C3E shared-SSH reboot harness is obsolete and
  must not be construed as a valid gate.
- Protected 6G/6H automatic handoff remains blocked by the existing explicit
  protected-mode gate. In a mixed deployment the new mapping fence denies
  legacy global failover; this may result in an outage rather than exposing
  Core. The full protected failover adapter belongs to a later release.

**Do not run** `edge_egress_uid_boot.py apply --enforce`, install generated
systemd units, enable `edge_egress_protected_mode`, change production UID
rules, migrate `nvl0557`, alter DNS or restart SSH during F1.

## Suggested test command on an isolated checkout

```bash
python3 -m unittest -v \
  tests.test_edge_egress_uid_route_state \
  tests.test_edge_egress_legacy_fence \
  tests.test_edge_egress_uid_dns \
  tests.test_edge_egress_uid_boot \
  tests.test_edge_egress_uid_systemd \
  tests.test_edge_egress_uid_recovery \
  tests.test_edge_egress_bot_integration
```
