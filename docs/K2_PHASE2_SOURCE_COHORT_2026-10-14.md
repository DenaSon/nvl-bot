# K2 Phase 2 — source-only cohort audit checkpoint (2026-10-14)

This is an incremental, **read-only** implementation on top of draft PR #120
for the original Python nvlbot. It does not execute customer cutovers.

## Confirmed gap

The former `read_transfer_preview` counted **all active SSH users**, regardless
of the Edge recorded in `ssh_accounts.host`. With customers spread across
multiple legacy Edges this could misrepresent the cohort of a selected relay
and invite an unsafe bulk change. Phase 1 correctly staged a new Edge
**outside** `host_pool`, which must not be interpreted as already selected
for customer ingress.

## Change and semantics

- New `edge_egress_k2_source_cohort.py` audits the **unique active default
  source** and active SSH accounts associated with it using read-only SQLite.
- Account counts are split into source users, accounts on other known Edges,
  accounts already on the target, and unknown/orphan host assignments.
  Other Edge customers are never candidates for this source's transfer.
- Unknown host assignments, ambiguous defaults and multi-Edge shared ingress
  are explicit HOLD reasons. The preview shows accurate counts and never
  offers a bulk execution callback or writes `ssh_accounts`.
- A new Edge that is not yet in the active customer pool may be displayed;
  **staged is not F4 READY**. Existing protected mode and F4 gates remain
  authoritative. No automatic Failover/6H behavior, legacy wizard or
  Core-wide Linux route is changed.

## Still required before Phase 2 is closed

A root-reviewed **actual** per-UID Worker under P3-A/6G with current PAM,
BootGuard, F3/F4 operator evidence and independent SSH/SOCKS public IPv4
packet proof; protected admission for all affected users; a separately
journaled and verified Edge-only ingress/default/DNS cutover respecting
mixed populations; safe HOLD/recovery on any ambiguity. The existing
`GuardedProtectedUIDPort`, `GuardedCustomerIngressBindingPort`,
`Existing6GGuardedExecutor` and related F4 modules are the starting point.
No safety toggles are flipped merely to green-light this preview.

**Do not merge PR #120 to master.** No production or disposable VPS host
changes are part of this checkpoint. CI proves read-only audit correctness,
not customer IP change.
