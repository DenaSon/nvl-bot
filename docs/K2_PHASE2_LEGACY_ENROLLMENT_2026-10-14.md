# K2 Phase 2 — Legacy enrollment inventory / safe handoff checkpoint (2026-10-14)

**Scope:** source-only change on the feature branch of draft PR #120. No `master`, Production Core, customers, route, DNS, PAM, WireGuard or Cloudflare mutation.

## Why this is necessary

The existing guarded Phase 2 `execute_relay_switch` and J positive 6G handoff require *every* active SSH UID to be already PROTECTED on exactly the current source Edge with coherent F3 allocation/runtime/binding. Legacy `hpdefmig_yes_` updates ingress metadata and DNS but **does not change Linux UID Egress**, so it is not a conversion mechanism. The P3-C `UID_ATTACH` primitive, as currently defined, requires distinct source/target Edge IP and global protected mode; it must **not** be misused for same-Edge Legacy enrollment, nor may globally enabling protected mode during a mixed-population change be considered safe.

## Implemented now

- New `edge_egress_k2_legacy_enrollment.inspect_legacy_enrollment` is a SELECT-only inventory: uniquely pinned current default/DNS; existing 6G RUNNING exclusion; source and target exact F3 STAGED IDs on the same Core, distinct and collision-free Edge IPs; both **fresh** F4 witnesses; every active SSH account's Unix username/UID and actual ingress owner.
- Exact classification of valid Legacy (neither runtime nor protected binding), valid PROTECTED (same source Edge ID, IP, UID, state), and unsafe/missing/partial/foreign records. No orphan protected rows or UID collisions accepted. Unknown/other-Edge host assignments HOLD.
- Fingerprint covers all observed accounts, actual OS UIDs, allocations, F4 witnesses, runtime and protected bindings. It is only a read-only audit digest, **not** an execution ticket.
- The existing Telegram relay review `🔀 تغییر مسیر ترافیک` displays identified Legacy and invalid counts when mixed, without introducing an execute button or exposing usernames/UIDs. Current ALL-PROTECTED cutover remains blocked until all its established conditions pass.
- Focused in-memory SQLite no-write, UID drift, missing F3/F4, orphan/foreign/partial, 6G busy, DNS and Telegram integration regressions.

## Still BLOCKED — required for actual Legacy → Protected conversion

1. Independently review a dedicated **same-ingress/same-egress** Legacy bootstrap protocol; P3-A currently prohibits source == target and P3-C requires already installed root-only roster/guard. Do not defeat those invariants by changing `settings` or injecting fake attestations.
2. Finish and validate concrete root-only source-Edge PAM, roster, BootGuard, WireGuard transport, IPv4+IPv6/DNS and fail-closed evidence provider on a disposable full-system VPS. F4 must be witnessed independently; DB flags and namespace IP alone do not prove it.
3. With independently tested rescue and recovery, implement audited per-UID or atomic cohort enrollment under the **same** 6G journal/fence, preserving login denial on uncertainty and unchanged other users. Recompute the audit/UID/fresh F4 inside the lease before any host write.
4. Only then authorize existing Phase 2 all-PROTECTED source→target manual J cutover; external SSH/SOCKS public IPv4 must match selected Edge before releasing subscriber access. Do not call Legacy `hpdefmig_yes_` or emergency Core fallback.

## Test

```bash
python3 -m unittest \
  tests.test_edge_egress_k2_legacy_enrollment \
  tests.test_edge_egress_k2_phase2_operator -v
```

CI is offline/source-only; independent disposable VPS and Phase 3 acceptance remain separate. PR #120 remains draft. Update context on the parent PR only after CI PASS.
