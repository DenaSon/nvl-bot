# D1-C3A — Fail-closed UID policy planning (no production cutover)

**Status: implemented as an offline policy builder in Draft PR #80.**
**No systemd activation, customer route, DNS, IPv6 or live host configuration is changed by this code.**
It must not be interpreted as D1-C3 completion or an approved deployment.

## Evidence from operator-only host experiment (2026-10-11)

Using the existing D1-C2B3/C2C staging files on the live Core and a configured Standby Edge, the operator:

1. Pinned Standby's SSH ED25519 fingerprint; authenticated Core -> Standby with a dedicated SSH identity.
2. Staged dedicated per-Edge WireGuard peers with host-local private keys, without modifying ingress wg0.
3. Started both dedicated shadow interfaces and confirmed HTTPS from Core's isolated namespace reported the Standby Edge public IP; stopped both afterward.
4. With a short-lived policy table and one test UID, routed only one IPv4 destination through shadow, confirmed the request originated from Standby's public IP, and rolled back routing and interfaces.

This proves the disposable path and one-destination routing, **not** unrestricted IPv4, DNS, IPv6, restart safety, failover, or customer readiness.

## Implemented D1-C3A design

Module: edge_egress_uid_policy.py.

- UIDPolicyRequest: validated Edge spec, username, numeric UID and rule priority; rejects privileged UIDs, reserved priorities and invalid names.
- build_policy_plan: returns structured argv only. No subprocess execution, no database writes, no bot integration and no remote activation.
- guard ordering: reject the chosen UID's IPv6 output; reject direct UID DNS to IPv4 loopback stub; create a terminal blackhole default in the dedicated Edge table; **then** bind selected UID to that table.
- attach: prefer the Core's dedicated namespace veth peer as IPv4 default in the Edge table, leaving blackhole default at higher metric.
- fail_closed_detach: delete only the working Edge next-hop. Do not remove the UID rule or blackhole, so a lost Edge route cannot fall through to Core's public default route.
- verify: explicit route, rule, IPv6 and localhost-DNS firewall inspection commands.
- The result is always customer_ready=False and may not be promoted by this builder.

### Critical boundaries

**DNS is not complete.** Blocking direct port 53 queries to 127.0.0.0/8 prevents one local-resolver delegation path, but libc NSS/systemd-resolved over D-Bus, proxied DNS and DoH require separate validation. Hostname lookup may fail when stub is blocked; until a known per-user DNS implementation resolves through Edge, do not enable this policy for customers.

**IPv6 is not complete.** ip6tables rejection is part of the plan, but its behavior, persistence and interaction with other IPv6 users must be verified on real hosts.

**Crash/reboot is not complete.** A pure plan does not survive reboot. The future controller must enforce protection *before* protected customer processes run, persist blackhole/UID rule/IPv6-DNS gates, reconcile stale state and fail closed on missing Edge, and coordinate with existing Phase 6G operation lock/journal.

**Routing ownership:** The future applying controller must read id -u for the username, validate table/priority ownership and reuse no UID/Priority/Edge table that conflicts with existing state, including legacy table 77/fwmark 0x77. It must never run global route flush, reset iptables, change Core main default, or touch wg0. Multiple UID bindings require a reviewed allocator, not naive duplicate priority use.

**Failover:** Standby is still operational Standby; no 6G manual or 6H automatic promotion occurs here. Protected accounts must never use public DNS fallback to Core.

### Next gates (D1-C3B onward)

1. Build a guarded, idempotent and durable lifecycle controller consuming this plan; Phase 6G lock/journal integration plus ownership reconciliation and UID identity attestation.
2. Implement usable DNS through Edge without unprotected Core resolver paths; test ordinary hostname lookups and DNS leak patterns, and confirm IPv6 rejection.
3. Test unrestricted IPv4 destinations, packet drop/recovery, namespace/Edge restart, Core reboot, policy persistence, cancellation and rollback without unprotected fallthrough.
4. Enable one explicit canary only after independent public IP proof; do not change existing users or default Edge until then.
5. Integrate protected Edge health, rekey and DNS ownership into manual 6G and opt-in 6H failover.

### Running offline tests

From a checkout of the PR, run:

    python3 -m unittest -v tests.test_edge_egress_uid_policy

**Deployment:** No production deploy before the above gates are tested. Stage files on the operator's hosts remain separate from bot runtime.
