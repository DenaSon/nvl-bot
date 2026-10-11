# D1-B3 — Isolated lifecycle + failure-injection review

**Status:** mock-kernel/network-simulator tests completed; real Linux kernel WireGuard/network-namespace smoke tests, systemd restart/reboot, and Core↔Edge public-IP proof are **NOT** completed. **Do not execute staged scripts on NVL Production.**

## Scope

The operator requested no disruption of the current SSH customer population, ingress WireGuard `wg0`, DNS, or Core default route. Accordingly D1-B3 is verified exclusively on GitHub CI using a fake command layer in temporary directories; there is **no production host connection**.

### Code changes

- Fixed Core namespace NAT source: packets forwarded from Core host to namespace arrive with the **root-side veth address**, `10.78.101.1/32`, not namespace veth `10.78.101.2/32`. The old staged command never matched actual C2-style forwarded packets. The corrected generated rule matches `spec.root_veth_ip`.
- `stage_files()` now rejects roles other than `core` or `edge` even for direct Python callers.
- `tests/support/fake_egress_command.py` intercepts all generated network shell-command calls through temporary `PATH` shims for `ip`, `wg`, `iptables`, `sysctl` and `ss`. It never invokes kernel networking APIs.
- `tests/test_edge_egress_activation_sim.py` exercises the generated scripts with fault injection and fake runtime state.
- `.github/workflows/edge-egress-staging.yml` runs all policy, staging and mock-lifecycle tests on Python 3.11/3.12.

### Simulated test scenarios

| Scenario | Expected invariant |
| --- | --- |
| Edge shadow up/down | Adds only tagged Egress firewall/NAT rules; retains preexisting `wg0` and baseline rules |
| Core shadow up/down | Own namespace + veth + WireGuard; no root UID rule and no root default route change |
| Core source NAT | Matches host veth source `10.78.101.1/32`, not `10.78.101.2/32` |
| Edge firewall failure after partial apply | ERR trap removes all generated rules and interface |
| Core namespace failure after partial apply | ERR trap removes namespace, WG and veth pair |
| Busy UDP Edge port | No interface or firewall mutation |
| Existing interface collision | Abort without touching existing resources |
| Idempotent down + repeated stop/start | Simulated cleanup leaves baseline state intact |
| Distinct Edge identities | Independent interface names, namespaces and allocated networks |

**CI result:** 32 tests across the combined D1-B1, D1-B2 and D1-B3 suites passed on both Python 3.11 and Python 3.12. GitHub's separate repository-level Python checks also passed at the preceding head. If the PR head changes, review fresh CI rather than relying on this historical count.

### What simulated success does **not** establish

- Kernel WireGuard handshake or actual public IPv4 egress through `172.86.94.174`.
- Real iptables-nft rule ordering, conntrack, SNAT/return packet path, provider UDP firewall, MTU or link flap behavior.
- Real `systemd` restart, reboot, crash/unclean-stop reconciliation. The tests execute generated `up.sh` and `down.sh` commands with mocks, not actual service manager operations.
- DNS, IPv6 leak safety, BadVPN/UDP, GOST/TLS, V2Ray routing, SSH client continuity, fail-closed policy, or failover automation.
- Proof that 6G's current DNS fallback to Core is safe for protected customers — **it is not**. Do not bypass the 6G global-domain guard or change its rollout controls.
- Endpoint replacement across multiple Edges in `host_pool` and the bot's operation lock. That is D1-C, not this phase.

## Next gate: D1-B4 dedicated Linux lab

Use two **disposable, non-production** Linux VMs with their own public or reachable private network and proper lab IPs. Review the generated shell scripts against the actual kernels and nft-backed iptables, then:

1. Confirm unique Egress tunnel and veth allocations; port `51832/udp` free in candidate lab Edge, and no conflicting interface/subnet/routing table.
2. Stage new secrets with restrictive permissions. Never put private keys or generated `wg.conf` in GitHub.
3. Explicitly arm timed independent cleanup and verify remote management access **before** shadow activation.
4. Start Edge shadow service, then Core shadow service; validate WireGuard handshake and IP observed by an external HTTPS echo service from within Core's Egress namespace.
5. Show that Core default route, `wg0`, existing SSH service and NAT remain unchanged during tests.
6. Failure injection: stop Edge service, drop UDP, restart each unit, reboot the lab VMs, verify cleanup and whether the separate Egress namespace recovers correctly.
7. Verify that all cleanup and rollback procedures are target-scoped; no failure path removes `wg0`, the root default route or unrelated iptables rules.
8. Do **not** enable a single production customer's UID rule until D1-C fail-closed and IPv6 safeguards are implemented and tested.

**Backup gate:** Core and active Edge local-only snapshots were successfully created; encrypted offsite copies and a restore rehearsal are still required before any production runtime changes.

No deployment, merge, or live network changes are authorized by this document.
