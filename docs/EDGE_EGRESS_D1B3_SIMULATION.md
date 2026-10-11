# D1-B3 — Isolated lifecycle + failure-injection review

**Status:** 32 simulated/unit tests passed plus a **real Linux kernel** Core→WireGuard→Edge→fake-WAN egress lab passed on a disposable GitHub runner, including Edge outage, explicit peer rekey, Core restart and cleanup. Real production Core↔Edge connectivity, actual public Internet, installed systemd units/reboot, and customer fail-closed policy are **NOT** tested. **Do not execute staged scripts on NVL Production.**

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


## Actual kernel WireGuard/NAT lab — verified

GitHub Actions: [successful disposable kernel lab](https://github.com/DenaSon/nvl-bot/actions/runs/38135093152).

The separate `ops/labs/edge_egress_kernel_lab.sh` workflow provisions **three temporary network namespaces on GitHub's ephemeral Ubuntu runner**:

1. Simulated Core and Edge have dedicated underlay veths; a third isolated namespace simulates the Internet HTTP endpoint.
2. The staged `up.sh` scripts create **real** WireGuard interfaces, move Core WireGuard into `nvl-egress-fra1`, install per-namespace iptables-nft NAT and set up veth forwarding.
3. A real WireGuard handshake is confirmed. A TCP request from the Core's veth traverses Core namespace SNAT + WireGuard + Edge MASQUERADE. The HTTP endpoint observes `172.86.94.174` as its source IP **inside the test network**. No packets traverse the real public Internet.
4. Shutting down the test Edge makes the dedicated egress path unavailable (there is no alternate global default in this lab). Restarting Edge **does not immediately restore** the existing Core WireGuard session by itself: Core still shows the old handshake; new Edge has handshake `0`. After targeted removal/reinstallation of the old Core peer on the **dedicated lab interface**, handshake and TCP egress recover.
5. Stopping and restarting the Core-side shadow tunnel recreates its namespace/veth. Egress still reports the Edge IP after the test-only host-veth destination route is restored.
6. Graceful cleanup deletes dedicated interfaces and the inner namespace. All network mutations were isolated to ephemeral CI namespaces, not to NVL Core/Edge or the GitHub runner main route/firewall.

### New lifecycle requirement from the outage experiment

**A restarted/replaced Edge with the same static WG identity can have stale live transport sessions on Core.** Bot-managed Edge lifecycle must coordinate *dedicated Peer rekey/reconciliation* with an active external egress probe, not infer recovery from `systemctl active` or interface existence. The Peer reset demonstrated in CI is only a **lab recovery mechanism**, not a production bot implementation. Failure to rekey can cause a prolonged blackhole until normal WG session rekey. This must be addressed in D1-C and tested with actual Edge replacement.

**Not yet proven:** automatic systemd process health recovery, full VM reboot, public Cloudflare DNS failover, protected SSH UID fail-closed and IPv6/BadVPN cases. The mock tests separately cover scripted stop/start and injected partial-setup failures.

## Next gate: D1-B4 dedicated Linux lab

The disposable GitHub kernel-namespace lab above verifies the basic dataplane, but does not replace **two disposable, non-production VMs** with real systemd, separate OS/kernel instances, and provider-level firewall. Review the generated shell scripts against those environments, then:

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
