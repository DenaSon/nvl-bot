# D1-C3D — Practical pre-deploy validation: kernel lab

**Status:** CI evidence gate on draft PR #80. No changes to live Core, active Edge or Standby. Not an authorization to deploy protected mode.

## The actual test environment

The enhanced shell lab creates three actual Linux network namespaces (Core, Edge, simulated Internet) on a disposable GitHub Actions Ubuntu runner, using real kernel WireGuard, policy routing, iptables, NAT, a Unix test UID and TCP/UDP traffic. An independent Core-to-Internet link with a different observed public source IP is explicitly present. If the UID guard is missing, egress visibly leaks through the simulated Core source address. The lab is invalid if that unprotected negative control is unavailable.

The simulated IPs used by the test are sample addresses of the NVL architecture. No real NVL production host is contacted.

## Tests / exact gates

| Gate | What must be true |
|---|---|
| Negative control | Unprotected UID uses functional Core fallback; WAN observes 209.200.246.198. |
| Protected startup | Applying BootGuardApplier on actual Core namespace's kernel twice is idempotent. With blackhole only, protected UID cannot use the working Core route. |
| Full IPv4 default | Protected UID reaches 203.0.113.50 and .51 with WAN-observed Edge IP 172.86.94.174; root still exits as simulated Core IP. |
| IPv6 bypass | Real IPv6 service on simulated WAN is reachable to root; selected UID is blocked by actual ip6tables OUTPUT rule. |
| DNS UDP/TCP | Protected UID sends DNS wire to a nominal external resolver port 53; kernel REDIRECT sends it to the actual local DNS relay bound to UID. |
| TLS DoH | Local relay sends HTTPS/TLS DNS POST through WireGuard to simulated DoH peer on 1.1.1.1:443 with verified hostname cloudflare-dns.com. The fake CI CA is trusted only for this test. Simulated WAN logs actual source and requires Edge IP. |
| Edge outage | Dedicated Edge WireGuard stops; protected UID IPv4 and DNS fail, while unprotected Core WAN still works. |
| Edge route removed | Deleting preferred Edge next-hop preserves terminal blackhole. Core fallback does not carry selected UID. |
| Edge recovery/rekey | Restart Edge peer, rekey dedicated Core WireGuard, reattach UID route; public-IP and DNS checks return Edge IP. |
| Core tunnel restart | Stop/recreate Core's dedicated shadow namespace/veth. While Edge next-hop is missing, protected UID cannot fall back to Core. After explicit reattachment, selected UID exits as Edge. |
| Scoped cleanup | Remove isolated namespaces, dedicated tunnel, test processes and disposable files; operational wg0 is never touched. |

The fake DNS server is a test fixture, not real Cloudflare or a production name server. TLS/IP/routing mechanics are real. The boot guard test intentionally injects a narrow NSS compatibility value and does not change the host's global nsswitch.conf.

## Evidence grading

Successful Python CI and a successful disposable kernel workflow mean KERNEL_LAB_VALIDATED for the simulated packet paths only. This must NEVER be described as a full-production reboot or certified no-leak result.

Production blockers remain:

1. Genuine disposable **VM reboot** with persisted systemd required guard + DNS services and actual SSH sessions; a tunnel restart is not a VM reboot.
2. Test a real system NSS/resolve configuration, systemd-resolved, Varlink/nscd, privileged helper DNS and abnormal app resolver paths. A UID-only redirect cannot prove all DNS callers.
3. Test IPv6 direct/forwarded traffic and protocols other than basic SSH-owned TCP (UDP/BadVPN etc.).
4. Real retained guard on sudden loss of process, iptables flush, route priority collision, kernel restart and overlapping failover operations.
5. Production 6G/6H integrated protected handoff, persisted startup/recovery and scoped multi-user route/table allocation.
6. Offsite encrypted backup and restore rehearsal; safe deployment checklist; chosen canary rollback without exposing protected customer through Core.

Until these gates pass: no merge, no deployment, protected setting OFF.

## Where

CI workflow: .github/workflows/edge-egress-kernel-lab.yml
Kernel script: ops/labs/edge_egress_kernel_lab.sh
Fake DoH fixture: ops/labs/edge_egress_ci_fake_doh.py
DNS query probe: ops/labs/edge_egress_ci_dns_probe.py

Only GitHub Actions root with explicit NVL_CI_KERNEL_LAB=1 may run the lab script. This is not safe to run manually on Production.
