# NVL-AWG-02 — Adopt an existing AmneziaWG Edge WITHOUT reinstalling

Status: source-only, pending CI/review. No production action permitted.

## Background and pilot

2026-11-14 independently tested infrastructure: Core 91.107.170.239 / awg0 10.203.77.1; Edge 149.104.110.138 / awg0 10.203.77.2. User independently verified NPV Tunnel ingress on Edge TCP/2252 and outbound IP from Core. Both AWG and NAT restored successfully after Edge reboot.

The pilot installed only TCP/2252 NAT. The existing NVL Legacy relay also expects a configured TLS/GOST customer service port, historically TCP/2088. Therefore the pilot, as currently observed, MUST NOT be admitted as a full Legacy Standby without further TLS proof.

## Implemented source components

- nvl_awg_adoption.py: pure identity and Core/Edge evidence validation (AWG peer ownership, overlapping AllowedIPs, Core->Edge tunnel reachability, Edge tunnel IP, IPv4 forwarding, live/persisted NAT + both FORWARD directions on *both* customer ports, boot-ready services).
- nvl_awg_pinned_probe.py: a read-only collector over SSH with an **independently approved** Ed25519 host fingerprint and an existing root-owned private management key, using Paramiko RejectPolicy. Reads only public AWG peer info, interface addresses, iptables, sysctl, service status; no private WireGuard, AWG HPK or SSH secrets are retrieved.
- register_inactive: a BEGIN IMMEDIATE-protected, guard-required transactional registration. Creates a normal manual Edge journal and host_pool record plus AWG binding. The host remains active=0, is_standby=0, is_default=0 (EDGE_READY only), so it does not enter customer routing or DNS. Rejects host collisions, account assignments, Cloudzy receipts, stale evidence, wrong Core identity, conflicting service ports, active automatic failover/K2 and failed shared route guards.
- tests/test_nvl_awg_adoption.py: offline regression cases for multi-peer Core, duplicate/overlapping ownership, incomplete TLS rules, live/persisted NAT, boot behavior, safe DB registration, rollback and identity gates.

## **Intentionally not wired to a button yet**

These are backend primitives, **not** a production-ready button/CLI command. Do not directly call register_inactive from an untrusted callback. The operator UI must:
1. Securely authenticate a private super-admin and enforce one-use explicit approval.
2. Verify and pin the SSH fingerprint using an independent trusted source (never AutoAddPolicy).
3. Re-collect all evidence freshly and bind it to the exact host/ports, using the existing root SSH management key; require independent NPV Tunnel client acceptance.
4. Invoke the existing Core protected/6G mutation guard in the exact transaction.
5. Present EDGE_READY as inactive with zero customer assignments. A later distinct, guarded flow may promote to STANDBY **only after Core limiter adaptation is actually deployed** and TLS/NAT/Client proof passes.
6. Do not change the manual install wizard's default Legacy wg0 behavior.

## Release boundary

The change intentionally does not execute setup_edge_relay.sh, mutate any Core/Edge network device, restart SSHD, install packages, alter the Core default route, change Cloudflare, or transfer users. GitHub merge is not a Core deploy.

Static checks:

    python -m unittest tests.test_nvl_awg_adoption tests.test_nvl_tunnel_backend -v
    python -m py_compile nvl_awg_adoption.py nvl_awg_pinned_probe.py
    bash -n setup_edge_relay.sh

Full GitHub Actions must remain green; no adoption call is authorized until UI/identity/limiter acceptance is fully implemented.
