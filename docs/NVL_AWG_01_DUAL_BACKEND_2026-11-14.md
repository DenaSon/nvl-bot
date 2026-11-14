# NVL-AWG-01 — Dual ingress tunnel backend (source-only)

Status: first code increment; NOT Production migration authorization.

## Confirmed infrastructure pilot (operator evidence, 2026-11-14)

- Core <CORE_PUBLIC_IP>: AWG 3.1, awg0 10.203.77.1/32.
- Edge <EXISTING_EDGE_PUBLIC_IP>: AWG 3.1, awg0 <EXISTING_EDGE_TUNNEL_IP>/32, UDP 42371.
- SSH customer ingress through Edge public TCP 2252; egress IP was Core public <CORE_PUBLIC_IP>.
- Edge reboot restored awg0/NAT/forwarding; operator retested NPV Tunnel successfully.
- These are operator runtime observations, not proof of bot registration.

## Delivered in source

1. nvl_tunnel_backend.py: strict read-only binding registry, peer AllowedIPs ownership, handshake and Core->Edge ping, for both WG and AWG.
2. Existing bot health path: *only* explicitly VERIFIED registry rows use the new probe. Missing registry/host retains original legacy wg0 path. Invalid registered binding is HOLD and never falls back to wg0.
3. The generated SSH limiter on future Core promotion preserves the legacy 10.77.0.0/24 exemption and adds exact verified AWG /32 shared sources, with a cached SQLite read. Existing running /root/ip_limiter.py has NOT been changed.
4. Unit tests for missing/malformed registry, duplicate IPs, spoofed peers, AWG probe and limiter behavior.

## Database and safety

The SCHEMA constant is not executed on module import or health tick. AWG-02 adoption must explicitly create the table and independently verify pinned SSH host key, interface, public peer key, handshake, NAT and NPV ISP witness BEFORE adding a VERIFIED binding. Legacy hosts are never backfilled implicitly.

Only public addresses, backend, interface, peer public key and verification metadata belong in the registry; never store private keys, HPK, passwords or bot credentials.

No runtime network changes, purchases, Cloudflare DNS writes, user moves, provisioning, AWG Egress/PAM protected-mode support or automatic failover are included in AWG-01.

## Follow-up

AWG-02: adopt the already-installed Edge without rerunning setup_edge_relay.sh; verify every required customer port (SSH 2252 and configured TLS/GOST historically 2088); use pinned host key, journal, identity guards, AWG config and NAT evidence.
AWG-03: guarded 6G/CZ07 Quick Switch, Cloudflare DNS, account assignment, rollback and lifecycle; leave existing protected Egress/PAM as a separate acceptance gate. Ensure running Core limiter has received the AWG-aware source rule before assigning a cohort to an AWG Edge. Retain WireGuard until Core promotion and all active dependency paths can survive replacement.

## Validation

Focused commands:

    python -m unittest tests.test_nvl_tunnel_backend tests.test_p1_shared_edge_ssh_limiter -v
    python -m py_compile nvl_tunnel_backend.py
    bash -n promote_edge_to_core.sh

Run existing repository CI as well. These tests use in-memory SQLite and fake command results; they do not execute systemctl, iptables, Cloudflare or SSH.

## Deployment boundary

Merge is NOT deploy. Confirm deployed Core SHA, snapshot SQLite/host state and use pinned release after separate approval. Before AWG adoption, ensure Core limiter really exempts <EXISTING_EDGE_TUNNEL_IP> and that host identity/NAT checks are updated. The AWG test server is NOT registered as a selectable relay by this PR.
