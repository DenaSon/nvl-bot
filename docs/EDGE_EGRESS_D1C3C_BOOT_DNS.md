# D1-C3C — Boot guard + per-UID DNS (draft, opt-in)

**Status: Implemented and unit-tested on Draft PR #80, not installed or enabled on Production.**

## Problem and prior proof

The operator's live Core/Standby experiment verified one protected UID (nvl0557 / 1644) could connect through dedicated WireGuard and exit as the Edge IPv4 for one destination, then successfully roll back. It did NOT prove all-destination traffic, DNS, IPv6, restart or failover safety. Existing C3B canary is intentionally disposable and restores the formerly unprotected account.

Linux UID routing alone cannot prevent DNS leaks if the host's systemd-resolved/NSS module hands the request to another process whose outbound identity differs from the SSH UID.

## Changes

### Boot: edge_egress_uid_boot.py

- Requires a root-owned, root-only manifest with explicit PROTECTED_BOOT_GUARD mode, exact username, UID, route-table priority and Edge spec, and optionally a DNS-port redirect.
- Validates live OS UID, route and rule collisions, protected-table ownership, and DNS/NSS compatibility before mutation.
- Orders guard installation: IPv6 REJECT, local loopback DNS REJECT, optional per-UID UDP/TCP DNS NAT redirect, terminal IPv4 blackhole and finally UID selection. Boots DENY, not CONNECTED or READY. Runs idempotently when only owned rules exist.
- Generates a systemd unit requiring activation *before ssh.service*. RequiredBy=ssh.service is essential; WantedBy alone does not prevent an unprotected SSH start. Unit installer/enable logic is intentionally absent.
- Does NOT install tunnel interfaces, change wg0, Core main route, DNS records or customer assignments.
- Boot protection is limited to newly started ssh.service sessions. Other UID processes started by other units, cron or linger require an additional launch gate and live monitoring. Merely generating this unit does not establish reboot safety.

### DNS: edge_egress_uid_dns.py

- Implements local unprivileged UDP+TCP DNS wire forwarder, designed to run as the exact protected UID.
- Uses IPv4-only HTTPS POST to hard-coded 1.1.1.1:443 with CA-validated TLS hostname cloudflare-dns.com via SNI; no system DNS bootstrap, Core DNS fallback, or plaintext fallback.
- Builds per-UID-only iptables OUTPUT NAT redirect for direct UDP/TCP port 53 requests to a high loopback port. Redirect installation is tied to boot guard when configured, and has exact check commands for idempotence.
- DNS proxy refuses to start if its user lacks the UID routing selector and the frozen terminal blackhole. DNS unit renderer requires the guard service, starts after it and must be required by SSH.
- Refuses NSS configurations containing resolve/Varlink delegates, mdns or other unverified hosts modules; it accepts only an exact 'hosts: files dns' line. It never edits the global nsswitch configuration.
- NSS cache daemons, domain resolution by privileged helpers, custom app-level proxying, DNS over other ports and packet-level no-leak evidence remain outside current proof.

### Recovery: edge_egress_uid_recovery.py

- Read-only audit of UID policy rule, blackhole, IPv6/DNS filter guards, UDP/TCP DNS NAT redirects, NSS host config, SSH dependencies, stale canary marker, and active shared Phase 6G RUNNING operation.
- Possible outcomes: UNSAFE_GUARD_ABSENT; HOLD_FOR_OPERATOR; GUARDED_OFFLINE; ROUTED_UNVERIFIED.
- Never reports CUSTOMER_READY, releases a 6G operation lock, removes a UID guard, enables DNS or changes kernel state.
- Even a present Edge route still requires fresh public-IP proof, DNS packet checks, and IPv6 bypass attempts.

## Configuration boundary

Protected boot manifests are root-owned JSON files with exactly: mode, username, uid, priority, spec, and optional dns_port. The spec is the existing EgressSpec format. The boot unit generator expects an immutable root-only manifest under /etc/nvl-egress/protected and modules under /opt/nvl-egress, with service name nvl-egress-guard-USERNAME.service. DNS unit name: nvl-egress-dns-USERNAME.service. BOTH services must appear in ssh.service Requires if DNS is enabled.

**No setup command in this PR writes these files to a live host or enables units.** Do not run BootGuardApplier.apply or start the proxy against current Core until independent provisioning, 6G coordination, backup and restoration tests are approved.

## Evidence / release blockers

Automated tests validate boot ordering, idempotence, wrong UID and collision rejection, DNS UDP and TCP framing, HTTPS SNI and failure without fallback, strict NSS policy, SSH systemd dependency declarations, and read-only recovery. The pre-existing disposable kernel lab proves WireGuard/NAT Edge outage/recovery, but NOT the new DNS or systemd boot code under a real reboot.

Remaining: actual protected user DNS packet capture; nscd/NSS/Varlink validation; IPv6 packet-leak attempt; systemd boot and restart injection; runtime guard removal; multiple user route ownership; Phase 6G/6H protected handoff integration; recovery of orphaned 6G locks; encrypted offsite backups and restore rehearsal.

**Production gate: Keep protected mode off, PR #80 Draft, and Core/Edge unchanged.**
