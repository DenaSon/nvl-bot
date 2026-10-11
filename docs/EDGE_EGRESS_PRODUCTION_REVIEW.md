# NVL Edge Egress — architecture review and backup gate

**Decision date:** 2026-10-11. **Status:** proposal only; nothing in this PR changes production routing.

## Verified evidence

- Current production is **Core-terminated SSH / Edge Relay**. The active Edge `172.86.94.174` DNATs incoming customer SSH to Core `209.200.246.198`.
- A separate WireGuard + network namespace POC proved that one Core-side SSH account (UID 1644) could egress through the Edge for one selected destination. The same SSH proxy still used Core egress for other destinations. This is a **technical POC, not a production release**.
- `setup_edge_relay.sh` provisions ingress WG and DNAT; it does not provision egress. `setup_edge_datapath.sh` describes a conflicting Edge-terminates-SSH architecture and must not be mixed into this mode.
- Phase 6G already has an operation lock/journal, candidate checks, atomic scoped account assignment, and DNS handoff. Phase 6H reuses that engine for opt-in automatic failover.
- **Critical incompatibility:** 6G/6H currently fall back public DNS to **Core** before rebuilding source-owned accounts on Standby. This may expose the Core public endpoint and is inconsistent with a strict no-Core-egress policy. Core-terminated SSH and standby rebuilding also require explicit role reconciliation.
- `public_domain` is global and has a multi-Edge safety guard. Preserve it until an alternative domain/ownership model has been tested.
- `server_migration/backup.py` concerns Marzban migration and is not an NVL Core/Edge emergency backup.

## Architecture decision

Keep **Core authentication + Edge ingress relay**. Add a **per-Edge, bot-managed egress data plane** using isolated WireGuard and routing state. Extend the existing Phase 6G failover transaction instead of building a second switch controller.

Each new/replacement Edge must be prepared and proven healthy for **both ingress and egress** before any customer assignment:

1. Provision the candidate with independently managed egress peer keys, NAT, firewall policy and restart-safe service units.
2. Check admin SSH, customer service port, ingress tunnel, egress handshake, route and external probe that proves the observed **public egress IP is exactly the candidate Edge IP**.
3. Acquire the existing failover lock, revalidate source customer ownership and candidate, and journal the whole handoff.
4. Install **fail-closed** per-account routing *before* shifting customer traffic. The route/table must contain a terminal unreachable/blackhole fallback; disappearance of the Edge route must never fall through to Core's main default route.
5. Coordinate Linux route changes, DB account/default assignments, and DNS handoff through a staged prepare/commit/verify/recovery saga. A SQLite transaction cannot atomically cover network devices and Cloudflare DNS.
6. Verify live SSH and public egress, then release the old Edge or roll back to a previously healthy Edge. If none works, block customer outbound and alert instead of leaking via Core.
7. For the protected mode, eliminate/disable temporary public **DNS -> Core** fallback unless it is explicitly reviewed as a separate accepted risk.

**Constraints:** Do not touch active `wg0` or Core default route while shadow provisioning. Do not reuse experimental mark `0x77` or table `77`. Do not mark UID 65534 or root broadly. DNS, IPv6, BadVPN/UDP, GOST/TLS and V2Ray are separate release gates. Preserve Phase 6G's global-domain multi-Edge guard and its failover lock. Test stop/restart/reboot, peer replacement and failure injection. Automatic failover remains OFF until proven.

## Emergency backups — required before any production mutation

Run `ops/backup_nvl_host.sh` as root **on Core with `core`**, and **on each current active/standby Edge with `edge`**. The script has no service stop/restart or routing/firewall mutations.

```bash
sudo bash ops/backup_nvl_host.sh core    # Core only
sudo bash ops/backup_nvl_host.sh edge    # Edge only
```

The script creates a root-only directory under `/root/nvl-emergency-backups/`, containing a live SQLite online snapshot on Core, network/systemd diagnostics, selected config and account data, private WireGuard/SSH material, and SHA256 checksums. It performs `PRAGMA integrity_check` on the SQLite snapshot and validates archive readability.

After execution **read the BACKUP_COMPLETE path**, check `sha256sum -c SHA256SUMS`, securely **export an encrypted copy outside that VPS**, and perform a controlled restore rehearsal. A local-only snapshot does NOT protect against VPS loss.

**Never commit/upload the snapshot, private keys, password hashes, database or raw server inventory to GitHub or chat.** Do not blindly extract `/etc/passwd`, `/etc/shadow`, WireGuard, SSH or iptables configuration on a live recovery host. This is an emergency selective host snapshot, not a whole-disk snapshot; also obtain provider-level image/snapshot before major migration.

## Delivery gates

1. Emergency snapshot Core + Edge(s), offsite encrypted copy, checksum/integrity and restore rehearsal.
2. Egress provisioning as a reproducible feature of current bot Edge lifecycle.
3. Extend 6G/6H preflight, transaction journal, safety/rollback and DNS behavior.
4. One SSH test UID full egress with fail-closed and IPv6/DNS tests; then selected canaries.
5. Separate UDP/BadVPN and protocol-specific test suite.
6. Simulate Edge filtering/replacement/failover, then staged production rollout.

No routing rollout or automatic failover is approved by this review alone.
