# NVL-AWG-02 — New Edge Provisioning (no existing Edge enrollment)

**Status: source-only staging; no live server, DNS, SSH user, or AWG peer was changed.**

## Operating rule

The already-serving AWG Edge is NOT a provisioning input and must never be
reinstalled, adopted or used as a hardcoded default. New Edge identity, public
IPv4, root admin SSH port, AWG UDP port, Core IP, customer SSH port and TLS
port all come from a fresh verified wizard request or Core state.

### Workflow planned for NVL Bot

1. Pin SSH host identity independently, and obtain explicit admin approval.
2. Under the preexisting shared Core installer lease, read the running Core
   AWG 3.1 interface and peer inventory. Allocate the next free private /32,
   rejecting all live Core peers and registered/reserved addresses.
3. Inspect the fresh VPS and refuse if any WG/AWG tunnel, customer listener,
   customer-port NAT, or managed host identity already exists.
4. Generate a root-owned 0600 new-Edge config using Core's exact
   S1-S4/H1-H4/HeaderProtectionKey parameters. Secret material goes only over
   pinned SSH/SFTP; never via bot chat, database, process arguments or logs.
5. Run one-time setup_edge_awg_relay.sh on **fresh Ubuntu 24.04**. It installs
   official PPA DKMS + tools, AWG, forwarding and DNAT/SNAT/FORWARD for both
   customer SSH and TLS ports. Service and rules persist after reboot.
6. Append only the new Core peer using an atomic compare-and-swap update and
   `awg set awg0 peer ...` (not a Core tunnel restart). Never overwrite
   `awg0.conf` peers or touch existing `wg0`.
7. Independently prove peer ownership, current handshake, Core-to-Edge path,
   SSH banner, NAT, active/persisted rules, reboot, and an external client
   witness. Only then may a separate, journalled admission workflow register
   EDGE_READY and later STANDBY. A healthy tunnel alone cannot authorize DNS.
8. Existing CZ07/6G lease, Cloudflare exact-DNS, fingerprinted SSH account
   movement and rollback remain the sole customer cutover authority.

### Current PR scope

The guarded bot callback is now wired behind NVL_AWG_NEW_EDGE_ENABLED=1.
Default remains OFF, and the existing WireGuard wizard UI/behavior is unchanged
when the flag is absent. Enabled AWG wizard steps use the existing verified
host-key/pinned SSH/password deletion journal. A new Edge is registered as
inactive EDGE_READY, never silently promoted to Standby.

The new-edge installer and callback are NOT deployed. Do not enable the flag
until the full pinned source release is deployed, CI green and a fresh VPS
canary passes. The production-serving AWG Edge is out of scope.


- `nvl_awg_new_edge.py`: parse shared Core settings, allocate safe /32,
  render new-edge config and Core peer block without hardcoding any live IP.
- `nvl_awg_core_peer.py`: pure Core append-only peer plan with SHA256 CAS
  checks. This is not yet a live executor.
- `setup_edge_awg_relay.sh`: guarded, fresh-server-only installer. It will
  refuse any existing `awg0` or `wg0`; never replay it on an active Edge.
- Unit/static regressions for AWG peer, wizard feature flag, limiter and NAT. The bot callback is implemented but default-OFF and not deployed.

### Hard blockers before enabling the bot action

- Run an isolated fresh-VPS canary of the existing pinned SSH, secret-safe SFTP,
  durable journal and locked Core peer append (no production retry of failures).
- Prove SSH customer and TLS service, current peer handshake and persisted NAT
  through an independent external client connection before any Standby.
- Check actual Core `/root/ip_limiter.py` is AWG shared-source aware; a
  source merge in `promote_edge_to_core.sh` does not patch a running Core.
- Enable the existing guarded AWG wizard flag only after pinned source release,
  Core runtime SHA checks, explicit administrator approval and the canary.
- Check provider inbound UDP permissions for the new AWG port.

No current production route, DNS record, user assignment or server
configuration is changed by this source-only PR.
