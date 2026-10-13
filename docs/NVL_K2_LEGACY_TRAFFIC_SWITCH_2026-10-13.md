# K2 — Legacy Relay Traffic Switch (verified source contract)

**2026-10-13 · Source review on `master=b86aaeaf` · K2 PR #120**. This document describes verified Legacy behavior and the deliberately separate K2 acceptance gate. It is **not** a statement of deployment, an operator acceptance, or a license to mutate Production.

## User's actual product contract

**Transfer users = route existing SSH/SOCKS customers' ingress and internet egress through the selected Edge.** Do **not** copy Unix users, passwords, database, subscriptions or invoice identities to the new VPS. Accounts and SSH daemon stay on Core. Legacy clients may require a fresh connection for their public hostname/IP to resolve to a newly selected Edge.

### 1. What existing Legacy Wizard does

`bot_final_v49-2.py::_provision_new_edge_sync`:

- Gets Core `wg0` public key/port and allocated Edge WireGuard IP.
- SSHes to fresh Edge with a one-time Root secret; transfers and runs the **existing** `setup_edge_relay.sh` script. It is still the existing SSH/Ingress installer, not an Egress IP change.
- On Edge, `setup_edge_relay.sh` creates `wg0` private peer with `AllowedIPs=10.77.0.1/32`, enables IP forwarding, then inserts customer-SSH and TLS `iptables PREROUTING DNAT` to `10.77.0.1:<customer port>` and Edge `POSTROUTING MASQUERADE`. It **does not create SSH customer accounts on Edge**.
- Appends the Edge `[Peer]` to Core's existing `wg0.conf` and performs `wg syncconf wg0`. For this reason installation is a **live privileged network operation** even when the optional Egress stage is read-only.
- The async wrapper `_provision_new_edge` persists a new active `host_pool`, `settings.hosts` member. In the K2 opt-in Wizard, `onboard_after_ingress` additionally creates only **Stage-only** dedicated Egress artifacts; it does not mark F4 ready, route any protected UID or change the default public relay. A partially successful install must HOLD, not rerun automatically.

### 2. What Legacy 'choose IP as relay / migrate existing users' actually does

- The Legacy success card offers `hpdef_<IP>`. This checks the reachable customer SSH socket, then `_db_set_default_host` changes `host_pool.is_default`. `_db_rebuild_hosts_from_pool` puts the new default IP first in `settings.hosts`. **That alone primarily changes host selection for new orders/configs.**
- The following `hpdef_migrate_<IP>` confirmation offers `hpdefmig_yes_<IP>`. On this second confirmation, the bot **rechecks SSH service reachability**, runs `_db_set_all_accounts_host` (only `ssh_accounts.host` metadata, excluding accounts 'درحال ساخت'), records cooldown, then calls `_update_cloudflare_dns` to move the public A record(s). If Cloudflare fails, the bot may have already changed the DB and must show a warning; this is not an atomic provider+SQLite transaction.
- Existing Cloudflare front door may keep a fixed public hostname while the resolved A record moves to new Edge. An old direct-IP client needs the updated endpoint; a DNS-based client may need reconnection/TTL propagation.
- **This normal workflow does not copy Linux users or authenticate clients on Edge.** Packet flow: `Client → Edge public SSH port → DNAT/legacy wg0 → Core sshd → Core routing → Internet`; without protected Core UID policy the outbound internet IP can remain **Core public IP**.

### 3. Do not confuse the emergency Phase 6G/6H Failover helper

`_safe_manual_failover` is a **distinct** emergency flow with a persisted shared 6G lock, temporary Core DNS fallback and `_run_phase6g_rebuild_helper` targeting a Standby. Reusing this function for routine protected Relay selection would violate the 'never expose protected users through Core IP' requirement. K2's positive handoff must use the **existing** 6G journal/lock, but **not its unsafe Core-DNS fallback or automatic account rebuild recipe**.

## K2 delta relative to the old familiar UX

1. Same **Wizard → new Edge → select Relay**. Keep `host_pool` metadata, new-order default and existing-customer public endpoint concepts. Do not claim a user account was migrated.
2. New Edge's Egress data plane must first have trusted, independently pinned Stage, allocated per-UID policy, PAM/Boot/IPv4/IPv6/DNS fail-closed and external F4 evidence, under the **existing 6G operation**.
3. For approved test users, bind their real Core-side Linux UID to the selected Edge's dedicated Egress using P3-C; validate public IPv4 through real customer SSH/SOCKS session. `ssh_accounts.host` is **client ingress endpoint metadata**, not the Egress enforcement mechanism.
4. A global default relay and fixed public domain A record can change **only after all affected customers can safely use that ingress and their egress IP is verified as that same Edge**. Existing P3-D guarded Cloudflare source→target handoff covers this contract in source but is release-disabled, and requires a separate audited provider/host adapter.
5. In mixed Legacy/Protected mode, the existing `legacy_new_edge_gate` and `any_protected_bindings` deliberately prevent unsafe new Edge provisioning. Do **not** flip global flags to bypass them; handle this gate in a separately reviewed protected-aware installer.
6. Existing sessions must be drained safely or left on their verified old route; after failure, protected UIDs stay `FROZEN/HOLD` with deny rules. No silent rollback to Core public Egress.

## Source references

- `setup_edge_relay.sh` (IP forwarding, DNAT, MASQUERADE; Edge hosts no user).
- `bot_final_v49-2.py`: `_provision_new_edge_sync` (~3628), `_provision_new_edge` (~3798), `_db_set_default_host` (~3483), `_db_rebuild_hosts_from_pool` (~4005), `hpdef_migrate_` / `hpdefmig_yes_` (~24390–24459), `_cf_update_dns_record_sync` (~4072), emergency `_safe_manual_failover` (~26090).
- `edge_egress_p3_uid.py` (per-UID guarded Egress), `edge_egress_p3_dns_cutover.py` (protected Ingress+Egress DNS cutover).
- `edge_egress_k2_relay_switch.py` and tests (PR #120): **read-only operator traffic switch review; no release enabled**.

**Release state:** PR #120 remains Draft; actual protected cohort data-plane, full 6G cutover, real fresh VPS acceptance and production release **are not done**.
