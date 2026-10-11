# D1-D2B: controlled stg1 staging

**Status: stage-only. No customer cutover, host tunnel activation, systemd changes, database migration, or protected-mode enablement.**

## Confirmed observations

Previous operator-provided Core and Standby read-only preflights found no conflicts for the proposed new staging resources. Existing Core nvlbot, ssh, wg0 and shared 6G lock were healthy/available; Standby public IPv4, eth0 uplink, wg0 and ipv4 forwarding were confirmed. Re-check before mutating network state; no automatic claim of ongoing availability.

New immutable profile at ops/examples/edge_egress_stg1.json:
- Core public IP: 209.200.246.198; Standby IP: 216.126.229.12 (not Primary Edge).
- New tunnel subnet 10.78.110.0/30; veth subnet 10.78.111.0/30.
- wg-nvl-stg1, vnh-stg1, vnn-stg1, nvl-egress-stg1.
- Tentative UDP 51842, route table 1790.
- Different from prior fra1/WireGuard port 51832 and live ingress wg0.

## First operator step, only on Standby as root

Generate a new host-local private/public pair in a NEW root-only path. Do not transmit any private key.

    set -euo pipefail
    umask 077
    BASE=/root/nvl-egress-keys
    DIR="$BASE/stg1"
    [ "$(id -u)" -eq 0 ]
    if [ -e "$DIR" ] || [ -L "$DIR" ]; then echo "STOP: stg1 key path already exists"; exit 1; fi
    if [ -e "$BASE" ] || [ -L "$BASE" ]; then
      [ -d "$BASE" ] && [ ! -L "$BASE" ] && [ "$(stat -c '%u:%a' "$BASE")" = '0:700' ] || {
        echo "STOP: unexpected shared key directory"; exit 1;
      }
    else
      mkdir -m 700 "$BASE"
    fi
    mkdir -m 700 "$DIR"
    wg genkey > "$DIR/private.key"
    chmod 600 "$DIR/private.key"
    echo "EDGE_STG1_PUBLIC_KEY=$(wg pubkey < "$DIR/private.key")"
    echo "STAGE_KEY_ONLY: no network or service changes"

Send back ONLY EDGE_STG1_PUBLIC_KEY and stop. Do not execute generated up/down scripts, and do not manually change any WireGuard interface.

## Following phases (operator-reviewed separately)

1. Generate independent Core key pair locally, exchange only public keys, and produce stage-only root-owned manifests using existing ops/edge_egress_provision.py.
2. Review staged configs and baseline network state on BOTH hosts. First activating change is only the scoped dedicated shadow Edge and Core namespaces; never touch wg0 or production UID routes.
3. Prove independent namespace traffic exits with Standby Edge public IP, inject outages, and explicitly teardown only owned resources.
4. Actual production protected SSH release is still BLOCKED pending real disposable VPS boot/systemd proof and fully reviewed live 6G/6H adapters. Draft PR #80 remains unmerged and the bot protected-mode setting stays OFF.

**No broad firewall or route flush, no changing ssh.service/nvlbot, master_bot.db, public DNS, or active Primary Edge.**

## Operator-verified on-host D1-D2C staging evidence — 2026-10-11

Evidence below is **operator-supplied terminal output**, not automated remote attestation or independently collected telemetry. It documents an isolated runtime shadow test, **not protected-mode customer traffic**.

1. Core and Standby generated separate stg1 WireGuard keypairs locally. Only public keys exchanged. Stage-only config generated on Core and transferred to Standby with matching SHA256 source checks. Both five-file stage inventories matched expected root-only modes. An ED25519 Standby host fingerprint was checked directly on host and against a Core keyscan before pinned one-host SSH transfer access was installed.
2. Read-only Core staging preflight reported `CORE_ONLY_CANDIDATE`, issues=[], warnings=[], active nvlbot/ssh/wg0, protected_mode=0, shared RUNNING 6G=0. Standby inventory confirmed eth0/216.126.229.12, wg0, IPv4 forwarding=1, UDP 51842 initially unused. Standby firewall backend: iptables nf_tables; INPUT/FORWARD ACCEPT, existing broad MASQUERADE (do not reset).
3. Dedicated Standby `wg-nvl-stg1` was deliberately started on UDP 51842, tunnel `10.78.110.1/30`, while existing `wg0` remained visible. Core then created isolated namespace `nvl-egress-stg1`, WireGuard `10.78.110.2/30`, veth `10.78.111.2/30`, namespace IPv4 default via dedicated WireGuard. Core root default routes and IPv4 ip rules were equal before/after activation.
4. Actual outbound HTTPS using `ip netns exec nvl-egress-stg1 curl -4 https://api.ipify.org` observed public IP **216.126.229.12**, matching Standby and not Core **209.200.246.198**; WireGuard handshake observed.
5. Simulated outage: operator set only Standby `wg-nvl-stg1` down, then attempted HTTPS from Core isolated namespace to the *already resolved and pinned* IP for api.ipify.org. HTTPS failed; no demonstrated Core fallback for this connection. Operator set Standby stg1 interface up again, but **first recovery curl timed out at 4 seconds**. Later read-only state check showed WireGuard UP and matching handshakes on both hosts; renewed HTTPS completed and returned **216.126.229.12** (`RECOVERY=PASS`). Recovery delay, automatic reconnect SLA and complete protocol leak-freedom are NOT proven.
6. The isolated test interfaces remain UP after observed recovery; no scoped teardown was reported. Existing production `wg0`, `nvlbot`, SSH, default route and main account database were not deliberately modified in this experiment, but independent before/after audit of all services is still required. Short-lived staging SSH credential remains present pending explicit revocation.

### Outstanding before production deployment

- DNS (including local stub vs real resolver, UDP/TCP 53 and application DoH), IPv6, representative user-generated SSH/BadVPN flows, routing ownership, and post-teardown verification are **unverified** on the real host.
- This Core namespace test does not exercise an operational SSH session owned by a protected real UID, global boot/systemd guard ordering, or protected 6G/6H live adapters. The separate disposable VPS boot gate from D1-C3E remains **DEFERRED**.
- No production Egress UID policy or protected 6G/6H cutover is approved. Keep PR Draft and protected mode OFF.


### DNS/IPv6 read-only test observation — 2026-10-11

Operator ran a read-only audit in the live Core isolated `nvl-egress-stg1` namespace, after independently confirming eventual Standby tunnel recovery. `/etc/resolv.conf` returned nameservers `8.8.8.8` and `8.8.4.4`. IPv4 route lookups inside the namespace for **both** nameservers selected `wg-nvl-stg1`, source `10.78.110.2`. `getent ahostsv4 example.com` returned success (`DNS_RESOLUTION=PASS`). `ip -6 route show default` returned no route, and `curl -6 --noproxy '*' https://api64.ipify.org` did not connect (`IPV6_PUBLIC_EGRESS=NO_CONNECTION`).

**Scope:** successful resolution and namespace route lookups are not packet captures or complete DNS leak proofs. They do not prove all DNS types/transports including DoH, TCP/UDP 53 or full SSH/BadVPN user flows are confined to the Edge; they do not verify production UID ownership, boot guard, recovery time, or production 6G/6H cutover. No protected production activation is authorized.

### SSH protocol / production baseline read-only observation — 2026-10-11

Operator tested TCP connectivity from inside the isolated Core namespace to the public SSH service on `ssh.github.com:443`. The test read a valid `SSH-2.0-*` protocol banner, printed `SSH_PROTOCOL_BANNER=PASS` and exited 0. This proves an outbound SSH protocol connection from that namespace, **not** an authenticated NVL SSH account session, OS UID-based egress route assignment, BadVPN operation, or account lifecycle.

The same terminal output showed `systemctl is-active nvlbot` = `active`, `systemctl is-active ssh` = `active`, root namespace `wg show interfaces` = `wg0`, and host route to `1.1.1.1` via `eth0` with source `209.200.246.198`. These are point-in-time production service/route observations, not a full incident-free user audit.

**D1-D2C RESULT:** Real isolated Core→Standby IPv4 HTTPS egress, controlled outage nonfallback for one connection, eventual recovery, namespace DNS route/resolution, absent public IPv6 connectivity, outbound SSH banner and production service status all observed. **Staging network test PASSED. Production deployment NOT authorized:** protected UID/SSH/BadVPN behavior, boot guard on disposable VPS, full DNS/IPv6 leak capture, live 6G/6H wiring and cleanup evidence remain unverified. Dedicated live staging Core/Standby interfaces and temporary SSH authorized_keys entry are still active/present until separately scoped teardown is completed.

