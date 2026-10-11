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
