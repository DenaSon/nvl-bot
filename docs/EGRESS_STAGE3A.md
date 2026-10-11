# NVL SSH Egress — Stage 3A: isolated endpoint contract

**State: draft, review-only. No production deployment or Telegram bot callback is wired.**

## Existing architecture versus new Egress

The active **Ingress** path is customer → Edge relay (DNAT/WireGuard) → Core SSHD.
The column `ssh_accounts.host` describes endpoint/routing metadata, not guaranteed outbound public IP.
Phase 6G/6H implement guarded standby failover, with account and DNS changes; do not reuse them as per-user Egress switches.

In Stage 1/2, a test for `nvl0557` passed with SSH SOCKS traffic leaving via `216.126.229.12` from `nvl-egress-stg1`.
That does not prove persistent service startup, real password acceptance, fail-closed behavior under WireGuard loss, UDPGW support or safe public exposure.

## What this PR provides

- A pure generator (`egress_pilot.py`) of **four proposed files**, not a deployment tool:
  - isolated `/etc/nvl/egress-pilot/sshd_config`;
  - `nvl-egress-pilot-sshd.service`;
  - loopback-only `nvl-egress-pilot-proxy.socket`;
  - `nvl-egress-pilot-proxy.service`.
- Only `127.0.0.1:22284` is proposed for ingress; no public port is enabled.
- Dedicated `AllowUsers` restriction, forwarding-only SSH (no TTY or shell sessions), root disabled.
- Proposed password authentication with PAM for **one pilot**; not yet proven with that customer's actual credential.
- A pure `route_blockers` check, rejecting an unexpected default-route pattern, IPv6 default, missing WireGuard device, or wrong observed Egress IP.
- Unit tests and an explicit gate list. No existing bot/DB/iptables/WireGuard/production SSH source is mutated.

## Safe rendering command

```bash
python3 egress_pilot.py \
  --username nvl0557 \
  --namespace nvl-egress-stg1 \
  --wg-interface wg-nvl-stg1 \
  --internal-ip 10.78.111.2 \
  --expected-edge-ip 216.126.229.12 \
  --core-ip 209.200.246.198 \
  --ssh-port 22284
```

Output is JSON containing `deployment=NOT_APPLIED` and proposed file contents. It performs no writes and no services are started.

## Strict gates before manual installation

1. Compare current running Core files and units with GitHub; the sanitized repository is not necessarily the production runtime.
2. Verify namespace and Core/veth route, one IPv4 default strictly over the correct WG device, no IPv6 default, plus actual policy rules, firewall and WG AllowedIPs; confirm no alternate route leaks via the Core.
3. Verify namespace SSH port and host TCP loopback port are unused; check no unit name conflicts. Inspect file ownership and modes, with host private key outside Git.
4. On Core, run `sshd -t` on the generated configuration and `sshd -T -C user=nvl0557,host=localhost,addr=127.0.0.1,laddr=10.78.111.2,lport=22284` with that file to confirm the active effective options.
5. Confirm `systemd-socket-proxyd` exists, the service and socket load correctly, and only local loopback ingress is reachable.
6. Test authenticating with the existing pilot's actual password (the Stage 2 test used a temporary key), and verify SOCKS proxy public Egress.
7. Simulate Edge/WG loss; confirm forwarding fails **without** Core-IP fallback. If it leaks or remains ambiguous, do not expose to public users.
8. Prepare an explicit rollback: stop the pilot socket/proxy and isolated SSHD, do not remove production SSH or change any current user route. Test recovery. Only then consider a separate public endpoint deployment.

## Bot integration later (Stage 3B)

Retain `ssh_accounts.host` as the ingress endpoint. Introduce a **separate** per-user Egress assignment with its own health preflight, routing and fail-closed guard, operation journal, lock and rollback. No broad `UPDATE ssh_accounts`, global DNS switch, or Phase 6G failover should be used to silently implement that operation.

## Test

```bash
python3 -m unittest discover -s tests -p 'test_egress_pilot.py' -v
```

**Stage 3A acceptance:** reviewed templates, guards, tests, and documentation only. This is not an operational Stage 3 deployment.
