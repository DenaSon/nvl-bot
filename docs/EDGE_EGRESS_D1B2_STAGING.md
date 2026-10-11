# D1-B2 — Stage-only Edge Egress Provisioner

Status: **code + staging tests only**, **NOT** deployed or enabled on any NVL host.
This PR does not change `nvlbot`, `wg0`, SSH, public DNS, production user routing or `master_bot.db`.

## Why this design

The current infrastructure is a **Core-terminated SSH + Edge ingress Relay**. Replacing a filtered Edge currently reassigns host ownership through the bot. The new outbound path must be attached to that same lifecycle and must not remain fixed to the previous Edge public IP.

One Edge identity = one `edge_id`, a dedicated WireGuard peer/key pair **on each side**, a dedicated /30 tunnel subnet, a dedicated Core namespace and veth subnet, and a future route table assignment.

- Edge instance: `wg-nvl-<edge_id>`, UDP listener and **scoped** NAT to its public uplink.
- Core instance: WireGuard interface created in **root netns** (UDP socket uses Core uplink), then moved into `nvl-egress-<edge_id>`; veth host ↔ namespace connects the future egress policy to it.
- Core host default route stays unchanged. Operational `wg0` stays unchanged.
- **D1-B2 deliberately does not install UID rules, fwmarks, nft/iptables root OUTPUT marks, global NAT, DNS changes, or account host updates.**
- Multiple candidate Edge identities may be staged at once. Their tunnel/veth subnets and route table allocations must be globally unique. A future allocator/registry in NVL will enforce this.

## Scope of the CLI

`ops/edge_egress_provision.py` accepts:

- `plan`: validate JSON and print intended resources. Pure, side-effect-free.
- `preflight`: read-only check of local interfaces/namespaces/routes, Edge UDP listen port/uplink, and Edge IPv4 forwarding. The checks are conservative; a passing result does **not** prove external egress.
- `stage`: write root-only config, scripts, systemd unit and manifest into a **new non-existing directory**. No service starts. Existing paths are never overwritten.

The staged `up.sh`/`down.sh` scripts represent a future opt-in activation path; **do not execute them on Production during D1-B2.** In a later gate, start the Edge instance first, then the Core instance, and prove from the Core namespace that the externally observed IP equals the selected Edge public IP. Validate start/stop/reboot, rollback, firewall ordering, conntrack, and port collision before enabling a service. Test independently with no user UID policy.

### Example plan — safe to run

```bash
python3 ops/edge_egress_provision.py plan --role edge \
  --spec ops/examples/edge_egress_fra1.json

python3 ops/edge_egress_provision.py plan --role core \
  --spec ops/examples/edge_egress_fra1.json
```

### Host preflight — read-only

```bash
python3 ops/edge_egress_provision.py preflight --role core \
  --spec /root/nvl-ops/edge_egress_fra1.json
# On selected Edge:
python3 ops/edge_egress_provision.py preflight --role edge \
  --spec /root/nvl-ops/edge_egress_fra1.json
```

`preflight` is not a substitute for administrator SSH verification, provider firewall/security-group checks, observed external IP proof, or prospective IPv6 leak tests.

### Key exchange and offline staging (NOT a production instruction)

Generate separate per-Edge Curve25519 WG private keys **on each of the Core and Edge**. Transfer **only public keys** between the machines. Never copy a private key into GitHub or the bot database.

One example key generation invocation in a secured, owner-only directory:

```bash
umask 077
mkdir -p /root/nvl-egress-keys/fra1
wg genkey > /root/nvl-egress-keys/fra1/private.key
wg pubkey < /root/nvl-egress-keys/fra1/private.key > /root/nvl-egress-keys/fra1/public.key
```

After the other machine's public key is known, stage a future role-specific directory, which **must not exist** yet:

```bash
python3 ops/edge_egress_provision.py stage --role core \
  --spec /root/nvl-ops/edge_egress_fra1.json \
  --stage-dir /root/nvl-egress-staging/fra1-core \
  --private-key-file /root/nvl-egress-keys/fra1/private.key \
  --peer-public-key "<PUBLIC_KEY_OF_EDGE>"
```

For `--role edge`, run on the Edge, with the Edge private key and Core public key. The stage directory's **parent must already exist**, be private, and not be a symlink. The `stage` operation creates an owner-only directory and files. The staged `wg.conf` contains a **private key**, so it must never be committed or pasted into chat.

**Do not run staged `up.sh`, copy the staged service into `/etc/systemd/system`, enable or start its service, or attach users yet.** The config sample uses current active Edge public IPv4; when replacing an Edge, create a new Edge identity/configuration and allocate fresh non-overlapping subnets rather than accidentally overwriting an existing stage.

## Safety gates before D1-B3 activation

1. Confirm verified encrypted offsite backup for Core and active Edge, plus an isolated restore rehearsal. Current local-only backups do not satisfy this.
2. Verify `preflight` on actual hosts and conflict-free allocations across *all* active/candidate Edges.
3. Re-review generated scripts on Ubuntu with the actual `iptables-nft` ruleset and provider firewall behavior; ensure no unexpected interaction with `wg0`, `nvlbot`, DNAT port 2252, or current NAT rules.
4. Start and verify only shadow endpoints with **no** UID routing or customer traffic, and test `wg show`, gateway NAT and observed IP.
5. Implement Core-side **fail-closed UID policy** with terminal unreachable route and IPv6 leak prevention; test one canary SSH UID.
6. Integrate the bot's 6G manual/6H opt-in auto failover transaction with egress staging, public-IP validation and rollback. Do not bypass the existing lock, global-domain guard or source-account CAS.
7. Remove/reconcile Phase 6G DNS-to-Core fallback for protected customers. Never mark a candidate `READY` merely because the tunnel handshake works.
8. Assess BadVPN/UDP, GOST and V2Ray separately; these have different process identity/data paths.

## Tests

```bash
python3 -m unittest discover -s tests -p 'test_edge_egress_*.py' -v
bash -n ops/backup_nvl_host.sh
```

Tests cover validation, subnet/device injection, no-route-change contract, staging permissions, exact NAT scopes, WG configuration shape, staged shell syntax, and read-only preflight conflicts. GitHub Actions runs the tests on PRs. Passing these tests **does not authorize Production activation**.
