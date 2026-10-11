# D1-D2A — Core-host Staging preflight (read-only)

**Status:** New code in Draft PR #80; NO live Core execution by this PR and no production change. This phase collects evidence before any Staging network/SSH launch.

## Decision

Use an isolated network namespace on the existing production Core only for a short-lived, separately approved test, not for reboot/systemd boot attestation. A netns shares the production kernel; Linux routes/firewall rules in the **root namespace** can affect all users if poorly scoped. All initial investigation is **read-only** and no user UID selector, iptables, ssh.service, wg0, production database or public DNS is modified.

### Proposed reserved resources — NOT yet active

| Item | Proposed value |
| --- | --- |
| Edge ID | stg1 (separate from fra1 existing disposable lab) |
| Core test namespace | nvl-egress-stg1 |
| Dedicated WireGuard name | wg-nvl-stg1 |
| Namespace veth | vnh-stg1 / vnn-stg1 |
| WireGuard subnet | 10.78.110.0/30 |
| Veth subnet | 10.78.111.0/30 |
| Route table / priority | 1790 / 1790 |
| Proposed Standby UDP port | 51842 |
| Proposed isolated SSH port | 22282 |
| Proposed SSH OS username | nvlstg1 (DO NOT create yet) |
| Intended Edge | **Standby only** 216.126.229.12; never active Primary 172.86.94.174 |
| Production Core | 209.200.246.198, with existing wg0/nvlbot untouched |

These are draft allocations. Their availability and safety must be verified on **both hosts** before creating any resources. A Core preflight success is only CORE_ONLY_CANDIDATE, never deployment permission.

## Read-only Core audit

Module: ops/labs/edge_egress_core_staging_preflight.py

- Reads only kernel interfaces, IPv4 routes across all tables, priority rules, namespaces, listening socket metadata, WireGuard interface **names** (no keys/config), and nvlbot/ssh.service **status**.
- Uses read-only SQLite URI plus PRAGMA query_only to read **only** the protected-mode setting and number of RUNNING Phase-6G operations; never returns account rows, secrets, VPN credentials or SQLite connection strings.
- Rejects collisions involving proposed subnets, tables, priority, namespace, UID username and interfaces; also blocks if protected mode was enabled, shared 6G lock is RUNNING, production wg0 is missing or a required probe fails.
- Does not enumerate or print customer usernames, WireGuard peers, database passwords, session keys, SSH credentials or user traffic.
- Output is JSON to stdout only; no files are created.

### Operator command — Core, after reviewing PR source

Run from a root shell on Core. This **updates only the local lab Git FETCH_HEAD** to read the versioned audit script; it does not change active bot code or kernel state:

    set -o pipefail
    GIT_SSH_COMMAND="ssh -i /root/.ssh/nvl_github_deploy -o IdentitiesOnly=yes" \
      git -C /root/nvl-egress-lab-src fetch --no-tags origin review/edge-egress-recovery-20261011
    git -C /root/nvl-egress-lab-src show \
      FETCH_HEAD:ops/labs/edge_egress_core_staging_preflight.py | python3 -

Do not use sudo if already root. Keep the printed issues/warnings and send the JSON result to review. If the Git deploy identity/path differs, DO NOT guess private keys or override existing credential handling. The script has no flag for kernel activation.

## Gates before D1-D2B

1. Receive actual Core preflight JSON and confirm no production policy conflicts, no 6G RUNNING lock, no unrecognized network resources; active production wg0/nvlbot status consistent with baseline.
2. Run an **independent read-only** Standby Edge preflight confirming its uplink, public IP, subnet/rule/port availability, staged resource ownership and no conflict with its production wg0. Never touch active Primary Edge.
3. Review isolated test user identity and authentication (no real customer account, no copied production SSH keys), strictly bound SSH listener inside the namespace, and prove the new WireGuard UDP socket cannot interfere with Core ingress.
4. Before any opt-in staged startup, approve an operator-only step-by-step activation and scoped teardown plan with a clean-before/clean-after snapshot. No global route/iptables flush, no new production UID rule, no actual public DNS change.
5. Tests should verify real login to namespace SSH, actual SSH-generated outgoing TCP, UDP/BadVPN only when separately instrumented, DNS IPv4/IPv6 attempts, Edge outage/no Core fallback, and cleanup. Staging does NOT prove whole-Core reboot ordering.
6. D1-C3E boot/security gate remains DEFERRED. A separate disposable VPS with out-of-band console and snapshot must validate ssh.service required dependencies before any protected-production rollout.

## Operational boundaries

The live Phase 6G/6H entrypoints, existing nvlbot service, ssh.service, host_pool and master_bot.db remain unchanged. PR #80 stays Draft; no bot deployment, merge, migration or production mode switch.
