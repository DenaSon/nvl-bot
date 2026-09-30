# Final Repository Review — 2026-09-30

Reviewed repository: `DenaSon/nvl-bot`

Reviewed head before this document: `6151166bf78d266589db96cb42b612e9536634b1`

Scope: main Telegram bot, SSH account lifecycle, Marzban/V2Ray integration, SQLite persistence, Edge/Core/WireGuard topology, filtering detection, health monitoring, failover/promotion/demotion, periodic Edge sync, migration bundles, and imported operational scripts.

No production code was changed by this review.

## Overall assessment

The currently running service is materially more stable than at the start of the audit. The resource leak, capacity double-count, capacity auto-lock, Hidden Hold activation, and Telegram duplicate-edit issues have already been fixed and validated end-to-end.

However, the repository still contains several architecture and security blockers that should be resolved before automated failover is trusted or major new infrastructure features are layered on top.

## P0 — fix before trusting automated failover / before expanding privileged features

### 1. Repository and production are not yet the same runtime baseline

The repository intentionally contains the sanitized source while production still uses the pre-sanitization runtime source/configuration.

Before GitHub becomes the source of truth, migrate production secrets to a root-only environment file, deploy the repository version in a controlled change, and validate Telegram login, RED/BLUE confirmation, Marzban access, and service restart behavior.

### 2. Active demote helper is missing and failover contracts disagree

The bot invokes:

`/root/demote_core_to_edge.sh <NEW_CORE_IP> <CUSTOMER_SSH_PORT>`

after `core_side_failover.sh`.

No active `demote_core_to_edge.sh` exists on the audited Core.

The recovered backup is intentionally kept only under `legacy/`; it accepts a different argument contract and describes a different Data-Plane architecture.

There is also a naming mismatch:
- `sync_bot_to_edges.sh` attempts to distribute `demote_core_to_edge_v2.sh`
- `preflight_check.sh` requires `demote_core_to_edge.sh`
- the bot itself invokes `demote_core_to_edge.sh`

Automated Promote can therefore complete the new Core promotion and then fail while converting the old Core into an Edge.

### 3. Management SSH and customer service ports are conflated

`host_pool.ssh_port` is still used for both:
- customer service traffic
- administrative SSH to an Edge

In the observed production topology, Edge customer ports DNAT/WireGuard back to Core. A successful SSH handshake to an Edge customer port can therefore mean “reached Core through the Edge”, not “reached the Edge management plane”.

This affects:
- `core_side_failover.sh`
- `sync_bot_to_edges.sh`
- `update_all_edges_endpoint.sh`
- host-health checks
- remote health checks
- Linux account operations and mirroring
- standby promotion

Required direction: introduce explicit `service_port` and `admin_ssh_port`, use only the latter for management, and verify target identity rather than trusting a successful TCP/SSH handshake.

### 4. Every synced Edge can receive control-plane secrets

The periodic sync/migration design currently builds and distributes a migration package that can contain:
- Core WireGuard private key
- full `master_bot.db`
- Edge provisioning SSH private key
- Telegram persistence
- TLS/certificate material
- bot/service snapshots

`sync_bot_to_edges.sh` then sends the migration package to every active Edge. It also stages the production systemd service unit.

Because the production database stores SSH customer passwords in recoverable plaintext, and the production unit may contain live runtime credentials, compromise of one Edge can substantially expand into control-plane compromise.

Do not pre-position the full Core secret bundle on every Edge. Prefer on-demand promotion material for a selected standby, separate least-privilege management keys, and secret rotation after promotion.

### 5. V2Ray authorization is inconsistent and contains a privilege boundary defect

`_show_user_detail()` routes V2Ray accounts to `_show_v2ray_user_detail()` before applying the normal `_can_manage_user()` ownership check.

Several V2Ray callbacks also perform state-changing operations without re-checking account ownership, including toggle/delete/renew/add-volume paths.

The SSH management paths generally perform the ownership check correctly.

Required fix: centralize account authorization and enforce it server-side before every read or mutation, including every V2Ray callback and text-state continuation.

## P1 — high-priority correctness / SLA work

### 6. Filtering detection cannot identify a filtered Edge reliably

The live connection counter now correctly counts sessions on Core only, which fixed capacity double-counting.

But the filtering detector reuses the same global Core counts. Therefore:
- it sees global online-user collapse, not per-Edge reachability
- it assumes the current default host is the filtered Edge
- a partial failure of one Edge may not cross the global threshold
- a global traffic dip can be mistaken for filtering

The detector can also switch the public domain to Core even when standby auto-failover mode is disabled.

Implement separate observability for each Edge: domestic probes, service-port probes, management probes, global control probes, session-loss correlation, quorum, and cooldown.

### 7. Host health can report a relay as healthy while only Core is reachable

Host health uses `host_pool.ssh_port` and a simple TCP connect.

On a relay Edge, the service port can DNAT to Core. This validates the forwarded customer path from the Core’s network perspective, not the Edge management plane and not reachability from Iranian user networks.

Management health and customer reachability must be separate metrics.

### 8. Standby activation updates more accounts than it rebuilds

`promote_standby_for_filtered_edge.py` correctly selects and rebuilds accounts whose `host` equals the filtered host, and updates only successful usernames.

After that script succeeds, the bot calls `_db_set_all_accounts_host(target_host)`, which rewrites the host for every non-building account.

That is broader than the script’s selected population and can move unaffected accounts to the standby.

### 9. Billing and external side effects are not atomic

SSH purchase finalizes the Linux/DB account first and then performs wallet deduction / commission distribution. The code explicitly leaves the account alive if the financial step fails.

Several V2Ray flows modify Marzban and the local DB before completing wallet/commission bookkeeping.

A transient DB or business-logic failure can therefore produce a valid service without matching financial settlement, or partial divergence between Marzban, SQLite, and balances.

Introduce idempotent transaction records / purchase states and compensating actions instead of treating financial failure as non-fatal.

### 10. Customer SSH passwords are stored recoverably in SQLite

The current failover/recreate design depends on reading `ssh_accounts.password` and feeding it to `chpasswd`.

This makes the DB a credential vault: database disclosure exposes customer SSH credentials.

If password recreation must remain supported, use application-level encryption at rest with a key stored separately from the database, rather than plaintext.

## P2 — hardening and maintainability

### 11. SSH host verification is disabled in multiple paths

The code uses Paramiko `AutoAddPolicy()` and shell SSH with `StrictHostKeyChecking=no` / `UserKnownHostsFile=/dev/null`.

Pin host keys or maintain a managed known-hosts inventory for Core/Edge management.

### 12. Alternate Edge architectures coexist in the repository

`setup_edge_relay.sh` matches the observed production topology: Edge service ports DNAT/WireGuard to Core.

`setup_edge_datapath.sh` describes a different architecture where Edge terminates SSH locally and depends on missing `edge_ip_limiter.py` / `edge-ip-limiter.service`.

The two modes must not be mixed implicitly. Choose one active architecture and move the other behind an explicit legacy/experimental boundary.

### 13. Monolith / state-machine complexity

The main bot is roughly 12.7k lines and contains very large callback/text handlers, string-based state transitions, infrastructure actions, billing, monitoring, and UI in one module.

Before large feature growth, start extracting:
- authorization/service layer
- account lifecycle
- billing
- infrastructure/Edge management
- monitoring/failover
- Telegram presentation

This can be incremental; a full rewrite is not required.

### 14. Ad-hoc schema migrations

Schema evolution is embedded in `init_db()` with many `ALTER TABLE ... except OperationalError: pass` operations.

At least one migration (`v2ray_gb_price`) is attempted before the `agents` table is created on a fresh DB and is currently unused.

Adopt explicit versioned migrations before clean installs / disaster recovery become routine.

### 15. Version identifiers are inconsistent

The module header, `BOT_VERSION_TAG`, and startup banner carry different version labels.

Use one build/version identifier and log the Git commit SHA at startup.

### 16. Marzban token cache is global

`v2ray_engine.py` caches one access token globally, not keyed by URL/admin identity.

This is acceptable while there is exactly one Marzban backend, but will be incorrect if multiple Marzban instances/accounts are introduced.

## Current strengths

- SQLite uses WAL, busy timeout, and transaction rollback in the common connection helper.
- SSH username reservation is atomic and Linux account creation has explicit rollback stages.
- Capacity detection and lock behavior were validated end-to-end after the audit fixes.
- Hidden Hold activation is now synchronized with Linux expiry.
- Background monitoring loops isolate most iteration failures and continue.
- Core/Edge operational scripts contain substantial rollback and diagnostic work compared with earlier versions.
- Secrets committed to Git were sanitized; private keys, DB files, production environment files, and live tokens are not intentionally committed.

## Development gate

The application can continue operating while these debts are addressed, but before treating GitHub as the deployment source and before trusting automated failover:

1. migrate production to the sanitized runtime/env baseline;
2. fix V2Ray authorization;
3. split management vs service ports and enforce Edge identity;
4. redesign secret pre-positioning on Edge hosts;
5. implement and validate the active demote path;
6. then redesign filtering/failover observability.

After these gates, feature development can proceed on a much safer baseline.
