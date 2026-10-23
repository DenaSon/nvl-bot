# NVL — Cloudzy quick Edge, Legacy-preserving UX plan and K2 runtime status

**Decision date:** 2026-10-23  
**Status:** Approved *design constraints and documentation only*. No new bot flow has been implemented, enabled, tested against production, or deployed.  
**Owner intent:** Cloudzy-assisted provisioning for frequent filtered public Edge/Relay IPs, without altering the existing, proven manual UI or depending on K2 customer Egress.

## 1. K2 operational status: NOT RELEASED / NOT ACCEPTED

Do **not** represent K2 UID-specific Egress migration as operational in Production.

**Source evidence on `master`:**
- `edge_egress_k2_root_direct.py`: `K2_ROOT_DIRECT_ENABLED = False`, `K2_ROOT_DIRECT_BATCH_ENABLED = False` (lines 28–29); execution additionally requires an explicitly registered, released root portal.
- `edge_egress_k2_core_operations.py`: `CORE_OPERATIONS_ENABLED = False` (line 20).
- `bot_final_v49-2.py`: the `srv_mkactive_` callback selects K2 only if `k2_native_operations_registered()` is true; otherwise it executes the **Legacy** default/DNS/NAT path. The integrated `hpeg_wizard` uses the existing ingress installer, with separate, staged-only K2 opt-in.
- Previous lab and publisher documents record source, STAGED tunnels and partial tests; **none is evidence of successful Production customer migration and independent field acceptance**.

**Scope/qualification:** This is the *source and documented operational-release conclusion*, not a fresh SSH inspection of the running Production host. The last recorded operator deployment evidence may be historical; do not claim K2 can never be switched on locally. Before changing operations, inspect current deployed code, flags, runtime registration, 6G state and field-acceptance evidence read-only. Until positively proved otherwise, classify customer K2 Egress as `NOT_OPERATIONAL / NOT_ACCEPTED`, and do not rely on it for Cloudzy/Legacy recovery. A namespace outbound IPv4 probe is not a real customer SSH/SOCKS acceptance test.

## 2. Protect the existing Legacy workflow

**Hard invariants for any future implementation:**

1. Keep **all original** Telegram Legacy controls, callback names, state transitions and existing manual use-cases intact. No renaming, removal, redirect, replacement or hidden auto-execution of old buttons.
2. Preserve `hp_addedge` and its `EDGE_NEW_IP → EDGE_NEW_ROOTPASS → EDGE_NEW_PORT` wizard, `_provision_new_edge_sync()`, `_provision_new_edge()`, `hpdef_`, `hpdef_migrate_`, `hpdefmig_yes_`, and `srv_mkactive_` as operator-facing legacy operations.
3. The proposed new Cloudzy path is a **new, admin-only entry near the top of the first admin menu/page**, not a replacement for those existing menu items. It drives a **separate new UI state machine** and calls existing provisioning/business primitives instead of emulating user callbacks or implementing a second SSH/WireGuard installer.
4. Fixed Cloudzy OS template: **Ubuntu 24.04 (`ubuntu-24.04`)**. Do not show an OS selector or OS choice on the new UI. Confirm that this template ID is available and compatible with the selected plan/region before a paid live request; if not, HOLD, not a silent OS downgrade.
5. Do **not** silently enable, bypass or relax protected-mode safety gates, K2 runtime flags, original 6G state, user-specific Egress routing or the Cloudflare/domain ownership rules. If Legacy protected-mode gate rejects an operation, report HOLD.
6. Do **not** import Cloudzy into the old manual wizard or modify the original callback behavior as a side effect of merely displaying the new UI. Regressions of legacy menu/navigation must be tested.

### Verified Legacy code reuse points

| Existing item | Source | Existing action |
| --- | --- | --- |
| Old manual Edge entry | `bot_final_v49-2.py`: `hp_addedge` | IP, root password, customer SSH port wizard |
| Edge installation | `_provision_new_edge_sync(edge_ip, root_password, customer_port, edge_name, private_key_path=...)` | Paramiko/SSH installation, WG peer and tunnel check |
| Async provisioning wrapper | `_provision_new_edge(... private_key_path, connect_retries, provider, provider_instance_id, egress_stage_requested=False)` | On success, adds/activates Edge in `host_pool` and stores provider metadata |
| Old default and account host migration | `hpdef_` and `hpdefmig_yes_` | Checks SSH banner, updates default; optionally `ssh_accounts.host` and DNS |
| Old relay activation | `server_role_panel.py` → `srv_mkactive_` | In non-K2 mode sets default, updates Cloudflare and Edge NAT |

`ssh_accounts.host`, `host_pool.is_default`, public DNS and **real per-UID internet Egress** are distinct. Legacy switches ingress/access metadata; they do **not** prove that customer outbound packets egress from a given Edge. Preserve this distinction in labels and reports.

## 3. Proposed new admin UI (not yet implemented)

```text
🏠 Admin / first page
  ⚡ Cloudzy — Quick Edge  [NEW; first/prominent]
  ... all existing buttons in their original places ...

⚡ Quick Edge
  1. Check account/balance and available Cloudzy regions/plans
  2. Select region + plan; OS fixed internally to ubuntu-24.04
  3. Show plan/base price, IP surcharge uncertainty, and request billing cycle
  4. Explicit operator purchase confirmation
  5. Create VPS and wait for Cloudzy ACTIVE
  6. Verify primary IPv4 and SSH reachability/key identity
  7. Reuse existing Legacy Edge provisioner with SSH key, same customer port
  8. Verify WG tunnel and SSH service; report staged/registered outcome
  9. Offer existing manual 'make Relay active' / 'move customers' routes
     with explicit review and confirmation and safe state reconciliation
  10. Report new and old IP, server ID, and incomplete actions
```

In the first implementation phase, stop at **Edge provisioned and tested**. Do not automatically change the default Edge, DNS, SSH account host, or delete the old VPS. A later *separately accepted* phase may orchestrate the existing manual relay/migration operations; no implicit global failover from the first purchase click.

## 4. Minimum safeguards, without a second orchestration platform

- **One purchase per operation:** admin-only, explicit amount/config confirmation, stable operation ID + Cloudzy `Idempotency-Key` and persisted provider VPS ID. A Telegram duplicate click, worker restart or API timeout must NOT purchase again blindly. Store only nonsecret metadata in a small SQLite operation record; never store private SSH keys/root credentials there.
- **Never assume Cloudzy ACTIVE means ready:** check IPv4, SSH access and host identity, existing setup result, WG connectivity, Edge service port and route readiness. Missing/partial results are reported as `HOLD`.
- **Existing installer can use SSH public-key onboarding:** `private_key_path` already exists, and `provider/provider_instance_id` can associate provider ownership. Do not ask for root password in the Cloudzy-assisted flow if key onboarding succeeds.
- **Host key verification:** current Legacy installer uses Paramiko `AutoAddPolicy` for fresh hosts. The new pathway must pin/verify the new server's SSH host key against a trusted, independently obtained value before sending privileged commands (without weakening the old UI code). If reliable attestation is unavailable, require operator review.
- **No unsafe switch chaining:** Legacy `srv_mkactive_` currently writes default metadata **before** Cloudflare update and Edge NAT, so a partial failure can leave DB/DNS/NAT inconsistent. Do not invoke it automatically inside a purchase operation. Before shipping phase 2, design a minimal review/confirm and recovery workflow with fresh source/target checks, original metadata snapshot, bounded operation status, and explicit reconciliation on uncertainty; do not blindly rollback unknown mutations.
- **Service check is not universal Iranian ISP reachability:** a working TCP/SSH banner alone did not detect the documented 2026-10-20 MCI-specific SSH issue. Continue to present client/operator field results separately, and never claim universal reachability.
- **Don't alter working infrastructure:** never remove old Edge, wg peer, Core state, Cloudflare DNS or customers merely because a new VPS was bought. Keep new server visible for operator recovery on failed provisioning.
- **Cloudzy authentication:** use scoped expiring `CLOUDZY_TOKEN`; no token/one-time password leakage in Telegram, logs or Git.
- **No uncontrolled background workflow:** reuse the existing bot execution model, keep pending operations bounded, record outcomes before displaying success. Source CI is not production acceptance.

## 5. Suggested release slices

**CZ-02A — Safe UX and Cloudzy preflight:** New first-page admin entry only; catalog, regions, billing balance, plan+region, purchase confirmation; old UI byte-equivalent from the user's perspective; no paid operation on automated tests.

**CZ-02B — Purchase and Legacy Edge installation:** One confirmed purchase, idempotent operation receipt, Ubuntu 24.04, SSH-key bootstrap, existing `_provision_new_edge` with `egress_stage_requested=False`; no K2, no default/DNS/account migration. Negative-path tests for provider timeout, missing IPv4, SSH host-key mismatch, lost message and partial install.

**CZ-03 — Guarded Relay promotion / customer host migration:** Operator-driven separate confirmation after fresh checks; reuse existing Legacy semantics, but address the proven default-before-DNS/NAT partial-failure risk *without changing the old manual UI*. Test 0/1/N customers, DNS failure, NAT failure, concurrent failover, protected-mode HOLD and operator recovery. Avoid automatic VPS deletion.

**Pre-release evidence:** isolated VPS acceptance, real SSH login plus representative client connection, DB/DNS/host_pool comparison, legacy navigation/callback regression, rollback and no customer mutation without operator approval. No claim of zero risk.

## 6. Implementation status

This document is a decision and review record only. No Cloudzy Telegram integration or Legacy/K2 code modifications have been made under this change. Existing `cloudzy_service.py` remains an independent, unconnected provider service. Never confuse source merge with production deploy.
