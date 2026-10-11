# D1-C1 — Egress compatibility gates wired into NVL's live code paths

**Status:** Implemented and CI tested in Draft PR #80. **Not deployed**. Protected routing and Edge replacement are **not implemented**. All existing NVL production customers remain on the unchanged data plane.

## Critical architectural finding

Current SSH customer sessions terminate on Core and enter through a WireGuard Relay Edge. The existing Phase 6G/6H engine is **not equivalent** to an egress-preserving relay handoff:

1. 6G initially changes global Cloudflare DNS A records **to Core**.
2. `promote_standby_for_filtered_edge.py` reconstructs SSH system users **on Standby**, which is consistent with migrating an SSH endpoint, not simply replacing a Core-terminated Relay.
3. 6G atomically rewrites scoped `ssh_accounts.host` and default ownership under its existing persisted failover lock, then switches global DNS to Standby.
4. This is incompatible with the new objective that users remain Core-authenticated and their outbound IP always be an assigned Edge. A surviving `wg0` handshake does not prove protected egress or end-to-end readiness.

No replacement for this engine is deployed or implied by the new code. Keep its existing lock/journal and global-domain multi-Edge guard.

## What D1-C1 actually integrates

New `edge_egress_lifecycle.py` supplies pure, deterministic compatibility gates. New setting `edge_egress_protected_mode` is inserted into `settings` with **default '0'**, and has **no admin UI toggle**.

| Entry point in existing NVL bot | Setting 0 (default) | Setting 1 or invalid |
| --- | --- | --- |
| `_safe_manual_failover_preflight` (manual UI preview, drill, shared 6G/6H recheck after persisted operation lock) | Original preflight continues | Rejects immediately **before DNS fallback or Standby account rebuild** |
| `_provision_new_edge` (auto Edge install) | Original ingress-only Edge provisioning continues | Rejects before SSH/installer is started, since new Edge does not yet have validated egress |
| `_cf_update_dns_record_sync` (central legacy Cloudflare updater) | Existing DNS behavior | Returns a protected-mode refusal before Cloudflare network I/O |
| `_failover_preflight_error_label_fa` | No change | Displays a Persian explanation of rejection |

**Important:** this is an **incompatibility block, not a protected failover implementation**. Manually flipping the flag to 1 would disable some current emergency procedures and cannot provide protected service. **DO NOT ENABLE THE FLAG ON PRODUCTION** until D1-C2 is complete.

The default-OFF path still uses current legacy semantics; the system has **not** achieved no-Core-IP guarantees. No account UID route/policy, firewall, provider settings, WG `wg0`, DNS, SSH port, SQLite DB or timer was mutated on Production by this PR.

### Additional write paths identified for D1-C2 review

Current `bot_final_v49-2.py` has several separate administrative host mutation entry points:

- `hpdef_` / `hpdefmig_yes_`: direct default-host and bulk account moves.
- `srv_mkactive_`: default-host + direct Cloudflare + Edge NAT changes.
- `tlstoedge`: public DNS switch from older UI.
- `hpblk_` / `hpact_`, host inventory sync and automatic health failover can update pool state independent of Phase 6G transaction.
- `_db_set_all_accounts_host` remains legacy bulk mutation functionality and must not be used for protected handoff.

The D1-C1 central DNS gate catches **legacy DNS requests** in protected mode but does **not** make all these multi-step workflows transactional; some mutate DB state first. The protected-mode flag must stay OFF. D1-C2 must route such operations through one operation journal/lock before enabling protected customer routing.

## Regression verification

New `tests/test_edge_egress_bot_integration.py` executes the real bot's extracted preflight and onboarding/DNS functions against mocks (no Telegram, SSH, Cloudflare or SQLite calls), plus pure compatibility tests.

- Protected manual/automatic preflight refuses without any network probe or account mutation.
- Invalid setting fails closed.
- Default-OFF preflight runs through the old successful validation path.
- New Edge onboarding in protected mode refuses before remote setup.
- Cloudflare updater in protected mode refuses before fetching Cloudflare config.
- Existing 6G persisted lock is acquired before the shared preflight and preflight precedes account rebuild and DNS mutation.
- Python 3.11 continues to execute standalone Egress tests. The existing main bot contains Python 3.12 f-string syntax, so main-bot parsing/integration tests run only on Python 3.12. This baseline version constraint predates D1-C1.

[GitHub Actions staging checks](https://github.com/DenaSon/nvl-bot/actions/runs/38135716714): all active tests passed on both matrix versions. [Existing Python checks](https://github.com/DenaSon/nvl-bot/actions/runs/38135716713) and the [disposable kernel lab](https://github.com/DenaSon/nvl-bot/actions/runs/38135716719) also passed.

## Pending D1-C2 — real bot-managed Relay replacement

Implement behind a **separate, reviewed deployment gate**, with no parallel failover controller:

1. Reserve a unique Edge identity, /30 tunnel, veth and route table in persistent bot-owned inventory; never reuse / overwrite active credentials.
2. Stage and apply Egress on the new Edge and corresponding isolated Core namespace (separate from `wg0`).
3. Reconcile/rekey dedicated Core-side WG peer after Edge restart; prove Core→Edge→external observed public IP == target.
4. Prepare fail-closed UID-based routes, protect IPv6 and DNS, and test one Core user without modifying unrelated users.
5. Coordinate Egress readiness, DB source-set CAS and DNS cutover under the **existing Phase 6G persisted lock and journal**, with clear crash/rollback semantics.
6. Replace the legacy **DNS->Core** temporary fallback **only for protected sessions**, without weakening the global-domain guard. Explicitly reconcile the legacy Standby-user-rebuild model with Core-terminated SSH.
7. Verify direct administrative activation, bulk host moves, old TLS commands and background health-switch callbacks cannot bypass this transaction.
8. Test isolated Linux VM/systemd reboots and user failover; keep automatic failover OFF until all release gates pass.

## Operational release gates

- Local backups already succeeded on Core and current Edge.
- Encrypted **offsite** copy and test restore are **not confirmed**.
- Standby backup intentionally deferred by operator.
- No changes from this PR should be merged/deployed to live NVL until protected mode design and the release gate have been reviewed. Do **not** run the generated `up.sh`/`down.sh` on production.

