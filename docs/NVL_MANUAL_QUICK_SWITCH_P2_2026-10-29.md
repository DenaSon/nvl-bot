# NVL Manual Quick Switch — Phase 2 (2026-10-29)

**Status: SOURCE ONLY. Not wired to Telegram, not deployed on Core.** PR #251. No live DNS, DB, WireGuard, SSH user or legacy CZ07 state changed.

## Objective

An SSH account exists on Core; Legacy Edge only relays it over WireGuard. The 2026-10-29 operator recovery changed DNS and DB host metadata (not credentials or Linux users). Historical unrelated CZ07 HOLD prevented conventional per-user batch cutover. Phase 1 (PR #250) fixed renewal/reactivation and field acceptance confirmed it.

## Engine API

- manual_quick_switch.py: ManualQuickSwitch(db_conn, dns, check_target, guard). Not imported by the production Telegram runtime.
- preview(target): one coherent source/default, verified manual standby identity, matching SSH port, no foreign active customer host, no active related migrations or original shared 6G lock, exact current Cloudflare A-record snapshot; independent pinned SSH/WG/NAT check.
- start(plan, actor, client_witness): revalidates preview and TTL (180 s), stores operator witness, atomically creates original 6G RUNNING lease with protected EGRESS_RECOVERY_REQUIRED phase and a durable DNS_INTENT journal. Uses CloudflareExactDNS.set_all with record-id/TTL/source checks; once DNS verified to target, changes account host metadata, default host, manual operation and settings in ONE SQLite transaction. Postchecks live DNS/DB and releases lease with DONE. Does not rebuild users or use Cloudzy API.
- resume(job, actor, retry_dns=False): inspects real DNS and DB after restart. DNS on target and DB on source → commit metadata without replaying DNS PUT. DNS and DB both on target → finish. DNS still on source → requires an explicit retry after fresh identity/transport checks. Partial/mixed DNS, drift and unknown write effects retain a protected recovery lease. No implicit rollback.
- latest(actor) / get(job): inspect pending recovery. A per-process async lock serializes repeated operator clicks.
- record_external_cutover(source,target,actor,client_witness,expected_active): append-only record for the already-completed 2026-10-29 emergency, *only* if exact manual-edge recovery reason and journal event exist, live DNS/target pinned SSH checks pass, and expected active roster matches. Never modifies old CZ07, accounts, DNS or 6G.
- check_manual_relay_via_cz04b(cz04b,plan): reuses existing pinned SSH/WG/NAT checks without Cloudzy provider reads. Independent real-client ISP witness remains a separate operator requirement.

## Lock and status contract

DNS_INTENT → DB_COMMITTED → DONE; uncertain states HOLD or DB_COMMITTED with an error (preserving post-DB recovery). External record uses EXTERNAL_VERIFIED, never pretends legacy CZ07 DONE.

Old CZ07 HOLD on unrelated endpoints does not block this *new engine*. Active CZ07 operations or HOLD on source/target, unresolved CZ04B route, CZ04A action on source/target and any active original 6G lease do block it. Historical CZ07 rows and global index are untouched, including their effect on legacy CZ07 UI until that UI is retired in Phase 3.

## Validation and release

SQLite and fake Cloudflare tests cover happy path, user count/host CAS, historical/related HOLD, simultaneous lease, DNS timeout, partial DNS, restart before DB write, restart after DB commit, pinned identity and idempotent emergency attestation.

Phase 3 must add admin-only Rich UI confirmation, explicit client acceptance, current-status/recovery screen and real isolated Edge test. Cloudzy buttons will be hidden then; shared engine code will remain. Do not invoke Quick Switch against active 45.59.126.73 (already default). Production does not run this source until separately deployed and wired.