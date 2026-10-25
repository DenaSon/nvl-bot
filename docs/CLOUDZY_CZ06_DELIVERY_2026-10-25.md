# CZ-06 delivery — One approved Cloudzy purchase → Edge → protected Standby

Date: 2026-10-25
Status: source candidate, pending CI/merge and production acceptance
Depends on: CZ-05, CZ-03 and CZ-04A. CZ-07 is explicitly out of scope.

## Operator goal and actual safety boundary

The new `🚀 Quick Relay · خرید تا Standby` button appears in the Cloudzy menu while the legacy `⚡ ساخت Edge · مدیریت دستی` path remains usable.

One explicit confirmation authorizes the chargeable Cloudzy VPS purchase **and subsequent guarded Edge/Standby preparation**. No additional *routine* confirmation is required to promote a verified Edge to **inactive customer / active standby**. **Exception:** SSH host-key fingerprint must be compared independently with Cloudzy console or another trusted source, and the operator must attest that comparison before Legacy remote provisioning. A fingerprint observed only over the target connection is not independent evidence. Removing that checkpoint is unsafe and is **not** part of CZ-06.

No CZ-06 operation changes public DNS, source Relay, default route, user ownership, SSH account records, or any customer migration state.

## Architecture, modules and bounded scope

- `cloudzy_quick_edge.py`: optional Quick Relay selection. Reuses original CZ-03 purchase receipt, one-shot confirmation, Idempotency-Key, provision, trusted-hostkey validation and postcheck.
- `cloudzy_cz06_orchestrator.py`: separate SQLite `cloudzy_cz06_runs` journal, stage CAS, printable progress, and guarded call-through to verified CZ-04A Standby. No new chargeable provider call here.
- `cloudzy_cz04a.py`: existing `_state`, `_isolated`, `_provider`, `probe`, `_reserve`, `_promote`, `_finish` used by CZ-06; **does not** bypass protected security/failover leases.
- `bot_final_v49-2.py`: attaches existing guarded CZ-04A adapter to existing CZ-03 wizard; routes `apps_cz6_start/status/resume_*` callbacks. No other bot navigation changed.
- `cloudzy_admin_panel.py`: extra Quick Relay menu entry; manual path preserved.

New journal is created **in the same SQLite transaction as the original CZ-03 receipt** to keep the paid authorization and quick-mode preference atomic. Stages: `PURCHASING`, `WAITING_PROVIDER`, `HOSTKEY_PENDING`, `INSTALLING`, `EDGE_READY`, `STANDBY_VERIFYING`, `READY`, `HOLD`. Journal stores operation ID/actor/chat/message ID/short status code, never auth token, password, private SSH key or raw provider response.

Telegram status screen provides source receipt and quick progress; existing message can be edited when message ID is accessible. Telegram delivery failure is only logged; it must not replay payment.

## Safety / recovery matrix

| Step | Interruption or failure | Recovery action |
|---|---|---|
| Before charge | SKU stock/price unavailable | CZ-05 rejects; no provider POST |
| POST /services | Timeout/5xx/unknown result | Original CZ-03 `CREATE_UNCERTAIN`; do not reissue POST; read-only reconciliation by exact hostname |
| Cloudzy provisioning/polling | Provider not ACTIVE, IP unknown | Original CZ-03 read-only reconcile; no new order |
| SSH host key | Independent fingerprint evidence unavailable | `HOSTKEY_PENDING`, stop; no remote install |
| Legacy provision | Partial/failed setup | Original `HOLD_PROVISION` + workflow `HOLD`; **never auto-rerun** |
| EDGE_READY | Worker restart before standby | Operator can invoke **continue Standby**; no repurchase or reinstall |
| CZ-04A standby | Provider/SSH/WG/route/lease check fails | `HOLD` with code; investigate CZ-04A journal before retry |
| Already promoted standby | Crash after DB commit before CZ-06 journal READY | A guarded replay can verify exact ownership/isolation and mark READY without another promote |
| Progress message | Telegram edit fails | Log only; authoritative SQLite and receipt remain |

A `HOLD` is deliberately not blindly retryable. Resume is exposed only for `EDGE_READY` receipt with CZ-06 `EDGE_READY/STANDBY_VERIFYING` journal, owner-bound and only one in-process job. On restart after an uncertain 04A commit, inspect CZ04A journal before allowing a new mutation.

## Acceptance tests

- End-to-end mocked single purchase, hostkey hold, Edge verification then CZ-04A standby; no DNS/users mutations.
- No extra `POST /services` when moving from `EDGE_READY` to Standby or using resume.
- Fail-closed when CZ04A protected guard, provider, active state, SSH/WG probe, K2 or failover is not accepted.
- Stale/duplicate stage CAS and concurrent workflow journal lock.
- Legacy CZ-03 manual workflow, CZ-04A/B, CZ-05 and the full suite must remain passing.
- CI: `python -m unittest discover -s tests -v`, source-bundle verification and root regression.

## Operational rollout / warning

1. Merge a passing PR only; deploy exact pinned master commit with backup and `python -m py_compile` of modified Python modules and `systemctl` health check.
2. The operator may test Quick Relay selection and availability without buying. Testing paid E2E requires a separate real Cloudzy purchase decision.
3. Begin production CZ-06 purchase only when no unresolved earlier CZ03/04A operation exists. The old Relay remains active and customers untouched.
4. Do **not** enable CZ-07 cutover/transfer under CZ-06. Independent real customer-path verification is still required for each new IP before any later DNS cutover.
5. Existing CZ-05 catalog price is still advisory; IPv4 and other addons can affect final Cloudzy charges. A confirmed quote contract is future work, never present the catalog amount as a guaranteed final charge.

## Next phase

CZ-07: guarded cutover with independently validated client-path health; durable low-concurrency queued SSH Host updates, safe HOLD/resume, progress reporting, resolution of Issue #191. Update CZ-07 documentation separately at completion.
