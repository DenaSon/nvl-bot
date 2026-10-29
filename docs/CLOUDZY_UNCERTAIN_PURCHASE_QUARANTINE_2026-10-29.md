# NVL Cloudzy uncertain paid POST — guarded operator quarantine hotfix

**2026-10-29**. Applies only to CZ03/CZ06 purchase cancellation after a Cloudzy paid POST produces an ambiguous result. **No** changes to DNS, WireGuard, customer SSH accounts, CZ04B or CZ07.

## Incident and root cause

An hourly Cloudzy order (e.g. `47580f8095da4314...`) may fail its create response with `CREATE_RESULT_UNCERTAIN`, leaving CZ03 `CREATE_UNCERTAIN` and CZ06 `HOLD`, possibly without provider_server_id/IP. Previously CREATE_UNCERTAIN was not in CANCELLABLE_STATES, yet one_unfinished and purchase reserve blocked any next attempt. A provider GET failure then became an indefinite lock.

The lack of a provider API receipt **does not prove no VPS exists or no charge was taken**, even when the operator sees no server in the panel.

## Contract: opt-in quarantine, not false provider cancellation

- The owner in the *same private Telegram chat* sees `🛡 درخواست لغو و تعیین تکلیف خرید نامشخص` when CREATE_UNCERTAIN and no in-process worker exists.
- On request and final confirmation, Cloudzy's list_servers is observed using GET, never reissue paid POST. A unique matching hostname/provider identity, any ambiguous exact match, or an already-known provider ID/IP blocks this path; resolve/delete that VPS separately.
- Missing inventory match (not conclusive) or GET unavailable permits **only explicit owner risk acceptance**; confirmation copy states Cloudzy control-panel examination is needed and possible ongoing hourly charges remain. The confirmation is single-use and expires after 180 seconds.
- The uncertain status must have remained unchanged at least 120 seconds. The original process must not be actively running; this protects normal in-process work but is **not cryptographic proof** that a remote POST cannot later take effect.
- In one BEGIN IMMEDIATE DB transaction, recheck exact actor/chat, original status, no known provider ID/IP, no customer/default/DNS/route attachment, no READY/CANCELLED CZ06, and then update CZ03=CANCELLED and CZ06=CANCELLED; create immutable `cloudzy_edge_cancel_events` and `cloudzy_purchase_quarantine` row with disposition `PENDING_PROVIDER_RECONCILIATION`.
- The UO linked record is updated atomically to `RECONCILE_REQUIRED / PROVIDER_PURCHASE_QUARANTINED`, keeping paid intent. Other local cancel states with paid intent similarly remain `RECONCILE_REQUIRED`, not falsely provider-settled.
- The native operation becomes terminal, releasing the one-unfinished index and next purchase selection. Its hostname, idempotency key, provider receipt and linked UO remain visible/auditable. No Cloudzy DELETE is attempted.
- A new purchase still needs the original independent one-shot operator approval, valid Cloudzy price/stock and unique idempotency key. Never automatically try again.

## Production operator flow

1. Admin → Programs → Cloudzy → `📋 سوابق و وضعیت عملیات`, select the uncertain receipt.
2. Optionally `🔎 بررسی همان VPS؛ بدون خرید`; if Cloudzy is down this may keep CREATE_UNCERTAIN. Return to the same receipt.
3. `🛡 درخواست لغو و تعیین تکلیف خرید نامشخص`. Review the original hostname against Cloudzy control-panel inventory and billing; do **not** delete or disable original customer Edge.
4. `✅ پذیرش ریسک و خروج از قفل خرید`. After 120 seconds from uncertain status the local journals close; provider outcome stays unresolved.
5. Verify CZ03/CZ06 CANCELLED, UO RECONCILE_REQUIRED and quarantined purchase tracking; start another purchase only with a fresh explicit approval.

## Read-only audit

```sql
SELECT substr(o.id,1,16) operation,o.status,o.hostname,o.hold_reason,
       c.stage,c.detail_code,u.state,u.code,u.external_intent,
       q.disposition,q.provider_observation
FROM cloudzy_edge_operations o
LEFT JOIN cloudzy_cz06_runs c ON c.operation_id=o.id
LEFT JOIN cloudzy_uo_operations u ON u.id=o.id
LEFT JOIN cloudzy_purchase_quarantine q ON q.operation_id=o.id
WHERE o.id LIKE '47580f8095da4314%';
```

## Follow-up and limits

The quarantine entry is a **billing/provider reconciliation obligation**, not proof of refund, successful deletion, cancelled Cloudzy subscription or absence of a VPS. Later check the provider's invoices and servers by the original hostname and provider ID, delete orphaned paid VPS from the guarded Cloudzy management path if appropriate, and separately document closure. Repeated API failures can still produce multiple explicit quarantined obligations; monitor the table to prevent unnoticed costs. Do not use direct SQL status edits to release purchase locks.

## Rollout

Merge after Python unit/release, Legacy and Edge CI green. Deploy only `cloudzy_quick_edge.py` and `cloudzy_unified_native.py` at pinned SHA, after runtime drift check, service and DB backup, syntax/import tests and controlled service restart. This patch is not a Core deployment and never modifies existing production SQLite rows just by loading the modules.
