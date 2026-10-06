# NVL Direct Market V1 — Architecture & 7-Phase Implementation Plan

**Status:** Active design record  
**Long-lived branch:** `feature/direct-market-v1`  
**Baseline:** `master@3cfc04981392999b331f76cb89143fd5d2dfd15d`  
**Started:** 2026-10-07  
**Rule:** Keep this document on the Direct Market branch and update it through the end of Phase 7.

## 1. Goal

NVL currently has a mature reseller/agent flow for SSH and Marzban/V2Ray sales, wallet/commission handling, receipt approval and service lifecycle. Direct Market V1 adds a separate customer-facing sales path without turning customers into agents and without rewriting the existing reseller domain.

Target customer flow:

```text
/start
  -> Customer Market
      -> Buy subscription
      -> My services
      -> Wallet
      -> Transactions
      -> Agent login (existing reseller entry)
```

Direct Market reuses the proven provisioning layer for SSH/Marzban, but identity, retail pricing, wallet, orders and accounting are separate from the existing Agent business model.

## 2. Non-negotiable compatibility rules

1. **Additive migrations only until Direct Market is proven in production.**
2. No `DROP TABLE`, `DROP COLUMN`, table rename, primary-key rewrite or mass legacy data migration.
3. No conversion of `agents` into generic users.
4. No modeling customers as zero-commission agents.
5. Existing `agents.balance`, commission, referral, emergency-credit, cashback and private-card behavior remain unchanged.
6. Existing `ssh_accounts.agent_id` semantics remain unchanged.
7. Existing rows in `ssh_accounts` receive `customer_id = NULL`; no historical ownership inference.
8. Direct Market uses **INTEGER toman** for all new monetary columns. Existing REAL/float columns are not rewritten.
9. `direct_market_enabled` starts at `0`; no public customer routing is activated in Phase 1.
10. Every phase preserves application-code rollback. Additive schema may remain inert after rollback.
11. Production deployment requires backup, integrity checks and legacy regression/smoke checks before enabling new behavior.

## 3. Domain boundaries

```text
Telegram
   |
   +--------------------+--------------------+
   |                                         |
Customer UI                              Agent UI
   |                                         |
   +-------------- Commerce -----------------+
                  /    |      \
             Customer Wallet Orders/Pricing
                       |
                  Provisioning
                  /          \
                SSH        Marzban
                       |
                 Service Account
```

- **Reseller:** Agent identity, Agent wallet, commission tree, emergency credit, cashback and reseller sales.
- **Commerce:** Customer identity, Direct Market plans, wallet ledger, orders and purchase state.
- **Provisioning:** Existing SSH/Marzban runtime creation and lifecycle.

A Direct Market customer is **not** an Agent with commission disabled.

## 4. Ownership model

During V1, `ssh_accounts` remains the service registry.

| Origin | agent_id | customer_id |
|---|---:|---:|
| Agent sale | > 0 | NULL |
| Direct Market customer sale | 0 | > 0 |
| Legacy/admin-created direct account | 0 | NULL |

`customer_name` is a label only and is never an authorization boundary.

No FK is added from legacy `ssh_accounts.customer_id` in Phase 1 because SQLite would require rebuilding the legacy table. Authorization will validate customer ownership in application code.

## 5. Accounting model

```text
Wallet top-up        = cash-in / customer credit
Order completion     = sale / revenue
Refund               = reversal / compensating movement
Wallet reservation   = temporary hold, not revenue
```

Example: a 500,000 toman top-up does not create 500,000 revenue. A later 180,000 toman completed order creates 180,000 revenue.

New monetary data is integer toman. The Direct Market wallet ledger is append-only; corrections use compensating entries.

## 6. Order state model

Target purchase state:

```text
pending
  -> funds_reserved
      -> provisioning
          -> completed
          -> failed -> funds released/refunded
```

Additional terminal states may include `cancelled` and `refunded`.

Every purchase attempt has an idempotency key. Telegram retries, callback replays and process retries must not create duplicate billable orders.

The legacy flow can provision an external service before financial settlement fully succeeds. Direct Market must not copy that behavior: Commerce owns money/order state and calls Provisioning from a controlled purchase workflow.

## 7. Phase 1 — Safety Baseline + Commerce Foundation

**Status: IN PROGRESS**

Scope:

- Create this long-lived architecture record.
- Feature flag `direct_market_enabled=0`.
- Add nullable `customer_id` to `ssh_accounts`.
- Add `customers`, `wallets`, `wallet_transactions`, `market_plans`, `orders`.
- Add ownership/history/order indexes.
- Store all new money as INTEGER toman with DB type checks.
- Keep wallet ledger append-only.
- Add order/ledger idempotency boundaries.
- Add regression tests proving legacy Agent/account/receipt/activity data is unchanged by schema installation.
- Make schema installation idempotent.
- Hook schema installation into existing `init_db()`.

Out of scope:

- no `/start` changes
- no customer auto-create/menu
- no wallet charging/receipt workflow
- no direct purchase
- no provisioning changes
- no Agent behavior changes
- no production feature enablement

Release gate:

1. `PRAGMA integrity_check` on production DB.
2. SQLite backup before deployment.
3. Run migration against a production DB copy first.
4. Compare legacy counts/totals before/after.
5. Run full test suite.
6. Deploy with feature flag OFF.
7. Post-deploy integrity + Agent/SSH/Marzban smoke tests.

Critical comparison set: `COUNT(agents)`, `COUNT(ssh_accounts)`, service distribution, `COUNT(receipts)`, `COUNT(activity_log)`, `SUM(agents.balance)`, and sample ownership rows.

## 8. Phase 2 — Customer Identity + /start Routing

**Status: PLANNED**

Routing:

```text
Super Admin -> Admin Panel
Authenticated Agent -> Agent Panel
Ordinary Telegram user -> Customer identity -> Market Home
```

Customer identity uses Telegram identifiers, not username/password.

Initial menu:

- 🛒 Buy subscription
- 📦 My services
- 💰 Wallet
- 🧾 Transactions
- 👨‍💼 Agent login

Security:

- Telegram user ID is the stable identity.
- Authorization is based on `customer_id`, never display username/name.
- Existing Agent/Admin session precedence remains compatible.

## 9. Phase 3 — Customer Wallet + Card-to-Card Top-up

**Status: PLANNED**

```text
Customer -> Wallet -> amount -> system card -> receipt
         -> pending -> admin approve/reject
         -> atomic wallet credit + immutable ledger row
```

Requirements:

- Customer receipts are modeled cleanly apart from Agent receipt ownership.
- Approval reloads amount/owner from DB; callback payload is not accounting truth.
- Duplicate approval is idempotent.
- Wallet balance update and ledger append are one DB transaction.
- Top-up is not sales revenue.
- Future gateways feed the same wallet-credit boundary.

## 10. Phase 4 — Direct SSH Purchase

**Status: PLANNED**

```text
select plan
 -> pending order
 -> verify available wallet
 -> reserve funds
 -> provision SSH
 -> set customer ownership
 -> capture purchase
 -> completed
```

Failure releases the reservation. No active service may silently remain without matching customer settlement. Provisioning and order execution must be retry-safe/idempotent.

## 11. Phase 5 — Direct Marzban/V2Ray Purchase

**Status: PLANNED**

Products:

- timed/unlimited V2Ray
- volume V2Ray

Reuse current Marzban provisioning/recovery logic. Retail plans live in `market_plans` and are independent from Agent pricing. Marzban is runtime state, not payment/ownership truth.

## 12. Phase 6 — My Services / Self-Service

**Status: PLANNED**

Customer sees only rows owned by its `customer_id`.

SSH: connection data, expiry/status, renewal.

V2Ray: QR, subscription URL, usage/remaining volume, expiry, add volume, renewal.

Source-of-truth split:

- NVL DB = ownership/order/billing
- Marzban = runtime service state

Renewal/add-volume actions are Orders, not ad-hoc deductions.

## 13. Phase 7 — Accounting, Hardening & Public Rollout

**Status: PLANNED**

Accounting separates Direct Market sales, Agent sales, wallet top-ups, revenue, refunds, pending payments and failed orders.

Hardening covers concurrency/double-click, callback replay, crash/restart recovery, stale orders, uncertain provisioning, insufficient balance and audit reconciliation.

Rollout:

1. feature OFF
2. internal/admin test customer
3. limited canary
4. reconciliation checks
5. public enablement
6. monitor failed/pending orders and accounting drift

## 14. Phase checklist

- [x] Long-lived Direct Market branch created.
- [x] Architecture decisions recorded.
- [ ] Phase 1 complete and reviewed.
- [ ] Phase 2 complete.
- [ ] Phase 3 complete.
- [ ] Phase 4 complete.
- [ ] Phase 5 complete.
- [ ] Phase 6 complete.
- [ ] Phase 7 complete / public rollout approved.

## 15. Deferred refactors

Not part of Direct Market V1:

- rename `ssh_accounts` to a generic service table
- merge Agent and Customer wallets
- replace all legacy REAL money fields
- rebuild all accounting into a single event store
- refactor the monolith solely for aesthetics
- infer historical customers from labels
