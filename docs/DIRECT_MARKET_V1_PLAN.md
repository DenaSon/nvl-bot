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

**Status: IMPLEMENTED ON BRANCH — PRODUCTION ROLLOUT PENDING**

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

Validation on branch:

- Phase-1 commit: `cf9b2b7bf7c6b5e82fbf28856dd559dc5b9a7185`
- GitHub Actions `syntax-and-unit-tests`: **passed**
- Full suite: **744 tests passed**
- Direct Market Phase-1 regression tests: **5/5 passed**
- Production DB migration/deployment has **not** been performed yet; the release gate above is still mandatory.

## 8. Phase 2 — Customer Identity + /start Routing

**Status: IMPLEMENTED ON BRANCH — FEATURE FLAG OFF / PRODUCTION ROLLOUT PENDING**

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

Implemented behavior:

- Customer identity is upserted by stable Telegram user ID; username/first name are refreshable metadata only.
- Customer storefront is private-chat only.
- Existing authenticated Admin/Agent/Accountant sessions retain precedence over Customer routing.
- `direct_market_enabled` remains the master gate and defaults to OFF.
- Customer home menu is available only when the gate is enabled:
  - 🛒 خرید اشتراک
  - 📦 سرویس‌های من
  - 💰 کیف پول
  - 🧾 تراکنش‌ها
  - 👨‍💼 ورود نماینده
- Phase-2 customer actions are non-financial placeholders; no order, wallet credit/debit or provisioning can occur.
- Customer can explicitly enter the existing Agent/Admin credential flow from the storefront.
- Customer sessions are fail-closed at the callback boundary and cannot execute legacy Agent/Admin callbacks.
- Customer arbitrary text cannot fall through into legacy state machines.
- A blocked customer is never reactivated by sending `/start`.

Validation on branch:

- Phase-2 commit: `0af828d80d8c1872159262b860f41c74fc2069c8`
- GitHub Actions `syntax-and-unit-tests`: **passed**
- Full suite: **757 tests passed**
- Direct Market Phase-2 tests: **13/13 passed**
- Production behavior is unchanged while `direct_market_enabled=0`.

## 9. Phase 3 — Customer Wallet + Card-to-Card Top-up

**Status: IMPLEMENTED ON BRANCH — FEATURE FLAG OFF / PRODUCTION ROLLOUT PENDING**

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

Implemented behavior:

- Added `customer_topup_receipts` as an additive table; legacy Agent `receipts` remains untouched.
- Direct Market schema version advanced to `2` only after all additive DDL succeeds.
- Customer wallet is created lazily with zero balance.
- Wallet screen now shows balance, available balance, reserved amount and pending top-up totals.
- Customer can start a card-to-card top-up from the Wallet screen.
- System `bank_card` setting is reused; if no system card is configured, the flow fails closed before a receipt can be submitted.
- Amounts accept integer toman only and reject float/non-positive/oversized values.
- Receipt submission is idempotent using the Telegram update identity.
- Admin review callbacks contain only `receipt_id`; customer ID and amount are reloaded from SQLite.
- Approval runs under an atomic SQLite write transaction and performs:
  1. wallet credit,
  2. immutable `wallet_transactions` append,
  3. receipt approval/status link.
- Duplicate approval returns `already_approved` and cannot credit twice.
- Rejected receipts cannot later be approved.
- Blocked customers cannot submit new top-up receipts.
- Customer transaction history now reads directly from the immutable wallet ledger.
- Customer callbacks remain explicit allowlist entries; all legacy Admin/Agent callbacks stay blocked.
- Top-up remains cash-in/customer credit, not sales revenue. Revenue accounting is still deferred to completed Orders.

Validation on branch:

- Main Phase-3 implementation commit: `f68989715906b86052fdd9d52a0ad39386490a5a`
- Final Phase-3 head after regression fixes: `e41f7def2193202e2e11b279d0e850ff23a10da8`
- GitHub Actions `syntax-and-unit-tests`: **passed**
- Full suite: **770 tests passed**
- Direct Market Phase-3 tests: **13/13 passed**
- Production behavior remains unchanged while `direct_market_enabled=0`.

## 10. Phase 4 — Direct SSH Purchase

**Status: IMPLEMENTED ON BRANCH — FEATURE FLAG OFF / PRODUCTION ROLLOUT PENDING**

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

Implemented behavior:

- Added `market_orders.py` as the Direct Market order/state-machine domain; it does not use Agent balance, commission, cashback or emergency-credit logic.
- Direct Market schema version advanced to `3` using additive-only changes.
- Added nullable `ssh_accounts.market_order_id` with a unique partial index. Direct SSH ownership is now bound by both `customer_id` and `market_order_id`.
- Extended the existing SSH finalizer with optional trailing `customer_id` / `market_order_id` arguments. Legacy Agent/Admin callers remain backward-compatible and continue to write NULL ownership metadata.
- `orders` now snapshots the purchase contract at order creation: price, duration, users limit and connection mode. Later edits to `market_plans` cannot change an already-created order.
- Retail SSH plans are read only from explicitly configured active `market_plans` rows. Phase 4 does **not** seed guessed/default retail prices and does not derive them from Agent pricing.
- Phase-4 SSH uses `connection_mode='direct'`. Additional service types/modes are introduced only in their dedicated phases.

Financial/state sequence:

```text
pending
  -> funds_reserved      (wallet balance unchanged; available balance decreases)
  -> provisioning
  -> completed           (capture: balance decreases + reservation clears + purchase ledger)
```

- Funds are reserved **before** any Linux `useradd` side effect.
- Order creation/reservation is idempotent. Replaying the same purchase callback cannot reserve twice or create a second billable Order.
- Provisioning uses a single-writer claim; a concurrent/replayed callback sees `in_progress` instead of creating another service.
- Wallet capture is allowed only after SQLite proves an active SSH row matching the exact username, customer and market order, with `agent_id=0`.
- Successful capture atomically:
  1. deducts `balance_toman`,
  2. releases `reserved_toman`,
  3. appends one immutable `purchase` wallet transaction,
  4. marks the Order `completed`.
- Re-running completion is idempotent and cannot charge twice.

Failure/compensation rules:

- If provisioning fails and cleanup is proven complete, the Order becomes `failed`, the reservation is released and wallet balance is not debited.
- Funds cannot be released while any `ssh_accounts` row still references the Order.
- If Linux/DB cleanup is uncertain, the Order stays in `provisioning`, receives a `RECOVERY_REQUIRED` reason, and the money remains **reserved but not captured**. Admins are notified automatically. This deliberately prefers a temporary hold over a free/unknown live service.
- If wallet capture itself fails after service creation, the service is compensated/removed first; reservation is released only when that cleanup is proven safe.
- Direct Market cleanup deletes only an artifact provably owned by the same customer/order attempt; it cannot broadly delete legacy Agent/Admin services.
- The Direct Market customer action/callback/photo paths re-check the master `direct_market_enabled` flag, so a stale persisted Customer session cannot continue purchasing after an operator disables the market.
- Order atomic functions preserve caller-owned SQLite transactions using SAVEPOINTs instead of committing unrelated outer work.

Provisioning reuse:

- Reuses the established SSH primitives for atomic username reservation, hidden hold scheduling, Linux `useradd` / `chpasswd`, DB finalization, PAM user-limit synchronization and invoice rendering.
- The legacy Agent purchase path itself is not refactored in this phase.

Deferred hardening:

- Automatic startup reconciliation/retry of stale `provisioning` Orders is intentionally deferred to Phase 7 hardening. Phase 4 is fail-closed: callback replay does not provision twice, and ambiguous cleanup keeps funds reserved for operator review rather than guessing.
- `📦 سرویس‌های من` remains Phase 6; Phase 4 returns the completed invoice directly after purchase.

Validation on branch:

- Main Phase-4 implementation commit: `82f306cb5c51319e72de25af4cfa282a87bfcb89`
- Final Phase-4 code head after transaction-boundary hardening: `ab7fb5660fd6404853fcee1c09deb81205069a32`
- GitHub Actions `syntax-and-unit-tests`: **passed**
- Full suite: **790 tests passed**
- Direct Market Phase-4 tests: **20/20 passed**
- Production deployment/migration has **not** been performed and `direct_market_enabled` remains OFF by default.

## 11. Phase 5 — Direct Marzban/V2Ray Purchase

**Status: IMPLEMENTED ON BRANCH — FEATURE FLAG OFF / PRODUCTION ROLLOUT PENDING**

Products:

- timed V2Ray with optional daily data cap; NULL `data_limit_gb` means unlimited data
- volumetric V2Ray with required total volume and optional expiry; NULL `duration_days` means unlimited time

Reuse current Marzban provisioning/recovery logic. Retail plans live in `market_plans` and are independent from Agent pricing. Marzban is runtime state, not payment/ownership truth.

Implemented behavior:

- Added `market_v2ray.py` as the Telegram/DB-agnostic mapping between immutable Commerce Orders and the Marzban runtime contract.
- Direct Market schema version advanced to `4` using additive-only migration. `orders.data_limit_gb` snapshots the purchased data contract alongside price, duration and users limit.
- No guessed/default V2Ray retail prices are seeded and no Agent `v2ray_base_price` / `v2ray_vol_price` values are reused. Only explicitly configured active `market_plans` can be purchased.
- The Customer Buy screen is now a product hub:
  - SSH
  - V2Ray timed
  - V2Ray volume
  - Wallet
- Timed V2Ray plan contract:
  - `service_type='v2ray'`
  - `duration_days > 0` is required
  - `users_limit > 0` is required
  - `data_limit_gb = NULL` means unlimited data and `no_reset`
  - a positive `data_limit_gb` means a daily data cap and uses Marzban `day` reset
- Volumetric V2Ray plan contract:
  - `service_type='v2ray_vol'`
  - positive `data_limit_gb` is required
  - `duration_days` is optional; NULL means no time limit
  - Marzban reset strategy is `no_reset`
  - the local service row keeps the existing NVL volumetric convention of `users_limit=0` for unlimited-user display/management semantics.

Commerce/order invariants:

```text
select V2Ray plan
 -> create idempotent Order
 -> reserve customer funds
 -> claim provisioning (single writer)
 -> create + verify Marzban User
 -> finalize exact local ownership
 -> capture wallet
 -> completed
```

- The same Phase-4 wallet reservation/capture engine is reused. No Agent balance, commission, cashback or emergency-credit path participates in Direct Market V2Ray settlement.
- Each Order snapshots `price_toman`, `duration_days`, `data_limit_gb`, `users_limit` and `connection_mode='v2ray'`; later plan edits cannot mutate an in-flight purchase.
- Telegram purchase callbacks use nonce-derived idempotency keys. Replays/double taps cannot create a second billable Order or reserve funds twice.
- Funds are reserved before the remote Marzban create POST.
- Successful wallet capture is still allowed only after SQLite proves an active service row matching the exact `customer_id + market_order_id + service_type`, with `agent_id=0`.
- Capture atomically deducts balance, clears the reservation, appends one immutable negative `purchase` ledger entry and marks the Order completed.
- Failure release is blocked while any local service row still references the Order.

Marzban safety and ownership verification:

- Before provisioning, Direct Market performs a Marzban/inbound preflight and builds the User from the currently authoritative supported inbound set rather than hard-coded stale tags.
- Every Direct Market Marzban User receives a runtime ownership marker in `note`:
  - `NVL_MARKET_ORDER:<order_id>;CUSTOMER:<customer_id>`
  - timed plans additionally carry the existing `IP_LIMIT:<users_limit>` marker.
- After create, the authoritative Marzban GET must match the exact username, active status, data limit, expiry, reset strategy (when returned) and Direct Market ownership marker before Commerce may capture money.
- The subscription URL is taken from the verified payload when available, otherwise fetched through the existing Marzban service boundary. The completed purchase returns both subscription URL and QR code.
- Local finalization binds `service_type`, `customer_id` and `market_order_id` before wallet capture.

Failure/recovery behavior:

- An explicit username collision is safe to retry with a newly reserved username.
- `MarzbanAdminService.create_user` was hardened so pre-POST failures are explicitly non-side-effecting, while any non-collision failure after the create POST is treated as potentially side-effecting.
- If POST/verify is ambiguous, Direct Market performs an authoritative GET reconciliation instead of blindly repeating the POST.
- If GET proves the exact Order-owned User exists, provisioning resumes without duplicate creation.
- If absence is proven and no local service remains, the Order fails safely and the wallet reservation is released with no debit.
- If existence/ownership/cleanup cannot be proven, the Order remains `provisioning`, gets `RECOVERY_REQUIRED`, customer money stays reserved but not captured, and admins are notified.
- Remote compensation is allowed only after the fetched Marzban User verifies the exact Direct Market marker/runtime contract. Local cleanup likewise deletes only the exact `customer_id + market_order_id + service_type` artifact.
- If wallet capture fails after remote/local provisioning, compensation runs first; reserved funds are released only after both Marzban and local cleanup are proven safe.

Compatibility and deferred work:

- Existing Agent/Admin V2Ray sale paths are not migrated to the Direct Market wallet/order model in this phase.
- The hardened Marzban create-error contract also makes legacy V2Ray sales safer: ambiguous non-collision POST failures now surface `created=True` and therefore retain the existing recovery marker rather than blind retrying.
- `📦 سرویس‌های من`, customer-side runtime usage, renewal and add-volume actions remain Phase 6.
- Automatic startup reconciliation of stale `provisioning/RECOVERY_REQUIRED` Orders remains Phase 7 hardening; Phase 5 is deliberately fail-closed rather than guessing after an uncertain remote side effect.

Validation on branch:

- Main Phase-5 implementation commit: `9f1aa9ffb49799d3743a17b37944f9cfe68432bc`
- Marzban ambiguous-POST hardening commit: `2834df2de0e4694091ac14e64eded2abaf26780c`
- GitHub Actions `syntax-and-unit-tests`: **passed**
- Full suite: **812 tests passed**
- Direct Market Phase-5 tests: **20/20 passed**
- Additional Marzban create-boundary hardening tests: **2/2 passed**
- Production deployment/migration has **not** been performed and `direct_market_enabled` remains OFF by default.

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
- [x] Phase 1 implementation complete on branch; CI green. Production rollout gate remains pending.
- [x] Phase 2 implementation complete on branch; CI green. Feature flag remains OFF pending controlled rollout.
- [x] Phase 3 implementation complete on branch; CI green. Feature flag remains OFF pending controlled rollout.
- [x] Phase 4 implementation complete on branch; CI green. Feature flag remains OFF pending controlled rollout.
- [x] Phase 5 implementation complete on branch; CI green. Feature flag remains OFF pending controlled rollout.
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
