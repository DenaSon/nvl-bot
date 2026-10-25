# CZ-05 — Hourly live-stock Cloudzy catalog and diagnostics

**Date:** 2026-10-25  
**Scope:** Cloudzy catalog / CZ-03 Telegram purchase wizard only. **No** DNS, Core, WireGuard, CZ-04A/B route, SSH ownership, legacy manual callback, or K2 mutation.  
**Release:** Source-level candidate. Production validation/deployment is separate.

## Field evidence from operator

- `GET /pricing/catalog` returned 25 plans, 2,186 price records, 306 hourly records. A regional hourly price uses `amount` (integer cents/hour, rounded by provider); `monthlyEquivCents` is **not** an hourly charge.
- `GET /regions` returned array data with `stocks`, `isOutOfStock`, etc. These fields do not establish **per-plan** availability. Region-level `orderable` contradicted web UI per-plan capacity, so it is **not** the authorization source.
- Browser observed `GET /plan-availability?region=DE-Frankfurt` and `...NL-Amsterdam-DC2`, with `region`, `checkedAt`, and `plans[].{planId,available,fitsOnNodes,source,code,reason}`.
- The same endpoint succeeded using a scoped Cloudzy Developer API Bearer Token in PowerShell. **Read-only field snapshot**, 2026-10-25: Frankfurt 0/10 standard VPS available; Amsterdam DC2 10/10. These counts are time-sensitive and not a guarantee of later capacity.
- The web UI visually marks Frankfurt standard VPS sizes `At capacity` although `stocks[type=default].orderable=true`.
- `ip-availability` and `quote` appeared in browser traffic; their API access/response contracts are **not yet verified**. This phase does not fabricate final IPv4 prices or perform unsupported quotes.

## Business rules and data mapping

Only allow:
1. `instanceType == "default"` **and** standard `slug` such as `vps-512` or `vps-1gb`; custom, CPU-optimized, and GPU options are excluded.
2. `billingCycle == "hourly"`, an **exact regional** pricing record `regionId == selected region`, `amount` positive integer, currency `USD`; no general-price fallback or `monthlyEquivCents` interpretation.
3. `/plan-availability` for the exact region, with `available is true`, `source == "live"`, `fitsOnNodes > 0`, exact `planId`, valid `checkedAt` not older than 90 seconds (allow 30 seconds forward clock skew).
4. Unknown/missing/stale/duplicate stock, errors or mismatched region/cycle cause HOLD and **no purchase**. Catalog availability is inherently advisory until provider accepts a paid request.

Location priority: Frankfurt (DE-Frankfurt) → Amsterdam (NL-Amsterdam-DC2 then NL-Amsterdam) → London (UK-London) → Bern (CH-Switzerland) → Dallas (DTX) → Utah (US-Utah) → Singapore (SG-Singapore-DC2 then SG-Singapore). Region-level inactive/hidden/out-of-stock status is excluded. `regionOutOfSales` is not treated as an authoritative Boolean, because operator observed contradictory data. Live per-plan stock is the controlling signal.

## Flow / safety

- The CZ-03 wizard lists preferred regions in priority order, with **auto-select first available** and explicit manual override.
- Live per-plan stock is checked for display, checked again on button confirmation **before** receipt reservation, and again directly before Cloudzy `POST /services`. Changes fail closed without initiating a charge. A reserved operation rejected in this last check is marked `REJECTED` in the existing durable journal, not `CREATE_UNCERTAIN`.
- The receipt still contains the provider idempotency key. Any uncertain **POST** outcome continues the existing `CREATE_UNCERTAIN` manual-reconciliation policy; no blind retry.
- Telegram errors provide safe error code/reference; application logs include reference or operation ID, stage, HTTP status and limited provider code. Do not log Cloudzy token, Authorization header, complete user input or private SSH keys.
- UI keeps explicit payment approval and conservatively labels catalog price (cents per hour) as an estimate excluding IPv4/add-ons. There is no promised final quote in CZ-05.
- Historical monthly receipts are readable for reconciliation; NEW CZ-03 reservations and old `apps_cz_qcy_monthly` callbacks are rejected.
- Legacy account provisioning, host-key acceptance, old manual controls, CZ04A/CZ04B cutover remain unchanged.

## Verification

Hermetic tests:
- `python -m unittest tests.test_cloudzy_service tests.test_cloudzy_quick_edge tests.test_cloudzy_cz05_catalog`
- Tests cover read-only route, hourly amount vs monthly equivalent, Regular CPU-only, exact-region pricing, stale/missing/estimated stock, preferred region priority, no-charge on stock change, old monthly callback rejection, idempotency and existing CZ03 regression.
- Full repository regression/CI still required before merge. A passing unit suite is not a live paid provider acceptance test.

## Follow-on work (NOT implemented in CZ-05)

- **CZ-06:** one approval → guarded paid purchase → Edge installation → Standby readiness, persistent orchestrator and resume.
- **CZ-07:** explicit field-validated cutover → durable queued SSH host migration and progress, recovery, final audit.
- A supported `quote`/IPv4 availability contract should be researched before displaying a true checkout total. Do **not** present catalog prices as final billed amounts.
- Issue #191: old Relay eligibility after CZ04B needs resolution before unattended CZ07 transfers.

**Documentation discipline:** Update delivery records after **each** of CZ-05, CZ-06, CZ-07 independently; avoid declaring future phases complete from current source.
