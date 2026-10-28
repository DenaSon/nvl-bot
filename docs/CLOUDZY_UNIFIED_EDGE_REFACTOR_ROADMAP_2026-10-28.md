# NVL — Unified Edge Refactor: 8 implementation phases

**Plan date:** 2026-10-28  
**State:** planned only. Documentation update is not an implementation or deployment authorization.  
**Canonical design:** [Unified Edge Lifecycle / Persian errors / Rich admin UI](CLOUDZY_UNIFIED_EDGE_LIFECYCLE_DESIGN_2026-10-28.md).  
**Owner scope:** existing Legacy SSH ingress Relay behind WG, Cloudzy VPS management, new-edge provisioning, safe public route cutover, customer endpoint metadata migration and 3-person Telegram admin UI. K2 protected per-UID Egress is deliberately excluded.

## Delivery protocol for every phase

- One small dedicated branch/PR per phase; owner review and exact-commit CI before merge. Never combine source modifications with live Core mutation.
- Begin by comparing current master, deployed Core source hash/feature flags and read-only DB schema; docs can be newer than production.
- Capture failing production-like fixture(s) and regression tests **before** changing behavior; preserve historical CZ-03/04A/04B/06/07/08 journal data and original 6G/6H fences.
- Complete phase with: code diff, added tests, failures deliberately injected, read-only verification plan, deployment/rollback boundaries, and an explicit PASS/HOLD report.
- No new production Cloudzy POST/DELETE, DNS cutover or customer transfer unless the owner **separately authorizes that precise action**.
- No K2, Marzban, wallets, finance, SSH/PAM/OS account rebuild, unrelated Telegram screens or global refactor. Keep existing Legacy UI/callbacks usable until phase 8 is accepted.
- Experimental Telegram 10.3 Rich UI can be tested in a private admin/lab chat, but **no HTML fallback implementation** for the new operation dashboard.

## Phase 1 — Routing truth + forensic baseline (P0)

**Goal:** freeze behavior and replace the ambiguity between host_pool, settings.hosts, cached/live DNS, accounts, standby and Core identity with a **read-only canonical RouteSnapshot / InvariantReport**. Identify the exact scope of DEFAULT_CUSTOMER_RELAY_NOT_ELIGIBLE, LEGACY_HOSTS_ORDER_MISMATCH, and renewal failure without prematurely changing business logic.

**Work:** add reusable read-model and validators, distinguish INVENTORY from ELIGIBLE_ENDPOINTS, CURRENT_DEFAULT, ACTIVE_CUSTOMER_ASSIGNMENTS and VERIFIED_STANDBY; map current Legacy + CZ04B/CZ07 implicit assumptions. Produce live-safe read-only report and fixture for 2026-10-28 mismatch. No automatic repair or DNS/DB mutation in this phase.

**Touchpoints:** new small route read-model, cloudzy_cz04b.py integration seams, existing host_pool/settings/SSH enrollment tests, legacy hpdef_/migrate contracts (read-only mapping).  
**Exit:** test reproduces default .249-last mismatch; invalid state has exact Persian diagnosis and indicates which fields disagree; known-good single-default state passes; no old behavior change.

## Phase 2 — Durable coordinator / leases / cancellation & reconciliation (P0)

**Goal:** build one operation-centric control plane without replacing original provider/6G/CZ04B operations with unreviewed parallel writers.

**Work:** additive journal/projection + append-only events; step and execution-state separation; attempt ids, expected-version CAS, bounded lease/heartbeat/fencing, crash restart scanner; explicit safe cancellation request and reconciliation decision engine. Reconstruct old CZ03/06/04A/04B/07/08 status read-only first; no broad schema rewrite.

**Failure tests:** crash between CZ07 QUEUED commit and worker launch, crash before/after provider response persistence, duplicate callback, stale worker simultaneous restart, repeated cancel, unrecoverable external-write ambiguity, expired leases.  
**Exit:** a stuck job remains discoverable, diagnosable and safely actionable after restart; no double worker/provider call; all original guards still apply. Cancellation never means force unlock.

## Phase 3 — Cloudzy purchase API / stock / billing intent (P0)

**Goal:** accurate Cloudzy errors and safe paid-order idempotency.

**Work:** distinguish READ errors, HTTP 401/403/429, stock freshness, changed price, unknown response, definite rejection and uncertain paid POST; approved SKU, hourly price and total billing ceiling/IPv4 charge disclosure; bounded GET retry and provider identity reconciliation. Every POST create has stable idempotency key; never repeat ambiguous create/delete. One paid authorization confirmation; subsequent checks automatic.

**Failure tests:** 90s stale catalog, stock goes to zero, regional price drift, provider 4xx/429/5xx and timeout, POST accepted but Telegram/SQLite response missing, duplicate callback, recycled-IP ownership.  
**Exit:** Persian explanation with meaningful action; no duplicate VPS or surprise new charge. Existing Cloudzy purchase path intact until promoted.

## Phase 4 — Edge provisioning & Standby recovery (P0)

**Goal:** prepared Edge can be adopted/reconciled or safely continued on the **same VPS**, not indefinitely HOLD due partially installed packages/SSH/WG.

**Work:** provider-ID-based identity, independent host-key attestation, Core key/port pin, manifest of install effects and exact read-only postchecks; make future installer steps resumable/idempotent **only after verified specification and isolated tests**. Preserve old setup_edge_relay.sh as-is until proven safe; no automatic rerun of its unconditional iptables operations. Unify CZ06 & CZ04A progress with secure standby acceptance.

**Failure tests:** apt lock, dropped SSH session, host-key changed, half-written wg0, NAT duplicated or missing, install postcheck crash, DB receipt failure after successful install, alternate/inactive IP collision.  
**Exit:** operator can cancel/inspect/reconcile same Edge without repurchase; no duplicate firewall/WG rules; Standby cannot receive customer routing prematurely.

## Phase 5 — Guarded public DNS / default cutover (P0)

**Goal:** eliminate non-atomic Legacy default/hosts/DNS divergence through one guarded ingress route cutover contract.

**Work:** reuse original CZ04B route stages, original shared 6G fence and Cloudflare exact-record checks; add canonical routing projection and evidence-driven reconciliation for partial external success. Stage preflight / DNS intent / live DNS verify / DB CAS / postcheck as a Saga. No blind rollback or replay of DNS writes. Legacy callbacks get compatibility/drift checks without removing them yet.

**Failure tests:** DNS fails before/after one record, provider read timeout before lock, Cloudflare changed externally, default drift, settings.hosts mismatch, locked 6G, late prior worker, stale customer fingerprint.  
**Exit:** after any failure show unambiguous verified source/target or RECONCILE_REQUIRED; no customer on invalid default and no unrelated global blocker. **No live Cutover in this phase unless separately approved**.

## Phase 6 — Customer migration + business-path validation (P0)

**Goal:** reliable resumable CZ07 transfer with exact per-batch outcome and no lost customers.

**Work:** preserve CAS-based <=50 batches and original guarded per-account update; persistent checkpoints, counters computed from DB, restart ownership leases, cancel at batch boundary, re-evaluate live DNS/default/WG/NAT/provider before every resumed mutation. Require source account scope consistency and independently verified affected-ISP SSH customer E2E evidence. After transfer verify new SSH account CREATE and existing account RENEW, not just connectivity; log them as distinct postconditions.

**Failure tests:** 0/1/50/51/493/495 accounts, crash mid-batch, duplicate resume, newly added user, one other host, DNS changed during migration, old server remains available, sales/renew contract failed.  
**Exit:** no partial-batch replay or double count; next safe action always visible. No DONE until business and external-client checks pass (or explicitly register a not-yet-accepted intermediate state).

## Phase 7 — Admin-only Telegram Rich UI, localization & automation (P1 but required before release)

**Goal:** implement the user-approved polished interface for **three administrators on up-to-date Telegram clients**. **Rich Messages only; no HTML fallback, no Mini App.**

**Work:** a single PTB 22.8 compatible Telegram Bot API 10.3 transport adapter (sendRichMessage / editMessageText.rich_message); is_rtl, compact table/list/details, inline contextual RichMessageButton styles, one durable editable operation card, throttled render from event version, per-admin message pointers and failed-delivery outbox. Translate all errors through ErrorCatalog + typed action policy; unknown errors get short Persian text and technical detail disclosure. Remove duplicate confirmation loops while retaining one charged-purchase authorization and truly independent SSH/client-path security attestations.

**Failure tests:** rich payload rendering on each current Telegram client used by admins, button callback 64-byte limit, stale nonce/operator authorization, duplicate press, Telegram 429/timeout/deleted message/restart, security redaction, Persian RTL mixing, long error details, no HTML fallback.  
**Exit:** one card accurately shows 8-stage timeline, real count x/y, stage-specific Retry/Resume/Reconcile/Cancel, no false success or duplicate business action from delivery failure.

## Phase 8 — Staging E2E, controlled rollout and Legacy retirement (P0 release gate)

**Goal:** demonstrate the new workflow can replace manual Legacy without losing create/renew/service operation after handoff.

**Work:** isolated staging with fake provider/DNS/SQLite, crash injection at every side-effect boundary, real TG Rich smoke with 3 administrators, actual Cloudzy VPS only after cost approval, fresh client test from affected ISP, guarded small first Production cutover under approved maintenance window; verify account CREATE+RENEW, customer connectivity, source/target DNS, default, count and no dangling locks. Keep old Relay online through observation; take exact deployed SHA, backup and independent rollback plan.

**Retirement protocol:** only after written operator acceptance: hide/disable old manual mutation menu in a separately approved reversible change; keep read-only history, source callbacks and data through a deprecation window. **Do not silently delete Legacy code or enable K2.** Rollback must be a guarded new operation, not forced DB/Cloudflare overwrite.

**Exit:** owner-signed independent field acceptance and repeatable incident recovery; no significant open P0; new workflow is primary for purchases and migration; only then approve Legacy UI retirement.

## Dependencies and release gates

```text
P1 Routing snapshot & contracts
  -> P2 Durable lifecycle / recoverability
    -> P3 Cloudzy API
    -> P4 Edge installer + Standby
      -> P5 DNS route Saga
        -> P6 customer batch migration + create/renew
          -> P7 Telegram Rich UI integration
            -> P8 staged Production acceptance / reversible retirement
```

P7 UI renderer can be prototyped **without mutable callbacks** while P2–P6 are built, but never attach automatic execution before guards pass. P8 is not equivalent to GitHub merge. Each phase is separately reviewed, tested, reported and merged; deployment and active production execution are separate explicit approvals.

## Key acceptance matrix (short)

| Scenario | Required state/action | Forbidden |
| --- | --- | --- |
| No stock / changed quote | Persian explanation, choose/refresh; no purchase | silent new price / POST |
| Ambiguous purchase | RECONCILE_REQUIRED and same provider order | second chargeable POST |
| Partial Edge install | inspect/adopt or operator repair | blind setup_edge_relay.sh replay |
| Unexpected hosts order | show actual mismatch and safe route report | manual force DNS/default rewrite |
| Stale QUEUED | classify and reclaim only with fenced lease & preflight | infinite QUEUED/no UI action |
| DNS partial/unknown | preserve 6G fence + authoritative reconciliation | blind DNS retry/rollback |
| 20/50 accounts migrated | durable checkpoint; stop at batch boundary | duplicate CAS or skipped users |
| Telegram timeout | retain operation and retry delivery only | mark workflow failed / re-buy |
| Cancel during provider write | persist request and await reconciliation | instantly release uncertain lock |
| Completed cutover | external ISP connectivity + SSH create/renew verified | DONE from journal count alone |
