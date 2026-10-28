# NVL Cloudzy unified Edge refactor — Phase 3 delivery

**Date:** 2026-10-28. **Scope:** existing Programs → Cloudzy | Edge & Relay CZ03/CZ05/CZ06 purchase path. **Deploy state:** Not deployed by creating this document. PR CI and merge SHA must be verified independently.

Design: [canonical lifecycle](CLOUDZY_UNIFIED_EDGE_LIFECYCLE_DESIGN_2026-10-28.md) and [8-phase plan](CLOUDZY_UNIFIED_EDGE_REFACTOR_ROADMAP_2026-10-28.md). Phase 1/2 were merged in source but were **not** deployed by the operator as of this work.

## Delivered in source

1. cloudzy_purchase_guard.py: pure classified purchase/read errors with Persian titles + safe follow-up; exact provider-ID/unique operation-hostname reconciliation; optional base-hourly price ceiling; read-only, no-charge CLI.
2. Existing cloudzy_quick_edge.py: after durable receipt reservation, classify GET preflight HTTP 401/403/429/5xx distinctly from catalog stale/price/stock; at most one additional read-only GET attempt on transient transport failures; no retry of paid POST. Preserve historic CZ05 stock rejection reason for backwards compatibility. Handle pre-purchase Telegram delivery separately from receipt. Reconcile only uniquely identified existing Cloudzy server; never trust a reused IPv4.
3. cloudzy_service.py: a 409 response to POST /services is ambiguous and requires reconciliation, preserving the original Idempotency-Key. HTTP 5xx/transport uncertainty remains no-retry. One-shot approval/nonce and provider POST are still in the existing CZ03 purchase workflow; no second buying engine.
4. Optional operational base price ceiling NVL_CLOUDZY_MAX_BASE_HOURLY_CENTS (e.g. 5) enforces **catalog base cents/hour only**, before reservation and again before provider POST; absent setting retains old priced flow. This is **NOT a verified all-in price cap**. Exact IPv4/surcharge/final quote cannot be proved from the current general catalog; operator still sees this limitation at confirmation. Do not claim all-in purchase ceiling, nor set a made-up limit.
5. No new Telegram view, fallback HTML UI, database migration, new paid endpoint, automatic DNS/6G cutover, SSH-user migration or hidden VPS purchase.

## Live-safe test on Core — no code activation, no restart

Run from root after the source PR merges and capture its exact **merged commit SHA**. The checkout in /root/nvl-release is a git mirror and historically **does not contain** bot_final_v49-2.py; never blindly copy the full checkout into /root. Stage exact module versions separately. Example:

\`\`\`bash
set -euo pipefail
PIN='<EXACT_MERGED_SHA>'
REPO='/root/nvl-release'
STAGE="$(mktemp -d /root/nvl-p3-audit.XXXXXX)"
git -C "$REPO" fetch --no-tags origin master
git -C "$REPO" cat-file -e "$PIN^{commit}"
for f in cloudzy_purchase_guard.py cloudzy_service.py cloudzy_cz05_catalog.py; do
  git -C "$REPO" show "$PIN:$f" > "$STAGE/$f"
done
PYTHONPATH="$STAGE" python3 -m py_compile "$STAGE"/*.py
PYTHONPATH="$STAGE" python3 -m cloudzy_purchase_guard --db /root/master_bot.db
\`\`\`

To test the **real Cloudzy API through GET only**, use a fresh shell and provide the existing Cloudzy Developer API v1 **dashboard Bearer token** securely via hidden prompt (do not paste it in chat/history or log it):

\`\`\`bash
read -r -s -p 'Cloudzy dashboard API token (hidden): ' CLOUDZY_TOKEN
echo
export CLOUDZY_TOKEN
PYTHONPATH="$STAGE" python3 -m cloudzy_purchase_guard \
  --db /root/master_bot.db --live-read --region DE-Frankfurt
RESULT=$?
unset CLOUDZY_TOKEN
echo "P3_PROVIDER_READ_EXIT=$RESULT"
\`\`\`

- Exit 0: read-only inspection passed and, if relevant, uniquely matched an existing Cloudzy VPS or correctly skipped a pre-purchase rejected receipt.
- Exit 1: exact provider identity could **not** be established (including a missing VPS; not authorization to re-buy).
- Exit 2: missing API token or unreadable DB/API/stock response. No purchase has occurred.
- The script only uses GET inventory/catalog/availability and SQLite mode=ro. For errors, do not attempt a purchase as a “test”.

## Optional guarded live bot rollout (separate approval/check)

Only after verifying the exact deployed runtime source matches the **pre-Phase-3 master** for every changed Python file, back up originals, validate imports and syntax, and perform a controlled restart. In case of mismatch, abort and investigate; **never** blindly replace the entire /root deployment. This phase does not require a restart for staging read-only audit.

Exact new runtime import: cloudzy_purchase_guard.py. Existing modified runtime files: cloudzy_service.py, cloudzy_quick_edge.py. Do **not** copy bot_final_v49-2.py, reset SQLite schema, modify any 6G/CZ07 journal or trigger VPS creation. Follow the current verified deployment pipeline and service rollback plan.

## Known limits and next gates

- Phase 3 does **not** implement a guaranteed total-price authorization across IPv4 fees. If the backend adds a trusted final quote endpoint, enforce an all-in cap before enabling no-confirmation buying; until then the original manual confirmation discloses uncertainty.
- Existing provider GET response may be paginated; if exact server is not in the current result, leave it uncertain; do not turn absence into certainty. A 409 is now uncertain by design.
- Phase 2 coordinator does **not** automatically fence existing CZ03/06 background tasks. The stable old CZ03 ledger and single-flight guard are still essential.
- New admin Rich-only 10.3 timeline/cancel will be integrated in Phase 7; no second panel or HTML fallback introduced here.
- The full process is not E2E until P4 installer, P5 DNS, P6 batch migration and SSH CREATE + RENEW, P7 UX and P8 live-client field acceptance.
