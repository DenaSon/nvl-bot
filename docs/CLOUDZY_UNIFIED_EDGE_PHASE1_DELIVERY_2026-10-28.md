# Cloudzy unified Edge refactor — Phase 1 delivery

**Date:** 2026-10-28  
**Scope:** existing Programs → Cloudzy | Edge & Relay. This phase supplies a read-only shared diagnostic **for that existing panel**, not a new panel or separate callback.  
**Status:** source implementation; test/merge/deploy status must be read from corresponding GitHub PR and runtime verification.  
**Authority:** [design](CLOUDZY_UNIFIED_EDGE_LIFECYCLE_DESIGN_2026-10-28.md) and [8-phase roadmap](CLOUDZY_UNIFIED_EDGE_REFACTOR_ROADMAP_2026-10-28.md).

## Changes

- New module \`cloudzy_route_snapshot.py\`: \`inspect_route(sqlite_connection)\` returns immutable, structured \`RouteSnapshot\`, \`RouteIssue\` records with Persian title/cause/action, and predicted Legacy sale gate code.
- Read-only observations: \`settings.hosts\`, cached \`dns_current_ip\`, \`core_wg_public_ip\`, full \`host_pool\` role inventory, **potentially eligible by role only** non-Core/non-Standby active Edge list, active SSH user counts per recorded \`host\`. Active SSH SQL predicate is deliberately identical to the current CZ04B \`status LIKE '%فعال%' AND status NOT LIKE '%غیر%'\` rule.
- Explicitly distinguishes default not eligible, multiple defaults, missing Core, wrong first Legacy host, cached-DNS mismatch, Standby/Core in Legacy hosts, missing/duplicate hosts and active-user assignment drift.
- \`sale_gate_code\` is a **read-only diagnostic projection** of current \`_default_customer_relay_checked\`; it does not execute that function, authorize account creation or change existing purchasing flow.
- Persian \`format_route_report(snapshot)\` produces a transport-neutral, safe diagnostic string. Its Telegram presentation is reserved for the future **Rich-only** phase; no HTML fallback UI, duplicate admin menu or Telegram callback is introduced in Phase 1.
- CLI: \`python3 -m cloudzy_route_snapshot --db /root/master_bot.db\` uses SQLite \`mode=ro\`, \`query_only=ON\` and a consistent read transaction; exits 0 when no local ERROR, 1 when anomalies exist, 2 on missing supported SQLite schema.
- No import/use of Cloudflare or Cloudzy API, no ssh/socket/Telgram network, no inserts/updates/transaction lease, no restart side effect. No live DNS or provider health is claimed.

## Audit baseline that Phase 1 reproduces

Owner Core snapshot 2026-10-28 11:13 UTC:
- one active non-Standby Default 45.59.113.249 and cached DNS 45.59.113.249.
- \`settings.hosts\` starts at 144.172.69.2, ends with 45.59.113.249.
- 488 active SSH accounts recorded at 45.59.113.249; 478 disabled historical rows excluded.
- projected \`DEFAULT_CUSTOMER_RELAY_ROUTE_MISMATCH\`; diagnostic \`LEGACY_HOSTS_ORDER_MISMATCH\`. A Standby also appears in the Legacy list.
- Four prior \`DEFAULT_CUSTOMER_RELAY_NOT_ELIGIBLE\` warnings occurred earlier in the day. Their historical cause **cannot** be attributed to the later mismatch from this snapshot alone.
- Observed older CZ07 metadata migration done to 144.172.69.2, later manual switch not journaled in CZ07; no active shared 6G lock in this snapshot.
- Current \`/root/nvl-release\` checkout is not the runtime \`/root/bot_final_v49-2.py\`: a file expected at \`/root/nvl-release/bot_final_v49-2.py\` was absent; never overwrite or deploy bot code based on that checkout SHA alone.

## Stage-only regression and safety gates

Test module \`tests/test_cloudzy_route_snapshot.py\` covers:
1. correct single default / no drift, exact active account status filter.
2. 2026-10-28 488-user default-last fixture, Standby/unknown host warning and exact split codes.
3. inactive/Standby/Core default, missing Core, no/multiple defaults.
4. cached DNS mismatch, empty/duplicate hosts and active users at unexpected or blank IPs.
5. SQLite authorizer denies INSERT/UPDATE/DELETE/CREATE/DROP while the inspector runs.
6. incomplete schema fails closed; CLI on a disk fixture remains byte-identical.

No code is wired to execute on startup, billing, live sale/renew, CZ03/04/07 state transition or existing Telegram callback. All existing tests/CI required before merge.

## Optional direct Core read-only smoke after code-only staging

A source-only master merge does not require a production restart and will not fix current sales/renewals. **No deploy is needed for the current bot to remain unchanged**. To inspect current DB with the new CLI, copy **only** \`cloudzy_route_snapshot.py\` from a verified pinned commit into a non-runtime, temporary staging directory and run:

\`\`\`bash
# Set this to the exact merged master commit after PR acceptance.
RELEASE_SHA='<PINNED_MERGED_MASTER_SHA>'
STAGE="$(mktemp -d /root/nvl-route-p1.XXXXXX)"
git -C /root/nvl-release fetch origin "$RELEASE_SHA" &&
git -C /root/nvl-release show "$RELEASE_SHA:cloudzy_route_snapshot.py" > "$STAGE/cloudzy_route_snapshot.py" &&
PYTHONPATH="$STAGE" python3 -m cloudzy_route_snapshot --db /root/master_bot.db
# Exit 1 is expected when local routing drift is detected.
\`\`\`

This runs **no** paid API, DNS, SSH, user-update or bot restart. An actual production code deploy for Phase 1 is optional because this module is not imported by the running app; future Rich UI integration and guarded behavior changes are separate phases.

## Future phases and boundaries

P2 durable journal/recovery, P3 Cloudzy API, P4 installer, P5 DNS Saga, P6 migration/CREATE/RENEW acceptance, P7 **Telegram Rich-only** admin display, P8 live acceptance/Legacy retirement. Do not treat an all-green route snapshot as network availability, ISP external E2E or authorization to mutate DNS.
