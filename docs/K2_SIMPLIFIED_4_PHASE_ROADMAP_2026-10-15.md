# K2 — three development phases, then manual deploy and real acceptance

Date: 2026-10-15. This is the owner's latest delivery plan and supersedes
the earlier four-development-phase and M1–M7 execution orders. M1–M7 code
remains shared implementation; this is a scope consolidation, not a rewrite.

Keep the existing Root-running bot on Core, existing database, SSH identities,
WireGuard entry points and original shared 6G journal. Selected Internet
traffic exits through the assigned Edge IP. A change of outbound egress does
not automatically move an existing inbound SSH connection to a new hostname.

## Phase 1 — Core Single engine

Bind the original P3/F2/6G and checkpoint to the existing bot at startup.
Build first/Nth UID prerequisites automatically, maintain deny-first route
and boot guards, and distinguish Edge readiness, routed UID proof and final
client SSH/SOCKS proof. Preserve every unselected UID and the global Legacy
mode. No daemon, new poller, Unix IPC or parallel migration engine.

Current source implementation:
[K2 Phase 1 Core Single engine](K2_PHASE1_CORE_SINGLE_ENGINE_2026-10-15.md).
Accept source with green exact-commit CI and documented remaining integration;
do not claim real VPS acceptance.

## Phase 2 — Complete Edge and transfer operations

Source implementation: [Phase 2 Core operations](K2_PHASE2_CORE_OPERATIONS_2026-10-16.md).
Native observations, existing wizard/transport persistence, protected repin,
group/all, active-egress marker and settled-cohort reconciliation are connected.
Source tests use synthetic host I/O; no deploy or real client acceptance yet.
Unknown original 6G recovery remains fail-closed, never an automatic unlock.

- Existing new-Edge wizard provisions/stages/activates the pinned tunnel and
  required host prerequisites automatically.
- Existing active-relay control uses the guarded data plane and verified
  results; default/DNS metadata alone cannot claim a changed client IP.
- Automatically invoke/refresh independent PRE_ATTACH, UID_ROUTE and
  POST_ATTACH observations at their engine stages. No per-user receipt-file
  editing, root command, manual guard/rule or policy preparation.
- Complete source/session handling, protected-UID reassignment and safe
  operation retry/reconciliation using the same original engine.
- Selected group or all eligible users are inventoried and executed
  sequentially in bounded waves; preserve per-user receipts, progress,
  explicit skipped/blocked users and stop on uncertainty. The operator
  must not manually re-enter ten usernames for each all-user wave.
- Batch release remains independent from initial Single release.

Acceptance: all scoped backend operations are connected and exercised by
integration/failure tests; no missing-function HOLD may masquerade as success.

## Phase 3 — Telegram UI/UX and release preparation

Source implementation: [Phase 3 Telegram UI/UX](K2_PHASE3_TELEGRAM_UX_2026-10-16.md).
Programs → Manage output, concise tips, complete account detail pages,
responsive review/prepare/execute, progress/STOP and original-root status are
connected. [Source packaging/manual release and rollback](K2_PHASE3_MANUAL_RELEASE_2026-10-16.md)
is prepared. Exact-commit CI is recorded in the PR. No production/field
acceptance is implied; manual SSH deploy and real tests are the next stage.

Two-column minimal Persian flow: select Edge, Single/group/all, fresh review,
confirm/cancel, progress/results, diagnostic guidance and scoped recovery.
Complete existing handler bindings, legacy compatibility, regression checks,
current agent context, pinned release manifest and deploy/rollback package.

Acceptance: the complete developer build and UI are ready for one controlled
manual SSH deployment; every ordinary operator action is in the bot.

## Stage 4 — Manual SSH deploy, then real Telegram acceptance

Only after development and related UI/UX are complete, deploy over SSH with
the operator, as before. Test in order: new Edge, one explicit UID, a small
group, all eligible users. Independently observe the exact Edge public IP
from actual SSH/SOCKS clients; verify DNS/IPv6/no-Core-leak, neighboring users,
WG loss, restart and safe recovery. Single failure returns to repair of the
same engine; group/all release requires successful Single acceptance.

No code-only CI result authorizes production mutation or proves that the
client IP issue is fixed. No new product features are added to this scope.
