# K2 — Four-phase Core/Edge traffic transfer (replacement execution plan)

Date: 2026-10-15. Approved scope: keep the current **single Root-running
`bot_final_v49-2.py` on Core**, existing Edge SSH/WireGuard entry points,
per-UID protected egress, original shared 6G journal and existing database.
No additional Telegram poller, root daemon, Unix IPC, microservice,
global default route/Edge switching, or blanket account migration.

## Exact service promise

Core continues to own SSH identities, users and session control. Edge is
the SSH entry gateway and **the client-observed internet egress public IP**
for users assigned to that Edge. On an active source SSH session, changing
the per-UID internet egress is not the same as changing the client-facing
Edge hostname/IP: existing inbound connections remain on their old Edge
until the client reconnects through the chosen new Edge. Explicitly verify
both addresses, not only the outbound local routing table.

## Phase 1 — Reconnect to the existing Root bot

- Reuse `RootMigrationPortal`, original M3/P3/6G and M4 checkpoint.
  Replace the new nonroot Unix client in the **existing** `hpeg_m4_*`
  Telegram callback handler with a same-process, explicitly registered
  `RootDirectOperatorClient`. It is not a new migration engine.
- Root-only registration is process-private; never put signed authorizations,
  root HMAC key, prepared privileged port or the migration client object
  in `context.user_data` or persistent `application.bot_data`.
- Root portal performs the same role recheck; prepare → opaque one-shot
  approval → consume-before-execute; error/crash requires manual 6G
  reconciliation. No extra lock, user role, daemon or systemd change.
- Status/preview remains read-only until a vetted physical factory
  is supplied and the default-OFF root-direct release is explicitly accepted.
- **Acceptance:** original single bot handler addresses only the process-
  private client, tests prove real `RootMigrationPortal`→original
  `Existing6GGuardedExecutor`→durable SQLite 6G and checkpoint; negative
  tests for foreign actor, replay, cancel, missing process registration,
  synthetic failure and unchanged execution switch defaults.
- **Status:** implemented at source/test level. Real root portal registration
  is deliberately not bootstrapped before independent M2/F4 host gates
  are implemented and verified in Phase 2. Not yet deployable for transfers.

## Phase 2 — Real Single transfer

- Implement the fixed, reviewed **Core-local Root portal startup composition**
  from existing DB, Linux UID, original admin role, M1 PAM+wg0 ingress
  reader, M2 first/Nth root plan, original 6G callbacks, F2 UID CAS and
  P3 physical kernel. Do not synthesize callbacks or accept Telegram-supplied
  source, root plan or readiness booleans.
- Correct any **circular F4 proof requirement**: pre-attach evidence may
  attest Edge readiness, independent rescue, source/session identity and
  neighbor isolation, but proof that a specific client exits from the new
  Edge must be collected **after** attaching that UID, before marking it
  verified. Never accept local-only curl/DB state as final packet witness.
- Execute one canary UID with blackhole/deny-first and no Core fallback.
  Existing inbound SSH and other UIDs are unchanged; client routing to the
  desired Edge entry is verified separately.
- **Acceptance:** single integrated Root Telegram command plus original
  P3/F2 and 6G, verified in a disposable host with external independent
  client-IP/DNS/IPv6/WG-loss/neighbor evidence. No customer migration.

## Phase 3 — Batch reuses Single

- Only after passing Single: enable at most ten explicitly chosen accounts
  per operator approval; sequentially invoke the identical Single executor,
  with a separate original 6G lease/receipt and durable checkpoint for each.
- Stop on first error/uncertain state/expired approval. No automatic retry,
  global route changes, or parallel migrations.
- **Acceptance:** hermetic 1st/3rd UID failure injection, exact ordering,
  correct partial progress, only selected UID changed and manual recovery
  before any restart.

## Phase 4 — Telegram polish and real disposable VPS acceptance

- Finalize two-column wizard (select Edge, single or batch, root-side
  fresh check, preview, confirm/cancel, progress/status).
- Deploy only to a disposable Core/Edge lab under a separately approved
  canary protocol. Confirm SSH ingress, client-observed egress equals assigned
  Edge, no IPv6/DNS/Core leaks, existing neighbors unaffected, WG loss and
  restart remain fail-closed; verify batch only after Single.
- Document proof and operator recovery and explicitly approve production
  when all above PASS; otherwise HOLD. Keep all changes within the four
  phases; no new product feature or second bot.

**Invariant throughout:** no Merge, production flag activation, global
default Edge/DNS change or live UID migration based solely on CI. The
separate historical root-worker/IPC code in PR #148 remains source-only
and must not be wired into the simplified execution path; retirement only
after code references and release validation are reviewed.
