# K2 Phase 1 — existing Core bot Single engine

Date: 2026-10-15. Source branch: `feature/k2-phase1-operational-engine-20261015`,
stacked on PR #148 at `6fc68d42780270043e05c36fe405b05867fbbdb0`.

## Scope and current acceptance

This is the first of the owner's **three development phases**, followed by
one separately performed manual SSH deployment/real Telegram test stage.
Accounts, Linux UIDs and SSHD stay on Core. The selected Edge supplies the
selected UID's Internet egress. No Production deployment or field trial is
performed as part of this source change.

Phase 1 implements Core startup composition, automatic first/Nth UID plans,
deferred prerequisite staging and the Single proof lifecycle. It does not
close the whole product's zero-CLI acceptance. Edge wizard/relay integration,
batch/all-user orchestration and automatic measurement invocation are Phase 2;
final Telegram UI/UX, release packaging and operator recovery are Phase 3.

## Implemented behavior

- The existing bot's `_post_init` invokes `start_core_single_runtime` once.
  This binds its process-private `RootDirectOperatorClient` to the original
  `RootMigrationPortal`, M42, M3, P3, F2 and original 6G SQL/journal.
  No new bot, service, IPC listener or alternate migration engine.
- Missing root profile is OFF. An explicitly enabled, root-owned profile
  first requires the complete reviewed source manifest and matching PAM
  digest. Only the exact Single flags are enabled in memory; Batch remains
  independently OFF. Registration failure restores previous flags. Errors
  leave the existing bot running and log sanitized exception types only.
- `CoreHostSources` supplies fixed real DB/OS/PAM/WG/native guard inspections
  and mandatory independently signed observations. Root policy is derived
  from current existing admin IDs and rechecked against current DB roles;
  HMAC material never enters Telegram/Pickle persistence.
- `CoreUIDSnapshotSource` builds first/Nth M2 plans in memory from the pinned
  target Stage, exact F3 table identity, actual OS UID, existing root roster
  and available rule priorities/DNS listeners. There is no manually written
  per-user `uid-plans/*.json` prerequisite for this route.
- `CoreGuardBootstrap` stages the complete SHA-pinned Python import closure,
  root directories and absent V2 policy **only after** the exact original
  6G intent exists. Existing exact module bundles can be reused. Inconsistent
  bundles, symlinks, orphan guards or policy bytes HOLD without overwrite.
  Existing M2 installer/append functions still perform the guarded host work.
- Module closure checks now include `ops.k2_*`; an empty explicit `ops`
  package is included, and DoH-readable file/directory modes survive a
  restrictive root umask. Critical source manifest pins cover this closure.
- Successful real PAM transactions can record the source journal under the
  enabled profile. Observation failure does not change the independently
  decided login; unproven source remains a transfer HOLD.

## Proof ordering — no circular client requirement

| Stage | Required evidence | What it authorizes |
| --- | --- | --- |
| `PRE_ATTACH` | Fresh signed Edge/F4 acceptance, source/session identity, host boot/WG-loss/rescue and neighbor evidence | Review/approval and guarded bootstrap; never customer egress success |
| `UID_ROUTE` | Exact scope + nonce hash + original operation ID, F2 `ROUTED_UNVERIFIED`, externally observed UID public IPv4, DNS/NSS/IPv6/no-Core-leak and neighbor results | Original P3's guarded per-UID PROTECTED commit |
| `POST_ATTACH` | Same exact operation, F2 `PROTECTED`, real SSH/SOCKS public IP and independent leak/neighbor results | Final original 6G SUCCEEDED receipt and verified operator result |

Old version-1 reports remain readable for historical compatibility. They
cannot verify a new transfer's UID_ROUTE or POST_ATTACH stage. A stale report,
wrong UID/target, previous nonce, completed operation, phase mismatch or
incorrect IP holds the operation. Signatures bind the exact bytes decoded.

After PROTECTED commit, only this concrete Core deferred port can publish
`probe_only` in its **still-RUNNING original 6G intent**. The selected UID can
then authenticate for its real client proof after its usual source/guard
checks. Other protected UIDs keep their own guards. Unknown/legacy/global
6G operations retain the old busy denial; a failed selected UID stays denied
and original 6G remains in RECOVERY. No lock is released to run the probe.

The root profile is read by the separately executed PAM Python process too;
enabling an in-memory bot flag alone cannot enable the installed PAM route.

## Phase 2 integration obligations

1. Reuse this registered engine from the existing new-Edge wizard and active
   relay controls, rather than installing the historical nonroot/IPC worker.
2. Automatically invoke and refresh the independent observation producer and
   publish signed PRE_ATTACH, UID_ROUTE and POST_ATTACH envelopes at their
   correct execution points. **Hand-editing or uploading per-user witness
   JSON is not an accepted product workflow.** The Phase 1 native engine
   consumes the fixed receipt paths and the existing off-Core producer can
   encode/sign all three formats; physical probe execution remains to be
   connected and accepted as part of the operator flow.
3. Handle source observation/reconnect guidance, selected-session drain,
   already-on-target users, protected-user reassignment and safe recovery;
   current new-UID bootstrap must not be misrepresented as arbitrary repeat
   protected-UID relocation. No historical host-field shortcut is allowed.
4. Batch/all reuse Single in bounded sequential waves with original receipts,
   per-user progress and stop-on-error. No implicit batch release here.

## Validation and release boundary

Added tests use real disposable SQLite, original 6G SQL/P3/checkpoint and
M1 plans, an isolated interpreter import of the actual installed module
closure, and synthetic OS/packet fixtures. Cases include startup/revoke,
first/Nth plans, missing lease, source/F3/resource drift, invalid bundles,
wrong phase/nonce/operation, post-commit probe admission, neighbor guards,
failure recovery and default-OFF imports. They are not a physical VPS pass.

Local full-suite execution may skip nonroot off-Core fixtures and cannot
create two historical AF_UNIX listener fixtures in the restricted executor;
GitHub's normal Linux CI is the authoritative full-platform check. Verify
the exact final commit's full Python and Python 3.11/3.12 safety jobs.

No merge to auto-deploying master, live profile enablement, PAM/UID change,
DNS/default switch or real user migration is authorized by this PR. After
Phase 3, deploy manually over SSH and test the entire Telegram workflow on
the agreed host scope before declaring the client IP issue fixed.
