# CICD-06H — Production acceptance record

Date: 2026-11-24 UTC
Scope: NVL Core-only automatic deployment. No Edge Sync or network changes.
Evidence: operator-supplied SSH outputs and actual Telegram notifications.
Accepted production commit: `b0d333a10d1d6aea13d81f3622dcdb7ff36a02ab`.

## Acceptance evidence

- PR #347, publisher/recovery hardening, merged at `d6f9d2373729a9088aee2008ff88ff231f346245`; master push CI passed.
- Exact three control-plane modules and apply service installed and verified. Effective ProtectHome=false; ProtectSystem=strict, NoNewPrivileges, PrivateTmp and explicit writable paths retained. Actual atomic runtime write probe succeeded without changing bot PID.
- The historical failed candidate `a4ba038992fb52740c38e31517c3713004f9b61c` was recovered via the official publisher. ROLLED_BACK, old runtime hash and schema verified; polling resumed. No database restore.
- First real runtime publication: `d6f9d2373729a9088aee2008ff88ff231f346245` COMMITTED. One file (radar_ui.py, acceptance witness comment only), hash verified, controlled restart, database and polling checks passed. Publisher reported 26 seconds; apply service ran approximately 43 seconds. Bot PID changed from 2565110 to 2567468; NRestarts=0. Observer sent actual success notice.
- Apply timer enabled; dry-run plan timer disabled; observer timer remains active. Timer cadence: OnBootSec=120s, OnUnitInactiveSec=60s, AccuracySec=5s. The planner's 300-second API cooldown remained intact.
- PR #348 linkless Telegram notices: merged at `b0d333a10d1d6aea13d81f3622dcdb7ff36a02ab`, master push CI passed (run 45434319096). Observer and release-notes modules manually installed and hashes verified; no bot restart.
- Scheduled apply independently registered b0d333a1, phase COMMITTED, file_count=0, restart_required=false, previous_deployed=d6f9d23. Checkpoint finished at 2026-11-24T16:22:41.000Z. Actual Telegram notification showed commit subject and changelog without repository URLs.
- From 16:24:43 to 16:28:48 UTC, five consecutive apply executions returned NO_NEW_COMMIT. Final plan baseline and candidate both b0d333a1, drift=[], manual=[], updates=[].
- Observer idle, pending=0, throughout the supplied post-release sample. Final bot ActiveState=active, MainPID=2567468, NRestarts=0.

## Production operating contract

Master push -> canonical successful CI -> planner/inventory/drift checks -> release revalidation -> backup and write preflight for runtime changes -> clean stop/publish/start/readiness -> durable outcome -> Telegram observer. Documentation-only or reconciled control-plane-only releases require no bot restart.

Only reviewed inventory files can be automatically published. Control-plane modules and the allowlisted apply unit must first be installed manually and reconciled to exact candidate blobs. Other changes, local drift, incomplete checkpoints and failed CI fail closed. Never manually advance release-state.json or clear API cooldown to force deployment. No automatic database restore.

For temporary network failure, preserve the last committed version; diagnose transport and allow the next scheduled retry. A plan-level HOLD is not a release-level RECOVERY_REQUIRED. For incomplete release checkpoints use the official publisher recovery only after manifest/runtime/schema/idle validation. Disable automatic apply if operational intervention is necessary; verify health and checkpoint before re-enabling. Keep observer enabled unless maintenance specifically requires otherwise.

## Known limitations / follow-up

- Live application behavior beyond the supplied polling and database health evidence has not been independently verified. Manager smoke tests remain separate from automated checks.
- The new notification removes generated GitHub links and repository address references. The actual merge subject still contains the owner/branch label, not a URL; removing that label would be a separate presentation change.
- The transient Git transport exit 128 cleared without configuration changes; exact root cause not proven. API_BACKOFF was expected local cooldown, not a GitHub rate limit incident.
- Unrelated existing systemd warnings (nobody users and executable edge sync unit files) are outside this acceptance scope.

Status: Core auto-apply operational acceptance PASS. This documentation-only record does not itself require runtime changes.
