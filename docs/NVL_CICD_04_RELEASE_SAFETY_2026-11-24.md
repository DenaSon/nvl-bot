# CICD-04 — code publication and rollback

Source-only. The existing timer remains a dry-run planner. No installer,
acceptance marker, or apply timer is shipped. The explicit publisher refuses
to run without a root-owned operator acceptance marker; do not create it
before CICD-06. Branch protection, verified baseline and runtime inventory,
a real quiescence/drain contract and application-level readiness are required.
The current pre/post-stop journal checks do not eliminate the race between
last check and stopping the bot, and process stability alone does not prove
Telegram/application health. These are activation blockers, not claims of
completed production safety.

## Transaction

- Explicit exact master SHA, fresh canonical push-only CI gate, ancestor
  proof, current runtime hash and explicit file inventory. Never trust a
  saved dry-run plan. Newly added root Python files are eligible only if
  explicitly listed and the path is genuinely absent. No deletions, changes
  to dependencies, shell, ops, services, or unreviewed files.
- Private local backup under /var/backups/nvl: original changed code, staged
  bytes, verified manifest and SQLite online backup with integrity check.
  Backup stays on Core; encrypted off-host snapshot/retention are separate.
- Durable release-state.json and atomic per-file publication while only
  nvlbot is stopped. No write to SQLite, environment, networking or other
  service units by publisher. Existing shared lease and job checks are
  read-only; no new application locks or auto-clearing old HOLD.
- Start bot, verify stable PID/restart counter, DB quick_check, schema
  fingerprint. Only then record the deployed SHA. A docs-only plan needs
  no service restart or database backup.
- On failure recover verified previous code if runtime hashes and schema
  still match and existing operations permit. Never restore database
  automatically. If schema changed, foreign changes exist, or recovery
  fails, preserve evidence and HOLD. Schema equality alone is not proof
  of semantic backward compatibility; owner must approve compatibility
  policy in acceptance. No automatic retry of a failed candidate.
- Explicit recovery after interrupted transaction; no automatic resume
  from stale planner output. Reconcile state and service before retrying.

## Next steps

CICD-05: bounded local history, deduplicated notifications, backup retention.
CICD-06: exact production inventory and bootstrap, deployment drain/health
contract, tested rollback and interruption drill, activation policy, branch
protection, real controlled rollout. No production changes in this PR.
