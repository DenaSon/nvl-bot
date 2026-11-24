# CICD-03 — NVL release planner

Source-only and dry-run only. Service and timer examples are not enabled.
No apply command exists. No writes to /root, SQLite, environment files,
networking, systemd units or customer data. No candidate code execution.

## Runtime layout (for later acceptance)

- /opt/nvl-deploy/nvl_cd_planner.py: independently installed trusted planner
- /etc/nvl-deploy/config.json: root-owned JSON with exact baseline SHA
  (baseline key) and explicit approved root Python filenames (inventory list).
- /var/lib/nvl-deploy/repository.git: dedicated root-owned bare Git repository
  pre-populated with baseline objects; no local hooks or custom config.
- /var/lib/nvl-deploy/latest-plan.json: most recent observation, never apply authority
- /var/lib/nvl-deploy/api-cooldown.json: persistent API polling budget

Do not derive the inventory from all tracked files. Privileged infrastructure
modules are not automatically approved. Baseline must be an ancestor of the
candidate and each managed file must match actual runtime. Previously audited
source hashes do not prove today's master was deployed; specifically the
repository-only nvl_awg_witness_refresh.py logging change requires reconciliation.

Poll Git remote master every approximately 60 seconds. On a new SHA, verify
canonical workflow, push event, branch, latest run and attempt, successful
completion and all four required checks. Fetch into a private bare repo with
object fsck, recheck master SHA and ancestry, compare Git blobs with live bytes.
No checkout or candidate execution. Hold unapproved changes, removals, mode
changes, dependencies, CI changes and ops changes for separate review.
Docs/tests-only changes are no-restart plans. This first scope intentionally
does not auto-admit new Python files; extend inventory safely in CICD-04.

The API cooldown is five minutes even on failure: normally at most 24 requests
per hour; shared public IP rate limits can still cause a HOLD. Polling never
changes deployed baseline. Revalidate CI, remote SHA, hashes, and operation
state at actual cutover in CICD-04. A stale plan must never authorize apply.
Implement transactional publication, backups, interrupted-release recovery,
health and code rollback before activation. Branch protection remains an
owner setting prerequisite. No production install or deploy in this PR.
