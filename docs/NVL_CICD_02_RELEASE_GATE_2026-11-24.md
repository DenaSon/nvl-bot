# NVL CICD-02 — CI release gate

## Scope

This is a source-only change. No deploy timer, production credentials, host
writes, database migration, service restart or feature-flag changes.

The existing Python checks workflow is the canonical release authority.
Pull requests preserve targeted selection (unknown/shared changes run all
tests). Every push to master runs the complete unprivileged and root suites.
Nightly/manual runs also run complete suites, but cannot authorize deployment.
All three prerequisite jobs use the pinned requirements; clean runtime
preflight verifies the exact checkout, compiles tracked Python files and
checks real bot imports in a fresh code-only stage. The existing source
bundle builder verifies its SHA and manifest in the root safety job.
The final **NVL Release Gate** job runs even if a prerequisite fails and
requires each prerequisite to report success.

## Future Core poller contract (CICD-03)

- Read the exact current master SHA via a read-only Git transport.
- Find the canonical workflow `.github/workflows/python-checks.yml` run for
  that SHA, branch master and event push. Require a completed successful run
  and a completed successful job named NVL Release Gate in its latest
  attempt; no success inferred from an empty status list, PR, scheduled run,
  manual run, skipped job or an earlier commit.
- On API failures, pending/failed checks or branch changes, leave production
  intact. Recheck master before cutover and never select a moving ref.
- The gate authorizes source validation only, not activation of feature
  flags, privileged installers or networking operations. Core deployment
  still needs scoped file inventory, backup, compatibility and health checks.
- Polling must back off and respect GitHub rate limits. No secrets are
  needed for reading the public repo; do not embed production credentials.

## Repository settings (owner action if admin API is unavailable)

In Settings > Branches, protect master: require a pull request and passing
status check **NVL Release Gate**, require branches to be up to date,
disable force pushes and deletion. Apply to administrators/bypass roles
where appropriate. Do not require an approval from another person for
a single-maintainer repository. The check must first appear in a successful
workflow run. Path-filtered jobs are not suitable as unconditional required
checks. This document does not assert the setting has been applied.

## Verification

A new PR must pass all applicable checks, and its eventual master push
must independently pass the release gate. No auto-deploy is enabled yet.
