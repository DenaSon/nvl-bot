# CD-06D — Core automatic apply scheduler

Adds a disabled-by-default oneshot service and timer. The root-owned existing
CICD-06-ACCEPTED marker is mandatory; no activation or marker creation here.
On acceptance, disable the existing dry-run timer and enable the apply
timer instead. The observer stays enabled. Both use the existing local
non-blocking release lock; no new application/business lock.

The tick discovers exact master, checks the canonical master push CI and
local inventory, honors the existing API cooldown and skips busy operations.
The publisher independently revalidates the exact master SHA, CI, inventory
and runtime hashes before any mutation. Pending recovery and a rolled-back
candidate are never automatically retried. Only nvlbot.service may be
restarted. Documentation-only releases checkpoint without a restart.

Terminal checkpoints are archived before replacement and transferred to
observer SQLite before deleting archived files. This avoids losing a
release outcome when two releases finish between observer ticks. The
observer still uses its existing retry policy. Checkpoints now distinguish
runtime and non-runtime releases and include timing/count metadata for
future release notes. No PR lookup or enrichment in this phase.

Acceptance gates still open: install and verify the lifecycle contract on
the actual Core, review the inventory (including independently used files),
reconcile the exact baseline, validate stop/rollback behavior, verify the
systemd service sandbox and perform a controlled pilot. Stop timeout for
the subprocess is 120s rather than matching systemd's current 90s. The
1200s service timeout is a last-resort bound, not a promise of atomic
shutdown on forced termination. An interrupted journal requires manual
recovery. No Edge Sync changes, no automatic DB restore, no live activation.
