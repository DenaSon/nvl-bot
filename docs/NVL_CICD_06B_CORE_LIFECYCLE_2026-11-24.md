# CICD-06B — Core lifecycle evidence

Scope: nvlbot.service on Core only. No Edge Sync, Edge, network or customer
routing changes. Existing read-only operation guards remain; no new business
locks. Auto Apply is still disabled.

The existing PTB getUpdates transport emits NVL_CD_POLL_OK at most once per
15 seconds on a successful Bot API response containing a result list, with
no token, payload, extra poll or Telegram message. The existing PTB lifecycle
post_stop awaits registered detached tasks for up to 45 seconds without
cancelling them. Existing post_shutdown cleanup remains, followed by a clean
marker only if the drain succeeded and no tracked or other loop tasks remain.

Publisher requires stable PID/invocation/restart counter for at least 12s,
recent real polling evidence from exact systemd invocation and PID, and DB
quick_check. Polling proof is not a full end-to-end command or business health
test. It validates the active polling path, not all handlers. The existing
rollback baseline must already provide this contract before apply.
Systemd stop must exit normally (not SIGKILL or timeout) and emit a clean
shutdown marker after the stop request. On missing proof publisher records
HOLD without publishing files or automatically issuing a second stop. If the
old process has stopped and proof is missing, inspect journal and operations
and recover explicitly; no automatic DB restoration.

Known limitations/acceptance gates: post_stop happens after PTB has drained
its own updates; existing periodic monitors and external threads may not be
covered by the detached registry. No claim of atomic admission/drain across
all external effects. Need real controlled bootstrap of bot and matching
publisher, verify successful polling and clean shutdown on Core, validate
existing operation journals and graceful stop behavior before permitting
unattended apply. The existing 90s systemd stop deadline may need tuning if
actual drain exceeds it; no systemd policy change in this PR. Edge Sync is
explicitly outside scope; separate standby copies are not guaranteed to
be generation-consistent by this Core-only feature.
