# CICD — Linkless Telegram changelog

## Release Summary
Keep deployment outcome and health metrics while removing GitHub links and repository identifiers from Telegram release notices.

## Changes
- Collect the actual candidate commit subject locally and show it alongside a bounded changelog.
- Prefer verified PR summary and changes; fall back to commit body when metadata is unavailable.
- Remove generated PR/compare/commit links, repository identifiers and the instruction to visit GitHub.
- Sanitize previously queued notices before delivery. No change to release gates, runtime, database schema or timers.

## Acceptance Tests
- Verify a release notice includes the commit message and available changelog without repository links.
- Verify missing metadata and legacy queued notices do not leak URLs or repository identifiers.

The observer and release-notes modules are control-plane files. Install their exact reviewed blobs manually under the existing release lock after green master CI. They do not self-update. No bot restart is needed for this control-plane-only change. Previously delivered Telegram messages are not modified.
