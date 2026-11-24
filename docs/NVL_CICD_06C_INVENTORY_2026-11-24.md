# CD-06C — Core runtime inventory review

The existing two-module pilot inventory is deliberately not automatically
expanded. nvl_cd_inventory.py reviews the exact Git commit in the already
fetched private bare repo, traverses statically resolvable imports from the
bot entrypoint without executing candidate code, and reports matching,
missing and drifted files. The independent AWG entrypoints and local
network sampler imports are separated, as are package files and unclassified
root modules. No config or runtime writes; no network calls.

Static imports are not a complete dependency or safety proof: dynamic
dispatch, subprocesses, shell scripts, optional features, cron and external
services may share files. Review every candidate and the actual Core
service inventory before explicitly enrolling files. Changes to dependency
versions, ops, systemd, packages and unapproved paths still HOLD. This
policy is Core-only; Edge Sync is not modified.

The CD-06B lifecycle module and entrypoint need a controlled bootstrap
before the newer publisher can verify readiness of the rollback baseline.
Do not mark the new master deployed before the actual files are installed
and verified. Do not create the operator acceptance marker yet.

The PR template also introduces Release Summary, Changes and Acceptance Tests
for the upcoming CD-06F observer enrichment. No automatic notification
enrichment is enabled by this PR.
