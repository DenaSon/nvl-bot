# CD-06F — Release notes and operational handoff

For each successful release, publish an advisory summary of the actual
deployed commit range to the existing Telegram admin group. The previous
baseline and new exact SHA define the range. Up to three first-parent
commits are resolved through GitHub's associated PR endpoint; only a unique
merged PR whose merge_commit_sha is the exact commit and whose base is
DenaSon/nvl-bot master is accepted. For incomplete/long/rebased ranges,
missing notes or failed API calls, explicitly show incomplete coverage and
a trusted compare link. No guessing or AI service.

Use only the title and explicit Release Summary, Changes, Acceptance Tests
sections from the PR template. Ignore HTML comments, fenced examples and
technical notes. Plain text, bounded fields, control characters removed,
external URLs and obvious token patterns redacted. Public PR authors must
not include credentials or private customer data. This is not a general
secret scanner. Link destinations are constructed from verified PR numbers
and exact SHA values. Best effort, no release gate dependency, bounded
request timeout (5s per PR, max 3). Metadata is collected before cutover,
saved in the existing durable release checkpoint/outcome, and delivered
using existing observer retry/deduplication, without extra GitHub calls
from the observer.

Runtime success includes recorded file count, elapsed seconds (stage
through health), CI/backup/Polling/DB proof from the committed publisher
outcome. Manager acceptance is explicitly pending, not automatically
passed. Metadata-only checkpoint has no restart or backup claim.
HOLD/ROLLBACK never invite testing the failed candidate. No change to
Edge Sync, network, bot business flows, or Telegram destination.

New trusted module nvl_cd_release_notes.py must be installed alongside the
updated publisher, planner and observer in /opt/nvl-deploy during the
controlled Core bootstrap. No automatic deployment activation yet.
