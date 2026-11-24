# CICD-06G — Publisher and recovery hardening

## Incident, 2026-11-24 (Core)
The first real apply reached a clean bot shutdown, but the release and its
recovery ended in HOLD. The verified manifest, old radar_ui.py and SQLite
schema remained intact; the bot was manually started. A matching transient
systemd sandbox reproduced EROFS on /root, while the deployment and backup
paths were writable. Changing ProtectHome to false in that sandbox made
all three probes pass. The original exception was not logged, so the
historical exception itself cannot be independently recovered.

## Changes
- The apply unit retains ProtectSystem=strict, the explicit writable paths,
  PrivateTmp and NoNewPrivileges, with ProtectHome=false for /root.
- The publisher tests actual atomic create/replace and cleanup in the runtime
  and existing bytecode directory before STOPPING; a failed test defers
  publication without stopping the bot. Rollback requiring writes also tests
  writability before stopping an active bot.
- Failures emit NVL_CD_FAILURE on stderr with phase, exception class, numeric
  errno/return code where applicable, internal Hold code and source location.
  No raw exception text, subprocess output, arguments, locals or secrets are
  logged. Original and recovery failures are separate events.
- If PUBLISHING failed and every changed file is verified OLD, a confirmed
  inactive/dead bot may resume the baseline without rewriting it or sending a
  second stop. Active or ambiguous generations and legacy HOLD without a
  failure phase do not use this shortcut. Schema, operational-idle and polling
  checks remain mandatory; live SQLite is never restored.
- A new HOLD preserves failure_phase for explicit recovery and audit.

## Production acceptance
Keep apply and plan timers disabled; observer may continue. Check the effective
unit and reproduce the write probe before any real deploy. Install exact
trusted control-plane blobs from the accepted master (they do not self-update).
Review the existing HOLD and manifest; use the explicit recovery path only after
operator approval and verified runtime/schema/idle/readiness. Legacy HOLD may
require a controlled restart. Do not edit checkpoint JSON or restore SQLite.
A rolled-back candidate is not retried automatically; a new reviewed master
with green CI is required. Verify a real COMMITTED release, polling evidence,
DB health, and runtime hashes before enabling the apply timer.
