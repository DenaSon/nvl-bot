# NVL: Force cancel of stranded Manual Edge / Quick Switch operations

## Incident evidence (2026-11-02, operator READ-ONLY snapshot)
- A different administrator has a DRAFT with no IP, blocking their next registration via `ACTIVE_MANUAL_OPERATION_EXISTS`.
- Another manual Edge has an `INSTALL_HOLD` at `45.61.178.99`; this is NOT a current owner intake lock but is eligible for explicit force-closing after inspection.
- One Quick Switch `HOLD`, source `172.86.66.113`, target `45.61.158.55`, is attached to original failover lease 255, marked `DB_COMMIT_REVIEW_REQUIRED`.
- Independent snapshot: `hosts=172.86.66.113` and active/default `172.86.66.113`, yet `dns_current_ip=153.75.87.158`; 449 active SSH accounts seen on source, while failed job's older snapshot included 558 accounts. **Those snapshots do not establish current public Cloudflare state, or that a transfer completed.**
- Do not assume the HOLD caused the DRAFT lock, or that the two are the same owner's operation.

## Explicit operator override behavior
1. In **مدیریت سرورها**, a DRAFT/IDENTITY_PENDING/HOSTKEY_PENDING/READY_INSTALL/INSTALL_HOLD/HOLD registration shows **لغو اجباری پرونده**. INSTALLING also offers it, but the original installer OS flock and same-process running-task guard must be free, or it stops. After independent confirmation (180-second one-use nonce), update *only this owner's* manual operation to CANCELLED, append a durable event; do not modify host_pool, VPS, WireGuard, SSH accounts, settings, DNS, other administrators' operations, or any route job.
2. In Quick Switch **وضعیت انتقال**, only a `QUICK/HOLD` job owned by the current authenticated private-chat administrator may be force aborted. The action is an explicit two-step confirmation with a one-use nonce. An atomic SQLite transaction changes only that job to `ABORTED`, sets reason `ADMIN_FORCE_ABORT_UNRECONCILED`, appends audit event and marks **only its exact owned** `RUNNING` original 6G lease `ABORTED`. Reject mismatched lease IDs, source/target, actor or component. Background worker in same process is serialized via existing effect_lock; intermediate `DNS_INTENT`, `DB_COMMITTED` and terminal `DONE` cannot be force aborted.
3. An ABORTED record is not a DONE. The action never retries Cloudflare, moves SSH accounts, changes host_pool or rewrites `hosts`/`dns_current_ip`; any existing mismatch must be investigated independently before a fresh Quick Switch.

## Release constraints
- Validate on pinned GitHub head; tests use fake Cloudflare and independent SQLite fixtures; no remote effects.
- Before production deployment, compare actual live module versions, stage required modules together, back up files + SQLite, and verify no actively running jobs or parallel installers.
- The previous HOLD and its lease are preserved until an administrator explicitly uses the new force-abort button. Do not auto-migrate or clear them as part of deployment.
- In incident recovery, inspect actual Cloudflare DNS, host_pool, live SSH roster and settings separately. Do not declare success based on job cancellation.
