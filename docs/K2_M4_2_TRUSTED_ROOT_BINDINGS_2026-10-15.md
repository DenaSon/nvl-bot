# NVL K2 M4.2 — Trusted Root Evidence and Original-6G Worker Binding

**Source checkpoint:** 2026-10-15 | **Parent:** M4.1 at `cc00ee15491b70142e03ca5b304c37a614840fed` | **Branch:** `feature/k2-m4-telegram-root-portal-20261014` (PR #148, Draft).  
**Safety:** No master merge, no Production changes, no authorized UID movement. These are **source-only root integration adapters**. Do not conflate source/CI with field acceptance or live activation.

## M4.2 delivered code

- `edge_egress_k2_m42_evidence.py`: strict signed external report contract (30s max; exact Edge + public IPv4 + selected UID/source + active session count; complete IPv4/SOCKS, DNS UDP/TCP, NSS, IPv6, no-Core-leak, F4, boot, WG loss, neighbour and rescue check set); detached SHA-256 OpenSSL signature verification against a **root-owned external public key**. No secret signer key is ever stored on Core or in Git. Missing/stale/invalid/mismatched evidence HOLD. The signed report is independent provenance only; physical methodology must be accepted separately.
- `edge_egress_k2_m42_bindings.py`: root-owned admin actor/chat allowlist **plus current role attestation**; M1 inventory rechecks the existing M2 PAM/WireGuard source provider and the independently attested session count for each UID. It binds real `issue_execution_ticket`, `Existing6GGuardedExecutor`, `confirm_original_6g_commit`, original DB checkpoint and strictly same-target-ingress Legacy enrollment. Cross-Edge `UID_ATTACH` with global Legacy mode 0 never gets silently enabled. All call paths remain behind default-off root release gates.
- `edge_egress_k2_m4_bootstrap.py`: a deferred P3 HostPort. It calls the original M2 first-UID/next-UID guarded bootstrap **only after original 6G intent is confirmed**, then builds the real M3 `GuardedVerifiedIngressUIDPort`. Failed/partial staging keeps original P3/6G RUNNING/HOLD with no auto-unlock, no next-UID dispatch and no Core fallback. Explicit resume_partial is forbidden in this path.
- Expanded M4.1 exact source SHA256 pin list to include all M4.2 security modules, original M2 journal/observer and P3 guarded-UID modules.
- Focused unit/security tests: signed witness canonicalization/expiry/forgery, **real OpenSSL detached signature verification** on temporary synthetic fixtures, cross-edge Legacy rejection, impersonated actor, mismatched source/session, F4 DB drift, one-shot P3 ticket, blocked M2 before 6G and retained HOLD on partial bootstrap.

## Explicit integration blockers — do not mark operational M4.2 as deployed

1. The current **production bot service still runs as root**; isolated non-root IPC client UID and role change cannot be assumed safe for the many existing bot-side root functions. Operator-approved, migration-safe identity/service split must be validated separately.
2. Static `ops/k2_m4_root_daemon.py` intentionally exits 78. Root-side `HostReviewedPorts` must be populated with exact **reviewed real** existing 6G acquire/journal, PAM/M2 roster root FilePort, protected-UID kernel safety and live role lookup; no generic shell/Telegram-controlled factory. These callback contracts cannot be passed off as automatically instantiated production integrations.
3. The signing **off-host witness service and private signing key** are not installed, its independent session counting and IPv4/IPv6/DNS/boot/WG-loss measurement method has **not** been physically reviewed, and target e9 is still F3 STAGED, not independently F4 accepted. Never manufacture/synthesize the report to make the system green.
4. The guarded first/Nth UID `port_factory` must be concretely assembled and physically verified in disposable Core/Edge before live `M2_FIRST_UID_ENABLED`, `M2_APPEND_ENABLED`, `M3_VERIFIED_INGRESS_ADAPTER_ENABLED` or root/IPC/portal flags can be released.
5. Telegram two-step PREPARE/CONFIRM/CANCEL, root-owned per-UID wave status after restarts and operator-facing reconcile remain M4.3/M4.4. No customer operator execution button exists.

**Phase bookkeeping:** M4.2 *source contracts and offline tests* can be reviewed/CI-accepted; **live integration + physically attested complete Root Worker** remains HOLD and must not be called an operationally closed phase. Release once all M4.2–M5 gates are independently accepted, with explicit production authorization.

## Acceptance requirements

Exact HEAD GitHub Python syntax/full test suite and Edge staging safety on Python 3.11/3.12 must pass. Label checkpoints distinctly: SOURCE, CI, PR MERGE, DEPLOY, PHYSICAL. No CLI required from regular operators after M7; provider disaster console remains exceptional. Preserve original wg0, 6G/6H, PAM, active SSH, e7 UID1644 and mia1 UID1690 existing fences, DNS/Cloudflare and all 425 accounts.
