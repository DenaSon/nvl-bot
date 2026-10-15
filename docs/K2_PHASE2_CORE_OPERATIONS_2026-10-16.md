# K2 Phase 2 — Core/Edge egress operations

Date: 2026-10-16 (Asia/Tehran). Branch:
`feature/k2-phase2-operations-20261015`, stacked on Phase 1 / PR #150
at `fc1d9061250fb9aea9b9947852927de22c355ab2`.

**Source implementation and synthetic integration acceptance only.**
No master merge, deployment, SSH session, live flag, PAM/user route change or
field acceptance was performed. The owner's sequence remains Phase 3 UI/UX,
then manual SSH deploy and real Telegram acceptance. Accounts/UIDs stay on Core.

## Existing engine and automatic Edge preparation

The existing root bot composes `CoreOperationalBindings` and on-demand native
observations under an explicit root-owned version-2 profile. Single and Batch
are independently released; absent profile/import defaults are OFF. Original
M42/M3/P3/F2/6G and the original SQLite checkpoint remain authoritative.
No additional bot, daemon, IPC listener, migration ledger or observation poller.

The existing wizard performs final isolated-candidate checks **before** native
activation. Original P1 then starts the pinned dedicated tunnel, proves exact
namespace IPv4 and registers/validates F3 STAGED. It stages the reviewed Core
import closure and installs/verifies the existing dedicated transport oneshot
on Core/Edge. Edge receives only three pinned transport Python files. Conflicting
files/units HOLD; no ExecStop tears down a shared transport. No F4 READY,
legacy pool/default/DNS or customer assignment is manufactured by provisioning.

The Edge installer includes Python/curl/OpenSSH client. Core observation tools
are one-time release-package dependencies, not per-user commands. First/Nth UID
bootstrap reuses the same module staging helper. Shared guard/DNS bundles now
have actual multi-user install targets using the existing V1 guard renderer.
Boot guards restore DENY; persistence never blindly unfences protected users.

## Automatic measurements and trust boundaries

Native operations require **no per-user witness JSON editing/uploading**.
The old separately gated signed-file route remains for historical compatibility.

- One-time root-owned field qualification is SHA-pinned to release/Core and
  records independently performed rescue, PAM, reboot, WG-loss and external
  client tests. It can describe a disposable VPS or owner-controlled Core.
  This is release-time qualification, not a new physical observation per UID.
- Each target still needs exact pinned stages/SSH key/F3 identity, non-revoked
  readiness and a fresh two-sided transport/public-IP observation. Native M1
  records a separate `target_qualification_digest`, leaves F4 acceptance false
  and the DB readiness STAGED. Only the concrete released collector qualifies
  a guarded UID trial. Generic callbacks/UI booleans/legacy paths remain F4-only.
- Source/session review uses current root journal, WG ownership and UID
  processes. Missing/stale source can be refreshed by actual pinned customer
  SSH/SOCKS authentication. Historical host is merely a connection hint:
  failed authentication/WG drift writes no source evidence. PAM/native journal
  writers share a file-CAS lock, not a second migration lease.
- UID_ROUTE follows F2 ROUTED_UNVERIFIED: real UID IPv4, UDP/TCP DNS, NSS,
  IPv6 denial, physical-uplink capture and neighboring-state checks.
- POST_ATTACH follows F2 PROTECTED, under the SAME original 6G/probe-only
  admission: actual public-relay SSH/SOCKS, challenge/scope/operation/IP binding
  and repeated no-leak/neighbor checks. When ingress differs, the client runs
  on a pinned Edge. For same-ingress, Core makes the full PUBLIC Edge-to-Core
  roundtrip because a local Edge connection bypasses PREROUTING DNAT.
  That fallback is **not** an independently located external device; Stage 4
  phone/desktop acceptance remains mandatory.

Capture must attach before probes, finish successfully with zero kernel drops
and show no matched physical-uplink leak. Probe subprocesses use a minimal
environment. Passwords never enter process arguments, Telegram state, results
or logs. Native typed live values are not represented as off-Core signatures.
Read-only transport remeasurement can run under the exact nonce-bound UID
intent; foreign/unknown 6G operations remain blocked.

## Reassignment, group/all and active egress

Unprotected users retain original deferred first/Nth bootstrap. Protected UID
reassignment reuses the original deny-first repin driver inside P3: F2 FROZEN,
UID DENY, manifest/roster/DNS repin, route proof, future-generation PAM policy,
PROTECTED CAS, client proof and original 6G terminal receipt. Observed ingress,
account host and unselected mappings remain intact. Failure retains recovery.

Group/all freezes eligible usernames once and executes original Single
sequentially in bounded waves. Every UID gets fresh review/ticket/receipt.
Confirmation must arrive within TTL; only its consumed exact RUNNING checkpoint
can continue beyond that TTL. Restart cannot replay approval or discover new users.
Busy/unproven/already-target users are explicit inventory skips. Active sessions
are **not forcibly disconnected**. An executing failure is HOLD, not a skip;
following users are DEFERRED. STOP takes effect between UIDs. Repeated task
cancellation retains single-flight ownership until current host work settles.
The existing Telegram poller stays responsive via its existing task mechanism.

Existing active-relay controls enter the guarded all-user flow. The separate
`k2_active_egress_edge` marker commits under P3/6G only when EVERY active SSH
account has target F2/mapping/guard and original verified receipt. An eligible
subset cannot advertise a global switch. Already-target users can confirm the
marker without replaying transfers. This does not move ingress DNS or identities.

## Recovery, validation and next phase

Bot reconciliation closes only the exact actor/chat/selection projection when
original 6G is settled and guards/accounts/receipts agree. It preserves progress,
replays nothing, and permits fresh selection of remaining users after STOP.
An original RUNNING/RECOVERY operation, partial repin, missing guard or UID/receipt
drift stays HOLD: **no blind unlock or repair/replay of ambiguous host changes**.
Phase 3 must present this distinction and useful recovery guidance accurately.

Tests use actual disposable SQLite, P3/6G/checkpoint with synthetic host I/O:
23 sequential UID receipts across approval TTL, protected repin/CAS failure,
failed-user stop, operator STOP, reconciliation, role revocation, cancellation,
marker-only confirmation, source-auth/WG drift, qualification without READY,
nonce/phase/IP/packet rejection, wizard ordering and persistent artifact ownership.
The complete reviewed module closure is imported in an isolated interpreter.
Exact-commit full Python and Python 3.11/3.12 safety results are recorded in the PR.

Next: Phase 3 final minimal Persian UI/UX, per-user skip/recovery presentation,
progress polish, regression, current context and pinned manual deploy/rollback
package. Then Stage 4: manual SSH deploy and real Telegram new Edge → one UID →
small group → all eligible, with external IP/DNS/IPv6, WG-loss/restart/recovery
acceptance. Single must pass before Batch release. CI is not a production IP fix.
