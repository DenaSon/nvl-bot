# K2 Phase 2 — Manual Protected Relay Cutover (2026-10-14)

Scope: PR #120 feature branch ONLY, no `master`/Production merge. This
reuses the existing J positive 6G protected handoff and K real host driver.
It does **not** turn Legacy `hpdef_` or emergency 6H into an Egress worker.

## Telegram operator workflow

`🛡 مدیریت سرورها → Edge → 🔀 تغییر مسیر ترافیک`:

1. A read-only all-active-SSH cohort review checks the actual current default
   host, `dns_current_ip`, all protected OS UID/runtime/binding identities,
   F3 STAGED allocation, fresh external F4 production acceptance, root-owned
   original Stage pin, matching new-Edge **customer service port**, trusted
   ingress H registry, target standby/unlisted identity and absence of a
   RUNNING 6G operation.
2. On a fully accepted cohort, `✅ بررسی نهایی انتقال` performs **read-only**
   exact Cloudflare A/AAAA source and record identity checks (not a cutover),
   and issues a random, 90-second, admin/chat/Edge/cohort/DNS-bound ticket.
3. `✅ انتقال محافظت‌شده` consumes the ticket before awaiting any action.
   The Worker independently rechecks the exact cohort, DNS record digests,
   root-owned Core stage SHA and trusted pinned Edge SSH, then invokes the
   **existing** `execute_protected_switch` using the original 6G lock/journal
   and `ProtectedLiveHostActions` (no alternate controller).
4. The J saga verifies F4/Ingress, *persists the FROZEN PAM admission fence*,
   drains SSH sessions, applies terminal UID DENY, repins per UID with
   stage-pinned WireGuard and root-owned manifests, proves Edge outbound
   IPv4 and DNS/IPv6, updates UID mapping/account host via CAS, performs
   the Edge-to-Edge Cloudflare cutover guarded by the originally reviewed
   record fingerprints, commits the default relay and `settings.hosts` list
   inside the existing 6G transaction, then re-verifies and releases UIDs.
5. Any ambiguity after host or DNS mutation keeps the shared RUNNING 6G
   operation in a protected HOLD and freezes affected UIDs. **Never** fall
   back to the Core public IP or release unverified accounts.

## Special new-Edge path

Phase 1 deliberately kept an unverified new Edge **outside** the live
`host_pool`; adding it prematurely would have exposed it to Legacy
selection/automatic Failover.

Phase 2 can now admit an *unlisted* new Edge atomically during the final
protected cutover **only after** the original enrollment saved the exact
customer service port and after F3 allocation + independent production F4
witness are valid. On this path J reads the protected pin and live H/WG0
owner under the shared 6G lock, verifies source/target matching port and
inserts the new default only within the final CAS after UID and public
DNS proof. `settings.hosts` is rebuilt from committed active `host_pool`
rows in the same transaction.

Original pins created *before* this extension may have
`customer_port=0`; they remain HOLD, not silently inferred.

## Explicit compatibility/HOLD behavior

- Legacy `hp_addedge` / `hpdef_` remain intact, unchanged.
- NO changes to automatic failover and NO automatic migration.
- **Mixed Legacy/Protected customer cohorts are NOT silently switched.**
  The protected all-user cutover requires **every active SSH account** to
  already have an exact PROTECTED UID/runtime and an installed complete
  root guard/roster. Any Legacy user or a user on a different Edge blocks
  the entire operation BEFORE host mutations. This is intentional: merely
  changing the ingress host leaves a customer's internet IP at Core.
  A future audited Legacy-to-protected enrollment is required for such a
  cohort. Never bypass this gate with a boolean.
- The protection mode and `settings.k2_p2_relay_switch_enabled=1` are
  **both mandatory**; setting absent/0 = no execution.
- F3 `STAGED` is not F4 `READY`. The Phase 1 namespace-IP probe is not
  a subscriber/IPv6/DNS/boot acceptance. The independent F4 acceptance
  witness, persisted PAM and BootGuard, and destructive disposable-VPS
  tests are prerequisites before enabling the operator release.
- No general reboot, PAM install or F4 approval from Telegram. Unknown
  SSH/PAM/root permissions, mixed users, invalid Stage or DNS → HOLD.

## Focused source acceptance

`python -m unittest tests.test_edge_egress_k2_phase2_operator tests.test_edge_egress_v1_positive_handoff tests.test_edge_egress_k2_relay_switch -v`

Scenarios include mixed cohorts, unlisted Edge admission during final CAS,
wrong pinned port, stale F4, busy 6G lease, stale/other-admin Telegram ticket,
two protected users, cutover DNS failure, active-session drain HOLD,
retention of protected 6G lease and exact `settings.hosts` default order.

Full Python and Egress Stage-only CI should run on exact PR #120 head
before any deploy. These tests use simulated host I/O and in-memory SQLite;
**do not interpret them as accepted live WireGuard/SSH/SOCKS behavior**.

## Remaining deployment acceptance

Only deploy to a controlled disposable Edge with independent Core rescue
and backup, verified SSH identity/port and F4 acceptance. Prove SSH and
SOCKS through Edge and exact customer public IPv4 from outside, UDP/TCP DNS,
IPv6, WG loss/restore, cold boot/persistence, session drain and HOLD/manual
recovery; verify the unaffected Legacy cohort. Do not merge feature #120 to
`master` until Phase 3 and acceptance are complete.

## Final Phase1→F3 registration bridge (#128)

A missing integration was found during Phase2 review: the Phase1 pinned
transport activation previously returned successful dedicated WG/IP evidence
without publishing a formal F3 reservation, so a newly onboarded Edge could
never pass the guarded protected cutover. The original Wizard now stores both
**public** WireGuard peer keys in its immutable root-only StagePin. After the
Core namespace independently observes the exact Edge public IPv4, the Phase1
Worker validates those original keys against the Core Stage, claims the
**existing** F3 allocation under the same 6G RUNNING intent and stages F3
readiness as `STAGED` in the **same** SQLite transaction. It does not mint
production F4 READY, touch subscribers or enroll early in active host_pool.
Migrations for F3 allocation/readiness must already be installed and backed
up; a missing table or an older pin without original WG public keys yields
protected HOLD and requires operator reconciliation, not an ad-hoc shortcut.

This completes the **source wiring** for new Edge Stage → F3 STAGED →
independent real F4 acceptance → all-PROTECTED guarded manual cutover.
A mixed Legacy/Protected cohort is still blocked. No live tests or production
release have been performed by this change. The user-facing Telegram source
interface does not automatically enroll Legacy customers or recover a 6G HOLD.
