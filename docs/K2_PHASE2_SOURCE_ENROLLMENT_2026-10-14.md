# K2 Phase 2 — Source Edge Legacy enrollment (2026-10-14)

**Status: Source-only implementation; no privileged live worker, Telegram execute registration, server deploy, F4 or Production acceptance.**

## Defined scope

Existing SSH accounts and customer credentials stay on Core. Each Legacy account is enrolled **on its already active ingress Edge**, so its actual Core OS UID can obtain a dedicated fail-closed egress policy through that same Edge. Only after all accounts are protected can the existing separate J/6G Edge→Edge positive cutover be attempted. No change to Legacy `hpdef_`, public DNS, `settings.hosts`, `host_pool`, Core default route, shared `wg0`, or 6H.

## Changes in this increment

- `UID_ENROLL_SOURCE` is an explicit new P3-A action: **requires source IPv4 == target IPv4**, unlike existing `UID_ATTACH` which still rejects equal addresses. The source action is allowed **only** while the persistent global protected-mode setting remains `0`; it cannot silently switch the rest of the Legacy population. Root-only operator execution, one-shot actor/chat ticket, persistent original 6G acquire/journal, fresh safety gates and SHA/digest identity all remain mandatory.
- Additional acceptance gate names: `SOURCE_EDGE_F4`, `MIXED_PAM_COMPATIBILITY`, `SOURCE_INGRESS_PIN`, `BOOT_ROSTER_PREINSTALLED`, **in addition** to P3-A existing rescue/host and P3-C F4/PAM/boot/DNS/IPv6/session requirements. These are required **inputs from independently checked evidence**, not built-in proof or activation flags. The implementation cannot mint a real F4 witness.
- `SameEdge6GUIDRuntimeStore` **subclasses** the existing F2 store and overrides only its lock check for the exact source UID operation. Every SQLite CAS checks the sole `RUNNING` 6G row and exact P3-A action, source==target, operation ID, nonce digest, scope digest and original phase. The original F2 store continues to forbid equal source and target.
- `plan_source_enrollment` uses the prior read-only full-population audit, refuses corrupt/unowned/stale source and target F3/F4, and demands a root-rostered matching `PROTECTED_BOOT_GUARD` for the selected exact Legacy UID **before** any kernel command.
- `GuardedSourceEnrollmentPort` rechecks the unchanged full cohort fingerprint **under the original 6G lease** before delegating to the original P3-C `GuardedProtectedUIDPort`. The P3-C lifecycle writes `BLOCKED` before host mutation; verifies boot/PAM/multi-UID/session idle; arms per-UID deny, attaches dedicated source Edge route, checks exact public source IPv4 plus independent DNS/IPv6 non-leak evidence, and commits `PROTECTED` mapping. On ambiguity, the existing P3-A recovery retains `RUNNING` and P3-C attempts UID freeze/HOLD. Host/DNS/default/global mode never change.
- Neither `GuardedSourceEnrollmentPort` nor `SameEdge6GUIDRuntimeStore` has a default live factory. `SOURCE_ENROLLMENT_RELEASED=False`; there is deliberately no bot mutating callback or root installer.

## Tests and acceptance boundary

```bash
python3 -m unittest tests.test_edge_egress_k2_source_enrollment -v
python3 -m unittest discover -s tests -p 'test_edge_egress_*.py' -v
```

Tests use a real SQLite DB, the original P3-A 6G journal and P3-C store, but **fake kernel and independent safety ports**. They cover success while `global mode=0`, no host/DNS/default mutation, wrong egress IP, packet evidence failure, stale cohort, source F4 expiry, mismatched operator gates, wrong 6G nonce, UID drift and old cross-Edge action still rejecting equal IP.

**NOT DONE:** the real legacy `_db_acquire_failover_lock` compatibility for same-source pair must be examined and independently tested; real pinned PAM/roster/BootGuard installer and live host safety evidence provider; session handling; failure/cold boot; external SSH/SOCKS test on disposable VPS; safe promotion from mixed `mode=0` to all-protected `mode=1`; and production rollout. Do not fake evidence, flip the global mode, or merge draft #120 into master until these are addressed. `#106` and `#108` remain open.
