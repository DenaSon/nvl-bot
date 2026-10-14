# K2 Phase 2 — All-Protected promotion under original 6G (2026-10-14)

**Implementation status:** guarded source-only/Python; **NOT a live release**. This change completes the final DB transition contract that separates per-UID source-edge Legacy enrollment from the already-written all-PROTECTED J cutover.

## Invariants

- Accounts, passwords and UNIX UIDs remain on **Core**; customer SSH still connects through the existing **source Edge**. During source enrollment the permanent mode remains `0`, and the root-only F2 PAM+roster admits a converted UID only when its protected routing and guard are verified.
- The new `COHORT_PROMOTE` P3-A action is a **distinct source/target** transaction (source = current default Edge, target = staged next Edge) and uses the original `_db_acquire_failover_lock`, original P3-A signed one-shot actor/chat/nonce ticket, and **same durable 6G journal**. There is no new lock.
- All *active* SSH accounts must be listed under that unique default source Edge with a valid real Core Unix UID, exact `PROTECTED` runtime and mapping rows, and a complete root-owned roster/guard. Any Legacy account, extra runtime, UID collision, other-Edge user or stale F4 holds. Source and target F3 must be exact/STAGED on the same Core, both must have current independent F4, and current public DNS must still be the source.
- Live evidence remains independently injected: root rescue, PAM/BootGuard/roster, all accounts idle, per-UID kernel-route isolation, external public IPv4 and DNS/IPv6 **no Core leak**, WG-loss and reboot recovery. Simple label strings do **not** prove these: actual host safety implementations and F4 must be reviewed during Phase 3.
- After confirmed P3-A RUNNING intent, the host port takes SQLite `BEGIN IMMEDIATE`, rechecks one original 6G op (exact action, nonce, scope), all source customers/OS identities/F3/F4/guard files and fingerprint, and executes **only**:
  `UPDATE settings SET value='1' WHERE key='edge_egress_protected_mode' AND value='0'`.
  Post-CAS state is rechecked in the same transaction and afterward, with independent packet/boot checks.
- On ambiguous failure the protected P3-A coordinator leaves 6G `RUNNING/EGRESS_P3_RECOVERY_REQUIRED`; it **never** writes mode `0` back, removes an old protected mapping or un-fences a UID. This intentionally may deny protected SSH logins until manual reconciliation, rather than leaking Core IP.
- This transition is a prerequisite for `k2_p2_relay_switch_enabled=1` and the existing separately confirmed `🔀 تغییر مسیر ترافیک` (source→new Edge), **not** a license to enable that switch itself.

## Existing 6G same-source contract

`tests/test_edge_egress_shared_lock.py` now extracts the exact production `_db_acquire_failover_lock` function from `bot_final_v49-2.py` and exercises `source==target` for `UID_ENROLL_SOURCE`, single-operation contention, and no stale unlock of `EGRESS_P3_EXECUTE_INTENT`. CI on Python 3.12 checks this legacy function, not a local mock.

## Tests

```bash
python3 -m unittest \
  tests.test_edge_egress_shared_lock \
  tests.test_edge_egress_k2_source_enrollment \
  tests.test_edge_egress_k2_cohort_promotion -v
```

The protected promotion tests use the real SQLite/F2/P3-A/P3-C account lifecycle and fake independent root/packet ports. Positive check: all accounts protected, exact original 6G lease, mode `0→1`, unchanged account/host/DNS/Edge/UID mappings. Failure injection: stale F4, foreign UID/mapping, extra Legacy, changed OS identity, source/DNS change after operator preview, wrong actor, failed external packet proof, failure **after** CAS, competing 6G lock. Tests are not evidence of a real running VPS.

## NO-GO for Production

No concrete privileged host-safety/roster/PAM/BootGuard installer has been signed off; no disposable VPS external SSH/SOCKS+packet DNS/IPv6+WG loss/reboot F4 completed; no live Telegram execute handler for source enrollment/promotion should be registered yet. The existing customer transfer still needs those operational gates, the target guarded J cutover, and a canary rollout. **Keep PR #120 draft, no master merge or operator flag toggles.** Follow pending release issues #106 and #108.
