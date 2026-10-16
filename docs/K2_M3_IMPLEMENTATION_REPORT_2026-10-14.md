# K2 M3 — Unified Single/Batch protected migration engine

**Checkpoint:** 2026-10-14 | **Status:** source-level implementation candidate; separate GitHub CI, review, merge, deployment and real F4 acceptance. **Production and the original 425 SSH accounts are unchanged.**

## Active roadmap / source provenance

Canonical seven-phase product contract: PR [#144](https://github.com/DenaSon/nvl-bot/pull/144). M1 source PR [#145](https://github.com/DenaSon/nvl-bot/pull/145) remains open. M2 source PR [#146](https://github.com/DenaSon/nvl-bot/pull/146) remains open. M3 implementation branch `feature/k2-m3-unified-waves-20261014` is based on M2 code at `66715e58b0913ba70faf889d3166052e68321943`. The abandoned **earlier** experimental `feature/k2-m3-unified-migration-engine-20261014` is not the branch to use. Do not merge a stacked PR directly to auto-deploying `master` without explicitly reviewing the whole dependency chain.

## Before / after M3

| Topic | Before | After — guarded source-level behavior |
| --- | --- | --- |
| One vs many transfers | M1 only provided separate `SINGLE` and `BATCH` immutable read-only selection; no worker-level cohort plan | `edge_egress_k2_m3_waves.py` builds one ordered `MigrationWavePlan` from both modes, preserving exact UID/ingress/target/host metadata and each selected account's blockers |
| Multi-user execution | P3-A `Existing6GGuardedExecutor` was restricted to one UID/ticket with no batch sequencing | One wave executes **serially**, UID by UID, with a **distinct existing P3-A scoped ticket and separate original 6G lease/journal entry per account**. No second kernel/UID engine or independent migration lock. `SINGLE` follows the same exact loop with wave size 1 |
| Safety/wave size | No bounded, independently confirmed batch contract | Max **10 UIDs per explicitly authorized wave**. A 425-user selection must be subdivided, every subwave has its own digest and approval; execution of a parent cohort over that maximum is rejected. No automatic all-user cutover |
| Admin authorization | No single/batch operator intent at engine level | Short-lived HMAC SHA-256 approval binds exact immutable wave plan digest, actor, chat and expiry. Root-held secret and operator permission enforcement must be wired by M4; M3 has **no bot handler**. Each UID still requires a real P3-A ticket/actor check |
| Preflight drift | Previous cohort helper could assume uniform default host and historical DB owner | Before **every UID**, M1 re-reads selected account UID, historical metadata, fresh authenticated ingress, target F4 and session drain. Any drift stops wave; no next UID. M1 snapshot is never treated as a lease |
| Durable result | Host port could report success without the batch knowing which durable 6G operation recorded it | `edge_egress_k2_m3_journal.py` checks original `failover_operations` row for exact `SUCCEEDED`, `EGRESS_P3_VERIFIED`, action, Edge, nonce hash, scope digest, source/target and **no RUNNING 6G** before next UID. A synthetic or missing receipt is HOLD |
| Partial failures | No per-account wave progress or deterministic failure stop | `VERIFIED / HOLD / DEFERRED` per UID, exact operation IDs for confirmed commits, stop after first rejected proof/6G/packet/session/exception; never mass retry, auto-unlock, un-fence or silently skip blocked accounts |
| Same-Edge Legacy | M1 incorrectly rejected any user with actual source ingress equal to target even if not yet protected; legacy group enrollment rejects large mixed historical hosts | M1 fixed to allow Legacy on target ingress, but rejects `TARGET_ALREADY_PROTECTED`; `edge_egress_k2_m3_ingress_port.py` checks root-attested current SSH/WG ingress instead of blindly trusting `ssh_accounts.host`, and delegates kernel/packet/F2/6G operations to existing `GuardedProtectedUIDPort` and `SameEdge6GUIDRuntimeStore` |
| Live activation | No supported batch executor | **`M3_WAVE_EXECUTION_ENABLED=False` and `M3_VERIFIED_INGRESS_ADAPTER_ENABLED=False`**, no Telegram registration, no root installer activation, no live customer transfer |

## How the intended operator workflow will work after later M4–M7 release

1. Admin selects exactly one UID or explicit group in Telegram, chooses Edge, reviews ready/HOLD counts.
2. The **trusted M4 root worker** creates a plan from the M1 + M2 independent source identity provider and obtains fresh F4 + per-UID session evidence. User may require new authenticated SSH connection through the intended Edge; an old DB `host` value or a source older than 300 seconds must never be manufactured as current proof.
3. Admin approves the **exact one-wave digest**; M3 validates signed actor/chat/expiry and dispatches at most 10 members one at a time via original P3-A/6G. The worker cannot mark a user `VERIFIED` unless P3 post-commit checks and the original persisted 6G terminal record agree.
4. Failure means HOLD for the UID and DEFERRED for unstarted UIDs. Root-owned Stage/UID guards remain fail-closed; no global DNS, `wg0`, PAM or default host changes and **no automatic fallback to Core IP**.
5. The bot later displays the **real** durable results, next-wave approval and safe recovery controls. M3 itself does not expose UI or run outside the independently reviewed root worker.

## Crucial scope / genuine remaining engineering and field gates

- **Target ingress and historical DB host are different identities.** Same-Edge (currently entered e9) Legacy `UID_ENROLL_SOURCE` can use root-attested current e9 ingress even if `ssh_accounts.host=104.194.144.195`. P3 still enforces global Legacy mode `0` for that action and exact root roster/BootGuard/kernel/F4. **No automatic end-user endpoint switch** was implemented by M3. M4 must expose/prove source/endpoint reconciliation; otherwise a client on a different Edge is HOLD.
- **Cross-Edge direct UID_ATTACH is not unrestricted.** Existing P3 requires global Protected mode `1`, unsafe for a mixed 425-client population without cohort acceptance. M3 **checks the effective protected-mode contract before issuing each UID ticket**: cross-Edge with mode `0` is immediately `HOLD`, same-Edge source enrollment with mode `1` is also `HOLD`. It does not override or toggle global mode. For mixed Legacy rollout, use a genuinely verified target ingress + same-Edge per-UID enrollment, or develop an independently safe restricted cross-Edge port before declaring release. **Do not** flip global protected mode merely to make preview green.
- Current production `e9` is F3 transport UP/STAGED but **F4 not accepted**, and `nvl0555/1636` has no dedicated e9 route. M3 source CI cannot make either ready. No PAM/SSH/WG/kernel/UID change has been performed.
- M3 source components are callback/injection interfaces **not connected to a real operator-authenticated root service**. M4 must bind vetted implementations, root secret storage, durable bot actor/nonce and per-wave review; M5/M6 must provide independent packet/F4/boot/WG-loss and mixed cohort physical acceptance. An arbitrary synthetic `committed_6g=True` function in a unit test is NOT acceptable as a live witness.
- Original P3 `failover_operations` is the only authoritative per-UID commit journal. The M3 report is an in-memory projection; **M4 needs a durable root-owned wave-intent/checkpoint projection for UI restart** that can be reconciled against immutable original 6G operations, never a second operation/lease authority. Unknown or lost batch tracking must HOLD pending explicit operator confirmation.
- Expected result after **all seven phases** remains full Telegram operation without routine manual operator CLI and no unresolved product-side functional blockers. This is NOT accomplished by just building source M3.

## Code and production status ledger

| Stage | Status |
| --- | --- |
| M3 source: common one/ten-UID wave engine, actual-ingress UID host port and 6G verifier | IMPLEMENTED on feature branch |
| M3 source: final exact-HEAD CI | Must verify both Python checks and stage-only PR checks (run IDs on PR) |
| PR review & dependency merges (M1 #145 → M2 #146 → M3) | NOT MERGED |
| Live privileged M3 P3 executor registration / bot authorization | OFF; assigned to M4 |
| e9 real SSH/SOCKS public IP + packet/DNS/IPv6/boot acceptance | NOT TESTED; M5/M6 |
| Fleet batch activation and migration of eligible accounts | OFF; M7 |

**No CLI action is requested from the operator** for this source phase. A long-run recovery of a lost UI checkpoint is explicitly not auto-replayed: only the real original 6G journal and a fresh signed operator approval can authorize any next UID.

## Verification and next phase handoff

Review `tests/test_edge_egress_k2_m3_waves.py` and `tests/test_edge_egress_k2_m3_ingress_port.py`: synthetic 425-account type constraints, wave-split, unchanged UID, expired/wrong actor HMAC, same-edge Legacy with historical-host mismatch, forged 6G receipt, 6G RUNNING, failure/cancellation, and no release flags. These tests do not execute real SSH/PAM/systemd/IP rules or wireguard.

**Status evidence:** GitHub Actions `Python checks` full suite must pass on exact M3 PR head; `Edge egress stage-only checks` should pass on the PR, too, but is not physical F4. Exact run IDs/results recorded in PR after verification.

**Next: M4 — Telegram UI and trusted root automation** for both one and many users; include fresh target/source selection, approve exact limited waves, progress/hold/reconcile buttons, per-user source proof / reconnect workflow, root-worker binding and module install/recovery. Stage-only M2/M3 source status is not operational acceptance; M5–M7 remain explicitly gated.
