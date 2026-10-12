# NVL R1 disposable LAB closeout and final integration gate

**Recorded:** 2026-10-12. **Scope:** two disposable VPSs, not production. **Status:** Core↔Edge transport + one-UID IPv4 smoke ACCEPTED; protected SSH service/6G/reboot/customer-ready NOT ACCEPTED. This is the single remaining-work register to avoid repeating successful tests.

## Hosts (do not confuse with Production)

- Amsterdam LAB Core: `107.189.16.36`
- Frankfurt LAB Egress Edge: `216.126.229.12`
- Separate, untouched Production Core: `209.200.246.198`.
- LAB Core Git checkout originally verified at `06d10e9cceae38c8519834e69ac3a2717ef8c18b`; current PR HEAD may have later documentation commits. Installed Stage SHAs stay independent of Git head.
- LAB WireGuard network `10.78.120.0/30`; namespace `nvl-egress-lab1`; dedicated route table 1791; LAB test user `nvlr1test`, UID 1555, login disabled.

## Completed; do not retest unless code/topology changes

1. Pinned Stage hashes, host markers, distinct host machine IDs, Python syntax, and 20/20 launcher unit tests on **both** VPSs: PASS.
2. Host SSH fingerprints pinned on LAB Core; Core→Edge and Core→Core **forced `probe` only** command returned `OFFLINE_VERIFIED`. This does not authorize `start`.
3. Both locally staged transports manually started, post-start transport identity verification PASS; Core default route and IP rules unchanged. Core namespace HTTP(S) request to Cloudflare returned `ip=216.126.229.12` while Core root routing retained source `107.189.16.36`.
4. LAB test UID guarded with F1 terminal table-1791 `blackhole default` and UID-specific firewall. Manual temporary single-UID IPv4 attach observed `UID_PUBLIC_IP: 216.126.229.12`; exact route removal restored blackhole and `curl` from test UID failed: PASS. This does not prove actual Edge-disconnect/fail-over behavior or absence of DNS/IPv6 helper leaks.
5. Root-owned `nvl-egress-lab1-guard.service` installed and `systemctl enable --now` returned ACTIVE/ENABLED. Test account remains password-locked and `/usr/sbin/nologin`. **No reboot acceptance has occurred.**

## Critical remaining blockers — implementation, not repeated smoke checks

1. **The Core LAB has no actual `/root/master_bot.db`, no running `nvlbot.service`, and no PAM Egress hook.** Its BootGuard is not an F2/6G controller. Existing genuine Phase 6G bot callbacks are `_db_acquire_failover_lock` and `_db_update_failover_operation` using one `failover_operations` journal.
2. **Topology mismatch with existing F2 controller:** `attach_protected()` explicitly rejects a `source` that equals either Core or Egress Edge public IPv4, and the runtime store requires a real active/default **ingress Edge** in `host_pool` and the matching `dns_current_ip`. This **two-host** disposable pair has a Core and an Egress Edge, but no distinct LAB ingress Edge. Do not invent a source/DNS/default-host entry. Full existing-F2 end-to-end cannot be truthfully accepted on this pair unchanged; obtain an independently isolated ingress role or explicitly design, review and implement a supported alternate LAB topology without undermining production invariants.
3. **Readiness circular dependency:** `Existing6GUIDRuntimeStore._owner()` demands a real F4 `READY` `edge_egress_readiness` (and exact `ssh_accounts`, `host_pool`, `settings`, allocations and bindings). F3 `VERIFIED_LAB` is **not** `READY`. No synthetic readiness, manual INSERT of `RUNNING`, or copied production DB may be substituted.
4. **Transport ownership:** both LAB transports are already UP from local scripts. `R1Lab6GShadow.start()` begins with offline collision probes; it cannot start/adopt the present unmanaged pair. Recovery/start must be separately implemented and proven with preserved HOLD semantics; do not blindly rerun `up.sh` or `down.sh`. Forced SSH key on both hosts is currently `probe`-only, so `start` isn't remotely authorized and **must not** be unrestricted.
5. **Reboot/SSH guard:** merely enabling `nvl-egress-lab1-guard.service` at `multi-user.target` does not attest ordering ahead of every `ssh.service`/`ssh.socket` activation. The PAM hook is absent and no real test SSH login, independent admin recovery, actual Edge loss, IPv6/DNS/BadVPN leak capture, or fault/reboot recovery is accepted.

## Bounded completion plan

- **Code integration (GitHub/CI first, no VPS mutations):** choose a valid ingress topology, integrate the authentic 6G controller and migrations/lease owner, make remote agent command authorization lease-gated, implement already-UP reconciliation and boot admission ordering, and supply root-owned lab-only installer with explicit disable/rollback policy. Keep Production out of scope.
- **One coordinated disposable LAB deployment:** only after reviewed code and independent console recovery, install real isolated control plane and per-account SSH/PAM. Test exactly one external SSH client: allow only on attested Edge route; on Edge loss deny with zero Core fallback; reboot to deny-first and recover under true 6G. Capture ingress/Core/Edge packet paths for DNS/IPv6 and userspace helpers.
- **Do not promote `READY` or migrate customer accounts** unless independent F4 acceptance is completed. The two-host functional lab can be marked *transport/UID-smoke finished* now while the product's protected service milestone remains *blocked*.

## Operator pause instructions

No more commands required from the operator **now**. Do not reboot, open `nvlr1test`, modify `/etc/pam.d/sshd`, change default routes, re-run Stage `up.sh`, or use production records as LAB fixtures. Preserve the current enablement/blackhole, LAB keys and verified Stage for the next reviewed implementation.

## 2026-10-12 6G/PAM code integration checkpoint (PR #92)

The following **code-only** implementation now exists on the draft PR. It does not install PAM, operate either VPS, seed a DB or mark customer READY:

| Module | Architectural responsibility | Default / release boundary |
| --- | --- | --- |
| `edge_egress_r1_lab_topology.py` | Exact `107.189.16.36` Core-as-ingress, `216.126.229.12` Egress Edge, independent lab marker SHA, machine ID, UID 1555 `nologin` ownership and real eth0 IPv4 verification | No production fallback; refuses foreign hosts/users/sources; this is a two-host **disposable LAB** exception, not an ingress identity invented in a DB. |
| `edge_egress_uid_runtime.attach_protected(...lab_core_ingress_attestor=...)` | Allows actual Core-as-ingress source **only** when the concrete `TwoHostCoreIngress` attests; otherwise preserves rejection of Core/target-as-source | Requires `authorized=True` and all existing F2 steps/real 6G journal. Caller-supplied `lambda: True` is rejected. |
| `edge_egress_r1_lab_launcher.CurrentBridge6GLease` and `bind_disposable_lab_shadow` | Re-verify the same acquired, unique RUNNING 6G row, including independently attested two-host source | Never creates a lock or journal; any row/status/missing DB fails closed. |
| `R1Lab6GShadow(...accept_verified_running_transport=True)` | With current real 6G lease and verified guard, reconcile a pair already UP from operator's smoke test by `inspect` on both sides, avoiding an unsafe repeat of `up.sh` | Mismatched/partial pair is HOLD. Still transport-only: no UID-ready inference, no reboot recovery. Default false. |
| `edge_egress_r1_lab_pam.py` | Disposable first-account-rule `pam_exec` candidate; if the exact UID 1555 lacks authentic F2 PROTECTED mapping + F4 READY + verified kernel/DNS guard, deny the protected SSH login | No automatic installation; root and unrelated accounts remain governed by normal PAM rules. No DB means pilot DENIED. |
| `edge_egress_r1_lab_ssh_gate.py` | Optional, root-restricted SSH `SSH_ORIGINAL_COMMAND` dispatcher, allowing only fixed agent `probe`/`inspect` actions from verified Coordinator IP | Never executes `start` or an arbitrary shell. Existing installed LAB keys remain statically `probe`-only until separately reviewed operator installation. |

### Required real dependencies before lab SSH acceptance

1. LAB Core needs an authentic **isolated** Phase-6G-compatible bot control-plane deployment: the same `failover_operations` journal and **real acquisition/update callbacks**, not a hand-inserted RUNNING row. The `Existing6GUIDRuntimeBridge` must use those exact callbacks and the live DB. Never copy Production DB.
2. F2 store additionally requires truthful lab `ssh_accounts`, `host_pool` (Core genuinely terminates test SSH), `dns_current_ip` matching *actual* ingress, allocations, F3 readiness and unique protected bindings. `READY` may only result from genuine F4 acceptance; `VERIFIED_LAB` does not substitute. The test account **must remain locked** while its admission/boot safety is still uncertain.
3. The independent per-account PAM installer and 6G-aware remote `start` authorization are still **not implemented/accepted**. The new read-only SSH gate is insufficient for post-reboot WireGuard activation; the F2 code cannot invoke it to start transport. Do not remove old `from=... restrict` options or change the global PAM file based on code-only status.
4. Once dependencies and console are available, do **one** coordinated E2E: legitimate F2 attach, actual SSH dynamic forwarding via UID, real Edge loss with no Core fallback, and Core reboot deny-before-unlock. DNS/IPv6/BadVPN and multi-UID remain F4/R4–R6 evidence, not automatically proven by tests.

**This closes the source-topology mismatch and defines PAM denial semantics in code, but NOT the complete deployed 6G/PAM runtime.** Existing verified transport/UID smoke results remain accepted; avoid further isolated smoke loops.

### Genuine 6G/PAM composition port — code checkpoint

`edge_egress_r1_lab_integration.py` adds `Existing6GLabPilot`, which composes the existing `Existing6GUIDRuntimeBridge` and `attach_protected()` with **injected genuine** `db_conn`, bot `acquire_fn`/`update_fn` callbacks, strict pinned Core topology, concrete `LocalLinuxProtectedRuntimeKernel`, a `ReviewedLabPAMGate` (SHA-reviewed module and first PAM account rule with sshd UsePAM), existing-session probe, persistent `LabUIDGuardProbe`, and the 6G-bound running-transport shadow. All effects remain opt-in for independently attested LAB-only hosts. It verifies that required real tables exist and F4 `READY` is eligible before constructing the port; otherwise it refuses. It **does not** initialize the bot's DB, inject a lock row, install PAM, unlock the test account, or change routes. New unit tests cover missing dependencies, false readiness, genuine callback binding, PAM rule ordering and SHA pinning.

**Remaining integration/release limitation:** F2/F3 currently require independently attested F4 `READY` before a protected attachment. That is deliberately enforced by the new composition. The first end-to-end SSH canary used to *produce* F4 `READY` must be staged via a separately reviewed, isolated disposable canary procedure (or a specifically reviewed disposable-only evidence process); do not seed a `READY` row or change production admission rules to sidestep this release boundary. Original LAB Core has no 6G DB or installed PAM, so calling `Existing6GLabPilot.attach` on the current hosts is expected to REFUSE without altering network state. Transport/UID smoke are not full protected SSH readiness.

**Operator workload:** no new VPS commands in this GitHub code-only checkpoint. Leave current LAB Guard DENY and test account locked until a single reviewed coordinated installer and actual SSH/Edge-loss/reboot canary can be run with console recovery.

## 2026-10-12 next-stage preparation: genuine isolated LAB 6G callback source

New default-OFF `edge_egress_r1_lab_6g_bootstrap.py` is intended for the **same disposable Amsterdam Core only**. It checks exact host/UID/marker identity and a fixed **git blob SHA `268849707efeeaf030a0bd7eb361a88b9980860a`** for the existing `bot_final_v49-2.py`. It extracts and executes **only** original `_parse_flexible_datetime`, `_db_acquire_failover_lock` and `_db_update_failover_operation` functions into an isolated namespace, without importing/running the Telegram bot or contacting its APIs. Because the rest of the bot uses Python-3.12-specific syntax, only the three reviewed function spans are parsed; their original definitions are not rewritten. The old exact bot source SHA is independent from subsequent R1 PR commits.

With explicit `install-empty`, it will **exclusive-create** `/root/master_bot.db` **only if absent on the exact attested LAB Core**, and migrate only **empty canonical** existing F1/F2/F3 allocation, protected-mapping, UID-runtime, readiness and Phase-6G journal schemas. It does **not** create customers, a `RUNNING` operation, fake host_pool/default ingress, settings/dns_current_ip, F4 READY, bot token/service, PAM hook, routes or SSH logins. A failure after DB file creation leaves a visible HOLD requiring inspection, never a blind reset or deletion. This is structural bootstrap, NOT deployable service.

A dedicated CI test executes the original bot 6G callbacks against temporary real SQLite and verifies unique RUNNING lease, CAS updates, journal finalization and source hash. Keep `nvlr1test` nologin/locked with table-1791 blackhole. Do not update the currently running Stage-backed `/root/nvl-egress-lab1-source` checkout during this preparation: Stage checks pin its **old** commit. Later deployment must use a separate root-only code archive path without changing Stage code identity. This is one of the last infrastructure preparation steps, but real host/default/SSH account metadata, safe F4 canary acceptance, PAM installation and reboot/outage E2E still remain blocked and should not be silently bypassed.

