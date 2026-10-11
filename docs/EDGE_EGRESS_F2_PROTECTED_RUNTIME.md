# NVL Protected SSH Egress — F2 Runtime

**Status:** implementation review candidate, **NOT production enabled**.
**Base:** F1 PR #84, branch `feature/egress-f1-safety-foundation-20261011`.
**F2 branch:** `feature/egress-f2-protected-uid-runtime`.

## Goal and non-goals

Normal Core-terminated SSH clients should eventually egress from their assigned
Edge public IPv4, not from Core. The confirmed staged namespace IP is
`216.126.229.12` while the unchanged production `nvl0557` direct IP is
`209.200.246.198`. F2 implements the protected per-UID **controller and
persistence contract**, not the final login/boot cutover.

F2 does not write the live Core, alter production `wg0`, public DNS, global
`ssh.service`, `ssh_accounts.host`, or install a PAM hook. F3 connects
verified new Edge provisioning and bot entrypoints. F4 verifies real
SSH/PAM, restart, multiple users and host-failure recovery before any cutover.

## Modules

- `edge_egress_uid_runtime_store.py`: explicit SQL migration for
  `edge_egress_uid_runtime`; unique UID/priority/DNS port, immutable Edge
  allocation, shared routing table *per Edge*. Requires the **same SQLite
  RUNNING 6G lease**, source active/default, stable ingress DNS,
  OS UID/account ownership and STAGED dedicated Edge allocation. CAS
  generations reject stale updates. `edge_egress_uid_bindings` receives
  `PROTECTED` only after controller proof.
- `edge_egress_uid_admission.py`: read-only per-account PAM policy candidate.
  A `BLOCKED`, `FROZEN`, `ROUTED_UNVERIFIED` or `HOLD` user is denied
  even when their password is correct. A `PROTECTED` user additionally needs
  immutable SQLite mapping, no running 6G operation, exact live UID/IPv6/DNS
  guards, a live dedicated DNS unit, terminal blackhole and owned Edge route.
  Root-only administrative break-glass is independent of SQLite. This hook is
  **NOT installed**, and whether all direct-TCPIP channels traverse the PAM
  account phase still requires the F4 end-to-end test.
- `edge_egress_uid_runtime.py`: async controller with explicit authorization,
  common 6G lock and journal, persistent DENY intent **before** checking
  old sessions or mutating kernel state, then boot guard, dedicated Edge
  start, owned attach, public IPv4, DNS/IPv6 guard checks, and CAS commit.
  Failures freeze the exact Edge route and keep a 6G recovery hold. There is
  **no** restoring protected accounts to the Core route.
- `edge_egress_uid_runtime_bridge.py`: injected existing 6G lock/journal
  bridge; no default host transport, no second lock, and mandatory externally
  attested per-user login gate plus drained live sessions.
- `edge_egress_uid_runtime_kernel.py`: explicit opt-in local Linux adapter
  for F1 boot guard, per-user DNS unit start, exact Edge route and actual
  `runuser` HTTPS public IP observation, and scoped freeze. It intentionally
  does not implement global SSH/DNS reconfiguration or assume Internet probe
  success guarantees full leak-proof operation.
- `edge_egress_legacy_fence.py`: now blocks legacy 6G/6H mutations from the
  *first* unverified `BLOCKED` runtime intent, not only after the protected
  mapping is committed. The existing recovery hold set includes F2 journal
  phases, preventing automatic stale-lock takeover.

## Runtime state machine

```text
                      [6G lock acquired]
                               |
                   per-user PAM gate attested
                               |
                BLOCKED (durable, denies logins)
                               |
                UID idle / IPv6 + DNS + IPv4 guard
                               |
                   dedicated Edge peer starts
                               |
             ROUTED_UNVERIFIED (denies logins)
                               |
                  actual Edge IPv4 and DNS/IPv6
                        guard proof
                               |
              PROTECTED (protected mapping CAS)
                               |
                      operator FREEZE
                               |
             FROZEN (blackhole retained; offline)
                               |
           explicit fresh-lease resume with same
           UID, Edge ID, priority and DNS port
                               |
             ROUTED_UNVERIFIED -> PROTECTED

Anything ambiguous after a protected intent -> HOLD + 6G RUNNING
(including failed freeze, journal uncertainty or lost kernel proof).
HOLD NEVER auto-recovers or deletes UID protection.
```

Multiple users on one Edge share its route-table/next-hop. Removing the
Edge default affects every such user; `freeze_protected` is not an isolated
single-user network action in this design. Per-user UID rules and DNS ports
remain unique. F3 needs Edge-wide maintenance and operational status.

## Key safety constraints

1. `edge_egress_uid_runtime` is an **explicit migration**, not performed
   by importing a module or bot startup. F1 `edge_egress_uid_bindings` and
   the allocation table are separately migrated.
2. The gate MUST already be applied in `/etc/pam.d/sshd` with `UsePAM yes`
   and independent verified administrative recovery *before any BLOCKED intent
   is written*. No generated `sshd` / PAM changes are installed in F2.
3. The gate's `PAM_USER` can never choose its own DB path. Only the root
   Core DB is read in query-only mode. A missing DB or corrupt metadata
   denies protected/unknown accounts. The root account is a narrowly scoped
   recovery exception; F4 must validate non-root administrator access too.
4. An already-established SSH process can continue despite a new PAM gate.
   Before arming a UID, an externally injected check MUST independently
   verify no existing process/forwarding sessions for that UID and deny new
   logins through the gate.
5. Per-user `systemd` startup dependencies are **not global
   `ssh.service` dependencies**. Boot recovery stays deny-only. Reboot and
   socket-activated SSH/PAM behavior are intentionally deferred to F4.
6. DNS/IPv6 assertions in code and an observed Edge IP are necessary but not
   sufficient to prove all possible resolver/helper UDP paths are leak-free.
   F4 must perform packet capture, failure injection and a live SSH session
   after reboot, plus offsite backup/rollback validation.
7. While a protected runtime row exists (including HOLD), old 6G/6H/DNS/Edge
   onboarding cannot perform a Core fallback. This trades availability for
   no unprotected fallback pending a later protected failover release.

## Test coverage

- SQLite reservation/transaction/unique resources/multiple UID shared
  Edge/CAS/replay/lock/source DNS/Edge allocation.
- PAM admission deny/allow and root break-glass policy, stale mapping, active
  6G lease and kernel/DNS proof failures.
- Attach proof sequence, wrong Core IP, runtime journal failure, preexisting
  session handling, fail-closed freeze, manually resumed FROZEN binding.
- Kernel adapter OFF by default, root/UID guards, only owned route detached,
  `wg0` untouched.
- Legacy F1 unit/regression suite remains required.

## Explicit remaining gates

- F2 is **not the live deployment**. No default CLI, bot registration,
  installed PAM hook or active customer route is provided.
- F3: integrate dedicated Edge provisioning/registration and explicit bot
  admin commands; verify RuntimePort implementations and shared Edge
  orchestration; install and validate the per-user PAM hook in disposable
  staging.
- F4: disposable VPS reboot with out-of-band console, root and non-root SSH
  recovery, noninteractive forwarding checks, DNS/IPv6/UDP leak tests, actual
  `nvl0557` SSH IP proof, backup/restore and rollback. Only then consider a
  protected production feature flag and controlled canary.

**Never** run `edge_egress_uid_boot.py apply --enforce`, migrate real
`nvl0557`, edit `/etc/pam.d/sshd`, restart SSH or change DNS/routes on
Production from this phase.
