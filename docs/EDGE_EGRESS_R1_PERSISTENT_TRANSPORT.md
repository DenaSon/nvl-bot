# NVL Edge Egress — R1 persistent transport implementation (review checkpoint)

**Date:** 2026-10-12. **Status:** R1 implementation **in progress**, default OFF. This PR provides the transport ownership/adoption barrier and an opt-in injection port for the **existing F2 shared-6G controller**. It does **not** close R1 or authorize live deployment, PAM, BootGuard, customer UID routing, or `READY`.

## Live baseline and intentional refusal

The 2026-10-12 operator-provided host audit is in [EDGE_EGRESS_CURRENT_HANDOFF.md](EDGE_EGRESS_CURRENT_HANDOFF.md). The Core already has `nvl-egress-stg1`, a dedicated netns WG, pilot SSHD and a root veth; Edge already has `wg-nvl-stg1` (UDP 51842). Those resources predate a managed R1 transport unit. **Do not stop, adopt, reinstall or recreate them.** The Edge has an earlier unscoped `POSTROUTING MASQUERADE` before the tagged staged rule, which must not be modified as part of merely inspecting the R1 port.

The other historical `fwmark 0x77` table 77/UID 1658 path still targets `wg0`, not `stg1`. Leave it untouched.

## Current code and invariants

- `edge_egress_r1_transport.inspect_linux()` reads only dedicated interfaces, namespace, veth, public WG peer/allowed IPs, Core namespace IPv4 default, Edge listen port/forwarding/NAT, and dedicated unit identity. It never reads or returns WireGuard private material. There is no CLI that applies live state.
- `stage_owned` requires an exact stage manifest/spec/role/owner token plus the **independently reviewed SHA-256** for the four root-owned stage files. The dedicated systemd unit must itself be root-owned/non-symlink, at the expected path, and byte-identical to the separately reviewed unit hash. No implicit adoption from a file name, active WG interface, or `systemctl static` output.
- A live unmanaged or partial shadow results in `HOLD` (no teardown); an earlier broad NAT rule in front of a tagged Edge NAT rule also means `HOLD`. `MANAGED_RUNNING` is transport-only evidence, never a customer-ready state.
- `GuardedR1ShadowPort` can be injected into `Existing6GUIDRuntimeBridge.shadow` **only** with an explicit opt-in, disposable-VPS flag, injected current **existing 6G lease** predicate, externally attested UID guard predicate and approved Core/Edge launchers. There is **no alternative lock or database**.
- The start sequence is Edge first, lease/guard recheck, then Core, then current lease/guard + transport identity verification. A partial failure raises `R1_TRANSPORT_START_UNCERTAIN_HOLD`; it never blindly calls the old lab `stop`/cleanup handlers. The outer existing F2 coordinator must persist the 6G HOLD and retain the UID blackhole.
- No code in this PR imports the bot on startup, installs units, migrates SQLite, writes PAM or touches `wg0`, `ssh.service`, `ssh.socket`, `ssh_accounts.host` or public DNS.

### Limits (not done in this checkpoint)

1. **Durable provisioning:** independently reviewed root-owned transport systemd manifests and explicit installation/rollback for a *new disposable Core+Edge pair*; no unreviewed startup of the current `stg1`.
2. **Boot/fault reconciliation:** automatic persistent boot ownership and deny-first startup cannot yet be claimed. True post-reboot UID guard/session admission is R2/R3 and must be independently verified in a disposable full VPS.
3. **Production adapter wiring:** this port intentionally has no production Core/Edge launchers or auto 6G bindings. Its predicates are injection points, not proof that any live host has them.
4. **Transport-specific effects:** exact NAT owner repair, long-lived sessions, DNS/IPv6/BadVPN leak captures, signed release witness and protected Canary are not implemented by the observation or unit tests.

## Acceptance for this code-only checkpoint

Run only focused new unit tests and syntax on a fresh checkout:

```bash
python3 -m py_compile edge_egress_r1_transport.py tests/test_edge_egress_r1_transport.py
python3 -m unittest -v tests.test_edge_egress_r1_transport
```

GitHub's normal changed-path matrix can also execute; it is **not** VPS boot verification. Record actual job results before claiming checks passed. Do not rerun earlier isolated SOCKS/staging experiments simply to validate this file.

**Issue #88 stays OPEN.** After completing this safe ownership foundation, finish durable R1 transport start/stop/freeze/reconcile and disposable VPS acceptance *within R1*, then proceed to R2. No protected cutover until R1–R6 are accepted.


## R1 systemd/boot checkpoint — 2026-10-12, code-only

Two additional modules are implemented on the **same Draft PR #92**:

- `edge_egress_r1_systemd.py`: offline `nvl-egress-EDGEID-transport.service` unit renderer and explicit **DISPOSABLE_ONLY** start boundary. The unit is **not installed or enabled by repository import or CI**. It has `Type=oneshot`, `RemainAfterExit=yes`, `Restart=no`, `After=network-online.target`, no `ExecStop` and no dependency on global SSH or customer UID guards. On a newly prepared disposable host only, an operator may separately choose to install/enable it; startup still requires a SHA-256-pinned root-only boot contract, exact reviewed stage file SHA-256 set, matching host `/etc/machine-id`, a root-only disposable-host marker with independently reviewed digest, empty dedicated transport resource preflight and no unscoped legacy NAT on Edge. The existing stage `up.sh` then runs; uncertainty is HOLD and is **not** a request to blindly tear down networks or release the 6G lease.
- `edge_egress_r1_reconcile.py`: **read-only deny-first** reconciliation against the observed transport identity, shared existing 6G RUNNING lock, protected UID mapping count, UID guard/gate attestation and outstanding recovery marker. Missing DB/journal evidence or any old protected binding, even with an apparently healthy transport, is HOLD until independently reviewed F2 reconciliation. Every result has `network_mutation_allowed=false`, `uid_attach_allowed=false` and `customer_ready=false`. No new lock or persistence database is introduced.
- `edge_egress_r1_transport.py` now uses a validated Python regex for the staged WireGuard **public peer key** instead of a double-escaped pattern; a positive fake-kernel regression exercises the actual parser. No WG private keys or staging material are emitted by the diagnostics.

### Installation boundary remains closed

These additions are **not production deployment instructions**. In particular, do not copy the boot marker, install/enable this unit on the running production Core/Edge pair, assume an old `stg1` interface is owned or rely on `systemd active` as proof of secure customer Egress. The disposable marker and machine-id are an operator-controlled lab interlock, **not cryptographic proof that the host is disposable**. R1 still needs a reviewed host installer/rollback plan, live independent Core↔Edge pinned transport start/freeze/reconcile across reboot, plus a full disposable VPS acceptance with independent console. R2–R6 remain blocked; do not migrate Production DB or attach protected UIDs here.

Relevant focused tests:

```bash
python3 -m unittest -v tests.test_edge_egress_r1_transport tests.test_edge_egress_r1_systemd
```

Do not mark CI PASS until the new PR-head workflow jobs have reported completion.


## R1 continuation: disabled-file install, rollback and live 6G admission (2026-10-12)

**This section supersedes the earlier wording that the rendered systemd service can start networking automatically at boot.** It now renders `ExecStart=... verify` (read-only identity check). In particular, neither boot nor invoking the CLI `start` may create the WireGuard tunnel or override the shared journal. `start_disposable_transport()` instead requires an explicit, *injected* `lease_check` callback that must remain true before preflight, before executing the reviewed stage `up.sh`, and after transport identity proof. The direct CLI `start` action always refuses. This is not automatic recovery of protected users.

- `edge_egress_r1_shared6g.py` supplies `Existing6GR1LeaseProbe`. It calls the **existing** `Existing6GUIDRuntimeStore._lock()` read-only verifier against `failover_operations`; source, target, ID, single RUNNING operation and lease validity are required. No new tables, locks, or lease acquisition. External F2 must still acquire and journal the transaction and attest the UID guard.
- `edge_egress_r1_install.py` provides a **DISPOSABLE_ONLY**, default-off, root-gated `prepare_bundle`, `install_disabled`, `rollback_disabled`. Independently reviewed SHA-256 digests are mandatory for the boot manifest and generated systemd unit; the stage files, disposable-host identity and reviewed root agent are required before exclusive file creation. Only one dedicated `/etc/nvl-egress/r1-ID-ROLE.json` and one `/etc/systemd/system/nvl-egress-ID-transport.service` are created, initially disabled. There is **no** `systemctl daemon-reload`, `start`, `enable`, SSH/PAM change or network mutation. Files are never overwritten or adopted.
- Rollback deletes **only byte-identical, root-owned files**, after *separately supplied* read-only attestation that the unit is inactive/disabled **and** all dedicated transport resources are absent. Unknown state, a live interface/netns, tampered bytes, symlink, or active unit => refusal. Rollback never removes running tunnels or releases the existing 6G lease; a failed/interrupted installation may require operator cleanup after independent verification.

### Remaining R1 acceptance boundary

These components are testable code with **injected verification ports**, not a deployable production installer or a complete R1 release. The agent dependencies and independent agent signature review, concrete systemd-state and kernel-absence probes, operator-directed installation/runbook, cross-host launcher, fresh boot/reboot fault behavior and recovery continuity **must be accepted on a disposable Core+Edge VPS with independent console**. The existing Core/Edge `stg1`, `wg0`, old UID `1658` path, production SSH/BadVPN and DB remain untouched. R2–R6 blocked; no customer cutover.

Focused CI now covers `tests/test_edge_egress_r1_install.py`, `tests/test_edge_egress_r1_shared6g.py`, and the earlier R1 suites. GitHub CI PASS must be checked against the **last code/docs commit**; never infer readiness from an older run.

## R1 disposable Amsterdam↔Frankfurt lab: 2026-10-12 operator stage evidence

This **supersedes the older live Frankfurt Edge inventory** above for IP `216.126.229.12`: the operator *reinstalled* that host. It no longer has the old `wg0`, `wg-nvl-stg1`, broad NAT or 10 previously listed Linux accounts. The 10 accounts **remain marked active in the Production SQLite DB**, and the owner explicitly deferred any account migration. Do not silently rewrite those records.

Isolated LAB pair, **not** the Production Core (`209.200.246.198`):
- Core: Amsterdam `107.189.16.36` (Ubuntu 24.04.3; fresh); public WG key `vikt7RynwBk0lpFDgz8Lbz7CBQs7Xuf+9IwPnGxbykY=`.
- Edge: Frankfurt `216.126.229.12` (Ubuntu 24.04.3; reinstalled); public WG key `f43HBIfTFpdm5yNNo8YbjIERIY+UqBSLyB3yW0R9pxc=`.
- Planned `lab1` WireGuard `10.78.120.0/30`, veth `10.78.121.0/30`, UDP `51852`, table `1791`, uplink `eth0`.
- Both checkout SHA `d37cf20d1e99f2a8236b2d481ddd41d708c86258` and stage **only**, with no tunnel/network activation. Core `/root/nvl-egress-staging/lab1-core`; Edge `.../lab1-edge`.
- Core Stage independent SHA-256: manifest `629fa465f68d87274447b6feac585b3108423b0451489131a7bf21ccbf6fb665`, wg.conf `39aec2fa1fd68bd7d4be9cbb4eb7c80db7fc46186c4ce3bc9490d179b2260157`, up.sh `424b32a3048d6a816daf78d9e0697dd94b03b5897dbc393bca51a349570d10f8`, down.sh `57c243bd6614e795bcbfcbfda78dc1c5a2208037779d3361c9dc8616a6a0a389`.
- Edge Stage SHA-256: manifest `2628951a7fdff4c219ecd191e09160974ef7daf737a97ae6f310f0d8e4378c1b`, wg.conf `58d46ad0e5212e9b79378e43e6cb2198535aa07282d20dc958d1d1f9757f3e00`, up.sh `31f5f7380087288e2ac93436fe813bcd6132b5fcfa2753cf7d3443f3632126a4`, down.sh `309dac5c560448eeb4424bf24fe208d0aaeaefce21efbb6d13b22422f9d2215c`.
- Both operator `preflight=PASS` and `_stage_owned=PASS`. Edge `net.ipv4.ip_forward` was changed **temporarily** from 0 to 1 before the passing preflight; persistence through reboot is NOT configured. Verify the current value again before activation.
- Two hosts have **no shared lab 6G DB/journal or installed PAM/UID BootGuard**. Neither a passing Stage SHA nor this PR allows network start/customer attachment. No live route/egress/leak/reboot proof yet.

### New implementation — only the explicit F2/6G bridge may dispatch

`edge_egress_r1_lab_launcher.py` adds a concrete, opt-in `RuntimeShadowPort` (`R1Lab6GShadow`), accepting the existing `Existing6GR1LeaseProbe`, *independent externally attested* UID guard check, and a pinned `LabSSHExecutor`. It checks live shared 6G and guard before probing both machines, between remote Edge and Core activation, and after both. Unknown result or lost admission raises `R1_DUAL_HOST_START_UNCERTAIN_HOLD` and never calls a cleanup, disables another interface or restores Core egress; F2 must persist HOLD and freeze its protected UID table.

`edge_egress_r1_lab_agent.py` is a **lab-only root transport agent**: exact root-owned Stage hashes, disposable marker, machine ID, clean pinned repository commit, host IPv4, absent prior resources, scoped NAT rules, WireGuard peer identity and tunnel addresses are verified. It only supports `probe` or `start`, and a failed start remains an operator-reconciled HOLD. It does NOT independently acquire or attest a live 6G lease on Edge: the live lease is exclusively on Core and must be checked around SSH dispatch. Its `SSH_CONNECTION` check is operational friction, **not** authentication or an F2 lock; restrict remote root SSH key access to the disposable Core and never use Production credentials.

This is **not yet runnable on the staged pair**: their checkout is pinned to the earlier SHA, the lab boot identity markers/agent sources/host-key-pinned SSH identity are not yet deployed, and the F2 Core database/session gate/UID boot guard are not initialized. Do **not** bypass this by issuing `up.sh` manually, setting `lab_activation=true` in a legacy worker, creating a pretend 6G RUNNING DB row, or faking the guard predicate. The R1 verification service still checks identity at boot, **not** auto-starts WireGuard. No `READY`, production installation, or cutover permitted.

After reviewing the new PR head and its CI: pin a fresh code SHA on **both** disposable hosts, provision a separate SSH key with strict known_hosts and an isolated access policy, independently provision the disposable identity marker and machine IDs, instantiate the *real* F2 journal/guard on the fresh Core, then run reviewed failure injection with an out-of-band console. Run `python3 -m unittest -v tests.test_edge_egress_r1_lab_launcher` before host integration.

### Concrete F2 lease binding (same operation, not a second transaction)

`bind_disposable_lab_shadow(bridge, ...)` rejects anything except a fresh, fully injected `Existing6GUIDRuntimeBridge`; it refuses replacement of another shadow. `CurrentBridge6GLease` reads `bridge.operation_id/source/target` only **after** `attach_protected()` has acquired the authentic F2/6G operation, and validates that exact row via `Existing6GR1LeaseProbe`. There is no inserted RUNNING row, fake callback, independent lock or second journal. The independently attested `guard_check` predicate is mandatory, and both opt-in flags default to false. Unit tests model a late-acquired lease and reject unbound/different operation.

Limit: the new disposable SSH host agent is a root-capable executor whose `SSH_CONNECTION` test is **not a cryptographic lease proof**. The owning Core coordinator must hold the 6G lease before and after each dispatch, protect its private SSH key and restrict remote root SSH access. Never expose the agent to arbitrary callers, and do not confuse this adapter with a production-safe distributed admission service. Only F2 journals failures and freezes protected UID routes.

### Read-only recovery diagnostic

`edge_egress_r1_lab_agent.py inspect` observes an already-running or partially failed dedicated interface without the clean-preflight collision check used for startup. It returns only `OFFLINE`, `TRANSPORT_VERIFIED`, or `HOLD`; identity/peer/NAT uncertainty is `HOLD`. The Core-facing `inspect_lab_transport()` returns `R1LabRecoveryEvidence`, with `recovery_required=true` when one host is unreachable, either is `HOLD`, or the two states differ. **No automatic restart, stop, route fallback, 6G transition or UID unlock is performed.** Successful transport inspection is not `READY`. R1 full reboot/fault recovery and R2–R6 acceptance remain open.

## Operator lab smoke test evidence — 2026-10-12 (supersedes prior offline state)

**Transport-only smoke test PASS on disposable hosts; R1 protected-runtime release remains HOLD.** On Amsterdam LAB Core `107.189.16.36` and reinstalled Frankfurt LAB Edge `216.126.229.12`, the operator reported both pinned staged `up.sh` scripts were invoked locally, **outside the proposed shared-6G protected launcher** (no bot DB, PAM or BootGuard exists on this lab Core). Both returned `TRANSPORT: VERIFIED`, `DEFAULT_ROUTE: UNCHANGED`, `IP_RULES: UNCHANGED`, `LAB TRANSPORT PASS`; neither attached a customer UID. On Core, `ip netns exec nvl-egress-lab1 curl -4 --noproxy '*' --max-time 15 https://1.1.1.1/cdn-cgi/trace` returned `ip=216.126.229.12`, and root-route `ip -4 route get 1.1.1.1` continued to select `via 107.189.16.1 dev eth0 src 107.189.16.36`. A standalone `wg latest-handshakes` output was not supplied; the successful namespace HTTPS egress is strong transport-path evidence but not a separately logged handshake timestamp.

Earlier, the pinned Git checkout `06d10e9cceae38c8519834e69ac3a2717ef8c18b` produced 20/20 R1 lab tests PASS on **each** host, disposable marker/Stage offline probes PASS on both, Core SSH host-key pinning PASS for both host keys, and distinct restricted `probe` SSH access from Amsterdam Core to Frankfurt Edge and to Core loopback/public address returned `OFFLINE_VERIFIED`. Restricted keys were still `probe`-only; the transport smoke test did not exercise SSH agent `start` authorization.

**Important current live state:** both LAB transport interfaces may now remain **UP but unmanaged/not boot-persistent**. Do not rerun `up.sh`, run `start` with fake guard or lease, enable the staging systemd unit, reboot expecting recovery, run any `down.sh`, or assume production customer fail-closed semantics without a fresh read-only ownership/lease assessment. Actual 6G journal/schema, account/PAM gate, UID BootGuard, safe reboot and outage tests, external SSH customer and DNS/IPv6/BadVPN leak checks remain OPEN. No production hosts, accounts or DB were intentionally changed. Do not classify the lab Edge `READY`. For efficiency do **not** repeat the already successful network smoke test unless code/hosts change.

### Operator lab UID-route smoke proof — 2026-10-12

On **disposable Amsterdam LAB Core 107.189.16.36**, operator provisioned a **locked, no-login local user** `nvlr1test` (UID `1555`) and applied the F1 `BootGuardApplier` in default-deny state (table `1791`, UID selector priority `1780`) with terminal blackhole. The operator reported `LAB GUARD PASS`, `EGRESS_TABLE: BLACKHOLE ONLY`, `CUSTOMER_READY: NO`. The account had no SSH login shell and no password, and **no PAM/6G runtime was installed**.

The operator then ran a **temporary manual single-UID attach/detach smoke test** on the existing LAB transport; observed console output was:

```text
GUARD: VERIFIED
BEFORE: BLACKHOLE
UID_PUBLIC_IP: 216.126.229.12
UID_EGRESS: PASS
ROUTE_RETURNED_TO_BLACKHOLE: YES
AFTER_DETACH: INTERNET_BLOCKED
CUSTOMER_READY: NO
===== UID ROUTING LAB PASS =====
```

Interpretation: IPv4 requests issued as the specific disposable UID traversed the Edge and later failed after exact UID default-route detachment, while a terminal blackhole remained. The test used a pinned literal-IP HTTPS probe (not DNS resolution) and did not involve an SSH customer session, live 6G journal, PAM gate, DNS service or boot management. **It does not prove no IPv6/DNS/privileged-helper leakage, BadVPN, real link-loss fail-close or reboot behavior**. This smoke proof should not be repeated unless the topology/code changed. Guard is currently armed and the `nvlr1test` route is DENY/BLACKHOLE; do not treat this as an enabled customer account. Production remains untouched.

Current remaining release blocker is not WireGuard connectivity but **integration** of real shared F2/6G DB/lease, verified PAM SSH session admission, boot-persistent guard and recovery/fault E2E. No fake lock, hand-inserted `RUNNING` journal, unguarded SSH account activation or production cutover is authorized.
