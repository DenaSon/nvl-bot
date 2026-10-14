# K2 P3 — Package 1 PAM/BootGuard and Package 2 UID worker (2026-10-14)

## Implementation and release boundary

The **original Core Linux account** stays on Core with unchanged username, UID, password, ingress source, default Edge, Cloudflare and operational `wg0`. The purpose of the new code is a single, independently witnessed **Legacy→PROTECTED egress UID** on its **existing source Edge**. This is not a global source→target cutover.

### Package 1 dependency staging: `ops/k2_p3_module_stage.py`

- Fixed source directory `/root/nvl-release` and fixed target `/opt/nvl-egress`, with a reviewed per-file SHA256 map and a pinned whole-bundle digest. Every transitive local `edge_egress_*.py` and `ops.edge_egress_*.py` import must be part of the bundle. No `bot_final_v49-2.py`, .env, binaries, private keys or arbitrary shell entrypoints.
- Code is root-owned but intentionally **0644 under 0755 directories**, because the `nvl-egress-dns-<username>` Systemd service runs as the non-root Linux UID and must read its Python modules. This is not a secrets deployment mechanism.
- Existing modules cause HOLD rather than an overwrite. Partial stage is reconciled manually; no automated uninstall or unsafe restart. Both the per-file SHA map and the bundle digest must be independently reviewed and retained off-host, not generated from an untrusted working tree during the release operation.

### Package 1: `ops/k2_p3_guard_installer.py`

- Pure `plan_guard_install`: validates exact Linux UID, reviewed PAM SHA, exact one-UID `PROTECTED_BOOT_GUARD` bytes and no duplicate roster identity; renders root-only V1 roster and existing per-UID isolated guard + DNS systemd units.
- `apply_guard_install`: opt-in/root only, requires independently confirmed OOB console and idle UID, independently SHA-pinned **already deployed** V1 PAM module at `/opt/nvl-egress`, and untouched PAM baseline. All paths are fixed, newly created artifacts use `O_EXCL/O_NOFOLLOW`, and PAM replacement performs a second content CAS. It first writes roster and manifest (persistent deny for selected canary), writes isolated service files, runs only `systemctl daemon-reload` and `enable --now` of the **selected** guard and DNS units, checks exact UID freeze, then writes PAM **last**. **NEVER restarts global ssh.service, flushes tables, disables existing users or silently removes guards on errors**. Crash between stages is manual recovery; no blind retry.
- Explicit **first-UID** installer only. Existing protected-roster updates require a separate CAS design; it intentionally refuses an existing roster instead of overwriting other users. The initial bootstrap contract handles **one disposable canary UID**, not the entire production population. Dependencies (root-owned `/etc/nvl-egress`/protected, pinned `/opt/nvl-egress` Python modules, root-owned service directory) must be preinstalled/reconciled independently. It does **not** automatically deploy the full Python import tree, claim a working production PAM login, or make a cold-boot pass. An incompatible existing PAM account stack is HOLD until reviewed; independent root/nonroot SSH rescue remains mandatory. The pre-change PAM bytes are archived as an owner-only file, before the final compare-and-swap edit. Exact per-user `sshd -T -C` with `UsePAM yes` is required before staging any host artifact.

### Package 2: `ops/k2_p3_uid_worker.py`

- One-shot `prepare_live_source_uid_worker` uses original `Existing6GGuardedExecutor`, `SameEdge6GUIDRuntimeStore`, `GuardedSourceEnrollmentPort`, `GuardedProtectedUIDPort` and the already existing concrete `LocalLinuxProtectedRuntimeKernel`. There is **no new DB lease or competing routing engine**.
- Requires root, explicit release, exact actor/chat ticket, verified F4/BOOT/NO-CORE gates in `FreshEvidence`, unchanged entire Legacy source cohort, complete pinned roster, matched live OS UID and independent packet/DNS/IPv6 + neighbouring UID observers. Refuses absent observers and fake non-Linux kernel ports.
- Runtime `IndependentSafety` inspects real `sshd -T -C`, V1 PAM/module hash, F4 source witness, actual WireGuard `wg0` peer identity, root-only manifest/roster, live UID process/session inventory and protected kernel guard; independent packet and other-UID evidence MUST be provided externally. Existing P3-C writes BLOCKED before host mutation; wrong public egress or packet proof invokes UID fence and persistent 6G recovery HOLD.
- `WORKER_ENABLED=False` and `INSTALLER_ENABLED=False` by default. **No Telegram execute handler, root schedule, server startup or unattended deployment is registered.** These are source/operator construction paths, not a claim that live Core/Edge F4, no DNS/NSS leak or systemd boot has been witnessed.

## Test boundaries

```bash
python3 -m unittest tests.test_edge_egress_k2_p3_guard_installer tests.test_edge_egress_k2_p3_uid_worker -v
python3 -m unittest discover -s tests -p 'test_edge_egress_*.py' -v
```

The tests also cover reviewed Python import closure and no-overwrite code staging, plus real temporary SQLite from the original K2 source enrollment, actual BootGuard manifest and V1 roster renderer, fake root host ports and fake Linux kernel subclass. No physical VPS was touched. **Do not set release flags or merge onto a running Core just to test.**

## Still must be proven before Production UID canary

- Independently reviewed `/opt/nvl-egress` module dependency deployment + exact hashes, root-only directories, first-canary roster construction and systemd ordering on a disposable clone. V1 PAM's fail-closed behavior for mixed Legacy + protected accounts must pass real SSH/password and direct-tcpip/SOCKS tests and root/admin rescue.
- External packet capture validating **both UDP/TCP DNS, NSS helpers and IPv6** without Core IP exposure, including dedicated WireGuard failure and cold-boot deny-before-SSH. Probe callback objects are not cryptographic F4 proof; complete operator evidence must be examined and recorded.
- Signed off non-root admin recovery, independent volume snapshots of Core and Edge, clone restore, single UID crash/replay/HOLD and safety of other active subscribers.
- Separate bounded reviewed Telegram execute integration (package 3); no live end-user migration until this and F4 accepted. Issue #106 and #108 stay OPEN.

**No claim here that packages 1 and 2 are deploy-ready for a running subscriber Core.** These increments implement the narrow code contracts but operational acceptance is intentionally withheld.
