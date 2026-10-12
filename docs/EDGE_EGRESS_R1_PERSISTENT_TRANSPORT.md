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
