# D1-C2B3 + D1-C2C — Pinned SSH stage and disposable shadow egress lab

**Status:** Implemented on Draft PR #80; opt-in code and unit tests only.
**Not connected to bot runtime; not merged or deployed to Production.**
No SSH customer UID routes, DNS, existing ingress `wg0`, Core default route, or customer ownership are changed.

## Purpose

Keep SSH authentication on Core, while eventually providing each protected SSH
user with the assigned Edge's public IPv4 as its outbound address. These two
steps produce an isolated, host-local preparation and *shadow* packet-path
experiment. They deliberately do not mark an Edge READY or move customers.

## Deliverables

- `edge_egress_ssh_transport.py`: explicit `EgressSSHIdentity` with a
  mandatory pinned SSH host-key SHA256 and keyfile authentication.
  `PinnedEgressHostPort` implements the four existing `LocalHostPort` methods
  consumed by `prepare_edge_stage_only`. `EgressLabHostFactory` binds exactly
  one Core identity and one Edge identity; it is never registered automatically.
- `ops/edge_egress_host_worker.py`: finite command allowlist, run through
  `python3 -` on the verified remote SSH host. Reviewed Python source is
  streamed from the repository to the host **over SSH stdin**: no persistent
  agent install, generic shell-executor endpoint, SFTP upload or password.
- Host-local WireGuard key creation with `wg genkey`/`wg pubkey`.
  The controller receives only validated **public** keys. The remote worker
  reads the local private key only to assemble the role-specific `wg.conf`.
- New `owner_token` inside atomic stage manifest. Cleanup is token-scoped and
  refuses a prior stage with a different owner. Stage directories and key files
  are root-owned with restrictive permissions.
- Opt-in **lab-only** verbs to run the **dedicated shadow** `up.sh`/`down.sh`
  and run `curl -4` from the Core egress namespace to `https://api.ipify.org`.
  `activate_and_prove_lab_shadow` starts Edge, then Core, verifies the observed
  public IPv4 equals the configured Edge public IPv4, and attempts scoped
  stop on failure.
- `inspect_lab_shadow_after_restart`: read-only stage-presence diagnostics
  on each host. It never marks ready, releases the 6G lock, or guesses cleanup.

## Connection model

The existing `Existing6GPreparationAdapter` still defaults to
`NoLiveHostTransport`. Test harnesses may explicitly construct:

```python
factory = EgressLabHostFactory(
    core_identity=core_ssh_identity,
    edge_identity=edge_ssh_identity,
    activation=False,
)
bridge = Existing6GPreparationAdapter(
    db_conn, acquire_existing_6g, update_existing_6g,
    host_factory=factory,
)
# Use only with a disposable DB and isolated hosts:
result = await prepare_edge_stage_only(
    bridge, spec=spec, source_host=source_edge_public_ip
)
# Result is STAGED, not READY; no network interfaces are started.
```

`activation=True` is a **separate explicit option**. It is not enabled by
the stage coordinator. Two disposable hosts with actual root SSH, the expected
host-key pins, required `ip/wg/iptables/ss/curl`, and a lab database are
required. Only after Stage succeeds, call
`activate_and_prove_lab_shadow(spec, core=..., edge=...)`. On success,
shadow resources remain running for observation; call
`stop_lab_shadow(...)` explicitly at the end.

## What was verified

- Local CI runs `test_edge_egress_*.py` on Python 3.11/3.12.
- Negative fingerprint/config checks, remote stream syntax, no private key in
  the SSH payload, activation default-off, wrong external IP rejection,
  Core/Edge cleanup ordering, and cleanup-uncertain signals.
- Existing separate ephemeral kernel WireGuard/NAT lab remains active.

**Not yet verified:** a real SSH handshake via this new implementation against
two separate disposable VMs, actual public Internet egress, remote systemd
enable/reboot, migration from a live Edge, and reliable operator recovery of
orphaned Stage files after process crash.

## Follow-up gates

1. Run the new transport against two disposable Linux VMs using out-of-band
   authenticated SSH host-key pins. Inspect SSH host-key mismatch, timeouts,
   stage permissions, restart/crash and independent remote IP proof.
2. Complete the durable, operator-approved **Phase 6G RUNNING lock** startup
   reconciler and orphan stage cleanup. The read-only inspection added here
   does **not** automatically repair or release ambiguous operations.
3. Implement dedicated WG systemd lifecycle/rekey and repeat actual VM reboot
   tests before considering a persistent READY/VERIFIED state.
4. D1-C3: per-UID terminal fail-closed routing, IPv6/DNS controls, no fallback
   to the Core's public IP, and isolated single-client proof.
5. D1-D: unify manual Edge switches and 6G/6H auto-failover with the same
   transaction and Edge-only DNS handoff.

**Production gate:** Do not merge/deploy PR #80, enable protected mode,
run generated network scripts on existing Core/Edge, or touch production
WireGuard `wg0`. Encrypted offsite backup and restore rehearsal remain
outstanding according to the current Egress production review.
