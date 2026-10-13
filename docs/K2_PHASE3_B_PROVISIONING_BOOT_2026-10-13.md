# K2 P3-B — Pinned Provisioning & Boot (source boundary)

## Scope & status
Source-only, no runtime installation, no Telegram mutation, no production
cutover. Reuses the existing `ops.edge_egress_v1_transport`,
`edge_egress_uid_systemd`, `edge_egress_v1_admission` and F4
PAM/boot review. P3-A is the **only** 6G executor and shared journal.

`edge_egress_p3_boot.build_stage_boot_review` builds a deterministic,
read-only review for an existing root-owned, SHA-pinned Core WireGuard
stage, an exact protected UID BootGuard manifest (shared-ingress
return + local DoH + explicit protected mode), isolated guard/DNS
systemd units, complete protected-identity roster review and proposed
PAM hook review. The review digest covers the full pinned EgressSpec,
service identities, boot/DNS/transport unit bytes, roster and PAM review.
Before every external action the adapter checks both the complete Stage
spec and its unchanged review fingerprint.
The roster and PAM outputs are **not installers**:
publishing a one-member roster would silently drop other customers, so
future P3-C must verify all previously protected members before update.

`GuardedStageBootPort` implements the P3-A `GuardedHostPort` interface
for **EDGE_PREPARE only**. It requires an explicitly released, injected
safety provider and trusted transport provider; none is registered
globally or through Telegram. Before each external action it rechecks:
- exact one RUNNING existing-6G operation, expected source and target;
- the P3-A **durable EGRESS_P3_EXECUTE_INTENT** journal, identical action,
  edge ID, scope hash and ticket nonce hash;
- SHA-pinned stage via existing `pinned(stage,'core',digest)` and Edge IP.
An independent `BootSafetyPort` must prove rescue access and resource
ownership, existing guarded per-UID DENY before transport, and currently
installed PAM + DNS + boot policy, not simply rendered files.
Only then may the reviewed transport port call the EXISTING
`ensure(stage,'core',digest)`; success requires `UP` observation.
No direct shell, `wg0` edits, default-route change, SSH restart or
automatic PAM file write are implemented by P3-B.
When any step becomes uncertain, P3-A's failure handler must retain
`RUNNING` with recovery marker and invoke fail-closed `freeze_owned_subjects`.
P3-B never automatically tears down interfaces used by SSH customers.

### Known safety gates, not yet waived
- Real `BootSafetyPort` must be backed by a root-only
  independent host inspector; fake/test ports do not authorize execution.
- F4 has **not** passed independent disposable VPS testing
  (root rescue, PAM account+direct-tcpip, SOCKS, NSS/DNS/IPv6,
  boot deny before SSH, tunnel-loss fail-closed and reboot).
- Operator-approved PAM edit is a separate guarded installation step.
  The existing reviewer says clearly that offline inspection cannot
  prove that PAM is called for direct-tcpip/SOCKS.
- Systemd renderer is independent of ssh.service and ssh.socket:
  `After=wg-quick@wg0.service` is ordering, not an authorization to
  change or restart wg0.
- No live `P3-B` runtime entrypoint or enabling flag is registered.
  `LIVE_PROVISIONING_ENABLED=False` and P3-A release is default-deny.
- Global protected mode remains unchanged; P3-C controls
  protected UID attachment, P3-D 6G/6H+Cloudflare, P3-E teardown,
  P3-F Telegram command path.

## Test gate and handoff
Run existing Python CI and Edge-egress stage-only CI, including
`tests/test_edge_egress_p3_boot.py`. Scenarios cover deterministic
boot review; wrong stage/spec/UID; unsafe ssh coupling; absent, foreign or
contended 6G intent; release disabled; deny-before-transport order;
mid-operation lock loss; integration with real P3-A dispatcher;
indeterminate PAM/boot, transport verification fail and recovery.

Changes are source-only and merged to master after green CI. For
next work P3-C, preserve `nvl0557` fail-closed UID1644 REJECT and
unfinished orphan e7 kernel resources on production Core.
Do not purchase a disposable VPS until B/C/D/E/F source gates close.
Issue #108 remains open; live F4 acceptance #106 remains open.
