# Egress Core stg1 — actual password-authenticated SSH SOCKS pilot and fail-closed evidence

**Date:** 2026-10-11. **Evidence:** operator-provided outputs from the live NVL Core staging namespace (not independent monitoring). **Release classification: STAGING EVIDENCE ONLY — no protected-customer cutover and no production deployment approval.**

This record consolidates the *distinct* runtime results established while experimenting on Draft PR #81 and the plan-only follow-up #82. It belongs alongside the broader implementation in **Draft PR #80**. Neither #81's generated local-only SSH listener nor #82's independent \`ssh_egress_intents\` table is a replacement for #80's dedicated UID mapping and **existing Phase 6G shared lock/journal**.

## Exact known pilot topology

- Core: \`209.200.246.198\`; ordinary production \`ssh\`, \`nvlbot\` and \`wg0\` are separate.
- Test Edge: \`216.126.229.12\`; dedicated WireGuard is \`wg-nvl-stg1\` in Core namespace \`nvl-egress-stg1\`.
- Namespace: \`10.78.110.2/30\` dedicated WireGuard, \`10.78.111.2/30\` veth; the only IPv4 default observed is \`default dev wg-nvl-stg1 scope link\`. IPv6 had no default route.
- Pilot's root-namespace ingress: \`127.0.0.1:22284\` **only**, proxying to namespace SSHD. This is **not public** and not boot-enabled. Original code/templates were on #81, pinned to commit \`933d54de9dda573851563da700a820e3864ddd42\`. The staging worktree used was \`/root/nvl-stage3a-review\`.
- SSH user used: \`nvl0557\` (an existing Core SSH account), not a newly provisioned production account. Avoid sharing passwords or resetting this account as part of reproducing this proof.

## Observations from user-provided production-Core terminal output

1. Git fetched the pinned #81 commit into a **separate detached Git worktree**; Python compilation succeeded, the seven Stage 3A unit tests passed, generated manifests passed \`sshd -t\`, and existing \`ssh\` and \`nvlbot\` remained \`active\`.
2. Preflight namespace HTTPS returned public \`216.126.229.12\`. The isolated SSHD and loopback proxy socket started successfully. \`ssh-keyscan\` and the pinned host key matched, and \`ss -H -ltn\` showed a listener **only** on \`127.0.0.1:22284\`; no public port was opened.
3. Interactive **real password** authentication for \`nvl0557\` succeeded through the localhost proxy, with an SSH \`-D\` SOCKS tunnel. A \`curl\` through \`socks5h://127.0.0.1:31884\` returned \`216.126.229.12\`. The temporary SOCKS session was closed afterward.
4. Read-only namespace preflight reported only one SSHD listener PID, standard routing rules (local/main/default), exactly the WG default IPv4 route, and no IPv6 default. The dedicated WG \`AllowedIPs=0.0.0.0/0\` peer pointed to the candidate Edge.
5. A **separately recovery-guarded** failure experiment administratively lowered only \`wg-nvl-stg1\` inside the pilot namespace. Baseline \`curl -4\` (with resolved destination IP pinned) was \`216.126.229.12\`, and the same curl failed with the link down (\`FAIL_CLOSED=PASS\`). After \`link up\` and restoration of the namespace default route, the probe returned \`216.126.229.12\` again (\`EGRESS_RECOVERY=PASS\`).
6. The concluding readout showed the original \`ssh\`, \`nvlbot\`, and the separate pilot SSHD all \`active\`; operator output included \`STAGE3B_FAIL_CLOSED=PASS\` and \`STAGE3B_RECOVERY=PASS\`.

**Meaning of this evidence:** A specific existing SSH identity can authenticate to a **separate local-only SSHD** and originate TCP SOCKS traffic through the isolated WireGuard to the expected Edge. For one pinned IPv4 HTTPS probe, administratively lowering that tunnel caused no observed Core-IP fallback and link restoration recovered traffic.

**What is NOT proven:** Transparent switching of the customer's *existing public SSH endpoint*; default Core production SSHD user forwarding through the chosen Edge; any other account's route; persistent boot ordering; independent IPv6 packet capture; all DNS transports; UDP/BadVPN/GOST/TLS forwarding; real-world Edge loss/rekey/blackholed-peer behavior; per-user multi-Edge selection; protected 6G/6H handoff; production fail-closed under all outages. A failed curl is a single probe, not exhaustive leak certification.

## Why the parallel draft PRs must not be merged independently

- **#81:** its \`egress_pilot.py\` generates a *one-user, loopback-only, separate SSHD*. It is useful as a reproducible isolated staging harness, but it must not become an alternative customer routing architecture beside #80's \`edge_egress_uid_*\` lifecycle and boot policies. The current pilot might still be active on Core; closing its PR **does not uninstall its units**. Preserve its exact source SHA/worktree until the pilot is explicitly retired and its cleanup audited.
- **#82:** its \`egress_manager.py\` introduces \`ssh_egress_targets\` and \`ssh_egress_intents\` with a separate PLANNED/CANCELLED workflow. #80 already defines a dedicated \`edge_egress_uid_bindings\` mapping and a **shared 6G lock/journal**. Parallel mapping/journals would produce incompatible ownership and two truths for Egress operations. The #82 Telegram view also creates tables from a read/navigation callback, rather than remaining read-only. It has **no real APPLY implementation**.
- The reusable UI concept from #82 is admin-only **visibility and preparation**. Adapt it in a future patch to #80's *existing read-only status* and shared 6G transaction **without copying its schema or switch engine**. Keep protected mode and automatic 6H **OFF**.

## Release gates (remain blocked)

1. Verify reboot **on a disposable VPS/VM with out-of-band console**: guard applied before any protected SSH customer starts; DNS/systemd protected dependency; deliberate fault injection and safe admin recovery. #80's C3E QEMU SSH timeout is **NOT a passing boot test**.
2. Wire #80's guarded, boot-attested, actual-UID protected network apply, mapping CAS, and 6G/6H journal to a live operator-approved adapter, without changing \`ssh_accounts.host\` or falling back public DNS to Core.
3. Audit callback/write fences, DNS/IPv6 (packet evidence), BadVPN/UDP, long-lived connections, and rekey/reboot recovery on disposable machines.
4. Obtain encrypted offsite Core and Edge backups and a verified restore rehearsal.
5. Confirm staging assets/credentials/units and account ownership, choose whether to maintain the pilot (reviewed, loopback-only) or explicitly uninstall it, and verify no public listener is introduced.
6. Only after independent review, prepare a **fresh CI-validated integration branch** of #80 and separately test compatibility with #79 Direct Market's monolithic bot edits.

Until then **DO NOT merge/deploy #80 as production protected Egress**, enable \`edge_egress_protected_mode\`, expose \`22284\` publicly, or claim that merely changing \`ssh_accounts.host\` switches external Egress.

## Pinned references

- Implementation: Draft PR #80 \`review/edge-egress-recovery-20261011\`.
- Tested isolated pilot source: Draft PR #81 @ \`933d54de9dda573851563da700a820e3864ddd42\`.
- Avoid as a second controller: Draft PR #82 @ \`857763b2e99da72ef1f2a0cf8d075aeba566bdc8\`.
- Main release checklist: \`docs/EDGE_EGRESS_PRODUCTION_REVIEW.md\`.
- Unverified boot gate: \`docs/EDGE_EGRESS_D1C3E_VM_BOOT.md\`.
