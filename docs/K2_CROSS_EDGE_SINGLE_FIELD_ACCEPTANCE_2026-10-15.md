# K2 Cross-Edge Single: Acceptance Contract (2026-10-15)

**Release classification: source-only / LAB HOLD. Not production-ready.**

## Invariant

A superadmin can select exactly one legacy SSH user and an Edge different
from the authenticated current SSH ingress in the **existing** Telegram
wizard. After an independently witnessed and safely committed operation,
the selected UID's *external IPv4* must equal the selected target Edge IPv4.
The SSH login ingress and historical account fields remain unchanged.
No other UID, default route/Edge, global `edge_egress_protected_mode`,
DNS setting, host pool, WireGuard peer or traffic is migrated implicitly.

## Source-controlled acceptance (verified by GitHub Actions)

- SINGLE is strictly gated at M3, M4 PREPARE/CONFIRM, M42 signed F4,
  the actual original P3/6G execution ticket and the typed Cross-Edge UID
  adapter. Mode 0 is not silently promoted to global protected mode 1.
- Original F2 tracks exactly one UID through BLOCKED, ROUTED_UNVERIFIED,
  PROTECTED, and freezes on partial failure. Root-only PAM policy is staged
  before the F2 committed generation is accepted by login admission.
- Signed independent ingress PAM record includes exact OS UID, remote WG
  address, Edge IP and WG public key; it is rechecked against live `wg0`.
  `ssh_accounts.host` is historical metadata, never current source proof.
- M42 postcommit accepts only the known protected-target/source-drift M1
  pair while the **exact same nonce-bound P3 6G ticket** is still RUNNING.
  Any changed nonce, policy, UID, peer, Edge or final F4 evidence is HOLD.
- Single socket readback is one Telegram poller, peer-credential checked
  Unix IPC, one-shot actor/chat approval, durable original 6G and M4 checkpoint.
  Untyped synthetic UID ports are blocked *even with* all internal flags
  patched on in hermetic tests. Synthetic host success is **not** evidence
  of real VPS success.
- All production toggles remain OFF. Batch remains OFF.

## Mandatory host acceptance — still unresolved

1. **Existing bot compatibility:** inventory all privileged historical
   `bot_final_v49-2.py` functions and prove that a *single* Telegram poller
   can run under a static nonroot UID with reviewed host-authority paths.
   Do not change `nvlbot.service User=` simply to make the socket work.
   In a disposable lab, run the *read-only*, always-HOLD audit
   `python3 -B -m ops.k2_m4_cutover_audit --source-root /path/to/reviewed/release --bot-uid UID --ipc-gid GID --details`
   and separately exercise all legacy admin, sales, SSH and health functions.
2. **Reviewed root composition:** physically bind root-only admin policy,
   the original shared-6G DB callbacks, fixed source M2/P3 plans, one-shot
   root worker/IPC, the live root-owned PAM+WireGuard reader, the target
   F4 evidence and genuine independent packet/neighbor witness. The
   installed `ops/k2_m4_root_daemon.py` main deliberately returns 78.
   Do not change that behavior before all of these are reviewed.
3. **Preflight safety:** disposable Core and new Edge, exact root-owned
   SHA256 release manifest, root-only HMAC key, static UID/GID IPC identity,
   pinned PAM module and SSHD `UsePAM`, rescue console, one canary account,
   no active sessions or other processes of that UID, no orphaned guards
   or mixed generations, normal legacy mode and 6G idle.
4. **Offhost F4 packet evidence:** an independent observer, not a local
   `curl` or a green root response, must witness the test user's SSH/SOCKS
   egress, DNS/NSS/IPv6 absence of Core leaks, correct IPv4 target, WG
   return path, neighbor UID isolation, and complete negative raw captures.
5. **Single live canary:** before/after record exact canary UID, ingress
   PAM RHOST+WG public key, original F2+6G/M4 journals, socket actors,
   `ssh_accounts.host`, old/global Edge, DNS settings and neighboring UIDs.
   After operation, **client-observed external IPv4 == target Edge public
   IPv4** and **not Core public IPv4**. The login ingress must still work.
6. **Failure injection:** drop WG/Edge, induce DNS/IPv6 leak, interrupt
   root daemon mid-execute, expire F4, cancel Telegram after confirm, reboot
   Core, restart original bot; demonstrate per-UID deny/freeze, no automatic
   Core fallback, no secret log exposure, and persistent UNKNOWN_INFLIGHT
   until manual reconciliation. No repeat/next UID while 6G is uncertain.
7. **Batch decision:** only after all six steps have independently signed
   results may a separate operator review the ≤10-UID sequential batch
   release. Never auto-enable batch on a successful single test.

## What “ready” means

**Ready for hermetic/code review:** green, exact-head CI with the complete
typed original P3/F2/M1 suite. **Ready for an isolated VPS exercise:** only
after the real Root worker/nonroot poller composition and its actual
offhost witness are approved, and a disposable Core/Edge can be used without
risking production. **Ready for production Single:** only with documented
passing physical canary and failure tests. **Ready for Batch:** separately
approved after Single field acceptance.

**Current answer: NO — this phase is not yet operationally ready.**
No merge, release switch, deployment, other UID migration or batch is
authorized by this document or a green CI alone.
