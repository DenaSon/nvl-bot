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
