# Repository guidance — NVL

## CURRENT PRIORITY — SSH Egress V1 (2026-10-12)

**Mandatory first read:** [SSH Egress V1 scope and verified evidence](docs/SSH_EGRESS_V1_PRODUCTION_SCOPE_AND_EVIDENCE.md).
This is the canonical source for **current scope, past real-host test results, blockers and the next action**.
Older [EDGE_EGRESS_CURRENT_HANDOFF](docs/EDGE_EGRESS_CURRENT_HANDOFF.md), F4 and [Issue #88](https://github.com/DenaSon/nvl-bot/issues/88) remain **historical evidence and safety references**, NOT instructions to resume expansive R1–R6 work.

**Latest read-only bot audit:** canonical V1 document **§12** records the existing `hp_addedge` ingress `wg0` + DNAT wizard, `hpdef_*` host default, `srv_mkactive_*` Cloudflare/DNS active relay, and the critical distinction from UID Egress routing. Preserve these flows; NEVER recreate Edge provisioning or assume UI “active relay” == egress-ready. P0 must first identify the actual account's ingress Edge.

Scope lock:
- **First priority:** fix the **outgoing IPv4 of one controlled SSH/SOCKS session on actual Production** to equal **the same account's genuine INGRESS Edge IP**. Do not confuse observed experimental Frankfurt Egress with the earlier `nvl0557` ingress IP.
- **P0 only until explicit approval:** narrow read-only inventory of actual Core, selected ingress Edge, routing/NAT/WG and candidate identity; report root cause and minimal exact delta BEFORE changes.
- **6G/6H:** no new development or integrations this round. Preserve the existing running mechanisms and shared-lock/fence invariants; DO NOT bypass any existing locks.
- **PR #92:** Draft/unmerged and frozen. LAB Amsterdam bootstrap/PAM/admin-root login are not Production customer SSH proof.
- Do not install Production PAM, toggle protected mode, edit public DNS, modify `wg0`/global route, move live users, stop shared Edge, or reboot without independent recovery, rollback, specific approval.
- Do not recreate F1–F4 or prior namespace/loopback SOCKS tests. Do not treat `STAGED`, CI green, local CURL, or an Edge **different from the ingress Edge** as success.
- Keep normal Core-terminated SSH/Marzban/Wallet/Bot/monitoring functioning, and never copy customer DB, live credentials, WireGuard private keys or raw sensitive dumps into Git/chat.
- After each **actual new** Production read-only observation, update the canonical V1 evidence document with date, measured facts, unresolveds and next gate. No unsolicited scope expansion.

## Historical context / safety controls (read second)

- Production has Core-terminated SSH and a legacy WireGuard `wg0` ingress relay. Assigning `ssh_accounts.host` does **not** change Linux internet egress.
- The earlier isolated SSHD/SOCKS pilot exited through Frankfurt Edge, but did **not** prove ordinary public SSH or equality with that account's ingress Edge.
- R1–R6, signed F4 acceptance, multi-user Failover, global bot automation and BadVPN are deferred scope; preserve their safety blockers for any future release.
- Historical version labels in `docs/NVL_PROJECT_MEMORY.md` are **not live deployment attestation**. Read-only verify the actual current Production build before any deployment.
