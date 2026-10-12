# Repository guidance — NVL

## CURRENT PRIORITY — SSH Egress V1 (2026-10-12)

**Mandatory first read:** [SSH Egress V1 scope and verified evidence](docs/SSH_EGRESS_V1_PRODUCTION_SCOPE_AND_EVIDENCE.md).
**Latest checkpoint: §14 (2026-10-12).** Core backup verified (41M at `/root/nvl-egress-backups/core-20261012-153159-0MgVNi`), Miami dedicated `wg-nvl-mia1` up, Canary UID1690 table1781 + terminal blackhole, `curl` under UID and actual external PowerShell SSH-D/SOCKS both returned `144.172.84.76`; default-route-removal fail-closed and recovery PASS. **Persistent boot guards / user admission / actual WG-loss / DNS/IPv6 / batch rollout unproven.** Backup is local, not independently restored; no Core reboot allowed without boot safety. `nvl-egc1` password L does not disable its authorized-key SSH login.

This is the canonical source for **current scope, past real-host test results, blockers and the next action**.
Older [EDGE_EGRESS_CURRENT_HANDOFF](docs/EDGE_EGRESS_CURRENT_HANDOFF.md), F4 and [Issue #88](https://github.com/DenaSon/nvl-bot/issues/88) remain **historical evidence and safety references**, NOT instructions to resume expansive R1–R6 work.

**Latest read-only bot audit:** canonical V1 document **§12** records the existing `hp_addedge` ingress `wg0` + DNAT wizard, `hpdef_*` host default, `srv_mkactive_*` Cloudflare/DNS active relay, and the critical distinction from UID Egress routing. Preserve these flows; NEVER recreate Edge provisioning or assume UI “active relay” == egress-ready. P0 must first identify the actual account's ingress Edge.

Scope lock:
- **Current objective:** the **first production same-ingress/same-egress SSH/SOCKS Canary is verified** (`nvl-egc1`, UID 1690; Miami `144.172.84.76`); next deliver **reliable, fail-closed multi-user / multi-Edge Egress** by proving persistence, admission/boot and shared-table behavior before guarded customer batches. Frankfurt `nvl0557` evidence is historical, distinct.
- **Current Production gate:** P1-A→P1-E manually executed on Core/Miami; SSH+SOCKS, route-loss fail-closed and route restore PASS for the **single UID only**. No real customer cutover yet. Next is **read-only Boot/Systemd/PAM/6G inventory**, then reviewed protected persistence and multi-user design with disposable-VPS tests and rescue access. Do **not** reboot or roll out customers using ephemeral manual UID rules.
- **6G/6H:** no new development or integrations this round. Preserve the existing running mechanisms and shared-lock/fence invariants; DO NOT bypass any existing locks.
- **PR #92:** Draft/unmerged and frozen. LAB Amsterdam bootstrap/PAM/admin-root login are not Production customer SSH proof.
- Do not install Production PAM, toggle protected mode, edit public DNS, modify `wg0`/global route, move live users, stop shared Edge, or reboot without independent recovery, rollback, specific approval.
- Do not recreate F1–F4 or prior namespace/loopback SOCKS tests. Do not treat `STAGED`, CI green, local CURL, or an Edge **different from the ingress Edge** as success.
- Keep normal Core-terminated SSH/Marzban/Wallet/Bot/monitoring functioning, and never copy customer DB, live credentials, WireGuard private keys or raw sensitive dumps into Git/chat.
- **Update documentation only when operator explicitly asks**. Keep the canonical §14 as the latest execution handoff. Record what is measured vs. pending and avoid expanding into unrelated features.


## Dynamic SSH Egress V1 development checkpoint (2026-10-12)

**Mandatory next read:** [Dynamic V1 delivery and F1 implementation checkpoint](docs/SSH_EGRESS_DYNAMIC_V1_DELIVERY.md). User has explicitly approved completing the scoped feature in GitHub before a single controlled deployment and testing via onboarding a NEW Edge. Keep tests focused and fast, update this delivery document at every actual stage. **F1 code exists on feature branch but DOES NOT enable persistent user-safe egress**. Next implement F2 deny-first boot/admission, then G multi-UID, H session ingress binding, I new Edge wizard, J 6H, K deploy. Do not re-run past Canary experiments without cause. No unreviewed Production SSH/PAM changes, reboot or customer migrations. Historical R1 PR #92 remains independent and unmerged.

## Historical context / safety controls (read second)

- Production has Core-terminated SSH and a legacy WireGuard `wg0` ingress relay. Assigning `ssh_accounts.host` does **not** change Linux internet egress.
- The earlier isolated SSHD/SOCKS pilot exited through Frankfurt Edge, but did **not** prove ordinary public SSH or equality with that account's ingress Edge.
- R1–R6, signed F4 acceptance, multi-user Failover, global bot automation and BadVPN are deferred scope; preserve their safety blockers for any future release.
- Historical version labels in `docs/NVL_PROJECT_MEMORY.md` are **not live deployment attestation**. Read-only verify the actual current Production build before any deployment.
