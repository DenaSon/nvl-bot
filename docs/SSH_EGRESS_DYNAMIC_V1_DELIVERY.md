# NVL — Dynamic SSH Egress V1 / implementation handoff

**Date:** 2026-10-12. **Status:** F1 merged to `master` via [PR #93](https://github.com/DenaSon/nvl-bot/pull/93), commit `0e9d976129cccbd47cb3ab6f9d14f93de468a64d`. **Product scope:** only Core-terminated SSH/SOCKS same-Edge IPv4 egress, fail-closed, frequently changing 6H active ingress, lifecycle of new Edges and safe incremental customer rollout. No Marzban, sales, Xray, wallet, extra controller or rewriting 6G/6H.

## Current real Production evidence (historical snapshot)

- Core `209.200.246.198`; Miami Edge `144.172.84.76`; dedicated live `wg-nvl-mia1`, Core `nvl-egress-mia1`, UID `nvl-egc1=1690`, routing table `1781`, terminal blackhole.
- `curl` under UID and ordinary **Windows → Miami:2252 → Core SSHD → SOCKS** both observed public egress `144.172.84.76`. Deleting only the user table's dedicated default led to `FAIL_CLOSED=PASS`; restoring it led to `EGRESS_RECOVERY=PASS`. Neither result attests WG peer-death behavior, DNS/IPv6 or reboot.
- Latest operator observation: `wg0` on both hosts is enabled. On Miami, **zero** `nvl-egress*` systemd units. On Core, only three unrelated `nvl-egress-pilot-*` static units; no managed Miami transport unit. Core `ssh.service disabled` but `active` (socket-activation behavior **not established**); `nvlbot enabled/active`, `wg-quick@wg0 enabled`. Do not modify SSH service enablement.
- Existing Miami Egress is **manually started**, and UID 1690 routing/IPv6/DNS guards were **manually added**. They are **not safely reboot persistent**. In particular, if UID selector disappears on boot the Canary may use the Core main default; **do not reboot Production or onboard customers before guard/admission gating**.
- Core local backup verified: `/root/nvl-egress-backups/core-20261012-153159-0MgVNi`. No verified offsite restore. Full evidence: [canonical V1 §14](SSH_EGRESS_V1_PRODUCTION_SCOPE_AND_EVIDENCE.md).

## Delivery stages (finish development first, deploy once, validate with a NEW Edge)

| Phase | Deliverable | Current |
|---|---|---|
| F1 — dedicated transport supervisor | One idempotent, hash-pinned, per-Edge state probe / start, simple offline systemd unit renderer; never uninstall active resources | **Merged / focused CI PASS and existing Python checks PASS** |
| F2 — fail-closed boot and admission | Persist deny-first protections for selected users, safe recovery and service ordering, without global ssh.service dependencies; account lockdown where UID rule is absent | Not implemented |
| G — shared-Edge multi-UID | Attach/detach individual UIDs without freezing Edge-wide default; reuse sole 6G lock/journal, no second DB/controller | Not implemented |
| H — session-to-ingress ownership | Pin actual SSH sessions to real ingress Edge; prohibit ambiguous same-UID multi-Edge access until a verified per-session method exists | Not implemented |
| I — Edge onboarding | Extend existing `hp_addedge` ingress wizard with separate dedicated Egress allocation/stage/readiness, no changes to operational `wg0` | Not implemented |
| J — 6H integration | Manual and automatic active-relay switch must check Egress readiness and preserve old-session mapping; deny protected sessions when target unready | Not implemented |
| K — deploy + acceptance | One reviewed deployment after code complete, NEW Edge onboarding E2E, two-Edge switch, limited users, observed egress and negative-failure proof | Not started |

**Boundary:** Production customer migration is forbidden until F2 and the shared-table/ingress ownership path work. Avoid blanket re-running past tests. Build lightweight unit tests for each new behavior. Keep the existing `python-checks.yml` unchanged; no new heavyweight CI jobs. Each stage updates this file and `AGENTS.md` with actual implemented vs pending.

## F1 implementation (this commit, code-only)

- `ops/edge_egress_v1_transport.py`: accepts an existing generated stage directory from `ops/edge_egress_provision.py` (on Core / Miami, respectively `/root/nvl-egress-mia1-core-stage` and `/root/nvl-egress-mia1-edge-stage`).
- `fingerprint` computes a stable SHA-256 over four staged files. `inspect` and `ensure` require the same explicit digest and the exact stage role/spec. Root-only files, no symlinks, existing WireGuard peer/tunnel address, Core namespace+veth/default, or Edge listen port + labeled NAT are checked.
- `ensure`: exact already-running transport → no-op; no owned resources → explicit existing read-only preflight then stage `up.sh`; partial/mismatch → HOLD. **Never invoke down.sh or modify UID rules**, including on failed/uncertain start. The design is reusable for new Edge IDs; no Miami-specific condition.
- `render-unit`: generates a *candidate* systemd unit (OneShot with `RemainAfterExit=yes`, no `ExecStop`, no dependency on shared SSH). The agent is intended to be installed under `/opt/nvl-egress` and invoked with `python3 -m ops.edge_egress_v1_transport`; the unit is **not installed/enabled or started** by the script.
- Six small tests in `tests/test_edge_egress_v1_transport.py`: staged identity, tamper/mismatch, permissions/symlink, missing/partial, idempotency, refusal of destructive cleanup. Run: `python3 -m unittest -v tests.test_edge_egress_v1_transport`. No live network access required.

**Known F1 limitations:** The module is a transport-only component, not an installer, PAM gate or per-UID boot guard. It does not assert packets cannot leak via Core WAN and does not declare Edge `READY`. In particular the existing manually launched Canary is *not* made reboot-safe by merging or installing this module alone. A generated unit for an existing interface can only be adopted after operator verifies it is really owned by the staged Core/Edge pair. Full code delivery must complete before adding Production startup commands.

## Immediate next action

Implement **F2 deny-first boot guard/admission** next, reusing the existing F1/F2/F4 safety primitives where possible. Then G/H/I/J in order. One dedicated new test Edge will be used for the final real end-to-end acceptance; no repeated general full-lab exercise after every tiny change.

### F1 acceptance record (2026-10-12)

PR #93 **merged** into `master` after successful checks on the final PR head `28d00d6c12beb60958ea5c3d677d3ed8dd6530c6`: `Python checks=success`; `Edge egress stage-only checks=success` (Python 3.11 and 3.12). Squash merge `0e9d976129cccbd47cb3ab6f9d14f93de468a64d`. This proves only source checks, not Production persistence or feature completion. **Next F2, no deployment yet.**
