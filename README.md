> **Health Center plan / 2026-10-20 (documentation only):** [HD-01/HD-02 MVP roadmap](docs/HEALTH_CENTER_HD01_HD02_ROADMAP_2026-10-20.md) and [MCI-specific SSH incident record](docs/HEALTH_INCIDENT_2026-10-20_MCI_EDGE.md). Existing Check-Host `CLEAR` is TCP-only and is **not** proof of MCI/Rightel SSH authentication readiness. Health must not write DNS, host/Edge state, accounts or trigger 6H; these phases are PLANNED, not implemented/deployed.

> **Core deploy update — 2026-10-14:** The operator reported a successful **code-only VPS publish** of SHA `d5ca38b6e7069d969d8aa33bcb42ef71c8c63b2a` on `CloudVPS121849`: 8 root Python files replaced, 13 added, 70 code hashes passed, nvlbot restarted and held a stable PID for 10 seconds. **Independent post-deploy host checks / Telegram UI smoke remain pending.** This is not an approved protected UID egress deployment or customer migration. See [exact Core recovery paths and next tests](docs/NVL_K2_CORE_CODE_RELEASE_RECORD_2026-10-14.md). Historical “not deployed” text below only describes pre-2026-10-14 state; do **not** run the one-shot deploy again.

# NVL Bot

## Current release / K2 project state — 2026-10-14

**Source of truth:** [K2 current handoff](docs/NVL_K2_AGENT_HANDOFF_2026-10-13.md), [Production SSH deployment runbook](docs/NVL_K2_PRODUCTION_SSH_DEPLOY_RUNBOOK_2026-10-14.md), [AGENTS.md](AGENTS.md), [Project Memory](docs/NVL_PROJECT_MEMORY.md).

PR #120 (K2 Phase1/2/3 source integration) and PR #139 (first-UID PAM/BootGuard installer, SHA-reviewed Python module staging and real Linux P3-A/P3-C worker constructor) are **MERGED to master**. Source baseline before the latest documentation follow-up: 331fd86e399bd18e2f524071edb7f14d099e00de. Exact-head PR #139 CI: 1,531 Python tests and 789 Edge Safety tests **per Python 3.11 and 3.12** passed. Confirm final master SHA and green CI at release time.

**Master merge is NOT a VPS deploy.** No live Core/Edge/UID/PAM changes or independent end-to-end F4 packet/boot acceptance are evidenced by these merges. The new UID worker and installer default OFF and are not reachable through an automatic bot execution callback. The module installer handles only the **first disposable UID**; multi-UID roster CAS, root/SSH rescue, real Linux/SSH SOCKS, DNS/NSS/IPv6 no-leak, WG-loss, cold-boot recovery and production canary remain gating work (#106, #108). Never activate global protected mode, alter operational wg0, reset the 6G journal or move active customers simply because CI is green.

**Next action:** Gate 0 **read-only** Core inventory, independent Core+Edge provider snapshots and off-host encrypted backup/restore verification, immutable pinned source staging; then approved **code-only SSH deploy**, then a separate **new Edge namespace IP trial via the existing Telegram admin wizard**. Protected UID physical acceptance begins on a disposable Core clone, not existing customers. See the canonical runbook.

## Historical repository introduction (superseded next-step notes below)

Private production repository for the NVL Telegram bot and its server-management tooling.

## 🔖 Current priority — SSH Egress V1 (2026-10-12)

**[Canonical scope, verified test evidence and next Production read-only step](docs/SSH_EGRESS_V1_PRODUCTION_SCOPE_AND_EVIDENCE.md).** The only current objective is for one controlled Production SSH/SOCKS account to exit through **the exact same public Edge IP it entered through**; diagnose routing/NAT/WireGuard first. No new 6G/6H development, no new control-plane/PR #92 work, and no production mutations without an independently reviewed P0 report and explicit operator approval.

**Historical handoff (F1–F4/R1–R6; safety and evidence reference, not the active plan):**

**Start here for ongoing SSH Edge Egress work:** [Canonical Egress handoff](docs/EDGE_EGRESS_CURRENT_HANDOFF.md).

F1–F4 code and CI fixes are merged. Production customer SSH Egress is **NOT enabled or accepted**: adding an Edge or migrating an SSH account currently does **not** change its Internet egress IP. Continue with the remaining live VPS readiness gates in [Issue #88](https://github.com/DenaSon/nvl-bot/issues/88); do not repeat completed stage-only tests or deploy UID/PAM/route changes before independent recovery and E2E acceptance.

## Current status

This repository was initialized from the production audit performed on 2026-09-30.

The production source is being imported as a **sanitized baseline**. Runtime secrets, databases, private keys, logs, backups, and production-only credentials must never be committed.

## Repository layout

- `bot_final_v49-2.py` — main bot application (sanitized production baseline)
- `requirements.txt` — Python packages captured from production
- `systemd/nvlbot.service.example` — secret-free systemd example
- `.env.example` — runtime environment variable template
- `docs/AUDIT.md` — audit findings, fixes, and technical debt
- `docs/PRODUCTION_BASELINE.md` — provenance and baseline notes

## Change workflow

Production changes should follow:

`branch -> review diff -> compile/test -> commit/PR -> controlled deploy -> verify/rollback if needed`

Do not commit production credentials or database files.
