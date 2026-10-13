# NVL Bot

## Current K2 status — 2026-10-13

**Start here:** [Agent Handoff / Release Readiness](docs/NVL_K2_AGENT_HANDOFF_2026-10-13.md) → [AGENTS.md](AGENTS.md) → [Project Memory](docs/NVL_PROJECT_MEMORY.md).

GitHub `master` at the last verified feature baseline `22eba3cda13c0c72407bd3d55d7328ae93496d25` contains merged K2 Phase2 and **P3-A through P3-F** (PRs #112–#118). Admin Edge Telegram UX is minimal/two-column Persian, but the **latest P3 features have NOT been deployed to Production**. P3-A–E still lack a reviewed concrete live privileged worker and release authorization. Independent disposable full-VPS **F4/PAM/boot/DNS/IPv6/tunnel-loss acceptance [#106](https://github.com/DenaSon/nvl-bot/issues/106)** and guarded rollout/integration [#108](https://github.com/DenaSon/nvl-bot/issues/108) remain OPEN. Do not enable protected-mode, automatic 6H, Cloudflare cutover or kernel teardown from merged source alone.

The New York `e7` VPS was removed; its ingress registry/F3 metadata were manually retired with backup, **not** its Core kernel resources. Never unfence test UID1644 or modify the working Core ingress/default/other UID routes without independent fresh read-only audit.

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
