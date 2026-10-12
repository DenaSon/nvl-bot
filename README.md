# NVL Bot

Private production repository for the NVL Telegram bot and its server-management tooling.

## 🔖 Current Edge Egress handoff (2026-10-12)

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
