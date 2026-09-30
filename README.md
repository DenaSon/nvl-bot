# NVL Bot

Private production repository for the NVL Telegram bot and its server-management tooling.

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
