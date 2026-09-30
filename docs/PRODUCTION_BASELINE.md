# Production Baseline

Audit/export date: **2026-09-30**

Source archive SHA-256:

`9b0af5f6a016b1e2af854b7278b6980e9ba0f1bbafe3eab561a13edc6b212ef8`

Production Python source SHA-256 before repository sanitization:

`fac1cdcc89b1c33e4c8315660727712c350483c62fb95950c5b1b9f093ce6213`

The exported source had 12,765 lines.

## Important sanitization note

The production export contained operational credentials/default secrets that must not be committed, including:
- a hardcoded fallback confirmation password
- hardcoded Marzban bootstrap credentials
- live environment values in the exported systemd unit

Therefore the repository baseline is intentionally sanitized and may differ from the exact production hash at credential/configuration lines only.

Do **not** replace production from this repository until the runtime environment migration for those values is completed and validated.

Production database files, Telegram persistence, SSH/WireGuard private keys, logs, and backups are intentionally excluded.
