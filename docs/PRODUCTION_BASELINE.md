# Production Baseline

Audit/export date: **2026-09-30**

Source archive SHA-256:

`9b0af5f6a016b1e2af854b7278b6980e9ba0f1bbafe3eab561a13edc6b212ef8`

Production Python source SHA-256 before repository sanitization:

`fac1cdcc89b1c33e4c8315660727712c350483c62fb95950c5b1b9f093ce6213`

Sanitized repository Python source SHA-256:

`b79fe0f6024f751fe0ac460caa11cf194a91eb9caeba4fb926382893e79ece18`

The production export contained **12,765** lines. The sanitized repository source contains **12,770** lines because credential bootstrap code was converted to environment-based configuration.

Initial sanitized source import commit:

`0935bed1d083801ad2c96360d28c5de9e46766bb`

## Important sanitization note

The production export contained operational credentials/default secrets that must not be committed, including:
- a hardcoded fallback confirmation password
- hardcoded Marzban bootstrap credentials
- live environment values in the exported systemd unit

The repository source therefore intentionally differs from the exact production snapshot in those credential/configuration locations:

1. `RB_CONFIRM_PASS` is environment-only and has no hardcoded fallback.
2. Marzban bootstrap values are read from `MARZBAN_URL`, `MARZBAN_USERNAME`, and `MARZBAN_PASSWORD`.
3. Marzban bootstrap uses `INSERT OR IGNORE` so an absent environment value does not overwrite existing database configuration.
4. The committed systemd unit is an example using `EnvironmentFile`; live production environment values are excluded.

Do **not** replace production from this repository until the runtime environment migration for these values is completed and validated.

Production database files, Telegram persistence, SSH/WireGuard private keys, logs, and backups are intentionally excluded.
