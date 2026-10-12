# Repository guidance — NVL

## SSH Edge Egress: mandatory orientation before implementation

Before investigating or modifying NVL's SSH Core/Edge Egress paths, **read
[docs/EDGE_EGRESS_CURRENT_HANDOFF.md](docs/EDGE_EGRESS_CURRENT_HANDOFF.md)**,
then [Issue #88](https://github.com/DenaSon/nvl-bot/issues/88) and the F4
release runbook. Update the handoff after each verified VPS result.

Key distinctions:
- **F1–F4 code is merged and CI is green (2026-10-12)**. Do not recreate those
  phases or rerun historical experiments without a concrete changed condition.
- SSH ingress Edge assignment/`ssh_accounts.host` **does not set Internet
  Egress**. Existing public Core SSH is not yet proven to exit via Edge.
- A password-authenticated SOCKS pilot **was** observed exiting an Edge through
  a separate loopback-only staging SSHD. It does not prove normal public SSH,
  reboot, DNS/IPv6/UDP, or Production readiness.
- Preserve Core-terminated authentication, existing `wg0`, global SSH and
  `nvlbot`. Use only a dedicated per-Edge WireGuard Egress dataplane with
  one existing **6G lock/journal** and fail-closed terminal routing.
- Do not install PAM, enable protected mode, rewrite global routes, migrate
  a live user, or infer a READY Edge from STAGED/VERIFIED_LAB/CI alone.
- The next milestone is **read-only VPS inventory → close R1–R6 on
  recoverable disposable VPS → guarded single-UID canary → bot integration**.
- Never commit live keys, passwords, database files, tokens or raw host dumps
  containing secrets. Record test classifications and sanitized evidence.

Historical notes in `docs/NVL_PROJECT_MEMORY.md` include outdated release
versions: **verify the current deployed version on the actual Core** before
planning any deployment.
