# NVL K2 — Core code-only Production release record (2026-10-14)

> **LATEST OBSERVED CORE CHECKPOINT, based on operator-supplied SSH transcript**. This record supersedes historical “merged but NOT deployed” statements **for code files only**. It does NOT prove Telegram functional smoke, new Edge traffic, physical F4, protected per-UID egress or customer transfer.

## Deployment outcome and provenance

- **State:** `K2_DEPLOY_SUCCESS` reported by the operator on Core `CloudVPS121849` on 2026-10-14. Release script completed its precheck, stopped **only** `nvlbot`, published the allowlisted root Python modules, verified the SHA-256 of **all 70 resolved modules**, started `nvlbot`, checked an active PID and stable PID over a 10-second interval. **Independent post-release host read-only audit and Telegram smoke are still pending.**
- **Exact deployed code git commit:** `d5ca38b6e7069d969d8aa33bcb42ef71c8c63b2a` (master after PR #141). This is the **staged SOURCE commit and code publication target**, not the local checkout HEAD.
- **Old live bot SHA-256**: `1e1f70fdb71e0b683d260e0ad08b7dc8426827edfa007ecaa1b871091c7bb237`.
- **New live bot expected SHA-256**: `ef65987e76cf561e4e422d037ac9a14aeb2d709d8fb9224bfdc4c8ac97560e83`. Script verified this immediately after replacement; get an **independent** hash from the Core shell.
- **Deployment file SHA-256:** `6386a4c3edf5334d3490698b09c153460c1a56133f34b387cd37a8f2681abc28`; script path **on Core** `/root/nvl_k2_publish.sh`. This is an operator-uploaded host-local script, **not a file published by GitHub master**.
- **Manifest:** 70 source-import-resolved modules, 49 unchanged, 8 replaced and 13 created; no symlinks/UNSAFE in predeploy audit. Root-level module-only changes; `ops/` remained unmodified on Core.
- **Observed stdout from release:** `PRECHECK=PASS; REPLACE=8; CREATE=13; SAME=49`, `STOPPING_BOT=YES`, `ALL_70_MODULE_HASHES=PASS`, `STARTING_BOT=YES`, `K2_DEPLOY_SUCCESS=d5ca38b6e7069d969d8aa33bcb42ef71c8c63b2a`.
- **Python:** `/root/venv/bin/python3` 3.12.3. Previous live process was `/root/venv/bin/python3 /root/bot_final_v49-2.py`, working directory `/root`, running as root; systemd `nvlbot`. Do not infer post-release process PID/start time without fresh audit. `BOT_VERSION_TAG` was identical in old and staged source, so it is **not** proof of publication.
- **Known service configuration paths:** `/etc/systemd/system/nvlbot.service`, drop-in `/etc/systemd/system/nvlbot.service.d/10-env.conf`, mandatory environment file `/etc/nvlbot/nvlbot.env`; the release script did **not** replace these.

## Core paths / where to resume

| Item | Path / state |
| --- | --- |
| Core VPS label | `CloudVPS121849` |
| Core public SSH address used by operator | `209.200.246.198` (re-verify against provider console before future connection) |
| Source git checkout | `/root/nvl-release` (last confirmed checkout HEAD `1e8f80d8e594832ec644786ee62a41b66035b891`; fetching updates `origin/master` but does not reset HEAD) |
| Final immutable code staging | `/root/nvl-k2-stage-d5ca38b6e706` |
| Earlier stage / backup script checkpoint | `/root/nvl-k2-stage-33321f5783bc` |
| Live bot executable source | `/root/bot_final_v49-2.py` |
| Original production DB | `/root/master_bot.db` — **never overwrite during code rollback** |
| Recovery plan + manifest | `/root/nvl-k2-predeploy-sJsySowp/manifest.json` |
| Eight old module copies | `/root/nvl-k2-predeploy-sJsySowp/original/` |
| Online DB backup from release preparation | `/root/nvl-k2-predeploy-sJsySowp/master_bot.sqlite3` |
| Immediate pre-code-cutover DB backup | `/root/nvl-k2-predeploy-sJsySowp/sqlite-immediate-before-release.db` |
| Actual operator release script | `/root/nvl_k2_publish.sh` |
| Generated allowlist (post release) | `/root/nvl-k2-predeploy-sJsySowp/k2-release-allowlist.tsv` |
| Earlier verified curated root snapshot | `/root/nvl-emergency-backups/core-20261014T144432Z-x4EVRH/` |
| User-reported Windows off-host download | `D:\\NVL-Backups\\core-20261014T144432Z-x4EVRH\\` — transfer reported complete; **checksum of Windows copy and independent restore drill not shown** |
| Core ingress legacy network | `wg0`; pre-release routes included `vnh-stg1`, `vnh-mia1`, `vnh-e7`, and UID routing rules `1690 → 1781`, `1644 → 20007` — **observe, never modify in this code-only phase** |

Operator confirmed provider full-disk snapshot and independent VPS console availability. Snapshot restore drill **not independently observed**. The off-host copy was transferred **without encryption at the operator's explicit direction**; keep it secured and never publish credentials, `/etc/shadow`, WireGuard private keys, SQLite backups, contents of `nvlbot.env`, or logs with tokens to GitHub/chat.

## Runtime gates just before publish — previous observations only

- Previous `sqlite3 /root/master_bot.db 'PRAGMA quick_check'` = `ok`; `failover_operations WHERE status='RUNNING'` = 0.
- `edge_egress_protected_mode=0` (OFF); `phase6h_auto_failover_enabled=1` (**legacy auto-failover was ON; do not silently disable or change**). K2 transport/relay keys were **absent** in the last reported settings query, not proven enabled.
- Core live process environment had no `RB_CONFIRM_PASS`, `MARZBAN_URL`, `MARZBAN_USERNAME` or `MARZBAN_PASSWORD`. Marzban URL/username/password **presence** was verified in SQLite `settings` (values deliberately not recorded). Old and new `RB_CONFIRM_PASS` assignments were environment-only, with no inline literal and no fallback.
- Last before-deploy source compile: 104 root + ops Python files; `pip check` clean. GitHub PR #141 CI 1,535 full and 793 each Edge 3.11/3.12 passing.
- Original Core backup initially had `ARCHIVE_ROOTS_UNTRUSTED` due to locale-dependent source sorting; corrected auditor in PR #141 accepted the **unaltered** archived snapshot: `LOCAL_CONSISTENT`, `blockers=[]`. This is **not** proof of complete live restore.
- **Post-release status UNKNOWN** until operator submits new shell audit and Telegram smoke. Do not retroactively mark these gates PASS.

## Next: post-code-publish verification (read-only)

Run on Core; do **not** rerun the one-shot publish script. Avoid outputting secrets or raw logs to chat.

~~~bash
echo "=== NVL POST RELEASE AUDIT ==="
systemctl show nvlbot -p ActiveState -p SubState -p MainPID -p ExecMainStartTimestamp -p NRestarts --no-pager
sha256sum /root/bot_final_v49-2.py
sha256sum /root/nvl_k2_publish.sh
sqlite3 /root/master_bot.db 'PRAGMA quick_check;'
sqlite3 -readonly /root/master_bot.db "SELECT COUNT(*) FROM failover_operations WHERE status='RUNNING';"
sqlite3 -readonly /root/master_bot.db "SELECT key,value FROM settings WHERE key IN ('edge_egress_protected_mode','phase6h_auto_failover_enabled','k2_p1_transport_activation_enabled','k2_p2_relay_switch_enabled') ORDER BY key;"
wg show interfaces
ip -4 rule show
ip -4 route show table main
~~~

Verify Telegram from an existing trusted admin: `/start` → `/admin`, legacy Edge inventory, `🧪 آزمایش VPS` and `🌍 تست IP سرور` only when a separately authorized, pinned and actually staged candidate exists. Never assume a green bot callback or namespace IP means real Linux user Internet egress is from Edge. Inspect journal locally if startup errors are seen; redact tokens/passwords/customer details before sharing.

If release functionality or startup fails, preserve the 6G lease/journal and perform **code-only** recovery from the `original/` + manifest, restoring only the eight old code modules and removing the 13 added root modules **after checking hashes and process state**. Do not blindly re-run `/root/nvl_k2_publish.sh`, replay the deployment, restore production SQLite over newer traffic, reset global routing, or activate PAM/UID worker. Never claim a complete rollback without a fresh post-rollback service/DB/network check.

## Open gates

1. New live host read-only post-publish audit, Telegram `/start`, `/admin` and new K2 admin UI smoke, legacy SSH/SOCKS/customer continuity.
2. New Edge VPS candidate host-key/pinned IP and staging through existing wizard, isolated **namespace-only** outward IPv4; hold on any uncertain observation.
3. Independent isolated Core clone F4 for protected canary: actual SSH/SOCKS + UDP/TCP DNS, NSS, IPv6 no-leak, WG loss/recovery, fail-closed boot, safe rollback and unaffected neighboring UIDs.
4. Production customer UID transfer not authorized; root-only P3 installer remains first-UID-only, missing multi-UID roster CAS and accepted independent F4 witness. Issues #106/#108 still open.

Primary handoff: [K2 current handoff](NVL_K2_AGENT_HANDOFF_2026-10-13.md), [SSH runbook](NVL_K2_PRODUCTION_SSH_DEPLOY_RUNBOOK_2026-10-14.md), [project memory](NVL_PROJECT_MEMORY.md).
