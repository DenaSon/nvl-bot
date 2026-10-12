> **LATEST NVL SSH EGRESS K2 MEMORY — 2026-10-13:** Read **[K2 New York e7 / iPhone Production E2E memory](SSH_EGRESS_K2_E7_MEMORY_2026-10-13.md)** FIRST for current concrete host/Edge/UID identifiers, successful e7 staging and actual mobile IPv4 proof, the local BootGuard whitespace hotfix, 20-minute Canary fence uncertainty, and exact remaining F4/PAM/boot/fail-closed gates. The on-phone `nvl0557` trace returned **`172.86.105.67`** from the same New York Edge; this is **one-request E2E PASS, NOT F4 READY or a durable production rollout**. Earlier P0 and 2026-10-12 next-step banners below are historical and superseded. No new customer changes, global protected mode, Core reboot, or blind B26 rerun.

> **NEW CURRENT-SCOPE OVERRIDE — 2026-10-12:** For active work on SSH client Internet IP, read **[SSH_EGRESS_V1_PRODUCTION_SCOPE_AND_EVIDENCE.md](SSH_EGRESS_V1_PRODUCTION_SCOPE_AND_EVIDENCE.md)** first. V1 is restricted to real Production, one controlled account, **Egress public IPv4 == that account's genuine Ingress Edge public IPv4**. Current next step: **P0 read-only Root Cause and minimal delta**. **6G/6H expansion and draft PR #92 are deferred/frozen**. Preserve historical evidence and existing failover lock invariants; do not rerun LAB tests or perform Production changes without a separate reviewed change plan. Older handoff and release docs below remain safety references rather than current scope.

> **Current SSH Edge Egress status (2026-10-12):** This file contains historical NVL production runbooks and release notes, including V115.2; do **not** infer today's deployed version from them. For the current F1–F4 implementation, actual CI results, blocked public SSH Egress, and exact next steps, read **[EDGE_EGRESS_CURRENT_HANDOFF.md](EDGE_EGRESS_CURRENT_HANDOFF.md)** first. GitHub `master` last verified at `589625073e5b191529485bd9dc3d1bbbd2119cea`; Production host state still requires read-only verification. **Do not rebuild finished Egress phases or confuse isolated SOCKS success with customer SSH Egress.**

---

# NVL Project Memory / Production Runbook

Last updated: **2026-10-02**  
Current production release: **V115.2-2026-10-02-predeploy-fixes**  
Release commit: `a5ed9e1ec943e1d88032f7ce8abb30e5d7631c66`

## Current system scope

NVL is a Telegram-based control plane for VPN service operations.

Current capabilities include:

- SSH account lifecycle, expiry, capacity monitoring, Hidden Hold and reseller sales.
- V2Ray/Marzban sales for timed and volume-based plans, including custom volume, expiry selection, subscription naming and reseller settlement.
- Marzban administration for users, nodes, inbounds and hosts through a dedicated service layer.
- Agent/reseller panel with wallet, commission, emergency credit and owned-user management.
- Core/Edge infrastructure with WireGuard relay topology, standby/failover tooling and Edge synchronization scripts.
- Phase 6A: explicit separation of customer `service_port` and management `admin_ssh_port`.
- Phase 6B: typed, persisted health evidence and canonical host health states.
- Phase 6C: per-Edge observability using WireGuard handshake freshness, Core-path evidence and optional external/regional probe evidence. Phase 6C is diagnostic only and does not itself trigger failover.
- Current Core is explicitly classified as `CORE_LOCAL` and excluded from Edge filtering probes.

## V115.2 production changes

- Fixed the reseller V2Ray sale path so a successful Marzban create does not fail afterward because of a redundant second user GET.
- The verified `subscription_url` returned by Marzban create is reused; fallback GET is only used when that field is absent.
- Agent action labels were cleaned up by removing possessive “من”; legacy labels remain accepted as compatibility aliases.
- V2Ray/Marzban endpoint is configuration-driven through `settings.marzban_url`.
- Production value observed during the V115.2 deploy: `https://gate.nvlsup.xyz:2053`.
- `ws.nvlsup.com` belongs to SSH/TLS and is separate from V2Ray/Marzban. Do not modify it during V2Ray endpoint work.
- V115.2 staging validation passed **172 unit/regression tests**.

---

# Canonical Production Deployment Procedure

This is the standard NVL deployment workflow. **Do not deploy by running Git directly in `/root`.**  
The Git checkout and validation environment are separate from the production runtime.

## 1. Pre-deploy database check

```bash
sqlite3 /root/master_bot.db "PRAGMA integrity_check;"
```

Expected:

```text
ok
```

Take an initial DB/source backup when appropriate.

## 2. Fetch the release repository

Persistent Git checkout:

```text
/root/nvl-release
```

GitHub deploy key:

```text
/root/.ssh/nvl_github_deploy
```

Fetch:

```bash
GIT_SSH_COMMAND="ssh -i /root/.ssh/nvl_github_deploy -o IdentitiesOnly=yes" \
git -C /root/nvl-release fetch origin master
```

Verify the target commit:

```bash
git -C /root/nvl-release rev-parse origin/master
```

Never continue if the fetched SHA is not the release SHA expected for the deployment.

## 3. Create an isolated staging worktree

Example:

```bash
rm -rf /root/nvl-v1152-stage

git -C /root/nvl-release worktree add --detach \
  /root/nvl-v1152-stage origin/master
```

All tests are run here before production cutover.

## 4. Compile and test staging

```bash
cd /root/nvl-v1152-stage

/root/venv/bin/python3 -m py_compile \
  bot_final_v49-2.py \
  marzban_admin.py \
  v2ray_engine.py \
  edge_observability.py

/root/venv/bin/python3 -m unittest discover \
  -s tests \
  -p 'test_*.py' \
  -v
```

Deployment gate:

```text
compile success
+ all tests PASS
+ final unittest result = OK
```

If staging fails, production files are not changed.

## 5. Compare release files with runtime

Before cutover, identify what actually changed:

```bash
for f in bot_final_v49-2.py marzban_admin.py v2ray_engine.py edge_observability.py; do
    echo "===== $f ====="
    if [ -f "/root/$f" ]; then
        cmp -s "/root/$f" "/root/nvl-v1152-stage/$f" \
          && echo "same" \
          || echo "CHANGED"
    else
        echo "NEW FILE"
    fi
done
```

Only release/runtime files required by that version should be copied.

## 6. Final pre-cutover backup

Create a timestamped rollback directory:

```bash
TS=$(date +%Y%m%d-%H%M%S)
B="/root/nvl-backups/pre-v1152-$TS"
mkdir -p "$B"

cp -a /root/bot_final_v49-2.py "$B/"
[ -f /root/marzban_admin.py ] && cp -a /root/marzban_admin.py "$B/"
[ -f /root/v2ray_engine.py ] && cp -a /root/v2ray_engine.py "$B/"
[ -f /root/edge_observability.py ] && cp -a /root/edge_observability.py "$B/"

sqlite3 /root/master_bot.db ".backup '$B/master_bot.db'"
```

## 7. Production cutover

Keep the validation phase separate from the runtime cutover. Stop/restart the service only for the short file-replacement window.

Copy the validated files from the staging worktree:

```bash
cp -a /root/nvl-v1152-stage/bot_final_v49-2.py /root/
cp -a /root/nvl-v1152-stage/marzban_admin.py /root/
cp -a /root/nvl-v1152-stage/v2ray_engine.py /root/
cp -a /root/nvl-v1152-stage/edge_observability.py /root/
```

Recompile the **actual runtime files**:

```bash
cd /root

/root/venv/bin/python3 -m py_compile \
  bot_final_v49-2.py \
  marzban_admin.py \
  v2ray_engine.py \
  edge_observability.py
```

Then start/restart:

```bash
systemctl restart nvlbot
```

If the service was intentionally stopped before cutover:

```bash
systemctl start nvlbot
```

## 8. Post-deploy verification

```bash
systemctl is-active nvlbot
systemctl status nvlbot --no-pager -l
journalctl -u nvlbot -n 100 --no-pager
```

Required checks:

- service = `active (running)`
- Telegram application starts and polling/API calls succeed
- no traceback or repeated restart loop
- expected version/release behavior is present
- Phase 6C identifies the current Core as `CORE_LOCAL`
- perform feature-specific smoke tests for the release; for V115.2 this includes reseller V2Ray creation and subscription delivery

## 9. Rollback

If post-deploy validation fails:

1. stop `nvlbot`
2. restore runtime files from the latest `/root/nvl-backups/pre-<version>-*`
3. restore the DB backup only if the release changed/migrated DB state and rollback requires it
4. compile restored runtime files
5. start `nvlbot`
6. verify service status and journal

---

## Deployment invariants

- `/root/nvl-release` is the persistent Git checkout; `/root` is the production runtime.
- Always validate in a separate detached staging worktree before copying files to production.
- Always verify the exact release commit SHA.
- Always compile both staging and final runtime files.
- Unit/regression tests must pass before cutover.
- Always create a rollback backup before replacing production files.
- ENV and systemd configuration are **not part of the normal code deploy**. Do not modify them unless a specific release explicitly requires a configuration migration.
- Never mix SSH/TLS domain changes with V2Ray/Marzban endpoint changes.
- Production secrets, DB files, private keys and logs must never be committed to Git.
