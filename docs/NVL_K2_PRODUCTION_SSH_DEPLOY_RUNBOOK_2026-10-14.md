> **CURRENT DEPLOY RECORD (2026-10-14):** The Core-only Python code publish described in section 3 was **executed successfully according to the operator-supplied command output** on `CloudVPS121849`: release SHA `d5ca38b6e7069d969d8aa33bcb42ef71c8c63b2a`, 8 replacements / 13 creations, 70 SHA256 checks passed, service restarted and stable over script's 10s observation. Source `/root/nvl-k2-stage-d5ca38b6e706`, host-local one-shot script `/root/nvl_k2_publish.sh`, rollback `/root/nvl-k2-predeploy-sJsySowp`, previous independently audited backup `/root/nvl-emergency-backups/core-20261014T144432Z-x4EVRH`. **DO NOT RE-RUN the one-shot publication script**: it requires old file hashes and a fresh backup filename and is not idempotent. Go directly to [post-deployment audit and Telegram smoke](NVL_K2_CORE_CODE_RELEASE_RECORD_2026-10-14.md). This changes only the **code-deployed** state, not customer Egress/F4/Edge acceptance. User confirms provider snapshot and console; unencrypted off-host backup transfer reported, checksum+restore drill remain unobserved.

---

# NVL K2 — SSH deployment and new Edge acceptance (2026-10-14)

## 2026-10-14 backup HOLD diagnosis (Core snapshot; READ ONLY)

After the first Core archive generated under git SHA 33321f5783bc7683482e2bd769fb59e2d8a0a90e, the checksum checks passed but the separate backup audit reported ARCHIVE_ROOTS_UNTRUSTED. This audit does **not** diagnose DB corruption or a service stop; do not continue deploy or change PAM/UID/6G.

The original auditor required Python-sorted roots even though the producer sorts via GNU sort -zu under the source host locale. The reviewer now allows **any ordered set of unique, trusted root names** with unchanged checksums, tar member coverage, mandatory identity files, root-only permissions and SQLite integrity. Duplicate entries, invalid paths and oversized manifest remain HOLD.

Run this read-only aggregate diagnostic on the actual Core backup (does not reveal path names):

~~~bash
python3 - <<'PY'
from pathlib import Path
p=Path("/root/nvl-emergency-backups/core-20261014T144432Z-x4EVRH/diagnostics/archived-roots.txt")
raw=p.read_bytes()
roots=raw.decode("utf-8").splitlines()
print("BYTES:", len(raw), "WITHIN_64K:", len(raw)<=65536)
print("ROOT_COUNT:", len(roots), "WITHIN_2048:", len(roots)<=2048)
print("UNIQUE:", len(roots)==len(set(roots)))
print("PYTHON_SORTED:", roots==sorted(set(roots)))
print("EMPTY_ENTRIES:", sum(not r for r in roots))
print("NUL_BYTES:", raw.count(b"\x00"))
PY
~~~

If the only issue is PYTHON_SORTED=False (all other checks true), use the **new reviewed auditor from the pinned new SHA** against the **unchanged old snapshot**. Never reorder, resign or modify archived-roots.txt or SHA256SUMS to force a PASS. If oversized, duplicated, malformed or a later check fails, stop and investigate from the original trusted input/snapshot. Even LOCAL_CONSISTENT does not prove independent provider snapshot or successful off-host restore. Preserve original backup intact.

---


**Canonical runbook.** GitHub code baseline after PRs #120 and #139: 331fd86e399bd18e2f524071edb7f14d099e00de (before this documentation and backup fix). Use the NEW final pinned merge SHA when deploying, not this historical SHA. The actual running VPS version, Linux/systemd/venv environment, database schema, Edge configuration and private modules MUST be independently read from the host.

## Release policy: three levels, never conflated

**A — Bot code only:** Publish approved source while preserving Linux Core accounts/UIDs, production DB, original wg0, global routing, SSH/PAM, default Edge, public DNS/Cloudflare, all existing 6G leases and all passwords. Flags for PAM installer and UID Worker stay OFF. A code-only bot restart does not demonstrate protected customer traffic.

**B — New Edge namespace-only canary:** Using the EXISTING bot wizard, stage one disposable Edge with pinned SSH host key, a separately reviewed P1 transport operation and exact dedicated namespace public IPv4 proof. Do not enroll existing customers or change their routing.

**C — Protected UID canary and migration (NOT RELEASED):** Packages 1 and 2 include opt-in Linux worker and deny-first PAM/BootGuard installer, but the installer is initially ONE-UID only, and no live Telegram execution factory or independent real DNS/IPv6 no-Core-leak packet witness is accepted. Never run those installers or route mutators on the live customer Core as part of A/B. Prove C in a disposable Core clone first.

## 0. Collect LIVE baseline from Core, READ ONLY

Run these commands as root through an already trusted administrative session. Keep a separate out-of-band provider console usable. Redact sensitive fields before sharing any result; do not paste environment values, private keys, raw database, or credentials.

~~~bash
set -euo pipefail
hostname -f
date -u -Is
python3 --version
/root/venv/bin/python3 --version
systemctl is-active nvlbot
systemctl show nvlbot -p User -p ExecStart -p WorkingDirectory -p NRestarts --no-pager
ls -l /root/bot_final_v49-2.py /root/master_bot.db
sha256sum /root/bot_final_v49-2.py
git -C /root/nvl-release rev-parse HEAD
git -C /root/nvl-release status --short
sqlite3 /root/master_bot.db 'PRAGMA quick_check;'
sqlite3 -readonly -header -column /root/master_bot.db \
  "SELECT id,status,source_host,target_host FROM failover_operations WHERE status='RUNNING';"
wg show interfaces
ip -4 rule show
ip -4 route show table main
~~~

STOP if Python for the live bot is not 3.12+, live unit paths differ, local Git checkout is dirty/unknown, SQLite fails integrity, or any old protected 6G RUNNING lease cannot be reconciled. These are not reasons to force a reset or unlock.

Inspect systemd EnvironmentFiles locally (avoid printing secrets). The sanitized repository deliberately removed hardcoded credential fallbacks. Verify necessary RB_CONFIRM_PASS and Marzban URL/username/password values are present in the live service environment before replacing the entrypoint. Do not regenerate or overwrite the live .env or install newer packages into the running venv as part of the initial release.

## 1. Independent backups and restore prerequisites

1. Request **full-volume provider snapshots of Core AND the new Edge**. Record actual snapshot IDs and independently test provider rescue/root and non-root admin access.
2. On a disposable clone, demonstrate a real restore of a provider snapshot, Linux UID ownership, sshd/PAM, original wg0 and kernel firewall/routing state. A logical tar backup alone is not sufficient.
3. Use the FIXED backup script from the pinned new master release. The script previously had incorrectly double-escaped NUL→newline conversion; this release fixes it and includes a regression test.
4. After immutable source staging (section 2), run on the respective hosts:

~~~bash
# On Core with the same independently pinned staging directory:
bash /root/NVL_RELEASE_STAGE/ops/backup_nvl_host.sh core

# On the separate NEW Edge after secure provisioning:
bash /root/NVL_RELEASE_STAGE/ops/backup_nvl_host.sh edge
~~~

The script prints an ACTUAL BACKUP_COMPLETE path. Never guess it. Treat the output as highly confidential (Linux hashes, SSH/WG private keys, Telegram/Cloudflare material). Store encrypted copies OFF the VPS with independently verified hashes and a restored disposable clone. Check the Core archive:

~~~bash
cd /root/NVL_RELEASE_STAGE
/root/venv/bin/python3 -m ops.k2_canary_backup_gate \
  --backup /root/nvl-emergency-backups/EXACT_CORE_BACKUP_DIRECTORY
~~~

A LOCAL_CONSISTENT result is NOT permission to execute UID/PAM changes or proof of off-host restore. Any HOLD blocks progression.

## 2. Immutable source staging and dry-run (Core only)

Pin the final GitHub master SHA from successful exact-head CI. Do not use git pull / reset --hard inside the live bot directory. No deployed customer account may change.

~~~bash
set -euo pipefail
EXPECTED_SHA='REPLACE_WITH_FINAL_VERIFIED_MASTER_SHA'
git -C /root/nvl-release fetch origin master
ACTUAL_SHA="$(git -C /root/nvl-release rev-parse origin/master)"
test "$ACTUAL_SHA" = "$EXPECTED_SHA" || {
  echo "STOP: master SHA mismatch"; exit 1;
}
STAGE="/root/nvl-release-stage-$EXPECTED_SHA"
test ! -e "$STAGE"
install -d -m 0700 "$STAGE"
git -C /root/nvl-release archive "$EXPECTED_SHA" | tar -xf - -C "$STAGE"
test -s "$STAGE/bot_final_v49-2.py"
bash -n "$STAGE/ops/backup_nvl_host.sh"
/root/venv/bin/python3 -m py_compile "$STAGE/bot_final_v49-2.py"
(
  cd "$STAGE"
  /root/venv/bin/python3 -m unittest \
    tests.test_edge_egress_k2_canary_backup_gate \
    tests.test_edge_egress_k2_p3_guard_installer \
    tests.test_edge_egress_k2_p3_uid_worker -q
)
printf 'STAGED_SHA=%s\nSTAGE=%s\n' "$EXPECTED_SHA" "$STAGE"
~~~

STOP if the staged test suite fails. Stage contains sanitized source only, not the actual service directory. The existing service example assumes /root/bot_final_v49-2.py, /root/venv/bin/python3, root-level imported modules and EnvironmentFile=/etc/nvlbot/nvlbot.env. **The real systemd unit must be checked**, since the example may not match Production. Compare intended files with their existing /root counterparts; check imported modules and historical production-specific patches. Do not run a broad rsync or cp -r of the repository into /root, and never overwrite /root/.env, /root/master_bot.db, private keys, SSH account material or systemd files blindly.

## 3. Controlled code-only publish (separate operator approval)

After Gates 0–2 and actual backup/restore verification, prepare an explicit manifest of precisely which root-level Python modules and bot entrypoint need replacing, with immutable copies and SHA256 for every replaced file. Only use this reviewed manifest to atomically replace those code files. Do NOT copy configs/secrets or invoke the new ops/k2_p3_guard_installer.py, ops/k2_p3_uid_worker.py, ops/k2_p3_module_stage.py, alter PAM, enable UID guards, change 6G flags, or modify the Edge pool. If the live systemd unit already runs the reviewed paths, ONE controlled nvlbot restart is permitted, not a general reboot:

~~~bash
systemctl is-active nvlbot
systemctl show nvlbot -p NRestarts --no-pager
journalctl -u nvlbot -n 60 --no-pager
sqlite3 /root/master_bot.db 'PRAGMA quick_check;'
wg show interfaces
ip -4 rule show
~~~

Review logs locally for secrets before sharing. Telegram smoke: /start, /admin, Edge detail, and the read-only 🧪 آزمایش VPS panel. Old customer ingress/egress, bot menus, original wg0, Cloudflare, host_pool/default and database must remain unchanged. Roll back **code files only** if the new bot fails and there is no ambiguous protected operation in the 6G journal. Never restore all account or network configuration onto a live instance as a shortcut.

There is deliberately NO generic automatic file-publishing script in this runbook: the live file/module inventory and service compatibility are not yet verified. Produce the exact allowlist and replacement commands only after Gate 0 evidence is reviewed.

## 4. Stage one NEW Edge via existing Telegram admin bot

1. Provision clean candidate VPS with independently verified public IPv4, SSH host key and working rescue console. Do not reuse removed e7 or its unverified Core remnants.
2. In the existing bot admin Edge wizard, add the new candidate using its trusted ingress setup and dedicated Core–Edge Stage; initially keep it OUT of customer host_pool/default and public DNS. If Stage fails, record HOLD and do not blindly rerun.
3. In Edge details, open 🧪 آزمایش VPS. Stage/transport status and counts of Legacy/PROTECTED Core SSH accounts must be visible.
4. ONLY after independent P1 authorization, activate dedicated test transport and use 🌍 تست IP سرور to establish that its namespace public IPv4 matches the **new Edge public IPv4**. Stage UP and namespace IP success do NOT prove any Linux SSH/SOCKS UID route, DNS/NSS/IPv6 nonleak or boot safety.
5. 👤 بررسی کاربر and 🔀 بررسی انتقال remain preview only. A HOLD is normal. Read-only Core inventory for ACTUAL staged edge_id:

~~~bash
cd /root/NVL_RELEASE_STAGE
/root/venv/bin/python3 -m ops.k2_final_readiness \
  --edge-id REPLACE_WITH_REAL_EDGE_ID
~~~

The inventory intentionally exits 2 when execution remains disabled. Never toggle global protected mode, 6H auto-failover, K2 P2 relay, or F4-ready flags merely to make it return zero.

## 5. Do NOT skip physical protected UID acceptance

Before even a throwaway UID on Production Core, test installer and original-6G worker in a disposable Core clone with independent root rescue and a separately witnessed F4 packet capture. Confirm one canary SSH/SOCKS public IPv4 equals its ingress Edge public IPv4; IPv4/DNS UDP+TCP/NSS/IPv6 leak absence; dedicated WG failure and reconnect; cold-boot deny-before-SSH; UID-only HOLD/6G recovery; and other UIDs unaffected. The installer is first-UID only and does not safely update a pre-existing multi-UID roster; external packet and neighbouring-UID observer implementations have not been approved. No live customer migration or Telegram execute binding is authorized by the stage-only CI.

## Release record and STOP rules

Keep a non-secret record: pin SHA, old running source SHA, Python/unit path, pre/post DB and 6G integrity, full-volume snapshots and successful clone restore, encrypted off-host copy verification, SSH/root rescue, legacy traffic uninterrupted, bot smoke results, Stage SHA, host fingerprint, observed namespace IPv4, recorded HOLD blockers and any separately approved F4 evidence. Do not label K2 P1/P2/P3 operationally closed until the protected UID and migration acceptance tests are successful.

References: docs/NVL_K2_AGENT_HANDOFF_2026-10-13.md, docs/K2_P3_GUARD_INSTALL_AND_UID_WORKER_2026-10-14.md, docs/K2_P3_VPS_LAB_TELEGRAM_2026-10-14.md, docs/K2_PRODUCTION_CANARY_ROLLBACK_2026-10-14.md; GitHub Issues #106 and #108.
