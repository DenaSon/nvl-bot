# DenaProbe R3 — clean Core Collector rollout and live schema verification
**Runbook:** 2026-11-03 | **Scope:** isolated `denaprobe-collector.service`, never NPV/GOST/relay switches or the customer bot database.
**Caution:** This guide is not evidence that a remote deployment ran. The operator must execute and return nonsecret outputs.

## Findings and release design
- DPT/1 and DPT/2 use **distinct** `telemetry_events` and `dpt2_events` tables. Incident tables use `dp3_*`. Existing old DPT/1 history cannot by itself open a DP3 incident.
- For a reproducible clean R3 pilot, use a **new SQLite DB** `/var/lib/denaprobe/telemetry-r3.sqlite3` and archive the previous `telemetry.sqlite3` with SQLite's **online backup API**, preserving original and its WAL journal. **Never run DELETE, DROP, truncate or ordinary `cp` of an active SQLite WAL DB.**
- Continue using **the existing private** `/var/lib/denaprobe/devices.json`; retain active old `k2`, ensure `k1` stays revoked and provision a **new independent `v2-` key ID**. Old DPT/1 records and keys remain separate.
- Source schema: `collector.initialize()` creates legacy DPT/1 tables; `dpt2.initialize()` creates the DPT/2 tables; `detector.initialize()` creates incident/transitions/delivery/rich tables. `schema_audit.py` verifies 14 required tables, key columns, indexes, SQLite quick_check/foreign_key_check, WAL and row counts. No migration overwrites existing values. Every new Collector request now closes its SQLite connection deterministically.
- The bot reads/writes this **same isolated** R3 database, not `/root/master_bot.db`. Its `NVL_DENAPROBE_R3_ENABLED` flag stays OFF until real board->Core DPT2 and admin UI acceptance. The existing bot example runs as root; if actual bot user differs, **STOP** and plan DAC/ACL instead of making DB public-readable.

## 0. Safe read-only preflight on Core (Linux)
Use the already authenticated and reviewed source release (`SRC`) at an exact master Git SHA; never substitute an unreviewed branch or arbitrary URL.

```bash
sudo -i
set -euo pipefail
SRC=/root/nvlbot-r3-source              # use your actual checked-out source path
OLD=/var/lib/denaprobe/telemetry.sqlite3
NEW=/var/lib/denaprobe/telemetry-r3.sqlite3
KEYS=/var/lib/denaprobe/devices.json
systemctl is-active denaprobe-collector
systemctl cat denaprobe-collector
systemctl show denaprobe-collector -p User -p WorkingDirectory -p ExecStart
systemctl show nvlbot -p User -p ExecStart
stat -c '%U:%G %a %n' /var/lib/denaprobe "$OLD" "$KEYS"
python3 --version
git -C "$SRC" rev-parse HEAD
test -f "$SRC/denaprobe_ingest/schema_audit.py"
test -f "$SRC/ops/denaprobe_sqlite_online_backup.py"
test ! -e "$NEW" || { echo 'STOP: R3 DB already exists; audit, do not initialize twice'; exit 1; }
```

If old Collector is not `User=denaprobe`, is not loopback-bound `127.0.0.1:18081`, any symlink/permissions differ, or `$NEW` already exists, stop before changing files. Compare current source SHA and previous file hashes.

## 1. Snapshot historical SQLite and private device keys — NO deletion
```bash
ARCH=/root/denaprobe-archive-$(date -u +%Y%m%dT%H%M%SZ)
install -d -m 0700 "$ARCH"
python3 "$SRC/ops/denaprobe_sqlite_online_backup.py" \
  --source "$OLD" --destination "$ARCH/telemetry-legacy.sqlite3"
install -m 0600 "$KEYS" "$ARCH/devices.json"
systemctl cat denaprobe-collector > "$ARCH/collector-unit-before.txt"
install -d -m 0700 "$ARCH/collector-code-before"
cp -a /opt/nvl-dpt-collector/denaprobe_ingest "$ARCH/collector-code-before/"
echo "ARCHIVE_DIR=$ARCH"
```
Do not print the `devices.json` content or share it in chat. Retain the original DB and the archive; a new path for the pilot is the clean reset.

## 2. Stage and validate the exact new Collector source
```bash
cd "$SRC"
python3 -m py_compile denaprobe_ingest/collector.py denaprobe_ingest/dpt2.py \
  denaprobe_ingest/detector.py denaprobe_ingest/schema_audit.py
python3 -m unittest discover -s tests -p 'test_denaprobe*.py' -v
```
Stop on failed tests. Compare current `systemctl cat` again. With explicit approval and confirmed backup, temporarily stop **only** Collector to publish its isolated package:

```bash
systemctl stop denaprobe-collector
rsync -a --exclude='__pycache__' --exclude='*.pyc' \
  "$SRC/denaprobe_ingest/" /opt/nvl-dpt-collector/denaprobe_ingest/
chown -R root:root /opt/nvl-dpt-collector/denaprobe_ingest
chmod -R a+rX /opt/nvl-dpt-collector/denaprobe_ingest
```

## 3. Create a clean, fully initialized R3 DB
```bash
sudo -u denaprobe env PYTHONPATH=/opt/nvl-dpt-collector \
  python3 -m denaprobe_ingest.schema_audit --db "$NEW" prepare-fresh
sudo -u denaprobe env PYTHONPATH=/opt/nvl-dpt-collector \
  python3 -m denaprobe_ingest.schema_audit --db "$NEW" audit
```
Both audits must report `status: PASS`; `telemetry_events`, `dpt2_events` and `dp3_incidents` must initially be 0. Target ID `1` is the registered new relay `153.75.89.31:2252`, **only if this is still the actual test relay**. Registration increases target revision each time: execute only once for this fresh database:
```bash
sudo -u denaprobe python3 /opt/nvl-dpt-collector/denaprobe_ingest/collector.py \
  --db "$NEW" --keys "$KEYS" target --id 1 --host 153.75.89.31 --port 2252
```

### Independent DPT2 HMAC key (NOT a bot environment variable)
This command mutates **only** the private `devices.json` and prints a newly generated secret. Run only on the authorized server console, save securely in the ESP32's ignored local `include/telemetry_private.h`, **never paste the secret in chat, GitHub, logs or a screenshot**.
```bash
sudo -u denaprobe python3 /opt/nvl-dpt-collector/denaprobe_ingest/collector.py \
  --db "$NEW" --keys "$KEYS" provision --id dp-lte-01 \
  --target-id 1 --key-id v2-r3-20261103
```
If the key ID already exists, do not rerun; choose a new versioned ID after reviewing current key IDs, not key values.

## 4. Collector settings / systemd override — NO bot restart
Install the exact two nonsecret Collector env variables as root-only `/etc/denaprobe/collector-r3.env`. Existing service retains its nonroot restrictions. Use an override, not a second service/port:
```bash
install -d -m 0700 /etc/denaprobe
install -m 0600 "$SRC/ops/denaprobe-collector-r3.env.example" \
  /etc/denaprobe/collector-r3.env
install -d -m 0755 /etc/systemd/system/denaprobe-collector.service.d
test ! -e /etc/systemd/system/denaprobe-collector.service.d/40-r3.conf
cat > /etc/systemd/system/denaprobe-collector.service.d/40-r3.conf <<'UNIT'
[Service]
EnvironmentFile=/etc/denaprobe/collector-r3.env
ExecStart=
ExecStart=/usr/bin/python3 /opt/nvl-dpt-collector/denaprobe_ingest/collector.py --db ${DENAPROBE_DB_PATH} --keys ${DENAPROBE_KEYS_PATH} serve --host 127.0.0.1 --port 18081 --enable-v2
UNIT
chmod 0644 /etc/systemd/system/denaprobe-collector.service.d/40-r3.conf
systemctl daemon-reload
systemctl restart denaprobe-collector
systemctl is-active denaprobe-collector
systemctl show denaprobe-collector -p ExecStart -p User
```
The only active listener must be `127.0.0.1:18081`; existing Cloudflare route must continue pointing there. This step opens signed DPT2 ingestion but sends **no Telegram alerts**.

## 5. Post-deploy local checks, then external route
```bash
curl -sS -i http://127.0.0.1:18081/healthz
curl -sS -i -H 'Content-Type: application/json' \
  --data '{}' http://127.0.0.1:18081/api/dpt/v2/telemetry
curl -sS -i -H 'Content-Type: application/json' \
  --data '{}' http://127.0.0.1:18081/api/dpt/v1/telemetry
sudo -u denaprobe env PYTHONPATH=/opt/nvl-dpt-collector \
  python3 -m denaprobe_ingest.schema_audit --db "$NEW" audit
journalctl -u denaprobe-collector -n 30 --no-pager
curl -sS -o /dev/null -w 'PUBLIC_HEALTH=%{http_code}\n' \
  https://board.nvlsup.online/healthz
```
Expected: health 200, unsigned POST 403 on both v1 and v2, schema PASS and public health 200. A signed POST/ACK test needs the locally configured ESP32 secret and a **new post-start BOOT**. The board flashed before this rollout may still be DPT1/default-off; server cannot manufacture DPT2 evidence.

## 6. Existing NVLBot environment and staged source deployment
The admin bot example service uses `/etc/nvlbot/nvlbot.env`, bot Python under `/root`. Add **only** these two lines (do not print other env values or the bot token):
```ini
NVL_DENAPROBE_R3_ENABLED=0
NVL_DENAPROBE_DB_PATH=/var/lib/denaprobe/telemetry-r3.sqlite3
```
Before setting `=1`, verify the live bot source includes `denaprobe_alerts.py`, `denaprobe_rich_admin.py`, the exact new main `bot_final_v49-2.py`, `cloudzy_rich_transport.py`, and the complete `denaprobe_ingest/` package, with a controlled source-code release. Merely updating Collector **does not** deploy these bot modules to `/root`. Stage all code with current live-file checks and backups, then restart **only nvlbot** as a separately approved change.

No Telegram token/SSH private key/device HMAC secret should be placed in new bot env values. Do not set the bot flag to 1 until device signed ACK, fresh rows, native Telegram Rich rendering and live authorization checks pass.

## 7. After the server: ESP32 R3 activation and readouts
Board `esp32dev_ssh_feasibility` does NOT automatically enable DPT2/deep: `PROBE_DPT_ENABLED` defaults 0, protocol 1, deep 0. Provision the ignored local board secret, verified CA and DPT2 URL, set protocol 2 and opt into the deep probe only after the restricted SSH user and relay-local `0x5A` responder are genuinely provisioned. Then rebuild/flash the feasibility environment and reboot, producing a new `BOOT q=1` in this clean DB.
Read recent DPT2 rows from the **new** DB:
```bash
sudo -u denaprobe python3 /opt/nvl-dpt-collector/denaprobe_ingest/collector.py \
  --db "$NEW" --keys "$KEYS" recent-v2 --limit 20
sudo -u denaprobe env PYTHONPATH=/opt/nvl-dpt-collector python3 - "$NEW" <<'PY'
from pathlib import Path
from denaprobe_ingest.collector import connect_db
import sys
with connect_db(Path(sys.argv[1])) as c:
    for r in c.execute("SELECT device_id,boot_id,ssh_sequence,https_sequence,"
                       "monitoring_gap FROM dpt2_latest"):
        print(dict(r))
PY
```
Check `monitoring_gap=0` after two eligible fresh SSH events, and non-NULL `https_sequence` only after direct HTTPS. Ensure D0/D1/D2 data-plane fields are actually present; pre-auth alone is UNKNOWN. Bot alerts remain OFF until independent E2E evidence has been reviewed.

## Rollback
- **Collector only:** stop `denaprobe-collector`, remove **only** the reviewed `40-r3.conf` drop-in, restore `denaprobe_ingest` from archived package, `systemctl daemon-reload`, start Collector. The historical DB and the new R3 DB are **retained**, never deleted.
- **Bot only:** set `NVL_DENAPROBE_R3_ENABLED=0`, restore previous bot runtime from independent backup if needed and restart only `nvlbot`; never restart GOST/NPV or remove user records.
- Never confuse "latest source merged" with "board->Core live field acceptance"; record current running service unit, live source hashes and nonsecret recent-v2/serial evidence separately.
