# DenaProbe R2-B — isolated Core collector, DPT/1

**Source PR #262 open/unmerged; operator-staged Collector live** · 2026-10-31 · **Domain:** board.nvlsup.online · **Source branch:** feature/dpt-r2b-core-collector-20261031

**Field status:** R2-B isolated ingestion installed on Core and verified externally; R2-C signed hardware ACK and SQLite storage **PASS**. Live-state continuity remains **OPEN** (`monitoring_gap=1`, `https_sequence=NULL` in later snapshot); **R2-C Hardening not started**. See [DenaProbe R2-C field handoff](https://github.com/DenaSon/DenaProbe/blob/feature/r2a-dpt1-telemetry-sender-20261031/docs/013-R2C-DPT1-HARDWARE-CORE-FIELD-VALIDATION-2026-10-31.md).

## Scope and production fence

The ESP32 is an instrument, not a censorship detector. This service ingests
raw DPT/1 observations and returns a durable ACK; it **never** sends a Telegram
notification, changes NVLBot accounts, performs SSH login, reads NPV traffic,
or modifies GOST, WireGuard, DNS, customer routes, Edge failover, PAM or 6G.
It is a **separate Python stdlib service** and **separate SQLite database**.
It never imports bot_final_v49-2.py or opens /root/master_bot.db.

Contract authority: DenaSon/DenaProbe docs/008-DPT-TELEMETRY-CONTRACT-V1.md
and contracts/dpt/v1/*.json. No DPT/2 or batch messages.

**Source merge is distinct from runtime installation.** The operator has
already installed and started this isolated Collector, switched the Cloudflare
Tunnel published application origin from 18080 to **18081**, and flashed a
live ESP32 sender. The release is still **experimental**, not a complete
replay/adverse-network/live-state/retention acceptance. These instructions
retain initial installation and rollback details for reproducibility; do not
re-run provisioning, replace the Core /root/ runtime, or restart nvlbot.service.

## Isolation

- Code /opt/nvl-dpt-collector/denaprobe_ingest/collector.py
- Service denaprobe-collector.service, nonroot user denaprobe
- Bind ONLY 127.0.0.1:18081
- Database /var/lib/denaprobe/telemetry.sqlite3, WAL, synchronous=FULL,
  BEGIN IMMEDIATE and UNIQUE(device_id,boot_id,sequence)
- Private file /var/lib/denaprobe/devices.json (0600, owned by denaprobe)
- **Current field route:** existing Cloudflare Tunnel `denaprobe-core` for
  `board.nvlsup.online` -> `http://127.0.0.1:18081` after successful
  local test. Temporary `127.0.0.1:18080` healthz service retained for
  reversible routing rollback (presence should be reconfirmed before use).
- Protected 443 continues to belong to GOST (its expired unrelated certificate
  is a separate operations issue, not addressed here).

Public paths ONLY: GET /healthz and POST /api/dpt/v1/telemetry. No
read/history/admin HTTP route exists; use local CLI.
Direct client requests require signed DPT/1 headers; reject malformed,
unsigned, tampered, unknown/revoked keys, duplicate auth headers, unknown
versions, >1024 bytes, and wrong JSON/field semantics. Compare exact raw
body hash; ACK 200 only after durable transaction commit. 200 r=0 new,
r=1 exact duplicate, r=2 history-only. Collisions return 409. Time/header
issues never bypass HMAC. Serve through existing Cloudflare HTTPS/Tunnel.

## Release: test in a separate staging checkout

On Core over SSH (root), first verify that the existing relay, bot, tunnel
and /healthz still work. Do not interrupt them:

    systemctl is-active gost nvlbot cloudflared denaprobe-healthz
    ss -lntp | grep -E ':(443|18080|18081)[[:space:]]'
    curl --max-time 5 -fsS http://127.0.0.1:18080/healthz

Fetch the exact approved feature branch in an independent checkout; do not
replace a live release checkout, and do not run old publish scripts:

    git clone --branch feature/dpt-r2b-core-collector-20261031 --single-branch \
      https://github.com/DenaSon/nvl-bot.git /root/nvl-dpt-r2b-stage
    cd /root/nvl-dpt-r2b-stage
    python3 -m unittest discover -s tests -p 'test_denaprobe_collector.py' -v
    python3 -m py_compile denaprobe_ingest/collector.py

Use the already configured private-repo auth for clone. Pin the resulting
commit SHA in the operator release record; don't pull branch changes blindly
after qualification. Tests use a **synthetic PUBLIC vector key only**.

Provision isolated filesystem and runtime. None of this touches the bot DB:

    id denaprobe >/dev/null 2>&1 || useradd --system \
      --home-dir /var/lib/denaprobe --shell /usr/sbin/nologin denaprobe
    install -d -o denaprobe -g denaprobe -m 0700 /var/lib/denaprobe
    install -d -o root -g root -m 0755 /opt/nvl-dpt-collector/denaprobe_ingest
    install -m 0644 denaprobe_ingest/collector.py /opt/nvl-dpt-collector/denaprobe_ingest/collector.py
    install -m 0644 denaprobe_ingest/__init__.py /opt/nvl-dpt-collector/denaprobe_ingest/__init__.py
    runuser -u denaprobe -- python3 /opt/nvl-dpt-collector/denaprobe_ingest/collector.py init
    runuser -u denaprobe -- python3 /opt/nvl-dpt-collector/denaprobe_ingest/collector.py \
      target --id 1 --host n1.nvlsup.com --port 2252

Validate the monitored Edge hostname/port against the existing private
firmware config and independently confirmed target registry. The target
revision is stored per event; never silently relabel earlier samples.

**Observed operator provisioning:** device `dp-mci-01`, target `1`, initially
key ID `k1`. The initial 256-bit `SECRET_HEX` was subsequently pasted into
conversation text and is **compromised**. A replacement key ID `k2` was
provisioned and its authenticated hardware delivery passed, but evidence that
`k1` was actually revoked has **not** been provided. Verify key **IDs only**
without printing values, and revoke `k1` if still present:

    runuser -u denaprobe -- python3 - <<'PY'
    import json
    from pathlib import Path
    d = json.loads(Path('/var/lib/denaprobe/devices.json').read_text())['devices'].get('dp-mci-01', {})
    keys = d.get('keys', {})
    print('device_enabled=', d.get('enabled'))
    print('k1_revoked=', 'k1' not in keys)
    print('k2_present=', 'k2' in keys)
    PY

    runuser -u denaprobe -- python3 /opt/nvl-dpt-collector/denaprobe_ingest/collector.py \
      revoke --id dp-mci-01 --key-id k1

Only execute `revoke` if the inspection says k1 remains. A `provision` command
prints its secret and **must not be re-run for an existing key ID**. On any
new/rotated key, capture the output into a root-owned `0600` private file with
terminal echo/redirection controls and put its value only in the gitignored
ESP32 config. Never paste private keys into ChatGPT, Telegram, logs or Git.
Never use public fixture keys on actual hardware.

Install/start a separate systemd service; verify local requests first:

    install -m 0644 ops/denaprobe-collector.service /etc/systemd/system/denaprobe-collector.service
    systemctl daemon-reload
    systemctl enable --now denaprobe-collector
    systemctl is-active denaprobe-collector
    curl -fsS http://127.0.0.1:18081/healthz
    curl -sS -o /dev/null -w '%{http_code}\n' \
      -X POST -H 'Content-Type: application/json' --data '{}' \
      http://127.0.0.1:18081/api/dpt/v1/telemetry

The last unauthenticated request must be **403**, not 200.

**Cutover was performed and verified on 2026-10-31:** the operator edited
*only* the existing Cloudflare Tunnel **Published Application** origin for
`board.nvlsup.online`, from `http://127.0.0.1:18080` to
`http://127.0.0.1:18081`. Neither public DNS hostname nor the tunnel,
GOST or 443 was changed. The general Zero Trust mesh/CIDR **Routes** screen
is **not** the Published Application route editor.
From Windows PowerShell validate:

    curl.exe -v https://board.nvlsup.online/healthz
    curl.exe -s -o NUL -w "%{http_code}" -X POST \
      -H "Content-Type: application/json" --data "{}" \
      https://board.nvlsup.online/api/dpt/v1/telemetry

**Observed externally:** 200 with `{"status":"ok","service":"denaprobe-core"}`
and 403 with `{"error":"request_rejected"}` on 2026-10-31. The signed
firmware test later separately confirmed real delivery and durable ACK.

**Observed flashed private board config:** `PROBE_DPT_ENABLED=1`,
`PROBE_DPT_OFFLINE_SMOKE_TEST=0`, `PROBE_DPT_DEVICE_ID="dp-mci-01"`,
`PROBE_DPT_TARGET_ID=1`, `PROBE_DPT_KEY_ID="k2"`, verified private HMAC secret,
`PROBE_DPT_API_URL="https://board.nvlsup.online/api/dpt/v1/telemetry"`, and
public `GTS Root R4` PEM in an ESP32 C++ raw string literal. The file
`include/telemetry_private.h` is gitignored and must never be logged or
committed. The public certificate chain was reported as domain -> WE1 ->
GTS Root R4 (cross-signed by GlobalSign). No TLS verification bypass was used.
SNTP was initially not ready after Wi-Fi, then `ready=YES` roughly 41 seconds
after boot in the field run; independent proof of UDP/123 was not collected.

**Partially completed R2-C hardware smoke (2026-10-31):** sender reported
`[dpt] READY | ... mode=HTTPS_SENDER`; a signed BOOT q=1 returned
`ACCEPTED`, `http=200`, and later normal/local observations returned
`ACCEPTED` and `HISTORY_ONLY`, `http=200`. Core `check` advanced from
`EVENT_COUNT=0` to **8** with `DPT_CHECK=ok`. Multiple events were stored
as historical-only after out-of-order delivery. Live exact-duplicate ACK
(`r=1`), tampered body/identity 409, reboot, 429/5xx retry, queue overflow,
24h stability and adverse-network tests **remain open**. No NPV data-path,
filtering, alert or failover outcome has been measured.

Local read-only history and integrity checks:

    runuser -u denaprobe -- python3 /opt/nvl-dpt-collector/denaprobe_ingest/collector.py check
    runuser -u denaprobe -- python3 /opt/nvl-dpt-collector/denaprobe_ingest/collector.py recent --limit 20

For backups, use SQLite's online backup API or .backup via sqlite3 CLI,
NOT a raw copy of an active WAL DB. Store secure backups with controlled
retention; a policy is required before production historical collection.

## Rollback

1. In Cloudflare Tunnel route ONLY, change board.nvlsup.online origin
   back to http://127.0.0.1:18080.
2. Confirm https://board.nvlsup.online/healthz returns 200.
3. systemctl stop denaprobe-collector
4. Keep /var/lib/denaprobe/telemetry.sqlite3 and devices.json intact
   for evidence; do **not** delete or reset DB, rotate a working device
   key unnecessarily, or restart nvlbot/GOST.
5. Unset board sender PROBE_DPT_ENABLED if Rollback is prolonged.

## Security limitations

- Cloudflare Tunnel + public HTTPS provides transport; the per-device
  HMAC authenticates the message, not an ISP diagnosis. Maintain Cloudflare
  WAF/rate limiting because HMAC failures alone do not stop flood traffic.
- Authorized-device keys on ESP32 can be physically extracted; compromise
  requires per-device revocation. Keep the local private JSON 0600 and
  state directory 0700.
- A signed uptime is sender-reported, not trusted UTC. Replay protection
  uses immutable identity + boot history + sequence and conservative
  latest-state gating. No server-side "filtering" verdict is computed.
- Existing SSH host pin and public 64KiB HTTPS probe both passed in the
  observed healthy field run. NTP `CLOCK_NOT_READY` was transient and later
  resolved to `ready=YES`; negative-path evidence remains open.
- **Critical live-state consistency gap observed:** `device_latest_state`
  showed `ssh_sequence=12`, `https_sequence=NULL`, `last_event_sequence=12`,
  `monitoring_gap=1`. Firmware newest/urgent-first backlog dispatch conflicts
  with the Collector's strict sequential fresh-state admission, causing
  `HISTORY_ONLY` for older results; history must be retained, not promoted
  unsafely into current status. Design and test FIFO/urgent reconciliation
  only in the later **R2-C Hardening** phase. No alert job until resolved.
- No production retention/notification thresholds are implicitly approved.

## Operator field snapshot and handoff (freeze before R2-C Hardening)

- **Core code provenance:** separate staging checkout `/root/nvl-dpt-r2b-stage`, pinned commit `7386ac3b0ab306ef772273bd74fb33f4385d75c4`; 10/10 standalone collector unit tests passed, Python compile passed, PR #262 open/unmerged at writing.
- **Service:** `systemctl is-enabled denaprobe-collector` => `enabled`, `systemctl is-active denaprobe-collector` => `active`, `ss -lntp` => bound to `127.0.0.1:18081` (not public listener); no NVLBot/GOST restarts observed in reported commands.
- **Collector and device:** `TARGET_REVISION=1`, HMAC device `dp-mci-01`, current key ID `k2`; private device secret not included in documentation.
- **Public API:** `GET /healthz` => 200; unsigned `POST /api/dpt/v1/telemetry` => 403; signed ESP32 POST => accepted 200 with matching ACK.
- **Persistence:** `DPT_CHECK= ok EVENT_COUNT= 8` at first completed live test, later current-state read `ssh_sequence=12`, `https_sequence=NULL`, `last_event_sequence=12`, `monitoring_gap=1` (not an atomic snapshot of eight events).
- **Outstanding before hardening:** verify `k1` revoked without printing keys, ordered current-state acceptance with fresh HTTPS sample, ACK duplicate/tamper/replay cases, transient network/overflow/reboot tests, retention, production monitoring/alert policy. No automatic Telegram alert or route mutator is implemented or approved.
- **Further evidence:** [DenaProbe R2-C field report](https://github.com/DenaSon/DenaProbe/blob/feature/r2a-dpt1-telemetry-sender-20261031/docs/013-R2C-DPT1-HARDWARE-CORE-FIELD-VALIDATION-2026-10-31.md).
