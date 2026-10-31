# DenaProbe R2-B — isolated Core collector, DPT/1

**Source only** · 2026-10-31 · **Domain:** board.nvlsup.online · **Source branch:** feature/dpt-r2b-core-collector-20261031

## Scope and production fence

The ESP32 is an instrument, not a censorship detector. This service ingests
raw DPT/1 observations and returns a durable ACK; it **never** sends a Telegram
notification, changes NVLBot accounts, performs SSH login, reads NPV traffic,
or modifies GOST, WireGuard, DNS, customer routes, Edge failover, PAM or 6G.
It is a **separate Python stdlib service** and **separate SQLite database**.
It never imports bot_final_v49-2.py or opens /root/master_bot.db.

Contract authority: DenaSon/DenaProbe docs/008-DPT-TELEMETRY-CONTRACT-V1.md
and contracts/dpt/v1/*.json. No DPT/2 or batch messages.

**Do not call source merge a live deployment.** Requires operator-run SSH
staging, independent telemetry flash, live Cloudflare Tunnel switch, replay
tests and reversible signoff. Never deploy by overwriting the Core /root/
runtime or restarting nvlbot.service. Existing working Tunnel route remains
http://127.0.0.1:18080 until explicit switch.

## Isolation

- Code /opt/nvl-dpt-collector/denaprobe_ingest/collector.py
- Service denaprobe-collector.service, nonroot user denaprobe
- Bind ONLY 127.0.0.1:18081
- Database /var/lib/denaprobe/telemetry.sqlite3, WAL, synchronous=FULL,
  BEGIN IMMEDIATE and UNIQUE(device_id,boot_id,sequence)
- Private file /var/lib/denaprobe/devices.json (0600, owned by denaprobe)
- Existing Cloudflare Tunnel board.nvlsup.online -> 127.0.0.1:18080
  **unchanged** until the new endpoint is tested locally
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

Register a distinct device identity and **random** 256-bit HMAC secret:

    runuser -u denaprobe -- python3 /opt/nvl-dpt-collector/denaprobe_ingest/collector.py \
      provision --id dp-mci-01 --key-id k1 --target-id 1

**SECRET_HEX** is shown once for secure transfer to the ignored local
ESP32 file (never paste it into ChatGPT/Telegram/logs/Git). For rotation
provision a NEW key-id. Revoke a single key without touching other devices:

    runuser -u denaprobe -- python3 /opt/nvl-dpt-collector/denaprobe_ingest/collector.py \
      revoke --id dp-mci-01 --key-id k1

Never use the public frozen fixture HMAC key on a real device.

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

After local validation, switch *only* the existing Cloudflare Tunnel
Published Application origin for board.nvlsup.online from
http://127.0.0.1:18080 to http://127.0.0.1:18081.
Do not alter the public DNS hostname, the tunnel itself, GOST or 443.
From Windows PowerShell validate:

    curl.exe -v https://board.nvlsup.online/healthz
    curl.exe -s -o NUL -w "%{http_code}" -X POST \
      -H "Content-Type: application/json" --data "{}" \
      https://board.nvlsup.online/api/dpt/v1/telemetry

Expected: 200 and 403 respectively. A 403 proves public auth gate only,
not live firmware delivery or a secure device provision.

With the board clock issue independently fixed, configure board:
PROBE_DPT_ENABLED=1, PROBE_DPT_OFFLINE_SMOKE_TEST=0,
PROBE_DPT_DEVICE_ID="dp-mci-01", PROBE_DPT_TARGET_ID=1,
PROBE_DPT_KEY_ID="k1", PROBE_DPT_SECRET_HEX=(provisioned key),
PROBE_DPT_API_URL="https://board.nvlsup.online/api/dpt/v1/telemetry",
PROBE_DPT_CA_PEM=(verified CA trust anchor). Keep this file ignored.

A *live* R2-C test must show signed BOOT q=1 -> ACK 0, real probes ->
ACK 0, byte-identical retry -> ACK 1, changed body same identity ->
HTTP 409, post-reboot new boot identity, and valid history_only=1 for
stale/out-of-order. Verify real sequence and time without claiming NPV
application health or filtering.

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
- Existing SSH pin, NTP CLOCK_NOT_READY and public 64KiB HTTPS probe
  issues are separate R2-C field gates; collector cannot resolve them.
- No production retention/notification thresholds are implicitly approved.
