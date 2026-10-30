# NVL ↔ DenaProbe v1 — read-only operator-owned telemetry

**Status (2026-10-28): source implementation staged in a feature branch; NOT deployed.**
The receiver and Telegram dashboard are additions to the existing Python NVL bot, not a
new Telegram bot or a replacement monitoring/failover subsystem.

## 1. Topology and boundaries

- ESP32 DenaProbe on an operator-owned mobile hotspot resolves **the public Edge hostname**
  every probe cycle, probes DNS/TCP/SSH identification and optionally POSTs a small JSON
  summary via **certificate-validated HTTPS** to a separate telemetry ingress hostname.
- The public telemetry ingress must be **independent of the rotating Edge** and must
  **not expose the hidden Core public address**. Use a separately approved HTTPS
  ingress with a private origin connection (e.g. a properly configured outbound
  tunnel) to the Python receiver on the NVL Core. Do not publish a DNS A record
  directly to the Core, open the receiver's port to the Internet, or route uploads
  through the Edge under test.
- The Python receiver binds **127.0.0.1:8765**, authenticates a device-specific
  random bearer token, validates a bounded 2 KB JSON body and stores measurements
  in independent SQLite **/var/lib/nvl-denaprobe/telemetry.sqlite3**.
- The existing NVL Telegram bot reads only that database to display device status
  in **🧩 برنامه‌ها → 📡 DenaProbe | پایش شبکه** or admin-only **/denaprobe**.
  A private chat, authenticated admin session and active admin ID are all required.
- This feature does **not** call 6E/6F/6G/6H, alter filtering verdicts,
  Cloudflare, active Edge/default DNS, WireGuard, SSH accounts, PAM, customer data,
  Failover, auto-switch or Telegram credentials. No device-reported SSH banner
  is treated as proof of authenticated SSH or functioning NPV Tunnel.

## 2. Device → API contract

POST \`/v1/reports\` over HTTPS, Content-Type \`application/json\`,
\`X-DenaProbe-Device: probe_01\`, \`Authorization: Bearer <random per-device token>\`.

Example sanitized body (the field \`carrier_declared\` is a DECLARATION, not ASN verification):

\`\`\`json
{
  "schema_version": 1,
  "device_id": "probe_01",
  "boot_id": "1234abcd",
  "sequence": 1,
  "uptime_ms": 22843,
  "edge_host": "edge.example.test",
  "edge_ipv4": "198.51.100.15",
  "edge_port": 2252,
  "carrier_declared": "MCI",
  "wifi_rssi_dbm": -48,
  "dns_ok": true, "dns_ms": 26,
  "tcp_ok": true, "tcp_ms": 320,
  "ssh_id_ok": true, "ssh_id_ms": 213,
  "control_ok": null, "control_ms": null
}
\`\`\`

\`control_ok=null\` means an independent public TCP control was **not attempted**;
it is not a successful control. Failure reports omit unattempted TCP and
SSH stages using \`null\`. \`boot_id + sequence\` ensures idempotent retries.
Server arrival timestamp, not ESP32 unsynchronized time, drives freshness.
Receivers never store Core IP or account/customer identifiers. Device trust
is based on bearer-token possession, not independent carrier provenance.

On the NVL side:
- \`200 {"ok":true,"duplicate":false}\`: sample stored;
- \`200 {"ok":true,"duplicate":true}\`: accepted idempotent retry;
- \`401\`: unauthorized; \`400\`: invalid stage/input; \`413\`: payload too large;
- \`503\`: temporary SQLite error; device should retry later.

**No zero-configuration network receiver exists:** absence of valid environment
secrets causes startup to fail closed. The systemd service is an example and is
not installed by GitHub merge.

## 3. Source-level/offline verification

\`\`\`bash
python3 -m py_compile denaprobe_store.py denaprobe_ingest.py denaprobe_telegram.py
python3 -m unittest -v tests.test_denaprobe_telemetry
\`\`\`

Check GitHub Actions results at the exact commit. Staged code checks alone are
**not** proof of production operations.

## 4. Controlled deployment gates (operator-run only)

**Preconditions:** read-only inventory of the actual NVL Core's Python runtime,
bot service/current commit and DB location; verified backup/restore and existing
recovery access. Do not reuse old K2 deployment scripts, restart the running
bot, or rewrite the main Python file before independent comparison and approval.
The Telegram integration requires deploying the updated
\`bot_final_v49-2.py\` **and** \`denaprobe_telegram.py\` and \`denaprobe_store.py\`
to the existing bot's import path; follow the existing NVL pinned release
discipline for code-only deployment. Always back up the running file first.

For the separately approved API receiver:
1. Create a dedicated unprivileged \`nvlprobe\` account and place
   \`denaprobe_ingest.py\` and \`denaprobe_store.py\` in \`/opt/nvl-denaprobe\`
   readable by that account. Do not install Telegram libraries for the receiver.
2. Prepare \`/etc/nvlbot/denaprobe.env\` with owner-only permissions, using
   \`systemd/denaprobe.env.example\` as a template. Replace the expected Edge
   host with the current **hostname** (not its IP). Generate a **distinct**
   random token of at least 32 characters for each device. Store the token only
   in the service env and the ignored ESP32 private report config.
3. Install \`systemd/nvl-denaprobe.service.example\` as
   \`/etc/systemd/system/nvl-denaprobe.service\`, after checking user/group/path.
   Start this **separate** service and verify the local-only
   \`curl -fsS http://127.0.0.1:8765/healthz\`. No change to \`nvlbot\`
   or operating network routes is required to start the receiver.
4. Configure independent authenticated HTTPS ingress to relay **only**
   \`/v1/reports\` to the loopback receiver. Maintain TLS hostname/CA verification,
   limits and rate limiting; do **not** expose \`/healthz\` publicly.
   Confirm \`ss -ltn\` shows receiver bound only to \`127.0.0.1:8765\`.
5. On the ESP32 local checkout, configure ignored
   \`include/probe_report_private.h\` from the source template with the hostname
   of that HTTPS ingress, path, device ID, random token and its **trusted
   public root CA PEM**. The new firmware requires a valid clock obtained via
   SNTP for TLS certificate validation; no \`setInsecure\` fallback exists.
   If time or CA verification fails, preserve the sample for later retry.
6. Confirm **one real POST** appears in independent SQLite, then only
   after a controlled code-only bot release check the private
   \`/denaprobe\` admin panel. Verify no user/non-admin can read data and
   that the panel shows fresh vs stale reports accurately. Record reversible
   deploy/rollback steps and the exact running commit.
7. Fail to safe on any SSH/Core or Telegram regression. This module
   is **read-only telemetry** and must never affect existing sales,
   connected customer tunnels or failover decisions.

## 5. Observability and retention

- The receiver stores only validated DNS/TCP/SSH-ID observations, independent
  public TCP controls, declared carrier, RSSI, Edge DNS answer and server time.
- Deduplication is on (device_id, boot_id, sequence). Old observations are
  pruned opportunistically after 14 days when sequence multiples of 100 arrive.
  With no new reports, cleanup does not run; add an independent DBA retention
  task only after the initial pilot if needed.
- Admin view shows the latest row per device and labels data older than
  **180 seconds** STALE rather than calling a previously green device healthy.
- ESP32 queues at most **8** pending reports in RAM. Power loss or more than
  8 unsent measurements may lose samples; this is not durable store-and-forward.
- All transport/security logging is bounded; no Authorization header, SSH
  credentials, customer IPs, Telegram token or Core address should be logged.

## 6. Scope and stop conditions

This is a **source-level optional, passive monitor**. It is not the separate
HD-01/HD-02 manual Health Center and does not redefine existing filtering status
or 6H automatic failover. Physical carrier verification and an authenticated
NPV Tunnel E2E diagnostic remain separate work. If probe DNS/TCP/SSH ID passes
but the VPN fails, the correct dashboard interpretation remains
**"Edge ingress preliminarily reachable; real NPV status unknown."**

Before labeling the feature *operational*, obtain evidence for: Python tests,
bounded auth rejection, HTTPS cert verification from the ESP32, one stored
measurement, 180-second staleness, private admin Telegram view and controlled
rollback. No live production change is implied by a merged PR.
