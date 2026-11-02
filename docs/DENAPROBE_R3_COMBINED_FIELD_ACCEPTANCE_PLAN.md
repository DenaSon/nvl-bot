# DenaProbe R3 — combined staged field-acceptance / rollout plan (NO DEPLOYMENT YET)
**Owner decision:** complete all three source phases before **any** Core deployment, ESP32 flashing or real operator-network tests. Prepared 2026-11-02. All current flags **OFF**. This runbook is an operator-controlled sequence to be executed only with explicit future approval.

## Release prerequisites and stable scope
1. Verify final approved GitHub master SHAs (DenaProbe + NVLBot), all status checks green and zero unresolved security-review threads. Archive both SHA IDs, build metadata, original active Collector SHA and firmware v0.0.4 rollback binaries.
2. Preserve existing NVLBot/NPV/GOST/DNS/relay configuration unchanged. Never move the default relay, publish a second bot or log manual relay-switch events. Do not modify any customer SSH accounts.
3. Keep `PROBE_DPT_PROTOCOL_VERSION=1`, `PROBE_DEEP_ENABLED=0`, Collector `--enable-v2` absent and `NVL_DENAPROBE_R3_ENABLED=0` until respective staged gates.
4. Verify DPT/1 Collector source compatibility and SQLite integrity with **online SQLite backup** (not plain copy during WAL activity). Check source service uses independent nonroot `denaprobe` identity and loopback `127.0.0.1:18081`; never use bot's user DB for telemetry.

## Phase A — offline staging, no customer impact
- Run Python `python -m unittest discover -s tests -p 'test_denaprobe*.py' -v`, `python -m unittest discover -s tests -p 'test_cloudzy_rich_bridge_phase7.py' -v`, and bot import preflight under an empty optional-flag environment.
- Build known-good `pio run -e esp32dev`, experimental SSH `pio run -e esp32dev_ssh_feasibility`, and Deep compile `pio run -e esp32dev_r3_deep_compile`. Verify Free Heap and stack/worker deadlines with a real board **later**; CI alone cannot certify the authenticated two-transfer worker.
- Replay archived healthy, D0 and D1 evidence as fixtures, plus partial/slow D2, lost Wi-Fi, stale direct HTTPS, old DPT/1, target revision, queue backlog, false/forged ACK, invalid host key and revoked device.
- Bound all test volumes and sampling cadence; no persistent speed-test loop. Benchmark time from sample capture to manager notification, but do not advertise <=90s before actual measurement.

## Phase B — isolated Core and relay provision (only when approved)
- Create restricted monitoring-only SSH user on **test target**, disposable non-customer public key, independent pinned host key; disable interactive PTY, shell and any arbitrary forwarding, restrict only `127.0.0.1:18180`. Keep Root and customer credentials completely separate.
- Run `ops/denaprobe_static_responder.py` on relay loopback only after review; default body precisely 16KiB `0x5A` and graceful EOF. Confirm no public listening socket.
- Provision independent `v2-` key-ID+secret for board, physically ignored config only, trusted CA and correct `/api/dpt/v2/telemetry`. Do not reuse or re-enable revoked DPT/1 key IDs.
- Stage/backup independent Core DPT Collector and run only its loopback service; verify `/healthz`, unauthenticated v2 403 (only after opt-in), HMAC+ACK accepted, invalid HMAC 403 and v1 unchanged. No additional public telemetry route or new Telegram poller.
- Device operator label is a **manually declared** `dp3_operator_labels` metadata field, never auto-deduced from hotspot SSID or Wi-Fi RSSI.

## Phase C — physical ESP32 ↔ Core (only when approved)
- Manual ESP32 flash with verified pin/secret, COM serial monitor and Wi-Fi hotspot only; **no SIM800L**.
- Confirm TCP preflight code, SSH host-key pin, auth, first and second transfer, sample sizes, channel-open failures vs transfer failure, Wi-Fi-loss->LOCAL_UNMEASURABLE, worker watchdog, heap budget, journal FIFO and 200 signed ACK.
- Verify `dpt2_latest.monitoring_gap` clears on two eligible fresh q only, and direct HTTPS newest seq is independent. Force offline/reconnect and retained historical q; historical events cannot open or recover incidents.
- Independently record tests for HEALTHY, D0, D1, D2, MONITORING_UNKNOWN and RECOVERED. Compare against Windows healthy and degraded evidence without claiming DPI or ISP culpability. If Deep libssh fails on real ESP32, stop rollout and leave optional feature OFF.

## Phase D — Rich monitoring manager pilot (only after physical acceptance)
- Review admin-only DB access and allow entry `NVL_DENAPROBE_R3_ENABLED=1` for a controlled window; current bot process exclusively owns Telegram token and UI.
- Validate 30s schedule, two distinct fresh q for open/change/recover, independent 6min direct control freshness, no false recovery on absent telemetry, no duplicate on retry, retired-admin queued alert suppression and 5min historical notification replay bound.
- Verify Bot API 10.3 Rich Message on iOS and Android: native blocks, compact RTL tables, contextual footer, buttons, source/receipt times, last accepted evidence; no HTML fallback. Confirm a forbidden/forwarded callback does not reveal details.
- Use real administrators only; verify OPEN and RECOVERED messages separately, and ambiguous Rich transport send is journaled `UNCERTAIN` and held for manual review.
- Confirm optional feature startup fails closed and normal bot continues when DPT package or DB absent, provided enable flag is OFF.
- Only after field evidence and explicit signoff, make the flag persistent. Activation is a deliberate service restart separately approved; **not done during source implementation**.

## Rollback and boundaries
- Immediately set `NVL_DENAPROBE_R3_ENABLED=0` if dashboard/alerts misbehave; retain incident history for review and do not delete SQLite event records.
- Switch only independent Collector back to v1 mode and preserve signed DPT/1 data. Restore isolated collector from backup if necessary. Flash previous known-good board firmware manually if deep-worker memory or auth fails.
- Never auto-change default relay, NPV customer accounts, DNS, GOST, remote SSH service, firewall policy, or Telegram admin permissions as a side effect of classification.
- Document real measured time-to-alert, false positives, incident IDs, CPU/heap, LTE usage and operator baseline. Treat **Source Merged / CI PASS** and **Field Accepted** as separate release statuses.
