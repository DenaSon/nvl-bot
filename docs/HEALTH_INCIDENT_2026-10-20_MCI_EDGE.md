# NVL Incident Record — 2026-10-20 — MCI-specific reachability failure on former Edge IP

**Status:** RESOLVED (owner-reported)  
**Impact:** Some SSH customers on **Hamrah-e Aval / MCI** remained at `Connecting` when using the then-default relay; access on **Rightel** worked. Full impacted-user count and duration not independently measured.  
**Service:** SSH customer traffic on TCP **2252** (`2088` is optional separate TLS service).  
**Former Edge IP:** `172.86.92.41` (Frankfurt).  
**Core:** SSH-terminating Core behind Edge DNAT + WireGuard.  
**Recovery:** Operator reports a colleague provisioned a **completely new VPS with a new IP**, activated it as the relay, and customers were again able to connect. New public IP not provided in the incident record.

## What was observed (UTC 2026-10-20)

1. **Core and relay:** Core `nvlbot` and SSH listeners active; WG Core–Edge route and peer responsive; TCP SSH banner reachable. Edge `iptables` DNAT `2252 -> 10.77.0.1:2252` in place, counters increasing.
2. **Former VPS outbound and load:** At approximately 17:29, public TCP 443 connects to 1.1.1.1, 8.8.8.8, 9.9.9.9 succeeded; HTTPS returned 200/204; short five-packet ping to 1.1.1.1 had 0% loss; `eth0` observed ~61 Mbps RX and ~60 Mbps TX during a 10-second window, no measured interface drop/error. Conntrack `263 / 8192`. These are **point-in-time checks** and do not prove ISP ingress reachability or exclude intermittent loss/limits.
3. **Existing regional TCP monitor:** Persisted Edge row recorded `filter_state=CLEAR`, `regional_filter_state=CLEAR`, `regional_filter_reason=HEALTHY_QUORUM`, `provider_status=OK`, 7/7 successful Check-Host nodes, at `2026-10-20 17:29:16`. This only proves the type of TCP check performed by those nodes, not protocol completion on MCI.
4. **Windows OpenSSH test on a working network:** TCP connection established, SSH banner and KEX completed, server host key matched the Core ED25519 fingerprint, received `SSH2_MSG_SERVICE_ACCEPT` and authentication methods. The deliberately non-authenticating `probe` user exited with `Permission denied` as expected.
5. **Windows OpenSSH tests on affected network:** On two runs with an actual account and another with `probe`, TCP connect, banner, KEX, `NEWKEYS`, `SSH2_MSG_EXT_INFO` succeeded. Each then ended with `ssh_dispatch_run_fatal: Connection ... port 2252: Connection timed out` **without** a recorded `SSH2_MSG_SERVICE_ACCEPT`. No SSH password was needed to reproduce the failure.
6. **Owner's confirmed cross-network comparison:** The former IP was blocked/filtered from **MCI**, while **Rightel** could connect. A new VPS/new IP restored the reported customer connections.

## Conclusion and confidence

- **Operational root-cause category:** **ISP-specific reachability/filtering of the former Edge public IP on MCI**, based on owner-controlled cross-ISP tests and recovery after changing VPS/IP. This is the resolved incident classification.
- **Packet-level mechanism:** **UNKNOWN**. The evidence does not distinguish selective DPI intervention from other ISP-path packet drops or resets, nor prove which device/network applied them.
- **VPS configuration vs public IP:** Replacing the entire VPS changed the public IP, host OS/kernel/runtime state and possibly network path together. Reinstall of the former VPS keeping its IP was discussed; **no post-reinstall controlled result is recorded here**. A clean A/B isolation was not performed.
- **Reachability nuance:** One connection being `TCP_CONNECTED` or `KEX_COMPLETE` is insufficient to mark `SSH_AUTH_READY` or a functional SOCKS tunnel.
- **Cross-ISP claim limit:** No public third-party provider with 7/7 TCP responses can guarantee successful SSH for all Iranian operators.

## Monitoring gap / durable follow-up

Existing monitoring is technically consistent with its **TCP-only semantics** but unsafe to present as universal user reachability. Keep infrastructure, 6D TCP quorum, SSH stage reachability and per-ISP evidence as different dimensions with independent freshness/provenance; unavailable ISP measurements must be `UNKNOWN`. No automatic 6H failover may be driven by Health Center diagnostics without a separately approved safety design.

**Planned response:** [Health Center HD-01/HD-02 roadmap](HEALTH_CENTER_HD01_HD02_ROADMAP_2026-10-20.md), two phases (diagnostic engine + TXT/JSON; then Telegram admin UI). This incident record is **documentation**, not a code deploy, a change to monitoring verdicts or a change to active relay.

## Operator safety note

Do not reactivate the former Edge, modify `n1.nvlsup.com`, or force a failover to investigate this closed incident. Any later experiment with the old IP should be a separate, explicitly approved, client-isolated field test with an immediate rollback path.
