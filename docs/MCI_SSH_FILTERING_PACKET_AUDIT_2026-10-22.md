# NVLBot — MCI SSH filtered-Edge incident, handshake and packet audit (2026-10-22)

**Compiled:** 2026-10-29  
**Status:** Historical operator-supplied **network incident audit**, not new production measurement or deploy.  
**Incident date:** 2026-10-22 (operator-reported).  
**Related, separate event:** [2026-10-20 MCI incident](HEALTH_INCIDENT_2026-10-20_MCI_EDGE.md).  
**Design reference:** [HD-01/HD-02 health roadmap](HEALTH_CENTER_HD01_HD02_ROADMAP_2026-10-20.md) and DenaProbe's `docs/006-FILTERED-PATH-AUDIT-2026-10-29.md`.

## 1. Operational determination and evidence boundary

The operator describes the former public Edge IP as **filtered for users of MCI**: affected customers were prevented from connecting to the SSH service, while the same endpoint was usable from Rightel. **This is an operational incident classification based on customer impact, operator-side cross-ISP comparison and repeatable SSH behavior.** It does **not** establish the responsible middlebox, packet-policy rule, DPI mechanism or exact network segment dropping traffic.

The operator provided a detailed retrospective audit with SSH stage comparison and paired TCP-capture analysis. **Raw captures were not independently inspected during this documentation update.** Keep this distinction in any external or automated report.

## 2. Sanitized network topology

```text
Customer device (MCI vs Rightel)
      |  TCP/2252 SSH-Direct
      v
Public Edge (DNAT to Core over WireGuard)
      |
      v
Core SSHD (authentication / actual forwarding)
```

The report states SSHD and WG were responsive, DNAT was present with traffic counters and there was no observed general Core outage. These are bounded observations, not guarantees about every packet path. Original Edge, Core/WG and customer IPs are **intentionally excluded from this public note**.

## 3. Controlled network comparison (operator report)

| Protocol stage | MCI / affected | Rightel / control |
| --- | --- | --- |
| TCP connect | PASS | PASS |
| SSH identification | PASS | PASS |
| KEXINIT / KEX | PASS | PASS |
| NEWKEYS / EXT_INFO | Reached | Reached |
| SSH `SERVICE_ACCEPT` | **Not observed** | PASS |
| End state | SSH timeout after key exchange | Userauth phase reached, expected denial for invalid `probe` user |

The diagnostic `Permission denied` on Rightel is **not** evidence of connectivity failure: intentionally invalid credentials were used after the server became authentication-ready. The MCI failure happened **earlier**, after `NEWKEYS` and `EXT_INFO` and before `SERVICE_ACCEPT`. Therefore a TCP-only health verdict and even a banner-only SSH verdict can incorrectly appear green.

`EXT_INFO` is optional and its omission on a future trace should not automatically be considered failure. `SERVICE_ACCEPT` proves entry to SSH userauth service only, not successful login or customer tunnel functionality.

## 4. Bidirectional capture claim (operator report)

- Windows: **34 packets**; Edge: **18 packets**; report says TCP stream sequences were matched.
- Edge payload: `SEQ=2187604102`, `492 bytes`; recorded Windows ACK: `2187604594` (= SEQ + 492).
- Windows captured further client-side data (reported as **16- and 60-byte** sends).
- Edge capture did **not show** the ACK or those subsequent client sends; Edge reportedly retransmitted its data segment.

**Inference if the captures are complete and comparable:** The client received/acknowledged the Edge segment locally, while traffic subsequently emitted by the client was not visible at the Edge capture point. This suggests a **client-to-Edge delivery/observation problem**. It does not independently identify filtering hardware, interception rules, hotspot NAT effects or whether capture filters/drops omitted packets.

**Forensic follow-up:** Before asserting packet loss at a particular hop, privately review full captures, direction/interface, NAT tuple, clock alignment, capture filters, capture drop counters, TCP timestamps/retransmissions and any offload artifacts. Never commit raw packet files to this repository.

## 5. Transport comparison and alternative hypotheses

A `wstunnel v11.1.0` TLS/WebSocket sidecar was reported on the **already affected** Edge IP. On MCI, TCP, TLS, WS upgrade, Core SSH connection and SSH identification succeeded but subsequent SSH exchange was unstable; on Rightel, `SERVICE_ACCEPT` was reached. The initial test inadvertently used a local HTTP proxy and is excluded. This comparison **does not prove DPI detects WSS**.

Operator reports other relay IPs were affected at other times, while previously usable IPs later developed the same MCI symptoms. Relevant hypotheses: operator-specific policy, destination-IP treatment, path or transient packet loss, hotspot/network behavior. **No evidence isolates an IP-age threshold, user count, bandwidth threshold or automatic blacklist rule.**

This incident was not a full TCP block; failure was **stage-specific**. Do not conflate it with the independent **2026-10-28/29 Windows HTTPS hostname-dependent TLS** experiment documented in DenaProbe.

## 6. Engineering consequences (documentation only)

- **Per-vantage results:** A reported MCI `FAIL_AFTER_NEWKEYS` must remain separate from Rightel `SERVICE_ACCEPT_PASS` and 6D regional TCP `CLEAR`. No provider TCP quorum can certify the affected ISP's SSH or real customer session.
- **Protocol stages:** `TCP_CONNECTED` → `SSH_BANNER_RECEIVED` → `KEX_COMPLETE` → `SERVICE_ACCEPT_RECEIVED`; report observed stop stage, reason and provenance. Do not infer an unobserved stage as pass.
- **Trust and privacy:** Future zero-credential SSH probes need trusted host-key pinning and fail-closed mismatch handling. Do not store credentials, customer accounts, IPs, raw captures or host secret data in public artifacts.
- **Application truth:** Neither `SERVICE_ACCEPT` nor `Permission denied` proves a functioning NPV Tunnel. Only a separately observed authenticated reference-client data path establishes that outcome.
- **DenaProbe gap:** Physically validated ESP32 v0.0.4 checks **DNS/TCP/banner only**. A filtered-path ESP32 audit and secure KEX/SERVICE_ACCEPT feasibility study are **pending**.
- **Boundaries:** This historical report **does not** change operational `host_pool` flags, 6E/6F monitoring, 6G/6H failover eligibility, default Edge, DNS, WG, SSHD, bot/API, telemetry, scheduler or infrastructure. No production tests or migrations are authorized by adding this note.

## 7. Evidence and verification status

| Evidence | Status |
| --- | --- |
| Incident description, SSH sequence, customer effect, cross-ISP result | Operator-reported |
| Paired capture packet numbers, sequence/ACK, missing Edge packets | Operator-reported; **raw trace review pending** |
| Windows HTTPS control comparison | Separate supplied console experiment; see DenaProbe Audit |
| Cause of delivery gap / filtering mechanism | **UNKNOWN** |
| ESP32 reproduction of 2026-10-22 SSH failure | **NOT TESTED** |
| Production mitigation or new filtering logic in this documentation change | **NONE** |

**Keep original packet captures and detailed machine logs in an approved private evidence location; only publish reviewed sanitized summaries.**
