# Production Audit — 2026-09-30

## Fixed and validated

- Paramiko resource leak that caused hundreds of SSH connections, sockets, and threads.
- Capacity monitor double-counting sessions through Edge service ports that DNAT back to Core.
- Capacity auto-lock now executes on Core, synchronizes DB state, terminates live sessions, and rolls back Linux lock if DB update fails.
- Hidden On Hold activation callback bug (`coroutine was never awaited`) fixed.
- On Hold first-connection flow validated end-to-end, including Linux expiry synchronization.
- Repeated Telegram `editMessageText` with identical content no longer creates an unhandled `Message is not modified` traceback.

## Production state after fixes

Observed healthy process state after deployment:
- service active
- 8 threads
- 0 swap
- RSS around 150 MB
- no restart loop

## High-priority technical debt

### Control plane vs data plane
`host_pool.ssh_port` is overloaded for both customer service traffic and management SSH. Edge customer service ports can DNAT/WireGuard back to Core, while management SSH is a different path. Split these concepts into explicit fields such as `service_port` and `admin_ssh_port`.

### Fast filtering / reachability detection
Current filtering detection primarily reacts to a sustained drop in online SSH users. There is also host-health monitoring, but probes originating outside Iran cannot prove domestic reachability.

Design a multi-signal reachability system:
- domestic synthetic probes from multiple networks/ISPs
- actual TCP/service-port checks, not ICMP alone
- global probe to distinguish server outage from domestic filtering
- session-drop signal as supporting evidence
- verified standby target before failover
- confirmation/quorum and cooldown to prevent false failover/flapping

### Mobile IP changes / roaming
Reproduce and measure user disconnects when a mobile provider changes the client public IP. SSH/TCP sessions cannot seamlessly migrate to a new source IP; investigate client auto-reconnect and recovery time so reconnect can be made fast and transparent.

### Security hardening
- move remaining hardcoded operational credentials/defaults to runtime configuration
- rotate exposed/previously logged credentials after the audit
- suppress Telegram token-bearing HTTP request URLs from INFO logs
- replace permissive SSH host-key handling (`AutoAddPolicy`) with verification
- review provisioning defaults that enable password/root SSH login
- harden firewall after traffic/control paths are fully mapped

### Monitoring correctness
- distinguish Edge management health from customer service reachability
- ensure forwarded service ports are never mistaken for management SSH health
- review monitoring duplication/caching around live connection counts

## Deferred / tracked

- shutdown lifecycle noise (`Event loop is closed`) observed only on the old process during restart
- provider/CPU-steal investigation if high steal/load reappears
- inactive/retired Edge cleanup
- HTTP logging hygiene
