# NVL — Phase 4: Cloudzy Edge install / Standby recovery

Date: 2026-10-28. Scope: the existing Programs → Cloudzy | Edge/Relay CZ03, CZ04A, CZ06 paths. Source-only until operator-controlled deploy.

## Audited legacy effect boundaries

The actual setup_edge_relay.sh performs apt installation (limited lock wait), overwrites /etc/wireguard/wg0.conf, restarts wg-quick@wg0, changes IPv4 forwarding, **unconditionally appends** SSH and TLS PREROUTING DNAT and POSTROUTING MASQUERADE via iptables -A, persists firewall rules, edits SSHD configuration and restarts SSH. Replaying it after any partial install or crash can duplicate NAT rules, overwrite a tunnel or interrupt admin access. NO automatic installer resume or replay is authorized.

## Implemented

1. Before the existing Legacy Edge installer begins, a live Cloudzy GET of the **exact provider server ID** must attest matching public IPv4 and (if returned) hostname and ACTIVE state. Recycled IP / wrong provider ID / changed name => HOLD_PROVISION, zero installer calls.
2. After the potentially effectful installer, but before setting the paid operation receipt EDGE_READY, reattest provider server ID, public IP and hostname; independently re-observe pinned SSH host key and Core public-key hash/customer port. Any drift => HOLD_PROVISION. The existing protected Legacy verification and WG/Core probe remain mandatory.
3. An **already committed** Standby from a previous run is no longer accepted on SQLite flags alone: verify protected CZ04A/6G gates, exact provider server ownership/IP, no customer/routing exposure, disabled auto/K2, and fresh SSH/WG/Core-path probe. After a new promotion, re-read the committed state and repeat these live checks. If a post-commit check fails, CZ06 enters HOLD; a later operator recovery checks the SAME VPS, never performs a second promotion.
4. New cloudzy_edge_install_evidence.py is a pure read-only manifest parser for trusted operator-supplied readings (public wg0 peer, IPv4 forwarding, active SSH/TLS DNAT, singleton MASQUERADE and persisted NAT). Wrong peer, duplicate/different DNAT, missing TLS, missing persisted rules or disabled forwarding => INSPECT_ONLY. Its all-PASS verdict is only COMPLETE_OBSERVATIONS_NOT_ADOPTION; it cannot alone approve EDGE_READY.
5. Existing owner/chat/single-use nonce, Core 6G, CZ03/CZ04A receipts, manual Smart Recovery and original Legacy provisioning remain. No new purchases, DNS, customer migration, K2, Cloudzy deletion or iptables writes originate in the new code.

## Read-only evidence collection (separately approved disposable Edge)

- wg show wg0 peers — public peer key only, never any private key.
- sysctl -n net.ipv4.ip_forward.
- iptables -t nat -S — strictly no -A or -I.
- iptables-save -t nat or read persisted IPv4 firewall rules.
- Separately authenticate the collection source and verify hostname, Cloudzy provider ID/IP, independently pinned SSH host key, correct Core port/key, fresh WG handshake, Core-path SSH test, no linked customers or route references.

**Unknown observation is never healthy.** Remote handshake, installer package state and SSHD drop-in cannot be established from local SQLite rows alone. The manifest does not perform SSH, call Cloudzy, read files on a remote Edge or contain private keys. No live NAT or Core network changes were carried out in development.

## Regression and operator acceptance

Tests: provider-ID replacement, reused public IP, hostname swap before Legacy install, provider/host-key/Core identity drift after effects, APT busy and failed legacy verification, existing Standby with broken probe or provider state, post-promotion probe failure with one same-VPS adoption, extra NAT rules, inconsistent persisted rules, wrong WG peer/disabled forwarding.

Stage new source and full tests from exact master SHA before controlled Core deployment. The Core P3 binary currently may match previous SHA 08c56c4 while the friendly-error patch 04db3d1 is merged but not yet published. Compare exact deployed file hashes against that baseline before replacing code. For phase 4, runtime files changed are cloudzy_quick_edge.py and cloudzy_cz06_orchestrator.py, plus newly added cloudzy_edge_install_evidence.py. Never broadly copy the repository or alter the running bot entrypoint.

Live acceptance requires a separately approved disposable VPS and an induced interrupted-install / recovery drill with independent live Cloudzy, SSH, WG, iptables and provider evidence. A fully idempotent per-step reinstaller is **not implemented** because the original script is non-idempotent and its effects cannot safely be retried. This is an explicit remaining Phase 4 gate, not a hidden claim that all deployment outcomes are recoverable.
