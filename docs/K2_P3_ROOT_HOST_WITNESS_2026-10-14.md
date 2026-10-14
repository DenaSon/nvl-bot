# K2 Phase 3 — Root-only, read-only Core UID host witness (2026-10-14)

**Status:** source implementation and offline tests. **No live Core/Edge test, rollout, F4 acceptance or privileged mutation has occurred.** Parent PR #120 remains Draft.

## Scope and interfaces

`ops/k2_p3_host_readonly.py` is a **root-only, read-only** Core command that composes existing F2/H/PAM/F4 checks for one already-PROTECTED Unix UID. It reads the exact `/root/master_bot.db` using SQLite `mode=ro` and `PRAGMA query_only=ON` and reads the existing root-only V1 roster/guard; never installs a module or edits PAM, systemd, WireGuard, routes, firewall, DNS, SSH users, F4 state or 6G.

It fails closed on:

- Wrong or missing *real* Unix UID, ambiguous active SSH owner/default Edge/public DNS, any concurrent RUNNING 6G, or invalid global protected-mode value.
- Missing/partial/foreign F2 `PROTECTED` runtime and protected mapping, unrostered pending or other protected UID, F3/spec mismatch (including full veth/tunnel/uplink/listen/route ownership) or missing/fresh F4 acceptance.
- Missing V1 PAM **first account** rule, incorrect `UsePAM yes` in actual per-user/per-listener `sshd -T -C` result, or untrusted installed V1 hook SHA256/owner/path.
- Missing root-only V1 roster+guard, mismatch of OS UID/manifest/F3, actual wg0 ingress peer vs root registry, failed V1 PAM protected admission, missing per-UID iptables/route terminal blackhole/DNS unit/BootGuard from the existing `edge_egress_f4_kernel_audit`.

This command reports only `LOCAL_PASS` or `HOLD` and machine-readable blocker codes. **Even LOCAL_PASS always returns `customer_ready=false`, `packet_no_core_leak_proven=false`.** It does not mint `FreshEvidence`, F4 witness, P3 execution ticket or Telegram transfer authorization. It is suitable as a conservative **non-mutating** Core snapshot before authorized disposable-VPS acceptance; it does not pretend an operational Linux host has been tested via GitHub.

## Usage — reviewed disposable Core only

After an independently approved deployment of this code and root-only V1 admission installation, with root console rescue confirmed:

```bash
python3 -m ops.k2_p3_host_readonly \
  --username 'nvl0557' \
  --edge-id 'e7' \
  --ingress-source 'SOURCE_EDGE_PUBLIC_IPV4' \
  --edge-ip 'EGRESS_EDGE_PUBLIC_IPV4' \
  --pam-rhost '10.77.0.X' \
  --ssh-local-addr '10.77.0.1' \
  --ssh-local-port 2252 \
  --reviewed-v1-gate-sha256 '64_lowercase_hex_digest'
```

All addresses are operator-supplied *pins*, never downloaded or inferred from the current primary route. `--pam-rhost` must be the **actual Core-observed** SSH WireGuard peer; it is not a public client IP. The V1 hook SHA must come from independent reviewed source bytes, not a hash provided by an unknown host. Do not run on the existing customer Core as an installation procedure.

## Test and release boundary

```bash
python3 -m unittest tests.test_edge_egress_k2_p3_host_readonly -v
```

Integration tests use an actual temporary SQLite Core schema populated by the existing K2 source-enrollment lifecycle, with fake kernel and packet observations; they verify failures for UID drift, missing/foreign F4, root roster/guard, 6G busy, F3 mismatch, PAM syntax, missing kernel/ingress proof, untrusted hook path and non-root CLI rejection.

**Remaining blockers:** root-only host mutation/installer and independently reviewed recovery strategy; external SSH/SOCKS public Edge IP; packet capture proving DNS UDP/TCP/NSS/IPv6 non-leak; dedicated WireGuard loss/restore, cold-boot failure, PAM forwarding and out-of-band root/admin rescue; separate operator F4 review and actual controlled single-user acceptance. Phase 2 source logic is not a production transfer. Issues #106/#108 stay open; never merge parent #120 into master or enable default-off release flags based on LOCAL_PASS.
