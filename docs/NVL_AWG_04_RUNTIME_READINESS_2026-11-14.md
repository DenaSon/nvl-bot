# NVL-AWG-04 — Runtime Limiter Witness, UI Honesty, Former Edge Rearm

Status: SOURCE ONLY. No Core/Edge, firewall, DNS, user, or runtime changes are made by merging this PR.

## Changes

1. A separate root-only `nvl_awg_limiter_witness.py` operator utility can issue the existing short-lived `/run/nvl-awg-limiter-ready` marker for **one explicitly registered managed AWG Edge**. It is never called by a Telegram callback.
2. It validates a VERIFIED `edge_tunnel_bindings` record and managed Edge lifecycle, fresh Core AWG peer/path, exact installed `/root/ip_limiter.py` bytes against the reviewed `promote_edge_to_core.sh` generated template, live root-owned `ssh-limiter.service` PID/cmdline and script age, the shared-source exemption via an isolated functional probe, and absence of the /32 in `ssh_penalty`. Failure deletes the previous marker and returns HOLD.
3. Quick Switch continues to require `NVL_AWG_CUTOVER_ENABLED=1`, matching verified target and the independent fresh marker. Marker validation now also checks the actual limiter service is active, with a 120-second expiry. No systemd service/timer is installed automatically.
4. AWG standby and former-rearm UI no longer offer Cutover while the gate is not ready. The former Edge rearm uses its registered backend: AWG read-only pinned verifier (including NAT) or the original WireGuard probe/NAT; the journal atomically rechecks registry/backend before rearming. Legacy WireGuard path is preserved.
5. AWG markers do not enroll the already-serving unregistered pilot Edge. No production actions are authorized.

## Release process

- Pin the reviewed `master` commit and follow the NVL deployment runbook (staging worktree, `py_compile`, tests, DB/runtime backups, runtime file hash checks, `nvlbot` journal). A Git merge is not a Core deploy.
- **Do not replace or restart the existing Core limiter automatically.** This new witness rejects an older or customized running limiter if it does not exactly match the reviewed promoted template. First inspect and plan a separate approved limiter upgrade if needed.
- Deploy `nvl_awg_limiter_witness.py` as root-owned, mode `0755`, along with the pinned code. The reviewed `promote_edge_to_core.sh` must be present at `/root/promote_edge_to_core.sh`; it is only read, never executed by this witness.
- Keep both `NVL_AWG_NEW_EDGE_ENABLED` and `NVL_AWG_CUTOVER_ENABLED` at their default OFF until the fresh-server pilot and acceptance criteria pass.
- On a **separate new Ubuntu 24.04 VPS**, test the bot's AWG install, SSH/TLS NAT, reboots, pinned host key, NPV client egress, fresh handshake, and preserved legacy services. Do not re-install the existing serving AWG Edge.
- After a verified target reaches STANDBY, the operator can run the root-only command below on Core for that specific registered Edge:
  `/usr/bin/python3 /root/nvl_awg_limiter_witness.py --host <FRESH_EDGE_PUBLIC_IPV4>`
  It must return `AWG_LIMITER_WITNESS=READY`. `HOLD` means no cutover.
- Use a **single approved root-owned** recurring timer for the one selected target to renew the marker while any DNS/Quick Switch recovery could be in progress. Do not permit multiple concurrent witness timers for different Edges. The marker is intentionally short-lived.
- Only then enable the existing guarded AWG cutover flag as a separate explicitly approved release step. Verify real ISP NPV traffic and the exact DNS/account snapshot again in Quick Switch. Keep the original WG backend until its Core-promotion/recovery dependencies are individually accepted.

### Optional operator-installed service and timer (not deployed by the PR)

Create `/etc/systemd/system/nvl-awg-limiter-witness@.service`:

```ini
[Unit]
Description=NVL AWG limiter witness for registered Edge %i
After=ssh-limiter.service
Requires=ssh-limiter.service

[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/python3 /root/nvl_awg_limiter_witness.py --host %i
NoNewPrivileges=true
```

Create `/etc/systemd/system/nvl-awg-limiter-witness@.timer`:

```ini
[Unit]
Description=Renew NVL AWG limiter witness for selected Edge %i

[Timer]
OnActiveSec=5s
OnUnitActiveSec=30s
AccuracySec=5s
Unit=nvl-awg-limiter-witness@%i.service

[Install]
WantedBy=timers.target
```

After independent production checks and operator approval, `systemctl daemon-reload`, enable **one** selected instance (for example `systemctl enable --now nvl-awg-limiter-witness@<EDGE_IP>.timer`), inspect `journalctl -u ...`, and ensure its refreshed marker maps to the selected /32. To revoke, stop that timer **and delete** `/run/nvl-awg-limiter-ready`; then turn the cutover flag OFF. This is never automatic during Git deployment.

## Failure semantics

- The witness does not touch any network configuration. It has only the authority to create/revoke a short-lived root-owned 0600 marker.
- Expired/missing marker, wrong host, no verified binding, limiter mismatch/restart/failure, banned shared source, invalid peer/path, or another guard: **HOLD**.
- An interrupted installer remains `INSTALL_HOLD`. Never replay setup on an existing Edge.
- DNS/SSH account migration is still performed **only** by the existing journalled Manual Quick Switch + Cloudflare exact-record + 6G lease and recovery process.

## Source-only tests

```bash
python -m py_compile manual_edge_journal.py manual_edge_wizard.py manual_quick_switch_ui.py nvl_awg_target.py nvl_awg_limiter_witness.py
python -m unittest tests.test_nvl_awg_04_readiness tests.test_nvl_awg_target tests.test_nvl_awg_wizard_gate -v
python -m unittest discover -s tests -p 'test_*.py'
```

All tests are offline; none proves a real customer ISP path. Deploy and canary remain distinct approval gates.
