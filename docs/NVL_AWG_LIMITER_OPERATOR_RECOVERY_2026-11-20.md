# NVL AWG Limiter operator recovery — 2026-11-20

## Incident
During AWG STANDBY → QuickSwitch, the independently renewed 120-second
Limiter markers were absent for every standby. The root timer ran every
30 seconds but exited 2. The operator's read-only checks proved AWG
peer/path/route, the approved Limiter file, functional exemption and ipset
all passed; only the Limiter running process check failed with
`LIMITER_SOURCE_CHANGED_AFTER_START`. A controlled restart of
`ssh-limiter.service` restored `AWG_WITNESS_REFRESH=READY count=3`
and the new Edge readiness marker.

## Recovery UI
In an owned AWG STANDBY Edge, open **عیب‌یابی و بازیابی Limiter**.
The page reads the verified AWG binding, installed Limiter source, live
process identity and independent marker. No bot action creates a marker.

Only a verified **shared superadmin** can approve the one-time action
when the exact blocker is `LIMITER_SOURCE_CHANGED_AFTER_START`.
The confirmation expires in 120 seconds and is consumed once. The
operation rechecks the blocker immediately and restarts **only**
`ssh-limiter.service`. It does not change sshd, VPN, AWG peers, routes,
NAT, DNS, users, jobs, journal locks, or markers. The independent timer
must reattest the marker; refresh the Edge details after its next run.

Other failures, including source hash mismatch, process image mismatch,
service down, unverified binding and missing witness, have **no** restart
button. Their explanatory status remains visible. Full route/CAS/lease
guards remain enforced by the transfer engine; UI recovery does not
start a transfer or release any shared 6G / CZ07 lock.

## Release requirements
1. Deploy `nvl_awg_limiter_recovery.py` alongside
   `manual_edge_wizard.py` before restarting `nvlbot`.
   Verify `/usr/bin/python3 -m py_compile` of both; do not publish the
   wizard without its new import.
2. Run `python3 -m unittest tests.test_nvl_awg_limiter_recovery` and the
   established bot regression suite.
3. If the deployment changes `/root/ip_limiter.py`, restart the
   trusted service as a separately controlled deployment step. Do not
   assume that editing the file updates the already running process.
4. Verify `systemctl is-active ssh-limiter.service`,
   `systemctl is-active nvl-awg-witness-refresh.timer`, and
   `AWG_WITNESS_REFRESH=READY` before allowing operational cutover.
5. Keep the unresolved historical CZ07 HOLD journal separate: an
   arbitrary manual unlock must never replace route/account/DNS
   reconciliation.

Related pending PR #309 addresses ignored CANCELLED history and safe
per-Edge witness failure codes. It should be evaluated separately,
rather than duplicating those changes in this branch.
