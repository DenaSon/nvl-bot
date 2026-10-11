# NVL Edge Egress — F4 Release Acceptance and Controlled Cutover

**F4 status:** GitHub code + offline/read-only acceptance tooling, **not a
finished production deployment**. This document intentionally records blockers
instead of granting a customer-ready flag from CI or from a manually completed
checklist.

**Baseline:** F1 #84, F2 #85, F3 #86 merged into `master`. Production Core
`209.200.246.198`, existing ingress Edge `172.86.94.174`, tested shadow
Egress Edge `216.126.229.12`. First candidate: `nvl0557` / UID 1644.
Values are historical audit observations, **not current-time attestations**.

## Invariants

- No direct Core public IPv4 egress for a `PROTECTED` account. Reject any
  fallback including traffic outside an SSH session, proxy-configured HTTP,
  DNS/NSS helpers, IPv6 and BadVPN/UDP.
- Do not change production `wg0`, global default route, `ssh.service`
  coupling, working legacy ingress, public DNS or existing `ssh_accounts.host`.
- A protected account's route MUST select its owned table with a terminal
  blackhole; when Edge is down, only denial is valid.
- Global SSH must remain independently reachable for unaffected users;
  emergency console/root and a non-root administrator must be tested **in a
  disposable full-system VPS** before any PAM change.
- All protected UID/Edge writes require the existing single 6G lock and
  durable journal. `HOLD` blocks reuse/recovery without an operator.
- Multiple UIDs share one per-Edge table. A table freeze is an Edge-wide
  outage; do not describe it as a one-UID freeze.
- `READY` must never result from `STAGED`, `VERIFIED_LAB`, a single
  `curl` or simulated unit tests.

## Implemented in this F4 PR

1. `edge_egress_f4_preflight.py` — read-only Core inventory:
   account/UID/source/default ingress host, public ingress DNS, required DB
   tables, active 6G lock, staged Edge allocation/readiness, existing protected
   mapping, `ssh`/`nvlbot` availability, effective per-user `sshd -T` and
   PAM hook. Returns machine-readable blockers. Passing **does not**
   activate a route or prove a packet path.
2. `edge_egress_f4_pam.py` — exact PAM account hook offline plan and
   inspection; no automatic `/etc/pam.d/sshd` writes or restart. Place first
   account rule only in an approved full-system disposable VM with console.
   A live direct-TCPIP/SOCKS test MUST show that the PAM hook is actually
   executed on every supported customer authentication path.
3. `edge_egress_f4_ssh_probe.py` — external client-only `curl` through
   `socks5h://127.0.0.1:<port>` over an **already-established SSH -D
   session**. Requires exact public Edge IPv4. If Edge is deliberately down
   **only in the disposable VM**, it requires a connection error; success
   through *any* IP is a release failure. It cannot prove DNS/IPv6 leaks
   without simultaneous packet captures.
4. `edge_egress_f4_release.py` — bounded structured evidence for 18 named
   real E2E tests including SSH proxy, PAM, reboot, IPv6/DNS/BadVPN,
   restoration, and admin reachability. It rejects stale/wrong-host/wrong-UID
   artifacts. Even complete results are only
   `CANDIDATE_FOR_INDEPENDENT_REVIEW`, `customer_ready=False`. Assertions
   in this file are not cryptographically or independently verified.
5. `edge_egress_uid_boot.py` — rejects wider competing UID range selectors,
   which could otherwise route protected traffic via Core/main.
6. New tests for all of the above run in the normal Python CI.

## Safe, read-only Core inventory

On a shell with current repository code installed but WITHOUT activating
protected mode (this emits no credentials):

```bash
python3 edge_egress_f4_preflight.py \
  --username nvl0557 --uid 1644 \
  --source-ip 172.86.94.174 \
  --edge-id fra1 --edge-ip 216.126.229.12
```

Expect blockers at this stage: F1–F3 did not install PAM, F3 readiness
migration may not exist in production, and no production Egress is enabled.
**Do not bypass or fake blockers.** This command must not be interpreted as
permission to install anything.

## Mandatory disposable full-VPS procedure — not CI namespace-only

1. Create a **fresh, disposable Core/Edge pair** from tested backups.
   Isolate IP addresses, all DNS/notification/webhooks, bots, and actual
   customers; do not reuse production secrets or allow clones to reach live
   control-plane endpoints. Verify independent out-of-band console first.
2. Reproduce the installed versions of Linux, OpenSSH, PAM, iptables backend,
   systemd service/socket activation, WireGuard and BadVPN. Document per-user
   `sshd -T -C user=...`, PAM stack and listener forwarding behavior.
   Test emergency root + non-root administrator recovery.
3. Install only explicitly reviewed, root-owned F1 guard + DNS manifests in
   the **disposable clone**. Verify that every supported SSH authentication
   mode and dynamic/direct-TCPIP forwarding session hits the PAM account
   gate; verify an existing user session is drained BEFORE protected intent.
   A globally required DNS service that can kill all SSH is forbidden.
4. With Edge actually routed, establish a real SSH-D SOCKS session *from a
   different machine*, using the test account/password securely. For example,
   `ssh -N -D 127.0.0.1:31884 -p <SSH_PORT> nvl0557@<CLONE_SSH_HOST>`.
   Then on the same external machine run:

   ```bash
   python3 edge_egress_f4_ssh_probe.py \
     --socks-port 31884 --edge-ip 216.126.229.12 \
     --core-ip 209.200.246.198
   ```

   Observe exact Edge IP. Simultaneously capture packets on Core uplink,
   the dedicated Edge WireGuard and DNS/NSS paths. Verify local UID traffic
   separately; SOCKS success does not prove UID-local or BadVPN traffic.
5. In the **disposable clone only**, fail the dedicated Egress peer while
   leaving `wg0`, global SSH and bot untouched. Repeat the same probe with
   `--expect-outage`. Network success at either Core OR Edge IP while
   deliberately disconnected is failure. Test both UDP/TCP DNS and IPv6
   negative leak probes and BadVPN as its own separately documented path.
6. Reboot the disposable Core. Before the dedicated Edge is restored, verify
   the protected UID is DENIED and `ssh.service` is healthy for unprotected
   users/admins. Restore Edge; verify protected recovery under the shared
   6G lock; test multiple UIDs on a shared Edge and hold after failure.
7. Test backup integrity, encrypted offsite restoration and independent
   console recovery. Record a signed or externally stored execution report
   with host identity, timestamps, packet-capture hashes, service/journal
   metadata, observed IPs and full failures. These are **not generated**
   automatically by the F4 code.

## Release gate review

Given a separately collected JSON evidence artifact with the exact keys
listed in `edge_egress_f4_release.py`, the following validates completeness
only:

```bash
python3 edge_egress_f4_release.py \
  --evidence /path/to/operator-evidence.json \
  --username nvl0557 --uid 1644 --edge-id fra1 \
  --core-ip 209.200.246.198 --edge-ip 216.126.229.12
```

**A successful evaluation does not set `edge_egress_readiness=READY`,
install PAM, alter the DB or authorize Production.** No F4 automatic
readiness signer or real host activation/controller registration is supplied
by this PR. Without an external VM and live SSH proof this release remains
BLOCKED. A release owner must review trusted proof provenance and explicitly
approve a separately implemented guarded production promotion.

## Known release blockers requiring further integration

- **F4-R1:** No production-ready, durable dedicated Core↔Edge Egress peer
  installer/startup/reconciliation adapter behind the existing 6G lock.
  F3's shadow hosts still require `lab_activation`.
- **F4-R2:** PAM hook is only rendered/inspected offline, NOT installed or
  verified in a real OpenSSH direct forwarding authentication path.
- **F4-R3:** Boot-time UID block, protected session admission and root/non-root
  admin recovery need actual disposable VPS reboot evidence and managed
  root-owned systemd/manifest deployment with verified rollback.
- **F4-R4:** DNS helper/NSS, IPv6 and BadVPN/UDP packet-level Core leak
  proofs and Edge failure matrix not yet observed on live kernel.
- **F4-R5:** No trusted signed production acceptance witness, readiness
  promotion workflow, guarded `nvl0557` cutover, or completed rollback
  transaction. A handwritten evidence JSON must never be such a witness.
- **F4-R6:** Existing running `PROTECTED` sessions are not terminated by
  changing the DB to FROZEN/HOLD. Admission blocks **new** sessions; the
  End-to-End experiment must verify active forwarding teardown or end-to-end
  fail-closed behavior, including unexpected session survival.

**Production deployment decision: BLOCKED until R1–R6 are closed.** Previous
CI passes validate code invariants in disposable runners, not production
readiness. `edge_egress_protected_mode` must remain OFF. Do not install the
PAM snippet or run the F1 guard `--enforce` on live Core from this PR.
