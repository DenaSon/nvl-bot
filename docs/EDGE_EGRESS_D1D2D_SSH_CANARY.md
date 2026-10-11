# D1-D2D — Stg1 actual SSH authentication canary (separately gated)

## Preconditions

The operator supplied successful read-only Staging SSH preflight:
\`SSHD_BINARY=READY\`, \`TEST_USER=FREE\`, \`CANARY_DIRECTORY=FREE\`, isolated namespace veth \`10.78.111.2/30\`, \`TEST_PORT=FREE\`, \`nvlbot=active\`, \`ssh=active\`. D1-D2C previously proved actual namespace IPv4 egress with Standby Edge IP \`216.126.229.12\`, isolated SSH protocol banner, DNS route and eventual outage recovery.

**No runtime Canary SSH step has been executed on Core as part of this commit.** This file does not authorize a production protected-mode cutover, live UID kernel rules, database migrations, boot integration or 6G/6H wiring.

## Versioned standalone canary

Source: \`ops/labs/edge_egress_stg1_ssh_canary.py\`.

Four explicit actions are individually invoked: \`preflight\` (read-only), \`prepare\` (creates staged assets/account), \`start\` (starts only standalone sshd in existing Staging namespace) and \`probe\` (validates actual authenticated SSH session's egress IPv4). There is no automatic start or re-run, nor bot/systemd registration. Every other action is rejected.

Security properties:
- **One new system-level Unix account** \`nvlstg1\` is created on the production Core in \`prepare\`. This changes Core local NSS (/etc/passwd etc.). Its password is unusable, home is \`/nonexistent\`, it has no sudo, and there is no authorized key in its default home. This account is *not* a production NVL customer. This mutation must be approved as a limited canary step; rollback requires specifically checking UID ownership and process state.
- sshd configuration remains outside /etc/ssh and is passed with \`-f\`; no change/reload of the production SSH service. Socket listens only on \`10.78.111.2:22282\` **inside** \`nvl-egress-stg1\` namespace. The root namespace SSH listener on port 22 is untouched.
- Standalone daemon permits only \`nvlstg1\`, with dedicated locally-generated client/host ED25519 keys, key-only authentication, no forwarding, no TTY, and \`ForceCommand\` invoking a reviewed root-owned canary script. Client host key is pre-pinned locally from the newly generated server host key; no TOFU.
- \`authorized_keys\` for this daemon is outside the test user's nonexistent home (so production sshd cannot automatically find it); it restricts origin to Core test veth \`10.78.111.1\`.
- The forced command prints the authenticated Unix username/UID and makes an outbound IPv4 HTTPS request to api.ipify.org, which must return \`216.126.229.12\`.
- Only the one prepared test identity is involved. No production customer keys, tunnel keys or credentials copied or displayed.

## On-Core controlled execution

The operator must pin the exact reviewed commit and validate the running namespace. Fetch the branch into the separate \`/root/nvl-egress-lab-src\` checkout; the active bot checkout is NOT changed. Run \`preflight\` first. On clean \`preflight\`, run \`prepare\` once, inspect the resulting output; **DO NOT execute \`start\` until separately authorized after reviewing prepare output.**

This step **does not alter** existing wg0, bot, sysctl, production SSH service, firewall or public DNS. It creates root-owned test key/config files and one password-disabled Unix user in a dedicated Linux host namespace.

## Reconciliation / cleanup

The \`prepare\` and \`start\` actions are one-shot, fail on existing paths and do not automatically retry or overwrite partial state. If any action fails after account creation, **stop and inspect**, do not rerun the same action or wipe other accounts/paths.

After a successful test the operator must:
1. Invoke the reviewed `stop` action, which checks the exact standalone sshd PID, its startup config and network namespace inode before sending SIGTERM; never restart/stop system sshd.
2. Verify no active SSH sessions, then remove exactly \`nvlstg1\` only if the UID, shell, home and known canary ownership match.
3. Remove only the owned canary credentials and known_hosts entries and verify the test port closed; do not touch production /root/.ssh or other authorized_keys.
4. Once the larger Staging experiment ends, separately stop the dedicated Core namespace + Standby stg1 shadow peer and remove only explicitly owned Staging resources, including the temporary Core→Standby transfer authorization.
5. Recheck production bot/ssh/wg0/default route and shared failover lock.

**Release gate remains blocked:** authenticated namespace SSH is *not* a live root-namespace UID policy test, a BadVPN session, or reboot/systemd guard proof. Disposable VPS reboot proof and protected 6G/6H runtime still required.

**Standalone service cleanup:** the scripted `stop` action is separate from `prepare/start/probe`. If the PID is stale or identity cannot be proven, it refuses a kill; inspect rather than using `pkill sshd`. The local `nvlstg1` NSS identity and keys require a separate verified teardown after testing; no automatic account deletion is performed.

## On-host compatibility incident and recovery — 2026-10-11

The operator executed `prepare` on Core from commit `93fb2b71942b62fe982a604ae253d9da907c5c37`. It stopped at `sshd -t` with `STOP:CHECK_FAILED:sshd`. Follow-up **read-only** diagnostic showed a single invalid OpenSSH directive at `/var/lib/nvl-egress-stg1-sshd/sshd_config` line 23: `Bad configuration option: AllowUserRC`. The valid OpenSSH directive is `PermitUserRC no`. **No canary sshd was started.** The partial prepare created password-disabled OS account `nvlstg1` UID 999, shell `/bin/sh`, home `/nonexistent`, and the expected five canary files (authorized_keys, egress-proof.sh, host_ed25519, host_ed25519.pub, sshd_config), root-owned with expected 644/755/600 modes. `/run/sshd` exists; production `ssh` and `nvlbot` remained active.

The reviewed script was patched to emit **`PermitUserRC no`** instead of `AllowUserRC no`; a test asserts both the correct directive and absence of the invalid one. **Do not rerun `prepare`** because the user and asset paths exist. Next operator action must be a **single-file, single-line, guarded** replacement in the existing canary sshd_config after verifying ownership, mode, complete old content and exact expected identity, followed by `/usr/sbin/sshd -t -f`. Keep `sshd` unstarted until validation completes. No production SSH, wg0, firewall, host routes, database or service changes required.
