# Telegram egress transfer — current release checkpoint

## Last owner-confirmed live state

- Production `209.200.246.198` remains application `febcc45c505e5bdc6a712745651dd8f87c2e1f91`.
- Isolated Core `144.172.84.127`, bot `@Corenvlbot`, last confirmed application
  is `0e06cf767872996cf3c1e93749a93a9646337960`.
- Lab e2 `144.172.84.112` has pinned Core/Edge transport UP. The owner
  separately confirmed its Telegram namespace IPv4 probe returns that IP.
- The Lab schema repair settled original operation 1 as SUCCEEDED and wrote
  allocation/readiness STAGED. F2 tables remained empty; customer runtime OFF.
  Its backup is `/root/nvl-lab-schema-backup-8rijvv1m`.
- PR #160 merged at `1e06445e0c48a0cbd67ff615d863a7b80e534281`, adding the
  installation-bound three-account Lab trial and its owner-run controller.
  No publication/activation output or real customer transfer has been supplied
  for that release. Do not record it as installed or rerun a started setup.

## Transfer-completion correction

The generated UID guard preserves the exact `10.77.0.0/24 dev wg0 ... src
10.77.0.1` SSH return route. The DNS service previously rejected that valid
route, preventing first-user setup. Its validator now accepts only that exact
owned route beside the terminal blackhole and optional pinned Edge default.
Duplicate/wrong-device/wrong-source routes and a Core default still fail.

The native collector could qualify a pinned target under the full release
field report, while the independent PAM process still required a READY row.
Both now use the same SHA/release/Core-bound field-report validator. PAM also
requires this exact PROTECTED UID's original P3 Single receipt. During original
6G RUNNING, only its post-commit `probe_only` phase can admit the selected user;
RECOVERY, a missing receipt, a revoked report/profile, UID/nonce/scope drift,
missing ingress, UID DENY or unhealthy kernel/DNS remains a denial.

The separate Lab grant stays bound to its original host/machine/recovery
identity, e2, and `nvltest1`/1636, `nvltest2`/1637, `nvltest3`/1638. A new profile
or namespace probe cannot create a field report or READY. Accounts/passwords,
Linux UIDs, historical account-host metadata and public DNS stay unchanged.

## Publication and acceptance

`ops/k2_lab_trial.py` reuses the existing code publisher, SQLite/code backup
and rollback. The reviewed delta from the last confirmed 0e06 Lab installation
is five critical files: Core runtime, collector, release policy, UID admission
and UID DNS. The controller fetches a pinned GitHub commit on Production and
copies its verified bundle to the Lab; only Lab nvlbot is restarted. It verifies
an independent `nvlrescue` SSH/sudo login, saves the Lab NSS bytes, registers the
native runtime and persists the existing transport through original 6G.

This is one-time owner-run SSH setup, never a per-user manager procedure.
Existing/partially started profiles, guard/module trees or running operations
must be inspected instead of overwritten or unlocked. An ambiguous failure
keeps protection and original 6G recovery. Never restore old SQLite over newer
activity or silently delete guards/transport to make a retry pass.

After actual `LAB_TELEGRAM_TRIAL_ENABLED`, use the existing bot:

1. Programs → Manage output → e2 → Transfer users → Single → `nvltest1`.
   Keep the selected account disconnected during review/transfer.
2. Connect an independent client to e2 port 2252 using that Lab account.
   Its actual internet IPv4 must be `144.172.84.112`.
3. Transfer `nvltest2` and `nvltest3` as a group; verify individual receipts
   and client connectivity. All-users review must skip already-protected users.
4. Select active egress after every active account has a complete verified
   receipt; this records the egress marker without an inbound DNS cutover.
5. Perform real tunnel-loss, DNS/IPv6, reboot and recovery acceptance before
   releasing Production customer traffic. Source/SQLite/kernel-model tests
   and namespace probes do not complete that physical stage.

No user migration, live profile enablement or client IP acceptance is claimed
by this source checkpoint.
