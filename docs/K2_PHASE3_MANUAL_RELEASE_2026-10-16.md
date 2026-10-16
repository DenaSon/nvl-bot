# K2 Phase 3 — manual release, rollback and real acceptance

This is a source handoff, not a deployment record. The owner explicitly chose
manual SSH deployment after UI/UX development. The existing production record
and backups remain historical evidence; refresh actual host state before use.
The Phase 1/2/3 branches are stacked. Do not deploy an unrelated master SHA or
assume an open PR is integrated. Pin the exact reviewed commit with green CI
for the final integrated tree.

## 1. Build one immutable source package, away from the live bot

From a trusted checkout containing the final reviewed SHA (Python 3.12+):

```bash
NVL_RELEASE_SHA='REPLACE_WITH_EXACT_40_CHARACTER_REVIEWED_SHA'
python3 -m ops.k2_release_bundle build \
  --repo . --commit "$NVL_RELEASE_SHA" \
  --output "/tmp/nvl-k2-$NVL_RELEASE_SHA.tar"
```

Record both printed `BUNDLE_SHA256` and `PACKAGE_MANIFEST_SHA256` with that
SHA in the operator's release record. Build reads committed Git objects even
if a working file differs. It excludes environment files, databases, keys and
non-source assets. Rebuilding the same commit produces identical bytes;
existing output is never silently replaced. The archive includes tests and
reviewed Python/shell source, `release.json` and `package.json`; neither is a
field-acceptance report or an enabled runtime profile.

## 2. Read-only host baseline and source staging

Use the live service's **actual** interpreter, ExecStart and working directory.
Known previous paths were `/root/bot_final_v49-2.py`, `/root/master_bot.db`,
`/root/venv/bin/python3`, unit `nvlbot`; they are observations, not assumptions.
Reuse [the baseline and backup procedure](NVL_K2_PRODUCTION_SSH_DEPLOY_RUNBOOK_2026-10-14.md)
sections 0–1. Verify provider rescue/snapshots and a restorable off-host backup;
do not reuse the old one-shot publisher. Keep SSH and provider console usable.

Before publication, verify DB integrity and any original RUNNING/RECOVERY
operation. Do not clear old state to make a check pass. Inspect required bot
secrets locally without printing them. Check Core tools: Python 3.12+ bot,
iproute2, WireGuard, iptables/ip6tables, curl, OpenSSH client, tcpdump, runuser,
systemd and the existing DNS-over-HTTPS service expected by the guard code.
The wizard installs its Edge prerequisites; no per-account installation is
part of normal transfer. Do not broadly upgrade the running venv.

Transfer the source archive over trusted SSH, check its whole-archive digest
against the independently recorded `BUNDLE_SHA256`, then extract into a new,
empty root-owned private staging directory. Never extract over `/root` or the
live bot. From that directory, using the actual bot interpreter:

```bash
/root/venv/bin/python3 -B -m ops.k2_release_bundle verify \
  --directory "$NVL_SOURCE_STAGE" --commit "$NVL_RELEASE_SHA" \
  --package-sha256 "$NVL_PACKAGE_MANIFEST_SHA256"
/root/venv/bin/python3 -m py_compile bot_final_v49-2.py
/root/venv/bin/python3 -m unittest discover -s tests -v
```

The staging path, SHA and manifest digest are the actual values recorded in
this session. Verify rejects modified/missing/additional files and symlinks;
run verification before compilation/tests create `__pycache__`. Tests operate
on synthetic host I/O and disposable data. Stop on a host test failure rather
than weakening production checks or altering archived receipts.

## 3. Review a concrete publish/rollback manifest, then publish manually

Prepare the exact source-file delta against **current live hashes**, including
all required imports and the changed runtime pin set. Save every replaced
file with mode/owner/hash; record every newly created path separately. Back up
SQLite with its backup API. Separately retain the previous root release
manifest and runtime profile, if present. Do not copy an entire repository
onto `/root`, overwrite environment/DB/private keys, or edit systemd/PAM/routes
as part of a code-only publish. The published `release.json` must match the
actual installed source directory and exact commit.

Initial UI smoke runs with execution disabled: an absent profile is OFF. An
already-enabled/unknown profile is a review stop, not permission to silently
reuse it against a different release. Publish the reviewed code delta while
the bot is stopped, verify its hashes, then perform one controlled service
restart and check PID stability, sanitized logs, DB integrity, Programs menu
and existing account/Marzban paths. Record the resulting live SHA and backup
path; source CI alone never completes this step.

**Code rollback before any customer mutation:** stop the bot, verify and restore
the exact prior code files/modes plus prior release manifest/profile; remove
only the paths recorded as newly created and still matching this release.
Restart using the original unit and repeat service/DB/menu checks. Preserve
new operation receipts; do not restore an old DB over newer user activity.

**After PAM/guard/UID/transport mutation:** old code alone is not a network
rollback. Stop further work, retain the original 6G recovery state and UID
DENY protection, inspect current guards/receipts through the scoped recovery
path and use the reviewed snapshot/rescue plan if needed. Never run old
`down.sh`, delete shared transports, unfreeze unknown users or clear a lock.
Settled STOP can be reconciled from the bot; ambiguous partial mutation still
requires technical repair, not an automatic UI unlock.

## 4. One-time field qualification, then real bot acceptance

The native operations profile is deliberately disabled without a root-owned,
release/Core-pinned field qualification. It is not generated by source tests
or this bundler. First qualify the real release on disposable Core/Edge or an
explicitly controlled Core, with rescue, PAM/boot guards, WG loss, DNS/IPv6,
external SSH/SOCKS and recovery observations. If this evidence is absent,
execution stays disabled; do not fabricate a READY record or receipt to get
past the gate. Field qualification is a once-per-release task; native
per-user measurements then run automatically without manual witness files.

After that gate, enable Single separately from Batch in the reviewed existing
root profile, not by editing Python booleans. Test in this order:

| Step | Action in the existing bot | Required independent result |
| --- | --- | --- |
| UI | Main menu → Programs → Manage output | Admin only; short Persian text; return/cancel work |
| Edge | Add one **new** disposable Edge | Wizard/tunnel/persistence; exact namespace public IP |
| Single | One explicit eligible test account | Real external client Internet IP equals Edge; Core account/UID unchanged |
| Safety | DNS, IPv6, neighbor and WG-loss/restart | No Core leak; unselected accounts unchanged; safe DENY/recovery |
| Group | Independently release Batch; a small explicit group | Per-account results and accurate active-session skips |
| All | All eligible; details, STOP, status and settled reconciliation | No hidden omission/replay; remaining users can be freshly selected |
| Active output | Select active output | Marker only after **every** active account is verified on target |

Do not forcibly terminate busy customers. The active marker records this
verified population; future accounts are not automatically enrolled. A Core
roundtrip public-SSH probe is not an external phone/desktop witness. Keep
same-ingress and different-ingress cases distinct in the acceptance record.
Any failed Single returns to repair of the same engine before Batch. There
is no deployment, real bot test or production IP-fix claim in Phase 3 CI.
