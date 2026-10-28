# NVL — Unified Edge Phase 8: Runnable E2E and Controlled Live Pilot

**Date:** 2026-10-28  
**Deliverable:** repeatable fault-injection gate, read-only Core+Cloudflare pilot preflight, final-acceptance audit, and reversible Legacy-retirement decision. This is **implementation**, not a claim that a Cloudzy VPS was purchased or a real Iranian ISP tested from GitHub.

## What “HOLD” means here

Do **not** block the project just because staging and field evidence are incomplete. Start a **real, bounded test** now using the actual CZ03→CZ06 native bot path and, after external SSH evidence, CZ07 under its existing human-confirmation/6G/CAS controls. An *uncertain charged POST, DNS PUT, partial installer, failed worker lease or inaccurate account assignment* must still stop the **affected job** until its real outcome is inspected. No global forced unlock.

**Critical migration fact:** the current CZ07 job moves the **whole eligible source cohort**, in chunks of 200; it is NOT a 5-user canary on a Production Core containing 488 customers. The `--max-accounts 5` pilot limit deliberately rejects a full production Cutover. The first live E2E cutover must therefore use **an isolated test Core with <=5 genuine test accounts** or a separately approved full-cohort production maintenance window. Never “pilot 5 users” by pointing CZ07 at the production customer default.

## 8.1/8.2 — Execute repeatable offline failure matrix

```bash
cd /path/to/isolated-nvl-bot-checkout  # full repo with tests/ available
/root/venv/bin/python3 -m unittest tests.test_cloudzy_phase8_pilot tests.test_cloudzy_phase8_matrix -v
/root/venv/bin/python3 cloudzy_phase8_matrix.py --list
/root/venv/bin/python3 cloudzy_phase8_matrix.py
```

The matrix invokes **25 existing native-module test cases** against temp SQLite and fake Cloudzy, DNS and SSH adapters. It covers stock drift, ambiguous Cloudzy charge/crash recovery, UO receipt atomicity, provider IP recycling, installer/host-key mismatch, apt lock, Standby not-equal-to-client acceptance, exact Cloudflare partially committed DNS intent and original 6G lease, CZ07 200 batches, full cohort counts, crash after CAS/before journal, user cancellation and manual resume, independent CREATE+RENEW+ISP receipt requirement, lost Telegram Rich ACK and false E2E evidence. Nonzero exit code fails the gate. This is not a substitute for physical ISP tests.

## 8.3 — Read-only production baseline before a paid pilot

Use the same pinned release deployed across ALL Phase-3-to-8 Python files. Make a SQLite online backup and an executable snapshot **without overwriting a live DB**. Avoid `git reset --hard` or `git clean` in a dirty production checkout. Confirm `systemctl is-active nvlbot` and actual deployed SHA separately.

```bash
# The CLI opens SQLite in mode=ro with query_only; no SQL write, provider POST or DNS PUT.
/root/venv/bin/python3 /root/cloudzy_phase8_pilot.py \
  --db /root/master_bot.db --phase purchase
```

Expected valid result: `READY_FOR_PURCHASE_TEST`, no blockers. It authorizes **nothing by itself**; the paid purchase is made only from the existing Cloudzy admin wizard, after the operator approves the specific VPS SKU, hourly base price **and possible IPv4/add-on charges**. Record CZ03 operation ID and exact provider instance/hostname. Only one purchase is allowed; never repeat a charged request with an ambiguous result.

Prepare the same real VPS through the existing CZ06 guided flow, with independently pinned SSH host key and Core/WG/NAT postchecks. Preserve existing installer as non-idempotent; do not rerun `setup_edge_relay.sh` after any partial/unknown effect. Record operation ID/provider ID/current public IP, CZ06 status and an independently observed **SSH Direct connection from the affected ISP**. Test SSH handshake/authentication, public IP/DNS expectations, traffic and actual application behavior. Save time-stamped reference and test client result without secrets.

### Check exact Cloudflare DNS before any cutover

For optional **read-only** Cloudflare API GET, configure values privately in the shell from existing operator-approved credentials (never commit, print or paste the token), matching the live Cloudflare record definitions:

```bash
export NVL_PHASE8_CF_ZONE='<zone id>'
export NVL_PHASE8_CF_TOKEN='<read-capable token>'
export NVL_PHASE8_CF_PUBLIC_DOMAIN='n1.nvlsup.com'
# Set this explicitly to match the bot's actual current DNS configuration:
export NVL_PHASE8_CF_TLS_PASSTHROUGH=1  # use 0 ONLY when TLS A record is not configured
export NVL_PHASE8_CF_TLS_DOMAIN='<actual configured TLS A-record domain>'
/root/venv/bin/python3 /root/cloudzy_phase8_pilot.py \
  --db /root/master_bot.db --phase cutover \
  --expected-target '<verified Cloudzy IPv4>' --max-accounts 5 --cloudflare-get
unset NVL_PHASE8_CF_TOKEN
```

A response `READY_FOR_CLIENT_TEST` means the live DNS/source/standby/6G/limit preflight passed but there is **still** no independently verified client proof: test the customer from the affected ISP, then use the existing operator-confirmation callback in the bot. The CLI does **not** accept user-provided strings as trust evidence, so it cannot accidentally authorize a DNS write. A controlled app can inject a trusted `client_witness` callback: only exact `True` yields `READY_FOR_CONTROLLED_CUTOVER`.

**When the test Core cohort is within the explicit bound**, use the bot CZ07 confirm for exactly that verified candidate and source, with the existing `NVL_CZ04B_ENABLE=1` / `NVL_CZ07_ENABLE=1` effect gates enabled deliberately for the approved test session. Rich UI needs **no** Feature Flag. Do not enable those mutation gates for an unapproved production-wide cutover. Old relay stays online and untouched. The guarded DNS saga must verify Cloudflare live and Core default; CZ07 transfers in batches <=200. Never force an unlock if the original 6G lease remains RUNNING.

If a crash occurs:
- Before a paid order: rerun GET/preflight only, not a duplicate POST.
- Paid POST uncertain: reconcile exact Cloudzy hostname/provider ID on GET before any further action.
- Installer partly applied: inspect evidence; never blindly reinstall.
- DNS change uncertain: preserve original 6G lease; inspect live DNS, CZ04B journal and Core CAS; no automatic rollback/PUT.
- Batch move committed but CZ07 progress not logged: recover counts from SQLite, verify route/NAT/DNS/provider and explicitly Resume; do not repeat account CAS from an old cursor.
- Telegram Rich message lost: delivery outbox is independent of business state; do not recreate a paid order.

### Business acceptance and end state

After the test route, **create** a new SSH account and **renew** an existing one using the real bot. Confirm both login and connectivity from the affected ISP, plus accurate destination host, active customer count and public DNS. The pre-existing `CZ07.accept_business` requires three traceable evidence IDs and a genuinely independent trusted verifier; operator-only text is not a verifier.

```bash
/root/venv/bin/python3 /root/cloudzy_phase8_pilot.py \
  --db /root/master_bot.db --phase final \
  --expected-target '<verified Cloudzy IPv4>' --cloudflare-get
```

`FINAL_AUDIT_PASS` requires: no route mismatch, no running 6G or unresolved route, accepted CZ07 DONE with complete count, independently certified CREATE + RENEW + client references, and exact current Cloudflare record identity at target. If the trusted verifier is not wired to an operator action, the result appropriately remains `CZ07_NOT_BUSINESS_ACCEPTED`. That is a **specific acceptance task**, not an excuse to stop staging development.

## 8.4 — Legacy retirement policy (developed, not prematurely executed)

`cloudzy_phase8_pilot.retirement_preview(final_report, independent_signoff=...)` returns `ELIGIBLE_FOR_SEPARATE_REVERSIBLE_RETIREMENT_REVIEW` only after final accepted field evidence and independent approval. A partial or unverified test returns `KEEP_LEGACY_ACTIVE`. This stage **does not delete, disable or rewrite** old Legacy callbacks, source Relay, user data, historical journals or shared 6G. A reversible UI retirement patch must be separately reviewed and released after real pilot acceptance; keep a safe rollback/read-only observability path.

## Remaining real-world signoff

GitHub CI alone cannot establish the Cloudzy charge, SSH pin/installer operation, actual Cloudflare GET, a customer's connection on a filtered ISP, true CREATE/RENEW, or a reliable fenced multi-process worker takeover. Report each as **not yet field-tested** until evidence is collected. Do not call a green simulation `PRODUCTION_ACCEPTED`.
