# K2 — Production canary and rollback contract (2026-10-14)

**Status:** pre-production preparation only. No customer SSH, DB, DNS, Core routing, Edge WireGuard or PAM modifications. No production-safe privileged P3 UID worker is declared complete.

## Decision

An actual **new Edge on Production Core** is acceptable for a tightly controlled first **dedicated namespace transport-only** test, after live read-only reconciliation and independently restorable backups. A live Linux UID SSH/SOCKS test is a *different* release level and requires independent PAM/BootGuard/F4 proof before any real user is enrolled. Do not use a production customer as the first canary.

**Backup alone is insufficient**: disk snapshots cannot necessarily reverse active kernel ip rules, iptables/nftables, in-flight 6G journal state, a changed public DNS record, missing WireGuard peers, or a PAM lockout. There is no safe blind `tar -xzf` recovery on a running VPS.

## Non-negotiable rollback prerequisites (all manually verified)

1. Independent **provider full-volume snapshot** for Core **and** new Edge, taken immediately before changes. Record snapshot IDs, locations and retention; confirm the provider console offers rescue mount/recovery when SSH is unreachable. Record unrelated-existing traffic impact and an explicit operator stop threshold.
2. Execute `ops/backup_nvl_host.sh core` on Core and `ops/backup_nvl_host.sh edge` on new Edge; it uses SQLite's online consistent `.backup`, checks integrity and captures curated root SSH, WireGuard, PAM, roster/BootGuard, stage pins, deployment tree and host/network diagnostics. It does not shut down or restart a daemon.
3. Export those **secrets-bearing** archives to encrypted **off-host** storage with a separately-held decryption credential. They contain Linux password hashes, SSH/WireGuard keys and Telegram/API material; do **not** upload to GitHub, chat or public CI.
4. Validate the Core archive with:
   `python3 -m ops.k2_canary_backup_gate --backup /root/nvl-emergency-backups/EXACT_CORE_SNAPSHOT_DIRECTORY`.
   A `LOCAL_CONSISTENT` result verifies only the local archive checksums, SQLite and covered paths. The tool explicitly returns `authorizes_customer_change=false` and cannot verify independent off-host copy, provider snapshot or recovery.
5. Run a **restore drill in a disposable clone**, checking Linux UID→username ownership, SSH keys and admin login, root rescue, exact F2/F3/F4/PAM/BootGuard material, boot/firewall rules and protected deny-first after reboot. Document tested snapshot ID and independent administrator confirmation. A checksum proves file integrity, *not* a bootable image or a safe restore plan.
6. Before any operator gate, the existing single 6G lock MUST be idle, source/default/DNS unchanged, no ambiguous K2 `RUNNING/RECOVERY_REQUIRED` phase, and non-root admin independent console tested. Back up the original `master_bot.db` immediately before any *specific* migration operation as well.

## Staged test matrix and rollback sequence

| Stage | Actions | PASS condition | On failure |
| --- | --- | --- | --- |
| A. Read-only inventory | Existing Telegram `🧪 آزمایش VPS`; `python3 -m ops.k2_final_readiness`; manual Core/Edge rescue and backup audit | Original SSH users, default Core+Edge and original wg0 unchanged | STOP, investigate, no toggles |
| B. New-Edge dedicated transport | Explicit P1 wizard/confirm on isolated target **only**, pinned SSH host key and original 6G journal, no UID mutation | Namespace `curl -4` public address equals **new Edge IPv4**, both transport peers UP | Preserve 6G HOLD on uncertainty. No blind rerun. Manually inspect exact owned dedicated tunnel before reversing only that resource |
| C. Disposable Core clone single SSH account | Install independently reviewed root-owned V1 PAM/BootGuard/UID fence, keep independent SSH rescue, external SOCKS/SSH and packet taps | SOCKS + UID direct curl exit exact Edge IPv4; DNS UDP/TCP/NSS and IPv6 have **zero Core exposure**; other UIDs unaffected | Fence selected UID first; retain 6G recovery. Restore reviewed single-UID resources in clone; reverify access |
| D. Failure and boot | On **clone only**, break dedicated Edge tunnel, test deny instead of Core fallback; force cold-boot with tunnel healthy and down | No public Core IP, no transient unprotected login, root/non-root admin rescue preserved | Independent provider console; inspect 6G journal; no automatic rollback that removes a UID fence |
| E. Production one-user canary | **Only after** C+D and independent F4 review, use a **new throwaway SSH UID**, no active customers; execute specific gated P3 and independent tests | Protected runtime/binding+roster/guards all exact, verified external Edge egress, no leak, other customers unaffected | Stop new canaries, freeze only canary UID, preserve 6G HOLD and isolate candidate Edge; rollback with independent console if necessary |
| F. Customer traffic cutover | **Not included in initial production test**; separate per-UID approved transition then all-PROTECTED atomic mode promotion and gated global Edge relay/DNS handoff | Zero Legacy gaps, completed F4/boot/packet evidence and audited operator approval | No automatic switch to global Legacy or blanket user deprotection |

### Action-independent rollback order

- **First** stop new mutating requests and failover; do not clear a protected `RUNNING` 6G operation simply to free the interface.
- If a protected UID is uncertain, **retain its deny fence**, then inspect exact transaction/host state from the out-of-band root console.
- Restore only **owned** dedicated Edge/UID resources on a confirmed matching host; do not flush shared iptables, stop original `wg0`, rewrite global `ssh.service` or roll every UID backward.
- The old Edge and Core routing remain serving other users. Verify current public DNS and original default; no changes to Cloudflare until a separately approved cutover.
- Only after verified network, PAM, admission, fresh test-account SSH/SOCKS and no-leak proofs may the operator reconcile and release the single 6G lease.
- If the host is inaccessible or the journal/resource ownership is ambiguous, use provider rescue/clone restore; do **not** run blanket restore over a live customer Core.

## Remaining engineering NO-GO

At this commit, the **actual** production-safe P3 UID mutation worker/PAM installer, reviewed per-user dry-run and one-shot execute confirmation, remote independent packet-negative witness, and reboot+failure F4 remain gated. `ops/k2_canary_backup_gate` and the enhanced backup script close only the *snapshot coverage/consistency* portion. PR #120 stays Draft; do not merge master or enable the source-enrollment/global-mode flags based on backups. See issues #106 and #108.
