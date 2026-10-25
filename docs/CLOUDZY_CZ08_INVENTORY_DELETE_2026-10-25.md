# CZ-08 — Cloudzy VPS Inventory & Guarded Delete (2026-10-25)

## Scope
Extend the existing `🖥 سرورهای Cloudzy` panel. The list is read live from the authenticated Cloudzy account (GET `/services`); no static IPs, manually curated inventory or stale NVL hosts are inserted.

* **🟢 Relay اصلی NVL** is always shown, never offers delete. Its identity comes from the sole `host_pool.active=1 AND is_default=1` and must agree with `settings.dns_current_ip` and the first entry in `settings.hosts`. It can be identified by its Cloudzy provider instance ID even if the listing omits the IPv4.
* Other VPSs display their live metadata. An eligible nondefault VPS has a two-step confirmation that binds actor/chat, exact Cloudzy ID, exact public IPv4, and an expiring one-time nonce.
* Protect Core host, all route-referenced hosts, and VPSs with active assigned customers; also refuse deletion during unfinished CZ-04A/CZ-04B/CZ-07/failover operations and unsettled per-provider purchase operations.
* Before the irreversible DELETE, re-fetch live provider list and details and re-check the NVL database in one write transaction.
* A durable `cloudzy_cz08_deletions` journal is written before the provider call. Do not replay HOLD operations after ambiguous provider responses. Provider 2xx acceptance updates historic managed host to inactive/non-standby, preserving identity for audit; no WireGuard peers, DNS, other server, or customer rows are edited.
* CZ-04B and CZ-07 guard against a target whose provider ID has a pending or uncertain deletion.
* On Core deployment, retain the existing NVL database path `/root/master_bot.db` or set `NVL_DB_PATH` if different. An unavailable or inconsistent DB blocks deletion, but does not prevent listing read-only provider inventory.
* The Cloudzy Developer token must have the applicable service deletion scope. This feature does not itself delete any server during deploy or when browsing.

## Manual acceptance checklist
1. Open Cloudzy → VPS inventory. Verify primary Relay is clearly marked and has no delete action. Check at least one managed older VPS and one unmanaged VPS.
2. Open older VPS → Delete request → Final confirmation. Verify no provider write happens on first confirmation screen.
3. Immediately before deleting, verify the target is not Core, DNS target, host-list entry or assigned active customer. Never test a real destructive deletion against production relay.
4. Execute deletion only for a known disposable Cloudzy VPS. After provider success, refresh Cloudzy and verify absence; check the journal is DONE and any matching `host_pool` row is inactive.
5. Simulate provider timeout / ambiguous result: journal must be HOLD, UI must not offer retry; reconcile manually in Cloudzy dashboard.
6. If the primary Relay changes while a confirmation is open, old confirmation MUST fail before any DELETE.

## Out of scope
No automatic SSH peer pruning or force removal of servers with active users. Retired provider resources may retain legacy WireGuard peers for a separately audited cleanup. No modification to the existing CZ-05/06/07 purchase or cutover UX.
