# CZ-04B — Guarded Legacy Relay route and separate SSH ownership transfer
Date: 2026-10-24
Status: Source implementation / live E2E acceptance pending

## Scope and terms
This operates **only on a verified CZ03 Cloudzy-managed active Standby**, with pinned SSH host key, externally verified Cloudzy VPS id/IP and state and fresh Core probes. A manual old Edge may be the source; it is never silently adopted as a Cloudzy-owned VPS. Existing legacy manual commands remain available and are NOT called by CZ04B. Protected/K2 UID Egress is explicitly excluded.

In the current Legacy architecture the Edge performs DNAT toward Core over WireGuard; the SSH identity remains on Core. A successful Core SSH/WG/NAT test **does not** establish Iranian ISP or real-client IP acceptance. Production handoff requires independent live-client evidence.

**NVL_CZ04B_ENABLE defaults OFF.** Set to 1 in the nvlbot systemd environment only during an approved maintenance/testing window after independent end-to-end checks. Reading previews and Journal is always permitted.

## Two separate admin approvals
From Programs > Cloudzy > Edge & Relay > CZ-04B:
1. Select a CZ03 verified Cloudzy standby. Preview rejects K2/protected mode, auto failover, concurrent original 6G lease, unresolved CZ04A/CZ04B journal, missing/changed default, target in legacy settings.hosts, target already assigned users, multi-Edge active SSH conflicts and misaligned service ports.
2. Read current public and TLS Cloudflare A records (exact ID, DNS-only, unambiguous), confirm both point to current default; fresh provider ID/IP/ACTIVE, admin/customer SSH, Core-WG, pinned root-management SSH and installed DNAT/SNAT rules. The installer created NAT during CZ03; CZ04B only verifies, does not blindly append rules.
3. Independent explicit route-change confirmation (one-use, 180 sec, actor/chat/session bound), after having independently tested a real customer path to the target.
4. Acquire the original shared Phase-6G lock with **no stale recovery**. Journal PREPARING then DNS_WRITE_INTENT **before first public DNS mutation**; update only the configured exact A records. Verify target DNS. In one local SQLite transaction, compare current source/default/hosts and active SSH snapshot and commit new default + host list order + dns_current_ip + timestamp; leave source active and leave **all customer Host assignments unchanged**. Verify live DNS again and local DB; mark route READY and shared 6G SUCCEEDED.
5. If DNS partially changes or DB CAS fails before commit, attempt verified restore of original public/TLS A records and mark ABORTED/6G FAILED only after read-back. If rollback is unknown/incomplete, HOLD + original 6G RUNNING with EGRESS_RECOVERY_REQUIRED marker; do NOT replay automatically. If post-DB-commit reconciliation is uncertain, HOLD the journal and shared lease instead of a blind rollback.
6. **Separate customer step**: after READY, select one active SSH account or up to 200 active accounts remaining on the previous default (including NULL/empty effective ownership). Independent one-use approval. Fresh provider, SSH, WG, pinned NAT, DNS and atomic SQLite compare-and-swap of every exact username/source assignment. No Linux credential rebuild, V2Ray assignment or K2 mapping change. Journal DONE or ABORTED/HOLD; zero-users path is read-only.

Only one CZ04B unresolved operation can be active at a time. A HOLD/IN_FLIGHT remains locked pending operator reconciliation; the bot does not offer an unsafe reset button.

## Cloudflare adapter
cloudzy_cz04b_dns.py separately enumerates exact public_domain A record and tls_domain A record (if tls_passthrough=1), refuses proxied, ambiguous or invalid records; preserves DNS-only and original TTL using exact record IDs. Credentials remain in existing NVL Cloudflare settings and are never persisted to the CZ04B operation journal or Telegram. The new adapter DOES NOT modify dns_current_ip: the orchestrator updates that only after verified provider writes.

## Field acceptance and Cloudflare auth correction (2026-10-24)
- The first Cloudzy Legacy Edge 153.75.90.152 passed paid provisioning, CZ03 EDGE_READY, CZ04A Standby promotion and external NVP Tunnel validation. Core egress IP was expected and confirmed; no customer cutover has occurred.
- During route preflight, Cloudflare returned HTTP 400 / code 9106 when the existing `cf_key` (an API Token) was sent with old-style `X-Auth-Email` / `X-Auth-Key` headers because `cf_email` was also populated. A read-only live test proved that `Authorization: Bearer` succeeds for the same credential, and n1.nvlsup.com is DNS-only and still points at 5.75.197.158.
- `CloudflareExactDNS` now tries Bearer first for reads, regardless of leftover `cf_email`. If a Cloudflare authentication error (9106 or 10000) is returned on a **GET** and email is configured, it tries legacy Global Key headers; a successful GET pins that mode for subsequent record checks and writes. A credential change invalidates the pinned mode. Failed non-authenticated reads are fail-closed. **No alternate authentication or automatic retry is attempted for PUT.**
- A single active SSH account `nevel1253` was found explicitly assigned to Core (91.107.170.239), whereas 470 SSH accounts were assigned to the old Relay. The operator reassigned this account using the existing bot IP-service workflow; the root cause of assigning newly created accounts to Core still needs separate investigation. Do not delete or silently rewrite active customer accounts to work around preflight.
- This patch makes no database schema, host-routing, auto-failover, provider or NAT changes. Reconfirm live account distribution and Cloudflare DNS-only before any approved CZ04B cutover. Keep `NVL_CZ04B_ENABLE=0` until the operator-approved maintenance window.
- Regression tests cover leftover-email Bearer, legacy Global Key fallback, unrelated API failures, failed authentication without writes, and credential rotation.

## Follow-up: SSH enrollment selected Core as least-loaded host (2026-10-24)
- After moving account `nevel1253` onto the old Relay, the read-only live SSH distribution first showed 471 active accounts on 5.75.197.158 and zero on 91.107.170.239, but the next check again showed one active account on Core. Identify that *new* account and transfer only after operator review; no automatic deletion or bulk reassignment.
- Root cause in `bot_final_v49-2.py`: `_pick_target_host_for_new_account` selected the least-loaded row among **all** `host_pool.active=1` rows excluding only Standby. The Core is included in that pool as an active fallback, so a near-empty Core won against the busy Relay on the next purchase.
- New SSH purchases (single and bulk) select only an active, non-Standby candidate explicitly listed in `settings.hosts`, excluding the authoritative `settings.core_wg_public_ip`. Load balancing among eligible Relays is preserved. With no verified Core public IP or eligible Relay, enrollment fails closed with an explicit admin/operator message; single-account temporary username reservation is cancelled before any OS account is created.
- Account identity and service are still provisioned on Core as before; this fix changes only the **customer-facing host assignment**. Existing active customers, Cloudflare, NAT, WireGuard, 6H, CZ04B Journal and egress protection are not mutated.
- Perform a post-deploy new-account smoke test and verify `SELECT host,COUNT(*) FROM ssh_accounts WHERE service_type='ssh' AND status='🟢 فعال' GROUP BY host` before attempting CZ04B again.

## Explicit safety boundaries
- No Core-IP fallback in DNS.
- No automatic old server power-off/delete; old source stays active.
- No bulk account migrations on first Relay approval.
- No per-user SSH password writes or remote user rebuild.
- No original srv_mkactive_ or hpdef_migrate_ chained callbacks.
- No assertion that NAT/WG handshake alone proves customer's public egress IP.
- No irreversible Cloudzy VPS operations (rename/delete/rebuild/reset password/key deletion deferred).

## Deployment
Merge only after CI. Deploy pinned SHA with detached staging. Run targeted tests plus production-shape Core read-only diagnostics. Back up /root/master_bot.db using SQLite backup and runtime files. Deploy cloudzy_cz04b.py, cloudzy_cz04b_dns.py, cloudzy_cz04a.py and bot_final_v49-2.py together. Restart nvlbot and check journalctl. Keep NVL_CZ04B_ENABLE=0 initially. Read-only Telegram smoke test may show zero standby candidates until CZ03 VPS purchase and CZ04A promotion. Do NOT enable paid DNS/user mutation before isolated live trial and external user/IP acceptance.

## Verification
tests/test_cloudzy_cz04b.py mocks Cloudflare public+TLS records, two-record partial failure and rollback, unresolved HOLD shared 6G lock, stale source-account snapshot, concurrent/cross-user approval, protected-mode/provider/NAT failures, zero/one/N users, and no implicit user migration. Other CZ03/CZ04A/Legacy and K2 test suites remain mandatory.
