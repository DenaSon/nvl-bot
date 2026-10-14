# K2 — Telegram VPS rehearsal navigation (2026-10-14)

**Status:** real integration in the existing admin-only Telegram Edge panel, but source-only staged rehearsal. This does **not** mean Protected UID customer E2E is deployed or passed.

## Operator flow (existing Telegram bot)

Open **🛡 مدیریت سرورها → select Edge → 🧪 آزمایش VPS**. The bot invokes `review_vps_lab(db_conn, edge_id)` and displays:
- target Edge IPv4 vs current/default source, stage/F3 pin and trusted H ingress;
- original shared 6G busy or idle;
- active Linux Core SSH users counted as Legacy, database-recorded PROTECTED, inconsistent, or owning another Edge;
- F4 identity/freshness in the underlying read-only snapshot (no F4 minting);
- numbered trial steps and firm assurance that SSH accounts remain on Core.

When the exact target Stage+trusted ingress+6G snapshot is coherent, the page links **🌍 تست IP سرور** directly to the **existing** `hpeg_p1_probe_<edge_id>` bot callback. A Legacy *source* may have no F3 protected-egress allocation at this early stage: that fact remains a migration HOLD but MUST NOT prohibit a harmless candidate VPS namespace IP test. That existing callback proves the dedicated *namespace* public Edge IPv4 only. It is **not** an SSH/SOCKS user-route proof. The page also links to the existing one-user review and guarded relay review, neither of which becomes executable from this page.

The new callback is **admin-only**, resolves a strictly validated Edge ID, runs only the read-only inventory in `asyncio.to_thread`, renders HTML via escaping and on exceptions returns a generic HOLD with navigation back. No new bot, webhook, permission, journal, or host port; no root shell or SSH commands within the new handler.

## Safe rehearsal on a fresh disposable VPS

1. Independently provision a **disposable** Edge with pinned SSH host key and a separately retained root rescue. Keep the original Core relay and existing users untouched. The already-developed wizard stages a dedicated transport using the existing controller; no customer UID is switched.
2. Open **🧪 آزمایش VPS** for that new Edge and document the HOLD reasons before toggling any operator gate. The page must not show a customer-ready badge or transfer confirmation.
3. After the separately approved Stage is fully prepared (and only when an independently reviewed P1 transport activation is permitted), use the existing operator flow to bring up its dedicated tunnel. Return to the lab page and use **🌍 تست IP سرور** to compare the observed namespace IPv4 to the Edge public IPv4. A mismatched IP = STOP.
4. Use **👤 بررسی کاربر** to view source SSH/UID evidence and **🔀 بررسی انتقال** to view the guarded phase 2 blockers; the UI must not transfer an account. Never set F4 READY from the namespace probe.
5. Only after a reviewed root-only PAM/BootGuard installer, per-UID 6G execution worker and independent F4 packet evidence are deployed to the disposable environment can external workstation SSH/SOCKS (Edge public IPv4), DNS UDP/TCP/NSS, IPv6, forced Edge loss/restore and cold-boot be tested and logged. Real F4 approval remains a separate operator action. Do not infer it from the Telegram view.

## Verification

```bash
python3 -m unittest tests.test_edge_egress_k2_vps_lab -v
python3 -m unittest discover -s tests -p 'test_edge_egress_*.py' -v
```

The new tests validate real SQLite snapshot, absence/expiry of F4, mixed cohort, 6G conflict, stage pin/H ingress drift, SQL table corruption, HTML escaping, callback allowlist, and a static check that the existing bot's callback is admin-only and cannot call a migration executor.

**No-go:** Parent PR #120 stays Draft. Do not merge to `master`, move user credentials/accounts, mutate Linux UID routing, update Cloudflare, change `dns_current_ip` or global protected mode, enable privileged release flags or run failure injection on Production. Lab view is the first *preparation* for a VPS test **with the bot**, not the final customer migration release; #106 and #108 remain open.
