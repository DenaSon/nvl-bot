# Manual Edge lifecycle: new Edge and former Relay reuse

## Goal

One operator-facing concept for all manually registered Edges: **Relay = verified customer-account routing + automatic Cloudflare DNS cutover**. Merely changing an Edge's label or `host_pool.is_default` is not a Relay migration.

### New Edge

`New VPS → pinned SSH identity → non-default EDGE_READY → verified STANDBY → Quick Switch preview/independent client acceptance → Cloudflare DNS + account migration → default ACTIVE`.

The existing onboarding and Quick Switch engines remain the single authority. This change keeps and tests that route; it does not introduce a second installer, DNS tool or migration implementation.

### Reuse a former Relay

After a completed Quick Switch the source host may still have journal status `ACTIVE`, but operationally it becomes a **former Relay** (`host_pool.active=1, is_default=0, is_standby=0`).

The **former Relay** detail offers:
1. `بررسی و تبدیل رله سابق به Standby` — first screen: read-only eligibility and a separate confirmation.
2. On confirmation, independently verify the original pinned SSH host key, Core customer/admin reachability, WG and NAT using the same hardened callbacks as fresh Standby validation.
3. Recheck under SQLite `BEGIN IMMEDIATE` with the shared protected-route guard. Only update `host_pool.is_standby=1` and the former operation journal `ACTIVE → STANDBY` with a `FORMER_NETWORK_REVERIFIED` audit event.
4. Present `تبدیل به رله اصلی (کاربران + DNS)` linking to the existing `apps_edge_quick_select_<ip>` action. Quick Switch must still independently accept current network state, operator confirmation, account snapshot, DNS and global route locks before any external mutation.
5. Following successful Quick Switch the newly former source can in turn be re-validated as Standby; no blind automatic role flip.

## Fail closed

- Never prepare the sole current default, a missing/ambiguous host, an archived identity, a host with different SSH pin or provider, or any host whose customer/admin ports do not match the registered receipt.
- Require coherent `settings.hosts`, `settings.dns_current_ip`, unique `host_pool.is_default` and valid Core public IP identity, with automation/K2 flags off.
- Reject a former Relay if **any** SSH account remains assigned there (including expired/disabled), any unresolved Quick Switch job remains, any relevant CZ07 job remains, or a 6G failover operation is running.
- Do not replay the non-idempotent Legacy installer, replace a WireGuard key, manually write DNS, forcibly clear HOLD, silently delete account rows, or change the current default during rearm.
- Read-only preview is not sufficient to authorize effects: a fresh key observation and live probe happen on confirmation, and the database guards are evaluated again atomically.
- Every failed callback returns a Persian action-oriented diagnostic code and a credential-safe log entry.

## Operational caveats

The Quick Switch engine is feature-gated via `NVL_MANUAL_QUICK_SWITCH_ENABLED=1` and additionally demands independently tested NPV Tunnel customer connectivity before final confirmation. A green local network probe alone does not attest to real ISP reachability. `DONE` is technical completion, not user connectivity acceptance. Check DNS externally and real client connections before considering a new Relay operational.

Source merge **is not** a Core deploy. Verify Production SHA, backup SQLite and files, review existing HOLD/Cloudflare state and use a controlled pinned release. Never silently turn on the Quick Switch feature flag during a source code deployment.
