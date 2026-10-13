# K2 Phase 1 — dedicated Edge Egress transport activation (2026-10-14)

**Delivery:** stacked PR on draft #120; source code only, no master/prod deployment.

## One existing Telegram workflow

`➕ افزودن سرور` uses existing `hpeg_wizard` + Legacy Ingress installer
and the dedicated Core/Edge Egress **Stage** writer. The installer now
records (atomically, root-only) the original Core and Edge Stage SHA256
and the observed public Ed25519 SSH host key under
`/etc/nvl-egress/k2-p1-pins/eN.json`. It reads back remote Stage artifacts
over that SSH session before pinning. A previous/duplicate Stage is HOLD;
never silently repin a stale or edited Edge.

Next Telegram buttons: `📤 فعال‌سازی خروجی` -> exact admin-only Stage/
ingress/host-key and dedicated transport preview -> one-shot confirmation
(max 120s, bound to user + chat + edge) -> root-only worker.

## Transport Worker

Reuses `ops.edge_egress_v1_transport.pinned/observe/ensure`. The Edge's
reviewed transport Python sources are streamed over **strictly pinned SSH**
(no unversioned remote tool installation). Both `up.sh` scripts are already
root-owned and exact-stage SHA-pinned. It starts Edge NAT/WG receiving peer
first and then Core dedicated namespace, then probes the public IPv4 through
`ip netns exec <dedicated-namespace> curl -4 ...`. Success demands exact
Edge public IPv4, not Core IPv4.

This flow never alters live `wg0`, host_pool, settings.hosts,
`ssh_accounts.host`, global default route, customer UID, PAM, Cloudflare
DNS, 6H Failover or automatic migrations.

The **existing** Phase6G operation journal is reused: action intent is
persisted *before* the first host change; current lease is checked after
each action. Any uncertain remote state/IP mismatch leaves a protected
`RUNNING` operation at `EGRESS_P1_TRANSPORT_RECOVERY_REQUIRED`.
The 6G stale-lock recovery recognizes both Phase1 states. Do NOT blindly
rerun while HOLD is recorded.

## Deliberate operator rollout gate

`settings.k2_p1_transport_activation_enabled` must be `1` for the
confirmation to execute. Default missing/0 = read-only/block. A controlled
test deployment operator enables only after reviewing backups, Core/Edge
rescue and new disposable VPS ownership. The Telegram button cannot
silently bypass this gate. Do **not** switch it on for current customers.

## What success means (and does NOT mean)

Success means a dedicated Core namespace exits the internet using the
candidate Edge IPv4, with the ingress wg0 registry intact. It is
`TRANSPORT PROVEN / NO CUSTOMERS MOVED`.

It is **not** F3 customer STAGED/READY, not F4 production acceptance,
not persisted boot service, not protected PAM admission, not a UID
fail-closed release, and **not** actual SSH/SOCKS subscriber IP proof.
Phase2/3 must still implement customer route/ingress switching; F4
requires fresh disposable VPS boot, DNS/IPv6/leak/failure evidence before
real users are permitted.

No production actions were performed while developing this change.

## Final Phase 1 source closure — additional safety review

- Existing Worker/Stage/onboarding/Telegram wiring was found at PR #120's original
  source SHA `fffa426c9fbe479e8c27746889a8f803ca7d01a2`. No parallel
  provisioning engine was introduced.
- The final activation rechecks **exact shared 6G intent (edge ID + both
  Stage SHAs), current source default, absent target customer-pool entry,
  live wg0/Ingress identity and Core Stage after acquiring its 6G lease**.
  A RECOVERY state cannot be treated as permission to resume the installer.
- The remote Edge and local Core `ensure` must return known success
  responses. Both peers must be observed `UP` afterwards, then a fresh
  namespace IPv4 probe must equal the exact candidate public IPv4.
  Injected/fake positive probes cannot override the equality check.
- The existing Edge panel now has **📊 وضعیت خروجی**: read-only pinned
  observation of Core and Edge (or HOLD). This deliberately does **not**
  advertise F4 customer readiness or an assumed public IP without proof.
- Failure or drift during activation holds the existing 6G operation for
  reconciliation without touching wg0, SSH users, default DNS or Failover.
- Focused mock/SQLite tests cover actual call ordering, no customer writes,
  wrong IP, ownership change after Edge start, missing UP state, and
  recovery-marker interruption. No extra hard-gates unrelated to Phase 1.

### Completion and deployment boundary

The **Phase 1 source workflow** is implemented and CI-validated:
`Telegram -> Add Edge -> Stage+pin -> admin preview -> confirm
-> ensure Edge -> ensure Core -> observe UP -> public IPv4 proof`.
It remains **OFF by default** through
`k2_p1_transport_activation_enabled=0`. A controlled disposable VPS
deploy/real network acceptance is still required before treating Phase 1
as validated on actual hosts. Never flip this setting on the live Core
without independently checked backups, pinned SSH, rescue access, and a
dedicated test VPS. The Worker does not install a persistent boot unit or
protected PAM/UID guard; those and F3/F4 readiness are deliberately NOT
inferred from a transport-only IPv4 probe. Existing Issue #106 records
later protected-customer acceptance requirements. Production/master remain
unchanged until the full 3-phase release is authorized.

