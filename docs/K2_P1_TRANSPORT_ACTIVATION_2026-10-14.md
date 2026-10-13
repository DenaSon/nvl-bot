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


## Phase 1 final source verification — Telegram

- The existing compact Edge details page now shows two side-by-side actions:
  `📤 فعال‌سازی خروجی` and `🌍 تست خروجی`.
- The latter invokes a **fresh, read-only** Core namespace `curl -4`
  with a fixed `--resolve` endpoint, strictly compares the observed public
  address to the selected Edge, and re-inspects both pinned Core/Edge
  transports afterwards. This does not acquire a write lease or change
  users/DNS/Failover. A DOWN/partial tunnel, 6G contention, drift or wrong
  public IP is HOLD and never presented as success.
- Remote `inspect` may return only `UP/ABSENT`; `ensure` may return
  only `TRANSPORT_STARTED/EXACT_TRANSPORT_ALREADY_UP`. A bogus `ABSENT`
  acknowledgement during activation is rejected.
- Even when using an injected alternate IP proof, the release worker itself
  rechecks the **exact expected Edge IPv4** before finishing its shared 6G
  operation; a mismatch leaves the protected recovery HOLD.
- Both activation and re-test use the existing Telegram admin identity
  restriction; activation requires the one-shot confirmation and
  `k2_p1_transport_activation_enabled=1` setting.

**Definition of done for source Phase 1:** the integrated Telegram wizard
creates a root-owned immutable Core+Edge Stage and independently pinned
remote SSH identity, the explicit admin-only Worker starts only its
dedicated transport, and the operator can check the exact public IPv4
from the bot without changing any subscriber. Python CI is the offline
gate; no real VPS evidence is inferred from mocks.

**Live acceptance remains separate from source completion.** Before
enabling for a disposable VPS: independently verify current Core
backup/rescue, root-only SSH key permission and correct pinned SSH host key,
readiness of the Edge public uplink and UDP port, and the status of
existing 6G operations. Inspect root-owned Stage artifacts. After
successful controlled activation, run the Telegram IP re-test. Verify
cold-boot behavior (dedicated transport persistence remains a separate
live deployment/boot acceptance item), DNS/IPv6/fail-closed behavior
and SSH/SOCKS per-UID routing in future protected customer phases.
Never advertise `F4 READY` or switch production traffic based on the
Phase 1 namespace IP probe.
