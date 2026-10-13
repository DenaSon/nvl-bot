> **Later 2026-10-13 e7 retirement update — DO NOT REUSE THIS AS LIVE SETUP INSTRUCTIONS:** The provider deleted New York e7 `172.86.105.67` after the historical iPhone egress-success tests below. The operator manually retired its ingress Registry/F3 metadata (PASS, backup `/root/nvl-backups/e7-retire-pRfWH19n`), with **network kernel resources and UID1644 fencing intentionally unchanged**. F4/PAM/boot/IPv6/reboot was never accepted. P3-E orphan retirement is source-only; no Core teardown has occurred. Read [the current K2 Agent Handoff](NVL_K2_AGENT_HANDOFF_2026-10-13.md) for accurate next actions before using old `e7` Stage/path/SSH instructions. Do not resurrect the VPS, remove its UID REJECT/blackhole, edit `wg0`, or treat the previous IP proof as current F4.

# NVL — K2 New York e7: Production Egress / iPhone E2E Memory

**Operator-observed checkpoint:** 2026-10-13 (Iran local time; collected from operator-pasted Core/Edge terminal outputs and iPhone Cloudflare trace).  
**Scope:** Core-terminated SSH/SOCKS Dynamic Egress V1, one NEW New York Edge and one explicitly tested existing UID. **This is an evidence handoff, NOT a customer-wide F4/READY release.**  
**Priority:** Read this checkpoint before resuming K2. Earlier 2026-10-12 documents are historical where they say K2 has not started.

## 0. Outcome, precisely

**PASS — first operator-confirmed actual iPhone/public SSH egress through the same New York Edge**. User explicitly confirmed the test ran over their `nvl0557` SSH mobile profile and supplied the live Cloudflare trace from `https://1.1.1.1/cdn-cgi/trace`:

```text
ip=172.86.105.67
colo=EWR
loc=US
tls=TLSv1.3
```

This establishes that **the tested mobile application request** egressed from `172.86.105.67` (New York), not Core `209.200.246.198`. The Core-side namespace HTTPS test independently returned the same New York public IPv4.

**Not PASS / not tested yet:** real WireGuard-loss fail-closed injection for this UID; DNS/NSS and IPv6 leak capture; PAM admission for new and already-authenticated SSH/SOCKS channels; reboot persistence/recovery; automated systemd supervision; F4 witness/READY; multiuser and Edge→Edge protected 6G/6H switches. Do not infer full leak-proof status from a single HTTPS trace or an IPv4 blackhole route. **Do not migrate customers or set READY.**

## 1. Architecture and concrete identifiers

```text
iPhone — public SSH (172.86.105.67:2252) — New York Edge
       — existing wg0 ingress (Edge 10.77.0.7/32 → Core 10.77.0.1)
       — Core SSHD (nvl0557, UID 1644)
       — UID-selected table 20007 via vnh-e7 → nvl-egress-e7 namespace
       — dedicated wg-nvl-e7 (Core 10.79.7.2/30 → Edge 10.79.7.1/30)
       — Edge eth0 NAT — public Internet 172.86.105.67
```

| Identity/resource | Observed or provisioned value |
|---|---|
| Core | `209.200.246.198`; host `CloudVPS121849` |
| NEW Edge | `172.86.105.67`; host `ubuntu-NewYorkCity-0`; Edge ID `e7` |
| Existing customer ingress | `wg0`, Edge Core-observed `10.77.0.7/32`, Core `10.77.0.1` |
| Dedicated Egress tunnel | `wg-nvl-e7`; `10.79.7.0/30`; Edge UDP `52007` |
| Dedicated Core namespace / veth | `nvl-egress-e7`, `vnh-e7` / `vnn-e7`; `10.80.7.0/30`; root veth `10.80.7.1`, namespace veth `10.80.7.2` |
| Per-user IPv4 routing | Linux table `20007`; priority `1782`; UID range `1644-1644`; default via `10.80.7.2 dev vnh-e7` plus terminal `blackhole default metric 4096` |
| Canary | existing `nvl0557`, UID/GID `1644` (not `nvl-egc1` / UID 1690, the historical Miami canary) |
| Root-only Core stage | `/root/nvl-egress-v1/core-e7`; deterministic stage digest `32bfba021c8b716fb34ea203f62446a25225f6e2955eb29ae826cd64d45ef846` |
| Root-only Edge stage | `/root/nvl-egress-v1/edge-e7`; stage digest `9daf70be459c64f96cafda14989d1ea440148286857382abc4056287ae5a9f0b` |
| Ingress identity registry | `/etc/nvl-egress/v1-ingress-peers.json`; e7 entry observed present |
| Core/Edge public-key SHA256 **prefixes** (20 chars, not actual keys) | Core `37700f7417cfbd60b26b`; Edge `663e2634d3125307b3c4` |

Core and Edge Stage were independently checked for root ownership/mode, correct stage-only manifests, and reciprocal WireGuard public-key fingerprints (B23 PASS). No WireGuard private keys, bot tokens, passwords or raw customer DB are in this document.

## 2. Chronological execution evidence — do not blindly repeat

1. **Existing Edge wizard:** `🚀 افزودن Edge` registered `172.86.105.67` in `host_pool` (active=1, is_default=0), installed existing `wg0` ingress/SSH relay at port `2252`, and Core observed exact e7 ingress identity `10.77.0.7/32`. The flags `edge_egress_v1_onboard_enabled=0` and `edge_egress_protected_mode=0` meant wizard **did not** automatically stage Egress. No change to existing default relay or Cloudflare DNS.
2. **B22 onboarding first failure:** invoking standalone `onboard_after_ingress(...)` via `/usr/bin/python3` initially failed `ModuleNotFoundError: paramiko`; required interpreter `/root/venv/bin/python3`. A subsequent run failed `STAGE_FAILED_OnboardHold`: Paramiko SFTP `sftp.file(path, "x")` created zero-byte `manifest.json` and no other stage files on Edge. The incomplete Edge directory was quarantined to `/root/nvl-egress-v1/edge-e7.failed-B22` after inspection; no rerun before cleanup/verification.
3. **B22 remediation:** narrow SFTP change `"x" → "wx"` and regression test were merged to `master` in [PR #103](https://github.com/DenaSon/nvl-bot/pull/103), commit `879465eb2a30b6e5ae462725a14cb240e71fb8ac`, with both recorded GitHub CI checks PASS. A separate **Production Core-only** hotfix to `/root/edge_egress_v1_onboarding.py` was applied with backup `/root/edge_egress_v1_onboarding.py.pre-b22-sftp`; no bot restart required for the standalone importer. Retry **B22.7 PASS** returned `STAGED_NOT_READY` and both stage paths; do not rerun.
4. **B23 stage verification:** Core `CORE_STAGE=PASS`, `INGRESS_REGISTRY=PASS`, peer fingerprints match; Core `TRANSPORT_STATE=ABSENT` before activation. Edge `EDGE_STAGE=PASS`, `MANIFEST=PASS`, `PERMISSIONS=PASS`, reciprocal fingerprints match.
5. **B24.1 Edge transport:** `/root/nvl-egress-v1/edge-e7/up.sh` started only dedicated `wg-nvl-e7` and tag-owned NAT/filter rules. Edge reports `EDGE SHADOW EGRESS UP (no user route changed)`, tunnel `10.79.7.1/30`, listen port `52007`. `wg-quick@wg0=active`.
6. **B24.2 Core transport:** `ops.edge_egress_v1_transport.ensure(stage, "core", pinned_sha)` returned `TRANSPORT_STARTED`, `observe=UP` after resource preflight. Namespace `nvl-egress-e7` tunnel `10.79.7.2/30`, **namespace-only** default route via `wg-nvl-e7`. Core default route unchanged; `nvlbot` and `wg-quick@wg0` active.
7. **B24.3 actual Core namespace Internet proof:** `ip netns exec nvl-egress-e7 curl -4 https://api.ipify.org` returned **`172.86.105.67`**, `EGRESS_IP_MATCH=PASS`. WG handshake and nonzero byte-transfer counters observed; no modification to customer routes.
8. **B25 read-only account preflight:** `nvl0557` UID `1644` originally routed via Core `eth0 src 209.200.246.198`; DB `ssh_accounts.host=104.194.144.195`, `service_type=ssh`, active. The operator disconnected an approximately two-hour SSH session before UID routing changes; the subsequent `ps -u nvl0557` returned empty. SSH services healthy. Effective SSH config command **needs** `-C ... laddr=10.77.0.1,lport=2252` due to `Match LocalPort`; observed `usepam yes`, `passwordauthentication yes`, `pubkeyauthentication yes`, `allowtcpforwarding yes`, `permitopen any`, `forcecommand none`.
9. **B26 initial guarded attach HOLD:** `BootGuardApplier.apply()` installed per-UID REJECT fence, IPv6/local DNS output protection, priority `1782` → table `20007`, terminal blackhole `metric 4096`, and wg0 ingress-return `10.77.0.0/24 dev wg0 scope link src 10.77.0.1`, but `verify` erroneously raised `INGRESS_RETURN_ROUTE_MISSING`. Fail handler kept UID fenced (confirmed `iptables -C OUTPUT -m owner --uid-owner 1644 -m comment --comment nvl-egress-uid-1644 -j REJECT` PASS). The `ip -4 route get 1.1.1.1 uid 1644` returned an error while the table was blackhole-only; that is **not** a live transport-failure injection.
10. **B26 root cause and local hotfix:** real `ip route show table 20007` includes trailing spaces on both lines, e.g. `'10.77.0.0/24 dev wg0 scope link src 10.77.0.1 \n'`. `BootGuardApplier.verify` anchored regex expected the last character directly before `$`, returning false. On **Core only**, immediately after obtaining `text = self.call("ip", "-4", "route", "show", "table", str(plan.table))`, the operator patched `/root/edge_egress_uid_boot.py` to normalize each line with `text = "\n".join(line.rstrip() for line in text.splitlines())`. Backup `/root/edge_egress_uid_boot.py.pre-b26-whitespace`. This yielded `VALIDATOR_FIXED=PASS` and `GUARD_VERIFICATION=PASS`. **Important: this one-line BootGuard fix is NOT yet verified merged into GitHub master; add regression test and upstream fix before the next code redeploy, else it can regress.**
11. **B26.2 retry / iPhone evidence:** assistant supplied a single-UID guarded attach script for `nvl0557` with expected UID route to `vnh-e7` and a 20-minute `systemd-run --unit=nvl-eg7-uid1644-autofreeze --on-active=20m` REJECT re-arm, then unfence and per-user HTTPS trace probe. **Operator did not paste the complete B26.2 script stdout after the final retry**; do not invent an explicit `PHONE_TEST_READY=YES` console log. **However the operator directly reported successful live iPhone SSH connection and provided Cloudflare trace `ip=172.86.105.67`; operator confirmed “کاملا درسته. پاس شد.”** Record that as user-observed live client E2E PASS, separate from console acceptance outputs.

## 3. Live state at handoff: partial / ephemeral, NOT F4 READY

- This was a **manual temporary Canary**, not a committed F2 protected runtime deployment. `edge_egress_protected_mode=0`, Egress PAM hook missing from `/etc/pam.d/sshd`, `/etc/nvl-egress/v1-protected-users.json` and `/etc/nvl-egress/protected` absent on the B25 snapshot. No proof of durable per-UID guard, authorized F4 readiness, signed evidence, or healthy restart behavior.
- B25 SQL read-only showed **zero `RUNNING` 6G operations**, and no e7 rows printed from `edge_egress_allocations` or `edge_egress_readiness`. Root-owned staged files and active transport **do not imply** a DB allocation or F4 READY row. The bot console may continue to show non-ready.
- **A 20-minute autofreeze was requested by the B26.2 script, but the operator did not supply systemd-run output or a later timer/status snapshot.** Treat the timer, active REJECT fence, installed per-UID Edge default and user connectivity as **unknown at next login**. Do not assume a still-open Canary or automatically remove the fence.
- `nvl-egc1` / UID `1690` has an independent historical rule at priority/table `1781`; do not modify. Other Core/WG0/6G/6H/customer routing and default DNS were intentionally untouched.
- No tested outage/fail-closed proof (new Edge WireGuard actually down), packet capture, DNS/NSS/IPv6 safety proof, persisted transport/boot services or reboot. **Do not reboot Core, run `down.sh`, flush iptables, remove UID blackhole/selector or enable production-wide protected mode as a shortcut.**
- `ssh_accounts.host` was only read as `104.194.144.195` during B25; B26 scripts made **no DB host update**. Do not conflate DB ingress ownership, user on-phone SSH destination, public DNS active relay and Linux UID egress path.

## 4. Minimum next steps, in order (do not restart onboarding)

1. **Reconcile actual live state, read-only first:** bounded `systemctl list-timers / status nvl-eg7-uid1644-autofreeze`, `iptables -C` for exact owner fence/IPv6/local DNS, `ip -4 rule show` and `ip -4 route show table 20007`, `ip -4 route get ... uid 1644`, `ps -u nvl0557`, `ip netns exec nvl-egress-e7 wg show wg-nvl-e7 latest-handshakes`, original `wg0`/bot/SSH health; count active 6G and inspect F4/DB state. Avoid printing WG private keys or personal data. Do not blindly rerun B26.2 or undo its fence.
2. **Upstream only the demonstrated narrow BootGuard whitespace bug** with regression test and GitHub CI; preserve existing behavior, ensure deployment version and operator-owned Stage SHA are not accidentally replaced. SFTP exclusive-write fix is already merged via PR #103.
3. For an authorized, controlled acceptance, establish independent root/admin rescue and install/rehearse F2 protected PAM admission, boot deny-first guard, per-UID DNS service, and transport persistence **without globally locking out legacy users**. Keep a validated rollback/recovery path and the existing shared 6G lock/journal.
4. Prove same-user real external SSH/SOCKS IPv4, DNS/NSS and IPv6 leak behavior, then a **controlled transport-loss fail-closed and restore** with packet evidence, and finally boot/recovery behavior in an approved window; maintain untouched customers and no Core fallback. Only then consider F4 READY, staged cohort expansion and protected 6G/6H integration. No manual F4 `READY` or fabricated DB evidence.
5. Keep bot UI/`hpeg_status` read-only/non-admitting until all gates pass; never re-run the legacy Edge wizard on the already-registered e7.

## 5. GitHub/source pointers

- Repository: [DenaSon/nvl-bot](https://github.com/DenaSon/nvl-bot), `master`.
- Source modules: `edge_egress_v1_onboarding.py`, `ops/edge_egress_provision.py`, `ops/edge_egress_v1_transport.py`, `edge_egress_uid_policy.py`, `edge_egress_uid_boot.py`, `edge_egress_uid_runtime_kernel.py`, `edge_egress_v1_admission.py`, `edge_egress_f3_readiness.py`.
- Historical/canonical scope: [SSH Egress V1 Production Scope & Evidence](SSH_EGRESS_V1_PRODUCTION_SCOPE_AND_EVIDENCE.md); dynamic implementation: [SSH Egress Dynamic V1 Delivery](SSH_EGRESS_DYNAMIC_V1_DELIVERY.md); project entry: [NVL Project Memory](NVL_PROJECT_MEMORY.md).
- Outstanding unrelated debt: [Issue #102](https://github.com/DenaSon/nvl-bot/issues/102) covers legacy Edge Sync/archive interaction. Do not alter live sync merely to finish this Canary.
- **Next-chat instruction:** “Read `docs/SSH_EGRESS_K2_E7_MEMORY_2026-10-13.md` first; continue from live read-only reconciliation of the temporary `nvl0557` Canary. Do not repeat successful e7 onboarding, B23, B24 or the successful iPhone IP proof. Preserve fail-closed UID state, root-owned stage hashes and all existing Production users.”
