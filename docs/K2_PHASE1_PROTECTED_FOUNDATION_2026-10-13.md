# NVL Dynamic SSH Egress — Phase 1: Protected Foundation

**Started:** 2026-10-13. **Implementation checkpoint:** narrow source corrections + regression coverage, not a live Production installation.  
**Three-phase program:** (1) Protected foundation and acceptance; (2) Telegram bot Egress administration; (3) guarded active-relay / Cloudflare / per-UID customer moves. **Phase 1 is NOT complete until external acceptance is passed.**

Read [K2 New York e7 operator memory](SSH_EGRESS_K2_E7_MEMORY_2026-10-13.md) before the next step. The iPhone `nvl0557` live SSH egress trace already showed `172.86.105.67`. That **single IPv4 proof** must be preserved without overstating F4 readiness.

## Phase 1 objective and boundary

Make new Edge Egress transport **boot-safe, fail-closed, observable and release-gated** for a protected test cohort. Keep Core SSHD, existing `wg0` ingress, root rescue, existing live accounts, original Cloudflare/default host and 6G/6H untouched until separate authorized deployment. No new control plane, database, second Edge wizard or global failover engine.

### Implemented in this source PR

| Change | Motivation | Proof |
|---|---|---|
| `edge_egress_uid_boot.py` | On real Core iproute2 emits trailing space in `ip -4 route show table 20007`; strict exact ingress-return regex falsely raised `INGRESS_RETURN_ROUTE_MISSING`. Remove **only terminal whitespace per line**, not arbitrary route attributes. | Regression with original trailing-space output and rejection of incorrect ingress route |
| `edge_egress_f4_kernel_audit.py` | F4 erroneously treated an expected explicit `10.77.0.0/24 dev wg0 ...` reply route as foreign. F4 frozen/HOLD on a **shared Edge** must verify the individual UID's REJECT fence, not insist that the Edge default be deleted for other users. | Source-level shared-fence/return-route positive and negative cases; still `customer_ready=False` |
| `edge_egress_f4_preflight.py` | Host `sshd` has `Match LocalPort`. Earlier `sshd -T -C user=...,addr=...` was invalid because `lport` was missing. Require explicit real `--ssh-local-addr`, `--ssh-remote-addr` and `--ssh-local-port`; no localhost or port inference. | Context and injection/invalid identity tests |

These are **source/CI fixes only**. The one-line BootGuard whitespace mitigation was already installed manually on Core during K2-B26; the new GitHub revision does not attest a deployed version, nor install permanent guard/PAM. No production host mutation takes place when this PR merges.

## Release-gate contract (all must pass independently)

| Area | Required acceptance | Present evidence |
|---|---|---|
| Identity & admin rescue | Pinned SSH host key; independent out-of-band root rescue; non-root admin login tested in disposable clone | Pinned e7 root SSH and user config previously observed; recovery not proven |
| Dedicated transport | Both e7 Stage digests pinned; `wg-nvl-e7`/namespace and Edge NAT exact; cold-start and restart; no `wg0` or Core global route change | B23/B24 positive IPv4 proof PASS; boot persistence unproven |
| Fail-closed UID | Per-UID deny FIRST, owned ingress-return route and terminal blackhole before selector; per-UID freeze/unfreeze only; shared Edge stays available to other UID | K2-B26 temporary `nvl0557` UID1644 guard; current runtime/fence state UNKNOWN |
| Admission | Root-only immutable protected roster/manifest; F2/H PAM hook active and authenticated for both normal login and SSH `direct-tcpip`/SOCKS; no non-root global lockout | Hook/roster absent at B25 snapshot; operator reviewed implementation only |
| Per-UID DNS / IPv6 | Dedicated DoH service under routed UID; NSS configuration and DNS UDP/TCP/IPv6 no-Core-leak packet capture | Not proven |
| Failure injection | Healthy external SOCKS baseline followed by deliberate dedicated WG peer loss on **disposable VPS**, with Core WAN packet capture and restoration; no Core public egress | Not proven on new e7 |
| Restart/reboot | Cold boot restores protected admission/deny BEFORE any protected login; positive Edge return and negative unavailable-Edge boot; rescue persists | Not proven; **no Core reboot** |
| Operator F4 | Timestamped signed/approved E2E witness and independent review, host/UID/Edge pins and non-expiring availability gates; `READY` only when all criteria pass | No e7 F4 witness/DB READY |

**Do not generate or set `READY` programmatically from the prior iPhone trace or the fixed validator.** The existing `edge_egress_f4_release.check_release_evidence` returns `CANDIDATE_FOR_INDEPENDENT_REVIEW` at most, always `customer_ready=False`. The actual DB state should not be fabricated.

### Non-disruptive execution sequence for eventual operator-approved deployment

1. **Reconcile current state read-only** on Core/Edge: UID1644 temporary timer `nvl-eg7-uid1644-autofreeze`, exact owned owner-REJECT rules, priority1782/table20007, ingress return, running processes, `wg0`, e7 dedicated WG/namespace, DB F2/F4 schema and existing 6G lock. Current 20-minute freeze timer may already have fired; neither running state nor uptime is inferred.
2. **Off-host clone first:** snapshot/restore and out-of-band console rehearsal. Stage both dedicated transport systemd unit candidates via `ops.edge_egress_v1_transport.render_unit`; review **exact** stage SHA on each host. This function only renders a unit; it does NOT install/enable it or make the system boot safe. Do not add `ExecStop` or `ssh.service` dependencies.
3. **Protected account gate and boot protection:** review source/byte digests for PAM module; test PAM with real host's local port and both auth methods; install only after testing that unrelated non-root admins and root rescue can still login; root-owned complete roster and guard/DoH manifests must be coherent. `edge_egress_uid_systemd.render_ssh_systemd_bundle` generates candidates only, not a live installer; its guard has no automatic enablement guarantee. Order and persistence MUST be independently tested.
4. **Packet-level outage tests on disposable hosts** including DNS/NSS, IPv6, long-lived SSH forwarding, protected session drain, Edge loss / return and shared-user freeze. No testing by killing `wg0`, flushing global iptables or editing Core default route. A failed client `curl` alone is not a packet leak proof.
5. **Reviewed production canary window:** after independent rescue and disposable PASS, stage dedicated components with deterministic rollback/freeze and journal; one opt-in UID first. Keep `edge_egress_protected_mode=0` and public DNS/default unchanged until full handoff accepted; no reboot without separately authorized window.

## Phase 2/3 UI/UX contract (reserved, NOT activated by Phase 1)

Use **the existing Telegram host-pool and `🛡 مدیریت Egress`**; no second Edge list or competing default setting.

* **Edge overview**: short 1-line summary per Edge (location/ID, Ingress, Transport, Protected-readiness), date/time of last witness, action `جزئیات`. Distinguish `پیش‌فرض ورودی`, `DNS فعال` and `Egress کاربران` as three independent facts; never show “رله فعال” based on OR of two disagreeing fields.
* **Edge detail screen**: clear status rows `Ingress`, `Egress/WG`, `Fail-Closed`, `PAM + Boot`, `DNS/IPv6`, `F4/READY`. Unknown evidence must say `بررسی نشده`, never healthy. Show observed vs expected public IP with freshness. User-facing actions are `تست زنده IP` (read-only), `گزارش سلامت`, then `آماده‌سازی محافظت‌شده` / `فعال‌سازی` gated by Phase 1.
* **Confirmation and failure UX**: show source/destination Edge, exactly which UID accounts will be affected, ingress client impact, F4 gates and rollback/freeze before operator confirms. No misleading green global READY badge. After failure, show `HOLD / FROZEN` and safe next action, avoid blind retry and noisy success notifications.
* **Phase 3 handoff**: reuse existing `hpdef_*` and `srv_mkactive_*` with a single 6G-journaled protected Edge→Edge admission, not direct default/DNS switching. Current mixed Legacy/Protected population remains HOLD. Cloudflare updates only with exact record CAS and no Core fallback.

### Exact UI status vocabulary

`INGRESS_ONLY` → `EGRESS_STAGED` → `TRANSPORT_UP` → `CANARY_IP_VERIFIED` → `ACCEPTANCE_BLOCKED` (for missing tests) → **`READY` only by an independent authorized F4 gate**. `HOLD`/`FROZEN` take precedence over optimistic labels. These are **presentation concepts**, not new persisted enums or authorization flags.

## Follow-up and changes excluded from this source PR

- Permanently install/enable systemd Edge+Core transport with tested boot ordering and supervised reconnection (source unit renderer already exists; live activation unproven).
- Install/rehearse PAM/roster/DoH with protected UID and independent admin rescue (sensitive operator action, not performed from GitHub).
- Obtain negative packet-level fail-closed/IPv6/DNS/NSS/boot evidence on separate disposable VMs, then e7 acceptance after operator approval.
- Wire UI actions in Phase 2 only **after Phase 1 actual readiness gates**; no one-click protected mode or current-customer DNS switch.
- Existing [Issue #102](https://github.com/DenaSon/nvl-bot/issues/102) about Edge Sync remains deferred.

**Handoff:** Source fixes and unit tests may be merged independently. **Phase 1 LIVE ACCEPTANCE remains OPEN** and must continue from a *fresh read-only snapshot*, without rerunning successful e7 onboarding/stage/IP tests.
