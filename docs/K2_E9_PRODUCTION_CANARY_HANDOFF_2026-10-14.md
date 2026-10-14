# NVL K2 — e9 live operator evidence, single-UID canary plan, and bulk migration boundary

**Checkpoint:** 2026-10-14; evidence from operator-supplied Telegram screenshots, Core shell stdout, PowerShell OpenSSH traces, and the completed production audit. **Operational observations, not automatically a code release or F4 approval.** Read this document FIRST in the next K2 conversation, then `NVL_K2_AGENT_HANDOFF_2026-10-13.md`, `NVL_PROJECT_MEMORY.md`, `AGENTS.md` and current source. Older 2026-10-13/14 “new Edge not yet deployed” guidance is historical where contradicted by the live e9 evidence below.

## 0. Precise continuation objective

**Operator decision:** Prefer the existing production Core, not a new Core LAB, for an eventual **explicitly approved single-account test**. This preference does **not** waive physical F4, account/PAM blast-radius checks, independent root rescue, provider snapshots, tested recovery or the documented disposable-clone prerequisite for destructive/break-glass experiments. If these cannot be established safely, the live mutation remains HOLD.

**Next development:** `K2 Single-User Protected Egress` for **`nvl0555` / Linux UID `1636`** entering via **`e9` at `45.61.163.75:2252`** and exiting with **exactly `45.61.163.75`**, while all other production clients stay unchanged. Keep the Linux SSH identity/password on Core; do not rewrite historical `ssh_accounts.host` as a substitute for ingress identity or per-UID egress. No global Cloudflare DNS/default change. Start with a source-only/read-only per-UID preview, not a live route/PAM command.

**Answer to “can we then move all users?”:** A successful **C1–C5 single-UID Canary** proves the per-user path, **NOT** readiness to bulk-migrate 425 subscribers. A separate `K2 Bulk Migration` track (D1–D5, described below), multi-UID roster updates, source/ingress inventory reconciliation, scaled admission and wave-based migration are required. Never infer “all 425 transferable” from a single canary or from a Telegram `STAGED` indicator.

## 1. Source and deployment provenance (four distinct states)

- GitHub: private `DenaSon/nvl-bot`; verified `master` at conversation checkpoint `e2726994b9b2389d25f8f1794eda7cef09be7724` (PR #143 Telegram customer port normalization). This document's PR is **documentation-only**; it is not a code deploy or operational activation.
- Earlier operator-reported **Core code-only publish** was `d5ca38b6e7069d969d8aa33bcb42ef71c8c63b2a` with hash checks, preserved recovery paths and bot restart. Actual post-hotfix runtime source digest on live Core was **not reattested** during the current chat. Do not assert e272 was fully redeployed merely from successfully completing the e9 Telegram wizard.
- GitHub P3 source contains `ops/k2_p3_guard_installer.py` (`INSTALLER_ENABLED=False`, first UID only), `ops/k2_p3_uid_worker.py` (`WORKER_ENABLED=False`), existing original 6G lease/journal, protected source enrollment, and an **ALL-PROTECTED** relay handoff. No approved registered Telegram live per-UID executor; no independently accepted full F4 packet/WG-loss/boot witness. Current P3 code **does not** handle arbitrary legacy user on an unknown historical host as a direct one-step e9 assignment.
- Preserve: `wg0`, `nvlbot`, SSH, all legacy clients, previous per-UID routes, original 6G/6H failover, Cloudflare, DNS/default and root-owned pinned Core/Edge artifacts. No direct SSH access is conferred by the GitHub plugin.

## 2. Verified production Core and new e9 Edge

| Item | Operator-observed state |
| --- | --- |
| Core | `CloudVPS121849`, public IPv4 `209.200.246.198`; `/root/master_bot.db`; bot `/root/bot_final_v49-2.py`; Python with Paramiko at `/root/venv/bin/python3` |
| e9 public IPv4 | `45.61.163.75`; customer SSH `2252`, management SSH `22` |
| e9 pinned Stage | `PIN=VALID`, `STAGE_PINNED=True`; `inspect_phase1(e9)`: `CORE=UP`, `EDGE=UP` |
| e9 F3 allocation | `edge_egress_allocations(e9,45.61.163.75,STAGED,20009)` |
| e9 F4 | `edge_egress_readiness` state `STAGED`, `admission_eligible=False`: **NOT F4 READY** |
| Dedicated transport | Core netns `nvl-egress-e9`; `wg-nvl-e9=10.79.9.2/30`; `vnn-e9=10.80.9.2/30`; actual `ip netns exec nvl-egress-e9 curl -4 https://api.ipify.org` returned `45.61.163.75` |
| Telegram | New e9 wizard succeeded; independent `🌍 تست خروجی` displayed expected/observed `45.61.163.75`. This **only proves namespace IP**, not SSH UID route/leak-freedom |
| Original ingress | Core `wg0`, e9 observed peer `10.77.0.9`; Core customer sshd listens `0.0.0.0:2252` and IPv6 port 2252 |
| e9 IP policy | `table 20009` did **not** exist in main netns during audit; no e9 UID selector yet (correct distinction: transport UP != UID PROTECTED) |
| Runtime gates | `edge_egress_protected_mode=0`; `k2_p1_transport_activation_enabled=0`; `k2_p2_relay_switch_enabled` unset/OFF; active original 6G `RUNNING=0` |
| P3 files | `/opt/nvl-egress/edge_egress_v1_admission.py`, `/etc/nvl-egress/v1-protected-users.json`, `/etc/nvl-egress/protected` absent; PAM V1 hook absent in `/etc/pam.d/sshd` |

**Earlier trap:** Running `load_stage_pin` via system `python3` failed `ModuleNotFoundError: paramiko` / `SSH_HOST_KEY_PIN_REQUIRED`; this was an interpreter/dependency issue, **not** proof of invalid pin. `/root/venv/bin/python3` validated the pin; Phase1 activation succeeded via the existing Telegram admin flow. Gate was closed afterward and verified 0. Do **not** rerun P1 activation or alter its completed stage.

## 3. Active SSH population: exact DB metadata, not inferred packet ownership

Read-only classification of **425 active SSH DB rows**:

- **1** has `ssh_accounts.host=172.86.111.69` (current unique default relay).
- **5** have a host listed in `host_pool` but not current/e9.
- **419** refer to host addresses **not listed in** `host_pool`. Of these, **405** have `host=104.194.144.195`, and the other **14** span eight additional legacy IPs.
- **0** e9-assigned active rows. `edge_egress_uid_runtime=0` and `edge_egress_uid_bindings=0`.
- **Do not call 419 accounts broken or claim 424 are active on e9.** Host fields are historical DB metadata, not proof of their live WireGuard ingress, active sessions or egress. Resolve source/owner per account before any bulk operation.

Specific users:
- `nvl0555`: UID/GID `1636`; DB active SSH, historical host `104.194.144.195`, shell `/bin/false`; password status `P`, account expires `2026-11-05` as observed. **No per-UID IPv4 rule**; `ip route get 1.1.1.1 uid 1636` selected Core `eth0` with public source `209.200.246.198`. **Not safe to use SOCKS to Internet until e9 protected route is installed and verified.** A live UID-owned sshd PID `1733413` was present in the later comprehensive audit: account idleness must be rechecked; do not kill a customer session to pass the gate without authorization.
- `nvl0557`: UID `1644`; old e7 policy at priority `1782` / table `20007` via `vnh-e7`, with blackhole fallback; despite live `nvl-egress-e7` remnants, **no e7 F3 allocation row**. Keep old fence/route untouched. Previous test produced DNS and `Connection refused` failures, not an e9 success proof.
- Historical `mia1`: UID `1690`, priority/table `1781` / `vnh-mia1`. Untouched.
- e7 physical VPS was retired; do not resurrect, blindly `ip rule del`, `down.sh`, `wg0` edit or unfence UID `1644`.

## 4. SSH investigation conclusion; do not repeat ad hoc log tests

- Core RSA host key fingerprint verified against Windows OpenSSH e9: `SHA256:2Ai7Wnjwi34IlIgVM2RMvTaevSEY1OvOLwQ/6MEcCmo`; correct real SSH host identity.
- `sshd -T` without `-C` errors because live SSH config has `Match LocalPort`. Use **full actual context**: `user=nvl0555,host=localhost,addr=10.77.0.9,laddr=10.77.0.1,lport=2252`. e9 and old peer `10.77.0.8` produced **no full effective-config diff**. Relevant options: `usepam yes`, password/kbd-interactive yes, `allowtcpforwarding yes`, no forced command, `permitopen any`.
- Windows `ssh -vv -o PreferredAuthentications=password -o KbdInteractiveAuthentication=no -N -D 127.0.0.1:1091 nvl0555@45.61.163.75 -p 2252` confirmed connection, RSA trust, SSH key exchange and password packet sent; **connection closed before auth outcome**. One `pam_unix` authentication failure for nvl0555 on e9 peer `10.77.0.9` was logged. Other nvl0555 password SSH sessions were accepted from `10.77.0.8` and older Edge peers. Reason for *every* e9 close **not proven**. Do not assert all are due to bad password, PAM, MTU, SSH throttling or that `/bin/false` blocks `-N`.
- **Positive e9 ingress proof exists:** `nvl0557` was logged `Accepted keyboard-interactive/pam` from `10.77.0.9` at least twice. This verifies some real e9 ingress→Core SSH authentication, not nvl0555 readiness.
- Production SSH was active and `sshd -t=PASS`, no OOM seen in bounded kernel review. There are many unrelated customer `connect_to` failures/IPv6 unreachable entries and some expired accounts; avoid broad `grep error|fatal | tail` as a diagnosis of the single canary. Need only targeted, time-bounded logs if a new authorized test warrants them.

**Resource risk from comprehensive audit** (server clock `2026-10-14T13:55:42-04:00`): RAM `1.9 GiB`, swap used `878 MiB`, load 1-min `9.46`, `381` sshd processes, `1691` established TCP sockets, `385` SSH service tasks. This is substantial observed load, **not proven as cause** of nvl0555 close. Require reviewed Core headroom and safety window before P3 PAM mutation.

## 5. Committed design direction: K2 Single-User Protected Egress (C1–C5)

| Phase | Deliverable / acceptance contract |
| --- | --- |
| **C1 — preview only** | Per-UID source/ingress identity reconciliation, exact OS UID, DB status, process/session drain, F3 target/peer, protected-map collision, 6G/F4/rescue checks. **No** global all-protected assumption, `ssh_accounts.host` mass update or users silently added to cohort. Branch/tests/CI. |
| **C2 — protected admission/kernel** | Attested first-canary roster/BootGuard/PAM and DNS/IPv4/IPv6 guards. Per-UID terminal blackhole + reject, no Core fallback. A global `/etc/pam.d/sshd` hook **has system-wide blast radius** even when roster contains one UID. Independently verify mixed Legacy logins and emergency root/non-root access. Actual installed manifest and module exact SHA; no unsafe enablement from a boolean. |
| **C3 — guarded one-shot worker** | Dedicated `SINGLE_UID_CANARY` execution using the **existing** 6G persisted lease/journal, pinned source+target, nonce/operator revalidation, session check, deny-first, immutable evidence and failed-step **HOLD/fence**, no automatic legacy fallback. Review existing P3-A/P3-C and adapt safely without a parallel DB lock/kernel engine. |
| **C4 — Telegram operator UI** | Minimal admin-only existing `hpeg_*` UI: read-only preview, explicit one-shot confirmation only after acceptance, status/HOLD/failure reason, recovery view. No developer jargon, no alternative Telegram bot. |
| **C5 — physical acceptance** | Independently witnessed public client SSH/SOCKS IPv4 e9 exact IP, Core packet capture (TCP/UDP DNS, NSS, IPv6), unaffected neighbour UID(s), guarded tunnel loss/recovery and cold-boot no-leak, out-of-band root rescue, snapshot/restore evidence and exact CI/deployed SHA. A namespace-only curl does not meet C5. |

**Execution rule:** User wants ONE consolidated preflight/report instead of long iterative one-command SSH debugging. Plan code/offline tests first in a narrow PR. CI success ≠ deployment ≠ real packet/F4 evidence ≠ approval. Do not merge to production master automatically; operator must review intended production action. User prefers testing on live Core, but safe physical loss/reboot cannot be tried there without impact isolation and recovery/acceptance. If no safe physical witness, leave C5 HOLD; don't fabricate `READY`.

## 6. Separate roadmap AFTER a successful Canary: K2 Bulk Migration (D1–D5)

**C1–C5 do not complete bulk transfer.** To make the bot capable of transferring the *entire eligible real population*, build, test and operationally accept:

1. **D1 Inventory/reconciliation:** source-of-truth for per-account actual WireGuard ingress edge, historical `ssh_accounts.host`, Linux UID/status/session, unknown/removed Edge mapping and target eligibility; separate the 405+14 unpooled-host accounts and five other-known Edge accounts. Explicit opt-in and no silent reassignment.
2. **D2 Safe multi-UID lifecycle:** atomic compare-and-swap **roster append/update/remove**, stable priority/table/DNS port per UID, shared Edge route/NAT reference accounting, UID collision/owner guarantees and strict first/second/wave boot/PAM/DoH semantics; avoid per-UID installer only supporting first UID.
3. **D3 Bounded wave orchestration:** `DRY_RUN`, batch sizing/concurrency limits, idempotent per-UID journal within original 6G, per-account HOLD/quarantine/reconcile/retry after approval, progressive 1→small wave→larger wave; active SSH session drain/notification and monitor. No global all-user cutover until every necessary UID is attested.
4. **D4 Ingress/DNS topology:** decide **per-user new connection endpoint vs shared Cloudflare/DNS switch** for each source Edge; prove original ingress peer and customer port end-to-end, handle other customers on those IPs. The existing **ALL-PROTECTED** global relay contract cannot simply be reused for a mixed 425-account fleet. Never redirect OTHER Edge customers by changing global default or DNS.
5. **D5 Production readiness:** Edge e9 capacity/CPU/RAM/conntrack/bandwidth/port/NAT validation; snapshots and independent rescue; sampled and independent packet leak tests per wave and boot/failure drills; controlled rollback/fail-closed recovery; user-visible migration states; customer-support/reconnect plan; final live post-wave reconcile of all enrolled account counts and original 6G idle.

Only after these gates can the operator authorize migration of **all eligible** accounts. Some accounts may remain HOLD until ownership/credentials/port/session anomalies are resolved; do not claim a guaranteed `425/425 PASS` in advance. Bulk transfer is a separate deliverable and release, not implied by a successful one-user proof.

## 7. Immediate next-chat instructions / explicit non-actions

- **Start here**; do not ask the operator to repeat the successful e9 wizard, P1 activation, independent IP curl, inventory or repeated unsuccessful SSH password attempts.
- First engineering deliverable: C1 **source-only, read-only** `nvl0555 / UID 1636 → e9` preview + focused tests; no bot-wide flag toggles or in-place production network commands.
- Before C2/C3 implementation, explicitly reconcile non-default historical host metadata with actual trusted ingress peer, one-session active PID, F4 source/target scope, per-UID admission; do **not** weaken `MIXED_OR_UNPROTECTED_COHORT`, F4 or ownership safeguards to make the UI green.
- Installer and worker defaults OFF; V1 PAM hook absent. No `ip rule add/del`, no F4 SQL `READY` patch, no global `edge_egress_protected_mode=1`, no `wg0`/SSH restart, no `down.sh` or deleting 6G records.
- Development workflow: verified latest master → branch → explicit C1–C5 scope and tests → independently reviewed PR and exact-head CI → separate operator-authorized deploy/acceptance. Then D1–D5 as a separate project.
- Preserve secret hygiene: never commit/paste SSH passwords, private keys, WireGuard secrets, environment files, live SQLite, personal data or raw auth logs. This sanitized checkpoint contains public host identity and scoped account IDs only.

**Relevant docs:** `NVL_K2_AGENT_HANDOFF_2026-10-13.md`, `NVL_PROJECT_MEMORY.md`, `K2_P3_GUARD_INSTALL_AND_UID_WORKER_2026-10-14.md`, `NVL_K2_PRODUCTION_SSH_DEPLOY_RUNBOOK_2026-10-14.md`, `SSH_EGRESS_K2_E7_MEMORY_2026-10-13.md` (historical); open acceptance/issues #106, #108, #129, #102.
