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

## 5. AUTHORITATIVE DEVELOPMENT PLAN — Unified Single + Batch M1–M7 (2026-10-14)

**New operator-approved direction; supersedes old C1–C5 followed by D1–D5.** Implement **both** Single and Batch against the same engine and original 6G/fail-closed guards in parallel, but RELEASE **only Single** to the first real e9 customer test. Batch remains disabled until the Single test and independent batch physical/capacity gates pass. There must be **no leftover product/functionality work and no ordinary operator CLI** after M7 acceptance.

**Canonical specification (READ NEXT): [K2 Unified Migration M1–M7 / zero-CLI release contract](K2_UNIFIED_MIGRATION_M1_M7_RELEASE_CONTRACT_2026-10-14.md).**

| Phase | Output and acceptance |
| --- | --- |
| **M1** | Inventory, trusted actual ingress/source owner, `SingleSelection` / `BatchSelection`, 425-row accounting, precise per-user and per-wave preview, actionable in-Telegram HOLD. |
| **M2** | Shared root-owned, fully automated protected infrastructure: multi-UID Roster CAS, mixed Legacy PAM safety, BootGuard, DNS/NSS/IPv4/IPv6 protections, independent F4 witness, durable dedicated transport and no-CLI provisioning/recovery. |
| **M3** | Unified Migration Engine: Single as batch-size 1; bounded batch waves on original 6G/journal; idempotent UID lifecycle, source-target pinning, guarded session drain, per-UID freeze/reconcile, no Core fallback. |
| **M4** | Existing Persian minimal Telegram admin UI for both Single and Batch (preview, approvals, progress, diagnostic evidence, scoped retry/recovery). Batch EXECUTE remains OFF before M7. |
| **M5** | Automated CI, physical/disposable acceptance and failure-injection for **both** paths, with no manual CLI for routine provisioning/probes and zero unresolved missing-function blockers. |
| **M6** | One authorized Production canary only: `nvl0555 / UID1636 → e9 45.61.163.75`, real SSH/SOCKS public egress + independent leak/fail-closed/neighbour proof; on failure repair shared code, stay HOLD, repeat M5/M6, no batch. |
| **M7** | Independently approved progressive batch waves and full fleet operational acceptance: no operator CLI for normal flow, verified per-user results, actionable safe holds, capacity and real ingress/egress coverage. |

**Definition of Done:** No outstanding *product-side* blockers (including first-UID-only worker, mixed/unpooled source handling, missing P3 execute binding, manual F4/packet tasks, bulk roster, admission, per-user endpoint policy, recovery UI). From fresh Edge onboarding through completed selected users and safe repair, operator acts in Telegram only. Independent emergency provider rescue remains a disaster-safety mechanism, not an expected manual migration step. Honest fail-closed HOLD for genuine external outages or unverifiable accounts is valid; a missing built feature disguised as HOLD is not. A single passing Canary does NOT count as successful group migration.

**Historical transition note:** The previous C1–C5 then D1–D5 plan was a **planning predecessor only**. Do not resume it or defer all batch implementation until after M6. Current committed design is unified M1–M7 and is not implemented by this documentation-only update.

## 6. Next-chat and implementation instructions

- Read the **canonical M1–M7 plan** above alongside the concrete evidence in sections 1–4; no further piecemeal diagnostics or repeat of proven e9 Phase1 namespace IP testing.
- Start M1 in source code on a fresh GitHub feature branch with both Single/Batch selection and no-CLI acceptance tests. Build M2–M5 in parallel against shared components before any new live test.
- Keep `nvl0555` UID1636, `e9` and existing `nvl0557` UID1644/`e7`, UID1690/`mia1` policy evidence distinct; only exact authorized scope can change.
- No unconditional PAM/SSH restart, `wg0` modification, global Cloudflare/default switch, unsafe `ip rule` patch, F4 `READY` forgery or bypass of independent packet/root rescue acceptance.
- Maintain four distinct checkpoints after each phase: **source implemented; CI passing; deployed; physically accepted**. No claim of operational success from code or documentation alone.
- Operator will approve source merge/deploy separately, as master auto-deploys; this documentation PR is NOT authorization to mutate Production.

**Other references:** `NVL_K2_AGENT_HANDOFF_2026-10-13.md`, `NVL_PROJECT_MEMORY.md`, `K2_P3_GUARD_INSTALL_AND_UID_WORKER_2026-10-14.md`, `NVL_K2_PRODUCTION_SSH_DEPLOY_RUNBOOK_2026-10-14.md`, historical `SSH_EGRESS_K2_E7_MEMORY_2026-10-13.md`. Live acceptance Issues #106, #108, #129, #102 remain open.
