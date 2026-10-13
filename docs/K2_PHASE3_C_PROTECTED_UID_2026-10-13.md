# K2 Phase 3-C — Protected UID Lifecycle

## Scope / status

P3-C adds a **source-only, release-disabled** per-UID host port for the
existing P3-A guarded executor, the existing 6G persisted lease/journal,
and the existing F2 `edge_egress_uid_runtime_store` CAS states.

Actions: `UID_ATTACH` (enroll a NEW pre-rostered account or resume a FROZEN
account under fresh evidence) and `UID_FREEZE` (deny an already PROTECTED
account). "Release" means **resume FROZEN → PROTECTED with new F4, PAM,
Ingress, per-UID boot/DoH, public IPv4 and negative DNS/IPv6 proofs**.
It does NOT mean drop per-UID firewall policy and release to legacy/Core.
Unprotection or retirement belongs to P3-E, after separate evidence.

## Reused source of truth

- `edge_egress_p3_executor.Existing6GGuardedExecutor` with the *same*
  `failover_operations` RUNNING intent. P3-C calls
  `assert_guarded_6g_intent()` before each side-effect, checking journal
  kind, phase, actor-bound scope digest, source, target, Edge and nonce.
  No alternative lock, journal or durable UID state table is created.
- `edge_egress_uid_runtime_store.Existing6GUIDRuntimeStore` owns all
  state CAS and uniqueness constraints, and requires real F4 readiness,
  source/default DNS match, OS UID ownership, STAGED allocation and
  exact account binding. Each transition still runs inside 6G.
- `edge_egress_v1_admission.load_roster` and `checked_guard` load
  root-owned roster and exact hashed per-UID guard, including all
  existing protected identities. New users must be pre-enrolled
  conservatively; P3-C **does not install or truncate any roster**.
  Incomplete roster or conflicting UID => HOLD.
- `edge_egress_uid_runtime_kernel.LocalLinuxProtectedRuntimeKernel`
  is the reference *disabled-by-default* UID-only implementation.
  P3-C does **not** construct or activate it. Tests inject fake kernels.
- `UIDIndependentSafety` requires verifiable PAM/Ingress/Boot,
  account-session idle, shared-Edge isolation and independent packet-level
  DNS/NSS/IPv6 nonleak evidence; offline fake evidence is NOT F4 approval.

## Transitions

| Operation | Precondition | Durable and kernel order | Final |
| --- | --- | --- | --- |
| New attach | Rostered, no prior runtime/mapping, idle, F4 READY | BLOCKED record BEFORE per-UID kernel mutation; DENY/terminal blackhole → owned Edge attach → ROUTED_UNVERIFIED → independent IP/DNS/IPv6 proof → CAS | PROTECTED |
| Resume | Exact FROZEN runtime and PROTECTED mapping, idle, new proofs | Preserve mapping + per-UID DENY; re-attach/prove then CAS | PROTECTED |
| Freeze | Exact PROTECTED runtime+mapping | Arm per-UID REJECT first; verify; CAS | FROZEN |
| Any uncertainty | Mutation possible | Re-arm per-UID REJECT; attempt CAS to HOLD; leave protected mapping, shared route, WG0 and user records unchanged | HOLD + 6G RUNNING |

Emergency freeze must work even when a session is active or F4/PAM/DNS
is unhealthy. It is never an excuse to detach a shared route. If UID
identity or 6G lease has drifted, only an independently approved manual
recovery path can reconcile. No auto-Core fallback.

## Admission + boot invariants

- PAM must deny pending BLOCKED, FROZEN, ROUTED_UNVERIFIED and HOLD even
  while a 6G transaction is running. The existing F2 gate performs
  these checks; source-level proof is NOT a substitute for real PAM E2E.
- Existing per-UID `REJECT` is removed only within the existing kernel
  attach method after the terminal blackhole, ingress return,
  attached Edge route and guards verify, while 6G remains RUNNING.
- On loss of F4 readiness, no new/resumed UID is authorized. Freeze is
  still permitted to contain an already protected UID.
- Stage-only tests simulate SQLite CAS, public-IP mismatch, packet evidence
  failure, shared lease loss, roster drift and partial kernel failures.
  They do not assert customer-ready or a live IP leak result.

## Release boundary and next steps

`UID_LIFECYCLE_ENABLED=False`. No bot callbacks, root daemon, deploy,
roster/PAM installer, live Cloudflare DNS mutation or automatic route
cleanup. P3-D must coordinate multiple UIDs under 6G/6H and Cloudflare
CAS, P3-E will handle guarded decommission/orphan resources, P3-F will
expose admin preview/confirmation only after final code and F4 acceptance.

Production `wg0`, SSH and Core services remain untouched; historic
e7 UID1644 fence stays in place. #108 guarded lifecycle remains open,
#106 independent F4/PAM/Boot/DoH/tunnel-loss lab acceptance remains open.
