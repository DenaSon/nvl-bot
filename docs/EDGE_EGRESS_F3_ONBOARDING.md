# NVL Edge Egress — F3 Edge Onboarding and Readiness

**Scope:** F3 of four, stacked after F2 PR #85 and F1 PR #84.
**Branch:** `feature/egress-f3-edge-onboarding-readiness`.
**Deployment:** CODE ONLY. No production DB migration, PAM install, WireGuard,
routing, ssh.service restart, public DNS or account mutation in this PR.

## Safety distinction

The existing NVL **Edge wizard** sets up customer ingress over operational
`wg0`. It does not make SSH Internet egress originate at the Edge.
In F3 the wizard additionally records a **non-operative** `INGRESS_ONLY`
candidate after successful inbound setup, if the F3 schema is explicitly
installed. This registration does not connect the outgoing Egress peer.

Egress configuration is staged by the existing 6G-locked
`prepare_edge_stage_only` coordinator via a deliberately injected, pinned
SSH host factory, not by reusing the wizard's root password or the operational
ingress tunnel. New F3 staging evidence is inserted in **the same
`BEGIN IMMEDIATE`** transaction that marks the allocation STAGED.

The F3 verifier performs a separate, **explicitly authorized lab** operation
under the existing 6G lock. It checks immutable allocated Edge identity,
source default ingress/DNS, pinned Core/Edge host identities, then starts
only dedicated disposable shadow peers using the finite worker allowlist.
It compares a fresh probe run **inside the Core's dedicated namespace** to
the expected Edge public IPv4. Both peers must be stopped before writing
`VERIFIED_LAB` evidence (TTL 60–3600 seconds). Uncertain cleanup records
`HOLD` and leaves 6G RUNNING for operator reconciliation.

**Critical:** `VERIFIED_LAB` is not a customer-ready state. F3 intentionally
does NOT promote anything to `READY`, generate a public production
WireGuard up/down service, or install a per-UID PAM gate. Current host
worker `start/stop/probe` require `lab_activation=True`. This safety
constraint must not be bypassed by pretending a lab witness is a production
witness.

## Files and responsibilities

- `edge_egress_f3_readiness.py`: explicit migration for
  `edge_egress_readiness` and `edge_egress_f3_ingress_candidates`;
  6G-locked STAGED/VERIFIED_LAB/HOLD evidence; exact public IPv4 checks,
  CAS generations and expiration. `admission_eligible()` accepts only
  a fresh, separately attested **F4_PRODUCTION_ACCEPTANCE** READY record.
  It is intentionally impossible for F3 to write such a record.
- `edge_egress_f3_verification.py`: injectable bounded and pinned Core/Edge
  lab witness, shared 6G journal and hold, scoped stop and no Core fallback.
- `edge_egress_6g_bridge.py`: stage readiness committed in the same existing
  6G transaction as allocation staging, never in a second DB lock.
- `edge_egress_uid_runtime_store.py`: cannot reserve or commit a protected UID
  against STAGED or VERIFIED_LAB. A live F4-ready Edge is a precondition
  *before* any BLOCKED runtime intent and kernel mutation.
- `edge_egress_uid_admission.py`: checks independent F4 acceptance freshness
  in addition to exact UID, IPv4, DNS and IPv6 guards.
- `edge_egress_status.py`: shows Egress allocation and evidence separately,
  with an explicit warning that lab witnesses are not customer readiness.
- `edge_egress_f3_admin.py` and `bot_final_v49-2.py`: admin-only Telegram
  **read-only** UID-to-Edge preview; input capped, regex validated, HTML escaped
  and no account reassignment, shell, UID migration or DNS writes.
- `edge_egress_handoff.py`: F3 mutating shadow phases are included among
  stale-6G recovery holds.

## State transitions and responsibilities

```text
[Legacy ingress Edge connected] → INGRESS_ONLY (candidate only)
                                            |
                             explicit pinned stage-only (6G)
                                            v
                        allocation STAGED + readiness STAGED
                                            |
                              explicit disposable lab probe
                                            v
                           VERIFIED_LAB (short-lived)
                          /                       \
              lab cleanup uncertain       production cutover?
                      |                           |
                      v                           v
                 HOLD / 6G RUNNING        BLOCKED until F4
```

F4 must introduce a **distinct Production acceptance process** that proves
reboot, PAM account gating (including ordinary direct-TCPIP SSH traffic),
multi-UID isolation, terminal fail-closed on Edge/WG/DNS outage, IPv6/DNS
negative packet capture, reliable boot after crash and offsite restore.
Only that process may write F4 production `READY` evidence and perform a
6G-locked customer canary. Before then, `nvl0557` must remain unchanged.

## How F3 is deliberately integrated

The existing production wizard now records the candidate when F3 migration
is present; if absent it preserves current behavior. Since the old wizard
uses password-based remote installer paths and F3 requires trusted pinned
host identities and root-only stage ownership, it **does not** automatically
start a production Egress session after ingress registration.

The operator-facing Egress status and preview actions are read-only. No
production actor constructs `Existing6GEdgeVerifier` with
`lab_activation=True`; such an action is only suitable for disposable
staging/CI through an explicitly injected host port. The F4 service
integration needs a reviewed production manifest/identity store.

**F3 completion is conditional** on CI and code review; a ready-to-merge PR
is distinct from a safe deploy authorization.

## Tests

```bash
python3 -m unittest -v \
  tests.test_edge_egress_f3_readiness \
  tests.test_edge_egress_f3_verification \
  tests.test_edge_egress_uid_runtime_store \
  tests.test_edge_egress_uid_admission
```

The entire existing Python and staged-safety CI must pass, along with future
F4 disposable VPS reboot, ingress/egress availability and failure tests.
