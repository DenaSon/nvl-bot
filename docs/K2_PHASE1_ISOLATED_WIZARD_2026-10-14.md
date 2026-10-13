# K2 Phase 1 — Isolated new-Edge wizard checkpoint (2026-10-14)

**Branch:** `feat/k2-phase1-isolated-wizard-20261014`, stacked on draft PR #120.
**Scope:** New Edge creation, isolated Ingress and dedicated Egress Stage; NO
client migration, default relay switch, failover or automatic transport activation.

## Why this correction is needed

The previous `hpeg_wizard` installed an Edge Ingress, staged a dedicated
Egress, then unconditionally called `_db_add_host_pool` and appended its IP
to `settings.hosts`. That enrolled an unverified Egress into the live
customer-selection pool. The same Legacy host mutator also categorically
blocked the integrated wizard when any protected UID existed. During new-Edge
SSH bootstrap the Legacy installer also forced root password auth and
restarted SSH even though the new protected wizard did not need this.

## Changes

- `hpeg_wizard` checks the desired public IP/port, no duplicate host/F3
  candidate/Egress allocation, and absence of an active shared 6G operation
  **before the remote SSH installer**. It rechecks after Stage creation.
  Protected users on other Edges are not changed by these checks.
- Reuse the **existing** root-SSH/wg0 Ingress installer and its authenticated
  Stage handoff, but skip its legacy SSH-password policy override and restart
  when the integrated K2 wizard was explicitly chosen. The legacy
  `hp_addedge` behavior remains unchanged.
- On integrated success publish a trusted Ingress registry entry and owned
  Core/Edge `STAGED_NOT_READY` artifacts, **not an active host_pool entry**,
  `settings.hosts` entry, default relay, DNS or account host change. The
  trusted registry lets the existing Telegram Edge dashboard display it.
  Root read-only Stage inspection is available without host-pool activation.
- Existing P3 review, one-user protected preview and K2 read-only relay
  screen remain present and cannot activate customers. No automatic 6H,
  Failover, public DNS update, PAM change or global route rewrite is added.

## Boundaries / next steps

**Stage is not activation.** A dedicated release-authorized transport/
BootGuard/PAM Worker, explicit F3 6G allocation and Stage pin, independent
F4 acceptance, then protected user cutover are still needed before a new Edge
can become the active relay. These are not achieved by changing a boolean.
The live WG0 Ingress install remains a privileged operation and must only be
attempted on a new disposable Edge after checking Core backups, rescue and
existing 6G status. Partial WG0/SSH/Stage failure is HOLD — do not rerun
blindly.

## Focused tests

`python -m unittest tests.test_edge_egress_k2_phase1_wizard -v`
plus the existing `test_edge_egress_*.py` suite, main-bot syntax, and
GitHub Python checks. No artificial F4/IPv6/WG-loss acceptance is claimed
from offline mocked tests.

**Next:** Phase 1 transport/activation worker integration needs completion
before the Phase 2 all-user relay switch. Never merge this stacked branch
directly into master or deploy as full K2 traffic switching.
