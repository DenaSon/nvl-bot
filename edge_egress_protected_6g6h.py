"""D1-D1: default-OFF guarded 6G/6H reuse of the EXISTING handoff saga.

This is an injected-port integration contract, NOT a new 6G/6H bot handler.
In particular:
- the original persisted 6G operation lock/journal is reused unchanged;
- old rebuild-on-Standby, bulk ssh_accounts.host reassignment and
  DNS-to-Core fallback are NEVER delegated from this guarded adapter;
- SSH ingress/public DNS are read-only during an egress-only switch;
- before staging and after selecting target, every source UID must have
  fresh evidence of a terminal deny, correct public Edge IP, DNS and IPv6;
- no protected cutover is authorized until real disposable VPS boot evidence
  exists. The QEMU/TCG reboot gate is DEFERRED, hence default is DENY.

A real adapter for protected mapping CAS and independent packet-level proofs
has not been supplied in this PR. Never point a live 6G/6H bot callback at
this module until those ports and VM proof are reviewed and exercised.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, Optional

from edge_egress_handoff import (
    HandoffSnapshot, HandoffPorts, HandoffResult, HandoffUnsafe,
    TargetObservation, run_protected_handoff,
)
from edge_egress_failover_guard import (
    ProtectedFailoverProof, assert_protected_failover_proof, VALID_TRIGGERS,
)


class GuardedFailoverUnsafe(HandoffUnsafe):
    pass


class GuardedFailoverPorts(HandoffPorts, Protocol):
    """Injected callbacks, backed by the existing 6G DB lock only.

    commit_protected_mapping_cas_only must update ONLY a dedicated Egress
    mapping. It may NOT move ssh_accounts.host, recreate Unix SSH identities,
    change global host_pool default, or call legacy host-rebuild helpers.
    """
    async def assert_protected_mode_under_6g_lock(self, operation_id: int) -> None: ...
    async def confirm_automatic_incident_under_6g_lock(self, operation_id: int,
                                                       incident_ref: str) -> None: ...
    async def measure_all_uid_guards(self, snapshot: HandoffSnapshot, *,
                                     operation_id: int, trigger: str,
                                     selected_edge_ip: str) -> ProtectedFailoverProof: ...
    async def commit_protected_mapping_cas_only(self, snapshot: HandoffSnapshot) -> None: ...
    async def assert_public_ingress_dns_unchanged(self,
                                                   snapshot: HandoffSnapshot) -> None: ...


@dataclass
class _GuardedPorts:
    real: GuardedFailoverPorts
    trigger: str
    incident_ref: Optional[str]
    operation_id: Optional[int] = None
    now: datetime | None = None

    async def acquire_6g_lock(self, source, target):
        operation_id, busy = await self.real.acquire_6g_lock(source, target)
        self.operation_id = operation_id
        return operation_id, busy

    async def update_6g_journal(self, operation_id, *, status, phase, details):
        if self.operation_id != operation_id:
            raise GuardedFailoverUnsafe("6G_OPERATION_ID_CHANGED")
        # Tag mutating candidate phases so legacy 6G stale-lock recovery
        # cannot silently abort an operation while the dedicated Edge is
        # partially staged or rekeyed.
        if status == "RUNNING" and phase in {
            "CANDIDATE_STAGE", "DEDICATED_PEER_REKEY",
            "EXTERNAL_EGRESS_PROOF", "REVALIDATE_OWNERSHIP_AND_ALLOCATION",
        }:
            phase = "EGRESS_GUARDED_" + phase
        details = dict(details)
        details.update(kind="PROTECTED_EGRESS_SWITCH", trigger=self.trigger)
        if self.incident_ref is not None:
            details["incident_ref"] = self.incident_ref
        await self.real.update_6g_journal(
            operation_id, status=status, phase=phase, details=details
        )

    async def _prove(self, snapshot, selected):
        if self.operation_id is None:
            raise GuardedFailoverUnsafe("6G_LOCK_REQUIRED_FOR_UID_PROOF")
        proof = await self.real.measure_all_uid_guards(
            snapshot, operation_id=self.operation_id,
            trigger=self.trigger, selected_edge_ip=selected,
        )
        assert_protected_failover_proof(
            snapshot, proof, operation_id=self.operation_id,
            trigger=self.trigger, selected_edge_ip=selected, now=self.now,
        )

    async def snapshot_under_lock(self, source, target):
        if self.operation_id is None:
            raise GuardedFailoverUnsafe("6G_LOCK_NOT_ACQUIRED")
        await self.real.assert_protected_mode_under_6g_lock(self.operation_id)
        if self.trigger == "automatic_6h":
            if self.incident_ref is None:
                raise GuardedFailoverUnsafe("6H_INCIDENT_REQUIRED")
            await self.real.confirm_automatic_incident_under_6g_lock(
                self.operation_id, self.incident_ref,
            )
        record = await self.real.snapshot_under_lock(source, target)
        record.validate()
        await self._prove(record, source)
        return record

    async def stage_target_shadow(self, snapshot):
        await self.real.stage_target_shadow(snapshot)

    async def rekey_dedicated_peer(self, snapshot):
        await self.real.rekey_dedicated_peer(snapshot)

    async def observe_target(self, snapshot) -> TargetObservation:
        return await self.real.observe_target(snapshot)

    async def revalidate_before_cutover(self, snapshot):
        if self.operation_id is None:
            raise GuardedFailoverUnsafe("6G_LOCK_REQUIRED")
        await self.real.assert_protected_mode_under_6g_lock(self.operation_id)
        await self.real.revalidate_before_cutover(snapshot)
        await self._prove(snapshot, snapshot.source_host)

    async def arm_fail_closed(self, snapshot):
        await self.real.arm_fail_closed(snapshot)

    async def select_target_egress(self, snapshot):
        await self.real.select_target_egress(snapshot)

    async def prove_selected_egress(self, snapshot):
        await self.real.prove_selected_egress(snapshot)
        await self._prove(snapshot, snapshot.target_host)

    async def commit_source_accounts_cas(self, snapshot):
        # CRITICAL: deliberately do NOT delegate the legacy implementation.
        # A protected Edge handoff must keep SSH account identities on Core.
        await self.real.commit_protected_mapping_cas_only(snapshot)

    async def switch_dns_direct_to_target(self, snapshot):
        # CRITICAL: egress-only handoff may NOT silently change public
        # SSH ingress DNS or route any public endpoint to Core as fallback.
        await self.real.assert_public_ingress_dns_unchanged(snapshot)

    async def verify_final(self, snapshot):
        await self.real.verify_final(snapshot)
        await self._prove(snapshot, snapshot.target_host)
        await self.real.assert_public_ingress_dns_unchanged(snapshot)

    async def freeze_customer_egress(self, snapshot):
        # Freeze must remove only preferred Edge next-hops while retaining
        # selected UID rules, IPv6/DNS guards and terminal blackholes.
        await self.real.freeze_customer_egress(snapshot)


async def run_guarded_6g6h_handoff(
    ports: GuardedFailoverPorts,
    *,
    source_host: str,
    target_host: str,
    trigger: str,
    incident_ref: str | None = None,
    explicitly_approved_for_isolated_lab: bool = False,
    now: datetime | None = None,
) -> HandoffResult:
    """Runs the existing 6G saga only through guarded, reviewed semantics.

    NO scheduling or bot callback registration here. Automatic 6H requires an
    independently validated, journal-bound incident. The flag is laboratory
    opt-in only; a live call still requires verifiable VPS boot evidence.
    """
    if trigger not in VALID_TRIGGERS:
        return HandoffResult(False, "INVALID_PROTECTED_FAILOVER_TRIGGER", None)
    if trigger == "automatic_6h" and (
        not isinstance(incident_ref, str) or
        not incident_ref.startswith("INC-") or len(incident_ref) > 64
    ):
        return HandoffResult(False, "6H_INCIDENT_EVIDENCE_REQUIRED", None)
    if trigger == "manual_6g" and incident_ref is not None:
        return HandoffResult(False, "UNEXPECTED_MANUAL_INCIDENT", None)
    if not explicitly_approved_for_isolated_lab:
        return HandoffResult(False, "PROTECTED_HANDOFF_RELEASE_NOT_APPROVED", None)
    adapter = _GuardedPorts(ports, trigger, incident_ref, now=now)
    return await run_protected_handoff(
        adapter, source_host, target_host, now=now, guarded_failover=True
    )
