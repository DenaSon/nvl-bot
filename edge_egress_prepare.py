"""D1-C2B2 — shared-6G-locked, stage-only Core/Edge Egress preparation.

This is an application-layer coordinator with injected IO ports. It reserves
an Edge allocation and stages *only* config files. No live bot/SSH adapter is
registered yet; it is never called by production NVL. It cannot install routes,
bring WG interfaces up, modify host_pool/users, change DNS, or mark an Edge
customer-ready.

Secrets are generated on the host that owns them. Only public WireGuard keys
cross from HostPorts back to this coordinator. Never write keys to journal/DB.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Optional
import ipaddress

from edge_egress_inventory import EdgeReservation
from ops.edge_egress_provision import EgressSpec, validated_key


PREPARE_RECOVERY_PHASE = "EGRESS_PREPARE_RECOVERY_REQUIRED"


class PreparationUnsafe(ValueError):
    pass


@dataclass(frozen=True)
class PreparedResult:
    ok: bool
    reason: str
    operation_id: Optional[int]
    requires_recovery: bool = False
    state: str = "NONE"


class LocalHostPort(Protocol):
    """A host-bound port, not a generic remote-command executor.

    Implementation must use verified/pinned SSH host key and bounded calls.
    Private key creation and staging occur ON that respective host; stage()
    accepts public peer key but MUST NOT return or log any private key.
    """
    async def read_only_preflight(self, spec: EgressSpec) -> tuple[bool, tuple[str, ...]]: ...
    async def ensure_local_keypair(self, edge_id: str) -> str: ...
    async def stage_config_only(self, spec: EgressSpec, *, peer_public_key: str) -> None: ...
    async def discard_staged_config_only(self, edge_id: str) -> None: ...


class PreparationPorts(Protocol):
    """Operator's EXISTING Phase-6G lock/journal plus scoped registry."""
    async def acquire_existing_6g_lock(self, source: str, target: str) -> tuple[Optional[int], Optional[int]]: ...
    async def journal_existing_6g(self, operation_id: int, status: str, phase: str,
                                  details: dict) -> None: ...
    async def reserve_under_6g_lock(self, spec: EgressSpec, *,
                                    core_public_key: str, edge_public_key: str) -> EdgeReservation: ...
    async def stage_reservation_under_6g_lock(self, edge_id: str) -> None: ...
    async def assert_current_ownership_unchanged(self, source: str, target: str) -> None: ...
    async def core(self, core_public_ip: str) -> LocalHostPort: ...
    async def edge(self, edge_public_ip: str) -> LocalHostPort: ...


def _validate_spec_for_request(spec: EgressSpec, source: str, target: str) -> None:
    spec.validate()
    if source == target or source == spec.core_public_ipv4:
        raise PreparationUnsafe("INVALID_SOURCE_EDGE")
    if target != spec.edge_public_ipv4 or target == spec.core_public_ipv4:
        raise PreparationUnsafe("EDGE_IDENTITY_NOT_TARGET")
    try:
        origin = ipaddress.IPv4Address(source)
    except ipaddress.AddressValueError as exc:
        raise PreparationUnsafe("INVALID_SOURCE_EDGE") from exc
    if not origin.is_global:
        raise PreparationUnsafe("SOURCE_NOT_PUBLIC_IPV4")


async def prepare_edge_stage_only(ports: PreparationPorts, *,
                                  spec: EgressSpec,
                                  source_host: str) -> PreparedResult:
    """Stage on Core + candidate Edge, but never activate or assign users.

    Lock/journal are existing 6G persisted records, not a new lock.
    We intentionally take the 6G lock even for staging to avoid overlapping
    live Edge-failover operations and confusing new candidate ownership.

    Failure after any staging attempt: try to delete only our staged files.
    If remote cleanup/journal is uncertain, keep 6G RUNNING lock and explicit
    PREPARE_RECOVERY_REQUIRED, for operator reconciliation. This function must
    never delete existing WG interfaces or operational ingress wg0.
    """
    target_host = spec.edge_public_ipv4
    try:
        _validate_spec_for_request(spec, source_host, target_host)
    except (PreparationUnsafe, ValueError) as exc:
        return PreparedResult(False, f"INVALID_SPEC:{exc}", None)

    operation_id, busy = await ports.acquire_existing_6g_lock(
        source_host, target_host
    )
    if operation_id is None:
        return PreparedResult(False, "SHARED_6G_OPERATION_BUSY", busy)

    phase = "LOCKED"
    staging_started = False
    core = edge = None

    try:
        await ports.journal_existing_6g(operation_id, "RUNNING", phase, {
            "kind": "EGRESS_STAGE_ONLY", "source": source_host,
            "target": target_host, "edge_id": spec.edge_id,
        })
        phase = "RECHECK_SOURCE"
        await ports.journal_existing_6g(operation_id, "RUNNING", phase, {})
        await ports.assert_current_ownership_unchanged(source_host, target_host)

        phase = "READ_ONLY_PREFLIGHT"
        await ports.journal_existing_6g(operation_id, "RUNNING", phase, {})
        core, edge = await ports.core(spec.core_public_ipv4), await ports.edge(target_host)
        for label, host in (("CORE", core), ("EDGE", edge)):
            ok, issues = await host.read_only_preflight(spec)
            if not ok or issues:
                raise PreparationUnsafe(f"{label}_PREFLIGHT_BLOCKED")

        # Host-local keypairs; private keys stay on the owning host.
        phase = "HOST_LOCAL_PUBLIC_KEYS"
        await ports.journal_existing_6g(operation_id, "RUNNING", phase, {})
        core_pub = validated_key(await core.ensure_local_keypair(spec.edge_id),
                                 "core public key")
        edge_pub = validated_key(await edge.ensure_local_keypair(spec.edge_id),
                                 "edge public key")
        if core_pub == edge_pub:
            raise PreparationUnsafe("PEER_KEY_REUSE")

        phase = "RESERVE_RESOURCE_IDENTITY"
        await ports.journal_existing_6g(operation_id, "RUNNING", phase, {})
        reservation = await ports.reserve_under_6g_lock(
            spec, core_public_key=core_pub, edge_public_key=edge_pub
        )
        if reservation.edge_id != spec.edge_id or reservation.edge_ip != target_host:
            raise PreparationUnsafe("RESERVATION_IDENTITY_MISMATCH")
        if reservation.status not in ("RESERVED", "STAGED"):
            raise PreparationUnsafe("RESERVATION_NOT_STAGING_SAFE")

        phase = "STAGE_EDGE"
        staging_started = True
        await ports.journal_existing_6g(operation_id, "RUNNING", phase, {})
        await edge.stage_config_only(spec, peer_public_key=core_pub)

        phase = "STAGE_CORE"
        await ports.journal_existing_6g(operation_id, "RUNNING", phase, {})
        await core.stage_config_only(spec, peer_public_key=edge_pub)

        phase = "RECHECK_OWNERSHIP"
        await ports.journal_existing_6g(operation_id, "RUNNING", phase, {})
        await ports.assert_current_ownership_unchanged(source_host, target_host)

        phase = "MARK_STAGED_NOT_READY"
        await ports.journal_existing_6g(operation_id, "RUNNING", phase, {})
        await ports.stage_reservation_under_6g_lock(spec.edge_id)

        # STAGED is not VERIFIED and cannot be used by protected handoff.
        await ports.journal_existing_6g(operation_id, "SUCCEEDED", "STAGED_ONLY", {
            "edge_id": spec.edge_id, "status": "STAGED",
            "wg_activated": False, "customers_moved": 0,
        })
        return PreparedResult(True, "STAGED_ONLY", operation_id, state="STAGED")
    except Exception as exc:
        reason = str(exc) if isinstance(exc, PreparationUnsafe) else "STAGING_FAILED"
        cleanup_ok = True
        if staging_started:
            for host in (core, edge):
                try:
                    if host is not None:
                        await host.discard_staged_config_only(spec.edge_id)
                except Exception:
                    cleanup_ok = False
        if not cleanup_ok:
            try:
                await ports.journal_existing_6g(
                    operation_id, "RUNNING", PREPARE_RECOVERY_PHASE,
                    {"kind": "EGRESS_STAGE_ONLY", "edge_id": spec.edge_id,
                     "failed_phase": phase, "cleanup_confirmed": False},
                )
            except Exception:
                pass
            return PreparedResult(False, reason, operation_id, True,
                                  "RECOVERY_REQUIRED")
        try:
            await ports.journal_existing_6g(
                operation_id, "FAILED", phase,
                {"kind": "EGRESS_STAGE_ONLY", "edge_id": spec.edge_id,
                 "reason": reason, "customers_moved": 0},
            )
        except Exception:
            return PreparedResult(False, "JOURNAL_UNCERTAIN", operation_id,
                                  True, "RECOVERY_REQUIRED")
        return PreparedResult(False, reason, operation_id, state="NOT_STAGED")
