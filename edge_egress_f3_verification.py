"""F3: existing-6G-locked Egress witness on PINNED disposable shadow peers.

This is an *explicitly invoked lab verifier* for an already STAGED Edge,
not an automatic production tunnel installer or customer activation.
It never installs SSH/PAM, changes wg0, assigns a UID or updates public DNS.
A verified shadow IP is always recorded as VERIFIED_LAB; F4 READY is blocked.

A timeout, uncertain cleanup, DB write or journal after activation keeps the
shared 6G RUNNING lease for operator reconciliation.
"""
from __future__ import annotations

from dataclasses import dataclass
import asyncio
from typing import Callable

from edge_egress_f3_readiness import Existing6GReadinessStore
from edge_egress_ssh_transport import (
    PinnedEgressHostPort, activate_and_prove_lab_shadow,
)
from ops.edge_egress_provision import EgressSpec


HOLD_PHASE = "EGRESS_F3_SHADOW_RECOVERY_REQUIRED"
PHASES = frozenset({
    "EGRESS_F3_LOCKED", "EGRESS_F3_ASSERT_STAGED",
    "EGRESS_F3_SHADOW_START_POSSIBLE", "EGRESS_F3_SHADOW_PROOF",
    "EGRESS_F3_SHADOW_STOP", "EGRESS_F3_RECORD_LAB_PROOF",
    "EGRESS_F3_VERIFIED_LAB", HOLD_PHASE,
})


class F3VerificationUnsafe(ValueError):
    pass


@dataclass(frozen=True)
class LabVerificationResult:
    ok: bool
    reason: str
    operation_id: int | None = None
    state: str = "DENIED"
    recovery_required: bool = False
    customer_ready: bool = False


@dataclass
class Existing6GEdgeVerifier:
    db_conn: Callable
    acquire_fn: Callable
    update_fn: Callable
    readiness: Existing6GReadinessStore
    core: PinnedEgressHostPort | None = None
    edge: PinnedEgressHostPort | None = None

    def _assert_ports(self, spec):
        if not (isinstance(self.core, PinnedEgressHostPort)
                and isinstance(self.edge, PinnedEgressHostPort)
                and self.core.lab_activation and self.edge.lab_activation):
            raise F3VerificationUnsafe("EXPLICIT_PINNED_LAB_HOSTS_REQUIRED")
        for role, port, addr in (
            ("core", self.core, spec.core_public_ipv4),
            ("edge", self.edge, spec.edge_public_ipv4),
        ):
            if port.identity.role != role or port.identity.expected_public_ip != addr:
                raise F3VerificationUnsafe("PINNED_HOST_IDENTITY_MISMATCH")

    def _assert_staged(self, operation_id, source, spec):
        with self.db_conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT status,source_host,target_host FROM failover_operations "
                "WHERE id=?", (operation_id,),
            ).fetchone()
            if row != ("RUNNING", source, spec.edge_public_ipv4):
                raise F3VerificationUnsafe("SHARED_6G_LOCK_NOT_HELD")
            if conn.execute(
                "SELECT 1 FROM failover_operations WHERE status='RUNNING' "
                "AND id!=? LIMIT 1", (operation_id,),
            ).fetchone():
                raise F3VerificationUnsafe("SHARED_6G_OPERATION_CONFLICT")
            source_row = conn.execute(
                "SELECT active,is_default FROM host_pool WHERE host=?",
                (source,),
            ).fetchone()
            dns = conn.execute(
                "SELECT value FROM settings WHERE key='dns_current_ip'"
            ).fetchone()
            if source_row != (1, 1) or dns != (source,):
                raise F3VerificationUnsafe("SOURCE_INGRESS_OWNERSHIP_CHANGED")
            reserved = conn.execute(
                "SELECT edge_public_ipv4,core_public_ipv4,tunnel_network,"
                "veth_network,route_table,status FROM edge_egress_allocations "
                "WHERE edge_id=?", (spec.edge_id,),
            ).fetchone()
            if reserved != (
                spec.edge_public_ipv4, spec.core_public_ipv4,
                spec.tunnel_network, spec.veth_network, spec.route_table,
                "STAGED",
            ):
                raise F3VerificationUnsafe("STAGED_ALLOCATION_MISMATCH")
            state = conn.execute(
                "SELECT state,edge_ipv4 FROM edge_egress_readiness "
                "WHERE edge_id=?", (spec.edge_id,),
            ).fetchone()
            if state != ("STAGED", spec.edge_public_ipv4):
                raise F3VerificationUnsafe("READY_STATE_ALREADY_OWNED")

    async def _journal(self, op, status, phase, details=None):
        if status not in ("RUNNING", "SUCCEEDED", "FAILED") or phase not in PHASES:
            raise F3VerificationUnsafe("INVALID_F3_JOURNAL")
        safe = details or {}
        if any(k not in ("edge_id", "observed_ip", "cleanup_ok", "failed_at")
               or type(v) not in (bool, str) for k, v in safe.items()):
            raise F3VerificationUnsafe("UNSAFE_JOURNAL_DATA")
        await asyncio.to_thread(
            self.update_fn, op, status=status,
            detail={"kind": "EGRESS_F3_LAB", "phase": phase, **safe},
            finished=status != "RUNNING", require_running=True,
        )

    async def verify_lab(self, spec: EgressSpec, *,
                         source: str, explicitly_authorized: bool = False,
                         ttl_seconds: int = 900) -> LabVerificationResult:
        spec.validate()
        if not explicitly_authorized:
            return LabVerificationResult(False, "EXPLICIT_LAB_AUTHORIZATION_REQUIRED")
        if source in (spec.edge_public_ipv4, spec.core_public_ipv4):
            return LabVerificationResult(False, "INVALID_SOURCE_EDGE")
        # No 6G operation is acquired if host identities are not pinned.
        self._assert_ports(spec)
        op, busy = await asyncio.to_thread(
            self.acquire_fn, source, spec.edge_public_ipv4,
        )
        if op is None:
            return LabVerificationResult(False, "SHARED_6G_BUSY", busy)
        phase = "EGRESS_F3_LOCKED"
        activation_possible = False
        cleanup_ok = False
        try:
            await self._journal(op, "RUNNING", phase,
                                {"edge_id": spec.edge_id})
            phase = "EGRESS_F3_ASSERT_STAGED"
            await self._journal(op, "RUNNING", phase)
            await asyncio.to_thread(self._assert_staged, op, source, spec)
            phase = "EGRESS_F3_SHADOW_START_POSSIBLE"
            await self._journal(op, "RUNNING", phase)
            activation_possible = True
            proof = await activate_and_prove_lab_shadow(
                spec, core=self.core, edge=self.edge,
            )
            if not proof.proven:
                if proof.cleanup_uncertain:
                    raise F3VerificationUnsafe("LAB_CLEANUP_UNCERTAIN")
                # Even on a failed probe the helper attempted scoped stop,
                # and we do not promote any readiness state.
                cleanup_ok = True
                raise F3VerificationUnsafe("LAB_EGRESS_NOT_PROVEN")

            phase = "EGRESS_F3_SHADOW_STOP"
            await self._journal(op, "RUNNING", phase)
            # Both dedicated shadow peers MUST stop before writing evidence.
            await self.core.stop_shadow(spec)
            await self.edge.stop_shadow(spec)
            cleanup_ok = True
            phase = "EGRESS_F3_RECORD_LAB_PROOF"
            await self._journal(op, "RUNNING", phase)
            await asyncio.to_thread(
                self.readiness.record_lab_verification, op,
                source=source, edge_id=spec.edge_id,
                target=spec.edge_public_ipv4, observed_ip=proof.observed_ip,
                ttl_seconds=ttl_seconds,
            )
            phase = "EGRESS_F3_VERIFIED_LAB"
            await self._journal(op, "SUCCEEDED",
                                phase, {"observed_ip": proof.observed_ip})
            return LabVerificationResult(
                True, "VERIFIED_DISPOSABLE_SHADOW_ONLY",
                op, state="VERIFIED_LAB", customer_ready=False,
            )
        except Exception:
            # If network activation was attempted and we cannot attest
            # cleanup, HOLD prevents another 6G operation from taking over.
            if activation_possible and not cleanup_ok:
                try:
                    await self.core.stop_shadow(spec)
                    await self.edge.stop_shadow(spec)
                    cleanup_ok = True
                except Exception:
                    pass
            if not cleanup_ok and activation_possible:
                try:
                    await asyncio.to_thread(
                        self.readiness.hold, op, source=source,
                        edge_id=spec.edge_id,
                        target=spec.edge_public_ipv4,
                    )
                except Exception:
                    pass
                try:
                    await self._journal(op, "RUNNING", HOLD_PHASE,
                                        {"edge_id": spec.edge_id,
                                         "cleanup_ok": False,
                                         "failed_at": phase})
                except Exception:
                    pass
                return LabVerificationResult(
                    False, "OPERATOR_RECOVERY_REQUIRED", op,
                    state="HOLD", recovery_required=True,
                )
            # A later journal or DB failure may have persisted evidence;
            # never return customer-ready. If terminal completion is
            # uncertain, leave RUNNING 6G, not a blind unlock.
            if phase in ("EGRESS_F3_RECORD_LAB_PROOF", "EGRESS_F3_VERIFIED_LAB"):
                try:
                    await asyncio.to_thread(
                        self.readiness.hold, op, source=source,
                        edge_id=spec.edge_id, target=spec.edge_public_ipv4,
                    )
                except Exception:
                    pass
                try:
                    await self._journal(op, "RUNNING", HOLD_PHASE,
                                        {"edge_id": spec.edge_id,
                                         "cleanup_ok": True,
                                         "failed_at": phase})
                except Exception:
                    pass
                return LabVerificationResult(
                    False, "EVIDENCE_OR_JOURNAL_RECONCILIATION_REQUIRED",
                    op, state="HOLD", recovery_required=True,
                )
            try:
                await self._journal(op, "FAILED", phase,
                                    {"edge_id": spec.edge_id,
                                     "cleanup_ok": cleanup_ok})
            except Exception:
                return LabVerificationResult(
                    False, "JOURNAL_RECONCILIATION_REQUIRED", op,
                    state="HOLD", recovery_required=True,
                )
            return LabVerificationResult(
                False, "LAB_VERIFICATION_FAILED", op, state="STAGED",
            )
