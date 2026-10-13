"""D1-C2: protected Relay handoff coordinator (INJECTED PORTS; NO LIVE ADAPTER).

This module extends the existing Phase 6G/6H failover model. It does not
create a second DB lock, write Linux network state, change DNS, or import the
large bot. An application adapter MUST pass through Phase 6G's *existing*
persisted operation lock and journal, enforce source-account compare-and-swap,
and provide externally verified routing/health evidence.

Safety invariants:
- Never install any Core-IP fallback for customers.
- All relevant UID traffic must remain terminally fail-closed through errors.
- An uncertain routing/DB/DNS outcome keeps the shared operation lock HELD,
  with journal phase EGRESS_RECOVERY_REQUIRED, for human reconciliation.
- Legacy rebuild-on-Standby is not called. SSH identities stay on Core.
- The caller MUST NOT enable this module in production without complete,
  tested Linux, DNS, DB and recovery adapters.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from ipaddress import IPv4Address, ip_address
from typing import Protocol, Optional
import asyncio

from edge_egress_policy import EgressReadiness, evaluate_protected_handoff

MAX_EVIDENCE_AGE = timedelta(seconds=30)
MANUAL_RECOVERY_PHASE = "EGRESS_RECOVERY_REQUIRED"

# Phases written BEFORE the first customer-route mutation or any later
# uncertain DB/DNS change. Existing Phase 6G stale lock recovery MUST NOT
# treat these as ordinary expired operations.
EGRESS_HOLD_PHASES = frozenset({
    "ARM_FAIL_CLOSED", "SELECT_TARGET_EGRESS", "VERIFY_CUSTOMER_EGRESS",
    "SOURCE_ACCOUNT_CAS", "EDGE_ONLY_DNS_CUTOVER", "VERIFY_FINAL",
    "PROTECTED_EGRESS_MAPPING_CAS", "VERIFY_PUBLIC_INGRESS_DNS_UNCHANGED",
    MANUAL_RECOVERY_PHASE,
    # Staging also produces host-local secret files. If a remote stage step
    # outlives the old 6G stale timeout, a second operation must not claim
    # the same Edge resources. Operator reconciliation is required on crash.
    "RECHECK_SOURCE", "READ_ONLY_PREFLIGHT", "HOST_LOCAL_PUBLIC_KEYS",
    "RESERVE_RESOURCE_IDENTITY", "STAGE_EDGE", "STAGE_CORE",
    "RECHECK_OWNERSHIP", "MARK_STAGED_NOT_READY",
    "EGRESS_PREPARE_RECOVERY_REQUIRED",
    # D1-C3B protected-UID canary: never auto-clear an ambiguous kernel guard.
    "EGRESS_UID_ARM_GUARD", "EGRESS_UID_START_SHADOW",
    "EGRESS_UID_ATTACH_ROUTE", "EGRESS_UID_PROVE_IPV4",
    "EGRESS_UID_PROVE_IPV6_DNS", "EGRESS_UID_STOP_SHADOW",
    "EGRESS_UID_RESTORE_CANARY", "EGRESS_UID_RECOVERY_REQUIRED",
    # Guarded 6G/6H candidate staging may mutate dedicated Edge resources.
    "EGRESS_GUARDED_CANDIDATE_STAGE",
    "EGRESS_GUARDED_DEDICATED_PEER_REKEY",
    "EGRESS_GUARDED_EXTERNAL_EGRESS_PROOF",
    "EGRESS_GUARDED_REVALIDATE_OWNERSHIP_AND_ALLOCATION",
    # F2 protected UID runtime: never auto-clear the shared 6G lease after
    # possible host mutation or after durable admission BLOCK intent.
    "EGRESS_UID_RUNTIME_BLOCK_INTENT",
    "EGRESS_UID_RUNTIME_ACCOUNT_IDLE",
    "EGRESS_UID_RUNTIME_ARM_GUARD",
    "EGRESS_UID_RUNTIME_START_EDGE",
    "EGRESS_UID_RUNTIME_ATTACH",
    "EGRESS_UID_RUNTIME_PROVE",
    "EGRESS_UID_RUNTIME_COMMIT_PROTECTED",
    "EGRESS_UID_RUNTIME_FREEZE",
    "EGRESS_UID_RUNTIME_RECOVERY_REQUIRED",
    # F3 pinned-shadow staging/verification can mutate dedicated peers.
    "EGRESS_F3_SHADOW_START_POSSIBLE",
    "EGRESS_F3_SHADOW_PROOF",
    "EGRESS_F3_SHADOW_STOP",
    "EGRESS_F3_RECORD_LAB_PROOF",
    "EGRESS_F3_SHADOW_RECOVERY_REQUIRED",
    # J: durable account-admission freeze and source-session drain are
    # protected mutations; stale 6G leases must never auto-unlock these.
    "ADMISSION_FENCE", "DRAIN_SOURCE_SESSIONS",
    "EDGE_ONLY_PROTECTED_DNS_CUTOVER",
    # P3-A journal-before-host-write; RUNNING must survive legacy stale-lock
    # recovery even when the executor is interrupted or host state is unknown.
    "EGRESS_P3_EXECUTE_INTENT", "EGRESS_P3_RECOVERY_REQUIRED",
})


def is_egress_recovery_hold(detail_json) -> bool:
    """Recognize an unresolved protected handoff in Phase 6G's shared lock."""
    import json

    if not isinstance(detail_json, str) or not detail_json.strip():
        return False
    try:
        data = json.loads(detail_json)
    except (ValueError, TypeError):
        return False
    return isinstance(data, dict) and data.get("phase") in EGRESS_HOLD_PHASES


class HandoffUnsafe(ValueError):
    pass


@dataclass(frozen=True)
class AccountOwner:
    username: str
    uid: int

    def __post_init__(self):
        if not isinstance(self.username, str) or not self.username or "\x00" in self.username:
            raise HandoffUnsafe("INVALID_SSH_USERNAME")
        if type(self.uid) is not int or not (1000 <= self.uid <= 60000):
            raise HandoffUnsafe("UNSAFE_SSH_UID")


@dataclass(frozen=True)
class HandoffSnapshot:
    """An immutable current source-ownership snapshot captured UNDER 6G lock."""
    source_host: str
    target_host: str
    core_public_ipv4: str
    current_dns_ipv4: str
    active_accounts: tuple[AccountOwner, ...]
    other_explicit_active_accounts: int
    source_is_default: bool
    target_is_active_standby: bool
    source_service_port: int
    target_service_port: int
    target_egress_identity_unique: bool

    def validate(self) -> None:
        try:
            source = ip_address(self.source_host)
            target = ip_address(self.target_host)
            core = ip_address(self.core_public_ipv4)
            dns = ip_address(self.current_dns_ipv4)
        except ValueError as exc:
            raise HandoffUnsafe("INVALID_IP") from exc
        if any(not isinstance(x, IPv4Address) or not x.is_global
               for x in (source, target, core)):
            raise HandoffUnsafe("NONPUBLIC_EDGE_OR_CORE")
        if source in (target, core) or target == core:
            raise HandoffUnsafe("SOURCE_TARGET_CORE_COLLISION")
        # The old Phase 6G allowed DNS==Core; protected Relay does not.
        if dns != source:
            raise HandoffUnsafe("DNS_NOT_AT_SOURCE_EDGE")
        if not self.source_is_default:
            raise HandoffUnsafe("SOURCE_NOT_CURRENT_DEFAULT")
        if not self.target_is_active_standby:
            raise HandoffUnsafe("TARGET_NOT_ACTIVE_STANDBY")
        if type(self.other_explicit_active_accounts) is not int or self.other_explicit_active_accounts != 0:
            raise HandoffUnsafe("GLOBAL_DOMAIN_MULTI_EDGE_CONFLICT")
        if type(self.source_service_port) is not int or type(self.target_service_port) is not int or not (
            1 <= self.source_service_port <= 65535
            and self.source_service_port == self.target_service_port
        ):
            raise HandoffUnsafe("SERVICE_PORT_MISMATCH")
        if self.target_egress_identity_unique is not True:
            raise HandoffUnsafe("EGRESS_ALLOCATION_COLLISION")
        if not self.active_accounts or len(self.active_accounts) > 10000:
            raise HandoffUnsafe("INVALID_ACCOUNT_SET")
        names = [u.username for u in self.active_accounts]
        uids = [u.uid for u in self.active_accounts]
        if len(names) != len(set(names)) or len(uids) != len(set(uids)):
            raise HandoffUnsafe("ACCOUNT_IDENTITY_COLLISION")
        if any(not isinstance(user, AccountOwner) for user in self.active_accounts):
            raise HandoffUnsafe("ACCOUNT_IDENTITY_UNVERIFIED")


@dataclass(frozen=True)
class TargetObservation:
    """Measured after dedicated Edge-peer reconciliation, not from cached wg."""
    readiness: EgressReadiness
    observed_at: datetime
    edge_instance: str

    def validate(self, target_host: str, now: datetime) -> None:
        if not self.edge_instance or self.readiness.edge_host != target_host:
            raise HandoffUnsafe("TARGET_OBSERVATION_IDENTITY_MISMATCH")
        if self.observed_at.tzinfo is None or now.tzinfo is None:
            raise HandoffUnsafe("UNTRUSTED_OBSERVATION_CLOCK")
        age = now - self.observed_at
        if age < timedelta(seconds=-5) or age > MAX_EVIDENCE_AGE:
            raise HandoffUnsafe("TARGET_OBSERVATION_STALE")


@dataclass(frozen=True)
class HandoffResult:
    ok: bool
    reason: str
    operation_id: Optional[int]
    needs_manual_recovery: bool = False


class HandoffPorts(Protocol):
    """All methods supplied by the *existing* NVL bot/6G adapters.

    No production implementation exists in this PR. The kernel/DB/DNS tests
    below use fakes. Every mutating operation must be idempotent or journaled.
    """
    async def acquire_6g_lock(self, source: str, target: str) -> tuple[Optional[int], Optional[int]]: ...
    async def update_6g_journal(self, operation_id: int, *, status: str, phase: str,
                                details: dict) -> None: ...
    async def snapshot_under_lock(self, source: str, target: str) -> HandoffSnapshot: ...
    async def stage_target_shadow(self, snapshot: HandoffSnapshot) -> None: ...
    async def rekey_dedicated_peer(self, snapshot: HandoffSnapshot) -> None: ...
    async def observe_target(self, snapshot: HandoffSnapshot) -> TargetObservation: ...
    async def revalidate_before_cutover(self, snapshot: HandoffSnapshot) -> None: ...
    async def block_new_logins(self, snapshot: HandoffSnapshot) -> None: ...
    async def drain_source_sessions(self, snapshot: HandoffSnapshot) -> None: ...
    async def arm_fail_closed(self, snapshot: HandoffSnapshot) -> None: ...
    async def select_target_egress(self, snapshot: HandoffSnapshot) -> None: ...
    async def prove_selected_egress(self, snapshot: HandoffSnapshot) -> None: ...
    async def commit_source_accounts_cas(self, snapshot: HandoffSnapshot) -> None: ...
    async def switch_dns_direct_to_target(self, snapshot: HandoffSnapshot) -> None: ...
    async def verify_final(self, snapshot: HandoffSnapshot) -> None: ...
    async def freeze_customer_egress(self, snapshot: HandoffSnapshot) -> None: ...


async def _record(ports: HandoffPorts, operation_id: int, status: str,
                  phase: str, details: dict) -> None:
    await ports.update_6g_journal(operation_id, status=status, phase=phase, details=details)


async def run_protected_handoff(
    ports: HandoffPorts,
    source_host: str,
    target_host: str,
    *,
    now: Optional[datetime] = None,
    guarded_failover: bool = False,
    require_admission_drain: bool = False,
) -> HandoffResult:
    """A conservative saga plan using 6G shared lock/journal.

    No live adapter or admin/UI entry point is implemented. The order is
    intentionally explicit: never perform the legacy DNS-to-Core fallback.
    The lock MUST be persisted across process crashes, and stale-lock
    recovery MUST respect EGRESS_RECOVERY_REQUIRED (release gate D1-C3).
    """
    if require_admission_drain and not guarded_failover:
        raise HandoffUnsafe("DRAIN_REQUIRES_GUARDED_HANDOFF")
    operation_id, busy_id = await ports.acquire_6g_lock(source_host, target_host)
    if operation_id is None:
        return HandoffResult(False, "SHARED_FAILOVER_BUSY", busy_id)

    snapshot = None
    safety_touched = False
    candidate_touched = False
    phase = "LOCKED"
    try:
        await _record(ports, operation_id, "RUNNING", phase,
                      {"source": source_host, "target": target_host})
        snapshot = await ports.snapshot_under_lock(source_host, target_host)
        snapshot.validate()
        if snapshot.source_host != source_host or snapshot.target_host != target_host:
            raise HandoffUnsafe("SNAPSHOT_REQUEST_MISMATCH")

        phase = "CANDIDATE_STAGE"
        if guarded_failover:
            candidate_touched = True
        await _record(ports, operation_id, "RUNNING", phase, {})
        await ports.stage_target_shadow(snapshot)

        phase = "DEDICATED_PEER_REKEY"
        await _record(ports, operation_id, "RUNNING", phase, {})
        await ports.rekey_dedicated_peer(snapshot)

        phase = "EXTERNAL_EGRESS_PROOF"
        await _record(ports, operation_id, "RUNNING", phase, {})
        evidence = await ports.observe_target(snapshot)
        evidence.validate(target_host, now or datetime.now(timezone.utc))
        decision = evaluate_protected_handoff(
            source_edge=source_host,
            target=evidence.readiness,
            core_public_ipv4=snapshot.core_public_ipv4,
            legacy_dns_core_fallback_enabled=False,
            global_domain_multi_edge_conflict=bool(snapshot.other_explicit_active_accounts),
        )
        if not decision.ready:
            raise HandoffUnsafe(decision.reason)

        phase = "REVALIDATE_OWNERSHIP_AND_ALLOCATION"
        await _record(ports, operation_id, "RUNNING", phase, {})
        # MUST compare account username+UID mapping, DNS, allocation and
        # candidate readiness under lock. Raise on any stale state.
        await ports.revalidate_before_cutover(snapshot)

        if require_admission_drain:
            # F2 PAM reads the existing runtime state. Mark the entire
            # protected set FROZEN under 6G before checking for live sessions;
            # otherwise a new SSH auth can race the last idle observation.
            phase = "ADMISSION_FENCE"
            safety_touched = True
            await _record(ports, operation_id, "RUNNING", phase, {})
            await ports.block_new_logins(snapshot)
            phase = "DRAIN_SOURCE_SESSIONS"
            await _record(ports, operation_id, "RUNNING", phase, {})
            await ports.drain_source_sessions(snapshot)

        # Arm terminal 'unreachable' fallback before changing any target route.
        # Treat a partial arm as possible mutation: freeze on ANY exception.
        phase = "ARM_FAIL_CLOSED"
        safety_touched = True
        await _record(ports, operation_id, "RUNNING", phase, {})
        await ports.arm_fail_closed(snapshot)

        phase = "SELECT_TARGET_EGRESS"
        await _record(ports, operation_id, "RUNNING", phase, {})
        await ports.select_target_egress(snapshot)

        phase = "VERIFY_CUSTOMER_EGRESS"
        await _record(ports, operation_id, "RUNNING", phase, {})
        await ports.prove_selected_egress(snapshot)

        # DB CAS + public DNS are not one transaction. They are journaled as
        # separately recoverable steps; never invent an atomic guarantee.
        phase = ("PROTECTED_EGRESS_MAPPING_CAS" if guarded_failover
                 else "SOURCE_ACCOUNT_CAS")
        await _record(ports, operation_id, "RUNNING", phase, {})
        await ports.commit_source_accounts_cas(snapshot)

        phase = ("EDGE_ONLY_PROTECTED_DNS_CUTOVER" if guarded_failover
                 else "EDGE_ONLY_DNS_CUTOVER")
        await _record(ports, operation_id, "RUNNING", phase, {})
        await ports.switch_dns_direct_to_target(snapshot)

        phase = "VERIFY_FINAL"
        await _record(ports, operation_id, "RUNNING", phase, {})
        await ports.verify_final(snapshot)

        phase = "SUCCEEDED"
        await _record(ports, operation_id, "SUCCEEDED", phase,
                      {"target": target_host, "account_count": len(snapshot.active_accounts)})
        return HandoffResult(True, "SUCCEEDED", operation_id)
    except Exception as exc:
        # Avoid logging raw provider or credential-containing exception text.
        reason = f"{type(exc).__name__}:{str(exc)[:120]}" if isinstance(exc, HandoffUnsafe) else (
            f"{type(exc).__name__}:OPERATION_FAILED"
        )
        if safety_touched and snapshot is not None:
            # Even if freeze fails, hold the SHARED failover lock. Do not
            # release it via FAILED status, because 6G treats FAILED as unlocked.
            frozen = False
            try:
                await ports.freeze_customer_egress(snapshot)
                frozen = True
            except Exception:
                pass
            try:
                await _record(ports, operation_id, "RUNNING", MANUAL_RECOVERY_PHASE,
                              {"failed_phase": phase, "frozen": frozen, "reason": reason})
            except Exception:
                # Last resort: do not unlock the shared lock.
                pass
            return HandoffResult(False, reason, operation_id, needs_manual_recovery=True)

        if guarded_failover and candidate_touched:
            # Candidate WireGuard/staging/rekey can have partially changed
            # even though the customer UID route remains on its source Edge.
            # The protected shared 6G lock stays HELD until an operator
            # reconciles dedicated candidate resources and account state.
            try:
                await _record(ports, operation_id, "RUNNING", MANUAL_RECOVERY_PHASE,
                              {"failed_phase": phase,
                               "candidate_reconcile_required": True,
                               "customer_routing_touched": False,
                               "reason": reason})
            except Exception:
                pass
            return HandoffResult(False, reason, operation_id,
                                 needs_manual_recovery=True)

        # No customer routing, account ownership or public DNS touched.
        # Shadow resources may remain, so cleanup is deferred to the manager.
        try:
            await _record(ports, operation_id, "FAILED", phase,
                          {"reason": reason, "customer_state_touched": False})
        except Exception:
            # If the journal failed, treat the lock as uncertain.
            return HandoffResult(False, "JOURNAL_UNCERTAIN", operation_id,
                                 needs_manual_recovery=True)
        return HandoffResult(False, reason, operation_id)
