"""K2 guarded cross-Edge UID port over the ORIGINAL P3/F2/6G engine.

One UID only; no shell, second lease, user mutation API, or global DNS/Edge
switch. Root factory must separately attest fresh physical F4 and PAM.
Never serves as an alternate privileged executor.
"""
from __future__ import annotations

from typing import Callable

from edge_egress_k2_m3_waves import (
    MigrationMember, build_wave_plan, m4_cross_edge_single_reviewed,
)
from edge_egress_k2_migration_inventory import (
    MigrationInventory, select_migration,
)
from edge_egress_p3_executor import (
    ExecutionScope, ExecutionTicket, assert_guarded_6g_intent,
    _scope_digest,
)
from edge_egress_p3_uid import GuardedProtectedUIDPort
from edge_egress_uid_runtime_store import K2CrossEdgeUIDRuntimeStore

M4_CROSS_EDGE_UID_PORT_ENABLED = False


class CrossEdgeUIDHold(ValueError):
    pass


class GuardedCrossEdgeUIDPort:
    """Recheck the *same* immutable M1 member before and after original P3."""

    def __init__(self, *, member: MigrationMember, scope: ExecutionScope,
                 ticket: ExecutionTicket, uid_port: GuardedProtectedUIDPort,
                 db_conn: Callable, live_inventory: Callable,
                 release_enabled: bool = False):
        store = getattr(uid_port, "store", None)
        if (type(uid_port) is not GuardedProtectedUIDPort
            or type(store) is not K2CrossEdgeUIDRuntimeStore
            or type(member) is not MigrationMember
            or type(scope) is not ExecutionScope
            or scope.action != "UID_ATTACH"
            or not isinstance(ticket, ExecutionTicket)
            or not callable(db_conn) or not callable(live_inventory)
            or uid_port.db_conn is not db_conn
            or uid_port.plan.scope != scope or uid_port.ticket != ticket
            or store.scope != scope or store.ticket != ticket
            or store.db_conn is not db_conn
            or store.ingress_edge_id != member.source_edge_id
            or member.username != scope.username or member.uid != scope.uid
            or not member.selectable or member.protected_edge_id
            or member.source_edge_id == member.target_edge_id
            or member.source_ipv4 == member.target_ipv4
            or member.source_ipv4 != scope.source_host
            or member.target_ipv4 != scope.target_host
            or member.target_edge_id != scope.edge_id
            or ticket.scope_digest != _scope_digest(scope)):
            raise CrossEdgeUIDHold("K2_EXACT_CROSS_EDGE_P3_UID_PORT_REQUIRED")
        self.member, self.scope, self.ticket = member, scope, ticket
        self.uid_port, self.db_conn = uid_port, db_conn
        self.live_inventory = live_inventory
        self.release_enabled = release_enabled is True
        self._started = False

    def _check(self, scope: ExecutionScope, *, committed: bool) -> None:
        if (not M4_CROSS_EDGE_UID_PORT_ENABLED
            or not self.release_enabled or scope != self.scope):
            raise CrossEdgeUIDHold("K2_CROSS_EDGE_P3_PORT_NOT_RELEASED")
        assert_guarded_6g_intent(self.db_conn, scope, self.ticket)
        member = self.member
        selection = select_migration(
            "SINGLE", (member.username,), member.target_edge_id
        )
        fresh = self.live_inventory(selection)
        if type(fresh) is not MigrationInventory:
            raise CrossEdgeUIDHold("K2_CROSS_EDGE_LIVE_INVENTORY_MISSING")
        plan = build_wave_plan(fresh, wave_size=1)
        chosen = plan.members[0] if len(plan.members) == 1 else None
        # A committed UID is expected to be PROTECTED, so M1 reports
        # TARGET_ALREADY_PROTECTED. Other changes remain fatal.
        if (not plan.selection.mode == "SINGLE"
            or any(x != "SHARED_6G_BUSY" for x in plan.global_blockers)
            or chosen is None or not fresh.target_f4_accepted
            or (chosen.blockers != ("TARGET_ALREADY_PROTECTED",)
                if committed else chosen.blockers != ())
            or chosen.username != member.username or chosen.uid != member.uid
            or chosen.source_edge_id != member.source_edge_id
            or chosen.source_ipv4 != member.source_ipv4
            or not chosen.source_proven or chosen.active_sessions != 0
            or chosen.historical_host != member.historical_host
            or chosen.target_edge_id != member.target_edge_id
            or chosen.target_ipv4 != member.target_ipv4
            or chosen.protected_edge_id != (
                member.target_edge_id if committed else ""
            )):
            raise CrossEdgeUIDHold("K2_CROSS_EDGE_SOURCE_OR_F4_DRIFT")
        assert_guarded_6g_intent(self.db_conn, scope, self.ticket)

    async def apply(self, scope: ExecutionScope) -> None:
        if self._started:
            raise CrossEdgeUIDHold("K2_CROSS_EDGE_ONE_SHOT")
        self._started = True
        self._check(scope, committed=False)
        await self.uid_port.apply(scope)

    async def verify(self, scope: ExecutionScope) -> bool:
        if not self._started:
            raise CrossEdgeUIDHold("K2_CROSS_EDGE_NOT_APPLIED")
        assert_guarded_6g_intent(self.db_conn, scope, self.ticket)
        if await self.uid_port.verify(scope) is not True:
            raise CrossEdgeUIDHold("K2_CROSS_EDGE_PACKET_PROOF_FAILED")
        self._check(scope, committed=True)
        return True

    async def freeze_or_hold(self, scope: ExecutionScope) -> None:
        if self._started and scope == self.scope:
            await self.uid_port.freeze_or_hold(scope)


def root_fresh_source_evidence():
    """Production-only CURRENT PAM journal + WireGuard owner; no fake source.

    This function has no Telegram-provided parameters. Reopens root-only
    registry and journal and queries live wg0 at each 6G step.
    """
    import subprocess
    import time
    from edge_egress_k2_m2_ingress_journal import make_m1_readonly_ingress_provider
    return make_m1_readonly_ingress_provider(
        now=int(time.time()), run=subprocess.run,
    )


from dataclasses import dataclass
from ops.k2_p3_uid_worker import IndependentSafety


CROSS_EDGE_PAM_SAFETY_ENABLED = False


@dataclass
class CrossEdgeIndependentSafety(IndependentSafety):
    """Same original P3 safety, with different *observed* SSH ingress.

    Override only the legacy same-IP PAM ingress predicate. All original
    account idleness, neighbour isolation and independent packet proof remain
    inherited, mandatory and unchanged.
    """
    ingress_edge_id: str = ""
    source_evidence: Callable = root_fresh_source_evidence

    def assert_pam_ingress_boot(self, req):
        from edge_egress_k2_m2_ingress_journal import RootReadOnlyIngressEvidence
        from edge_egress_f4_pam import verify_installed_gate_digest
        from edge_egress_f4_preflight import sshd_connection_spec
        from edge_egress_f3_readiness import read_readiness, admission_eligible
        from edge_egress_uid_boot import BootGuardApplier
        from edge_egress_v1_admission import inspect_pam
        from ops.k2_p3_host_readonly import trusted_pam_config
        from ops.k2_p3_uid_worker import _checked, LiveUIDHold
        if (not CROSS_EDGE_PAM_SAFETY_ENABLED
            or not callable(self.source_evidence)
            or self.source_evidence is not root_fresh_source_evidence
            or not isinstance(self.ingress_rhost, str)
            or not self.ingress_rhost.startswith("10.77.0.")
            or not isinstance(self.ingress_edge_id, str)
            or self.ingress_edge_id == self.target_edge_id
            or req.spec.edge_id != self.target_edge_id
            or req.spec.edge_public_ipv4 == self.source_ipv4
            or not verify_installed_gate_digest(self.reviewed_module_sha256)):
            raise LiveUIDHold("K2_CROSS_EDGE_PAM_NOT_ATTESTED")
        manifest = self._manifest(req)
        sshd_spec = sshd_connection_spec(
            username=req.username, local_addr=self.ssh_local_addr,
            remote_addr=self.ingress_rhost,
            local_port=self.ssh_local_port,
        )
        if not inspect_pam(
            trusted_pam_config(),
            _checked("sshd", "-T", "-C", sshd_spec),
        ):
            raise LiveUIDHold("K2_CROSS_EDGE_EFFECTIVE_SSHD_UNVERIFIED")
        observed = self.source_evidence()
        if type(observed) is not RootReadOnlyIngressEvidence:
            raise LiveUIDHold("K2_ROOT_LIVE_INGRESS_SOURCE_REQUIRED")
        try:
            witness = observed(req.username)
        except (ValueError, OSError, KeyError) as exc:
            raise LiveUIDHold("K2_PAM_JOURNAL_WG_NOT_CURRENT") from exc
        matches = [
            peer for peer in observed.peers
            if peer.edge_id == self.ingress_edge_id
            and peer.edge_ipv4 == self.source_ipv4
            and peer.ingress_ipv4 == self.ingress_rhost
        ]
        # The journal's authenticated PAM_RHOST/key must identify this
        # exact SSH ingress, not merely another peer on the same Edge.
        from edge_egress_k2_m2_ingress_journal import _validated
        source_record = _validated(observed.raw).get(req.username)
        if (witness.username != req.username or witness.edge_id != self.ingress_edge_id
            or witness.edge_ipv4 != self.source_ipv4 or len(matches) != 1
            or source_record is None
            or source_record.ingress_ipv4 != self.ingress_rhost
            or source_record.wg_public_key != matches[0].wg_public_key):
            raise LiveUIDHold("K2_CROSS_EDGE_WG_KEY_OR_SOURCE_DRIFT")
        with self.db_conn() as db:
            readiness = read_readiness(db, req.spec.edge_id)
            if (readiness is None
                or readiness.edge_ipv4 != req.spec.edge_public_ipv4
                or not admission_eligible(readiness, now=self.now())):
                raise LiveUIDHold("K2_TARGET_F4_NOT_ACCEPTED")
        BootGuardApplier().verify(manifest, require_frozen=True)
