"""K2 P3-E: read-only orphan inventory + guarded, UID-fenced Edge retirement.

NO production host adapter or bot callback is installed. Mutations are allowed
only through a separately approved, injected root-only worker and the SAME
P3-A nonce-bearing 6G EXECUTE_INTENT lease. No deletion of wg0, SSH, global
route/DNS, source account, per-UID selector, blackhole or IPv4/IPv6 REJECT.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import re
from pathlib import Path
from typing import Callable, Protocol

from edge_egress_p3_executor import (
    ExecutionScope, ExecutionTicket, assert_guarded_6g_intent,
)
from ops.edge_egress_provision import EgressSpec
from ops.edge_egress_v1_transport import pinned

P3E_RETIRE_EXECUTOR_ENABLED = False


class EdgeRetireHold(ValueError):
    pass


@dataclass(frozen=True)
class RetiredUIDFence:
    username: str
    uid: int
    priority: int
    table: int
    unix_owner_matches: bool
    ipv4_reject: bool
    ipv6_reject: bool
    terminal_blackhole: bool
    selector_exact: bool
    preferred_edge_route: bool
    active_sessions: int


@dataclass(frozen=True)
class OwnedKernelSnapshot:
    """Attested by an independent read-only host inspector, not the bot."""
    namespace_present: bool
    veth_present: bool
    dedicated_wg_present: bool
    units_enabled: bool
    units_running: bool
    wg0_runtime_reference: bool
    wg0_persistent_reference: bool
    foreign_references: tuple[str, ...]
    owned_uid_fences: tuple[RetiredUIDFence, ...]
    audit_complete: bool


@dataclass(frozen=True)
class OrphanRetirePlan:
    stage: Path
    stage_sha256: str
    spec: EgressSpec
    scope: ExecutionScope
    snapshot: OwnedKernelSnapshot
    registry_has_edge: bool
    fingerprint: str

    @property
    def detached_uids(self) -> tuple[str, ...]:
        return tuple(f.username for f in self.snapshot.owned_uid_fences)


class OwnedRetireHostPort(Protocol):
    """Must be an audited host-pinned root worker, NOT a generic shell."""
    def inspect(self, spec: EgressSpec) -> OwnedKernelSnapshot: ...
    def disable_exact_owned_units(self, spec: EgressSpec) -> None: ...
    def remove_exact_owned_next_hop(self, spec: EgressSpec,
                                     fence: RetiredUIDFence) -> None: ...
    def remove_exact_dedicated_transport(self, spec: EgressSpec) -> None: ...
    def reaffirm_uid_fences(self, spec: EgressSpec,
                             fences: tuple[RetiredUIDFence, ...]) -> None: ...


def _digest(stage: Path, pin: str, spec: EgressSpec,
            kernel: OwnedKernelSnapshot, registry_present: bool) -> str:
    return sha256(json.dumps({
        "stage": str(stage), "pin": pin, "spec": asdict(spec),
        "kernel": asdict(kernel), "registry": registry_present,
    }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _assert_kernel_identity(spec: EgressSpec, observation: OwnedKernelSnapshot, *,
                            baseline: tuple[RetiredUIDFence, ...],
                            require_all_detached: bool = False,
                            require_retired: bool = False) -> None:
    if not isinstance(observation, OwnedKernelSnapshot) or observation.audit_complete is not True:
        raise EdgeRetireHold("KERNEL_INVENTORY_NOT_ATTESTED")
    if (observation.wg0_runtime_reference or observation.wg0_persistent_reference
            or observation.foreign_references):
        raise EdgeRetireHold("WG0_OR_FOREIGN_RESOURCE_REFERENCE")
    if (len(observation.owned_uid_fences) != len(baseline)
            or tuple((x.username,x.uid,x.priority,x.table)
                     for x in observation.owned_uid_fences) != tuple(
                        (x.username,x.uid,x.priority,x.table) for x in baseline)):
        raise EdgeRetireHold("FOREIGN_UID_RULE_OR_OWNERSHIP_DRIFT")
    for old, current in zip(baseline, observation.owned_uid_fences):
        if (current.table != spec.route_table or current.uid < 1000
                or current.uid >= 60000 or not current.unix_owner_matches
                or not current.ipv4_reject or not current.ipv6_reject
                or not current.terminal_blackhole or not current.selector_exact
                or current.active_sessions != 0):
            raise EdgeRetireHold("UID_FENCE_OR_TERMINAL_BLACKHOLE_MISSING")
        if old.preferred_edge_route is False and current.preferred_edge_route:
            raise EdgeRetireHold("REMOVED_EDGE_ROUTE_REAPPEARED")
        if require_all_detached and current.preferred_edge_route:
            raise EdgeRetireHold("DEDICATED_EDGE_NEXT_HOP_STILL_IN_USE")
    if require_retired and (
            observation.namespace_present or observation.veth_present
            or observation.dedicated_wg_present or observation.units_running
            or observation.units_enabled):
        raise EdgeRetireHold("DEDICATED_TRANSPORT_OR_PERSISTENCE_NOT_RETIRED")


def _assert_db_clean(conn, spec: EgressSpec, *, allow_current_lock: bool) -> None:
    tables = (
        "host_pool", "ssh_accounts", "settings", "failover_operations",
        "edge_egress_f3_ingress_candidates", "edge_egress_allocations",
        "edge_egress_readiness", "edge_egress_uid_bindings",
        "edge_egress_uid_runtime",
    )
    available={name for (name,) in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    )}
    if not set(tables).issubset(available):
        raise EdgeRetireHold("REQUIRED_K2_SCHEMA_MISSING")
    ip = spec.edge_public_ipv4
    host = conn.execute(
        "SELECT active,is_default FROM host_pool WHERE host=?", (ip,)
    ).fetchall()
    if len(host)>1 or any(row!=(0,0) for row in host):
        raise EdgeRetireHold("EDGE_HOST_ACTIVE_OR_DEFAULT")
    if conn.execute("SELECT 1 FROM ssh_accounts WHERE host=? LIMIT 1",(ip,)).fetchone():
        raise EdgeRetireHold("SSH_ACCOUNT_ON_EDGE")
    if conn.execute(
        "SELECT value FROM settings WHERE key='dns_current_ip'"
    ).fetchone() in (None, (ip,)):
        raise EdgeRetireHold("PUBLIC_DNS_EDGE_OR_UNKNOWN")
    if conn.execute(
        "SELECT 1 FROM edge_egress_f3_ingress_candidates WHERE edge_ipv4=? LIMIT 1",
        (ip,)
    ).fetchone():
        raise EdgeRetireHold("INGRESS_CANDIDATE_STILL_PRESENT")
    for table, keys in (
        ("edge_egress_allocations", (("edge_id",spec.edge_id),("edge_public_ipv4",ip))),
        ("edge_egress_readiness", (("edge_id",spec.edge_id),("edge_ipv4",ip))),
        ("edge_egress_uid_bindings", (("edge_id",spec.edge_id),("edge_ipv4",ip))),
        ("edge_egress_uid_runtime", (("edge_id",spec.edge_id),("edge_ipv4",ip))),
    ):
        for column, value in keys:
            if conn.execute(
                f"SELECT 1 FROM {table} WHERE {column}=? LIMIT 1",
                (value,)
            ).fetchone():
                raise EdgeRetireHold("EDGE_METADATA_STILL_ATTACHED:" + table)
    running=conn.execute(
        "SELECT id FROM failover_operations WHERE status='RUNNING'"
    ).fetchall()
    if not allow_current_lock and running:
        raise EdgeRetireHold("6G_ALREADY_RUNNING")
    if allow_current_lock and len(running)!=1:
        raise EdgeRetireHold("6G_NOT_EXCLUSIVE")


def plan_orphan_cleanup(db_conn: Callable, scope: ExecutionScope, *,
                        stage: Path, stage_sha256: str,
                        host: OwnedRetireHostPort,
                        registry_loader: Callable,
                        stage_reader: Callable = pinned) -> OrphanRetirePlan:
    """Read-only. Requires a trusted staged manifest; no blind name-based del."""
    if (not isinstance(scope, ExecutionScope) or scope.action!="EDGE_RETIRE"
            or not isinstance(stage, Path)
            or stage!=Path("/root/nvl-egress-v1")/("core-"+scope.edge_id)
            or not isinstance(stage_sha256,str)
            or not re.fullmatch(r"[0-9a-f]{64}",stage_sha256)):
        raise EdgeRetireHold("PINNED_CORE_STAGE_REQUIRED")
    spec,_peer=stage_reader(stage,"core",stage_sha256)
    if (not isinstance(spec,EgressSpec) or
            (spec.edge_id,spec.core_public_ipv4,spec.edge_public_ipv4)!=
            (scope.edge_id,scope.source_host,scope.target_host)):
        raise EdgeRetireHold("PINNED_STAGE_IDENTITY_MISMATCH")
    peers=registry_loader()
    if not isinstance(peers,tuple):
        raise EdgeRetireHold("REGISTRY_NOT_VERIFIED")
    own=[p for p in peers if p.edge_id==scope.edge_id or p.edge_ipv4==scope.target_host]
    if len(own)>1 or (own and (own[0].edge_id,own[0].edge_ipv4)!=(scope.edge_id,scope.target_host)):
        raise EdgeRetireHold("REGISTRY_COLLISION")
    with db_conn() as conn:
        _assert_db_clean(conn,spec,allow_current_lock=False)
    audit=host.inspect(spec)
    fences=audit.owned_uid_fences if isinstance(audit,OwnedKernelSnapshot) else ()
    if len({f.uid for f in fences})!=len(fences) or len({f.priority for f in fences})!=len(fences):
        raise EdgeRetireHold("UID_OR_PRIORITY_COLLISION")
    _assert_kernel_identity(spec,audit,baseline=fences)
    return OrphanRetirePlan(stage,stage_sha256,spec,scope,audit,bool(own),
                            _digest(stage,stage_sha256,spec,audit,bool(own)))


class GuardedOrphanRetirePort:
    """P3-A EDGE_RETIRE HostPort; release-disabled and non-reentrant.

    Preserve all selected UID RPDB rules, IPv4/IPv6 REJECT and blackholes.
    Only an exact preferred route, dedicated persistence and namespace may go.
    Post-cleanup registry/metadata retire is an INDEPENDENT later operation.
    """

    def __init__(self, *, db_conn: Callable, plan: OrphanRetirePlan,
                 ticket: ExecutionTicket, host: OwnedRetireHostPort | None = None,
                 stage_reader: Callable=pinned, registry_loader: Callable | None=None,
                 release_enabled: bool=False):
        self.db_conn,self.plan,self.ticket=db_conn,plan,ticket
        self.host,self.stage_reader,self.registry_loader=host,stage_reader,registry_loader
        self.release_enabled=release_enabled
        self._used=False
        self._touched=False

    def _check(self, scope: ExecutionScope, *, require_units_off=False,
               require_detached=False, require_retired=False) -> OwnedKernelSnapshot:
        p=self.plan
        if (not self.release_enabled or self.host is None or
                self.registry_loader is None or scope!=p.scope):
            raise EdgeRetireHold("RETIRE_HOST_RELEASE_MISSING")
        assert_guarded_6g_intent(self.db_conn,scope,self.ticket)
        if (p.fingerprint != _digest(p.stage,p.stage_sha256,p.spec,
                                    p.snapshot,p.registry_has_edge)
                or self.ticket.evidence_digest != p.fingerprint):
            raise EdgeRetireHold("ORPHAN_REVIEW_FINGERPRINT_CHANGED")
        spec,_peer=self.stage_reader(p.stage,"core",p.stage_sha256)
        if spec!=p.spec:
            raise EdgeRetireHold("PINNED_STAGE_CHANGED")
        peers=self.registry_loader()
        if (not isinstance(peers,tuple)
                or any(
                    (x.edge_id==scope.edge_id or x.edge_ipv4==scope.target_host)
                    and (x.edge_id,x.edge_ipv4)!=(scope.edge_id,scope.target_host)
                    for x in peers)
                or bool([x for x in peers if x.edge_id==scope.edge_id])
                   !=p.registry_has_edge):
            raise EdgeRetireHold("REGISTRY_CHANGED_DURING_RETIREE")
        with self.db_conn() as conn:
            _assert_db_clean(conn,p.spec,allow_current_lock=True)
        state=self.host.inspect(p.spec)
        _assert_kernel_identity(p.spec,state,baseline=p.snapshot.owned_uid_fences,
                                require_all_detached=require_detached,
                                require_retired=require_retired)
        if require_units_off and (state.units_running or state.units_enabled):
            raise EdgeRetireHold("DEDICATED_UNITS_STILL_LIVE")
        return state

    async def apply(self,scope: ExecutionScope) -> None:
        if self._used:
            raise EdgeRetireHold("RETIRE_ONE_SHOT")
        self._used=True
        p=self.plan
        self._check(scope)
        self._touched=True
        self.host.disable_exact_owned_units(p.spec)
        self._check(scope,require_units_off=True)
        for fence in p.snapshot.owned_uid_fences:
            if fence.preferred_edge_route:
                # Other UIDs sharing a namespace cannot be detached until
                # each individual selector+REJECT+blackhole is proved.
                self._check(scope,require_units_off=True)
                self.host.remove_exact_owned_next_hop(p.spec,fence)
                self._check(scope,require_units_off=True)
        self._check(scope,require_units_off=True,require_detached=True)
        self.host.remove_exact_dedicated_transport(p.spec)
        self._check(scope,require_units_off=True,require_detached=True,
                    require_retired=True)

    async def verify(self,scope: ExecutionScope) -> bool:
        if not self._used:
            raise EdgeRetireHold("NO_RETIRE_APPLY")
        self._check(scope,require_units_off=True,require_detached=True,
                    require_retired=True)
        return True

    async def freeze_or_hold(self,scope: ExecutionScope) -> None:
        if not self._touched or self.host is None or scope!=self.plan.scope:
            return
        # Re-fence only exact previously authorized UIDs; never clear rules
        # or add a broad iptables policy impacting other Core customers.
        self.host.reaffirm_uid_fences(
            self.plan.spec,self.plan.snapshot.owned_uid_fences,
        )
        current=self.host.inspect(self.plan.spec)
        _assert_kernel_identity(
            self.plan.spec,current,baseline=self.plan.snapshot.owned_uid_fences,
        )
