"""Existing Edge wizard/relay controls into the same root/P3/6G engine.

Active *egress* is distinct from inbound hostname/DNS selection. Accounts
stay on Core. The marker is committed only when every active account has a
verified target F2 binding; an eligible subset can never claim ALL switched.
"""
from __future__ import annotations

from hashlib import sha256
from dataclasses import dataclass
import json

from edge_egress_p3_executor import (
    ExecutionScope,FreshEvidence,BASE_GATES,Existing6GGuardedExecutor,
    issue_execution_ticket,assert_guarded_6g_intent,
)


ACTIVE_EGRESS_SETTING='k2_active_egress_edge'


class CoreEdgeHold(ValueError):
    pass


@dataclass(frozen=True)
class PreparedActiveEgress:
    scope: object
    ticket: object
    identity: tuple
    expires_at: int


def prepare_edge(root,edge_id,*,actor_id,chat_id):
    if not root.admin(actor_id,chat_id):
        raise CoreEdgeHold('EDGE_CURRENT_ADMIN_REQUIRED')
    root.mode()
    from edge_egress_k2_p1_worker import (
        load_stage_pin,activate_phase1,register_stage_allocation,_check_lease,
        _remote_transport,STAGE_ROOT,
    )
    pin=load_stage_pin(edge_id)
    root.observations._qualification(pin.core_ipv4)
    with root.ports.db_conn() as db:
        rows=db.execute('SELECT edge_public_ipv4,status FROM edge_egress_allocations WHERE edge_id=?',
                        (edge_id,)).fetchall()
    if rows and rows!=[(pin.edge_ipv4,'STAGED')]:
        raise CoreEdgeHold('EDGE_ALLOCATION_NEEDS_RECONCILIATION')
    def journal(op,*,status,detail,finished=False,require_running=True):
        return root.ports.journal_6g(op,status=status,detail=detail,
            finished=finished,require_running=require_running)
    def register(db_conn,op,source,current,spec,peer):
        def locked():return _check_lease(db_conn,op,source,pin.edge_ipv4,pin=pin)
        locked()
        if not rows:
            register_stage_allocation(db_conn,op,source,current,spec,peer)
        else:
            with db_conn() as db:
                identity=db.execute('SELECT edge_public_ipv4,core_public_ipv4,route_table,status,'
                    'tunnel_network,veth_network FROM edge_egress_allocations WHERE edge_id=?',
                    (edge_id,)).fetchall()
            if identity!=[(pin.edge_ipv4,pin.core_ipv4,spec.route_table,'STAGED',
                           spec.tunnel_network,spec.veth_network)]:
                raise CoreEdgeHold('EDGE_EXISTING_ALLOCATION_IDENTITY_DRIFT')
        from edge_egress_k2_core_prerequisites import CoreUIDSnapshotSource,stage_core_modules
        from ops.edge_egress_v1_transport import install_persistence
        snapshot=root.ports.port_factory.read_root_snapshot
        if type(snapshot) is not CoreUIDSnapshotSource:
            raise CoreEdgeHold('EDGE_PINNED_CORE_MODULE_SOURCE_REQUIRED')
        stage_core_modules(snapshot.blobs,snapshot.pins,snapshot.bundle_digest,locked)
        install_persistence(STAGE_ROOT/('core-'+edge_id),'core',pin.core_sha,guard=locked)
        locked()
        if _remote_transport(pin,'persist')!='TRANSPORT_PERSISTENCE_VERIFIED':
            raise CoreEdgeHold('EDGE_TRANSPORT_BOOT_PERSISTENCE_REQUIRED')
        locked()
    return activate_phase1(edge_id,db_conn=root.ports.db_conn,
        acquire=root.ports.acquire_6g,journal=journal,register_f3=register)


class _ActiveEgressPort:
    def __init__(self,root,scope,ticket,identity):
        self.root,self.scope,self.ticket=root,scope,ticket
        self.identity=identity
        self.changed=False

    def _locked(self,scope):
        if scope!=self.scope:
            raise CoreEdgeHold('ACTIVE_EGRESS_SCOPE_CHANGED')
        return assert_guarded_6g_intent(self.root.ports.db_conn,scope,self.ticket)

    def inspect(self):
        from edge_egress_v1_admission import load_roster,checked_guard
        from edge_egress_uid_boot import BootGuardApplier
        with self.root.ports.db_conn() as db:
            accounts=db.execute("SELECT username FROM ssh_accounts WHERE service_type='ssh' "
                "AND status LIKE '%فعال%' AND status NOT LIKE '%غیر%' ORDER BY username").fetchall()
            rows=db.execute('SELECT username,uid,edge_id,edge_ipv4,state,generation,last_operation_id '
                'FROM edge_egress_uid_runtime ORDER BY username').fetchall()
            mappings=db.execute('SELECT username,uid,edge_id,edge_ipv4,status '
                'FROM edge_egress_uid_bindings ORDER BY username').fetchall()
            active=db.execute('SELECT value FROM settings WHERE key=?',(ACTIVE_EGRESS_SETTING,)).fetchall()
        if (not accounts or len(rows)!=len(accounts) or len(mappings)!=len(accounts)
            or tuple(x[0] for x in rows)!=tuple(x[0] for x in accounts)):
            raise CoreEdgeHold('ACTIVE_EGRESS_INCOMPLETE_COHORT')
        roster=load_roster()
        for row,mapped in zip(rows,mappings):
            name,uid,edge,ip,state,generation,op=row
            if (edge!=self.scope.edge_id or ip!=self.scope.target_host
                or state!='PROTECTED' or mapped!=(name,uid,edge,ip,state)
                or self.root.ports.os_uid(name)!=uid):
                raise CoreEdgeHold('ACTIVE_EGRESS_SOME_USERS_NOT_VERIFIED_ON_TARGET')
            member=roster.get(name)
            if member is None or member.uid!=uid:
                raise CoreEdgeHold('ACTIVE_EGRESS_ROSTER_UNVERIFIED')
            man=checked_guard(member)
            if man.request.spec.edge_id!=edge:
                raise CoreEdgeHold('ACTIVE_EGRESS_GUARD_TARGET_CHANGED')
            BootGuardApplier().verify(man)
            with self.root.ports.db_conn() as db:
                receipt=db.execute('SELECT status,detail_json FROM failover_operations WHERE id=?',
                                   (op,)).fetchone()
            try:
                detail=json.loads(receipt[1])
                valid=(receipt[0]=='SUCCEEDED' and detail.get('kind')=='K2_P3A'
                       and detail.get('phase')=='EGRESS_P3_VERIFIED'
                       and detail.get('username')==name and detail.get('uid')==uid
                       and detail.get('edge_id')==edge)
            except (ValueError,TypeError,IndexError):
                valid=False
            if not valid:
                raise CoreEdgeHold('ACTIVE_EGRESS_ORIGINAL_UID_RECEIPT_MISSING')
        return accounts,rows,mappings,active

    async def apply(self,scope):
        self._locked(scope)
        observed=self.inspect()
        if observed!=self.identity:
            raise CoreEdgeHold('ACTIVE_EGRESS_COHORT_CHANGED')
        with self.root.ports.db_conn() as db:
            db.execute('BEGIN IMMEDIATE')
            old=db.execute('SELECT value FROM settings WHERE key=?',(ACTIVE_EGRESS_SETTING,)).fetchall()
            if old!=self.identity[3]:
                raise CoreEdgeHold('ACTIVE_EGRESS_SETTING_CAS_LOST')
            db.execute('INSERT INTO settings(key,value) VALUES(?,?) '
                       'ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                       (ACTIVE_EGRESS_SETTING,scope.edge_id))
        self.changed=True
        self._locked(scope)

    async def verify(self,scope):
        self._locked(scope)
        current=self.inspect()
        return current[:3]==self.identity[:3] and current[3]==[(scope.edge_id,)]

    async def freeze_or_hold(self,scope):
        self._locked(scope)
        # This operation changes only an egress selection marker. Verified
        # per-UID guards remain in place; never unroute an entire cohort.


def prepare_active_egress(root,edge_id,*,actor_id,chat_id):
    if not root.admin(actor_id,chat_id):
        raise CoreEdgeHold('ACTIVE_EGRESS_CURRENT_ADMIN_REQUIRED')
    root.mode()
    from edge_egress_k2_p1_worker import load_stage_pin,probe_phase1
    pin=load_stage_pin(edge_id)
    root.observations._qualification(pin.core_ipv4)
    probe_phase1(edge_id,db_conn=root.ports.db_conn)
    # Core IP here identifies a control transaction, never a fallback route.
    scope=ExecutionScope('EDGE_PREPARE',edge_id,pin.core_ipv4,pin.edge_ipv4)
    probe=_ActiveEgressPort(root,scope,None,None)
    identity=probe.inspect()
    evidence=_relay_evidence(root,scope,probe,identity)
    ticket=issue_execution_ticket(scope,evidence(scope),actor_id=actor_id,chat_id=chat_id,
                                  now=root.ports.now())
    return PreparedActiveEgress(scope,ticket,identity,root.ports.now()+90)


def _relay_evidence(root,scope,probe,identity):
    def evidence(current):
        if current!=scope:
            raise CoreEdgeHold('ACTIVE_EGRESS_SCOPE_DRIFT')
        state=probe.inspect()
        # The final read may differ only in the guarded marker itself.
        if state[:3]!=identity[:3] or (not probe.changed and state[3]!=identity[3]):
            raise CoreEdgeHold('ACTIVE_EGRESS_USERS_CHANGED')
        return FreshEvidence(sha256(json.dumps(identity[:3],sort_keys=True).encode()).hexdigest(),
                             root.ports.now(),BASE_GATES)
    return evidence


async def execute_active_egress(root,prepared,*,actor_id,chat_id):
    if (not root.admin(actor_id,chat_id) or type(prepared) is not PreparedActiveEgress
        or prepared.expires_at<=root.ports.now()):
        raise CoreEdgeHold('ACTIVE_EGRESS_CONFIRMATION_EXPIRED_OR_FOREIGN')
    scope,ticket,identity=prepared.scope,prepared.ticket,prepared.identity
    probe=_ActiveEgressPort(root,scope,ticket,identity)
    evidence=_relay_evidence(root,scope,probe,identity)
    executor=Existing6GGuardedExecutor(db_conn=root.ports.db_conn,
        acquire_fn=root.ports.acquire_6g,journal_fn=root.ports.journal_6g,
        review_fn=evidence,host_port=probe,release_enabled=True,
        geteuid=root.ports.geteuid,clock=root.ports.now)
    return await executor.execute(scope,ticket,actor_id=actor_id,chat_id=chat_id)


async def select_active_egress(root,edge_id,*,actor_id,chat_id):
    prepared=prepare_active_egress(root,edge_id,actor_id=actor_id,chat_id=chat_id)
    return await execute_active_egress(root,prepared,actor_id=actor_id,chat_id=chat_id)
