"""Phase-2 wiring for the existing M42/Single/cohort engine.

No alternate execution journal. The root process measures facts, binds one
ticket to the observed ingress and previous F2 generation, and delegates to
the original guarded P3 executor. Every cohort entry remains a Single.
"""
from __future__ import annotations

from dataclasses import asdict,replace
from hashlib import sha256
import json

from edge_egress_k2_m42_bindings import RootM42Bindings,M42BindingHold
from edge_egress_k2_migration_inventory import select_migration
from edge_egress_p3_executor import (
    FreshEvidence,BASE_GATES,ATTACH_GATES,SOURCE_ENROLL_GATES,_scope_digest,
)
from edge_egress_uid_runtime_store import read_binding

CORE_OPERATIONS_ENABLED=False


class CoreOperationalBindings(RootM42Bindings):
    def __init__(self,*,observations,**kwargs):
        super().__init__(**kwargs)
        self.observations=observations
        self._ticket_initial={}

    def review(self,selected):
        if not CORE_OPERATIONS_ENABLED:
            raise M42BindingHold('CORE_OPERATIONS_NOT_RELEASED')
        if len(selected.usernames)<=10:
            self.observations.pre(selected)
            result=super().review(selected)
            digest=getattr(self.observations,'target_digest','')
            if not result.target_f4_accepted:
                from edge_egress_k2_core_observer import CorePhysicalObservations
                if type(self.observations) is not CorePhysicalObservations or len(digest)!=64:
                    return result
                result=replace(result,global_issues=tuple(
                    x for x in result.global_issues if x!='TARGET_F4_NOT_ACCEPTED'),
                    target_qualification_digest=digest,
                    fingerprint=sha256((result.fingerprint+digest).encode()).hexdigest())
            return result
        parts=[]
        chosen={}
        for start in range(0,len(selected.usernames),10):
            sub=select_migration('BATCH',selected.usernames[start:start+10],selected.target_edge_id)
            part=self.review(sub)
            parts.append(part)
            chosen.update((a.username,a) for a in part.accounts if a.selected)
        first=parts[0]
        accounts=tuple(replace(a,selected=True,issues=chosen[a.username].issues,
            source_edge_id=chosen[a.username].source_edge_id,
            source_ipv4=chosen[a.username].source_ipv4,
            source_proven=chosen[a.username].source_proven,
            active_sessions=chosen[a.username].active_sessions)
            if a.username in chosen else a for a in first.accounts)
        return replace(first,selection=selected,selected_total=len(selected.usernames),
            accounts=accounts,
            global_issues=tuple(dict.fromkeys(x for p in parts for x in p.global_issues)),
            fingerprint=sha256(json.dumps([p.fingerprint for p in parts]).encode()).hexdigest(),
            target_f4_accepted=all(p.target_f4_accepted for p in parts),
            target_qualification_digest=first.target_qualification_digest)

    def physical_f4(self,plan):
        try:
            current=self.review(plan.selection)
            from edge_egress_k2_m3_waves import build_wave_plan
            return current.target_accepted and build_wave_plan(current).digest==plan.digest
        except (ValueError,OSError,TypeError):
            return False

    def _initial(self,scope):
        with self.ports.db_conn() as db:
            row=read_binding(db,scope.username)
        return asdict(row) if row is not None else None

    def fresh_p3_evidence(self,scope,*,expected_ticket=None):
        self._gate()
        inventory=self.review(select_migration('SINGLE',(scope.username,),scope.edge_id))
        accounts=[a for a in inventory.accounts if a.selected]
        if len(accounts)!=1:
            raise M42BindingHold('CORE_OPERATION_EXACT_ACCOUNT_REQUIRED')
        a=accounts[0]
        current=self._initial(scope)
        expected=(self._ticket_initial.get(expected_ticket.nonce)
                  if expected_ticket is not None else None)
        initial=expected['runtime'] if expected is not None else current
        postcommit=expected_ticket is not None and self._post_commit_under_current_6g(scope,expected_ticket)
        allowed=('TARGET_ALREADY_PROTECTED',) if postcommit else ()
        if (not CORE_OPERATIONS_ENABLED or self.mode()!='0'
            or any(x!='SHARED_6G_BUSY' for x in inventory.global_issues)
            or not inventory.target_accepted or a.uid!=scope.uid
            or a.username!=scope.username or not a.source_proven
            or a.source_ipv4!=scope.source_host or a.active_sessions!=0
            or a.issues!=allowed
            or inventory.target_ipv4!=scope.target_host
            or (current!=initial and not postcommit)
            or (initial is not None and initial['state']!='PROTECTED')
            or (postcommit and current['edge_id']!=scope.edge_id)):
            raise M42BindingHold('CORE_OPERATION_SOURCE_OR_F2_CHANGED')
        identity=dict(scope=_scope_digest(scope),source_edge=a.source_edge_id,
                      source_ipv4=a.source_ipv4,uid=a.uid,runtime=initial,
                      qualification=self.observations.qualification_sha256,
                      release=self.observations.release_sha)
        if expected is not None and identity!=expected:
            raise M42BindingHold('CORE_OPERATION_TICKET_IDENTITY_CHANGED')
        return FreshEvidence(
            digest=sha256(json.dumps(identity,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
            checked_at=self.ports.now(),gates=BASE_GATES|ATTACH_GATES|
            (SOURCE_ENROLL_GATES if scope.action=='UID_ENROLL_SOURCE' else frozenset()))

    def issue_ticket(self,scope,actor,chat):
        ticket=super().issue_ticket(scope,actor,chat)
        inventory=self.review(select_migration('SINGLE',(scope.username,),scope.edge_id))
        a=next(a for a in inventory.accounts if a.selected)
        self._ticket_initial[ticket.nonce]=dict(
            scope=_scope_digest(scope),source_edge=a.source_edge_id,source_ipv4=a.source_ipv4,
            uid=a.uid,runtime=self._initial(scope),
            qualification=self.observations.qualification_sha256,
            release=self.observations.release_sha)
        # No changed snapshot can be registered against a just-issued ticket.
        check=self.fresh_p3_evidence(scope,expected_ticket=ticket)
        if check.digest!=ticket.evidence_digest:
            self._ticket_initial.pop(ticket.nonce,None)
            self._outstanding.pop(ticket.nonce,None)
            raise M42BindingHold('CORE_OPERATION_CHANGED_DURING_TICKET_ISSUE')
        return ticket

    def _prune_expired_one_shot_tickets(self):
        super()._prune_expired_one_shot_tickets()
        for nonce in tuple(self._ticket_initial):
            if nonce not in self._outstanding:
                self._ticket_initial.pop(nonce)

    async def execute_single(self,scope,ticket,actor,chat):
        try:
            if ticket.nonce not in self._ticket_initial:
                raise M42BindingHold('CORE_OPERATION_TICKET_NOT_ISSUED')
            self.observations.uid_intent=(scope,ticket)
            return await super().execute_single(scope,ticket,actor,chat)
        finally:
            self.observations.uid_intent=None
            self._ticket_initial.pop(ticket.nonce,None)


class CoreOperationalHostFactory:
    """Route NEW to the original bootstrap and existing PROTECTED to repin."""
    def __init__(self,*,new_factory,host,observations):
        self.new_factory,self.host,self.observations=new_factory,host,observations
        self.read_root_snapshot=new_factory.read_root_snapshot

    def __call__(self,scope,ticket,review):
        if not CORE_OPERATIONS_ENABLED:
            raise M42BindingHold('CORE_OPERATIONS_NOT_RELEASED')
        with self.new_factory.db_conn() as db:
            old=read_binding(db,scope.username)
        if old is None:
            return self.new_factory(scope,ticket,review)
        from edge_egress_k2_core_reassignment import CoreReassignmentPort
        return CoreReassignmentPort(scope=scope,ticket=ticket,db_conn=self.new_factory.db_conn,
                                    host=self.host,observations=self.observations)


def eligible_cohort(db_conn,edge_id,*,review):
    """Freeze explicit usernames once; never discover more during execution.

    Invalid/busy/offline/unproven/already-target users are reported as skips.
    A failed *executing* user still stops the cohort; it is never a skip.
    """
    from edge_egress_k2_core_observer import CoreObservationHold
    with db_conn() as db:
        names=tuple(r[0] for r in db.execute(
            "SELECT username FROM ssh_accounts WHERE service_type='ssh' "
            "AND status LIKE '%فعال%' AND status NOT LIKE '%غیر%' ORDER BY username"))
    if not names or len(names)>10000:
        raise M42BindingHold('CORE_ALL_COHORT_EMPTY_OR_OVERSIZED')
    eligible=[];skipped=[]
    for name in names:
        try:
            inv=review(select_migration('SINGLE',(name,),edge_id))
            a=next(a for a in inv.accounts if a.selected)
            if inv.global_issues:
                # A destination/global failure cannot be hidden by skipping
                # the whole population and returning an empty success.
                raise M42BindingHold('CORE_ALL_DESTINATION_OR_GLOBAL_HOLD')
            if a.issues:
                skipped.append((name,a.issues[0]))
            else:
                eligible.append(name)
        except M42BindingHold:
            raise
        except CoreObservationHold as exc:
            code=str(exc)
            if code in ('SELECTED_USER_HAS_ACTIVE_SESSIONS','SOURCE_PROBE_SESSION_NOT_DRAINED'):
                skipped.append((name,'ACTIVE_SESSIONS_PRESENT'))
            elif (code.startswith(('SOURCE_PROBE_','CLIENT_PROBE_','EXTERNAL_CLIENT_',
                                    'CLIENT_MEASUREMENT_','PUBLIC_RELAY_CLIENT_'))):
                skipped.append((name,'SOURCE_OR_SESSION_UNVERIFIED'))
            else:
                raise M42BindingHold('CORE_ALL_DESTINATION_OR_GLOBAL_HOLD') from exc
        except (ValueError,OSError,KeyError,StopIteration):
            skipped.append((name,'SOURCE_OR_SESSION_UNVERIFIED'))
    selection=(select_migration('BATCH',tuple(eligible),edge_id) if eligible else None)
    return selection,tuple(skipped)
