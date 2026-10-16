"""Protected UID relocation inside the original P3/F2/6G transaction.

Reuse the existing deny-first manifest/roster/DNS repin implementation.
Ingress remains independently observed; it is never replaced by old egress
or ssh_accounts.host. No global relay, account or DNS-provider mutation.
"""
from __future__ import annotations

from dataclasses import asdict
from hashlib import sha256
import json

from edge_egress_p3_executor import assert_guarded_6g_intent
from edge_egress_k2_m4_bootstrap import DeferredOriginal6GHostPort
from edge_egress_uid_runtime_store import read_binding
from edge_egress_uid_policy import UIDPolicyRequest
from edge_egress_v1_admission import load_roster, checked_guard
from edge_egress_v1_live_driver import ProtectedLiveHostActions, LiveDriverConfig

CORE_REASSIGNMENT_ENABLED = False


class ReassignmentHold(ValueError):
    pass


class _ScopedRepin(ProtectedLiveHostActions):
    """Only lease binding changes; original reviewed repin commands are reused."""
    def _lease(self):
        return assert_guarded_6g_intent(self.db_conn, self.scope, self.ticket)


class CoreReassignmentPort(DeferredOriginal6GHostPort):
    """Typed original-P3 host port; the P3 executor remains the sole executor."""

    def __init__(self, *, scope, ticket, db_conn, host, observations):
        from edge_egress_k2_p1_worker import load_stage_pin, _check_stage, STAGE_ROOT
        from edge_egress_k2_phase2_operator import _Phase1Remote
        self.scope,self.ticket,self.db_conn=scope,ticket,db_conn
        self.host,self.observations=host,observations
        self.release_enabled=True
        self._started=False
        self._touched=False
        self._port=None
        self.bootstrap=None
        self.pin=load_stage_pin(scope.edge_id)
        spec,_,_= _check_stage(self.pin)
        roster=load_roster()
        member=roster.get(scope.username)
        if member is None or member.uid!=scope.uid:
            raise ReassignmentHold("REASSIGNMENT_ROSTER_IDENTITY_MISSING")
        self.old_manifest=checked_guard(member)
        self.req=UIDPolicyRequest(spec,scope.username,scope.uid,
                                  self.old_manifest.request.priority)
        self.req.validate()
        with db_conn() as db:
            self.old=read_binding(db,scope.username)
            mapping=db.execute(
                "SELECT uid,edge_id,edge_ipv4,status FROM edge_egress_uid_bindings "
                "WHERE username=?",(scope.username,),
            ).fetchone()
        old=self.old
        if (old is None or old.state!="PROTECTED" or old.uid!=scope.uid
            or old.edge_id==scope.edge_id or old.edge_ipv4==scope.target_host
            or mapping!=(old.uid,old.edge_id,old.edge_ipv4,"PROTECTED")
            or self.old_manifest.request.spec.edge_id!=old.edge_id
            or self.old_manifest.request.spec.edge_public_ipv4!=old.edge_ipv4
            or self.old_manifest.request.priority!=old.priority
            or self.old_manifest.dns_port!=old.dns_port):
            raise ReassignmentHold("REASSIGNMENT_SOURCE_BINDING_CONFLICT")
        self.before_others=self._others()
        config=LiveDriverConfig(
            core_stage=STAGE_ROOT/("core-"+scope.edge_id),
            core_digest=self.pin.core_sha,edge=_Phase1Remote(self.pin),
            acceptance_enabled=True,
        )
        self.driver=_ScopedRepin(config,db_conn,lambda: {})
        self.driver.scope,self.driver.ticket=scope,ticket

    def _others(self):
        roster=load_roster()
        manifests=tuple(sorted((name,member.uid,member.guard_sha256)
                              for name,member in roster.items()
                              if name!=self.scope.username))
        with self.db_conn() as db:
            runtime=db.execute(
                "SELECT * FROM edge_egress_uid_runtime WHERE username<>? ORDER BY username",
                (self.scope.username,),
            ).fetchall()
            bindings=db.execute(
                "SELECT * FROM edge_egress_uid_bindings WHERE username<>? ORDER BY username",
                (self.scope.username,),
            ).fetchall()
        return manifests,runtime,bindings

    def _locked(self, scope):
        if (not CORE_REASSIGNMENT_ENABLED or scope!=self.scope
            or self.host.os_uid(scope.username)!=scope.uid
            or self._others()!=self.before_others):
            raise ReassignmentHold("REASSIGNMENT_IDENTITY_OR_NEIGHBOUR_DRIFT")
        return assert_guarded_6g_intent(self.db_conn,scope,self.ticket)

    def _cas(self, expected, target, *, repin=False, commit=False):
        op=self._locked(self.scope)
        with self.db_conn() as db:
            db.execute("BEGIN IMMEDIATE")
            # Assert the same original nonce while holding the SQL writer.
            rows=db.execute(
                "SELECT id FROM failover_operations WHERE status='RUNNING'"
            ).fetchall()
            if rows!=[(op,)]:
                raise ReassignmentHold("REASSIGNMENT_LEASE_CHANGED")
            row=read_binding(db,self.scope.username)
            if row!=expected:
                raise ReassignmentHold("REASSIGNMENT_F2_CAS_CHANGED")
            edge,ip,table=(self.req.spec.edge_id,self.req.spec.edge_public_ipv4,
                           self.req.spec.route_table) if repin else (
                               row.edge_id,row.edge_ipv4,row.route_table)
            changed=db.execute(
                "UPDATE edge_egress_uid_runtime SET state=?,edge_id=?,edge_ipv4=?,"
                "route_table=?,generation=generation+1,last_operation_id=?,"
                "updated_at=CURRENT_TIMESTAMP WHERE username=? AND uid=? AND generation=?",
                (target,edge,ip,table,op,row.username,row.uid,row.generation),
            ).rowcount
            if changed!=1:
                raise ReassignmentHold("REASSIGNMENT_F2_CAS_LOST")
            if commit:
                changed=db.execute(
                    "UPDATE edge_egress_uid_bindings SET edge_id=?,edge_ipv4=? "
                    "WHERE username=? AND uid=? AND edge_id=? AND edge_ipv4=? AND status='PROTECTED'",
                    (edge,ip,row.username,row.uid,self.old.edge_id,self.old.edge_ipv4),
                ).rowcount
                if changed!=1:
                    raise ReassignmentHold("REASSIGNMENT_MAPPING_CAS_LOST")
            result=read_binding(db,row.username)
        self._locked(self.scope)
        return result

    async def apply(self, scope):
        if self._started:
            raise ReassignmentHold("REASSIGNMENT_ONE_SHOT")
        self._started=True
        self._locked(scope)
        self.host.pre(scope)
        if self.host.idle(scope.username,scope.uid) is not True:
            raise ReassignmentHold("REASSIGNMENT_DISCONNECT_SELECTED_SESSIONS")
        # Persist non-admitting F2 before touching the old selector/files.
        frozen=self._cas(self.old,"FROZEN")
        self._touched=True
        self.driver.kernel.freeze(self.old_manifest.request)
        self.driver.kernel.assert_frozen(self.old_manifest.request)
        self._locked(scope)
        await self.driver.repin_frozen_uid(scope.username,scope.uid,
                                          self.old.edge_ipv4,scope.target_host)
        self._locked(scope)
        self.driver.kernel.attach(self.req)
        routed=self._cas(frozen,"ROUTED_UNVERIFIED",repin=True)
        self.observations.post(scope,self.ticket,phase="UID_ROUTE")
        self._stage_policy(routed)
        self._cas(routed,"PROTECTED",commit=True)

    def _stage_policy(self,row):
        from edge_egress_k2_uid_ingress_egress import (
            ROOT_BINDINGS,MAX_BINDING_BYTES,UIDIngressEgressBinding,
            parse_uid_ingress_egress_bindings,
        )
        from edge_egress_v1_admission import _trusted_bytes
        from edge_egress_v1_live_driver import _atomic_root
        from edge_egress_k2_m4_cross_edge_port import root_fresh_source_evidence
        from edge_egress_k2_m2_ingress_journal import _validated
        self._locked(self.scope)
        before=_trusted_bytes(ROOT_BINDINGS,MAX_BINDING_BYTES)
        records=parse_uid_ingress_egress_bindings(before)
        observed=root_fresh_source_evidence()
        source=observed(self.scope.username)
        record=_validated(observed.raw)[self.scope.username]
        if source.edge_ipv4!=self.scope.source_host or record.uid!=self.scope.uid:
            raise ReassignmentHold("REASSIGNMENT_INGRESS_CHANGED")
        roster=load_roster()
        newer=UIDIngressEgressBinding(
            self.scope.username,self.scope.uid,source.edge_id,source.edge_ipv4,
            self.scope.edge_id,self.scope.target_host,record.wg_public_key,
            row.generation+1,row.last_operation_id,roster[self.scope.username].guard_sha256,
        )
        old=records.get(self.scope.username)
        if old is not None and (old.uid!=self.old.uid
                                or old.egress_edge!=self.old.edge_id
                                or old.egress_ipv4!=self.old.edge_ipv4
                                or old.runtime_generation!=self.old.generation):
            raise ReassignmentHold("REASSIGNMENT_OLD_PAM_POLICY_CONFLICT")
        if any(x.uid==self.scope.uid and x.username!=self.scope.username
               for x in records.values()):
            raise ReassignmentHold("REASSIGNMENT_PAM_UID_DUPLICATE")
        # Same-ingress target uses ordinary F2 admission; it needs no cross
        # record, but a stale old cross record must still be removed by CAS.
        if source.edge_id==self.scope.edge_id:
            records.pop(self.scope.username,None)
        else:
            records[self.scope.username]=newer
        raw=(json.dumps({"version":2,"bindings":[asdict(records[n]) for n in sorted(records)]},
                        sort_keys=True,separators=(",",":"))+"\n").encode()
        parse_uid_ingress_egress_bindings(raw)
        if len(raw)>MAX_BINDING_BYTES or _trusted_bytes(ROOT_BINDINGS,MAX_BINDING_BYTES)!=before:
            raise ReassignmentHold("REASSIGNMENT_PAM_POLICY_CAS_LOST")
        self._locked(self.scope)
        _atomic_root(ROOT_BINDINGS,raw)
        if _trusted_bytes(ROOT_BINDINGS,MAX_BINDING_BYTES)!=raw:
            raise ReassignmentHold("REASSIGNMENT_PAM_POLICY_NOT_DURABLE")

    async def verify(self,scope):
        self._locked(scope)
        if not self._started:
            raise ReassignmentHold("REASSIGNMENT_NOT_STARTED")
        self.observations.post(scope,self.ticket,phase="POST_ATTACH")
        self._locked(scope)
        return True

    async def freeze_or_hold(self,scope):
        if (scope!=self.scope or not CORE_REASSIGNMENT_ENABLED
            or self.host.os_uid(scope.username)!=scope.uid):
            raise ReassignmentHold('REASSIGNMENT_CONTAINMENT_IDENTITY_CHANGED')
        assert_guarded_6g_intent(self.db_conn,scope,self.ticket)
        if not self._touched:
            return
        # Either manifest can be present after interrupted two-file repin.
        # UID-wide DENY is the same on both; never delete shared routes.
        self.driver.kernel.freeze(self.req)
        with self.db_conn() as db:
            row=read_binding(db,scope.username)
        if row and row.uid==scope.uid:
            self._cas(row,"HOLD")
