"""Phase-2 integration with real SQLite/P3/6G/checkpoint and fake host I/O.

No real SSH, packet, PAM or VPS acceptance is claimed by these fixtures.
"""
import asyncio
from contextlib import contextmanager
from dataclasses import asdict,replace
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch,Mock

from edge_egress_k2_core_operations import CoreOperationalBindings,eligible_cohort
from edge_egress_k2_m42_bindings import HostReviewedPorts,RootAdminPolicy
from edge_egress_k2_m42_evidence import SignedExternalEvidence,WitnessAccount,PRE_ATTACH_CHECKS
from edge_egress_k2_migration_inventory import select_migration,LiveIngressWitness,preview_migration
from edge_egress_k2_m3_waves import build_wave_plan,run_migration_wave,sign_wave_approval
from edge_egress_k2_m4_checkpoint import DurableWaveCheckpoint,install_checkpoint_schema
from edge_egress_k2_m4_root_portal import RootMigrationPortal
from edge_egress_k2_a_6g_shared import Original6GRootCallbacks
from edge_egress_p3_executor import (
    ExecutionScope,ExecutionTicket,ExecutionReceipt,FreshEvidence,BASE_GATES,ATTACH_GATES,
    Existing6GGuardedExecutor,_scope_digest,assert_guarded_6g_intent,INTENT_PHASE,
)
from edge_egress_uid_runtime_store import install_runtime_schema,read_binding
from edge_egress_k2_core_reassignment import CoreReassignmentPort
from edge_egress_uid_boot import BootGuardManifest
from edge_egress_uid_policy import UIDPolicyRequest
from ops.edge_egress_provision import EgressSpec
from tests import test_edge_egress_k2_migration_inventory as inv_fixture
NOW,SOURCE,TARGET=inv_fixture.NOW,inv_fixture.SOURCE,inv_fixture.TARGET

SECRET=b'phase2-tests-only-'+b'x'*48


class CoreFixture(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'original-core.sqlite'
        self.db=self.db  # Stable function identity, as in production startup.
        fixture=inv_fixture.K2M1InventoryTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        with self.db() as db: fixture.c.backup(db)
        self.names={'nvl0555':1636,'nvl0557':1644,'pool_user':1666}
        self.now=NOW
        with self.db() as db:
            db.executescript('''
                DROP TABLE failover_operations;
                CREATE TABLE failover_operations(id INTEGER PRIMARY KEY AUTOINCREMENT,
                mode TEXT,source_host TEXT,target_host TEXT,status TEXT,
                started_at TEXT,updated_at TEXT,finished_at TEXT,detail_json TEXT);
                DROP TABLE edge_egress_uid_runtime;
                CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
                INSERT INTO settings VALUES('edge_egress_protected_mode','0');
            ''')
            install_runtime_schema(db);install_checkpoint_schema(db)
        self.callbacks=Original6GRootCallbacks(self.db)
        self.observations=SimpleNamespace(qualification_sha256='a'*64,release_sha='b'*40)
        def pre(selected):
            self.observations.proof=SignedExternalEvidence('f'*64,self.now,self.now+30,'e9',TARGET,
                PRE_ATTACH_CHECKS,tuple(WitnessAccount(n,self.names[n],'s8',SOURCE,0)
                                       for n in selected.usernames),phase='PRE_ATTACH')
            return self.observations.proof
        self.observations.pre=pre
        self.observations.current=lambda:self.observations.proof
        ports=HostReviewedPorts(db_conn=self.db,acquire_6g=self.callbacks.acquire,
            journal_6g=self.callbacks.journal,port_factory=lambda *a:None,
            live_admin_role=lambda a,c:(a,c)==(11,11),protected_mode=lambda:'0',
            external_evidence=self.observations.current,
            ingress_provider=lambda **kw:lambda n:LiveIngressWitness(n,'s8',SOURCE,self.now,'INDEPENDENT_LIVE'),
            os_uid=lambda n:self.names[n],now=lambda:self.now,geteuid=lambda:0)
        self.root=CoreOperationalBindings(ports=ports,root_secret=SECRET,
            admin_policy=RootAdminPolicy(frozenset(((11,11),))),reviewed_release=True,
            observations=self.observations)
        for flag in (
            'edge_egress_k2_core_operations.CORE_OPERATIONS_ENABLED',
            'edge_egress_k2_m42_bindings.M42_LIVE_BINDINGS_ENABLED',
            'edge_egress_k2_migration_inventory.M1_INDEPENDENT_EGRESS_ENABLED',
            'edge_egress_k2_m3_waves.M3_COHORT_OPERATIONS_ENABLED',
            'edge_egress_k2_m3_waves.M3_WAVE_EXECUTION_ENABLED',
            'edge_egress_k2_m3_waves.M3_CROSS_EDGE_LEGACY_SINGLE_ENABLED',
            'edge_egress_k2_m4_checkpoint.M4_CHECKPOINT_RELEASE_ENABLED',
            'edge_egress_k2_m4_root_portal.M4_ROOT_PORTAL_ENABLED',
            'edge_egress_k2_core_reassignment.CORE_REASSIGNMENT_ENABLED',
            'edge_egress_p3_executor.P3_CROSS_EDGE_LEGACY_UID_ATTACH_ENABLED',
            'edge_egress_p3_executor.P3_UID_POST_COMMIT_PROBE_ENABLED',
        ):
            p=patch(flag,True);p.start();self.addCleanup(p.stop)

    @contextmanager
    def db(self):
        db=sqlite3.connect(self.path)
        try:
            with db: yield db
        finally: db.close()

    def protect(self,name='nvl0555',edge='s8',ip=SOURCE,generation=3,op=10):
        uid=self.names[name]
        with self.db() as db:
            db.execute('INSERT INTO edge_egress_uid_runtime '
                '(username,uid,edge_id,edge_ipv4,route_table,priority,dns_port,state,generation,last_operation_id) '
                "VALUES(?,?,?,?,?,?,?,'PROTECTED',?,?)",
                (name,uid,edge,ip,20008,10000+uid,40000+uid,generation,op))
            db.execute("INSERT INTO edge_egress_uid_bindings VALUES(?,?,?,?,'PROTECTED')",
                       (name,uid,edge,ip))


class NativeEvidenceTests(CoreFixture):
    def test_new_ticket_rechecks_identity_but_allows_fresh_measurement_time(self):
        scope=ExecutionScope('UID_ATTACH','e9',SOURCE,TARGET,'nvl0555',1636)
        ticket=self.root.issue_ticket(scope,11,11)
        self.now+=10
        fresh=self.root.fresh_p3_evidence(scope,expected_ticket=ticket)
        self.assertEqual(fresh.digest,ticket.evidence_digest)
        self.assertEqual(fresh.checked_at,self.now)

    def test_already_protected_cross_ingress_is_eligible_for_reassignment(self):
        self.protect(edge='s8')
        with self.db() as db:
            db.execute("UPDATE edge_egress_uid_runtime SET edge_id='e9',edge_ipv4=?",(TARGET,))
            db.execute("UPDATE edge_egress_uid_bindings SET edge_id='e9',edge_ipv4=?",(TARGET,))
        # On a third target the independent inbound source remains s8.
        with self.db() as db:
            db.execute("INSERT INTO edge_egress_allocations VALUES('x3','216.126.229.12','STAGED',20003)")
            db.execute("INSERT INTO edge_egress_readiness VALUES('x3','216.126.229.12','READY','216.126.229.12','F4_PRODUCTION_ACCEPTANCE',?,?,2,7)",
                       (NOW-1,NOW+300))
        sel=select_migration('SINGLE',('nvl0555',),'x3')
        inv=preview_migration(self.db,sel,os_uid=lambda n:self.names[n],
            ingress_witness=lambda n:LiveIngressWitness(n,'s8',SOURCE,NOW,'INDEPENDENT_LIVE'),
            session_count=lambda n,u:0,now=NOW)
        self.assertEqual(next(a for a in inv.accounts if a.selected).issues,())
        self.assertTrue(build_wave_plan(inv).members[0].selectable)

    def test_f2_generation_drift_invalidates_an_issued_ticket(self):
        self.protect()
        scope=ExecutionScope('UID_ATTACH','e9',SOURCE,TARGET,'nvl0555',1636)
        ticket=self.root.issue_ticket(scope,11,11)
        with self.db() as db:
            db.execute("UPDATE edge_egress_uid_runtime SET generation=generation+1")
        with self.assertRaises(ValueError):
            self.root.fresh_p3_evidence(scope,expected_ticket=ticket)

    def test_postcommit_matches_original_nonce_and_keeps_same_ticket_digest(self):
        self.protect()
        scope=ExecutionScope('UID_ATTACH','e9',SOURCE,TARGET,'nvl0555',1636)
        ticket=self.root.issue_ticket(scope,11,11)
        op,_=self.callbacks.acquire(SOURCE,TARGET)
        self.callbacks.journal(op,status='RUNNING',finished=False,require_running=True,
            detail={'kind':'K2_P3A','phase':INTENT_PHASE,'action':'UID_ATTACH','edge_id':'e9',
                'scope_digest':_scope_digest(scope),'nonce_hash':sha256(ticket.nonce.encode()).hexdigest()})
        with self.db() as db:
            db.execute("UPDATE edge_egress_uid_runtime SET edge_id='e9',edge_ipv4=?,generation=6,last_operation_id=?",
                       (TARGET,op))
            db.execute("UPDATE edge_egress_uid_bindings SET edge_id='e9',edge_ipv4=?",(TARGET,))
        fresh=self.root.fresh_p3_evidence(scope,expected_ticket=ticket)
        self.assertEqual(fresh.digest,ticket.evidence_digest)
        with self.assertRaises(ValueError): self.root.fresh_p3_evidence(scope)

    def test_all_freezes_eligible_names_and_reports_each_skip(self):
        self.protect(edge='e9',ip=TARGET)
        selected,skipped=eligible_cohort(self.db,'e9',review=self.root.review)
        self.assertEqual(selected.usernames,('nvl0557','pool_user'))
        self.assertEqual(skipped,(('nvl0555','TARGET_ALREADY_PROTECTED'),))
        with self.db() as db:
            db.execute("INSERT INTO ssh_accounts VALUES('new_user',?,'ssh','فعال')",(SOURCE,))
        self.assertNotIn('new_user',selected.usernames)

    def test_global_target_failure_cannot_become_an_all_skipped_success(self):
        with self.db() as db: db.execute("UPDATE edge_egress_readiness SET state='HOLD'")
        with self.assertRaisesRegex(ValueError,'GLOBAL_HOLD'):
            eligible_cohort(self.db,'e9',review=self.root.review)

    def test_broad_cohort_inventory_binds_every_selected_user(self):
        names=[]
        with self.db() as db:
            for i in range(23):
                name='batch'+str(i);names.append(name);self.names[name]=2000+i
                db.execute("INSERT INTO ssh_accounts VALUES(?,?,'ssh','فعال')",(name,SOURCE))
        inventory=self.root.review(select_migration('BATCH',tuple(names),'e9'))
        plan=build_wave_plan(inventory)
        self.assertEqual(len(plan.members),23)
        self.assertEqual([len(w) for w in plan.waves],[10,10,3])
        self.assertEqual(plan.blocked,())


class ReassignmentTransactionTests(CoreFixture):
    def port(self,fail=False):
        self.protect()
        self.scope=ExecutionScope('UID_ATTACH','e9',SOURCE,TARGET,'nvl0555',1636)
        self.ticket=self.root.issue_ticket(self.scope,11,11)
        # Build the exact typed port with a fake physical driver only. The
        # original P3 journal and the port's real F2 CAS are exercised below.
        p=CoreReassignmentPort.__new__(CoreReassignmentPort)
        p.scope,p.ticket,p.db_conn=self.scope,self.ticket,self.db
        p.release_enabled=True;p.bootstrap=None;p._started=False;p._touched=False
        p.host=SimpleNamespace(os_uid=lambda n:self.names[n],pre=lambda s:None,idle=lambda n,u:True)
        with self.db() as db:p.old=read_binding(db,'nvl0555')
        spec=EgressSpec('e9',TARGET,'209.200.246.198','10.78.90.0/30','10.78.91.0/30','eth0',51890,20009)
        p.req=UIDPolicyRequest(spec,'nvl0555',1636,p.old.priority)
        p.old_manifest=BootGuardManifest(replace(p.req,spec=replace(spec,edge_id='s8',edge_public_ipv4=SOURCE)),
            'PROTECTED_BOOT_GUARD',p.old.dns_port,ingress_return=True,shared_edge=True)
        p.before_others=((),[],[])
        p._others=lambda:p.before_others
        self.events=[]
        def freeze(req):self.events.append('deny')
        async def repin(*a):
            self.events.append('repin')
            if fail:raise RuntimeError('synthetic physical failure')
        def post(scope,ticket,*,phase):
            assert_guarded_6g_intent(self.db,scope,ticket)
            with self.db() as db:row=read_binding(db,scope.username)
            self.assertEqual(row.state,'ROUTED_UNVERIFIED' if phase=='UID_ROUTE' else 'PROTECTED')
            self.events.append(phase)
        p.driver=SimpleNamespace(kernel=SimpleNamespace(freeze=freeze,assert_frozen=lambda r:None,
            attach=lambda r:self.events.append('attach')),repin_frozen_uid=repin)
        p.observations=SimpleNamespace(post=post)
        p._stage_policy=lambda row:self.events.append('policy:'+str(row.generation+1))
        return p

    def execute(self,p):
        executor=Existing6GGuardedExecutor(db_conn=self.db,acquire_fn=self.callbacks.acquire,
            journal_fn=self.callbacks.journal,review_fn=lambda s:self.root.fresh_p3_evidence(s,expected_ticket=self.ticket),
            host_port=p,release_enabled=True,geteuid=lambda:0,clock=lambda:self.now)
        return asyncio.run(executor.execute(self.scope,self.ticket,actor_id=11,chat_id=11))

    def test_reassignment_uses_original_6g_and_preserves_account_host(self):
        p=self.port()
        result=self.execute(p)
        self.assertTrue(result.allowed)
        self.assertEqual(self.events,['deny','repin','attach','UID_ROUTE','policy:6','POST_ATTACH'])
        with self.db() as db:
            row=read_binding(db,'nvl0555')
            self.assertEqual((row.edge_id,row.state,row.generation),('e9','PROTECTED',6))
            self.assertEqual(db.execute('SELECT host FROM ssh_accounts WHERE username=?',('nvl0555',)).fetchone(),
                             ('104.194.144.195',))
            self.assertEqual(db.execute('SELECT status FROM failover_operations').fetchall(),[('SUCCEEDED',)])

    def test_partial_repin_stays_denied_and_original_6g_running(self):
        p=self.port(fail=True)
        result=self.execute(p)
        self.assertFalse(result.allowed)
        with self.db() as db:
            self.assertEqual(read_binding(db,'nvl0555').state,'HOLD')
            state,raw=db.execute('SELECT status,detail_json FROM failover_operations').fetchone()
        self.assertEqual(state,'RUNNING')
        self.assertEqual(json.loads(raw)['phase'],'EGRESS_P3_RECOVERY_REQUIRED')
        self.assertNotIn('attach',self.events)
        self.assertEqual(self.events[-1],'deny')

    def test_binding_cas_drift_is_not_overwritten(self):
        p=self.port()
        with self.db() as db:db.execute('UPDATE edge_egress_uid_runtime SET generation=99')
        with self.assertRaises(ValueError): self.execute(p)
        self.assertEqual(self.events,[])


if __name__=='__main__': unittest.main()
