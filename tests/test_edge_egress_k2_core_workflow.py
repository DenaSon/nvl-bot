"""Native cohort/direct-bot integration with ORIGINAL SQLite/P3/6G receipts.

Only physical host/packet I/O is synthetic. No VPS or live Telegram access.
"""
import asyncio
from dataclasses import replace
import json
from types import SimpleNamespace
import threading
import unittest
from unittest.mock import patch

import edge_egress_k2_root_direct as direct
from edge_egress_k2_core_reassignment import CoreReassignmentPort
from edge_egress_k2_core_recovery import reconcile_settled_cohorts
from edge_egress_k2_m4_checkpoint import DurableWaveCheckpoint
from edge_egress_k2_migration_inventory import select_migration
from edge_egress_p3_executor import assert_guarded_6g_intent
from edge_egress_uid_policy import UIDPolicyRequest
from edge_egress_uid_runtime_store import read_binding
from ops.edge_egress_provision import EgressSpec
from tests.test_edge_egress_k2_core_operations import CoreFixture,SOURCE,TARGET


class NativeCohortWorkflowTests(CoreFixture):
    def setUp(self):
        super().setUp()
        self.executed=[]
        self.fail_name=None
        self.stop_after=None
        self.tick=0
        self.root.ports=replace(self.root.ports,port_factory=self.port)
        cp=DurableWaveCheckpoint(db_conn=self.db,geteuid=lambda:0,
            clock=lambda:self.now,release_enabled=True)
        self.portal=self.root.portal(checkpoint=cp)
        self.client=direct.RootDirectOperatorClient(portal=self.portal,geteuid=lambda:0,released=True)
        for flag in ('K2_ROOT_DIRECT_ENABLED','K2_ROOT_DIRECT_BATCH_ENABLED'):
            setting=patch.object(direct,flag,True);setting.start();self.addCleanup(setting.stop)
        with self.db() as db:
            db.execute('UPDATE edge_egress_readiness SET expires_at=?',(self.now+90000,))
        self.root.observations._qualification=lambda ip:None

    def port(self,scope,ticket,review):
        port=CoreReassignmentPort.__new__(CoreReassignmentPort)
        port.scope,port.ticket,port.db_conn=scope,ticket,self.db
        port.release_enabled=True;port.bootstrap=None;port._started=False;port._touched=False
        port.host=SimpleNamespace(os_uid=lambda n:self.names[n],pre=lambda s:None,idle=lambda n,u:True)
        with self.db() as db:port.old=read_binding(db,scope.username)
        spec=EgressSpec('e9',TARGET,'209.200.246.198','10.78.90.0/30','10.78.91.0/30','eth0',51890,20009)
        port.req=UIDPolicyRequest(spec,scope.username,scope.uid,port.old.priority)
        port.old_manifest=SimpleNamespace(request=replace(port.req,spec=replace(spec,
            edge_id='s8',edge_public_ipv4=SOURCE)))
        def others():
            with self.db() as db:
                return db.execute('SELECT * FROM edge_egress_uid_runtime WHERE username<>? ORDER BY username',
                                  (scope.username,)).fetchall()
        port._others=others;port.before_others=others()
        async def repin(*args):
            self.executed.append(scope.username)
            if self.fail_name==scope.username:
                raise ValueError('synthetic physical failure')
        def post(current,approval,*,phase):
            assert_guarded_6g_intent(self.db,current,approval)
            with self.db() as db:row=read_binding(db,current.username)
            self.assertEqual(row.state,'ROUTED_UNVERIFIED' if phase=='UID_ROUTE' else 'PROTECTED')
            if phase=='POST_ATTACH':
                self.now+=self.tick
                if self.stop_after==scope.username:
                    self.client._stop=True
        port.driver=SimpleNamespace(kernel=SimpleNamespace(freeze=lambda req:None,
            assert_frozen=lambda req:None,attach=lambda req:None),repin_frozen_uid=repin)
        port.observations=SimpleNamespace(post=post)
        port._stage_policy=lambda row:None
        return port

    def cohort(self,count=3):
        names=tuple(self.names)
        if count!=3:
            names=tuple('cohort'+str(i).zfill(3) for i in range(count))
            with self.db() as db:
                for i,name in enumerate(names):
                    self.names[name]=2000+i
                    db.execute("INSERT INTO ssh_accounts VALUES(?,?,'ssh','فعال')",(name,SOURCE))
        for name in names:
            self.protect(name,op=1000+self.names[name])
            with self.db() as db:
                db.execute("INSERT INTO failover_operations(id,source_host,target_host,status,detail_json) "
                    "VALUES(?,?,?,'SUCCEEDED',?)",(1000+self.names[name],TARGET,SOURCE,
                        json.dumps(dict(kind='K2_P3A',phase='EGRESS_P3_VERIFIED',
                            username=name,uid=self.names[name],edge_id='s8'))))
        with self.db() as db:
            self.before_hosts=db.execute('SELECT username,host FROM ssh_accounts ORDER BY username').fetchall()
        return select_migration('BATCH',names,'e9')

    async def run_selection(self,selected,**kwargs):
        reply=await self.client.request('PREPARE',actor_id=11,chat_id=11,selection=selected,**kwargs)
        return await self.client.request('CONFIRM',actor_id=11,chat_id=11,request_id=reply['request_id'])

    def test_23_users_run_once_with_per_uid_original_receipts_after_approval_ttl(self):
        selected=self.cohort(23);self.tick=45
        result=asyncio.run(self.run_selection(selected))
        self.assertEqual(result['state'],'COMPLETED')
        self.assertEqual(result['completed'],23)
        self.assertEqual(self.executed,list(selected.usernames))
        with self.db() as db:
            rows=db.execute('SELECT id,status,detail_json FROM failover_operations WHERE target_host=? ORDER BY id',
                            (TARGET,)).fetchall()
            self.assertEqual(len(rows),23)
            self.assertTrue(all(r[1]=='SUCCEEDED' for r in rows))
            self.assertEqual([json.loads(r[2])['username'] for r in rows],list(selected.usernames))
            state,progress=db.execute('SELECT state,progress_json FROM k2_m4_wave_checkpoints').fetchone()
            self.assertEqual(state,'SUCCEEDED');self.assertEqual(len(json.loads(progress)),23)
            self.assertEqual(db.execute('SELECT username,host FROM ssh_accounts ORDER BY username').fetchall(),self.before_hosts)

    def test_error_stops_at_failed_uid_and_cannot_reconcile_original_running_lease(self):
        selected=self.cohort();self.fail_name=selected.usernames[1]
        result=asyncio.run(self.run_selection(selected))
        self.assertEqual(result['state'],'HOLD')
        self.assertEqual([r['state'] for r in result['accounts']],['VERIFIED','HOLD','DEFERRED'])
        self.assertEqual(self.executed,list(selected.usernames[:2]))
        with self.assertRaisesRegex(ValueError,'ORIGINAL_6G_STILL_RUNNING'):
            reconcile_settled_cohorts(self.root,selected,actor_id=11,chat_id=11)
        with self.db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM failover_operations WHERE status='RUNNING'").fetchone(),(1,))

    def test_operator_stop_keeps_verified_receipt_and_settled_reconciliation_allows_fresh_plan(self):
        selected=self.cohort();self.stop_after=selected.usernames[0]
        result=asyncio.run(self.run_selection(selected))
        self.assertEqual(result['state'],'HOLD')
        self.assertEqual(result['completed'],1)
        self.assertEqual(self.executed,[selected.usernames[0]])
        # Source/guard inspection is physical I/O only; real journal and all
        # checkpoint/recovery SQL remain in use.
        with patch('edge_egress_v1_admission.load_roster',return_value={
            n:SimpleNamespace(uid=self.names[n]) for n in selected.usernames}),\
             patch('edge_egress_v1_admission.checked_guard',side_effect=lambda m:SimpleNamespace(
                 request=SimpleNamespace(spec=SimpleNamespace(edge_id='e9' if m.uid==1636 else 's8',
                     edge_public_ipv4=TARGET if m.uid==1636 else SOURCE)))),\
             patch('edge_egress_uid_boot.BootGuardApplier.verify'):
            result=reconcile_settled_cohorts(self.root,selected,actor_id=11,chat_id=11)
            self.assertEqual(result,{'state':'RECONCILED','closed':1,'replayed':False})
        remaining=select_migration('BATCH',selected.usernames[1:],'e9')
        self.stop_after=None
        self.assertEqual(asyncio.run(self.run_selection(remaining))['completed'],2)
        with self.db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM failover_operations WHERE status='RUNNING'").fetchone(),(0,))

    def test_repeated_task_cancellation_keeps_single_flight_until_host_work_finishes(self):
        async def scenario():
            entered=threading.Event();release=threading.Event()
            def work():
                entered.set();release.wait(3);return 'settled'
            task=asyncio.create_task(self.client._host_task(work))
            while not entered.is_set():await asyncio.sleep(.005)
            task.cancel();await asyncio.sleep(.01)
            task.cancel();await asyncio.sleep(.01)
            self.assertFalse(task.done())
            self.assertTrue(self.client._stop)
            release.set()
            with self.assertRaises(asyncio.CancelledError):await task
        asyncio.run(scenario())

    def relay_inspection(self):
        roster={n:SimpleNamespace(username=n,uid=uid) for n,uid in self.names.items()}
        def guard(member):
            with self.db() as db:row=read_binding(db,member.username)
            return SimpleNamespace(request=SimpleNamespace(spec=SimpleNamespace(
                edge_id=row.edge_id,edge_public_ipv4=row.edge_ipv4)))
        for setting in (
            patch('edge_egress_v1_admission.load_roster',return_value=roster),
            patch('edge_egress_v1_admission.checked_guard',side_effect=guard),
            patch('edge_egress_uid_boot.BootGuardApplier.verify'),
            patch('edge_egress_k2_p1_worker.load_stage_pin',return_value=SimpleNamespace(
                edge_id='e9',core_ipv4='209.200.246.198',edge_ipv4=TARGET)),
            patch('edge_egress_k2_p1_worker.probe_phase1',return_value={'observed_ipv4':TARGET}),
        ):
            setting.start();self.addCleanup(setting.stop)

    def test_active_relay_requires_complete_receipts_and_handles_already_target_without_replaying_users(self):
        selected=self.cohort()
        self.assertEqual(asyncio.run(self.run_selection(selected))['completed'],3)
        self.relay_inspection()
        async def scenario():
            inv=await self.client.request('ALL',actor_id=11,chat_id=11,edge_id='e9',activate_relay=True)
            self.assertIsNone(inv['selection'])
            reply=await self.client.request('PREPARE',actor_id=11,chat_id=11,
                selection=selected,activate_relay=True)
            with self.db() as db:
                self.assertIsNone(db.execute("SELECT value FROM settings WHERE key='k2_active_egress_edge'").fetchone())
            result=await self.client.request('CONFIRM',actor_id=11,chat_id=11,request_id=reply['request_id'])
            self.assertEqual(result['relay_state'],'VERIFIED')
            self.assertEqual(result['completed'],0)
        asyncio.run(scenario())
        self.assertEqual(self.executed,list(selected.usernames))
        with self.db() as db:
            self.assertEqual(db.execute("SELECT value FROM settings WHERE key='k2_active_egress_edge'").fetchone(),('e9',))
            self.assertEqual(db.execute("SELECT COUNT(*) FROM failover_operations WHERE target_host=?",(TARGET,)).fetchone(),(4,))

    def test_active_relay_cannot_commit_after_user_generation_changes_since_confirmation(self):
        selected=self.cohort()
        asyncio.run(self.run_selection(selected));self.relay_inspection()
        async def scenario():
            reply=await self.client.request('PREPARE',actor_id=11,chat_id=11,
                selection=selected,activate_relay=True)
            with self.db() as db:db.execute('UPDATE edge_egress_uid_runtime SET generation=generation+1')
            with self.assertRaisesRegex(ValueError,'USERS_CHANGED'):
                await self.client.request('CONFIRM',actor_id=11,chat_id=11,request_id=reply['request_id'])
        asyncio.run(scenario())
        with self.db() as db:
            self.assertIsNone(db.execute("SELECT value FROM settings WHERE key='k2_active_egress_edge'").fetchone())

    def test_revoked_admin_cannot_inventory_or_prepare_a_cohort(self):
        selected=self.cohort()
        self.root.ports=replace(self.root.ports,live_admin_role=lambda a,c:False)
        async def scenario():
            for action,kwargs in (('ALL',{'edge_id':'e9'}),('PREPARE',{'selection':selected})):
                with self.assertRaisesRegex(ValueError,'SUPERADMIN'):
                    await self.client.request(action,actor_id=11,chat_id=11,**kwargs)
        asyncio.run(scenario())
        self.assertEqual(self.executed,[])


if __name__=='__main__':unittest.main()
