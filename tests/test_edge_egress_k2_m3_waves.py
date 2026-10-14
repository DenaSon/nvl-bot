"""K2 M3 unified Single/Batch waves; all host ports synthetic and disabled."""
from __future__ import annotations

import asyncio
from dataclasses import replace
from hashlib import sha256
import json
import sqlite3
import unittest
from unittest.mock import patch

from edge_egress_k2_migration_inventory import (
    LiveIngressWitness, select_migration,
)
from edge_egress_k2_m3_waves import (
    MAX_WAVE_SIZE, M3_WAVE_EXECUTION_ENABLED, MigrationWaveHold,
    build_wave_plan, split_wave_plan, sign_wave_approval,
    verify_wave_approval, run_migration_wave,
)
from edge_egress_k2_m3_journal import confirm_original_6g_commit
from edge_egress_p3_executor import (
    ExecutionScope, ExecutionTicket, ExecutionReceipt, _scope_digest,
)
from tests.test_edge_egress_k2_migration_inventory import (
    K2M1InventoryTests, NOW, SOURCE, TARGET,
)

SECRET=b"test-only-hmac-key-not-for-production-"+b"0"*32


class M3WaveTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.fx=K2M1InventoryTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.now=NOW
        self.scopes=[]
        self.receipts=[]
        self.tickets=[]
        self.verify_calls=[]

    def inventory(self,names=("nvl0555",),mode="SINGLE",**opts):
        return self.fx.preview(names,mode,**opts)

    def plan(self,names=("nvl0555",),mode="SINGLE",size=10,**opts):
        return build_wave_plan(self.inventory(names,mode,**opts),
                               wave_size=size)

    def approval(self,plan,**kwargs):
        args=dict(actor_id=1001,chat_id=-55,expires_at=NOW+180,
                  secret=SECRET,now=NOW,operator_authorized=True)
        args.update(kwargs)
        return sign_wave_approval(plan,**args)

    def dispatcher(self,fail_name=None,fail_commit=None,
                   stale_name=None,**overrides):
        count=[0]
        def preview(sel):
            self.verify_calls.append(sel.usernames[0])
            if sel.usernames[0]==stale_name:
                return self.fx.preview(sel.usernames,sel.mode,
                   os_uid=lambda n:9999)
            return self.fx.preview(sel.usernames,sel.mode)
        def ticket(scope,actor,chat):
            count[0]+=1
            self.scopes.append(scope)
            t=ExecutionTicket(actor,chat,format(count[0],"032x"),
                              NOW+60,_scope_digest(scope),"a"*64)
            self.tickets.append(t)
            return t
        async def run(scope,t,actor,chat):
            if scope.username==fail_name:
                return ExecutionReceipt(False,"HOLD_RECONCILIATION_REQUIRED",
                                        90+count[0],manual_recovery=True)
            self.receipts.append(scope.username)
            return ExecutionReceipt(True,"SUCCEEDED",90+count[0])
        def committed(scope,t,op):
            return scope.username!=fail_commit
        return dict(fresh_inventory=preview,issue_single_ticket=ticket,
                    execute_single=run,committed_6g=committed,
                    **overrides)

    async def execute(self,plan,**kwargs):
        args=dict(actor_id=1001,chat_id=-55,approval_secret=SECRET,
                  release_enabled=True,geteuid=lambda:0,
                  clock=lambda:NOW)
        args.update(self.dispatcher(**kwargs))
        with patch("edge_egress_k2_m3_waves.M3_WAVE_EXECUTION_ENABLED",
                   True):
            return await run_migration_wave(plan,self.approval(plan),**args)

    def test_single_and_batch_share_exact_member_contract(self):
        s=self.plan()
        b=self.plan(("nvl0555","nvl0557"),"BATCH")
        self.assertFalse(M3_WAVE_EXECUTION_ENABLED)
        self.assertFalse(s.can_execute)
        self.assertFalse(b.can_execute)
        self.assertEqual(s.members[0],b.members[0])
        self.assertEqual(b.ready_count,2)
        self.assertEqual(len(b.waves),1)
        self.assertEqual([m.username for m in b.members],
                         ["nvl0555","nvl0557"])

    async def test_single_uses_existing_guarded_p3_not_a_parallel_route(self):
        plan=self.plan()
        res=await self.execute(plan)
        self.assertEqual(res.completed,1)
        self.assertTrue(res.all_verified)
        self.assertFalse(res.halted)
        self.assertEqual([s.action for s in self.scopes],["UID_ATTACH"])
        self.assertEqual(self.scopes[0].source_host,SOURCE)
        self.assertEqual(self.scopes[0].target_host,TARGET)
        self.assertEqual(res.progress[0].operation_id,91)

    async def test_batch_uses_distinct_ticket_and_scope_per_uid(self):
        plan=self.plan(("nvl0555","nvl0557"),"BATCH")
        res=await self.execute(plan)
        self.assertTrue(res.all_verified)
        self.assertEqual(res.completed,2)
        self.assertEqual(len(set(t.nonce for t in self.tickets)),2)
        self.assertEqual([s.username for s in self.scopes],
                         ["nvl0555","nvl0557"])
        self.assertEqual([p.operation_id for p in res.progress],[91,92])

    async def test_failed_second_uid_halts_before_any_later_account(self):
        plan=self.plan(("nvl0555","nvl0557","pool_user"),"BATCH")
        res=await self.execute(plan,fail_name="nvl0557")
        self.assertTrue(res.halted)
        self.assertEqual(res.completed,1)
        self.assertEqual([p.status for p in res.progress],
                         ["VERIFIED","HOLD","DEFERRED"])
        self.assertEqual(self.receipts,["nvl0555"])
        self.assertEqual(self.verify_calls,["nvl0555","nvl0557"])

    async def test_missing_durable_6g_commit_is_not_a_success(self):
        plan=self.plan(("nvl0555","nvl0557"),"BATCH")
        res=await self.execute(plan,fail_commit="nvl0555")
        self.assertEqual(res.completed,0)
        self.assertTrue(res.halted)
        self.assertEqual(res.progress[0].status,"HOLD")
        self.assertEqual(res.progress[1].status,"DEFERRED")
        self.assertEqual(self.receipts,["nvl0555"])

    async def test_source_uid_drift_halts_before_ticket(self):
        plan=self.plan(("nvl0555","nvl0557"),"BATCH")
        res=await self.execute(plan,stale_name="nvl0555")
        self.assertEqual(res.completed,0)
        self.assertEqual(self.scopes,[])
        self.assertEqual(res.halt_reason,"M3_UID_OR_F4_EVIDENCE_CHANGED")

    async def test_legacy_already_on_target_uses_source_enroll_action(self):
        witness=lambda n:LiveIngressWitness(n,"e9",TARGET,NOW-2,
                                             "INDEPENDENT_LIVE")
        plan=self.plan(ingress_witness=witness)
        self.assertTrue(plan.members[0].selectable)
        count=[0]
        args=self.dispatcher()
        args["fresh_inventory"]=lambda sel:self.fx.preview(
            sel.usernames,sel.mode,ingress_witness=witness)
        args.update(dict(actor_id=1001,chat_id=-55,
                         approval_secret=SECRET,release_enabled=True,
                         geteuid=lambda:0,clock=lambda:NOW))
        with patch("edge_egress_k2_m3_waves.M3_WAVE_EXECUTION_ENABLED",True):
            result=await run_migration_wave(
                plan,self.approval(plan),**args)
        self.assertTrue(result.all_verified)
        self.assertEqual(self.scopes[0].action,"UID_ENROLL_SOURCE")
        self.assertEqual(self.scopes[0].source_host,TARGET)

    async def test_not_executable_without_root_flag_and_auth(self):
        plan=self.plan()
        args=self.dispatcher()
        args.update(dict(actor_id=1001,chat_id=-55,
                         approval_secret=SECRET,release_enabled=True,
                         geteuid=lambda:0,clock=lambda:NOW))
        with self.assertRaisesRegex(MigrationWaveHold,"NOT_RELEASED"):
            await run_migration_wave(plan,self.approval(plan),**args)
        with patch("edge_egress_k2_m3_waves.M3_WAVE_EXECUTION_ENABLED",True):
            with self.assertRaisesRegex(MigrationWaveHold,"NOT_RELEASED"):
                await run_migration_wave(
                    plan,self.approval(plan),**dict(args,geteuid=lambda:1000))
        self.assertEqual(self.scopes,[])

    def test_approval_denied_unless_explicit_admin_and_valid_hmac(self):
        plan=self.plan()
        with self.assertRaises(MigrationWaveHold):
            self.approval(plan,operator_authorized=False)
        with self.assertRaises(MigrationWaveHold):
            self.approval(plan,secret=b"tiny")
        a=self.approval(plan)
        verify_wave_approval(plan,a,actor_id=1001,chat_id=-55,
                             secret=SECRET,now=NOW)
        for changed in (
            dict(actor_id=1111,chat_id=-55),
            dict(actor_id=1001,chat_id=-56),
            dict(actor_id=1001,chat_id=-55,now=NOW+181),
        ):
            with self.subTest(changed=changed),self.assertRaises(MigrationWaveHold):
                verify_wave_approval(plan,a,secret=SECRET,now=NOW,**changed)

    def test_forged_member_with_stale_digest_fails_integrity(self):
        plan=self.plan()
        tampered=replace(plan,members=(replace(plan.members[0],uid=1988),))
        with self.assertRaisesRegex(MigrationWaveHold,"IMMUTABILITY"):
            self.approval(tampered)

    async def test_global_and_per_uid_blockers_cannot_silently_migrate(self):
        self.fx.c.execute("UPDATE edge_egress_readiness SET state='STAGED'")
        plan=self.plan(("nvl0555","nvl0557"),"BATCH")
        self.assertEqual(plan.ready_count,0)
        result=await self.execute(plan)
        self.assertTrue(result.halted)
        self.assertEqual(self.scopes,[])
        self.assertEqual(result.completed,0)

    async def test_busy_session_blocks_whole_wave_with_per_uid_hold(self):
        plan=self.plan(("nvl0555","nvl0557"),"BATCH",
            session_count=lambda n,u:1 if n=="nvl0557" else 0)
        result=await self.execute(plan)
        self.assertEqual(self.scopes,[])
        self.assertEqual([p.status for p in result.progress],
                         ["DEFERRED","HOLD"])

    async def test_large_batch_must_be_split_and_approved_per_wave(self):
        new_names=[f"wave{i:03d}" for i in range(15)]
        self.fx.c.executemany(
            "INSERT INTO ssh_accounts VALUES(?,?,'ssh','🟢 فعال')",
            [(n,SOURCE) for n in new_names])
        self.fx.uids.update({n:3000+i for i,n in enumerate(new_names)})
        plan=self.plan(tuple(new_names),"BATCH",size=6)
        self.assertEqual([len(w.members) for w in split_wave_plan(plan)],
                         [6,6,3])
        self.assertTrue(all(w.digest!=plan.digest
                            for w in split_wave_plan(plan)))
        with self.assertRaisesRegex(MigrationWaveHold,"EXPLICIT_SUBWAVE"):
            await self.execute(plan)
        first=split_wave_plan(plan)[0]
        result=await self.execute(first)
        self.assertEqual(result.completed,6)
        self.assertEqual(self.receipts,new_names[:6])

    async def test_cancel_is_not_swallowed_and_does_not_advance(self):
        plan=self.plan(("nvl0555","nvl0557"),"BATCH")
        args=self.dispatcher()
        async def cancel(scope,t,a,c):
            raise asyncio.CancelledError
        args["execute_single"]=cancel
        args.update(dict(actor_id=1001,chat_id=-55,
                         approval_secret=SECRET,release_enabled=True,
                         geteuid=lambda:0,clock=lambda:NOW))
        with patch("edge_egress_k2_m3_waves.M3_WAVE_EXECUTION_ENABLED",True):
            with self.assertRaises(asyncio.CancelledError):
                await run_migration_wave(plan,self.approval(plan),**args)
        self.assertEqual([s.username for s in self.scopes],["nvl0555"])


class M3Original6GJournalTests(unittest.TestCase):
    def setUp(self):
        self.c=sqlite3.connect(":memory:")
        self.addCleanup(self.c.close)
        self.c.execute(
            "CREATE TABLE failover_operations("
            "id INTEGER,status TEXT,source_host TEXT,target_host TEXT,"
            "detail_json TEXT)")
        self.scope=ExecutionScope(
            "UID_ATTACH","e9",SOURCE,TARGET,username="nvl0555",uid=1636)
        self.ticket=ExecutionTicket(1,-4,"b"*32,NOW+60,
                                    _scope_digest(self.scope),"a"*64)
        self.detail={
            "kind":"K2_P3A","phase":"EGRESS_P3_VERIFIED",
            "action":self.scope.action,"edge_id":"e9",
            "scope_digest":_scope_digest(self.scope),
            "nonce_hash":sha256(self.ticket.nonce.encode()).hexdigest(),
        }
        self.insert(1,"SUCCEEDED",self.detail)

    def insert(self,n,status,detail,source=SOURCE,target=TARGET):
        self.c.execute("INSERT INTO failover_operations VALUES(?,?,?,?,?)",
                       (n,status,source,target,json.dumps(detail)))

    def check(self,scope=None,ticket=None,op=1):
        return confirm_original_6g_commit(
            lambda:self.c,scope or self.scope,ticket or self.ticket,op)

    def test_exact_original_succeeded_receipt_is_accepted(self):
        self.assertTrue(self.check())

    def test_running_or_recovery_hold_rejected(self):
        self.insert(2,"RUNNING",{"kind":"K2_P3A","phase":"EGRESS_P3_RECOVERY_REQUIRED"})
        self.assertFalse(self.check())
        self.c.execute("DELETE FROM failover_operations WHERE id=2")
        self.c.execute("UPDATE failover_operations SET status='RUNNING' WHERE id=1")
        self.assertFalse(self.check())

    def test_forged_terminal_phase_identity_nonce_or_source_rejected(self):
        for key,val in (
            ("phase","EGRESS_P3_EXECUTE_INTENT"),
            ("kind","K2_FAKE"),
            ("action","UID_FREEZE"),
            ("edge_id","e8"),
            ("scope_digest","c"*64),
            ("nonce_hash","c"*64),
        ):
            with self.subTest(key=key):
                d=dict(self.detail,**{key:val})
                self.c.execute("UPDATE failover_operations SET detail_json=?",
                               (json.dumps(d),))
                self.assertFalse(self.check())
        self.c.execute("UPDATE failover_operations SET detail_json=?",
                       (json.dumps(self.detail),))
        self.c.execute("UPDATE failover_operations SET target_host=?",
                       ("172.86.111.69",))
        self.assertFalse(self.check())

    def test_missing_duplicate_or_wrong_operation_id_rejected(self):
        self.assertFalse(self.check(op=2))
        self.insert(1,"SUCCEEDED",self.detail)
        self.assertFalse(self.check())
        self.c.execute("DELETE FROM failover_operations")
        self.assertFalse(self.check())

    def test_corrupt_journal_does_not_create_success(self):
        self.c.execute("UPDATE failover_operations SET detail_json='{'")
        self.assertFalse(self.check())

if __name__=="__main__":
    unittest.main()
