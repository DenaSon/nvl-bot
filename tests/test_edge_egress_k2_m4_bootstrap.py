"""M4.2 defers M2 first/Nth UID root changes until original P3/6G."""
from __future__ import annotations
import unittest
from unittest.mock import patch
import edge_egress_k2_m4_bootstrap as bs
from edge_egress_p3_executor import ExecutionScope,ExecutionTicket,_scope_digest

TARGET="45.61.163.75"


class DeferredBootTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.scope=ExecutionScope(
            "UID_ENROLL_SOURCE","e9",TARGET,TARGET,username="nvl0555",uid=1636)
        self.ticket=ExecutionTicket(
            11,-222,"a"*32,1792010200,_scope_digest(self.scope),"b"*64)
        self.operations=[]
        self.db=lambda:None

    def bootstrap(self,kind="FIRST_UID",**changes):
        kwargs=dict(scope=self.scope,ticket=self.ticket,
                    db_conn=self.db,release_enabled=True)
        kwargs.update(changes)
        return bs.GuardBootstrap(self.scope,self.ticket,kind,kwargs)

    def test_first_and_nth_call_original_m2_never_generic_executor(self):
        with patch.object(bs,"guarded_first_uid_bootstrap",side_effect=lambda **k:self.operations.append("first")),\
             patch.object(bs,"apply_next_uid",side_effect=lambda **k:self.operations.append("next")):
            self.bootstrap().run(self.scope,self.ticket)
            self.bootstrap("NEXT_UID",resume_partial=False).run(self.scope,self.ticket)
        self.assertEqual(self.operations,["first","next"])

    def test_unknown_resume_or_forged_ticket_denied(self):
        tests=(self.bootstrap("OTHER"),self.bootstrap("NEXT_UID",resume_partial=True),
               self.bootstrap(ticket=None),self.bootstrap(scope=None))
        for spec in tests:
            with self.subTest(kind=spec.kind),self.assertRaises(bs.M42BootstrapHold):
                spec.run(self.scope,self.ticket)

    async def test_cannot_stage_anything_without_original_6g(self):
        bootstrap=self.bootstrap()
        with patch.object(bs,"assert_guarded_6g_intent",side_effect=ValueError("NO_6G")),\
             patch.object(bs,"guarded_first_uid_bootstrap",side_effect=AssertionError("unsafe")):
            port=bs.DeferredOriginal6GHostPort(
                scope=self.scope,ticket=self.ticket,db_conn=self.db,
                bootstrap=bootstrap,
                port_factory=lambda *args: self.operations.append("factory"),
            )
            with self.assertRaisesRegex(ValueError,"NO_6G"):
                await port.apply(self.scope)
        self.assertEqual(self.operations,[])

    async def test_original_m2_failure_remains_hold_without_next_uid(self):
        with patch.object(bs,"assert_guarded_6g_intent",return_value=41),\
             patch.object(bs,"guarded_first_uid_bootstrap",side_effect=ValueError("PARTIAL_M2")):
            port=bs.DeferredOriginal6GHostPort(
                scope=self.scope,ticket=self.ticket,db_conn=self.db,
                bootstrap=self.bootstrap(),
                port_factory=lambda *args:self.operations.append("factory"),
            )
            with self.assertRaisesRegex(ValueError,"PARTIAL_M2"):
                await port.apply(self.scope)
            with self.assertRaises(bs.M42BootstrapHold):
                await port.freeze_or_hold(self.scope)
            with self.assertRaises(bs.M42BootstrapHold):
                await port.apply(self.scope)
        self.assertEqual(self.operations,[])

    async def test_scope_drift_denied_before_m2(self):
        forged=ExecutionScope("UID_ENROLL_SOURCE","e8",
                               "172.86.111.69","172.86.111.69",
                               username="nvl0555",uid=1636)
        with patch.object(bs,"assert_guarded_6g_intent",return_value=41):
            port=bs.DeferredOriginal6GHostPort(
                scope=self.scope,ticket=self.ticket,db_conn=self.db,
                bootstrap=self.bootstrap(),
                port_factory=lambda *args:self.operations.append("factory"),
            )
            with self.assertRaisesRegex(bs.M42BootstrapHold,"SCOPE_CHANGED"):
                await port.apply(forged)
        self.assertEqual(self.operations,[])


if __name__=="__main__":
    unittest.main()
