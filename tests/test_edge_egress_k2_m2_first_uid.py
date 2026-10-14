"""M2 first-UID root bootstrap wrapper: original 6G shared before each write."""
from __future__ import annotations
import unittest
from unittest.mock import patch

from edge_egress_p3_executor import ExecutionScope, ExecutionTicket,_scope_digest
from ops.k2_m2_first_uid import (
    FirstUIDHold, Original6GRootPort, guarded_first_uid_bootstrap,
    M2_FIRST_UID_ENABLED,
)
from tests.test_edge_egress_k2_p3_guard_installer import GuardInstallerTests,FakePort


class M2FirstUIDTests(unittest.TestCase):
    def setUp(self):
        self.fx=GuardInstallerTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.plan=self.fx.plan()
        self.port=FakePort()
        source=self.fx.fx.request.spec.edge_public_ipv4
        self.scope=ExecutionScope("UID_ENROLL_SOURCE","src1",source,source,
                                  username="nvl0557",uid=1644)
        self.ticket=ExecutionTicket(15,15,"a"*32,99999999,
                                     _scope_digest(self.scope),"b"*64)
        self.locks=[]
    def call(self,**kw):
        params=dict(plan=self.plan,scope=self.scope,ticket=self.ticket,
            current_pam=self.fx.pam,db_conn=lambda:None,
            os_uid=self.fx.fx.lookup,port=self.port,
            independent_rescue_ok=lambda:True,
            independent_f4_ok=lambda scope:True,
            mixed_legacy_pam_ok=lambda:True,
            account_idle_ok=lambda username,uid:True,
            sshd_effective_probe=lambda:"usepam yes\n",
            release_enabled=True,geteuid=lambda:0)
        params.update(kw)
        return guarded_first_uid_bootstrap(**params)

    def test_off_by_default_without_original_6g(self):
        self.assertFalse(M2_FIRST_UID_ENABLED)
        with self.assertRaisesRegex(FirstUIDHold,"RELEASE_NOT_ATTESTED"):
            self.call()
        self.assertEqual(self.port.actions,[])

    def test_unauthorized_or_wrong_target_rejects_before_write(self):
        with patch("ops.k2_m2_first_uid.M2_FIRST_UID_ENABLED",True):
            for props in (dict(independent_rescue_ok=lambda:False),
                          dict(independent_f4_ok=lambda _:False),
                          dict(mixed_legacy_pam_ok=lambda:False),
                          dict(account_idle_ok=lambda n,u:False),
                          dict(geteuid=lambda:1000),
                          dict(os_uid=lambda _:5555)):
                with self.subTest(props=props),self.assertRaises(FirstUIDHold):
                    self.call(**props)
            self.assertEqual(self.port.actions,[])

    def test_current_plan_and_ticket_are_pinned_to_same_uid(self):
        with patch("ops.k2_m2_first_uid.M2_FIRST_UID_ENABLED",True):
            bad=ExecutionScope("UID_ENROLL_SOURCE","src1",
                self.scope.source_host,self.scope.target_host,
                username="nvl0555",uid=1636)
            with self.assertRaisesRegex(FirstUIDHold,"IDENTITY_DRIFT"):
                self.call(scope=bad)

    def test_every_first_uid_root_write_checks_existing_6g(self):
        def locked(*args):
            self.locks.append("6G")
            return 23
        def fake_apply(**args):
            port=args["port"]
            self.assertEqual(args["current_pam"],self.fx.pam)
            port.create("/etc/nvl-egress/test","bytes")
            port.command("systemctl","daemon-reload")
            port.replace_exact("/etc/pam.d/sshd",b"a",b"b")
            self.assertTrue(args["release_enabled"])
        with patch("ops.k2_m2_first_uid.M2_FIRST_UID_ENABLED",True), \
             patch("ops.k2_m2_first_uid.assert_guarded_6g_intent",
                   side_effect=locked), \
             patch("ops.k2_m2_first_uid.apply_guard_install",
                   side_effect=fake_apply):
            self.call()
        self.assertEqual(len(self.locks),5)
        self.assertEqual(len(self.port.actions),3)

    def test_forward_resume_from_pinned_partial_stage(self):
        from pathlib import Path
        from ops.k2_p3_guard_installer import PAM, UNITS
        from edge_egress_v1_admission import GUARD_DIR, ROSTER
        from ops.k2_m2_first_uid import resume_first_uid_bootstrap
        pinned={str(ROSTER):self.plan.roster_bytes}
        current=[self.fx.pam]
        plan=self.plan
        class PersistPort(FakePort):
            def create(self,path,data):
                super().create(path,data)
                pinned[str(path)]=data
            def replace_exact(self,path,before,after):
                super().replace_exact(path,before,after)
                current[0]=after
        port=PersistPort()
        args=dict(plan=plan,scope=self.scope,ticket=self.ticket,
            current_pam=self.fx.pam,db_conn=lambda:None,
            os_uid=self.fx.fx.lookup,port=port,
            rescue_ok=lambda:True,f4_ok=lambda scope:True,
            mixed_legacy_ok=lambda:True,
            idle_ok=lambda n,u:True,sshd_effective=lambda:"usepam yes\\n",
            guard_frozen_ok=lambda m:True,dns_ipv6_ok=lambda m:True,
            release_enabled=True,geteuid=lambda:0)
        from ops.k2_p3_guard_installer import PAM as GLOBAL_PAM
        import ops.k2_p3_guard_installer as installer
        orig_exists=Path.exists
        with patch("ops.k2_m2_first_uid.M2_FIRST_UID_ENABLED",True), \\
             patch("ops.k2_m2_first_uid.assert_guarded_6g_intent",
                   side_effect=lambda *x:self.locks.append("6G")), \\
             patch("ops.k2_p3_guard_installer._owned"), \\
             patch("ops.k2_p3_guard_installer._safe_read",
                   side_effect=lambda path,**kw:(
                       current[0] if path==GLOBAL_PAM else pinned[str(path)])), \\
             patch("edge_egress_f4_pam.verify_installed_gate_digest",
                   return_value=True), \\
             patch("edge_egress_v1_admission.inspect_pam",
                   return_value=True), \\
             patch("ops.k2_m2_first_uid.Path.exists",
                   new=lambda path:str(path) in pinned):
            resume_first_uid_bootstrap(**args)
        self.assertEqual(current[0],plan.pam_after)
        self.assertEqual(len([a for a in port.actions if a[0]=="create"]),4)
        self.assertEqual(port.actions[-1][0],"pam")
        self.assertTrue(self.locks)

    def test_first_uid_recovery_inspects_every_partial_stage(self):
        from ops.k2_m2_guard_recovery import inspect_first_uid_stage
        plan=self.plan
        staged={
            "roster":plan.roster_bytes,
            "guard":None,"pam_backup":None,
            "guard_unit":None,"dns_unit":None,
        }
        state=inspect_first_uid_stage(
            plan=plan,pinned_pam_before=self.fx.pam,
            current_pam=self.fx.pam,staged=staged,
            original_6g_running=True)
        self.assertTrue(state.may_request_replay)
        self.assertFalse(state.customer_ready)
        self.assertEqual(state.state,"PARTIALLY_STAGED")
        self.assertEqual(inspect_first_uid_stage(
            plan=plan,pinned_pam_before=self.fx.pam,
            current_pam=self.fx.pam,staged=staged,
            original_6g_running=False).state,"HOLD")
        self.assertEqual(inspect_first_uid_stage(
            plan=plan,pinned_pam_before=self.fx.pam,
            current_pam=b"unknown",staged=staged,
            original_6g_running=True).reason,"PAM_CONTENT_UNTRUSTED")

    def test_6g_lost_mid_first_bootstrap_prevents_later_pam(self):
        calls=[0]
        def locked(*args):
            calls[0]+=1
            if calls[0]==3:
                raise FirstUIDHold("LEASE_LOST")
        def fake_apply(**args):
            p=args["port"]
            p.create("new-guard",b"guard")
            p.replace_exact("pam",b"pre",b"post")
        with patch("ops.k2_m2_first_uid.M2_FIRST_UID_ENABLED",True), \
             patch("ops.k2_m2_first_uid.assert_guarded_6g_intent",
                   side_effect=locked), \
             patch("ops.k2_m2_first_uid.apply_guard_install",
                   side_effect=fake_apply):
            with self.assertRaisesRegex(FirstUIDHold,"LEASE_LOST"):
                self.call()
        self.assertEqual([x[0] for x in self.port.actions],["create"])

if __name__=="__main__":
    unittest.main()
