"""Package A root assembly and non-root live systemd identity guard.

Fixtures are synthetic. No switch from production root bot is attempted.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import edge_egress_k2_a_root_assembly as a
from edge_egress_k2_a_6g_shared import Original6GRootCallbacks
from edge_egress_k2_a_host_factory import ReviewedM2P3HostFactory
from edge_egress_k2_m42_bindings import (
    HostReviewedPorts, RootAdminPolicy,
)
from edge_egress_k2_m4_root_worker import WorkerPaths, RootWorkerHold


def paths():
    return WorkerPaths(
        source_root=Path("/srv/nvl/reviewed"),
        manifest_file=Path("/etc/nvl-egress/k2-m4/release.json"),
        secret_file=Path("/etc/nvl-egress/k2-m4/root-hmac.key"),
        runtime_dir=Path("/run/nvl-k2-m4"),
        bot_uid=12001,ipc_gid=12002,
    )


class BotNonrootIdentityTests(unittest.TestCase):
    def setUp(self):
        self.p=paths()
        self.rendered="User=nvlbot\nMainPID=321\nActiveState=active\nDynamicUser=no\n"
        self.seen=[]
        self.procuid=(
            "Name:\tpython\n"
            "Uid:\t12001\t12001\t12001\t12001\n"
            "Gid:\t12001\t12001\t12001\t12001\n"
            "Groups:\t12001 12002\n"
            "CapInh:\t0000000000000000\n"
            "CapPrm:\t0000000000000000\n"
            "CapEff:\t0000000000000000\n"
            "CapAmb:\t0000000000000000\n"
            "NoNewPrivs:\t1\n"
        )
        self.pwd=SimpleNamespace(pw_uid=12001,pw_gid=12001)

    def command_run(self,args,**kwargs):
        self.seen.append(args)
        self.assertEqual(args[0:3],["systemctl","show","nvlbot.service"])
        self.assertFalse(kwargs.get("shell",False))
        return SimpleNamespace(returncode=0,stdout=self.rendered)

    def check(self,**changed):
        opts=dict(
            run=self.command_run,read_status=lambda pid:self.procuid,
            getpw=lambda user:self.pwd,
            getgrouplist=lambda name,gid:[gid,12002],
        )
        opts.update(changed)
        a.assert_nonroot_bot_identity(self.p,**opts)

    def test_matches_live_kernel_uid_twice_pinned_unit_and_ipc_gid(self):
        self.check()
        self.assertEqual(len(self.seen),2)

    def test_root_or_unset_user_never_qualifies(self):
        for line in ("User=\n","User=root\n","User=../root\n"):
            self.rendered=line+"MainPID=321\nActiveState=active\nDynamicUser=no\n"
            with self.subTest(line=line),self.assertRaises(a.M4AAssemblyHold):
                self.check()

    def test_nonroot_process_identity_group_and_pid_attested(self):
        for fake in (
            dict(read_status=lambda _: "Uid:\t0\t0\t0\t0\n"),
            dict(getgrouplist=lambda name,gid:[gid]),
            dict(getpw=lambda username:SimpleNamespace(pw_uid=12009,pw_gid=12001)),
        ):
            with self.subTest(kind=list(fake)),self.assertRaises(a.M4AAssemblyHold):
                self.check(**fake)

    def test_kernel_capabilities_groups_and_no_new_privileges_required(self):
        original=self.procuid
        for changed in (
            original.replace("CapEff:\t0000000000000000","CapEff:\t0000000000000001"),
            original.replace("CapPrm:\t0000000000000000","CapPrm:\t0000000000000001"),
            original.replace("CapInh:\t0000000000000000","CapInh:\t0000000000000001"),
            original.replace("CapAmb:\t0000000000000000","CapAmb:\t0000000000000001"),
            original.replace("Groups:\t12001 12002","Groups:\t12001"),
            original.replace("NoNewPrivs:\t1","NoNewPrivs:\t0"),
            original.replace("Gid:\t12001\t12001\t12001\t12001",
                             "Gid:\t0\t0\t0\t0"),
        ):
            self.procuid=changed
            with self.subTest(status=changed[-90:]),self.assertRaises(a.M4AAssemblyHold):
                self.check()
        self.procuid=original
        self.check()

    def test_dynamic_uid_stopped_pid_and_pid_reuse_denied(self):
        for key,value in (("DynamicUser","yes"),("ActiveState","inactive"),
                          ("MainPID","0"),("MainPID","not-pid")):
            before=self.rendered
            self.rendered=before.replace(key+"="+{
                "DynamicUser":"no","ActiveState":"active","MainPID":"321",
            }[key],key+"="+value)
            with self.subTest(key=key),self.assertRaises(a.M4AAssemblyHold):
                self.check()
            self.rendered=before
        count=[0]
        def swap(args,**kwargs):
            count[0]+=1
            return SimpleNamespace(
                returncode=0,stdout=self.rendered if count[0]==1 else
                self.rendered.replace("MainPID=321","MainPID=322")
            )
        with self.assertRaises(a.M4AAssemblyHold):
            self.check(run=swap)


class ReviewedAssemblyTests(unittest.TestCase):
    def setUp(self):
        self.p=paths()
        self.db=lambda:None
        self.callbacks=Original6GRootCallbacks(self.db)
        self.root_uid=lambda:0
        self.os_uid=lambda name:1636
        self.factory=ReviewedM2P3HostFactory(
            db_conn=self.db, read_root_snapshot=lambda *a:None,
            os_uid=self.os_uid, geteuid=self.root_uid,
            release_enabled=True,
        )
        self.ports=HostReviewedPorts(
            db_conn=self.db,
            acquire_6g=self.callbacks.acquire,
            journal_6g=self.callbacks.journal,
            port_factory=self.factory,
            live_admin_role=lambda a,c:False,
            protected_mode=lambda:"0",
            os_uid=self.os_uid,geteuid=self.root_uid,
        )
        self.identity=patch.object(a,"assert_nonroot_bot_identity")
        self.verifier=patch.object(a,"verify_reviewed_release",return_value="a"*40)
        self.secret=patch.object(a,"load_root_secret",return_value=b"k"*48)
        self.policy=patch.object(
            a,"load_root_admin_policy",
            return_value=RootAdminPolicy(frozenset({(11,-222)})),
        )
        self.gates=patch("edge_egress_k2_m42_bindings.M42_LIVE_BINDINGS_ENABLED",True)
        for p in (self.identity,self.verifier,self.secret,self.policy,self.gates):
            p.start()
            self.addCleanup(p.stop)

    def test_default_off_cannot_assemble_privileged_root_service(self):
        self.assertFalse(a.M4A_ROOT_ASSEMBLY_ENABLED)
        with self.assertRaisesRegex(a.M4AAssemblyHold,"NOT_AUTHORIZED"):
            a.assemble_reviewed_root(
                paths=self.p,ports=self.ports,release_enabled=True,
            )

    def test_root_and_original_port_only_released_in_reviewed_composition(self):
        with patch.object(a,"M4A_ROOT_ASSEMBLY_ENABLED",True):
            result=a.assemble_reviewed_root(
                paths=self.p,ports=self.ports,release_enabled=True,
            )
            self.assertEqual(result.bot_uid,self.p.bot_uid)
            self.assertEqual(result.release_sha,"a"*40)
            self.assertIs(result.worker.transport.portal.checkpoint.db_conn,
                          self.ports.db_conn)
            self.assertIs(result.worker.transport.portal.execute_single,
                          result.worker.transport.portal.execute_single)
            self.assertEqual(result.worker.transport.bot_uid,12001)
            # No socket listener is enabled by this composition.
            with self.assertRaisesRegex(RootWorkerHold,"DISABLED"):
                result.worker.open_listener()

    def test_unreviewed_direct_host_factory_refused_before_root_assembly(self):
        fake=HostReviewedPorts(**{
            **self.ports.__dict__,
            "port_factory":lambda *args:None,
        })
        with patch.object(a,"M4A_ROOT_ASSEMBLY_ENABLED",True):
            with self.assertRaisesRegex(a.M4AAssemblyHold,"NOT_AUTHORIZED"):
                a.assemble_reviewed_root(
                    paths=self.p,ports=fake,release_enabled=True,
                )

    def test_unreviewed_second_6g_callback_is_rejected(self):
        altered=HostReviewedPorts(**{
            **self.ports.__dict__,
            "acquire_6g":lambda *args:None,
        })
        with patch.object(a,"M4A_ROOT_ASSEMBLY_ENABLED",True):
            with self.assertRaisesRegex(a.M4AAssemblyHold,"NOT_AUTHORIZED"):
                a.assemble_reviewed_root(
                    paths=self.p,ports=altered,release_enabled=True,
                )

    def test_unverified_external_witness_override_is_rejected(self):
        altered=HostReviewedPorts(**{
            **self.ports.__dict__,
            "external_evidence":lambda:None,
        })
        with patch.object(a,"M4A_ROOT_ASSEMBLY_ENABLED",True):
            with self.assertRaisesRegex(a.M4AAssemblyHold,"NOT_AUTHORIZED"):
                a.assemble_reviewed_root(
                    paths=self.p,ports=altered,release_enabled=True,
                )


if __name__=="__main__":
    unittest.main()
