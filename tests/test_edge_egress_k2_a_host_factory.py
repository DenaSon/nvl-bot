"""Package A root host wiring: explicit source gates and no pre-6G mutation.

All fixtures are disposable. Never accept synthetic F4 as physical release.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

import edge_egress_k2_a_host_factory as factory
from edge_egress_k2_migration_inventory import LiveIngressWitness
from edge_egress_p3_executor import ExecutionScope,ExecutionTicket,_scope_digest
from tests.test_edge_egress_k2_migration_inventory import (
    K2M1InventoryTests,TARGET,NOW,
)


class ReviewedHostFactoryTests(unittest.TestCase):
    def setUp(self):
        fixture=K2M1InventoryTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fx=fixture
        self.scope=ExecutionScope(
            "UID_ENROLL_SOURCE","e9",TARGET,TARGET,
            username="nvl0555",uid=1636,
        )
        self.ticket=ExecutionTicket(
            11,-222,"a"*32,NOW+100,
            _scope_digest(self.scope),"b"*64,
        )
        self.ops=[]
        self.f= factory.ReviewedM2P3HostFactory(
            db_conn=fixture.db,
            read_root_snapshot=lambda *args:self.ops.append("root-plan"),
            os_uid=lambda name:fixture.uids[name],
            geteuid=lambda:0,release_enabled=True,
        )
        self.good_review=lambda selection:fixture.preview(
            selection.usernames,
            ingress_witness=lambda name:LiveIngressWitness(
                name,"e9",TARGET,NOW-1,"INDEPENDENT_LIVE",
            ),
        )

    def test_default_source_flag_blocks_before_rootsnapshot(self):
        self.assertFalse(factory.M4A_REAL_HOST_FACTORY_ENABLED)
        with self.assertRaisesRegex(factory.M4AHostHold,"RELEASE"):
            self.f(self.scope,self.ticket,self.good_review)
        self.assertEqual(self.ops,[])

    def test_wrong_scope_nonroot_or_untrusted_ticket_denied_before_m2(self):
        with patch.object(factory,"M4A_REAL_HOST_FACTORY_ENABLED",True):
            root=factory.ReviewedM2P3HostFactory(
                db_conn=self.fx.db,read_root_snapshot=self.f.read_root_snapshot,
                os_uid=self.f.os_uid,geteuid=lambda:1000,
                release_enabled=True,
            )
            with self.assertRaisesRegex(factory.M4AHostHold,"RELEASE"):
                root(self.scope,self.ticket,self.good_review)
            cross=ExecutionScope(
                "UID_ATTACH","e9","172.86.111.69",TARGET,
                username="nvl0555",uid=1636,
            )
            with self.assertRaisesRegex(factory.M4AHostHold,"RELEASE"):
                self.f(cross,self.ticket,self.good_review)
            with self.assertRaisesRegex(factory.M4AHostHold,"RELEASE"):
                self.f(self.scope,object(),self.good_review)
        self.assertEqual(self.ops,[])

    def test_stale_or_wrong_ingress_never_queries_host_bootstrap(self):
        with patch.object(factory,"M4A_REAL_HOST_FACTORY_ENABLED",True):
            bad=lambda selection:self.fx.preview(
                selection.usernames,ingress_witness=lambda name:
                LiveIngressWitness(name,"e9",TARGET,NOW-301,
                                   "INDEPENDENT_LIVE"),
            )
            with self.assertRaises(factory.M4AHostHold):
                self.f(self.scope,self.ticket,bad)
            self.assertEqual(self.ops,[])

    def test_signed_source_ok_but_unpinned_host_factory_remains_hold(self):
        with patch.object(factory,"M4A_REAL_HOST_FACTORY_ENABLED",True):
            with self.assertRaisesRegex(factory.M4AHostHold,"SNAPSHOT"):
                self.f(self.scope,self.ticket,self.good_review)
        self.assertEqual(self.ops,["root-plan"])

    def test_no_shell_or_parallel_lease_api(self):
        self.assertFalse(hasattr(factory,"execute_shell"))
        self.assertFalse(hasattr(factory,"acquire_6g"))
        self.assertFalse(hasattr(factory,"migrate_users"))


if __name__ == "__main__":
    unittest.main()
