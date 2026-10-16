"""K2 cross-edge positive final gate: M1 intentional egress drift is not an error.

Uses original M1 SQLite inventory, not a hand-authored inventory object.
The 6G guard is intercepted; no kernel, WG, network or production action.
"""
import unittest
from unittest.mock import patch
from edge_egress_k2_m3_waves import build_wave_plan
from edge_egress_k2_m4_cross_edge_port import GuardedCrossEdgeUIDPort, CrossEdgeUIDHold
from edge_egress_p3_executor import ExecutionScope
from tests.test_edge_egress_k2_migration_inventory import K2M1InventoryTests, SOURCE, TARGET


class CrossEdgeCommittedM1Tests(unittest.TestCase):
    def setUp(self):
        self.fx=K2M1InventoryTests(methodName="test_single_and_batch_use_same_account_evidence")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.before=self.fx.preview()
        self.member=build_wave_plan(self.before,wave_size=1).members[0]
        self.scope=ExecutionScope("UID_ATTACH","e9",SOURCE,TARGET,
                                  username="nvl0555",uid=1636)
        # Only _check is tested. Typed original P3 construction has distinct tests.
        self.adapter=object.__new__(GuardedCrossEdgeUIDPort)
        self.adapter.member=self.member
        self.adapter.scope=self.scope
        self.adapter.ticket=object()
        self.adapter.db_conn=self.fx.db
        self.adapter.live_inventory=lambda selected:self.fx.preview(
            selected.usernames,selected.mode
        )
        self.adapter.release_enabled=True

    def _check(self, *, committed):
        with patch("edge_egress_k2_m4_cross_edge_port.M4_CROSS_EDGE_UID_PORT_ENABLED",True),\
             patch("edge_egress_k2_m4_cross_edge_port.assert_guarded_6g_intent",return_value=41):
            self.adapter._check(self.scope,committed=committed)

    def _protected(self):
        self.fx.c.execute(
            "INSERT INTO edge_egress_uid_runtime VALUES (?,?,?,?,?)",
            ("nvl0555",1636,"e9",TARGET,"PROTECTED"),
        )
        self.fx.c.execute(
            "INSERT INTO edge_egress_uid_bindings VALUES (?,?,?,?,?)",
            ("nvl0555",1636,"e9",TARGET,"PROTECTED"),
        )

    def test_before_then_after_intended_cross_edge_commit(self):
        self.fx.c.execute("INSERT INTO failover_operations VALUES (41,'RUNNING')")
        self._check(committed=False)
        self._protected()
        post=self.fx.preview()
        selected=next(a for a in post.accounts if a.selected)
        self.assertEqual(selected.issues,(
            "TARGET_ALREADY_PROTECTED","PROTECTED_SOURCE_DRIFT"
        ))
        self.assertEqual(selected.protected_edge_id,"e9")
        self._check(committed=True)

    def test_wrong_other_uid_protection_does_not_pass(self):
        self.fx.c.execute("INSERT INTO failover_operations VALUES (41,'RUNNING')")
        self._protected()
        self.fx.c.execute(
            "UPDATE edge_egress_uid_runtime SET edge_id='s8',edge_ipv4=?",
            (SOURCE,),
        )
        self.fx.c.execute(
            "UPDATE edge_egress_uid_bindings SET edge_id='s8',edge_ipv4=?",
            (SOURCE,),
        )
        with self.assertRaises(CrossEdgeUIDHold):
            self._check(committed=True)

    def test_rejected_without_original_6g_intent(self):
        self.fx.c.execute("INSERT INTO failover_operations VALUES (41,'RUNNING')")
        self._protected()
        with patch("edge_egress_k2_m4_cross_edge_port.M4_CROSS_EDGE_UID_PORT_ENABLED",True),\
             patch("edge_egress_k2_m4_cross_edge_port.assert_guarded_6g_intent",
                   side_effect=ValueError("NO_6G")):
            with self.assertRaises(ValueError):
                self.adapter._check(self.scope,committed=True)


if __name__=="__main__":
    unittest.main()
