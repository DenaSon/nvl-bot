"""A3 -> M4A typed cross-Edge root plan factory, actual wiring and no writes.

The reviewed original A3 snapshot+M4A factory are exercised with disposable
M1 SQLite and a synthetic RootHostSafetyGates witness. External F4/packet
evidence remains FIELD HOLD; this test does not release or touch production.
"""
from contextlib import ExitStack
from dataclasses import replace
import unittest
from unittest.mock import patch

import edge_egress_k2_a3_host_plans as a3
import edge_egress_k2_a_host_factory as host_factory
from edge_egress_k2_m4_bootstrap import (
    DeferredCrossEdgeOriginal6GHostPort, DeferredOriginal6GHostPort,
)
from edge_egress_k2_m4_cross_edge_port import (
    CrossEdgeIndependentSafety, root_fresh_source_evidence,
)
from edge_egress_k2_migration_inventory import LiveIngressWitness
from edge_egress_p3_executor import ExecutionScope, ExecutionTicket, _scope_digest
from tests.test_edge_egress_k2_a3_host_plans import RootOwnedSnapshotWiringTests
from tests.test_edge_egress_k2_migration_inventory import NOW, SOURCE, TARGET


class CrossEdgeRootPlanFactoryIntegrationTests(unittest.TestCase):
    def setUp(self):
        # Reuse the actual disposable M1 fixture and original typed A3 plan
        # builders. Redirect nested cleanup hooks to this test runner.
        self.fixture=RootOwnedSnapshotWiringTests(
            methodName="test_factory_receives_real_typed_snapshot_and_defers_sixg"
        )
        self.fixture.addCleanup=self.addCleanup
        self.fixture.setUp()
        fx=self.fixture
        fx.scope=ExecutionScope(
            "UID_ATTACH", "e9", SOURCE, TARGET,
            username="nvl0555",uid=1636,
        )
        fx.ticket=ExecutionTicket(
            11,-222,"a"*32,NOW+100,_scope_digest(fx.scope),"b"*64,
        )
        safety=CrossEdgeIndependentSafety(
            db_conn=fx.fx.db,target_edge_id="e9",source_ipv4=SOURCE,
            ingress_rhost="10.77.0.8",ssh_local_addr="10.77.0.1",
            ssh_local_port=22,reviewed_module_sha256="a"*64,
            packet_witness=lambda req:True,
            neighbour_witness=lambda req:True,
            ingress_edge_id="s8",source_evidence=root_fresh_source_evidence,
        )
        fx.gates=replace(fx.gates,safety=safety)
        fx.review=lambda selection:fx.fx.preview(
            selection.usernames,ingress_witness=lambda name:
            LiveIngressWitness(name,"s8",SOURCE,NOW-1,"INDEPENDENT_LIVE")
        )
        # A3 captured the old same-edge callback during its constructor.
        # Both A3 and M4A must consume the SAME current cross-edge M1
        # provider, not two independently authored/frozen snapshots.
        fx.adapter.inventory_provider=fx.review
        self.host=host_factory.ReviewedM2P3HostFactory(
            db_conn=fx.fx.db,read_root_snapshot=fx.adapter,
            os_uid=fx.uid,geteuid=fx.root,release_enabled=True,
        )
        self.initial_ops=[]

    def gates(self):
        stack=ExitStack()
        stack.enter_context(patch.object(
            host_factory,"M4A_REAL_HOST_FACTORY_ENABLED",True,
        ))
        stack.enter_context(patch.object(
            host_factory,"M4A_CROSS_EDGE_FACTORY_ENABLED",True,
        ))
        stack.enter_context(patch.object(
            a3,"A3_ROOT_SNAPSHOT_BINDING_ENABLED",True,
        ))
        stack.enter_context(patch.object(
            a3,"A3_ROOT_CROSS_EDGE_SNAPSHOT_ENABLED",True,
        ))
        stack.enter_context(patch.object(
            a3.RootOwnedM2PlanSource,"__call__",
            return_value=self.fixture.root_plan("FIRST_UID",self.fixture.plan),
        ))
        stack.enter_context(patch.object(
            a3,"_read_checked",return_value=self.fixture.pam,
        ))
        stack.enter_context(patch.object(
            a3.BootGuardManifest,"parse",return_value=self.fixture.manifest,
        ))
        return stack

    def test_root_a3_m4a_builds_exact_cross_edge_deferred_port_without_writes(self):
        fx=self.fixture
        self.assertNotEqual(fx.scope.source_host,fx.scope.target_host)
        with self.gates():
            port=self.host(fx.scope,fx.ticket,fx.review)
        self.assertIs(type(port),DeferredCrossEdgeOriginal6GHostPort)
        self.assertIsInstance(port,DeferredOriginal6GHostPort)
        self.assertIs(port.db_conn,fx.fx.db)
        self.assertEqual(port.scope,fx.scope)
        self.assertEqual(port.ticket,fx.ticket)
        self.assertFalse(port._started)
        self.assertEqual(fx.calls,["gates"])
        self.assertFalse(fx.fx.c.execute(
            "SELECT 1 FROM failover_operations WHERE status='RUNNING'"
        ).fetchone())

    def test_cross_edge_factory_without_distinct_gate_is_held_before_snapshot(self):
        fx=self.fixture
        with patch.object(host_factory,"M4A_REAL_HOST_FACTORY_ENABLED",True):
            with self.assertRaisesRegex(host_factory.M4AHostHold,"RELEASE"):
                self.host(fx.scope,fx.ticket,fx.review)
        self.assertEqual(fx.calls,[])

    def test_cross_edge_source_drift_rejected_before_any_a3_plan(self):
        fx=self.fixture
        bad=lambda selection:fx.fx.preview(
            selection.usernames,ingress_witness=lambda name:
            LiveIngressWitness(name,"e9",TARGET,NOW-1,"INDEPENDENT_LIVE"),
        )
        with self.gates():
            with self.assertRaisesRegex(host_factory.M4AHostHold,"SOURCE_OR_F4"):
                self.host(fx.scope,fx.ticket,bad)
        self.assertEqual(fx.calls,[])

    def test_wrong_independent_safety_identity_rejected(self):
        fx=self.fixture
        fx.gates=replace(fx.gates,safety=replace(
            fx.gates.safety, ingress_edge_id="e9",
        ))
        with self.gates():
            with self.assertRaisesRegex(a3.A3PlanHold,"PHYSICAL_WITNESS"):
                self.host(fx.scope,fx.ticket,fx.review)
        self.assertEqual(fx.calls,["gates"])


if __name__=="__main__":
    unittest.main()
