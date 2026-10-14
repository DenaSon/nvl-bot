"""M3 per-UID actual-ingress same-Edge adapter. All P3/6G kernel calls mocked."""
from __future__ import annotations

from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from edge_egress_k2_m3_ingress_port import (
    GuardedVerifiedIngressUIDPort, VerifiedIngressContract,
    VerifiedIngressHold, M3_VERIFIED_INGRESS_ADAPTER_ENABLED,
)
from edge_egress_k2_m3_waves import build_wave_plan
from edge_egress_k2_migration_inventory import (
    LiveIngressWitness, select_migration,
)
from edge_egress_p3_executor import (
    ExecutionScope, ExecutionTicket, _scope_digest,
)
from edge_egress_p3_uid import GuardedProtectedUIDPort
from edge_egress_k2_source_enrollment import SameEdge6GUIDRuntimeStore
from tests.test_edge_egress_k2_migration_inventory import (
    K2M1InventoryTests,NOW,TARGET,
)


class M3VerifiedIngressPortTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.fx=K2M1InventoryTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.witness=lambda name:LiveIngressWitness(
            name,"e9",TARGET,NOW-1,"INDEPENDENT_LIVE")
        selection=select_migration("SINGLE",("nvl0555",),"e9")
        review=self.fx.preview(selection.usernames,selection.mode,
                               ingress_witness=self.witness)
        member=build_wave_plan(review).members[0]
        self.assertTrue(member.selectable)
        scope=ExecutionScope("UID_ENROLL_SOURCE","e9",TARGET,TARGET,
                             username="nvl0555",uid=1636)
        ticket=ExecutionTicket(3,-5,"1"*32,NOW+60,
                               _scope_digest(scope),"a"*64)
        uid_port=object.__new__(GuardedProtectedUIDPort)
        uid_port.plan=SimpleNamespace(scope=scope)
        uid_port.ticket=ticket
        uid_port.store=object.__new__(SameEdge6GUIDRuntimeStore)
        uid_port.store.scope=scope
        uid_port.store.ticket=ticket
        self.scope,self.ticket,self.uid_port=scope,ticket,uid_port
        self.contract=VerifiedIngressContract(member,scope)
        self.events=[]
        self.review=lambda sel:self.fx.preview(sel.usernames,sel.mode,
                                       ingress_witness=self.witness)
        self.port=GuardedVerifiedIngressUIDPort(
            contract=self.contract,ticket=self.ticket,
            uid_port=self.uid_port,db_conn=self.fx.db,
            live_inventory=self.review,release_enabled=True)

    def setup_trust(self):
        return patch(
            "edge_egress_k2_m3_ingress_port.M3_VERIFIED_INGRESS_ADAPTER_ENABLED",
            True,
        )

    async def test_real_ingress_allows_legacy_with_different_historical_host(self):
        self.assertEqual(self.contract.member.historical_host,
                         "104.194.144.195")
        self.assertEqual(self.contract.member.source_ipv4,TARGET)
        self.assertFalse(M3_VERIFIED_INGRESS_ADAPTER_ENABLED)
        self.uid_port.apply=AsyncMock()
        self.uid_port.verify=AsyncMock(return_value=True)
        self.uid_port.freeze_or_hold=AsyncMock()
        def mark_protected(scope):
            self.fx.c.execute(
                "INSERT INTO edge_egress_uid_runtime VALUES"
                "('nvl0555',1636,'e9',?,'PROTECTED')",(TARGET,))
            self.fx.c.execute(
                "INSERT INTO edge_egress_uid_bindings VALUES"
                "('nvl0555',1636,'e9',?,'PROTECTED')",(TARGET,))
        self.uid_port.apply.side_effect=mark_protected
        with self.setup_trust(),patch(
            "edge_egress_k2_m3_ingress_port.assert_guarded_6g_intent",
            return_value=40):
            await self.port.apply(self.scope)
            self.assertTrue(await self.port.verify(self.scope))
        self.uid_port.apply.assert_awaited_once_with(self.scope)
        self.uid_port.verify.assert_awaited_once_with(self.scope)

    async def test_unreleased_adapter_refuses_before_existing_p3_port(self):
        self.uid_port.apply=AsyncMock()
        with self.assertRaisesRegex(VerifiedIngressHold,"NOT_RELEASED"):
            await self.port.apply(self.scope)
        self.uid_port.apply.assert_not_awaited()

    async def test_changed_ingress_or_f4_refused_before_kernel(self):
        self.uid_port.apply=AsyncMock()
        with self.setup_trust(),patch(
            "edge_egress_k2_m3_ingress_port.assert_guarded_6g_intent",
            return_value=40):
            self.witness=lambda name:LiveIngressWitness(
                name,"s8","172.86.111.69",NOW-1,"INDEPENDENT_LIVE")
            with self.assertRaises(VerifiedIngressHold):
                await self.port.apply(self.scope)
        self.uid_port.apply.assert_not_awaited()

    async def test_loss_of_original_6g_refused_before_kernel(self):
        self.uid_port.apply=AsyncMock()
        with self.setup_trust(),patch(
            "edge_egress_k2_m3_ingress_port.assert_guarded_6g_intent",
            side_effect=VerifiedIngressHold("EXACT_6G_LEASE_LOST")):
            with self.assertRaisesRegex(VerifiedIngressHold,"EXACT_6G_LEASE_LOST"):
                await self.port.apply(self.scope)
        self.uid_port.apply.assert_not_awaited()

    async def test_fail_closed_freeze_delegates_only_to_same_pinned_uid(self):
        self.uid_port.freeze_or_hold=AsyncMock()
        with self.setup_trust():
            await self.port.freeze_or_hold(self.scope)
            self.uid_port.freeze_or_hold.assert_not_awaited()
            self.port._started=True
            await self.port.freeze_or_hold(self.scope)
            self.uid_port.freeze_or_hold.assert_awaited_once_with(self.scope)

if __name__=="__main__":
    unittest.main()
