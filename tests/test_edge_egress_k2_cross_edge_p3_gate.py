"""Original 6G P3 mode-0 exception is sealed to one M4 reviewed host.

Tests intercept ONLY privileged host methods; the original executor owns
real SQLite journal, ticket, replay and locking. No VPS or live root actions.
"""
import asyncio
from unittest.mock import AsyncMock, patch
import unittest

from edge_egress_k2_m4_bootstrap import (
    GuardBootstrap, DeferredCrossEdgeOriginal6GHostPort,
)
from edge_egress_p3_executor import (
    ATTACH_GATES, BASE_GATES, ExecutionScope, ExecutorHold, FreshEvidence,
)
from tests.test_edge_egress_p3_executor import ExecutorTests


class CrossEdgeLegacyP3GateTests(unittest.TestCase):
    def setUp(self):
        self.fx = ExecutorTests(methodName="test_global_source_default_off_and_requires_explicit_gate")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        # A bound method lookup is a distinct Python object each time;
        # the real P3 6G port requires the EXACT DB callable identity.
        self.db_conn = self.fx.conn
        self.scope = ExecutionScope(
            "UID_ATTACH", "e7", self.fx.scope.source_host,
            self.fx.scope.target_host, username="nvl0557",uid=1644,
        )
        self.fx.evidence = FreshEvidence(
            self.fx.digest,self.fx.now,BASE_GATES | ATTACH_GATES,
        )
        self.ticket = self.fx.ticket(scope=self.scope)
        self.bootstrap = GuardBootstrap(
            self.scope,self.ticket,"FIRST_UID",{
                "scope":self.scope,"ticket":self.ticket,
                "db_conn":self.db_conn,"release_enabled":True,
            },
        )
        self.port = DeferredCrossEdgeOriginal6GHostPort(
            scope=self.scope,ticket=self.ticket,
            db_conn=self.db_conn,bootstrap=self.bootstrap,
            port_factory=lambda *args:None,release_enabled=True,
        )
        self.port.apply = AsyncMock(return_value=None)
        self.port.verify = AsyncMock(return_value=True)
        self.port.freeze_or_hold = AsyncMock(return_value=None)

    def _engine(self, port=None):
        engine=self.fx.engine()
        engine.db_conn=self.db_conn
        engine.host_port=self.port if port is None else port
        return engine

    def _run(self, engine=None, ticket=None):
        return asyncio.run((engine or self._engine()).execute(
            self.scope, ticket or self.ticket,actor_id=18,chat_id=35,
        ))

    def test_all_source_flags_default_off_and_generic_port_never_mode_zero(self):
        import edge_egress_p3_executor as ex
        self.assertFalse(ex.P3_CROSS_EDGE_LEGACY_UID_ATTACH_ENABLED)
        with self.assertRaisesRegex(ExecutorHold,"PROTECTED_MODE_REQUIRED"):
            self._run()
        self.assertEqual(self.fx.acquire_count,0)
        with patch.object(ex,"P3_CROSS_EDGE_LEGACY_UID_ATTACH_ENABLED",True):
            with self.assertRaisesRegex(ExecutorHold,"PROTECTED_MODE_REQUIRED"):
                self._run(self._engine(self.fx.host))
        self.assertEqual(self.fx.acquire_count,0)
        self.port.apply.assert_not_called()

    def test_p3_exact_sealed_port_can_run_original_6g_with_legacy_unchanged(self):
        with patch(
            "edge_egress_p3_executor.P3_CROSS_EDGE_LEGACY_UID_ATTACH_ENABLED",
            True,
        ):
            receipt=self._run()
        self.assertTrue(receipt.allowed)
        self.assertEqual(receipt.result,"SUCCEEDED")
        self.port.apply.assert_awaited_once_with(self.scope)
        self.port.verify.assert_awaited_once_with(self.scope)
        self.assertEqual(self.fx.journal_count,2)
        with self.fx.conn() as db:
            self.assertEqual(db.execute(
                "SELECT value FROM settings WHERE key='edge_egress_protected_mode'"
            ).fetchone(),("0",))

    def test_forged_deferred_ticket_or_disabled_port_is_not_privileged(self):
        with patch(
            "edge_egress_p3_executor.P3_CROSS_EDGE_LEGACY_UID_ATTACH_ENABLED",
            True,
        ):
            self.port.release_enabled=False
            with self.assertRaisesRegex(ExecutorHold,"PROTECTED_MODE_REQUIRED"):
                self._run()
            self.port.release_enabled=True
            self.port.ticket=self.fx.ticket(scope=self.scope)
            with self.assertRaisesRegex(ExecutorHold,"PROTECTED_MODE_REQUIRED"):
                self._run()
        self.assertEqual(self.fx.acquire_count,0)
        self.port.apply.assert_not_called()


if __name__=="__main__":
    unittest.main()
