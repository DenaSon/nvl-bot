"""Cross-Edge M4 IPC must REFUSE a simulated untyped P3 host port.

The legacy-mode cross-edge P3 exception ONLY works with an exact typed
DeferredCrossEdgeOriginal6GHostPort and one-shot 6G ticket. The M45 synthetic
host cannot be used to fake a successful customer cutover; this regression
proves fail-closed behavior over the real AF_UNIX stream. No VPS touched.
"""
import unittest
from unittest.mock import patch

from edge_egress_k2_migration_inventory import LiveIngressWitness, preview_migration
from edge_egress_k2_m3_journal import confirm_original_6g_commit
from tests.test_edge_egress_k2_m45_end_to_end import (
    M45FullIntegrationTests, ADMIN, CHAT,
)
from tests.test_edge_egress_k2_migration_inventory import SOURCE, TARGET


class SingleCrossEdgeSocketIntegrationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.fx=M45FullIntegrationTests(
            methodName="test_real_socket_full_green_p3_6g_checkpoint_and_root_readback"
        )
        # The nested IsolatedAsyncioTestCase has no own asyncio runner.
        # Register EVERY existing M45 cleanup with this active test runner,
        # otherwise its patch.stop raises before restoring global release flags.
        self.fx.addCleanup=self.addCleanup
        self.fx.setUp()
        self.fx.portal.review=self.review
        for flag in (
            "edge_egress_k2_m3_waves.M3_CROSS_EDGE_LEGACY_SINGLE_ENABLED",
            "edge_egress_k2_m4_root_portal.M4_CROSS_EDGE_SINGLE_ENABLED",
        ):
            p=patch(flag,True)
            p.start()
            self.addCleanup(p.stop)

    async def asyncSetUp(self):
        await self.fx.asyncSetUp()

    def review(self,selection):
        return preview_migration(
            self.fx.db,selection,
            os_uid=lambda name:self.fx.m1uid[name],
            ingress_witness=lambda name:LiveIngressWitness(
                name,"s8",SOURCE,
                self.fx.now-1 if not self.fx.review_changes
                else self.fx.now-350,"INDEPENDENT_LIVE",
            ),
            session_count=lambda name,uid:0,
            now=self.fx.now,
        )

    async def test_cross_edge_untyped_host_cannot_fake_6g_success(self):
        inventory=self.review(self.fx.selection)
        member=next(x for x in inventory.accounts if x.selected)
        self.assertEqual((member.source_edge_id,member.source_ipv4),("s8",SOURCE))
        self.assertEqual(member.historical_host,"104.194.144.195")
        self.assertEqual((inventory.selection.target_edge_id,inventory.target_ipv4),
                         ("e9",TARGET))
        self.assertNotEqual(member.source_ipv4,inventory.target_ipv4)
        self.assertEqual((await self.fx.status())["wave_state"],"NO_CHECKPOINT")
        prepared=await self.fx.prepare()
        self.assertEqual(prepared.selection.mode,"SINGLE")
        self.assertFalse(self.fx.original_rows())
        refused=await self.fx.confirm()
        self.assertEqual(refused["state"],"HOLD",refused)
        self.assertEqual(refused["completed"],0)
        self.assertFalse(self.fx.original_rows())
        self.assertEqual(self.fx.effects.count("synthetic-host-apply"),0)
        self.assertEqual(self.fx.effects.count("original-6g-acquired"),0)
        with self.fx.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT value FROM settings WHERE key='edge_egress_protected_mode'"
            ).fetchone(),("0",))

    async def test_fake_cross_edge_partial_failure_cannot_mutate_any_uid(self):
        self.fx.fail_after_apply=True
        await self.fx.prepare()
        result=await self.fx.confirm()
        self.assertEqual(result["state"],"HOLD")
        self.assertEqual(result["completed"],0)
        self.assertFalse(self.fx.original_rows())
        self.assertEqual(self.fx.effects.count("synthetic-host-apply"),0)
        self.assertEqual(self.fx.effects.count("synthetic-host-freeze"),0)
        with self.fx.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT value FROM settings "
                "WHERE key='edge_egress_protected_mode'"
            ).fetchone(),("0",))
            self.assertEqual(conn.execute(
                "SELECT host FROM ssh_accounts WHERE username='nvl0555'"
            ).fetchone(),("104.194.144.195",))


if __name__=="__main__":
    unittest.main()
