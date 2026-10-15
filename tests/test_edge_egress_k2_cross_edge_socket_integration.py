"""Single Cross-Edge through the ORIGINAL Telegram->AF_UNIX->M3/P3/6G chain.

This is an integration harness: RootOperatorIPC uses kernel AF_UNIX
SO_PEERCRED and actual disposable SQLite original 6G journal/checkpoint.
The host/packet proof is intentionally synthetic and NO customer, real WG,
PAM, socket service, or production VPS is touched. It is NOT field release.
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
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
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

    async def test_true_cross_edge_target_with_original_single_6g_and_ipc(self):
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
        accepted=await self.fx.confirm()
        self.assertEqual(accepted["state"],"COMPLETED")
        self.assertEqual(accepted["completed"],1)
        self.assertEqual(len(self.fx.original_rows()),1)
        self.assertEqual(self.fx.original_rows()[0][1],"SUCCEEDED")
        self.assertEqual((await self.fx.status())["wave_state"],"RECEIPTS_RECORDED")
        self.assertEqual(self.fx.effects.count("synthetic-host-apply"),1)

    async def test_cross_edge_abort_and_unchanged_legacy_global_mode(self):
        self.fx.fail_after_apply=True
        await self.fx.prepare()
        result=await self.fx.confirm()
        self.assertEqual(result["state"],"HOLD")
        self.assertEqual(self.fx.original_rows()[0][1],"RUNNING")
        self.assertEqual(self.fx.effects.count("synthetic-host-freeze"),1)
        self.assertTrue((await self.fx.status())["unresolved"])
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
