"""Phase 1: same-process ROOT Telegram -> original P3/6G/Checkpoint.

Hermetic existing M45 fixture, actual SQLite original 6G and Portal;
only kernel actions and external packet observer are synthetic. No VPS.
"""
import asyncio
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from edge_egress_k2_root_direct import (
    RootDirectOperatorClient, bound_root_client,
)
from edge_egress_k2_m43_client import M43ClientHold
from edge_egress_k2_m43_workflow import PendingTelegramApproval
from edge_egress_k2_migration_inventory import select_migration
from tests.test_edge_egress_k2_m45_end_to_end import (
    M45FullIntegrationTests, ADMIN, CHAT, MESSAGE,
)


class ExistingRootBotDirectTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.fx=M45FullIntegrationTests(
            methodName="test_real_socket_full_green_p3_6g_checkpoint_and_root_readback"
        )
        # Nested fixture must register patches/SQLite cleanup with this
        # runner, never leak release switches across global test modules.
        self.fx.addCleanup=self.addCleanup
        self.fx.setUp()
        release=patch("edge_egress_k2_root_direct.K2_ROOT_DIRECT_ENABLED",True)
        release.start()
        self.addCleanup(release.stop)
        self.client=RootDirectOperatorClient(
            portal=self.fx.portal,geteuid=lambda:0,released=True,
        )

    async def test_root_bot_direct_single_original_6g_with_no_socket(self):
        selection=self.fx.selection
        app=SimpleNamespace(bot_data={"k2_root_direct_client":self.client})
        client=bound_root_client(app)
        self.assertIs(client,self.client)
        self.assertEqual((await client.request(
            "STATUS",actor_id=ADMIN,chat_id=CHAT,selection=selection,
        ))["wave_state"],"NO_CHECKPOINT")
        reply=await client.request(
            "PREPARE",actor_id=ADMIN,chat_id=CHAT,selection=selection,
        )
        pending=PendingTelegramApproval.create(
            selection=selection,actor_id=ADMIN,chat_id=CHAT,
            message_id=MESSAGE,result=reply,now=self.fx.now,
        )
        self.assertFalse(self.fx.original_rows())
        prepared=pending.check(
            actor_id=ADMIN,chat_id=CHAT,message_id=MESSAGE,
            edge_id=selection.target_edge_id,now=self.fx.now,
        )
        self.assertIsNone(prepared)
        done=await client.request(
            "CONFIRM",actor_id=ADMIN,chat_id=CHAT,
            request_id=pending.request_id,
        )
        self.assertEqual(done["state"],"COMPLETED")
        self.assertEqual(done["accounts"],[
            {"username":"nvl0555","state":"VERIFIED"},
        ])
        self.assertEqual(len(self.fx.original_rows()),1)
        self.assertEqual(self.fx.original_rows()[0][1],"SUCCEEDED")
        self.assertEqual(self.fx.effects,[
            "p3-ticket","original-6g-acquired",
            "journal:EGRESS_P3_EXECUTE_INTENT",
            "synthetic-host-apply","synthetic-host-verify",
            "journal:EGRESS_P3_VERIFIED",
        ])
        status=await client.request(
            "STATUS",actor_id=ADMIN,chat_id=CHAT,selection=selection,
        )
        self.assertEqual(status["wave_state"],"RECEIPTS_RECORDED")
        self.assertFalse(status["unresolved"])
        with self.assertRaisesRegex(M43ClientHold,"APPROVAL_MISSING"):
            await client.request(
                "CONFIRM",actor_id=ADMIN,chat_id=CHAT,
                request_id=pending.request_id,
            )

    async def test_root_direct_release_off_and_no_global_registration(self):
        app=SimpleNamespace(bot_data={})
        with self.assertRaisesRegex(M43ClientHold,"NOT_REGISTERED"):
            bound_root_client(app)
        with patch("edge_egress_k2_root_direct.K2_ROOT_DIRECT_ENABLED",False):
            with self.assertRaisesRegex(M43ClientHold,"NOT_RELEASED"):
                await self.client.request(
                    "PREPARE",actor_id=ADMIN,chat_id=CHAT,
                    selection=self.fx.selection,
                )
        nonroot=RootDirectOperatorClient(
            portal=self.fx.portal,geteuid=lambda:1002,released=True,
        )
        with self.assertRaisesRegex(M43ClientHold,"NOT_RELEASED"):
            await nonroot.request(
                "PREPARE",actor_id=ADMIN,chat_id=CHAT,
                selection=self.fx.selection,
            )
        self.assertFalse(self.fx.original_rows())

    async def test_other_admin_and_replay_are_rejected_without_6g(self):
        reply=await self.client.request(
            "PREPARE",actor_id=ADMIN,chat_id=CHAT,
            selection=self.fx.selection,
        )
        with self.assertRaises(Exception):
            await self.client.request(
                "CONFIRM",actor_id=ADMIN+1,chat_id=CHAT,
                request_id=reply["request_id"],
            )
        with self.assertRaisesRegex(M43ClientHold,"APPROVAL_MISSING"):
            await self.client.request(
                "CONFIRM",actor_id=ADMIN,chat_id=CHAT,
                request_id="f"*32,
            )
        self.assertFalse(self.fx.original_rows())

    async def test_cancel_drops_token_and_never_runs_original_6g(self):
        reply=await self.client.request(
            "PREPARE",actor_id=ADMIN,chat_id=CHAT,
            selection=self.fx.selection,
        )
        result=await self.client.request(
            "CANCEL",actor_id=ADMIN,chat_id=CHAT,
            request_id=reply["request_id"],
        )
        self.assertEqual(result,{"state":"CANCELLED"})
        with self.assertRaisesRegex(M43ClientHold,"APPROVAL_MISSING"):
            await self.client.request(
                "CONFIRM",actor_id=ADMIN,chat_id=CHAT,
                request_id=reply["request_id"],
            )
        self.assertFalse(self.fx.original_rows())

    async def test_partial_host_failure_preserves_original_6g_and_checkpoint(self):
        reply=await self.client.request(
            "PREPARE",actor_id=ADMIN,chat_id=CHAT,
            selection=self.fx.selection,
        )
        self.fx.fail_after_apply=True
        result=await self.client.request(
            "CONFIRM",actor_id=ADMIN,chat_id=CHAT,
            request_id=reply["request_id"],
        )
        self.assertEqual(result["state"],"HOLD")
        self.assertEqual(self.fx.original_rows()[0][1],"RUNNING")
        recovered=await self.client.request(
            "STATUS",actor_id=ADMIN,chat_id=CHAT,
            selection=self.fx.selection,
        )
        self.assertTrue(recovered["busy"])
        self.assertTrue(recovered["unresolved"])
        # A restarted bot discards volatile tokens; original 6G remains
        # authoritative and the checkpoint remains in HOLD.
        self.client=RootDirectOperatorClient(
            portal=self.fx.portal,geteuid=lambda:0,released=True,
        )
        with self.assertRaises(Exception):
            await self.client.request(
                "PREPARE",actor_id=ADMIN,chat_id=CHAT,
                selection=self.fx.selection,
            )
        self.assertEqual(len(self.fx.original_rows()),1)

    async def test_batch_is_still_independently_off(self):
        multi=select_migration("BATCH",("nvl0555","nvl0557"),"e9")
        with self.assertRaisesRegex(M43ClientHold,"BATCH_OR_INFLIGHT"):
            await self.client.request(
                "PREPARE",actor_id=ADMIN,chat_id=CHAT,selection=multi,
            )
        self.assertFalse(self.fx.original_rows())

    def test_existing_bot_bound_only_to_single_root_direct_client(self):
        source=(Path(__file__).resolve().parents[1]/
                "bot_final_v49-2.py").read_text(encoding="utf-8")
        self.assertIn(
            "bound_root_client as k2_root_direct_client",source,
        )
        self.assertIn(
            "k2_root_direct_client(context.application).request(",source,
        )
        self.assertNotIn("k2_m43_client(released=True)",source)
        self.assertNotIn("Application.builder()",source[source.index(
            '    elif d.startswith("hpeg_m4_"):'
        ):source.index('    elif d.startswith("hpeg_transfer_"):')])


if __name__=="__main__":
    unittest.main()
