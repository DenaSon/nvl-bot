"""M4 privileged portal: never trust Telegram memory, fake admin or F4."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from edge_egress_k2_m4_root_portal import (
    M4_ROOT_PORTAL_ENABLED,RootMigrationPortal,RootPortalHold,
)
from edge_egress_k2_m4_checkpoint import (
    DurableWaveCheckpoint, install_checkpoint_schema,
)
from edge_egress_k2_migration_inventory import (
    select_migration,LiveIngressWitness,
)
from edge_egress_k2_m3_waves import MigrationWaveHold
from edge_egress_p3_executor import (
    ExecutionScope,ExecutionTicket,ExecutionReceipt,_scope_digest,
)
from tests.test_edge_egress_k2_migration_inventory import (
    K2M1InventoryTests,NOW,SOURCE,TARGET,
)
SECRET=b"test-only-root-secret-"+b"q"*32


class M4RootPortalTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.fx=K2M1InventoryTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        install_checkpoint_schema(self.fx.c)
        self.actions=[]
        self.clock=lambda:NOW
        self.admin=lambda actor,chat:actor==11 and chat==-222
        self.witness=lambda n:LiveIngressWitness(
            n,"e9",TARGET,NOW-1,"INDEPENDENT_LIVE",
        )
        self.review=lambda sel:self.fx.preview(
            sel.usernames,sel.mode,ingress_witness=self.witness,
        )
        self.selection=select_migration("SINGLE",("nvl0555",),"e9")
        def ticket(scope,actor,chat):
            self.actions.append("ticket")
            return ExecutionTicket(actor,chat,"b"*32,NOW+100,
                                   _scope_digest(scope),"c"*64)
        async def run(scope,t,actor,chat):
            self.actions.append("mutation")
            return ExecutionReceipt(True,"SUCCEEDED",41)
        self.portal=RootMigrationPortal(
            root_secret=SECRET,review=self.review,
            admin_authorized=self.admin,
            independent_physical_f4=lambda plan:True,
            current_protected_mode=lambda:"0",
            issue_single_ticket=ticket,execute_single=run,
            committed_6g=lambda scope,t,op:True,
            checkpoint=DurableWaveCheckpoint(
                db_conn=self.fx.db,geteuid=lambda:0,
                clock=self.clock,release_enabled=True,
            ),
            clock=self.clock,geteuid=lambda:0,release_enabled=True,
        )

    def test_disabled_flag_never_prepares_or_executes(self):
        self.assertFalse(M4_ROOT_PORTAL_ENABLED)
        with self.assertRaisesRegex(RootPortalHold,"RELEASE"):
            self.portal.prepare(self.selection,actor_id=11,chat_id=-222)
        self.assertEqual(self.actions,[])

    def test_wrong_admin_chat_and_nonroot_are_fail_closed(self):
        with patch("edge_egress_k2_m4_root_portal.M4_ROOT_PORTAL_ENABLED",True), \
             patch("edge_egress_k2_m4_checkpoint.M4_CHECKPOINT_RELEASE_ENABLED",True):
            for actor,chat in ((12,-222),(11,-333)):
                with self.assertRaisesRegex(RootPortalHold,"SUPERADMIN"):
                    self.portal.prepare(self.selection,actor_id=actor,chat_id=chat)
            self.portal.geteuid=lambda:1000
            with self.assertRaisesRegex(RootPortalHold,"RELEASE"):
                self.portal.prepare(self.selection,actor_id=11,chat_id=-222)
        self.assertEqual(self.actions,[])

    def test_cross_edge_legacy_cannot_consume_operator_approval(self):
        # A read-only M1 plan can show a cross-edge source, but the live M4
        # host adapter only supports same-edge UID_ENROLL_SOURCE. Source
        # preview must NEVER be confused with an executable UID_ATTACH.
        self.witness=lambda n:LiveIngressWitness(
            n,"s8",SOURCE,NOW-1,"INDEPENDENT_LIVE",
        )
        with patch("edge_egress_k2_m4_root_portal.M4_ROOT_PORTAL_ENABLED",True), \
             patch("edge_egress_k2_m4_checkpoint.M4_CHECKPOINT_RELEASE_ENABLED",True):
            with self.assertRaisesRegex(RootPortalHold,"CROSS_EDGE_ATTACH"):
                self.portal.prepare(self.selection,actor_id=11,chat_id=-222)
        self.assertEqual(self.fx.c.execute(
            "SELECT COUNT(*) FROM k2_m4_wave_checkpoints"
        ).fetchone(),(0,))
        self.assertEqual(self.actions,[])

    def test_cross_edge_single_m4_requires_root_release_and_signed_physical_f4(self):
        self.witness=lambda n:LiveIngressWitness(
            n,"s8",SOURCE,NOW-1,"INDEPENDENT_LIVE",
        )
        with patch("edge_egress_k2_m4_root_portal.M4_ROOT_PORTAL_ENABLED",True),\
             patch("edge_egress_k2_m4_root_portal.M4_CROSS_EDGE_SINGLE_ENABLED",True),\
             patch("edge_egress_k2_m4_checkpoint.M4_CHECKPOINT_RELEASE_ENABLED",True):
            self.portal.physical_f4=lambda plan:False
            with self.assertRaisesRegex(RootPortalHold,"PHYSICAL_F4"):
                self.portal.prepare(self.selection,actor_id=11,chat_id=-222)
            self.assertEqual(self.fx.c.execute(
                "SELECT COUNT(*) FROM k2_m4_wave_checkpoints"
            ).fetchone(),(0,))
            self.portal.physical_f4=lambda plan:True
            prepared=self.portal.prepare(
                self.selection,actor_id=11,chat_id=-222)
            self.assertEqual(prepared.plan.selection.mode,"SINGLE")
            self.assertEqual(prepared.plan.members[0].source_edge_id,"s8")
            self.assertEqual(self.actions,[])

    def test_cross_edge_batch_cannot_prepare_even_with_single_gate(self):
        self.witness=lambda n:LiveIngressWitness(
            n,"s8",SOURCE,NOW-1,"INDEPENDENT_LIVE",
        )
        selection=select_migration(
            "BATCH",("nvl0555","nvl0557"),"e9",
        )
        with patch("edge_egress_k2_m4_root_portal.M4_ROOT_PORTAL_ENABLED",True),\
             patch("edge_egress_k2_m4_root_portal.M4_CROSS_EDGE_SINGLE_ENABLED",True),\
             patch("edge_egress_k2_m4_checkpoint.M4_CHECKPOINT_RELEASE_ENABLED",True):
            with self.assertRaisesRegex(RootPortalHold,"CROSS_EDGE_ATTACH"):
                self.portal.prepare(selection,actor_id=11,chat_id=-222)
        self.assertEqual(self.actions,[])

    def test_wrong_protected_mode_denied_before_durable_prepare(self):
        self.portal.current_protected_mode=lambda:"1"
        with patch("edge_egress_k2_m4_root_portal.M4_ROOT_PORTAL_ENABLED",True), \
             patch("edge_egress_k2_m4_checkpoint.M4_CHECKPOINT_RELEASE_ENABLED",True):
            with self.assertRaisesRegex(RootPortalHold,"REQUIRES_LEGACY_MODE"):
                self.portal.prepare(self.selection,actor_id=11,chat_id=-222)
        self.assertEqual(self.fx.c.execute(
            "SELECT COUNT(*) FROM k2_m4_wave_checkpoints"
        ).fetchone(),(0,))
        self.assertEqual(self.actions,[])

    async def test_mode_drift_after_prepare_holds_before_6g(self):
        with patch("edge_egress_k2_m4_root_portal.M4_ROOT_PORTAL_ENABLED",True), \
             patch("edge_egress_k2_m4_checkpoint.M4_CHECKPOINT_RELEASE_ENABLED",True):
            prepared=self.portal.prepare(
                self.selection,actor_id=11,chat_id=-222)
            self.portal.current_protected_mode=lambda:"1"
            with self.assertRaisesRegex(RootPortalHold,"MODE_CHANGED"):
                await self.portal.execute(
                    prepared,actor_id=11,chat_id=-222)
        self.assertEqual(self.fx.c.execute(
            "SELECT state FROM k2_m4_wave_checkpoints"
        ).fetchone(),("PREPARED",))
        self.assertEqual(self.actions,[])

    def test_fake_packet_f4_never_yields_signed_approval(self):
        self.portal.physical_f4=lambda plan:False
        with patch("edge_egress_k2_m4_root_portal.M4_ROOT_PORTAL_ENABLED",True), \
             patch("edge_egress_k2_m4_checkpoint.M4_CHECKPOINT_RELEASE_ENABLED",True):
            with self.assertRaisesRegex(RootPortalHold,"PHYSICAL_F4"):
                self.portal.prepare(self.selection,actor_id=11,chat_id=-222)
        self.assertEqual(self.actions,[])

    async def test_one_use_approval_tamper_and_changed_snapshot(self):
        with patch("edge_egress_k2_m4_root_portal.M4_ROOT_PORTAL_ENABLED",True), \
             patch("edge_egress_k2_m4_checkpoint.M4_CHECKPOINT_RELEASE_ENABLED",True):
            prepared=self.portal.prepare(
                self.selection,actor_id=11,chat_id=-222)
            self.witness=lambda n:LiveIngressWitness(
                n,"e9",TARGET,NOW-1,"INDEPENDENT_LIVE",
            )
            with patch("edge_egress_k2_m4_root_portal.M4_ROOT_PORTAL_ENABLED",
                       True),patch("edge_egress_k2_m4_checkpoint.M4_CHECKPOINT_RELEASE_ENABLED",True), \
             patch("edge_egress_k2_m3_waves.M3_WAVE_EXECUTION_ENABLED",True):
                out=await self.portal.execute(
                    prepared,actor_id=11,chat_id=-222)
                self.assertTrue(out.all_verified)
                self.assertEqual(self.actions,["ticket","mutation"])
                with self.assertRaisesRegex(Exception,"CONSUMED"):
                    await self.portal.execute(
                        prepared,actor_id=11,chat_id=-222)

    async def test_snapshot_drift_rejected_before_p3_ticket(self):
        with patch("edge_egress_k2_m4_root_portal.M4_ROOT_PORTAL_ENABLED",True), \
             patch("edge_egress_k2_m4_checkpoint.M4_CHECKPOINT_RELEASE_ENABLED",True):
            prepared=self.portal.prepare(
                self.selection,actor_id=11,chat_id=-222)
            self.fx.uids["nvl0555"]=2999
            with self.assertRaisesRegex(RootPortalHold,"CHANGED"):
                await self.portal.execute(
                    prepared,actor_id=11,chat_id=-222)
        self.assertEqual(self.actions,[])

    def test_secret_never_part_of_bare_telegram_action(self):
        self.assertNotIn("ticket",str(self.selection))
        self.assertNotIn("root-secret",str(self.selection))


if __name__=="__main__":
    unittest.main()
