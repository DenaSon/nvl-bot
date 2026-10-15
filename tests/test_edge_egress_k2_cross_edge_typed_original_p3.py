"""Typed single Cross-Edge M1 -> original P3/F2 -> root PAM policy -> M1.

This exercises the actual GuardedCrossEdgeUIDPort, real original SQLite
6G intent+nonce, P3 UID lifecycle and F2 CAS, on disposable files.
The system kernel, SSH/PAM, WG and external packet measurement are fake.
NEVER claim physical VPS egress acceptance from these tests.
"""
import asyncio
from contextlib import ExitStack
import time
import unittest
from unittest.mock import patch

from edge_egress_k2_m3_waves import build_wave_plan
from edge_egress_k2_m4_cross_edge_port import (
    GuardedCrossEdgeUIDPort, CrossEdgeUIDHold,
)
from edge_egress_k2_migration_inventory import (
    LiveIngressWitness, preview_migration, select_migration,
)
from edge_egress_uid_runtime_store import read_binding
from tests.test_edge_egress_k2_cross_edge_p3_stage import (
    OriginalP3CrossEdgeStagingTests,
)
from tests.test_edge_egress_uid_runtime_store import SOURCE, TARGET


class TypedOriginalP3CrossEdgeTests(unittest.TestCase):
    def setUp(self):
        self.h=OriginalP3CrossEdgeStagingTests(
            methodName="test_p3_stages_future_policy_after_packet_before_f2_commit"
        )
        self.h.setUp()
        self.addCleanup(self.h.doCleanups)
        self.scope=self.h.harness.scope
        self.ticket=self.h.harness.ticket
        # Use the actual immutable member from original M1 plan, never
        # synthesize historical/source fields that can silently disagree.
        self.member=build_wave_plan(
            self.preview(select_migration("SINGLE",("nvl0557",),"fra1")),
            wave_size=1,
        ).members[0]
        self.port=GuardedCrossEdgeUIDPort(
            member=self.member,scope=self.scope,ticket=self.ticket,
            uid_port=self.h.port,db_conn=self.h.base.conn_factory,
            live_inventory=self.preview,release_enabled=True,
        )

    def preview(self,selection):
        observed_at=int(time.time())-1
        return preview_migration(
            db_conn=self.h.base.conn_factory,selection=selection,
            os_uid=self.h.base.unix_lookup,
            ingress_witness=lambda name:LiveIngressWitness(
                name,"s8",SOURCE,observed_at,"INDEPENDENT_LIVE"
            ),
            session_count=lambda name,uid:0,
            now=observed_at+1,
            trusted_ingress_peers=(self.h.harness.peer,),
        )

    def _gates(self):
        stack=ExitStack()
        stack.enter_context(self.h.pinned())
        stack.enter_context(patch(
            "edge_egress_k2_m4_cross_edge_port.M4_CROSS_EDGE_UID_PORT_ENABLED",
            True,
        ))
        return stack

    def test_original_p3_cross_edge_full_positive_f2_and_pam_policy(self):
        selection=select_migration("SINGLE",("nvl0557",),"fra1")
        before=self.preview(selection)
        chosen=[a for a in before.accounts if a.selected][0]
        self.assertEqual(chosen.issues,(),chosen.issues)
        with self._gates():
            asyncio.run(self.port.apply(self.scope))
            self.assertTrue(asyncio.run(self.port.verify(self.scope)))
        with self.h.base.db() as db:
            binding=read_binding(db,"nvl0557")
            self.assertEqual((binding.state,binding.generation),
                             ("PROTECTED",3))
            self.assertEqual(db.execute(
                "SELECT value FROM settings "
                "WHERE key='edge_egress_protected_mode'"
            ).fetchone(),("0",))
            self.assertEqual(db.execute(
                "SELECT host FROM ssh_accounts WHERE username='nvl0557'"
            ).fetchone(),(SOURCE,))
        after=self.preview(selection)
        chosen_after=[a for a in after.accounts if a.selected][0]
        self.assertEqual(chosen_after.issues,(
            "TARGET_ALREADY_PROTECTED","PROTECTED_SOURCE_DRIFT",
        ))
        self.assertEqual(chosen_after.protected_edge_id,"fra1")
        self.assertEqual(self.h.base.safety.events.count("packet"),2)

    def test_cross_edge_adapter_release_off_refuses_even_current_6g(self):
        before=self.preview(select_migration("SINGLE",("nvl0557",),"fra1"))
        self.assertEqual(next(a.issues for a in before.accounts if a.selected),())
        with self.h.pinned():
            with self.assertRaisesRegex(CrossEdgeUIDHold,"NOT_RELEASED"):
                asyncio.run(self.port.apply(self.scope))
        self.assertIsNone(self.h.base.binding())


if __name__=="__main__":
    unittest.main()
