"""K2 M4.4 crash/restart root-only checkpoint + original 6G forensic view."""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from edge_egress_k2_m44_recovery import (
    M44StatusHold, M44_ROOT_STATUS_ENABLED, inspect_root_recovery,
)
from edge_egress_p3_executor import ExecutionScope,_scope_digest
from edge_egress_k2_m3_waves import WaveProgress,WaveReport
from tests.test_edge_egress_k2_m4_checkpoint import M4CheckpointTests
from tests.test_edge_egress_k2_migration_inventory import NOW,TARGET


class M44RootRecoveryTests(unittest.TestCase):
    def setUp(self):
        fx=M4CheckpointTests()
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        self.fx=fx
        with fx.connect() as conn:
            for name in ("source_host","target_host","detail_json"):
                conn.execute("ALTER TABLE failover_operations ADD COLUMN "+name+" TEXT")
            conn.execute("CREATE TABLE edge_egress_allocations "
                         "(edge_id TEXT, edge_public_ipv4 TEXT)")
            conn.execute("INSERT INTO edge_egress_allocations VALUES(?,?)",
                         ("e9",TARGET))
        flag=patch("edge_egress_k2_m44_recovery.M44_ROOT_STATUS_ENABLED",True)
        flag.start()
        self.addCleanup(flag.stop)

    def inspect(self,actor=11,chat=-222,selection=None):
        return inspect_root_recovery(
            self.fx.connect, selection or self.fx.plan.selection,
            actor_id=actor,chat_id=chat,
            admin_authorized=lambda a,c:(a,c)==(11,-222),
            os_uid=lambda n:self.fx.fx.uids[n],
            clock=lambda:NOW,geteuid=lambda:0,release_enabled=True,
        )

    def put_receipt(self,*,valid=True,operation=41,status="SUCCEEDED"):
        s=ExecutionScope("UID_ENROLL_SOURCE","e9",TARGET,TARGET,
                         username="nvl0555",uid=1636)
        detail=dict(kind="K2_P3A",phase="EGRESS_P3_VERIFIED",
                    action=s.action,edge_id="e9",
                    scope_digest=_scope_digest(s) if valid else "0"*64,
                    nonce_hash="a"*64,manual_recovery=False)
        with self.fx.connect() as conn:
            conn.execute("INSERT INTO failover_operations "
                         "(id,status,source_host,target_host,detail_json) "
                         "VALUES(?,?,?,?,?)",(operation,status,TARGET,TARGET,
                                             json.dumps(detail)))

    def test_default_off_and_revoked_actor_no_data_read(self):
        self.assertFalse(M44_ROOT_STATUS_ENABLED)
        with patch("edge_egress_k2_m44_recovery.M44_ROOT_STATUS_ENABLED",False):
            with self.assertRaisesRegex(M44StatusHold,"NOT_RELEASED"):
                self.inspect()
        with self.assertRaisesRegex(M44StatusHold,"NOT_AUTHORIZED"):
            self.inspect(actor=20)

    def test_absent_checkpoint_is_unknown_not_idle_or_success(self):
        x=self.inspect()
        self.assertEqual(x.wave_state,"NO_CHECKPOINT")
        self.assertEqual(x.users[0].state,"UNKNOWN")
        self.assertFalse(x.unresolved)

    def test_persisted_running_survives_restart_and_blocks_new_approval(self):
        self.fx.begin()
        view=self.inspect()
        self.assertEqual(view.wave_state,"UNKNOWN_INFLIGHT")
        self.assertTrue(view.unresolved)
        with self.assertRaisesRegex(Exception,"UNRESOLVED"):
            self.fx.port.prepare(self.fx.plan,self.fx.approval)
        self.assertEqual(self.inspect().users[0].state,"UNKNOWN")

    def test_p3_scoped_receipt_not_promoted_to_packet_proof(self):
        self.fx.begin()
        self.put_receipt()
        self.fx.port.record_verified(
            self.fx.plan,self.fx.approval,"nvl0555",1636,41)
        x=self.inspect()
        self.assertEqual(x.wave_state,"UNKNOWN_INFLIGHT")
        self.assertEqual(x.users[0].state,"RECEIPT_SCOPED")
        p=self.fx.plan.members[0]
        report=WaveReport(
            self.fx.plan.digest,
            (WaveProgress(p.username,p.uid,"VERIFIED","P3_6G_COMMITTED",41),),
            False,"",True,
        )
        self.fx.port.finish(self.fx.plan,self.fx.approval,report)
        y=self.inspect()
        self.assertEqual(y.wave_state,"RECEIPTS_RECORDED")
        self.assertEqual(y.note,"REQUIRES_INDEPENDENT_PACKET_PROOF")
        self.assertFalse(y.unresolved)

    def test_forged_original_6g_scope_never_matches(self):
        self.fx.begin()
        self.put_receipt(valid=False)
        self.fx.port.record_verified(self.fx.plan,self.fx.approval,
                                     "nvl0555",1636,41)
        self.fx.port.finish(self.fx.plan,self.fx.approval,
            WaveReport(self.fx.plan.digest,
                (WaveProgress("nvl0555",1636,"VERIFIED","P3_6G_COMMITTED",41),),
                False,"",True))
        v=self.inspect()
        self.assertEqual(v.wave_state,"HOLD")
        self.assertTrue(v.unresolved)
        self.assertEqual(v.users[0].state,"RECEIPT_UNVERIFIED")

    def test_crashed_original_six_g_does_not_autounlock(self):
        self.fx.begin()
        with self.fx.connect() as conn:
            conn.execute("INSERT INTO failover_operations(id,status) "
                         "VALUES(27,'RUNNING')")
        v=self.inspect()
        self.assertTrue(v.original_6g_busy)
        self.assertEqual(v.wave_state,"UNKNOWN_INFLIGHT")
        with self.fx.connect() as conn:
            self.assertEqual(conn.execute(
                "SELECT status FROM failover_operations WHERE id=27"
            ).fetchone(),("RUNNING",))

    def test_terminal_hold_also_blocks_new_prepares(self):
        self.fx.begin()
        self.fx.port.hold(self.fx.plan,self.fx.approval)
        v=self.inspect()
        self.assertEqual(v.wave_state,"HOLD")
        self.assertTrue(v.unresolved)
        from edge_egress_k2_m3_waves import sign_wave_approval
        from tests.test_edge_egress_k2_m4_checkpoint import SECRET
        another=sign_wave_approval(self.fx.plan,actor_id=12,chat_id=-333,
                                   expires_at=NOW+90,secret=SECRET,now=NOW,
                                   operator_authorized=True)
        with self.assertRaisesRegex(Exception,"UNRESOLVED"):
            self.fx.port.prepare(self.fx.plan,another)

    def test_corrupt_progress_and_forced_uid_drift_fail_closed(self):
        self.fx.begin()
        with self.fx.connect() as conn:
            conn.execute("UPDATE k2_m4_wave_checkpoints SET progress_json='[false]'")
        with self.assertRaises(M44StatusHold):
            self.inspect()
        with self.fx.connect() as conn:
            conn.execute("UPDATE k2_m4_wave_checkpoints SET progress_json='[]'")
        self.assertEqual(self.inspect().wave_state,"UNKNOWN_INFLIGHT")

    def test_missing_original_6g_table_always_hold(self):
        with self.fx.connect() as conn:
            conn.execute("DROP TABLE failover_operations")
        with self.assertRaises(M44StatusHold):
            self.inspect()


if __name__=="__main__":
    unittest.main()
