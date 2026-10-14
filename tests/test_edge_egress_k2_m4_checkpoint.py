"""M4 persisted operator checkpoint: restart, replay, concurrency, forged progress."""
from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from edge_egress_k2_m3_waves import (
    build_wave_plan,sign_wave_approval,WaveProgress,WaveReport,
)
from edge_egress_k2_m4_checkpoint import (
    CheckpointHold,DurableWaveCheckpoint,install_checkpoint_schema,
)
from tests.test_edge_egress_k2_migration_inventory import (
    K2M1InventoryTests,NOW,
)

SECRET=b"test-checkpoint-only-"+b"a"*32


class M4CheckpointTests(unittest.TestCase):
    def setUp(self):
        fx=K2M1InventoryTests()
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        self.fx=fx
        self.plan=build_wave_plan(fx.preview())
        self.approval=sign_wave_approval(
            self.plan,actor_id=11,chat_id=-222,expires_at=NOW+90,
            secret=SECRET,now=NOW,operator_authorized=True,
        )
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db=Path(temp.name)/"core.db"

        @contextmanager
        def connect():
            conn=sqlite3.connect(str(self.db),timeout=2,isolation_level=None)
            try:
                yield conn
                conn.commit()
            except BaseException:
                conn.rollback()
                raise
            finally:
                conn.close()
        self.connect=connect
        with connect() as c:
            c.execute("CREATE TABLE failover_operations("
                      "id INTEGER PRIMARY KEY,status TEXT)")
            install_checkpoint_schema(c)
        self.port=DurableWaveCheckpoint(
            db_conn=connect,geteuid=lambda:0,
            clock=lambda:NOW,release_enabled=True,
        )
        self.flag=patch(
            "edge_egress_k2_m4_checkpoint.M4_CHECKPOINT_RELEASE_ENABLED",True)
        self.flag.start()
        self.addCleanup(self.flag.stop)

    def begin(self):
        self.port.prepare(self.plan,self.approval)
        self.port.begin(self.plan,self.approval,
                        actor_id=11,chat_id=-222)

    def test_disabled_flag_prevents_root_write(self):
        with patch("edge_egress_k2_m4_checkpoint.M4_CHECKPOINT_RELEASE_ENABLED",
                   False):
            with self.assertRaisesRegex(CheckpointHold,"NOT_RELEASED"):
                self.port.prepare(self.plan,self.approval)
        with self.connect() as c:
            self.assertEqual(c.execute(
                "SELECT COUNT(*) FROM k2_m4_wave_checkpoints"
            ).fetchone(),(0,))

    def test_replayed_confirmation_rejected_after_new_process(self):
        self.begin()
        restarted=DurableWaveCheckpoint(
            db_conn=self.connect,geteuid=lambda:0,
            clock=lambda:NOW,release_enabled=True,
        )
        with self.assertRaisesRegex(CheckpointHold,"CONSUMED|UNRESOLVED"):
            restarted.begin(self.plan,self.approval,actor_id=11,chat_id=-222)
        view=restarted.inspect(self.plan,self.approval)
        self.assertEqual(view.state,"UNKNOWN_INFLIGHT")
        self.assertEqual(view.usernames,("nvl0555",))

    def test_inflight_wave_blocks_second_wave_across_restart(self):
        self.begin()
        other=sign_wave_approval(
            self.plan,actor_id=12,chat_id=-333,expires_at=NOW+90,
            secret=SECRET,now=NOW,operator_authorized=True)
        self.port.prepare(self.plan,other)
        with self.assertRaisesRegex(CheckpointHold,"ANOTHER_WAVE|UNRESOLVED"):
            self.port.begin(self.plan,other,actor_id=12,chat_id=-333)
        self.assertEqual(self.port.inspect(self.plan,self.approval).state,
                         "UNKNOWN_INFLIGHT")

    def test_wrong_actor_expired_or_nonce_cannot_begin(self):
        self.port.prepare(self.plan,self.approval)
        with self.assertRaisesRegex(CheckpointHold,"CONSUMED"):
            self.port.begin(self.plan,self.approval,actor_id=12,chat_id=-222)
        with self.assertRaisesRegex(CheckpointHold,"CONSUMED"):
            self.port.begin(self.plan,self.approval,actor_id=11,chat_id=-223)
        self.port.clock=lambda:NOW+91
        with self.assertRaisesRegex(CheckpointHold,"CONSUMED"):
            self.port.begin(self.plan,self.approval,actor_id=11,chat_id=-222)
        self.assertEqual(self.port.inspect(self.plan,self.approval).state,
                         "EXPIRED")

    def test_original_6g_busy_prevents_checkpoint_transition(self):
        self.port.prepare(self.plan,self.approval)
        with self.connect() as c:
            c.execute("INSERT INTO failover_operations VALUES(7,'RUNNING')")
        with self.assertRaisesRegex(CheckpointHold,"6G_BUSY"):
            self.port.begin(self.plan,self.approval,actor_id=11,chat_id=-222)
        with self.connect() as c:
            c.execute("DELETE FROM failover_operations")
        self.port.begin(self.plan,self.approval,actor_id=11,chat_id=-222)

    def test_verified_terminal_is_projection_not_route_proof(self):
        self.begin()
        p=self.plan.members[0]
        report=WaveReport(self.plan.digest,
                          (WaveProgress(p.username,p.uid,"VERIFIED",
                                        "P3_6G_COMMITTED",41),),
                          False,"",True)
        self.port.record_verified(self.plan,self.approval,
                                  p.username,p.uid,41)
        self.port.finish(self.plan,self.approval,report)
        view=self.port.inspect(self.plan,self.approval)
        self.assertEqual(view.state,"SUCCEEDED")
        self.assertEqual(view.progress,(("nvl0555","VERIFIED",41),))
        with self.assertRaisesRegex(CheckpointHold,"CONSUMED"):
            self.port.begin(self.plan,self.approval,actor_id=11,chat_id=-222)

    def test_uid_checkpoint_survives_restart_before_next_uid(self):
        self.begin()
        p=self.plan.members[0]
        self.port.record_verified(self.plan,self.approval,
                                  p.username,p.uid,41)
        restarted=DurableWaveCheckpoint(
            db_conn=self.connect,geteuid=lambda:0,
            clock=lambda:NOW,release_enabled=True,
        )
        view=restarted.inspect(self.plan,self.approval)
        self.assertEqual(view.state,"UNKNOWN_INFLIGHT")
        self.assertEqual(view.progress,(("nvl0555","VERIFIED",41),))
        with self.assertRaisesRegex(CheckpointHold,"PROGRESS_LENGTH"):
            restarted.record_verified(self.plan,self.approval,
                                      p.username,p.uid,41)

    def test_uid_progress_tampering_rejected_on_terminal(self):
        self.begin()
        p=self.plan.members[0]
        report=WaveReport(
            self.plan.digest,
            (WaveProgress(p.username,p.uid,"VERIFIED","P3_6G_COMMITTED",41),),
            False,"",True,
        )
        with self.assertRaisesRegex(CheckpointHold,"NOT_CONSISTENT"):
            self.port.finish(self.plan,self.approval,report)
        self.assertEqual(self.port.inspect(self.plan,self.approval).state,
                         "UNKNOWN_INFLIGHT")

    def test_forged_user_or_missing_operation_id_cannot_commit(self):
        self.begin()
        p=self.plan.members[0]
        for bad in (
            WaveReport(self.plan.digest,
                (WaveProgress("other",p.uid,"VERIFIED","x",4),),False,"",True),
            WaveReport(self.plan.digest,
                (WaveProgress(p.username,p.uid,"VERIFIED","x",None),),False,"",True),
            WaveReport(self.plan.digest,
                (WaveProgress(p.username,p.uid,"DEFERRED","x"),),False,"",True),
        ):
            with self.assertRaisesRegex(CheckpointHold,"NOT_VERIFIABLE"):
                self.port.finish(self.plan,self.approval,bad)
        self.assertEqual(self.port.inspect(self.plan,self.approval).state,
                         "UNKNOWN_INFLIGHT")

    def test_exception_holds_without_releasing_original_6g(self):
        self.begin()
        with self.connect() as c:
            c.execute("INSERT INTO failover_operations VALUES(17,'RUNNING')")
        self.port.hold(self.plan,self.approval)
        self.assertEqual(self.port.inspect(self.plan,self.approval).state,"HOLD")
        with self.connect() as c:
            self.assertEqual(c.execute(
                "SELECT status FROM failover_operations WHERE id=17"
            ).fetchone(),("RUNNING",))
        with self.assertRaisesRegex(CheckpointHold,"HOLD_ONLY"):
            self.port.hold(self.plan,self.approval)

    def test_batch_first_uid_persists_and_later_uid_holds(self):
        batch=build_wave_plan(
            self.fx.preview(("nvl0555","nvl0557"),"BATCH"))
        approval=sign_wave_approval(
            batch,actor_id=11,chat_id=-222,expires_at=NOW+110,
            secret=SECRET,now=NOW,operator_authorized=True,
        )
        self.port.prepare(batch,approval)
        self.port.begin(batch,approval,actor_id=11,chat_id=-222)
        first,second=batch.members
        self.port.record_verified(
            batch,approval,first.username,first.uid,111)
        crash_view=self.port.inspect(batch,approval)
        self.assertEqual(crash_view.state,"UNKNOWN_INFLIGHT")
        self.assertEqual(crash_view.progress,
                         ((first.username,"VERIFIED",111),))
        report=WaveReport(
            batch.digest,
            (WaveProgress(first.username,first.uid,"VERIFIED",
                          "P3_6G_COMMITTED",111),
             WaveProgress(second.username,second.uid,"HOLD",
                          "M3_F4_DRIFT")),
            True,"M3_F4_DRIFT",False,
        )
        self.port.finish(batch,approval,report)
        final=self.port.inspect(batch,approval)
        self.assertEqual(final.state,"HOLD")
        self.assertEqual(final.progress[0][2],111)
        self.assertEqual(final.progress[1][1],"HOLD")
        with self.assertRaises(CheckpointHold):
            self.port.begin(batch,approval,actor_id=11,chat_id=-222)

    def test_corrupt_stage_does_not_look_successful(self):
        self.begin()
        with self.connect() as c:
            c.execute("UPDATE k2_m4_wave_checkpoints "
                      "SET progress_json='[false, 1]'")
        with self.assertRaises(CheckpointHold):
            self.port.inspect(self.plan,self.approval)


if __name__=="__main__":
    unittest.main()
