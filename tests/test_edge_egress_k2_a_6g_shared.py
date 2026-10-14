"""Package A: one shared 6G SQL implementation, strict K2 root reuse.

Tests touch a throwaway SQLite file only.
"""
from __future__ import annotations
from contextlib import contextmanager
from datetime import datetime,timedelta
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from edge_egress_k2_a_6g_shared import (
    acquire_original_6g, update_original_6g, Original6GRootCallbacks,
)
from safe_failover import (
    FAILOVER_MODE_MANUAL, FAILOVER_STATUS_RUNNING,
    FAILOVER_STATUS_ABORTED_STALE,
)


NOW=datetime(2026,10,15,0,0,0)


class CommonOriginal6GTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path=Path(temp.name)/"original-core.sqlite"
        with self.db() as conn:
            conn.execute(
                "CREATE TABLE failover_operations ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "mode TEXT,source_host TEXT,target_host TEXT,"
                "status TEXT,started_at TEXT,updated_at TEXT,"
                "finished_at TEXT,error TEXT,detail_json TEXT,"
                "account_count INTEGER,moved_count INTEGER,"
                "previous_default_host TEXT,previous_dns_ip TEXT,"
                "core_fallback_ip TEXT)"
            )

    @contextmanager
    def db(self):
        conn=sqlite3.connect(str(self.path),timeout=3)
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def acquire(self, *, stale=False):
        return acquire_original_6g(
            self.db,"1.1.1.1","8.8.8.8",
            stale_seconds=1800,parse_datetime=datetime.fromisoformat,
            clock=lambda:NOW,allow_legacy_stale_recovery=stale,
        )

    def test_both_legacy_and_root_share_same_original_table(self):
        op,busy=self.acquire()
        self.assertEqual((op,busy),(1,None))
        adapter=Original6GRootCallbacks(self.db)
        self.assertEqual(adapter.acquire("1.1.1.1","8.8.8.8"),(None,1))
        self.assertEqual(self.acquire(),(None,1))
        adapter.journal(
            op,status="RUNNING",detail={"phase":"EGRESS_P3_EXECUTE_INTENT"},
            require_running=True,finished=False,
        )
        with self.db() as conn:
            row=conn.execute(
                "SELECT status,detail_json FROM failover_operations WHERE id=?",
                (op,),
            ).fetchone()
        self.assertEqual(row[0],FAILOVER_STATUS_RUNNING)
        self.assertEqual(json.loads(row[1])["phase"],"EGRESS_P3_EXECUTE_INTENT")
        adapter.journal(
            op,status="SUCCEEDED",
            detail={"phase":"EGRESS_P3_VERIFIED"},
            require_running=True,finished=True,
        )
        with self.db() as conn:
            result=conn.execute(
                "SELECT status,finished_at FROM failover_operations WHERE id=?",
                (op,),
            ).fetchone()
        self.assertEqual(result[0],"SUCCEEDED")
        self.assertIsNotNone(result[1])
        with self.assertRaisesRegex(RuntimeError,"NO_LONGER_RUNNING"):
            adapter.journal(
                op,status="SUCCEEDED",detail={"phase":"EGRESS_P3_VERIFIED"},
                require_running=True,finished=True,
            )

    def test_strict_root_does_not_steal_legacy_stale_lease(self):
        ancient=(NOW-timedelta(days=10)).strftime("%Y-%m-%d %H:%M:%S")
        with self.db() as conn:
            conn.execute(
                "INSERT INTO failover_operations "
                "(mode,source_host,target_host,status,started_at,updated_at) "
                "VALUES (?,?,?,?,?,?)",
                (FAILOVER_MODE_MANUAL,"1.1.1.1","8.8.8.8",
                 FAILOVER_STATUS_RUNNING,ancient,ancient),
            )
        root=Original6GRootCallbacks(self.db)
        self.assertEqual(root.acquire("1.1.1.1","8.8.8.8"),(None,1))
        with self.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM failover_operations"
            ).fetchone()[0],1)
            self.assertEqual(conn.execute(
                "SELECT status FROM failover_operations"
            ).fetchone()[0],FAILOVER_STATUS_RUNNING)
        new,_=self.acquire(stale=True)
        self.assertEqual(new,2)
        with self.db() as conn:
            statuses=conn.execute(
                "SELECT status FROM failover_operations ORDER BY id"
            ).fetchall()
        self.assertEqual(statuses[0][0],FAILOVER_STATUS_ABORTED_STALE)
        self.assertEqual(statuses[1][0],FAILOVER_STATUS_RUNNING)

    def test_protected_recovery_never_stale_unlocked_by_legacy(self):
        ancient=(NOW-timedelta(days=10)).strftime("%Y-%m-%d %H:%M:%S")
        with self.db() as conn:
            conn.execute(
                "INSERT INTO failover_operations "
                "(mode,source_host,target_host,status,started_at,updated_at,"
                "detail_json) VALUES(?,?,?,?,?,?,?)",
                (FAILOVER_MODE_MANUAL,"1.1.1.1","8.8.8.8",
                 FAILOVER_STATUS_RUNNING,ancient,ancient,
                 json.dumps({"phase":"EGRESS_P3_RECOVERY_REQUIRED"})),
            )
        self.assertEqual(self.acquire(stale=True),(None,1))
        self.assertEqual(
            Original6GRootCallbacks(self.db).acquire("1.1.1.1","8.8.8.8"),
            (None,1),
        )

    def test_guarded_root_does_not_write_without_running_cas(self):
        adapter=Original6GRootCallbacks(self.db)
        with self.assertRaisesRegex(ValueError,"SCOPE"):
            adapter.journal(
                1,status="FAILED",detail={},finished=False,
                require_running=True,
            )
        with self.assertRaisesRegex(RuntimeError,"NO_LONGER_RUNNING"):
            adapter.journal(
                1,status="SUCCEEDED",detail={},finished=True,
                require_running=True,
            )
        with self.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM failover_operations"
            ).fetchone()[0],0)


if __name__=="__main__":
    unittest.main()
