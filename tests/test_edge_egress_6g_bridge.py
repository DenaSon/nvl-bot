"""D1-C2B2: exercise real SQLite Phase-6G-shaped adapter, no real hosts.

Host endpoints are in-memory fakes; all SQL uses a temporary DB file.
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from edge_egress_6g_bridge import Existing6GPreparationAdapter
from edge_egress_inventory import ensure_schema
from edge_egress_prepare import prepare_edge_stage_only
from edge_egress_handoff import is_egress_recovery_hold

from test_edge_egress_prepare import FakeHost, spec


class DatabaseHarness:
    def __init__(self,path):
        self.path=path
        with self.connection() as conn:
            conn.executescript("""
            CREATE TABLE failover_operations(
              id INTEGER PRIMARY KEY AUTOINCREMENT, source_host TEXT,
              target_host TEXT, status TEXT, updated_at TEXT, detail_json TEXT);
            CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
            INSERT INTO settings(key,value)
              VALUES ('dns_current_ip','172.86.94.174');
            CREATE TABLE host_pool(
              host TEXT PRIMARY KEY, active INTEGER, is_default INTEGER,
              is_standby INTEGER, service_port INTEGER);
            INSERT INTO host_pool VALUES
              ('172.86.94.174',1,1,0,2252),
              ('216.126.229.12',1,0,1,2252);
            CREATE TABLE ssh_accounts(
              username TEXT PRIMARY KEY, host TEXT,
              service_type TEXT, status TEXT);
            INSERT INTO ssh_accounts VALUES
              ('nvl0557','172.86.94.174','ssh','🟢 فعال');
            """)
            ensure_schema(conn)

    @contextmanager
    def connection(self):
        conn=sqlite3.connect(self.path,timeout=5)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def acquire(self,source,target):
        with self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            busy=conn.execute(
                "SELECT id FROM failover_operations WHERE status='RUNNING'"
            ).fetchone()
            if busy:
                return None,busy[0]
            cur=conn.execute(
                "INSERT INTO failover_operations(source_host,target_host,status,updated_at) "
                "VALUES (?,?,'RUNNING','today')",(source,target),
            )
            return cur.lastrowid,None

    def update(self,operation_id,*,status,detail,finished):
        with self.connection() as conn:
            cur=conn.execute(
                "UPDATE failover_operations SET status=?,detail_json=? WHERE id=?",
                (status,json.dumps(detail),operation_id),
            )
            if cur.rowcount!=1:
                raise ValueError("unknown 6g lock")

    def row(self,query,*params):
        with self.connection() as c:
            return c.execute(query,params).fetchone()


class BridgeIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.h=DatabaseHarness(str(Path(self.temp.name)/"nvldb.sqlite"))
        self.events=[]
        self.core=FakeHost("core",self.events)
        self.edge=FakeHost("edge",self.events)
        def factory(role,ip):
            if role=="core":
                self.assertEqual(ip,"209.200.246.198")
                return self.core
            self.assertEqual((role,ip),("edge","216.126.229.12"))
            return self.edge
        self.factory=factory

    def tearDown(self):
        self.temp.cleanup()

    def adapter(self,**kwargs):
        return Existing6GPreparationAdapter(
            self.h.connection,self.h.acquire,self.h.update,
            host_factory=kwargs.get("factory",self.factory))

    def execute(self,bridge):
        return asyncio.run(prepare_edge_stage_only(
            bridge,spec=spec(),source_host="172.86.94.174"
        ))

    def test_full_staging_with_real_sqlite_shared_lock_and_unique_registry(self):
        bridge=self.adapter()
        r=self.execute(bridge)
        self.assertTrue(r.ok,r.reason)
        self.assertEqual(r.state,"STAGED")
        self.assertEqual(self.h.row(
            "SELECT status FROM edge_egress_allocations WHERE edge_id='fra1'"
        )[0],"STAGED")
        result=self.h.row(
            "SELECT status,detail_json FROM failover_operations WHERE id=?",
            r.operation_id
        )
        self.assertEqual(result[0],"SUCCEEDED")
        self.assertEqual(json.loads(result[1])["phase"],"STAGED_ONLY")
        self.assertEqual(self.h.row(
            "SELECT host FROM host_pool WHERE is_default=1"
        )[0],"172.86.94.174")
        self.assertEqual(self.h.row(
            "SELECT host FROM ssh_accounts WHERE username='nvl0557'"
        )[0],"172.86.94.174")
        self.assertEqual(self.h.row(
            "SELECT value FROM settings WHERE key='dns_current_ip'"
        )[0],"172.86.94.174")
        self.assertNotIn("private_key",result[1])
        self.assertFalse(is_egress_recovery_hold(result[1]))

    def test_lock_busy_prevents_any_host_calls(self):
        self.h.acquire("172.86.94.174","216.126.229.12")
        r=self.execute(self.adapter())
        self.assertEqual(r.reason,"SHARED_6G_OPERATION_BUSY")
        self.assertEqual(self.events,[])

    def test_no_default_live_host_transport_refuses_without_side_effect(self):
        r=self.execute(self.adapter(factory=None))
        self.assertFalse(r.ok)
        self.assertEqual(r.state,"NOT_STAGED")
        self.assertEqual(self.h.row(
            "SELECT count(*) FROM edge_egress_allocations"
        )[0],0)

    def test_wrong_service_port_blocks_before_keys_and_reservation(self):
        with self.h.connection() as conn:
            conn.execute(
                "UPDATE host_pool SET service_port=2022 WHERE host='216.126.229.12'"
            )
        r=self.execute(self.adapter())
        self.assertFalse(r.ok)
        self.assertEqual(self.events,[])
        self.assertEqual(self.h.row(
            "SELECT count(*) FROM edge_egress_allocations"
        )[0],0)

    def test_global_multi_edge_owner_rejected(self):
        with self.h.connection() as conn:
            conn.execute(
                "INSERT INTO ssh_accounts VALUES (?,?,?,?)",
                ("other","216.126.229.12","ssh","🟢 فعال")
            )
        r=self.execute(self.adapter())
        self.assertFalse(r.ok)
        self.assertEqual(self.events,[])

    def test_changed_dns_blocks_staging_before_read_only_preflight(self):
        with self.h.connection() as conn:
            conn.execute(
                "UPDATE settings SET value='209.200.246.198' "
                "WHERE key='dns_current_ip'"
            )
        r=self.execute(self.adapter())
        self.assertFalse(r.ok)
        self.assertEqual(self.events,[])

    def test_stage_failure_cleanup_in_same_shared_lock(self):
        self.core.error_at="stage"
        r=self.execute(self.adapter())
        self.assertFalse(r.ok)
        self.assertIn("core:discard",self.events)
        self.assertEqual(self.h.row(
            "SELECT status FROM failover_operations WHERE id=?",
            r.operation_id
        )[0],"FAILED")

    def test_cleanup_failure_keeps_shared_6g_lock_fenced(self):
        self.core.error_at="stage"
        self.core.cleanup_error=True
        r=self.execute(self.adapter())
        self.assertTrue(r.requires_recovery)
        operation=self.h.row(
            "SELECT status,detail_json FROM failover_operations WHERE id=?",
            r.operation_id
        )
        self.assertEqual(operation[0],"RUNNING")
        self.assertTrue(is_egress_recovery_hold(operation[1]))

    def test_standalone_registry_never_replaces_current_host_pool(self):
        r=self.execute(self.adapter())
        self.assertTrue(r.ok)
        edge=self.h.row(
            "SELECT edge_public_ipv4,core_public_ipv4 FROM edge_egress_allocations "
            "WHERE edge_id='fra1'"
        )
        self.assertEqual(edge,("216.126.229.12","209.200.246.198"))
        self.assertEqual(self.h.row("SELECT count(*) FROM host_pool")[0],2)


if __name__=="__main__":
    unittest.main()
