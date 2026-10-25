"""CZ-07 offline queue tests: SQLite journal and fail-closed gates."""
from contextlib import contextmanager
from tempfile import TemporaryDirectory
from pathlib import Path
import sqlite3
import unittest

from cloudzy_cz07_queue import DurableCutoverQueue, CZ07Hold, BATCH_SIZE


class Fake04B:
    def __init__(self):
        self.source = "source.example"
        self.target = "target.example"
    def enabled(self):
        return True
    def guard(self, db):
        pass
    def _settings(self, db):
        return dict(db.execute("SELECT key,value FROM settings"))
    def _guard_settings(self, st):
        if st.get("auto_failover_mode") == "1":
            raise CZ07Hold("AUTO_FAILOVER_ENABLED")
    def _open(self, db):
        return None
    def _source_accounts(self, db, source):
        return db.execute("SELECT username,host,status FROM ssh_accounts "
                          "WHERE host=? ORDER BY username", (source,)).fetchall()


class QueueTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        path = Path(temp.name)/"test.db"
        @contextmanager
        def factory():
            db = sqlite3.connect(path)
            try:
                yield db
                db.commit()
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()
        self.factory = factory
        with factory() as db:
            db.executescript("""
                CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
                CREATE TABLE host_pool(host TEXT,active INTEGER,is_default INTEGER,
                    is_standby INTEGER,provider TEXT,provider_instance_id TEXT);
                CREATE TABLE ssh_accounts(username TEXT,host TEXT,status TEXT,service_type TEXT);
                CREATE TABLE cloudzy_cz06_runs(operation_id TEXT,actor_id INTEGER,
                    chat_id INTEGER,stage TEXT,updated_at INTEGER);
                CREATE TABLE cloudzy_edge_operations(id TEXT,status TEXT,
                    public_ipv4 TEXT,provider_server_id TEXT);
                CREATE TABLE failover_operations(status TEXT);
                CREATE TABLE cloudzy_cz04a_actions(status TEXT);
            """)
            db.executemany("INSERT INTO settings VALUES(?,?)", [
                ("hosts","source.example"),("dns_current_ip","source.example"),
                ("auto_failover_mode","0")])
            db.executemany("INSERT INTO host_pool VALUES(?,?,?,?,?,?)", [
                ("source.example",1,1,0,"",""),
                ("target.example",1,0,1,"cloudzy","provider-1")])
            db.execute("INSERT INTO cloudzy_cz06_runs VALUES (?,?,?,?,?)",
                       ("purchase-1",7,8,"READY",1))
            db.execute("INSERT INTO cloudzy_edge_operations VALUES (?,?,?,?)",
                       ("purchase-1","EDGE_READY","target.example","provider-1"))
            db.executemany("INSERT INTO ssh_accounts VALUES(?,?,?,?)",[
                (f"user{i:04}","source.example","active","ssh") for i in range(473)])
        self.fake=Fake04B()
        self.q=DurableCutoverQueue(db_conn=factory,cz04b=self.fake,
                                   enabled=lambda:True,now=lambda:100)

    def test_capacity_bound_and_exact_candidate(self):
        self.assertEqual(BATCH_SIZE, 50)
        self.assertEqual(self.q.candidate()[:3],
                         ("purchase-1","target.example","provider-1"))

    def test_authorization_one_job_and_durable_events(self):
        from cloudzy_cz04b import _digest
        with self.factory() as db:
            rows = self.fake._source_accounts(db,"source.example")
        candidate = self.q.candidate()
        with self.assertRaises(CZ07Hold):
            self.q.reserve(candidate,"source.example",actor=20,chat=8,
                           expected_fp=_digest(rows),expected_count=473)
        job=self.q.reserve(candidate,"source.example",actor=7,chat=8,
                           expected_fp=_digest(rows),expected_count=473)
        self.assertEqual(self.q.get(job)["status"],"QUEUED")
        self.q.transition(job,"QUEUED","ROUTING",code="ROUTE_START")
        self.assertEqual(self.q.get(job)["status"],"ROUTING")
        with self.assertRaises(CZ07Hold):
            self.q.transition(job,"QUEUED","MIGRATING")
        with self.assertRaises(CZ07Hold):
            self.q.reserve(candidate,"source.example",actor=7,chat=8,
                           expected_fp=_digest(rows),expected_count=473)
        self.assertEqual(len(self.q.events(job)),2)

    def test_host_pin_guard_without_verified_cutover(self):
        from cloudzy_cz04b import _digest
        with self.factory() as db:
            rows=self.fake._source_accounts(db,"source.example")
        job=self.q.reserve(self.q.candidate(),"source.example",actor=7,chat=8,
                           expected_fp=_digest(rows),expected_count=473)
        self.q.transition(job,"QUEUED","MIGRATING",code="TEST_ONLY")
        with self.assertRaises(CZ07Hold):
            self.q.route_pin(job)
        with self.factory() as db:
            self.assertEqual(db.execute(
                "SELECT value FROM settings WHERE key='hosts'").fetchone()[0],
                "source.example")


if __name__ == "__main__":
    unittest.main()
