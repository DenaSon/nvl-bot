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


class FakeDNS:
    def __init__(self, source, target):
        self.current, self.source, self.target = source, source, target
    def snapshot(self):
        return [{"name": "dns.example", "ip": self.current}]


class DryRun04B(Fake04B):
    def __init__(self, db):
        super().__init__()
        self.db = db
        self.dns = FakeDNS(self.source, self.target)
        self.route_calls = 0
        self.batch_sizes = []
    async def _run_route(self, actor, chat, target):
        self.route_calls += 1
        with self.db() as db:
            db.execute("UPDATE host_pool SET is_default=0 WHERE host=?", (self.source,))
            db.execute("UPDATE host_pool SET is_default=1,is_standby=0 WHERE host=?", (self.target,))
            db.execute("UPDATE settings SET value=? WHERE key='hosts'",
                       (self.target+","+self.source,))
            db.execute("UPDATE settings SET value=? WHERE key='dns_current_ip'",
                       (self.target,))
        self.dns.current = target
        return "READY"
    def _route_ready(self):
        return self.source,self.target,"provider-1"
    def _expect_dns(self, values, target):
        if any(value["ip"] != target for value in values):
            raise CZ07Hold("DNS_CHANGED")
    def _migration_snapshot(self, source, target):
        from cloudzy_cz04b import _digest
        with self.db() as db:
            rows = self._source_accounts(db,source)
        return rows,_digest(rows)
    def _ready_probe_state(self, source, target, pid):
        return {}
    async def _fresh(self, state):
        return
    async def _run_users(self, actor, chat, names, fingerprint):
        from cloudzy_cz04b import _digest
        with self.db() as db:
            rows = self._source_accounts(db,self.source)
            if _digest(rows) != fingerprint:
                raise CZ07Hold("ACCOUNT_CAS_CHANGED")
            for name in names:
                db.execute("UPDATE ssh_accounts SET host=? WHERE username=? AND host=?",
                           (self.target,name,self.source))
        self.batch_sizes.append(len(names))
        return len(names)


class OfflineApp:
    class Bot:
        async def send_message(self, chat, text):
            return
    bot = Bot()


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

    def test_dry_run_473_accounts_through_bounded_worker(self):
        from cloudzy_cz04b import _digest
        import asyncio
        dry=DryRun04B(self.factory)
        self.q.cz04b=dry
        with self.factory() as db:
            rows=dry._source_accounts(db,dry.source)
        job=self.q.reserve(self.q.candidate(),dry.source,actor=7,chat=8,
                           expected_fp=_digest(rows),expected_count=len(rows))
        asyncio.run(self.q._work(job,OfflineApp(),resume=False))
        final=self.q.get(job)
        self.assertEqual(final["status"],"DONE")
        self.assertEqual((final["moved"],final["total"]),(473,473))
        self.assertEqual(dry.route_calls,1)
        self.assertEqual(dry.batch_sizes,[50]*9+[23])
        with self.factory() as db:
            self.assertEqual(db.execute("SELECT value FROM settings WHERE key='hosts'").fetchone()[0],
                             dry.target)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM ssh_accounts WHERE host=?",
                                        (dry.target,)).fetchone()[0],473)



if __name__ == "__main__":
    unittest.main()
