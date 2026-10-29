"""Phase 2 Quick Switch: SQLite/Cloudflare crash and concurrency regression."""
from contextlib import contextmanager
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from manual_quick_switch import ManualQuickSwitch, QuickSwitchHold


OLD = "153.75.87.190"
NEW = "45.59.126.73"
HIST_SOURCE = "144.172.69.19"
HIST_TARGET = "144.172.69.61"


class FakeDNS:
    def __init__(self):
        self.records = [
            dict(name="n1.nvlsup.com", id="a1", ttl=120, ip=OLD),
            dict(name="tls.nvlsup.com", id="a2", ttl=120, ip=OLD),
        ]
        self.error = None
        self.writes = 0

    def snapshot(self):
        return [dict(row) for row in self.records]

    def set_all(self, expected, target):
        assert self.snapshot() == expected
        self.writes += 1
        if self.error == "before":
            raise TimeoutError("outage")
        if self.error == "partial":
            self.records[0]["ip"] = target
            raise TimeoutError("partial write")
        for row in self.records:
            row["ip"] = target
        return self.snapshot()


class QuickSwitchTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.dbpath = Path(temp.name) / "live.db"
        with sqlite3.connect(self.dbpath) as db:
            db.executescript("""
                CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
                CREATE TABLE host_pool(
                  host TEXT PRIMARY KEY,active INTEGER,is_default INTEGER,
                  is_standby INTEGER,service_port INTEGER,admin_ssh_port INTEGER,
                  provider TEXT,provider_instance_id TEXT
                );
                CREATE TABLE ssh_accounts(
                  username TEXT PRIMARY KEY,host TEXT,status TEXT,
                  service_type TEXT,expire_date TEXT
                );
                CREATE TABLE manual_edge_operations(
                  id TEXT PRIMARY KEY,actor INTEGER,chat INTEGER,ip TEXT,
                  status TEXT,pin_type TEXT,pin_base64 TEXT,
                  reason TEXT,updated_at INTEGER
                );
                CREATE TABLE manual_edge_events(
                  seq INTEGER PRIMARY KEY AUTOINCREMENT,
                  op_id TEXT,actor INTEGER,status TEXT,code TEXT,happened INTEGER
                );
                CREATE TABLE failover_operations(
                  id INTEGER PRIMARY KEY AUTOINCREMENT,mode TEXT,
                  source_host TEXT,target_host TEXT,status TEXT,
                  started_at TEXT,updated_at TEXT,finished_at TEXT,
                  detail_json TEXT
                );
                CREATE TABLE cloudzy_cz07_jobs(
                  source TEXT,target TEXT,status TEXT
                );
            """)
            db.executemany("INSERT INTO settings VALUES (?,?)", (
                ("hosts", OLD), ("dns_current_ip", OLD),
                ("core_wg_public_ip", "91.107.170.239"), ("tls_port", "2088"),
                ("auto_failover_mode","0"), ("phase6h_auto_failover_enabled","0"),
            ))
            db.executemany("INSERT INTO host_pool VALUES (?,?,?,?,?,?,?,?)", (
                (OLD,1,1,0,2252,22,"cloudzy","legacy"),
                (NEW,1,0,1,2252,22,"manual",None),
                ("91.107.170.239",1,0,0,2252,22,"core",None),
            ))
            db.execute(
                "INSERT INTO manual_edge_operations VALUES (?,?,?,?,?,?,?,?,?)",
                ("manual-1",7,7,NEW,"STANDBY","ssh-ed25519","pinned","",0)
            )
            db.executemany("INSERT INTO ssh_accounts VALUES (?,?,?,?,?)", (
                ("alice",OLD,"🟢 فعال","ssh","2026-11-28"),
                ("bob",OLD,"🔴 غیرفعال","ssh","2026-10-28"),
                ("charlie",None,"🟢 فعال","ssh","2026-11-29"),
                ("v2ray",OLD,"🟢 فعال","v2ray","2026-11-28"),
            ))
            db.execute(
                "INSERT INTO cloudzy_cz07_jobs VALUES (?,?,?)",
                (HIST_SOURCE,HIST_TARGET,"HOLD")
            )
        self.dns = FakeDNS()
        self.checks = 0

        async def check(plan):
            self.checks += 1
            self.assertEqual(plan["target"], NEW)
            self.assertEqual(plan["identity"]["provider"], "manual")
            return True

        @contextmanager
        def connect():
            conn = sqlite3.connect(self.dbpath)
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

        self.connect = connect
        self.engine = ManualQuickSwitch(
            db_conn=connect,dns=self.dns,check_target=check
        )

    def one(self, sql, *params):
        with self.connect() as db:
            return db.execute(sql,params).fetchone()

    async def test_cutover_ignores_unrelated_historical_hold_but_preserves_it(self):
        plan = await self.engine.preview(NEW)
        self.assertEqual(plan["count"],3)  # includes inactive old + active NULL
        job = await self.engine.start(
            plan,actor="telegram:7",client_witness="MCI client E2E accepted"
        )
        self.assertEqual(self.engine.get(job)["status"],"DONE")
        self.assertEqual(self.one(
            "SELECT host FROM host_pool WHERE is_default=1"),(NEW,))
        self.assertEqual(self.one(
            "SELECT value FROM settings WHERE key='hosts'"),(NEW,))
        self.assertEqual(self.one(
            "SELECT value FROM settings WHERE key='dns_current_ip'"),(NEW,))
        self.assertEqual(self.one(
            "SELECT COUNT(*) FROM ssh_accounts "
            "WHERE service_type='ssh' AND host=?",(NEW))[0],3)
        self.assertEqual(self.one(
            "SELECT host FROM ssh_accounts WHERE username='v2ray'"),(OLD,))
        self.assertEqual(self.one(
            "SELECT status FROM cloudzy_cz07_jobs"),("HOLD",))
        self.assertEqual(self.one(
            "SELECT status FROM failover_operations"),("SUCCEEDED",))
        self.assertEqual(self.one(
            "SELECT status FROM manual_edge_operations WHERE ip=?",(NEW)),
            ("ACTIVE",))
        self.assertEqual(self.dns.writes,1)
        self.assertEqual(await self.engine.resume(
            job,actor="telegram:7"),"DONE")

    async def test_relevant_hold_blocks_route_without_6g_writes(self):
        with self.connect() as db:
            db.execute("UPDATE cloudzy_cz07_jobs SET source=?", (OLD,))
        with self.assertRaisesRegex(QuickSwitchHold,"RELEVANT_CZ07"):
            await self.engine.preview(NEW)
        self.assertIsNone(self.one("SELECT id FROM failover_operations"))

    async def test_active_unrelated_job_blocks_global_dns(self):
        with self.connect() as db:
            db.execute("UPDATE cloudzy_cz07_jobs SET status='MIGRATING'")
        with self.assertRaisesRegex(QuickSwitchHold,"RELEVANT_CZ07"):
            await self.engine.preview(NEW)

    async def test_source_snapshot_stale_blocks_before_external_write(self):
        plan = await self.engine.preview(NEW)
        with self.connect() as db:
            db.execute("UPDATE ssh_accounts SET status='🔴 غیرفعال' "
                       "WHERE username='alice'")
        with self.assertRaisesRegex(QuickSwitchHold,"PREVIEW_CHANGED"):
            await self.engine.start(
                plan,actor="7",client_witness="MCI client test"
            )
        self.assertEqual(self.dns.writes,0)

    async def test_preexisting_6g_running_blocks_new_switch(self):
        with self.connect() as db:
            db.execute("INSERT INTO failover_operations "
                       "(mode,status,source_host,target_host) "
                       "VALUES ('MANUAL','RUNNING',?,?)",(OLD,NEW))
        with self.assertRaisesRegex(QuickSwitchHold,"SHARED_6G_BUSY"):
            await self.engine.preview(NEW)

    async def test_dns_timeout_keeps_lease_and_user_route_unchanged(self):
        plan = await self.engine.preview(NEW)
        self.dns.error="before"
        with self.assertRaisesRegex(
                QuickSwitchHold,"DNS_WRITE_RESULT_UNCERTAIN"):
            await self.engine.start(
                plan,actor="7",client_witness="MCI witness"
            )
        job=self.one("SELECT id FROM manual_quick_switch_jobs")[0]
        self.assertEqual(self.engine.get(job)["status"],"HOLD")
        self.assertEqual(self.one(
            "SELECT status FROM failover_operations"),("RUNNING",))
        self.assertEqual(self.one(
            "SELECT host FROM host_pool WHERE is_default=1"),(OLD,))
        with self.assertRaisesRegex(QuickSwitchHold,"DNS_RETRY_REQUIRES"):
            await self.engine.resume(job,actor="7")

    async def test_partial_dns_write_requires_manual_reconciliation(self):
        plan = await self.engine.preview(NEW)
        self.dns.error="partial"
        with self.assertRaisesRegex(QuickSwitchHold,"DNS_WRITE_RESULT"):
            await self.engine.start(
                plan,actor="7",client_witness="MCI witness"
            )
        job=self.one("SELECT id FROM manual_quick_switch_jobs")[0]
        with self.assertRaisesRegex(QuickSwitchHold,"DNS_UNCERTAIN"):
            await self.engine.resume(job,actor="7")
        self.assertEqual(self.dns.writes,1)
        self.assertEqual(self.one(
            "SELECT host FROM host_pool WHERE is_default=1"),(OLD,))

    async def test_crash_after_dns_change_resumes_without_duplicate_dns_put(self):
        plan=await self.engine.preview(NEW)
        job=self.engine._reserve(plan,actor="7",evidence="MCI witness")
        self.dns.set_all(plan["dns"],NEW)
        self.assertEqual(await self.engine.resume(job,actor="7"),"DONE")
        self.assertEqual(self.dns.writes,1)

    async def test_crash_after_db_commit_finishes_without_second_account_move(self):
        plan=await self.engine.preview(NEW)
        job=self.engine._reserve(plan,actor="7",evidence="MCI witness")
        self.dns.set_all(plan["dns"],NEW)
        rec=self.engine.get(job)
        self.engine._commit(rec)
        self.assertEqual(self.engine.get(job)["status"],"DB_COMMITTED")
        self.assertEqual(await self.engine.resume(job,actor="7"),"DONE")
        self.assertEqual(self.dns.writes,1)

    async def test_standby_identity_invalid_fails_closed(self):
        with self.connect() as db:
            db.execute("UPDATE manual_edge_operations SET pin_base64=NULL")
        with self.assertRaisesRegex(Exception,"MANUAL_RECEIPT_NOT_VERIFIED"):
            await self.engine.preview(NEW)

    async def test_external_rescue_attestation_is_append_only(self):
        # Models previously executed operator-side emergency SQL and live DNS.
        with self.connect() as db:
            db.execute("UPDATE host_pool SET is_default=0 WHERE host=?",(OLD,))
            db.execute(
                "UPDATE host_pool SET is_default=1,is_standby=0 WHERE host=?",
                (NEW,))
            db.execute(
                "UPDATE manual_edge_operations SET status='ACTIVE',"
                "reason='EMERGENCY_DELETED_SOURCE_RECOVERY' WHERE ip=?",
                (NEW,))
            db.execute(
                "INSERT INTO manual_edge_events "
                "(op_id,actor,status,code,happened) "
                "VALUES ('manual-1',7,'ACTIVE',"
                "'EMERGENCY_DELETED_SOURCE_RECOVERY',1)"
            )
            db.execute("UPDATE ssh_accounts SET host=? "
                       "WHERE service_type='ssh'",(NEW,))
            db.execute("UPDATE settings SET value=? "
                       "WHERE key IN ('hosts','dns_current_ip')",(NEW,))
        self.dns.set_all(self.dns.snapshot(),NEW)
        before = self.one("SELECT COUNT(*) FROM failover_operations")[0]
        job=await self.engine.record_external_cutover(
            source=OLD,target=NEW,actor="telegram:7",
            client_witness="Verified independent NPV tunnel real client",
            expected_active=2)
        same=await self.engine.record_external_cutover(
            source=OLD,target=NEW,actor="telegram:7",
            client_witness="Verified independent NPV tunnel real client",
            expected_active=2)
        self.assertEqual(job,same)
        self.assertEqual(self.engine.get(job)["status"],"EXTERNAL_VERIFIED")
        self.assertEqual(self.one("SELECT COUNT(*) FROM failover_operations")[0],
                         before)
        self.assertEqual(self.one(
            "SELECT status FROM cloudzy_cz07_jobs"),("HOLD",))

    async def test_external_attestation_rejects_wrong_account_count(self):
        with self.assertRaisesRegex(QuickSwitchHold,"EXTERNAL_ROUTE_UNVERIFIED"):
            await self.engine.record_external_cutover(
                source=OLD,target=NEW,actor="7",
                client_witness="test",expected_active=446)


if __name__ == "__main__":
    unittest.main()
