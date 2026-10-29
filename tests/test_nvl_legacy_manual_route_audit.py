"""Legacy manual Edge audit: read-only, no flag or HTTPS dependency."""
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from ops.nvl_legacy_manual_route_audit import audit

EDGE = "153.75.87.190"
OLD = "144.172.69.61"


class LegacyManualRouteAuditTest(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "master_bot.db"
        with sqlite3.connect(self.path) as db:
            db.executescript("""
                CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
                CREATE TABLE host_pool(
                    host TEXT PRIMARY KEY,active INTEGER,is_default INTEGER,
                    is_standby INTEGER,service_port INTEGER);
                CREATE TABLE ssh_accounts(
                    username TEXT PRIMARY KEY, host TEXT, service_type TEXT,
                    status TEXT);
                CREATE TABLE cloudzy_cz07_jobs(
                    id TEXT PRIMARY KEY, status TEXT,target TEXT,
                    updated_at INTEGER);
            """)
            db.executemany("INSERT INTO settings VALUES(?,?)", [
                ("hosts",EDGE+","+OLD), ("dns_current_ip",EDGE),
                ("public_domain","n1.example.test"),
                ("tls_domain","tls.example.test"),("tls_passthrough","1")
            ])
            db.executemany("INSERT INTO host_pool VALUES (?,?,?,?,?)", [
                (EDGE,1,1,0,2252), (OLD,1,0,0,2252)
            ])
            db.executemany("INSERT INTO ssh_accounts VALUES (?,?,?,?)", [
                ("user1",EDGE,"ssh","🟢 فعال"),
                ("user2",EDGE,"ssh","🟢 فعال"),
                ("old_user",OLD,"ssh","🔴 غیرفعال"),
            ])

    def sql(self, query, args=()):
        with sqlite3.connect(self.path) as db:
            db.execute(query, args)

    def test_live_legacy_path_does_not_require_https_or_new_flags(self):
        before = self.path.read_bytes()
        result = audit(self.path)
        self.assertTrue(result["ready_metadata"])
        self.assertEqual(result["default_edge"], EDGE)
        self.assertEqual(result["customer_port"], 2252)
        self.assertEqual(result["active_ssh_by_host"], {EDGE:2})
        self.assertEqual(result["picker_hosts"], [EDGE,OLD])
        self.assertNotIn("https",str(result).lower())
        self.assertEqual(self.path.read_bytes(), before)

    def test_dns_drift_fails_closed_without_route_mutation(self):
        self.sql("UPDATE settings SET value=? WHERE key='dns_current_ip'",(OLD,))
        before = self.path.read_bytes()
        report = audit(self.path)
        self.assertFalse(report["ready_metadata"])
        self.assertIn("CACHED_DNS_DEFAULT_MISMATCH",report["failures"])
        self.assertEqual(self.path.read_bytes(), before)

    def test_unrelated_historical_hold_is_visible_not_silently_closed(self):
        self.sql("INSERT INTO cloudzy_cz07_jobs VALUES(?,?,?,?)",
                 ("historical-job","HOLD",OLD,100))
        report=audit(self.path)
        self.assertTrue(report["ready_metadata"])
        self.assertEqual(report["unresolved_jobs"][0]["status"],"HOLD")
        self.assertIn("UNRESOLVED_MIGRATION_REVIEW_SEPARATELY",report["warnings"])
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute(
                "SELECT status FROM cloudzy_cz07_jobs WHERE id='historical-job'"
            ).fetchone()[0],"HOLD")

    def test_default_cannot_be_standby_or_inactive(self):
        for set_clause in ["active=0","is_standby=1"]:
            with self.subTest(set_clause=set_clause):
                self.sql("UPDATE host_pool SET "+set_clause+" WHERE host=?",(EDGE,))
                report=audit(self.path)
                self.assertIn("DEFAULT_RELAY_NOT_ELIGIBLE", report["failures"])
                self.sql("UPDATE host_pool SET active=1,is_standby=0 WHERE host=?",
                         (EDGE,))

    def test_duplicate_default_rejected(self):
        self.sql("UPDATE host_pool SET is_default=1 WHERE host=?",(OLD,))
        report=audit(self.path)
        self.assertIn("DEFAULT_RELAY_NOT_UNIQUE",report["failures"])

    def test_cloudflare_dns_resolution_is_only_an_observation(self):
        def resolved(name, *_args, **_kwargs):
            if name=="n1.example.test":
                ip=EDGE
            else:
                ip=OLD
            return [(None,None,None,None,(ip,0))]
        report=audit(self.path,resolve_dns=True,resolver=resolved)
        self.assertTrue(report["ready_metadata"])
        self.assertEqual(len(report["public_dns"]),2)
        self.assertIn("PUBLIC_DNS_DEFAULT_MISMATCH",report["warnings"])

    def test_picker_mismatch_is_blocker(self):
        self.sql("UPDATE settings SET value=? WHERE key='hosts'",(OLD+","+EDGE,))
        report=audit(self.path)
        self.assertIn("HOST_PICKER_DEFAULT_MISMATCH",report["failures"])


if __name__=="__main__":
    unittest.main()
