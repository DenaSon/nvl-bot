"""P5 read-only evidence tests; no Cloudflare, 6G, DNS or customer writes."""
from contextlib import contextmanager
from tempfile import TemporaryDirectory
from pathlib import Path
import sqlite3
import unittest

from cloudzy_route_reconcile import (
    RouteProjectionHold, require_customer_route_projection,
    classify_dns_records, classify_db_route, reconcile_evidence,
)

SRC = "203.0.113.11"
DST = "203.0.113.12"
CORE = "203.0.113.100"

class RouteAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "fixture.db"
        with self.db() as db:
            db.executescript("""
                CREATE TABLE host_pool(
                    host TEXT,active INTEGER,is_default INTEGER,is_standby INTEGER
                );
                CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
                INSERT INTO host_pool VALUES
                 ('203.0.113.11',1,1,0),
                 ('203.0.113.12',1,0,1),
                 ('203.0.113.13',1,0,0),
                 ('203.0.113.20',0,0,0);
                INSERT INTO settings VALUES
                 ('hosts','203.0.113.11,203.0.113.13'),
                 ('dns_current_ip','203.0.113.11'),
                 ('core_wg_public_ip','203.0.113.100');
            """)
    @contextmanager
    def db(self):
        with sqlite3.connect(self.path) as conn:
            yield conn

    def test_clean_legacy_source_and_isolated_standby(self):
        with self.db() as db:
            self.assertEqual(
                require_customer_route_projection(db, source=SRC, target=DST),
                (SRC, (SRC, "203.0.113.13")))
            self.assertEqual(classify_db_route(db, source=SRC, target=DST), "SOURCE")

    def test_mismatched_legacy_order_is_hold(self):
        with self.db() as db:
            db.execute("UPDATE settings SET value=? WHERE key='hosts'",
                       ("203.0.113.13,203.0.113.11",))
            with self.assertRaisesRegex(RouteProjectionHold, "LEGACY_HOSTS_ORDER_MISMATCH"):
                require_customer_route_projection(db, target=DST)

    def test_standby_in_customer_hosts_is_never_eligible(self):
        with self.db() as db:
            db.execute("UPDATE settings SET value=? WHERE key='hosts'",
                       (SRC + "," + DST,))
            with self.assertRaisesRegex(RouteProjectionHold, "ROUTE_HOST_NOT_CUSTOMER_ELIGIBLE"):
                require_customer_route_projection(db)

    def test_duplicate_and_inactive_hosts_hold(self):
        for hosts, expected in ((SRC+","+SRC, "ROUTE_HOSTS_DUPLICATE"),
                                (SRC+",203.0.113.20", "ROUTE_HOST_NOT_CUSTOMER_ELIGIBLE")):
            with self.db() as db:
                db.execute("UPDATE settings SET value=? WHERE key='hosts'", (hosts,))
                with self.assertRaisesRegex(RouteProjectionHold, expected):
                    require_customer_route_projection(db, target=DST)

    def test_default_cached_dns_drift_and_target_change(self):
        with self.db() as db:
            db.execute("UPDATE settings SET value=? WHERE key='dns_current_ip'", (DST,))
            with self.assertRaisesRegex(RouteProjectionHold, "ROUTE_CACHED_DNS_DEFAULT_DRIFT"):
                require_customer_route_projection(db, target=DST)
            self.assertEqual(classify_db_route(db, source=SRC, target=DST),
                             "MIXED_OR_OTHER")
        with self.db() as db:
            db.execute("UPDATE settings SET value=? WHERE key='dns_current_ip'", (SRC,))
            db.execute("UPDATE host_pool SET is_standby=0 WHERE host=?", (DST,))
            with self.assertRaisesRegex(RouteProjectionHold, "ROUTE_TARGET_NOT_ISOLATED"):
                require_customer_route_projection(db, target=DST)

    def test_ambiguous_defaults_and_core_in_routes_hold(self):
        with self.db() as db:
            db.execute("UPDATE host_pool SET is_default=1 WHERE host='203.0.113.13'")
            with self.assertRaisesRegex(RouteProjectionHold, "ROUTE_DEFAULT_AMBIGUOUS"):
                require_customer_route_projection(db)
        with self.db() as db:
            db.execute("UPDATE host_pool SET is_default=0 WHERE host='203.0.113.13'")
            db.execute("UPDATE settings SET value=? WHERE key='core_wg_public_ip'",
                       (SRC,))
            with self.assertRaisesRegex(RouteProjectionHold, "ROUTE_DEFAULT_IS_CORE"):
                require_customer_route_projection(db)

    def test_external_dns_all_source_target_mixed_or_bad_identity(self):
        source = [{"name":"ssh.example","id":"a","ip":SRC,"ttl":60},
                  {"name":"tls.example","id":"b","ip":SRC,"ttl":60}]
        target = [dict(row, ip=DST) for row in source]
        mixed = [source[0],target[1]]
        self.assertEqual(classify_dns_records(source,source=SRC,target=DST),"SOURCE")
        self.assertEqual(classify_dns_records(target,source=SRC,target=DST),"TARGET")
        self.assertEqual(classify_dns_records(mixed,source=SRC,target=DST),"MIXED_OR_OTHER")
        self.assertEqual(classify_dns_records([],source=SRC,target=DST),"UNVERIFIED")
        self.assertEqual(classify_dns_records([source[0]]*2,source=SRC,target=DST),"UNVERIFIED")
        self.assertEqual(classify_dns_records(target,source=SRC,target=DST,
                                              expected=source),"TARGET")
        self.assertEqual(classify_dns_records(target[:1],source=SRC,target=DST,
                                              expected=source),"UNVERIFIED")
        forged = [dict(target[0],id="different"),target[1]]
        self.assertEqual(classify_dns_records(forged,source=SRC,target=DST,
                                              expected=source),"UNVERIFIED")

    def test_reconciliation_never_auto_releases_original_6g(self):
        for db, dns, expected in (
            ("SOURCE","SOURCE","SOURCE_CONSISTENT_UNRELEASED"),
            ("TARGET","TARGET","TARGET_CONSISTENT_UNACCEPTED"),
            ("SOURCE","TARGET","RECONCILE_REQUIRED"),
            ("TARGET","SOURCE","RECONCILE_REQUIRED"),
            ("TARGET","MIXED_OR_OTHER","RECONCILE_REQUIRED"),
            ("UNVERIFIED","UNVERIFIED","RECONCILE_REQUIRED"),
        ):
            with self.subTest(db=db,dns=dns):
                result = reconcile_evidence(db_route=db,dns_route=dns,
                                             shared_lock_running=True)
                self.assertEqual(result.disposition,expected)
                self.assertNotIn("RELEASE", result.next_action[:6])
        self.assertEqual(reconcile_evidence(
            db_route="TARGET",dns_route="TARGET",shared_lock_running=False
        ).disposition, "SHARED_6G_OWNERSHIP_UNVERIFIED")

if __name__ == "__main__":
    unittest.main()
