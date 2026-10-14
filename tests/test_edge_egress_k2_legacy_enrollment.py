"""Phase 2 legacy admission inventory: real SQLite, NO privileged writes."""
import sqlite3
import time
import unittest

from edge_egress_f3_readiness import install_readiness_schema
from edge_egress_uid_runtime_store import install_runtime_schema
from edge_egress_protected_mapping import install_protected_mapping_schema
from edge_egress_k2_legacy_enrollment import (
    inspect_legacy_enrollment, legacy_enrollment_html, LegacyEnrollmentHold,
)

SOURCE = "144.172.84.76"
TARGET = "144.172.84.82"
CORE = "209.200.246.198"


class LegacyEnrollmentInventoryTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(self.db.close)
        self.db.executescript("""
            CREATE TABLE host_pool(host TEXT PRIMARY KEY,active INTEGER,
                is_default INTEGER);
            INSERT INTO host_pool VALUES('144.172.84.76',1,1);
            CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
            INSERT INTO settings VALUES('dns_current_ip','144.172.84.76');
            CREATE TABLE failover_operations(id INTEGER PRIMARY KEY,status TEXT);
            CREATE TABLE ssh_accounts(username TEXT PRIMARY KEY,host TEXT,
                service_type TEXT,status TEXT);
            INSERT INTO ssh_accounts VALUES
                ('legacy1','144.172.84.76','ssh','🟢 فعال'),
                ('protected1','144.172.84.76','ssh','🟢 فعال'),
                ('inactive','144.172.84.76','ssh','🔴 غیرفعال');
            CREATE TABLE edge_egress_allocations(
                edge_id TEXT PRIMARY KEY,edge_public_ipv4 TEXT,
                core_public_ipv4 TEXT,route_table INTEGER,status TEXT);
            INSERT INTO edge_egress_allocations VALUES
                ('e8','144.172.84.76','209.200.246.198',20008,'STAGED'),
                ('e9','144.172.84.82','209.200.246.198',20009,'STAGED');
        """)
        install_readiness_schema(self.db)
        install_runtime_schema(self.db)
        install_protected_mapping_schema(self.db)
        self.clock = int(time.time())
        for name,ip in (("e8",SOURCE),("e9",TARGET)):
            self.db.execute(
                "INSERT INTO edge_egress_readiness "
                "(edge_id,edge_ipv4,state,observed_ipv4,witness,probed_at,"
                "expires_at,last_operation_id) VALUES(?,?,'READY',?,"
                "'F4_PRODUCTION_ACCEPTANCE',?,?,1)",
                (name,ip,ip,self.clock-5,self.clock+120),
            )
        self.db.execute(
            "INSERT INTO edge_egress_uid_runtime "
            "(username,uid,edge_id,edge_ipv4,route_table,priority,dns_port,"
            "state,last_operation_id) VALUES("
            "'protected1',1645,'e8',?,20008,20011,10554,'PROTECTED',1)",
            (SOURCE,),
        )
        self.db.execute(
            "INSERT INTO edge_egress_uid_bindings "
            "(username,uid,edge_id,edge_ipv4,status) "
            "VALUES('protected1',1645,'e8',?,'PROTECTED')", (SOURCE,),
        )
        self.uids = {"legacy1":1644,"protected1":1645,"inactive":1646}
        self.db_conn = lambda:self.db

    def audit(self):
        return inspect_legacy_enrollment(
            self.db_conn, "e9", os_uid=lambda n:self.uids[n], now=self.clock,
        )

    def test_exact_legacy_cohort_only_and_no_database_write(self):
        trace = []
        self.db.set_trace_callback(trace.append)
        a = self.audit()
        self.assertTrue(a.inventory_clear,a.blockers)
        self.assertEqual(a.legacy_users,(("legacy1",1644),))
        self.assertEqual(a.active_count,2)
        self.assertEqual(a.protected_count,1)
        self.assertEqual(a.invalid_count,0)
        self.assertEqual((a.source_edge_id,a.target_edge_id),("e8","e9"))
        self.assertEqual(len(a.fingerprint),64)
        self.assertFalse(any(q.strip().upper().startswith((
            "INSERT ","UPDATE ","DELETE ","CREATE ","REPLACE ","DROP ",
        )) for q in trace))
        ui = legacy_enrollment_html(a)
        self.assertNotIn("legacy1",ui)
        self.assertNotIn("1644",ui)
        self.assertIn("نیازمند انتقال امن",ui)

    def test_cohort_uid_drift_changes_fingerprint(self):
        first = self.audit()
        self.uids["legacy1"]=1655
        second=self.audit()
        self.assertNotEqual(first.fingerprint,second.fingerprint)
        self.assertEqual(second.legacy_users,(("legacy1",1655),))

    def test_partial_mapping_never_classified_as_legacy(self):
        self.db.execute("DELETE FROM edge_egress_uid_bindings "
                        "WHERE username='protected1'")
        a=self.audit()
        self.assertFalse(a.inventory_clear)
        self.assertEqual(a.invalid_count,1)
        self.assertIn("PARTIAL_OR_FOREIGN_PROTECTED_IDENTITY",a.blockers)

    def test_foreign_protected_edge_id_does_not_count(self):
        self.db.execute("UPDATE edge_egress_uid_runtime SET edge_id='e7' "
                        "WHERE username='protected1'")
        a=self.audit()
        self.assertFalse(a.inventory_clear)
        self.assertEqual(a.protected_count,0)
        self.assertIn("PARTIAL_OR_FOREIGN_PROTECTED_IDENTITY",a.blockers)

    def test_missing_or_retired_source_f3_stays_hold(self):
        self.db.execute("UPDATE edge_egress_allocations SET status='RETIRED' "
                        "WHERE edge_id='e8'")
        a=self.audit()
        self.assertFalse(a.inventory_clear)
        self.assertIn("SOURCE_F3_ALLOCATION_REQUIRED",a.blockers)

    def test_missing_or_stale_f4_stays_hold(self):
        self.db.execute("UPDATE edge_egress_readiness SET expires_at=1 "
                        "WHERE edge_id='e8'")
        a=self.audit()
        self.assertIn("SOURCE_F4_NOT_ACCEPTED",a.blockers)
        self.assertFalse(a.inventory_clear)
        self.db.execute("UPDATE edge_egress_readiness SET expires_at=1 "
                        "WHERE edge_id='e9'")
        self.assertIn("TARGET_F4_NOT_ACCEPTED",self.audit().blockers)

    def test_foreign_host_and_missing_os_uid_cannot_enroll(self):
        self.db.execute("UPDATE ssh_accounts SET host='146.190.3.22' "
                        "WHERE username='legacy1'")
        a=self.audit()
        self.assertEqual(a.invalid_count,1)
        self.assertFalse(a.legacy_users)
        self.assertIn("ACCOUNT_OS_UID_OR_SOURCE_UNVERIFIED",a.blockers)
        self.db.execute("UPDATE ssh_accounts SET host=? WHERE username='legacy1'",(SOURCE,))
        self.uids.pop("legacy1")
        self.assertIn("ACCOUNT_OS_UID_OR_SOURCE_UNVERIFIED",self.audit().blockers)

    def test_uid_collision_and_unaccounted_runtime_hold(self):
        self.uids["legacy1"]=1645
        self.assertIn("ACCOUNT_OS_UID_OR_SOURCE_UNVERIFIED",self.audit().blockers)
        self.uids["legacy1"]=1644
        self.db.execute(
            "INSERT INTO edge_egress_uid_runtime "
            "(username,uid,edge_id,edge_ipv4,route_table,priority,dns_port,"
            "state,last_operation_id) VALUES("
            "'orphan',1650,'e8',?,20008,20012,10556,'FROZEN',1)",
            (SOURCE,),
        )
        self.assertIn("ORPHAN_PROTECTED_IDENTITY",self.audit().blockers)

    def test_dns_lock_and_source_ownership_holds(self):
        self.db.execute("UPDATE settings SET value=? WHERE key='dns_current_ip'",(TARGET,))
        self.assertIn("SOURCE_DNS_NOT_PINNED",self.audit().blockers)
        self.db.execute("INSERT INTO failover_operations VALUES(1,'RUNNING')")
        self.assertIn("SHARED_6G_BUSY",self.audit().blockers)

    def test_invalid_target_and_schema_fail_closed(self):
        for value in ("", "INVALID", "../e9", None, 125):
            with self.subTest(value=value), self.assertRaises(LegacyEnrollmentHold):
                inspect_legacy_enrollment(self.db_conn,value)
        self.db.execute("DROP TABLE edge_egress_uid_bindings")
        with self.assertRaisesRegex(LegacyEnrollmentHold,"INVENTORY_EVIDENCE_UNAVAILABLE"):
            self.audit()


if __name__=="__main__":
    unittest.main()
