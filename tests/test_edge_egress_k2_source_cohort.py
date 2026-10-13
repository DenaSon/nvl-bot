"""K2 Phase 2 source-only customer scope; real SQLite, zero writes."""
import sqlite3
import unittest

from edge_egress_k2_source_cohort import (
    read_source_cohort, CohortHold,
)

SOURCE = "104.194.144.195"
TARGET = "216.126.229.12"
OTHER = "146.190.3.22"


class SourceCohortTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.addCleanup(self.conn.close)
        self.conn.executescript("""
            CREATE TABLE host_pool(host TEXT PRIMARY KEY,active INT,is_default INT);
            INSERT INTO host_pool VALUES('104.194.144.195',1,1);
            INSERT INTO host_pool VALUES('146.190.3.22',1,0);
            CREATE TABLE ssh_accounts(username TEXT PRIMARY KEY,host TEXT,
                                      service_type TEXT,status TEXT);
            INSERT INTO ssh_accounts VALUES
              ('from_source','104.194.144.195','ssh','🟢 فعال'),
              ('from_source2','104.194.144.195','ssh','🟢 فعال'),
              ('other_edge','146.190.3.22','ssh','🟢 فعال'),
              ('disabled','146.190.3.22','ssh','🔴 غیرفعال'),
              ('not_ssh','146.190.3.22','v2ray','🟢 فعال');
        """)
        self.db = lambda: self.conn

    def test_only_source_edge_is_in_customer_cohort(self):
        snap = read_source_cohort(self.db, TARGET)
        self.assertEqual(snap.source_ip, SOURCE)
        self.assertEqual(snap.target_ip, TARGET)
        self.assertEqual(snap.source_accounts, 2)
        self.assertEqual(snap.other_edge_accounts, 1)
        self.assertEqual(snap.active_total, 3)
        self.assertFalse(snap.source_only)
        self.assertTrue(any("سرورهای دیگر" in msg for msg in snap.blockers))

    def test_cohort_with_only_source_users_has_no_ownership_blockers(self):
        self.conn.execute(
            "UPDATE ssh_accounts SET status='🔴 غیرفعال' WHERE username='other_edge'"
        )
        snap = read_source_cohort(self.db, TARGET)
        self.assertEqual(snap.source_accounts, 2)
        self.assertEqual(snap.other_edge_accounts, 0)
        self.assertTrue(snap.source_only)

    def test_explicit_target_member_not_counted_in_source(self):
        self.conn.execute(
            "INSERT INTO ssh_accounts VALUES('already',?,'ssh','🟢 فعال')",
            (TARGET,),
        )
        snap = read_source_cohort(self.db, TARGET)
        self.assertEqual(snap.source_accounts, 2)
        self.assertEqual(snap.already_target_accounts, 1)
        self.assertEqual(snap.other_edge_accounts, 1)

    def test_unknown_orphan_account_holds_readonly(self):
        self.conn.execute(
            "UPDATE ssh_accounts SET host='203.0.113.20' WHERE username='from_source2'"
        )
        observed = []
        self.conn.set_trace_callback(observed.append)
        snap = read_source_cohort(self.db, TARGET)
        self.assertEqual(snap.unknown_accounts, 1)
        self.assertEqual(snap.source_accounts, 1)
        self.assertIn("مالکیت برخی حساب‌ها مشخص نیست",snap.blockers)
        self.assertFalse(any(q.lstrip().upper().startswith((
            "INSERT ", "UPDATE ", "DELETE ", "CREATE ", "REPLACE ", "DROP ",
        )) for q in observed))

    def test_duplicate_default_or_existing_default_target_holds(self):
        self.conn.execute(
            "UPDATE host_pool SET is_default=1 WHERE host=?", (OTHER,),
        )
        snap = read_source_cohort(self.db, TARGET)
        self.assertEqual(snap.source_ip, "")
        self.assertIn("رله مبدأ یکتا و معتبر نیست",snap.blockers)
        self.conn.execute(
            "UPDATE host_pool SET is_default=0 WHERE host=?", (OTHER,),
        )
        snap = read_source_cohort(self.db, SOURCE)
        self.assertIn("این سرور هم‌اکنون پیش‌فرض است",snap.blockers)

    def test_invalid_target_and_missing_schema_fail_closed(self):
        for value in ("10.0.0.1","127.0.0.1","garbage"):
            with self.subTest(value=value), self.assertRaises(CohortHold):
                read_source_cohort(self.db,value)
        self.conn.execute("DROP TABLE host_pool")
        snap = read_source_cohort(self.db,TARGET)
        self.assertIn("فهرست سرورها یا حساب‌ها کامل نیست",snap.blockers)


if __name__ == "__main__":
    unittest.main()
