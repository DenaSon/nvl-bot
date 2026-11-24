"""Read-only, anonymous refund exposure audit (isolated synthetic DB)."""
import sqlite3
import sys
from datetime import date
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ops"))
import nvl_ssh_refund_audit as subject


class RefundAuditTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.executescript("""
            CREATE TABLE agents (id INTEGER PRIMARY KEY, base_price TEXT);
            CREATE TABLE ssh_accounts (
              username TEXT, agent_id INTEGER, service_type TEXT, users_limit INTEGER,
              creation_date TEXT, expire_date TEXT, hold_active INTEGER,
              hold_duration_days INTEGER
            );
            CREATE TABLE activity_log (
              username TEXT, service_type TEXT, action TEXT, details TEXT, cost REAL
            );
            INSERT INTO agents VALUES (1, '100000');
            INSERT INTO ssh_accounts VALUES (
              'private-test-user',1,'ssh',2,'2026-10-01','2026-12-03',0,NULL
            );
            INSERT INTO activity_log VALUES (
              'private-test-user','ssh','extend','30 روز',75000
            );
        """)

    def tearDown(self):
        self.conn.close()

    def test_report_exposes_money_difference_without_usernames(self):
        report = subject.audit(self.conn, today=date(2026,11,18))
        self.assertEqual(report["counts"]["accounts"],1)
        self.assertEqual(report["counts"]["different_refunds"],1)
        self.assertEqual(report["corrected_quote_total_toman"],100000)
        self.assertEqual(report["counts"]["recorded_extension_rate_mismatch_events"],1)
        self.assertNotIn("private-test-user",str(report))
        self.assertIn("S1",str(report))

    def test_no_mutations_performed(self):
        before = list(self.conn.iterdump())
        subject.audit(self.conn, today=date(2026,11,18))
        after = list(self.conn.iterdump())
        self.assertEqual(before,after)


if __name__ == "__main__":
    unittest.main()
