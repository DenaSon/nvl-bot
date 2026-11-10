"""Isolated tests for NVL's read-only finance audit probe; never use production DBs."""
import contextlib
import io
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ops"))
import nvl_finance_readonly_audit as subject


class FinanceReadonlyAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.master_path = root / "master_bot.db"
        self.finance_path = root / "accounting.db"
        with sqlite3.connect(self.master_path) as con:
            con.executescript("""
                CREATE TABLE agents (id INTEGER, balance REAL, withdrawable_balance REAL,
                    emergency_used REAL, referral_income REAL, cashback_income REAL);
                CREATE TABLE receipts (id INTEGER, agent_id INTEGER, amount REAL,
                    status TEXT, created_at TEXT, card_owner_agent_id INTEGER);
                CREATE TABLE activity_log (id INTEGER, agent_id INTEGER, action TEXT,
                    service_type TEXT, cost REAL, created_at TEXT);
                CREATE TABLE withdrawal_requests (id INTEGER, agent_id INTEGER, amount REAL,
                    status TEXT, created_at TEXT, done_at TEXT);
            """)
            con.executemany("INSERT INTO agents VALUES (?, ?, ?, ?, ?, ?)", [
                (1, 1000, 200, 30, 40, 50), (2, 400, 100, 0, 10, 20),
            ])
            con.executemany("INSERT INTO receipts VALUES (?, ?, ?, ?, ?, ?)", [
                (1, 1, 100, "approved", "2026-11-08 10:00", None),
                (2, 1, 250, "approved", "2026-11-08 11:00", 2),
                (3, 1, 0, "pending", "bad date", None),
                (4, 1, 500, "approved", "2026-11-08 12:00", None),
                (5, 1, 600, "approved", "2026-11-08 13:00", None),
            ])
            con.executemany("INSERT INTO activity_log VALUES (?, ?, ?, ?, ?, ?)", [
                (1, 1, "create", "ssh", 120, "2026-11-08 09:00:00"),
                (2, 0, "extend", "v2ray", 0, "2026-11-08 11:00:00"),
            ])
            con.executemany("INSERT INTO withdrawal_requests VALUES (?, ?, ?, ?, ?, ?)", [
                (1, 2, 80, "done", "2026-11-08 10:00", None),
                (2, 2, 100, "pending", "2026-11-08 11:00", None),
            ])
        with sqlite3.connect(self.finance_path) as con:
            con.execute("""CREATE TABLE finance_logs (id INTEGER, date TEXT, agent_name TEXT,
                action_type TEXT, amount REAL, details TEXT)""")
            con.executemany("INSERT INTO finance_logs VALUES (?, ?, ?, ?, ?, ?)", [
                (1, "2026-11-08 10:02:00", "Private Agent A", subject.CREDIT_ACTION, 100, "شناسه رسید: 1"),
                (2, "2026-11-08 11:02:00", "Private Agent A", subject.CREDIT_ACTION, 250, "شناسه رسید: 2"),
                (3, "2026-11-08 11:03:00", "Private Agent A", subject.CREDIT_ACTION, 250, "شناسه رسید: 2"),
                (4, "2026-11-08 12:02:00", "Private Agent A", subject.CREDIT_ACTION, 450, "شناسه رسید: 4"),
                (5, "2026-11-08 13:02:00", "Private Agent A", subject.CREDIT_ACTION, 99, "شناسه رسید: 777"),
                (6, "2026-11-08 14:02:00", "Private Agent A", "شارژ دستی", 900, "Private Details"),
            ])

    def test_reconciliation_and_snapshot(self):
        with subject.readonly(self.master_path) as master, subject.readonly(self.finance_path) as finance:
            report = subject.audit(master, finance)
        self.assertEqual(report["agent_current_snapshot"]["raw_sums_toman"]["balance"], "1400.00")
        self.assertEqual(report["receipts"]["approved_with_delegate_card"], 1)
        self.assertEqual(report["receipts"]["date_quality"]["invalid"], 1)
        self.assertEqual(report["withdrawals"]["done_missing_done_at"], 1)
        recon = report["receipt_finance_reconciliation"]
        self.assertEqual(recon["approved_receipts"], 4)
        self.assertEqual(recon["approved_receipts_without_bank_approval_log"], 1)
        self.assertEqual(recon["approved_receipts_with_multiple_bank_approval_logs"], 1)
        self.assertEqual(recon["approved_receipts_with_mismatched_logged_amount"], 1)
        self.assertEqual(recon["bank_approval_logs_for_unknown_receipts"], 1)
        self.assertNotIn("Private Agent A", json.dumps(report, ensure_ascii=False))
        self.assertNotIn("Private Details", json.dumps(report, ensure_ascii=False))

    def test_connections_reject_writes(self):
        for path in [self.master_path, self.finance_path]:
            with self.subTest(database=path.name), subject.readonly(path) as con:
                with self.assertRaises(sqlite3.OperationalError):
                    con.execute("CREATE TABLE should_never_be_created (id INTEGER)")
                with self.assertRaises(sqlite3.OperationalError):
                    con.execute("DELETE FROM sqlite_master")

    def test_missing_database_never_created(self):
        not_existing = Path(self.tmp.name) / "missing.db"
        with self.assertRaises(OSError):
            subject.readonly(not_existing)
        self.assertFalse(not_existing.exists())

    def test_cli_json_does_not_expose_agent_names(self):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(sys, "argv", ["audit", "--db", str(self.master_path), "--accounting", str(self.finance_path)]), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = subject.main()
        self.assertEqual(code, 0)
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(json.loads(out.getvalue())["audit_mode"], "READ_ONLY_SOURCE_DATA_QUALITY")
        self.assertNotIn("Private Agent A", out.getvalue())


if __name__ == "__main__":
    unittest.main()
