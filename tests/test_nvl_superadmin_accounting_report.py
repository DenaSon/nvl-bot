"""Hermetic tests for read-only NVL Super Admin finance report (no bot imports)."""
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from zoneinfo import ZoneInfo

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from nvl_superadmin_accounting_report import (
    TEHRAN, ReportUnavailable, build_report_data, build_report_text,
    is_superadmin_request,
)

NOW = datetime(2026, 11, 10, 12, 0, tzinfo=TEHRAN)


class AccountingReportV1Tests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.db = self.base / "master_bot.db"
        self.fin = self.base / "accounting.db"
        with sqlite3.connect(self.db) as conn:
            conn.executescript("""
                CREATE TABLE agents (id INTEGER PRIMARY KEY, balance REAL, withdrawable_balance REAL, emergency_used REAL);
                CREATE TABLE receipts (id INTEGER, status TEXT, amount REAL, created_at TEXT, card_owner_agent_id INTEGER);
                CREATE TABLE activity_log (id INTEGER, action TEXT, service_type TEXT, agent_id INTEGER, cost REAL, created_at TEXT);
                CREATE TABLE withdrawal_requests (id INTEGER, status TEXT, amount REAL, created_at TEXT, done_at TEXT);
            """)
            conn.executemany("INSERT INTO agents VALUES (?, ?, ?, ?)", [
                (1, 1000.25, 200, 50), (2, 300, 120.5, 10),
            ])
            conn.executemany("INSERT INTO receipts VALUES (?, ?, ?, ?, ?)", [
                (1, "approved", 100, "2026-11-03 08:30:00", 2),  # boundary IN 7d (UTC)
                (2, "approved", 200, "2026-11-03 08:29:59", None),  # just OUT 7d
                (3, "approved", 50, "2026-11-09 11:00:00", None),
                (4, "pending", 300, "2026-11-10 07:00:00", None),
                (5, "rejected", 15, "2026-10-20 05:00:00", None),
                (6, "approved", 900, "2026-11-10 08:30:00", 2),  # exactly NOW: excluded
            ])
            conn.executemany("INSERT INTO activity_log VALUES (?, ?, ?, ?, ?, ?)", [
                (1, "create", "ssh", 1, 80, "2026-11-03 08:30:00"),
                (2, "create", "ssh", 1, 60, "2026-11-03 08:29:59"),
                (3, "extend", "v2ray", 1, 30, "2026-11-09 12:00:00"),
                (4, "create", "v2ray", 0, 0, "2026-11-09 14:00:00"),
                (5, "reduce", "ssh", 1, 5, "2026-11-09 14:00:00"),
                (6, "create", "v2ray_vol", 2, 70, "2026-10-20 06:00:00"),
            ])
            conn.executemany("INSERT INTO withdrawal_requests VALUES (?, ?, ?, ?, ?)", [
                (1, "done", 70, "2026-10-31 08:00:00", "2026-11-09 09:00:00"),
                (2, "pending", 40, "2026-11-09 09:00:00", None),
                (3, "cancelled", 20, "2026-10-20 08:00:00", None),
            ])
        with sqlite3.connect(self.fin) as conn:
            conn.execute("""CREATE TABLE finance_logs
                (id INTEGER, date TEXT, action_type TEXT, amount REAL)""")
            conn.executemany("INSERT INTO finance_logs VALUES (?, ?, ?, ?)", [
                (1, "2026-11-03 12:00:00", "شارژ دستی", 500),
                (2, "2026-11-03 11:59:59", "شارژ دستی", 200),
                (3, "2026-11-09 18:00:00", "واریز بانکی (تایید شده)", 100),
                (4, "2026-10-19 12:00:00", "شارژ دستی", 300),
            ])

    def report(self, period="7d", **kwargs):
        return build_report_data(str(self.db), str(self.fin), period, now=NOW, **kwargs)

    def test_7day_rolling_window_and_separate_sources(self):
        r = self.report("7d")
        self.assertEqual(r["receipts"]["approved"]["delegate"], [1, 100])
        self.assertEqual(r["receipts"]["approved"]["unmarked"], [1, 50])
        self.assertEqual(r["receipts"]["pending"], 1)
        self.assertEqual(r["receipts"]["rejected"], 0)
        self.assertEqual(r["activity"][("create", "ssh")], (1, 80))
        self.assertEqual(r["activity"][("extend", "v2ray")], (1, 30))
        self.assertEqual(r["activity"][("create", "v2ray")], (1, 0))
        self.assertEqual(r["reductions"], 1)
        self.assertEqual(r["manual_topups"], (1, 500))
        self.assertEqual(r["withdrawals"]["requested"], (1, 40))
        self.assertEqual(r["withdrawals"]["completed"], (1, 70))
        self.assertEqual(r["withdrawals"]["pending_now"], (1, 40))
        self.assertEqual(r["agents"]["wallet"], 1300.25)
        self.assertEqual(r["agents"]["withdrawable"], 320.5)

    def test_all_time_uses_available_history_and_includes_zero_cost_admin(self):
        r = self.report("all")
        self.assertEqual(r["receipts"]["approved"]["delegate"], [2, 1000])
        self.assertEqual(r["receipts"]["approved"]["unmarked"], [2, 250])
        self.assertEqual(r["activity"][("create", "ssh")], (2, 140))
        self.assertEqual(r["activity"][("create", "v2ray")], (1, 0))
        self.assertEqual(r["manual_topups"], (3, 1000))
        self.assertEqual(r["withdrawals"]["requested"], (3, 130))
        self.assertEqual(r["withdrawals"]["completed"], (1, 70))
        self.assertIsNone(r["since_ir"])

    def test_30day_includes_old_records_but_not_future(self):
        r = self.report("30d")
        self.assertEqual(r["receipts"]["approved"]["delegate"], [1, 100])
        self.assertEqual(r["receipts"]["approved"]["unmarked"], [2, 250])
        self.assertEqual(r["receipts"]["rejected"], 1)
        self.assertEqual(r["activity"][("create", "v2ray_vol")], (1, 70))
        self.assertEqual(r["manual_topups"], (3, 1000))

    def test_host_local_timestamps_configurable_not_silently_utc(self):
        with sqlite3.connect(self.db) as conn:
            conn.execute("INSERT INTO receipts VALUES (7, 'approved', 25, '2026-11-03 12:00:00', NULL)")
        utc = self.report("7d")
        tehran = self.report("7d", legacy_server_tz=TEHRAN)
        self.assertEqual(utc["receipts"]["approved"]["unmarked"][1], 75)
        # Tehran-start boundary is 12:00 local: prior 08:29:59 and 11:00 are excluded
        self.assertEqual(tehran["receipts"]["approved"]["unmarked"][1], 25)

    def test_current_balances_never_filtered_by_period(self):
        for period in ("all", "7d", "30d"):
            self.assertEqual(self.report(period)["agents"]["wallet"], 1300.25)
            self.assertEqual(self.report(period)["withdrawals"]["pending_now"], (1, 40))

    def test_invalid_period_and_naive_clock_fail_closed(self):
        with self.assertRaises(ValueError):
            self.report("last-year")
        with self.assertRaises(ValueError):
            build_report_data(str(self.db), str(self.fin), "7d", now=datetime(2026, 11, 10))

    def test_missing_db_never_created(self):
        missing = self.base / "missing.db"
        with self.assertRaises(ReportUnavailable):
            build_report_data(str(self.db), str(missing), "all", now=NOW)
        self.assertFalse(missing.exists())

    def test_required_schema_absent_is_failure_not_zero(self):
        with sqlite3.connect(self.fin) as conn:
            conn.execute("DROP TABLE finance_logs")
        with self.assertRaises(ReportUnavailable) as raised:
            self.report()
        self.assertEqual(str(raised.exception), "SCHEMA_INCOMPLETE")

    def test_readonly_db_files_unchanged(self):
        with sqlite3.connect(self.db) as conn:
            before = conn.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
        self.report()
        with sqlite3.connect(self.db) as conn:
            after = conn.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
        self.assertEqual(before, after)
        self.assertEqual(after, 6)

    def test_superadmin_security_requires_role_user_and_private_chat(self):
        kwargs = {"role": "admin", "chat_id": 999, "user_id": 999, "superadmin_id": 999}
        self.assertTrue(is_superadmin_request(**kwargs))
        for delta in ({"role": "agent"}, {"role": "accountant"},
                      {"chat_id": 888}, {"user_id": 888},
                      {"user_id": None}, {"chat_id": None}):
            with self.subTest(delta=delta):
                self.assertFalse(is_superadmin_request(**(kwargs | delta)))

    def test_render_safe_and_text_only(self):
        text = build_report_text(str(self.db), str(self.fin), "7d", now=NOW)
        self.assertIn("۷ روز اخیر", text)
        self.assertIn("1,300.25", text)
        self.assertIn("تاریخ ارسال", text)
        self.assertIn("کارت اختصاصی نمایندگان", text)
        self.assertNotIn("<img", text)
        self.assertLess(len(text), 3900)


if __name__ == "__main__":
    unittest.main()
