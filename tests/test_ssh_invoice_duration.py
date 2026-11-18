"""Read-only SSH invoice duration regression tests.

The duration shown on a re-opened invoice must be the *last renewal* when
a valid extension exists, rather than the lifetime since original creation.
"""
import ast
import asyncio
from datetime import datetime, timezone
from pathlib import Path
import re
import sqlite3
import unittest


SOURCE = (Path(__file__).resolve().parents[1] / "bot_final_v49-2.py").read_text(
    encoding="utf-8"
)
TREE = ast.parse(SOURCE)


def isolate(globals_dict):
    names = {
        "_ssh_invoice_duration_label",
        "_ssh_invoice_event_time",
        "_db_ssh_invoice_last_renewal_days",
        "_build_invoice_text",
    }
    nodes = [
        node for node in TREE.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in names
    ]
    assert len(nodes) == len(names)
    scope = dict(globals_dict)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "<invoice-tests>", "exec"), scope)
    return scope


class SSHInvoiceDurationTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.conn.executescript("""
            CREATE TABLE activity_log (
                id INTEGER PRIMARY KEY,
                username TEXT,
                action TEXT,
                service_type TEXT,
                details TEXT,
                created_at TEXT
            );
        """)
        self.row = (
            "test-password", "2027-01-01", "2026-09-03", 1,
            "🟢 فعال", 0, "1.2.3.4", "direct",
        )
        async def endpoint(_host, _mode):
            return "n1.example.com", "2252", "🔌 مستقیم"

        self.scope = isolate({
            "db_conn": lambda: self.conn,
            "datetime": datetime,
            "timezone": timezone,
            "re": re,
            "asyncio": asyncio,
            "_db_get_user": lambda _un: self.row,
            "_db_get_hold_info": lambda _un: (0, None, None),
            "_ssh_endpoint_info": endpoint,
            "get_remaining_days": lambda _exp: "30 روز باقی مانده",
            "format_db_date_to_jalali": lambda value: value,
            "credential_fields_text": lambda h, u, p, port: f"{h}:{port} {u}",
            "esc": str,
            "ACCOUNT_HOLD_DAYS": 3,
        })

    def tearDown(self):
        self.conn.close()

    def add_log(self, username, details, created_at, action="extend", kind="ssh"):
        self.conn.execute(
            "INSERT INTO activity_log (username,action,service_type,details,created_at) "
            "VALUES (?,?,?,?,?)", (username, action, kind, details, created_at)
        )
        self.conn.commit()

    def render(self, username="account1"):
        return asyncio.run(self.scope["_build_invoice_text"](username))

    def test_two_month_renewal_not_four_month_lifetime(self):
        self.add_log("account1", "60 روز", "2026-11-18 12:00:00")
        output = self.render()
        self.assertIn("مدت آخرین تمدید:</b> 2 ماه", output)
        self.assertNotIn("مدت اشتراک:</b> 4 ماه", output)
        self.assertIn("2027-01-01", output)

    def test_latest_renewal_wins_over_old_renewal(self):
        self.add_log("account1", "90 روز", "2026-10-18 12:00:00")
        self.add_log("account1", "60 روز", "2026-11-18 12:00:00")
        self.assertEqual(
            self.scope["_db_ssh_invoice_last_renewal_days"]("account1", "2026-09-03"),
            60,
        )

    def test_custom_day_renewal_not_rounded_up_to_months(self):
        self.add_log("account1", "45 روز", "2026-11-18 12:00:00")
        self.assertIn("مدت آخرین تمدید:</b> 45 روز", self.render())

    def test_other_service_and_account_are_ignored(self):
        self.add_log("account2", "60 روز", "2026-11-18 12:00:00")
        self.add_log("account1", "75 روز", "2026-11-18 12:00:00", kind="v2ray")
        self.assertIsNone(
            self.scope["_db_ssh_invoice_last_renewal_days"]("account1", "2026-09-03")
        )

    def test_old_reused_username_activity_is_ignored(self):
        self.add_log("account1", "60 روز", "2026-08-18 12:00:00")
        output = self.render()
        self.assertIn("بازه از ساخت تا انقضا", output)
        self.assertNotIn("مدت آخرین تمدید", output)

    def test_missing_activity_and_paid_tables_do_not_crash(self):
        self.conn.execute("DROP TABLE activity_log")
        self.assertIsNone(
            self.scope["_db_ssh_invoice_last_renewal_days"]("account1", "2026-09-03")
        )
        self.assertIn("بازه از ساخت تا انقضا", self.render())

    def test_paid_event_fallback_when_activity_missing(self):
        self.conn.execute("DROP TABLE activity_log")
        self.conn.executescript("""
            CREATE TABLE ssh_paid_events (
                id INTEGER PRIMARY KEY,
                username TEXT,
                kind TEXT,
                period_from TEXT,
                period_to TEXT,
                created_at_utc TEXT
            );
            INSERT INTO ssh_paid_events VALUES
                (1, 'account1', 'EXTEND', '2026-11-01', '2026-12-31',
                 '2026-11-18T10:00:00+00:00');
        """)
        self.assertEqual(
            self.scope["_db_ssh_invoice_last_renewal_days"]("account1", "2026-09-03"),
            60,
        )
        self.assertIn("مدت آخرین تمدید:</b> 2 ماه", self.render())

    def test_most_recent_paid_event_wins_over_older_legacy_activity(self):
        self.add_log("account1", "30 روز", "2026-10-18 12:00:00")
        self.conn.executescript("""
            CREATE TABLE ssh_paid_events (
                id INTEGER PRIMARY KEY,
                username TEXT,
                kind TEXT,
                period_from TEXT,
                period_to TEXT,
                created_at_utc TEXT
            );
            INSERT INTO ssh_paid_events VALUES
                (1, 'account1', 'EXTEND', '2026-11-01', '2026-12-31',
                 '2026-11-18T12:00:00+00:00');
        """)
        self.assertEqual(
            self.scope["_db_ssh_invoice_last_renewal_days"]("account1", "2026-09-03"),
            60,
        )

    def test_invalid_paid_interval_is_not_used(self):
        self.conn.execute("DROP TABLE activity_log")
        self.conn.executescript("""
            CREATE TABLE ssh_paid_events (
                id INTEGER PRIMARY KEY, username TEXT, kind TEXT,
                period_from TEXT, period_to TEXT, created_at_utc TEXT
            );
            INSERT INTO ssh_paid_events VALUES
                (1, 'account1', 'EXTEND', '2026-12-31',
                 '2026-12-01', '2026-11-18T12:00:00+00:00');
        """)
        self.assertIsNone(
            self.scope["_db_ssh_invoice_last_renewal_days"]("account1", "2026-09-03")
        )

    def test_hold_plan_duration_used_without_renewal(self):
        self.scope["_db_get_hold_info"] = lambda _un: (1, None, 90)
        self.assertIn("مدت اشتراک:</b> 3 ماه", self.render())
        self.assertIn("در انتظار اولین اتصال", self.render())

    def test_unknown_duration_does_not_default_to_one_month(self):
        self.row = (
            "pass", "not-a-date", "not-a-date", 1, "🟢 فعال", 0,
            "1.2.3.4", "direct",
        )
        self.assertIn("نامشخص", self.render())
        self.assertNotIn("مدت اشتراک:</b> 1 ماه", self.render())

    def test_read_only_history(self):
        self.add_log("account1", "60 روز", "2026-11-18 12:00:00")
        self.conn.execute("PRAGMA query_only=ON")
        self.assertEqual(
            self.scope["_db_ssh_invoice_last_renewal_days"]("account1", "2026-09-03"),
            60,
        )
        self.assertIn("مدت آخرین تمدید", self.render())


if __name__ == "__main__":
    unittest.main()
