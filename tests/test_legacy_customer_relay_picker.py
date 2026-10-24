"""Regression: never sell new SSH accounts on the active Core or a Standby."""
import ast
from contextlib import contextmanager
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock


BOT = Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"
CORE = "91.107.170.239"
RELAY = "5.75.197.158"
RELAY2 = "104.194.151.49"
STANDBY = "153.75.90.152"
GHOST = "198.51.100.50"


class CustomerRelayPickerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = BOT.read_text(encoding="utf-8")
        tree = ast.parse(source)
        picker = next(
            n for n in tree.body
            if isinstance(n, ast.FunctionDef)
            and n.name == "_pick_target_host_for_new_account"
        )
        ns = {}
        exec(compile(ast.Module(body=[picker], type_ignores=[]), str(BOT), "exec"), ns)
        cls.picker_fn = staticmethod(ns["_pick_target_host_for_new_account"])

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db_path = Path(tmp.name) / "core.sqlite"
        self.log = Mock()
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT);
                CREATE TABLE host_pool(host TEXT PRIMARY KEY,
                    active INTEGER, is_standby INTEGER);
                CREATE TABLE ssh_accounts(username TEXT PRIMARY KEY,
                    host TEXT, status TEXT, service_type TEXT);
                INSERT INTO settings VALUES
                    ('core_wg_public_ip', '91.107.170.239'),
                    ('hosts', '5.75.197.158,91.107.170.239,104.194.151.49');
                INSERT INTO host_pool VALUES
                    ('91.107.170.239',1,0),
                    ('5.75.197.158',1,0),
                    ('104.194.151.49',1,0),
                    ('153.75.90.152',1,1),
                    ('198.51.100.50',1,0);
            """)
            conn.executemany(
                "INSERT INTO ssh_accounts VALUES (?, ?, '🟢 فعال', 'ssh')",
                [(f"current{i}", RELAY) for i in range(471)]
            )

    @contextmanager
    def db(self):
        with sqlite3.connect(self.db_path) as conn:
            yield conn

    def pick(self):
        fn = self.picker_fn
        fn.__globals__["db_conn"] = self.db
        fn.__globals__["log"] = self.log
        return fn()

    def test_never_select_core_with_zero_accounts(self):
        # Live incident: 471 accounts on the Relay and 0 on active Core.
        with self.db() as db:
            db.execute("UPDATE host_pool SET active=0 WHERE host=?", (RELAY2,))
        self.assertEqual(self.pick(), RELAY)

    def test_never_select_standby_or_unlisted_active_edge(self):
        with self.db() as db:
            db.execute(
                "UPDATE settings SET value=? WHERE key='hosts'",
                (f"{STANDBY},{CORE},{RELAY}",)
            )
        self.assertEqual(self.pick(), RELAY)

    def test_least_loaded_among_explicit_active_customer_relays(self):
        self.assertEqual(self.pick(), RELAY2)
        with self.db() as db:
            db.executemany(
                "INSERT INTO ssh_accounts VALUES (?, ?, '🟢 فعال', 'ssh')",
                [(f"other{i}", RELAY2) for i in range(472)]
            )
        self.assertEqual(self.pick(), RELAY)

    def test_ties_follow_configured_order(self):
        with self.db() as db:
            db.execute("DELETE FROM ssh_accounts")
        self.assertEqual(self.pick(), RELAY)

    def test_inactive_or_standby_configured_relay_fails_closed(self):
        with self.db() as db:
            db.execute("UPDATE host_pool SET active=0 WHERE host=?", (RELAY,))
            db.execute("UPDATE host_pool SET is_standby=1 WHERE host=?", (RELAY2,))
        with self.assertRaisesRegex(RuntimeError, "NO_ELIGIBLE_CUSTOMER_RELAY"):
            self.pick()

    def test_only_core_configured_fails_closed(self):
        with self.db() as db:
            db.execute("UPDATE settings SET value=? WHERE key='hosts'", (CORE,))
        with self.assertRaisesRegex(RuntimeError, "NO_ELIGIBLE_CUSTOMER_RELAY"):
            self.pick()

    def test_missing_core_identity_fails_closed(self):
        with self.db() as db:
            db.execute("DELETE FROM settings WHERE key='core_wg_public_ip'")
        with self.assertRaisesRegex(RuntimeError, "CORE_PUBLIC_IP_UNVERIFIED"):
            self.pick()

    def test_new_account_purchase_handlers_cancel_or_avoid_reservation_on_hold(self):
        tree = ast.parse(BOT.read_text(encoding="utf-8"))
        source = BOT.read_text(encoding="utf-8")
        snippets = [
            ast.get_source_segment(source, node) or ""
            for node in ast.walk(tree)
            if isinstance(node, ast.ExceptHandler)
            and (node.type is not None)
            and isinstance(node.type, ast.Name)
            and node.type.id == "RuntimeError"
            and any("SSH single purchase HOLD" in (ast.get_source_segment(source, node) or "")
                    or "SSH bulk purchase HOLD" in (ast.get_source_segment(source, node) or "")
                    for _ in (0,))
        ]
        self.assertEqual(len(snippets), 2)
        self.assertTrue(any("_db_cancel_reservation" in snippet for snippet in snippets))
        self.assertTrue(any("SSH bulk purchase HOLD" in snippet for snippet in snippets))


if __name__ == "__main__":
    unittest.main()
