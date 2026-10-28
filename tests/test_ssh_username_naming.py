"""Regression tests for NVL SSH naming, with exact production functions extracted."""
import ast
from contextlib import contextmanager
import contextlib
from pathlib import Path
import re
import sqlite3
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parents[1]
BOT = ROOT / "bot_final_v49-2.py"


class SSHUsernameNamingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = BOT.read_text(encoding="utf-8")
        cls.source = source
        tree = ast.parse(source)
        names = {"_db_reserve_username", "_db_get_prefix_start_counter",
                 "_resolve_username_prefix"}
        methods = [x for x in tree.body if isinstance(x, ast.FunctionDef)
                   and x.name in names]
        assert {x.name for x in methods} == names
        cls.production_code = compile(
            ast.Module(body=methods, type_ignores=[]), str(BOT), "exec")

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db_path = Path(tmp.name) / "users.db"
        with sqlite3.connect(self.db_path) as db:
            db.executescript("""
                CREATE TABLE ssh_accounts(
                    username TEXT PRIMARY KEY,
                    password TEXT,expire_date TEXT,creation_date TEXT,
                    users_limit INTEGER,status TEXT,agent_id INTEGER
                );
                CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
                INSERT INTO settings(key,value) VALUES('brand','test');
            """)

        @contextmanager
        def connect():
            with sqlite3.connect(self.db_path) as db:
                yield db

        def setting(key, default=None):
            with sqlite3.connect(self.db_path) as db:
                row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
                return row[0] if row else default

        self.ns = {
            "db_conn": connect,
            "_db_get_setting": setting,
            "re": re,
            "sqlite3": sqlite3,
            "contextlib": contextlib,
            "fa_to_en_digits": lambda s: s,
        }
        exec(self.production_code, self.ns)

    def reserve(self, prefix="nevel", count=1, ssh=True):
        return self.ns["_db_reserve_username"](
            prefix, count, ssh=ssh)

    def test_default_ssh_brand_is_nevel_and_reservation_has_separator(self):
        self.assertIsNone(self.ns["_resolve_username_prefix"]("admin", None))
        self.assertEqual(self.reserve(), ("nevel-0001", 1))
        with sqlite3.connect(self.db_path) as db:
            self.assertEqual(db.execute(
                "SELECT status FROM ssh_accounts WHERE username='nevel-0001'"
            ).fetchone()[0], "⏳ درحال ساخت")

    def test_existing_old_account_and_new_names_do_not_collide(self):
        with sqlite3.connect(self.db_path) as db:
            db.execute("INSERT INTO ssh_accounts(username) VALUES('nevel0042')")
            db.execute("INSERT INTO ssh_accounts(username) VALUES('nevel-0044')")
        self.assertEqual(
            self.ns["_db_get_prefix_start_counter"]("nevel"), 45)
        self.assertEqual(self.reserve(count=44), ("nevel-0045", 45))

    def test_counter_setting_continues_sequence(self):
        with sqlite3.connect(self.db_path) as db:
            db.execute(
                "INSERT INTO settings(key,value) VALUES('counter_nevel','0077')")
        self.assertEqual(self.ns["_db_get_prefix_start_counter"]("nevel"), 77)
        self.assertEqual(self.reserve(count=77), ("nevel-0077", 77))

    def test_agent_custom_brand_and_v2ray_legacy_names_unaffected(self):
        info = [None] * 11
        info[10] = "MyStore"
        prefix = self.ns["_resolve_username_prefix"]("agent", info)
        self.assertEqual(prefix, "mystore")
        self.assertEqual(self.reserve("mystore"), ("mystore0001", 1))
        self.assertEqual(self.reserve("nevel", ssh=False), ("nevel0001", 1))

    def test_ssh_single_bulk_and_v2ray_callsite_wiring(self):
        # Six SSH reservation calls (including Linux retry handling) opt in.
        # Four V2Ray reservation calls must retain the previous naming.
        tree = ast.parse(self.source)
        relevant = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not (isinstance(node.func, ast.Attribute)
                    and node.func.attr == "to_thread" and node.args
                    and isinstance(node.args[0], ast.Name)
                    and node.args[0].id == "_db_reserve_username"):
                continue
            ssh_kw = next((kw.value for kw in node.keywords
                           if kw.arg == "ssh"), None)
            relevant.append(ssh_kw)
        self.assertEqual(len(relevant), 10)
        self.assertEqual(sum(isinstance(x, ast.Constant) and x.value is True
                             for x in relevant), 6)
        self.assertEqual(sum(x is None for x in relevant), 4)
        self.assertEqual(
            self.source.count("_resolve_username_prefix(role, ainf) or 'nevel'"),
            2)


if __name__ == "__main__":
    unittest.main()
