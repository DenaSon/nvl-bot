"""SSH-REACTIVATE-01: real SQLite lifecycle regression without importing Telegram runtime."""
import ast
from contextlib import contextmanager
import logging
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from ssh_reactivation import SSHReactivationHold, resolve_ssh_reactivation_host, audit_ssh_reactivation


ROOT = Path(__file__).resolve().parents[1]
BOT_PATH = ROOT / "bot_final_v49-2.py"


class SSHReactivationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Extract the exact production DB functions; importing the full bot
        # starts unrelated dependencies and background functionality.
        source = ast.parse(BOT_PATH.read_text(encoding="utf-8"))
        names = {
            "_db_preflight_ssh_reactivation",
            "_db_activate_ssh_account_tx",
            "_db_toggle_status",
        }
        nodes = [
            node for node in source.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name in names
        ]
        assert len(nodes) == 3, "Production activation functions missing"
        cls.code = compile(ast.Module(body=nodes, type_ignores=[]), str(BOT_PATH), "exec")

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "reactivation.db"
        with sqlite3.connect(self.path) as db:
            db.executescript("""
                CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
                CREATE TABLE host_pool(
                    host TEXT PRIMARY KEY, active INTEGER,
                    is_default INTEGER, is_standby INTEGER
                );
                CREATE TABLE ssh_accounts(
                    username TEXT PRIMARY KEY, host TEXT, status TEXT,
                    service_type TEXT, expire_date TEXT, hold_active INTEGER DEFAULT 0
                );
            """)
            db.executemany("INSERT INTO settings VALUES (?,?)", [
                ("hosts", "new.example"),
                ("core_wg_public_ip", "core.example"),
                ("dns_current_ip", "new.example"),
            ])
            db.executemany("INSERT INTO host_pool VALUES (?,?,?,?)", [
                ("new.example", 1, 1, 0),
                ("old.example", 1, 0, 0),  # CZ-07 leaves former relay powered on
                ("dedicated.example", 1, 0, 0),
                ("standby.example", 1, 0, 1),
                ("core.example", 1, 0, 0),
            ])
            db.execute("INSERT INTO ssh_accounts VALUES (?,?,?,?,?,?)",
                       ("nevel0879", "old.example", "🔴 غیرفعال",
                        "ssh", "2026-10-01", 1))
            db.execute("""CREATE TABLE cloudzy_cz07_jobs (
                source TEXT, target TEXT, status TEXT
            )""")
            db.execute(
                "INSERT INTO cloudzy_cz07_jobs VALUES (?,?,?)",
                ("old.example", "new.example", "DONE"),
            )
        self.block_account = False
        self.block_protected = False

        @contextmanager
        def factory():
            db = sqlite3.connect(self.path)
            try:
                yield db
                db.commit()
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()

        def check_account(db):
            if self.block_account:
                raise RuntimeError("FAILOVER_WRITE_LOCKED:123")

        def check_protected(db):
            if self.block_protected:
                raise RuntimeError("PROTECTED_MAPPING_GUARD")

        self.ns = {
            "db_conn": factory,
            "resolve_ssh_reactivation_host": resolve_ssh_reactivation_host,
            "audit_ssh_reactivation": audit_ssh_reactivation,
            "_db_assert_account_write_allowed": check_account,
            "_db_assert_legacy_host_mutation_allowed": check_protected,
            "log": logging.getLogger(__name__),
        }
        exec(self.code, self.ns)

    def row(self):
        with sqlite3.connect(self.path) as db:
            return db.execute(
                "SELECT host,status,expire_date,hold_active FROM ssh_accounts "
                "WHERE username='nevel0879'"
            ).fetchone()

    def audit(self):
        with sqlite3.connect(self.path) as db:
            exists = db.execute(
                "SELECT 1 FROM sqlite_master WHERE name='ssh_reactivation_audit'"
            ).fetchone()
            if not exists:
                return []
            return db.execute(
                "SELECT previous_host,target_host,reason,actor "
                "FROM ssh_reactivation_audit ORDER BY id"
            ).fetchall()

    def test_cz07_completed_reactivation_moves_inactive_account(self):
        self.assertEqual(
            self.ns["_db_preflight_ssh_reactivation"]("nevel0879"),
            "new.example",
        )
        next_status = self.ns["_db_toggle_status"](
            "nevel0879", "🔴 غیرفعال", "telegram:7"
        )
        self.assertEqual(next_status, "🟢 فعال")
        self.assertEqual(self.row()[:2], ("new.example", "🟢 فعال"))
        self.assertEqual(
            self.audit(),
            [("old.example", "new.example", "CZ07_RETIRED_SOURCE", "telegram:7")],
        )

    def test_valid_nondefault_explicit_host_remains_pinned(self):
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE settings SET value=? WHERE key='hosts'",
                       ("new.example,dedicated.example",))
            db.execute("UPDATE ssh_accounts SET host=? WHERE username=?",
                       ("dedicated.example", "nevel0879"))
        self.ns["_db_toggle_status"]("nevel0879", "🔴 غیرفعال")
        self.assertEqual(self.row()[:2], ("dedicated.example", "🟢 فعال"))
        self.assertEqual(self.audit(), [])

    def test_missing_host_is_reconciled_to_safe_default(self):
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE ssh_accounts SET host=NULL WHERE username='nevel0879'")
        self.ns["_db_toggle_status"]("nevel0879", "🔴 غیرفعال")
        self.assertEqual(self.row()[:2], ("new.example", "🟢 فعال"))

    def test_unresolved_cz07_holds_without_changing_status(self):
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO cloudzy_cz07_jobs VALUES (?,?,?)",
                       ("x.example", "y.example", "MIGRATING"))
        with self.assertRaisesRegex(SSHReactivationHold, "CZ07_UNRESOLVED"):
            self.ns["_db_toggle_status"]("nevel0879", "🔴 غیرفعال")
        self.assertEqual(self.row()[:2], ("old.example", "🔴 غیرفعال"))

    def test_no_safe_default_fails_closed(self):
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE host_pool SET active=0 WHERE host='new.example'")
        with self.assertRaisesRegex(SSHReactivationHold, "NO_VALID_DEFAULT"):
            self.ns["_db_toggle_status"]("nevel0879", "🔴 غیرفعال")
        self.assertEqual(self.row()[:2], ("old.example", "🔴 غیرفعال"))

    def test_bad_dns_during_completed_cutover_holds(self):
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE settings SET value='unexpected.example' "
                       "WHERE key='dns_current_ip'")
        with self.assertRaisesRegex(SSHReactivationHold, "CZ07_ROUTE_CHANGED"):
            self.ns["_db_toggle_status"]("nevel0879", "🔴 غیرفعال")
        self.assertEqual(self.row()[:2], ("old.example", "🔴 غیرفعال"))

    def test_failover_write_lock_and_protected_fence(self):
        self.block_account = True
        with self.assertRaisesRegex(RuntimeError, "FAILOVER_WRITE_LOCKED"):
            self.ns["_db_toggle_status"]("nevel0879", "🔴 غیرفعال")
        self.block_account = False
        self.block_protected = True
        with self.assertRaisesRegex(RuntimeError, "PROTECTED_MAPPING_GUARD"):
            self.ns["_db_toggle_status"]("nevel0879", "🔴 غیرفعال")
        self.assertEqual(self.row()[:2], ("old.example", "🔴 غیرفعال"))

    def test_compare_and_swap_rejects_stale_status(self):
        with self.assertRaisesRegex(RuntimeError, "STATUS_CHANGED"):
            self.ns["_db_toggle_status"]("nevel0879", "🟢 فعال")
        self.assertEqual(self.row()[:2], ("old.example", "🔴 غیرفعال"))

    def test_renewal_reactivation_changes_host_and_expiry_atomically(self):
        with self.ns["db_conn"]() as db:
            db.execute("BEGIN IMMEDIATE")
            self.ns["_db_activate_ssh_account_tx"](
                db, "nevel0879", expected_status="🔴 غیرفعال",
                expire_date="2026-12-01", actor="renewal:agent:1",
            )
        self.assertEqual(self.row(),
                         ("new.example", "🟢 فعال", "2026-12-01", 0))
        self.assertEqual(self.audit()[0][3], "renewal:agent:1")

    def test_no_partial_renewal_on_hold(self):
        self.block_account = True
        with self.assertRaisesRegex(RuntimeError, "FAILOVER_WRITE_LOCKED"):
            with self.ns["db_conn"]() as db:
                db.execute("BEGIN IMMEDIATE")
                self.ns["_db_activate_ssh_account_tx"](
                    db, "nevel0879", expire_date="2026-12-01"
                )
        self.assertEqual(self.row(), ("old.example", "🔴 غیرفعال", "2026-10-01", 1))

    def test_disable_does_not_mutate_host(self):
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE ssh_accounts SET status='🟢 فعال'")
        self.ns["_db_toggle_status"]("nevel0879", "🟢 فعال")
        self.assertEqual(self.row()[:2], ("old.example", "🔴 غیرفعال"))
        self.assertEqual(self.audit(), [])

    def test_v2ray_status_does_not_touch_ssh_host(self):
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE ssh_accounts SET service_type='v2ray'")
        self.ns["_db_toggle_status"]("nevel0879", "🔴 غیرفعال")
        self.assertEqual(self.row()[:2], ("old.example", "🟢 فعال"))
        self.assertEqual(self.audit(), [])


if __name__ == "__main__":
    unittest.main()
