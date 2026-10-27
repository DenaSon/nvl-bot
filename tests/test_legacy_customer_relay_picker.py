"""Regression: new Legacy SSH users must use the *verified default* Relay.

The same policy is checked inside the reservation finalization transaction,
so a CZ-04B/CZ-07 route switch cannot silently strand a new customer.
"""
import ast
from contextlib import contextmanager
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest


BOT = Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"
CORE = "91.107.170.239"
RELAY = "144.172.68.167"
RELAY2 = "144.172.68.62"
STANDBY = "144.172.68.200"
GHOST = "198.51.100.50"


class CustomerRelayPickerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)
        names = {
            "_default_customer_relay_checked",
            "_pick_target_host_for_new_account",
            "_db_finalize_reserved_user",
        }
        selected = [
            n for n in cls.tree.body
            if isinstance(n, ast.FunctionDef) and n.name in names
        ]
        assert {n.name for n in selected} == names
        cls.ns = {}
        exec(compile(ast.Module(body=selected, type_ignores=[]), str(BOT), "exec"), cls.ns)

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "core.sqlite"
        with self.db() as db:
            db.executescript("""
                CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT);
                CREATE TABLE host_pool(host TEXT PRIMARY KEY, active INTEGER,
                    is_standby INTEGER, is_default INTEGER);
                CREATE TABLE ssh_accounts(username TEXT PRIMARY KEY,
                    password TEXT, expire_date TEXT, creation_date TEXT,
                    users_limit INTEGER, status TEXT, agent_id INTEGER,
                    conn_mode TEXT, hold_active INTEGER, hold_deadline TEXT,
                    hold_duration_days INTEGER, host TEXT, service_type TEXT DEFAULT 'ssh');
                INSERT INTO settings VALUES
                    ('core_wg_public_ip', '91.107.170.239'),
                    ('hosts', '144.172.68.167,144.172.68.62,91.107.170.239'),
                    ('dns_current_ip', '144.172.68.167');
                INSERT INTO host_pool VALUES
                    ('91.107.170.239',1,0,0),
                    ('144.172.68.167',1,0,1),
                    ('144.172.68.62',1,0,0),
                    ('144.172.68.200',1,1,0),
                    ('198.51.100.50',1,0,0);
            """)
            db.executemany(
                "INSERT INTO ssh_accounts(username,host,status) VALUES (? ,?,'🟢 فعال')",
                [(f"current{i}", RELAY) for i in range(489)]
            )
        self.ns["db_conn"] = self.db
        self.ns["_db_assert_account_write_allowed"] = lambda conn: None

    @contextmanager
    def db(self):
        with sqlite3.connect(self.path) as conn:
            yield conn

    def pick(self):
        return self.ns["_pick_target_host_for_new_account"]()

    def finalize(self, username, host):
        return self.ns["_db_finalize_reserved_user"](
            username, "12345", "2026-11-27", "2026-10-27", 1, "0001",
            "test", host=host
        )

    def test_new_account_stays_on_default_when_old_edge_empty(self):
        # Incident: 489 users on default; old active Edge empty.
        self.assertEqual(self.pick(), RELAY)

    def test_never_select_standby_core_or_nondefault_active(self):
        self.assertEqual(self.pick(), RELAY)
        with self.db() as db:
            db.execute("UPDATE host_pool SET active=0 WHERE host=?", (RELAY2,))
            db.execute("UPDATE host_pool SET is_standby=1 WHERE host=?", (RELAY2,))
        self.assertEqual(self.pick(), RELAY)

    def test_no_load_balancing_even_when_default_has_more_users(self):
        self.assertEqual(self.pick(), RELAY)
        with self.db() as db:
            db.execute("DELETE FROM ssh_accounts")
            db.executemany(
                "INSERT INTO ssh_accounts(username,host,status) VALUES (?,?,'🟢 فعال')",
                [(f"other{i}", RELAY2) for i in range(1000)]
            )
        self.assertEqual(self.pick(), RELAY)

    def test_default_must_be_unique_and_active(self):
        with self.db() as db:
            db.execute("UPDATE host_pool SET active=0 WHERE host=?", (RELAY,))
        with self.assertRaisesRegex(RuntimeError, "DEFAULT_CUSTOMER_RELAY_NOT_ELIGIBLE"):
            self.pick()
        with self.db() as db:
            db.execute("UPDATE host_pool SET active=1 WHERE host=?", (RELAY,))
            db.execute("UPDATE host_pool SET is_default=1 WHERE host=?", (RELAY2,))
        with self.assertRaisesRegex(RuntimeError, "DEFAULT_CUSTOMER_RELAY_AMBIGUOUS"):
            self.pick()

    def test_never_sell_to_standby_or_core_even_if_default_flagged(self):
        with self.db() as db:
            db.execute("UPDATE host_pool SET is_standby=1 WHERE host=?", (RELAY,))
        with self.assertRaisesRegex(RuntimeError, "DEFAULT_CUSTOMER_RELAY_NOT_ELIGIBLE"):
            self.pick()
        with self.db() as db:
            db.execute("UPDATE host_pool SET is_standby=0 WHERE host=?", (RELAY,))
            db.execute("UPDATE host_pool SET is_default=0 WHERE host=?", (RELAY,))
            db.execute("UPDATE host_pool SET is_default=1 WHERE host=?", (CORE,))
        with self.assertRaisesRegex(RuntimeError, "DEFAULT_CUSTOMER_RELAY_NOT_ELIGIBLE"):
            self.pick()

    def test_route_mismatch_fails_closed(self):
        with self.db() as db:
            db.execute("UPDATE settings SET value=? WHERE key='hosts'",
                       (f"{RELAY2},{RELAY}",))
        with self.assertRaisesRegex(RuntimeError, "DEFAULT_CUSTOMER_RELAY_ROUTE_MISMATCH"):
            self.pick()
        with self.db() as db:
            db.execute("UPDATE settings SET value=? WHERE key='hosts'",
                       (f"{RELAY},{RELAY2}",))
            db.execute("UPDATE settings SET value=? WHERE key='dns_current_ip'",
                       (RELAY2,))
        with self.assertRaisesRegex(RuntimeError, "DEFAULT_CUSTOMER_RELAY_ROUTE_MISMATCH"):
            self.pick()

    def test_missing_core_identity_fails_closed(self):
        with self.db() as db:
            db.execute("DELETE FROM settings WHERE key='core_wg_public_ip'")
        with self.assertRaisesRegex(RuntimeError, "CORE_PUBLIC_IP_UNVERIFIED"):
            self.pick()

    def test_same_default_finalize_success(self):
        with self.db() as db:
            db.execute("INSERT INTO ssh_accounts(username,status) VALUES (?,?)",
                       ("newbie", "⏳ درحال ساخت"))
        self.finalize("newbie", RELAY)
        with self.db() as db:
            row = db.execute("SELECT host,status FROM ssh_accounts WHERE username='newbie'").fetchone()
        self.assertEqual(row, (RELAY, "🟢 فعال"))

    def test_stale_relay_after_cutover_does_not_activate_account(self):
        with self.db() as db:
            db.execute("INSERT INTO ssh_accounts(username,status) VALUES (?,?)",
                       ("newbie", "⏳ درحال ساخت"))
        self.assertEqual(self.pick(), RELAY)
        # The CZ-04B route transaction commits before reserved-user finalization.
        with self.db() as db:
            db.execute("UPDATE host_pool SET is_default=0 WHERE host=?", (RELAY,))
            db.execute("UPDATE host_pool SET is_default=1 WHERE host=?", (RELAY2,))
            db.execute("UPDATE settings SET value=? WHERE key='hosts'",
                       (f"{RELAY2},{RELAY}",))
            db.execute("UPDATE settings SET value=? WHERE key='dns_current_ip'",
                       (RELAY2,))
        with self.assertRaisesRegex(RuntimeError, "SSH_CUSTOMER_RELAY_CHANGED_BEFORE_FINALIZE"):
            self.finalize("newbie", RELAY)
        with self.db() as db:
            row = db.execute("SELECT host,status FROM ssh_accounts WHERE username='newbie'").fetchone()
        self.assertEqual(row, (None, "⏳ درحال ساخت"))
        self.assertEqual(self.pick(), RELAY2)

    def test_guard_prevents_bad_finalize_without_router_mutations(self):
        with self.db() as db:
            db.execute("INSERT INTO ssh_accounts(username,status) VALUES (?,?)",
                       ("newbie", "⏳ درحال ساخت"))
        with self.assertRaisesRegex(RuntimeError, "SSH_CUSTOMER_RELAY_CHANGED_BEFORE_FINALIZE"):
            self.finalize("newbie", RELAY2)
        with self.db() as db:
            row = db.execute("SELECT host,status FROM ssh_accounts WHERE username='newbie'").fetchone()
        self.assertEqual(row, (None, "⏳ درحال ساخت"))

    def test_buy_handlers_use_same_picking_policy_in_single_and_bulk(self):
        source = self.source
        self.assertGreaterEqual(source.count("await asyncio.to_thread(_pick_target_host_for_new_account)"), 2)
        self.assertIn("_db_finalize_reserved_user", source)
        self.assertIn("SSH single purchase HOLD", source)
        self.assertIn("SSH bulk purchase HOLD", source)
        self.assertIn("_db_cancel_reservation", source)


if __name__ == "__main__":
    unittest.main()
