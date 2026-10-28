"""REGRESSION: Legacy monitoring may observe but not mutate customer routing.

Run with: python -m unittest tests.test_legacy_route_mutation_freeze -v
Production source functions are AST-extracted so no Telegram bot is started.
"""
import ast
import asyncio
from contextlib import contextmanager
from datetime import datetime, timedelta
import logging
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

BOT = Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"
SOURCE = BOT.read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)
DEFAULT = "144.172.68.167"
OTHER = "144.172.68.157"
CORE = "91.107.170.239"


def extract(*names, extras=None):
    nodes = [n for n in TREE.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
             and n.name in names]
    if len(nodes) != len(names):
        raise AssertionError("Missing production functions: " + str(set(names) - {n.name for n in nodes}))
    ns = dict(extras or {})
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(BOT), "exec"), ns)
    return ns


def region(start, end):
    return SOURCE.split(start, 1)[1].split(end, 1)[0]


class DefaultOnlyLegacyDB(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "routes.db"
        with sqlite3.connect(self.path) as db:
            db.executescript("""
                CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT);
                CREATE TABLE host_pool(host TEXT PRIMARY KEY, active INTEGER,
                                       is_default INTEGER, is_standby INTEGER);
                CREATE TABLE ssh_accounts(username TEXT PRIMARY KEY, host TEXT,
                                          status TEXT, service_type TEXT);
            """)
            db.executemany("INSERT INTO settings VALUES (?,?)", [
                ("hosts", DEFAULT), ("dns_current_ip", DEFAULT),
                ("core_wg_public_ip", CORE),
            ])
            db.executemany("INSERT INTO host_pool VALUES (?,?,?,?)", [
                (DEFAULT, 1, 1, 0),
                (OTHER, 1, 0, 0),
                ("144.172.68.62", 1, 0, 0),
                (CORE, 1, 0, 0),
                ("144.172.119.189", 0, 0, 0),
            ])
            db.execute(
                "INSERT INTO ssh_accounts VALUES (?,?,?,?)",
                ("nvl-test", DEFAULT, "🟢 فعال", "ssh"),
            )

        @contextmanager
        def factory():
            with sqlite3.connect(self.path) as conn:
                yield conn

        self.db = factory
        self.ns = extract(
            "_default_customer_relay_checked", "_db_rebuild_hosts_from_pool",
            "_db_set_account_host", "_db_set_hosts_bulk", "_db_set_all_accounts_host",
            extras={
                "db_conn": factory,
                "_db_assert_legacy_host_mutation_allowed": lambda db: None,
                "_db_assert_account_write_allowed": lambda db: None,
            },
        )

    def setting(self, key):
        with self.db() as db:
            return db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()[0]

    def account_host(self):
        with self.db() as db:
            return db.execute("SELECT host FROM ssh_accounts WHERE username='nvl-test'").fetchone()[0]

    def test_manual_legacy_rebuild_never_promotes_unlisted_inventory(self):
        # The *inventory* still contains four active hosts, including Core.
        # Customer-facing settings.hosts must NOT advertise all four.
        self.ns["_db_rebuild_hosts_from_pool"]()
        self.assertEqual(self.setting("hosts"), DEFAULT)
        self.assertEqual(self.account_host(), DEFAULT)
        with self.db() as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM host_pool WHERE active=1"
            ).fetchone()[0], 4)
            self.assertEqual(self.ns["_default_customer_relay_checked"](db), DEFAULT)

    def test_manual_rebuild_holds_on_dns_drift_without_other_writes(self):
        with self.db() as db:
            db.execute("UPDATE settings SET value=? WHERE key='dns_current_ip'", (OTHER,))
        with self.assertRaisesRegex(RuntimeError, "CACHED_DNS_OR_CORE_MISMATCH"):
            self.ns["_db_rebuild_hosts_from_pool"]()
        self.assertEqual(self.setting("dns_current_ip"), OTHER)
        self.assertEqual(self.setting("hosts"), DEFAULT)
        self.assertEqual(self.account_host(), DEFAULT)
        with self.db() as db:
            with self.assertRaisesRegex(RuntimeError, "DEFAULT_CUSTOMER_RELAY_ROUTE_MISMATCH"):
                self.ns["_default_customer_relay_checked"](db)

    def test_core_or_standby_may_be_visible_but_never_default_customer(self):
        with self.db() as db:
            db.execute("UPDATE host_pool SET is_default=0")
            db.execute("UPDATE host_pool SET is_default=1 WHERE host=?", (CORE,))
            db.execute("UPDATE settings SET value=? WHERE key='dns_current_ip'", (CORE,))
        with self.assertRaisesRegex(RuntimeError, "CACHED_DNS_OR_CORE_MISMATCH"):
            self.ns["_db_rebuild_hosts_from_pool"]()
        with self.db() as db:
            with self.assertRaisesRegex(RuntimeError, "DEFAULT_CUSTOMER_RELAY_NOT_ELIGIBLE"):
                self.ns["_default_customer_relay_checked"](db)
        with self.db() as db:
            db.execute("UPDATE host_pool SET is_default=0 WHERE host=?", (CORE,))
            db.execute("UPDATE host_pool SET is_default=1,is_standby=1 WHERE host=?", (OTHER,))
            db.execute("UPDATE settings SET value=? WHERE key='dns_current_ip'", (OTHER,))
        with self.assertRaisesRegex(RuntimeError, "DEFAULT_NOT_CUSTOMER_ELIGIBLE"):
            self.ns["_db_rebuild_hosts_from_pool"]()
        with self.db() as db:
            with self.assertRaisesRegex(RuntimeError, "DEFAULT_CUSTOMER_RELAY_NOT_ELIGIBLE"):
                self.ns["_default_customer_relay_checked"](db)

    def test_explicit_legacy_account_setters_can_target_other_active_edge(self):
        for operation, args in [
            ("_db_set_account_host", ("nvl-test", OTHER)),
            ("_db_set_hosts_bulk", (["nvl-test"], OTHER)),
            ("_db_set_all_accounts_host", (OTHER,)),
        ]:
            with self.subTest(operation=operation):
                self.ns[operation](*args)
                self.assertEqual(self.account_host(), OTHER)
                with self.db() as db:
                    db.execute(
                        "UPDATE ssh_accounts SET host=? WHERE username='nvl-test'",
                        (DEFAULT,),
                    )


class BackgroundMutationFreeze(unittest.TestCase):
    def test_old_migration_helpers_fail_closed(self):
        async def health():
            return {"cpu_pct": 99, "ram_pct": 98}, None
        def forbidden(*args, **kwargs):
            raise AssertionError("Unexpected DB mutation")

        ns = extract(
            "_run_ip_service_auto_migrate", "_run_ip_service_full_balance",
            extras={"_get_server_health": health, "asyncio": asyncio,
                    "_db_set_account_host": forbidden,
                    "_db_get_all_active_accounts_with_host": forbidden},
        )
        observed, note, moves = asyncio.run(ns["_run_ip_service_auto_migrate"]())
        self.assertEqual(observed["cpu_pct"], 99)
        self.assertEqual(moves, [])
        self.assertIn("غیرفعال", note)
        moves, error = asyncio.run(ns["_run_ip_service_full_balance"]())
        self.assertEqual(moves, [])
        self.assertEqual(error, "LEGACY_IP_AUTO_BALANCE_DISABLED")

    def test_sustained_pressure_escalates_only_one_admin_alert(self):
        settings = {
            "ip_pressure_streak": "2",
            "ip_pressure_since": (datetime.now() - timedelta(hours=4)).isoformat(),
            "ip_pressure_escalated_at": "",
        }
        notices = []

        async def health():
            return {"cpu_pct": 97, "ram_pct": 94, "load1": 1.0}, None

        async def notify(_app, message):
            notices.append(message)

        def read(k, default=""):
            return settings.get(k, default)

        def update(k, value):
            settings[k] = value

        ns = extract("_ip_pressure_monitor_tick", extras={
            "_get_server_health": health,
            "_db_get_setting": read,
            "_db_update_setting": update,
            "_notify_admins": notify,
            "IP_PRESSURE_WARN_PCT": 90,
            "IP_PRESSURE_CONFIRM_TICKS": 2,
            "IP_PRESSURE_AUTOBALANCE_AFTER_HOURS": 3,
            "asyncio": asyncio, "datetime": datetime, "log": logging.getLogger(__name__),
        })
        asyncio.run(ns["_ip_pressure_monitor_tick"](object()))
        asyncio.run(ns["_ip_pressure_monitor_tick"](object()))
        self.assertEqual(len(notices), 1)
        self.assertIn("هیچ IP", notices[0])
        self.assertTrue(settings["ip_pressure_escalated_at"])
        self.assertNotIn("ip_pressure_autobalanced", settings)

    def test_health_tick_contains_no_unapproved_mutation(self):
        sec = region("async def _host_health_tick(app):",
                     "async def _host_health_loop(app):")
        for forbidden in ("_cf_switch_public_domain", "_db_set_host_active",
                          "_db_rebuild_hosts_from_pool", "_hf01_plan_host_deactivation"):
            self.assertNotIn(forbidden, sec)
        self.assertIn("_db_record_host_check", sec)
        self.assertIn("_notify_admins", sec)

    def test_stale_legacy_buttons_cannot_distribute(self):
        sec = region("elif d == \"ipsvc_distribute_confirm\"",
                     "# 🆕 V89 — تنظیمات سیستم شناسایی خودکار فیلتر")
        self.assertNotIn("UPDATE ssh_accounts", sec)
        self.assertNotIn("_apply_distribution", sec)
        self.assertIn("return", sec)
        default_callback = region(
            'elif d.startswith(("hpdef_migrate_", "hpdefmig_yes_", "hpdef_"))',
            "# 🗑 حذف‌شده: خریدِ خودکارِ VPS")
        self.assertIn("CZ04B/CZ07", default_callback)
        for forbidden in ("_db_set_default_host", "_db_set_all_accounts_host",
                          "_update_cloudflare_dns"):
            self.assertNotIn(forbidden, default_callback)
        mass = region('elif d.startswith("ipallconf_yes_")',
                      'elif d == "ipsvc_auto"')
        self.assertIn("CZ07", mass)
        self.assertNotIn("_db_set_all_accounts_host", mass)
        self.assertIn('elif d == "ipsvc_distribute_confirm"', SOURCE)


if __name__ == "__main__":
    unittest.main()
