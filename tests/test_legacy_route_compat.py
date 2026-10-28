"""Legacy/Cloudzy route metadata regression: SQLite only, never live DNS or users."""
import ast
from contextlib import contextmanager
from pathlib import Path
import sqlite3
import unittest

from legacy_route_compat import (
    LegacyRouteHold, project_customer_hosts,
    repair_local_metadata, validate_customer_host_edit,
)

DEFAULT = "45.61.180.119"
OLD = "144.172.69.2"
STANDBY = "45.59.113.161"
EXTRA = "144.172.69.10"
OTHER = "153.75.88.4"
CORE = "91.107.170.239"

class LegacyHostProjectionTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.db.executescript("""
            CREATE TABLE settings (key TEXT PRIMARY KEY,value TEXT);
            CREATE TABLE host_pool (
              host TEXT PRIMARY KEY, active INTEGER,is_default INTEGER,
              is_standby INTEGER
            );
            CREATE TABLE ssh_accounts (
              username TEXT,host TEXT,service_type TEXT,status TEXT
            );
        """)
        self.db.executemany("INSERT INTO host_pool VALUES (?,?,?,?)", [
            (DEFAULT, 1, 1, 0), (OLD, 1, 0, 0),
            (STANDBY, 1, 0, 1), (EXTRA, 1, 0, 0),
            (OTHER, 1, 0, 0),
        ])
        self.original = ",".join((OLD, STANDBY, EXTRA, DEFAULT))
        self.db.executemany("INSERT INTO settings VALUES (?,?)", [
            ("hosts",self.original),("dns_current_ip",DEFAULT),
            ("core_wg_public_ip",CORE),
        ])
        self.db.executemany("INSERT INTO ssh_accounts VALUES (?,?,?,?)",[
            ("alice",DEFAULT,"ssh","🟢 فعال"),
            ("bob",DEFAULT,"ssh","🟢 فعال"),
        ])
        self.db.commit()

    def change(self, key, value):
        self.db.execute("UPDATE settings SET value=? WHERE key=?", (value,key))
        self.db.commit()

    def test_realistic_drift_restores_default_first_excludes_standby(self):
        plan=project_customer_hosts(self.db)
        self.assertEqual(plan.before,self.original)
        self.assertEqual(plan.after,",".join((DEFAULT,OLD,EXTRA)))
        self.assertEqual(plan.excluded_standby,(STANDBY,))
        self.assertNotIn(OTHER,plan.after)  # no implicit inventory promotion

    def test_rebuild_never_writes_dns_user_or_role_and_is_idempotent(self):
        root = Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"
        tree = ast.parse(root.read_text())
        fun = next(node for node in tree.body if isinstance(node,ast.FunctionDef)
                   and node.name=="_db_rebuild_hosts_from_pool")
        mod = ast.Module(body=[fun],type_ignores=[])
        @contextmanager
        def connection():
            with self.db:
                yield self.db
        g = {
            "db_conn":connection,
            "_db_assert_legacy_host_mutation_allowed":lambda conn:None,
            "_db_assert_account_write_allowed":lambda conn:None,
        }
        exec(compile(mod,str(root),"exec"),g)
        before_role = self.db.execute("SELECT * FROM host_pool ORDER BY host").fetchall()
        before_users = self.db.execute("SELECT * FROM ssh_accounts ORDER BY username").fetchall()
        g["_db_rebuild_hosts_from_pool"]()
        g["_db_rebuild_hosts_from_pool"]()
        self.assertEqual(self.db.execute(
            "SELECT value FROM settings WHERE key='hosts'").fetchone()[0],
            ",".join((DEFAULT,OLD,EXTRA)))
        self.assertEqual(before_role,self.db.execute(
            "SELECT * FROM host_pool ORDER BY host").fetchall())
        self.assertEqual(before_users,self.db.execute(
            "SELECT * FROM ssh_accounts ORDER BY username").fetchall())
        self.assertEqual(self.db.execute(
            "SELECT value FROM settings WHERE key='dns_current_ip'").fetchone()[0],
            DEFAULT)

    def test_explicit_activation_adds_only_known_nonstandby(self):
        p = project_customer_hosts(self.db,add_host=OTHER)
        self.assertEqual(p.after,",".join((DEFAULT,OLD,EXTRA,OTHER)))
        for candidate in (STANDBY,"203.0.113.22",CORE):
            with self.subTest(candidate=candidate):
                with self.assertRaises(LegacyRouteHold):
                    project_customer_hosts(self.db,add_host=candidate)

    def test_drift_in_default_dns_core_and_customer_assignment_blocks(self):
        self.change("dns_current_ip",OLD)
        with self.assertRaisesRegex(LegacyRouteHold,"CACHED_DNS_OR_CORE_MISMATCH"):
            project_customer_hosts(self.db)
        self.change("dns_current_ip",DEFAULT)
        self.db.execute("UPDATE ssh_accounts SET host=? WHERE username='bob'",(OLD,))
        self.db.commit()
        with self.assertRaisesRegex(LegacyRouteHold,"ACTIVE_CUSTOMERS_NOT_ON_DEFAULT"):
            project_customer_hosts(self.db)
        self.db.execute("UPDATE ssh_accounts SET host=? WHERE username='bob'",(DEFAULT,))
        self.db.execute("UPDATE host_pool SET is_default=1 WHERE host=?",(OLD,))
        self.db.commit()
        with self.assertRaisesRegex(LegacyRouteHold,"DEFAULT_NOT_UNIQUE"):
            project_customer_hosts(self.db)

    def test_legacy_text_editor_rejects_unverified_or_standby_or_reordered(self):
        with self.assertRaisesRegex(LegacyRouteHold,"LEGACY_DEFAULT_MUST_BE_FIRST"):
            validate_customer_host_edit(self.db, OLD+","+DEFAULT)
        with self.assertRaisesRegex(LegacyRouteHold,"LEGACY_HOST_NOT_CUSTOMER_ELIGIBLE"):
            validate_customer_host_edit(self.db, DEFAULT+","+STANDBY)
        with self.assertRaisesRegex(LegacyRouteHold,"LEGACY_HOST_NOT_CUSTOMER_ELIGIBLE"):
            validate_customer_host_edit(self.db, DEFAULT+",203.0.113.99")
        with self.assertRaisesRegex(LegacyRouteHold,"LEGACY_HOSTS_MALFORMED"):
            validate_customer_host_edit(self.db, DEFAULT+","+DEFAULT)
        self.assertEqual(validate_customer_host_edit(self.db,DEFAULT+","+OLD),
                         (DEFAULT,OLD))

    def test_operator_cas_is_stale_safe_and_metadata_only(self):
        with self.assertRaisesRegex(LegacyRouteHold,"OPERATOR_PREVIEW_STALE"):
            repair_local_metadata(
                self.db,expected_before="wrong",expected_default=DEFAULT)
        self.assertEqual(self.db.execute(
            "SELECT value FROM settings WHERE key='hosts'").fetchone()[0],
            self.original)
        roles=self.db.execute("SELECT * FROM host_pool ORDER BY host").fetchall()
        self.db.execute("BEGIN IMMEDIATE")
        p=repair_local_metadata(self.db,expected_before=self.original,
                                expected_default=DEFAULT)
        self.db.commit()
        self.assertEqual(p.after,",".join((DEFAULT,OLD,EXTRA)))
        self.assertEqual(roles,self.db.execute(
            "SELECT * FROM host_pool ORDER BY host").fetchall())

    def test_old_srv_mkactive_does_not_write_default_before_cloudflare(self):
        source=(Path(__file__).resolve().parents[1] /
                "bot_final_v49-2.py").read_text()
        block=source.split('elif d.startswith("srv_mkactive_")')[1]
        block=block.split('elif d == "srv_wiz_promote_start"')[0]
        self.assertIn("k2_native_operations_registered()",block)
        self.assertIn("CZ04B",block)
        for unsafe in ("_db_set_default_host", "_cf_update_dns_record_sync",
                       "_update_cloudflare_dns", "spawn_bg_task(_make_edge_active())"):
            self.assertNotIn(unsafe,block)

    def test_existing_telegram_callbacks_no_longer_perform_unjournaled_cutover(self):
        source=(Path(__file__).resolve().parents[1]/
                "bot_final_v49-2.py").read_text()
        block=source.split('elif d.startswith(("hpdef_migrate_", "hpdefmig_yes_", "hpdef_"))')[1]
        block=block.split("    # 🗑 حذف‌شده: خریدِ خودکارِ VPS")[0]
        self.assertIn("return",block)
        self.assertNotIn("_db_set_default_host",block)
        self.assertNotIn("_db_set_all_accounts_host",block)
        other=source.split('elif d.startswith("ipallconf_yes_")')[1]
        other=other.split('elif d == "ipsvc_auto"')[0]
        self.assertIn("return",other)
        self.assertNotIn("_update_cloudflare_dns",other)

if __name__=="__main__":
    unittest.main()
