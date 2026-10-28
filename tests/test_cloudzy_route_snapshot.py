"""Phase 1: deterministic, read-only route evidence and regression fixtures."""
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from cloudzy_route_snapshot import inspect_route, format_route_report, main


CORE = "91.107.170.239"
DEFAULT = "45.59.113.249"
OLD = "144.172.69.2"
STANDBY = "45.59.113.161"


class RouteSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.db.executescript("""
            CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE host_pool (
                host TEXT PRIMARY KEY, active INTEGER, is_default INTEGER,
                is_standby INTEGER, provider TEXT, provider_instance_id TEXT
            );
            CREATE TABLE ssh_accounts(
                username TEXT, host TEXT, status TEXT, service_type TEXT
            );
        """)
        self.db.executemany("INSERT INTO settings VALUES(?,?)", [
            ("core_wg_public_ip", CORE),
            ("dns_current_ip", DEFAULT),
            ("hosts", DEFAULT),
        ])
        self.db.executemany("INSERT INTO host_pool VALUES(?,?,?,?,?,?)", [
            (DEFAULT, 1, 1, 0, None, None),
            (OLD, 1, 0, 0, "cloudzy", "provider-old"),
            (STANDBY, 1, 0, 1, "cloudzy", "provider-standby"),
            (CORE, 1, 0, 0, None, None),
        ])
        self.db.executemany("INSERT INTO ssh_accounts VALUES(?,?,?,?)", [
            ("alice", DEFAULT, "🟢 فعال", "ssh"),
            ("bob", DEFAULT, "🟢 فعال", "ssh"),
            ("expired", OLD, "🔴 غیرفعال", "ssh"),
            ("v2", OLD, "🟢 فعال", "v2ray"),
        ])
        self.db.commit()

    def setting(self, key, value):
        self.db.execute("UPDATE settings SET value=? WHERE key=?", (value, key))
        self.db.commit()

    def codes(self):
        return {issue.code for issue in inspect_route(self.db).issues}

    def test_healthy_route_and_exact_customer_filter(self):
        snap = inspect_route(self.db)
        self.assertTrue(snap.consistent)
        self.assertEqual(snap.sale_gate_code, "PASS")
        self.assertEqual(snap.active_assignments, ((DEFAULT, 2),))
        self.assertEqual(snap.default_hosts, (DEFAULT,))
        # Only candidate by ROLE, not verified network/provider healthy.
        self.assertEqual(snap.eligible_candidates, (OLD, DEFAULT))
        self.assertFalse(snap.live_dns_verified)

    def test_production_2026_10_28_default_last_reproduction(self):
        self.setting("hosts",
                     f"{OLD},144.172.69.3,144.172.69.10,"
                     f"{STANDBY},45.59.113.202,{DEFAULT}")
        self.db.executemany(
            "INSERT INTO ssh_accounts VALUES(?,?,?,?)",
            [(f"nvl{i:04d}", DEFAULT, "🟢 فعال", "ssh") for i in range(486)],
        )
        self.db.commit()
        snap = inspect_route(self.db)
        self.assertEqual(snap.active_assignments, ((DEFAULT, 488),))
        self.assertEqual(snap.sale_gate_code, "DEFAULT_CUSTOMER_RELAY_ROUTE_MISMATCH")
        self.assertIn("LEGACY_HOSTS_ORDER_MISMATCH", self.codes())
        self.assertIn("STANDBY_IN_LEGACY_HOSTS", self.codes())
        self.assertIn("LEGACY_HOST_NOT_IN_POOL", self.codes())
        self.assertNotIn("DEFAULT_CUSTOMER_RELAY_NOT_ELIGIBLE", self.codes())
        text = format_route_report(snap)
        self.assertIn("ترتیب مسیرهای Legacy", text)
        self.assertIn("علت:", text)
        self.assertIn("راهنما:", text)
        self.assertIn("۴۸۸", text.replace("488", "۴۸۸"))
        self.assertIn("DNS زنده", text)

    def test_noneligible_default_is_not_confused_with_hosts_order(self):
        self.db.execute("UPDATE host_pool SET active=0 WHERE host=?", (DEFAULT,))
        self.db.commit()
        snap = inspect_route(self.db)
        self.assertEqual(snap.sale_gate_code, "DEFAULT_CUSTOMER_RELAY_NOT_ELIGIBLE")
        self.assertIn("DEFAULT_CUSTOMER_RELAY_NOT_ELIGIBLE", self.codes())
        self.assertNotIn("LEGACY_HOSTS_ORDER_MISMATCH", self.codes())

    def test_standby_default_is_ineligible(self):
        self.db.execute("UPDATE host_pool SET is_standby=1 WHERE host=?", (DEFAULT,))
        self.db.commit()
        self.assertEqual(inspect_route(self.db).sale_gate_code,
                         "DEFAULT_CUSTOMER_RELAY_NOT_ELIGIBLE")

    def test_core_as_default_is_ineligible(self):
        self.db.execute("UPDATE host_pool SET is_default=0 WHERE host=?", (DEFAULT,))
        self.db.execute("UPDATE host_pool SET is_default=1 WHERE host=?", (CORE,))
        self.setting("hosts", CORE)
        self.setting("dns_current_ip", CORE)
        self.assertEqual(inspect_route(self.db).sale_gate_code,
                         "DEFAULT_CUSTOMER_RELAY_NOT_ELIGIBLE")

    def test_duplicate_defaults_are_not_silently_selected(self):
        self.db.execute("UPDATE host_pool SET is_default=1 WHERE host=?", (OLD,))
        self.db.commit()
        snap = inspect_route(self.db)
        self.assertEqual(snap.sale_gate_code, "DEFAULT_CUSTOMER_RELAY_AMBIGUOUS")
        self.assertIn("DEFAULT_CUSTOMER_RELAY_AMBIGUOUS", self.codes())

    def test_no_default_is_not_silently_selected(self):
        self.db.execute("UPDATE host_pool SET is_default=0")
        self.db.commit()
        self.assertIn("DEFAULT_CUSTOMER_RELAY_AMBIGUOUS", self.codes())

    def test_missing_core_precedes_other_sale_gates(self):
        self.setting("core_wg_public_ip", "")
        snap = inspect_route(self.db)
        self.assertEqual(snap.sale_gate_code, "CORE_PUBLIC_IP_UNVERIFIED")
        self.assertIn("CORE_PUBLIC_IP_UNVERIFIED", self.codes())

    def test_dns_mismatch_is_not_live_cloudflare_evidence(self):
        self.setting("dns_current_ip", OLD)
        snap = inspect_route(self.db)
        self.assertIn("CACHED_DNS_DEFAULT_MISMATCH", self.codes())
        self.assertEqual(snap.sale_gate_code, "DEFAULT_CUSTOMER_RELAY_ROUTE_MISMATCH")
        self.assertFalse(snap.live_dns_verified)

    def test_empty_and_duplicate_hosts(self):
        self.setting("hosts", "")
        self.assertIn("LEGACY_HOSTS_EMPTY", self.codes())
        self.setting("hosts", f"{DEFAULT},{DEFAULT}")
        self.assertIn("LEGACY_HOSTS_DUPLICATED", self.codes())

    def test_core_and_standby_in_legacy_hosts_are_only_warnings(self):
        self.setting("hosts", f"{DEFAULT},{STANDBY},{CORE}")
        snap = inspect_route(self.db)
        self.assertTrue(snap.consistent)
        self.assertEqual(snap.sale_gate_code, "PASS")
        self.assertIn("STANDBY_IN_LEGACY_HOSTS", self.codes())
        self.assertIn("CORE_IN_LEGACY_HOSTS", self.codes())

    def test_active_customer_on_other_or_empty_host_is_drift(self):
        self.db.execute(
            "INSERT INTO ssh_accounts VALUES('stray', ?, '🟢 فعال', 'ssh')", (OLD,)
        )
        self.db.execute(
            "INSERT INTO ssh_accounts VALUES('blank', '', '🟢 فعال', 'ssh')"
        )
        self.db.commit()
        snap = inspect_route(self.db)
        self.assertIn("ACTIVE_SSH_ASSIGNMENT_DRIFT", self.codes())
        self.assertIn(f"{OLD}: 1", snap.issues[0].reason_fa if
                      snap.issues[0].code == "ACTIVE_SSH_ASSIGNMENT_DRIFT"
                      else " ".join(i.reason_fa for i in snap.issues))

    def test_inspector_executes_select_only_not_even_table_init(self):
        # Deny *all* mutations: snapshot must neither migrate schema nor change
        # an existing account/DNS/default, even on a reused app connection.
        denied = {
            sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE,
            sqlite3.SQLITE_CREATE_TABLE, sqlite3.SQLITE_DROP_TABLE,
            sqlite3.SQLITE_CREATE_INDEX, sqlite3.SQLITE_DROP_INDEX,
        }
        def guard(op, arg1, arg2, dbname, trigger):
            return sqlite3.SQLITE_DENY if op in denied else sqlite3.SQLITE_OK
        self.db.set_authorizer(guard)
        try:
            self.assertTrue(inspect_route(self.db).consistent)
            with self.assertRaises(sqlite3.DatabaseError):
                self.db.execute("DELETE FROM host_pool")
        finally:
            self.db.set_authorizer(None)

    def test_missing_schema_fails_closed_without_creating_tables(self):
        empty = sqlite3.connect(":memory:")
        self.addCleanup(empty.close)
        with self.assertRaises(sqlite3.OperationalError):
            inspect_route(empty)
        self.assertEqual(empty.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
        ).fetchone()[0], 0)

    def test_cli_reads_existing_db_without_writing(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "fixture.db"
        disk = sqlite3.connect(path)
        self.db.backup(disk)
        disk.close()
        before = path.read_bytes()
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(["--db", str(path)]), 0)
        self.assertEqual(before, path.read_bytes())
        self.assertIn("فقط خواندنی", output.getvalue())


if __name__ == "__main__":
    unittest.main()
