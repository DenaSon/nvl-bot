"""Registration is real but never promotes an unproven IP to customer traffic."""
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from legacy_manual_host_registration import PendingEdgeHold, register_pending_edge


NEW="144.172.68.248"
OLD="153.75.87.190"
CORE="91.107.170.239"


class RegisterPendingEdgeTest(unittest.TestCase):
    def setUp(self):
        d=TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.path=Path(d.name)/"test.db"
        with sqlite3.connect(self.path) as db:
            db.executescript("""
                CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
                CREATE TABLE host_pool (
                    host TEXT PRIMARY KEY,active INTEGER,is_default INTEGER DEFAULT 0,
                    is_standby INTEGER DEFAULT 0,added_at TEXT,ssh_port INTEGER,
                    service_port INTEGER,admin_ssh_port INTEGER);
                CREATE TABLE ssh_accounts(username TEXT,host TEXT);
                CREATE TABLE cloudzy_edge_operations(public_ipv4 TEXT,status TEXT);
                CREATE TABLE manual_edge_operations(ip TEXT,status TEXT);
            """)
            db.executemany("INSERT INTO settings VALUES(?,?)", [
                ("core_wg_public_ip",CORE),("dns_current_ip",OLD),
                ("hosts",OLD),("port","2252")
            ])
            db.execute(
                "INSERT INTO host_pool VALUES(?,1,1,0,'2026',2252,2252,22)",
                (OLD,)
            )
            db.execute("INSERT INTO ssh_accounts VALUES ('customer',?)",(OLD,))

        @contextmanager
        def factory():
            with sqlite3.connect(self.path) as db:
                yield db
        self.factory=factory
        self.guard=lambda db: None

    def snapshot(self):
        with self.factory() as db:
            return (
                db.execute("SELECT * FROM settings ORDER BY key").fetchall(),
                db.execute("SELECT * FROM ssh_accounts").fetchall(),
                db.execute("SELECT * FROM host_pool WHERE host=?", (OLD,)).fetchall(),
            )

    def test_new_public_edge_is_only_inactive_inventory(self):
        before=self.snapshot()
        result=register_pending_edge(self.factory,NEW,guard=self.guard)
        self.assertEqual(result["status"],"INVENTORY_PENDING")
        self.assertEqual(result["service_port"],2252)
        with self.factory() as db:
            row=db.execute(
                "SELECT active,is_default,is_standby,service_port,admin_ssh_port "
                "FROM host_pool WHERE host=?",(NEW,)
            ).fetchone()
        self.assertEqual(row,(0,0,0,2252,22))
        self.assertEqual(self.snapshot(),before)

    def test_duplicate_does_not_mutate_existing_host(self):
        register_pending_edge(self.factory,NEW,guard=self.guard)
        before=self.path.read_bytes()
        with self.assertRaisesRegex(PendingEdgeHold,"EDGE_ALREADY_REGISTERED"):
            register_pending_edge(self.factory,NEW,guard=self.guard)
        self.assertEqual(self.path.read_bytes(),before)

    def test_nonpublic_and_core_rejected(self):
        for ip in ("127.0.0.1","10.77.0.125","192.168.1.1","1.1.1.1:22",
                   "example.com","153.75.87.190/32",CORE,""):
            with self.subTest(ip=ip),self.assertRaises(PendingEdgeHold):
                register_pending_edge(self.factory,ip,guard=self.guard)

    def test_protected_guard_blocks_before_insert(self):
        def block(db):
            raise RuntimeError("PROTECTED_ROUTING_ACTIVE")
        before=self.snapshot()
        with self.assertRaisesRegex(RuntimeError,"PROTECTED"):
            register_pending_edge(self.factory,NEW,guard=block)
        with self.factory() as db:
            self.assertIsNone(db.execute(
                "SELECT 1 FROM host_pool WHERE host=?",(NEW,)
            ).fetchone())
        self.assertEqual(self.snapshot(),before)

    def test_no_core_identity_fail_closed(self):
        with self.factory() as db:
            db.execute("DELETE FROM settings WHERE key='core_wg_public_ip'")
        with self.assertRaisesRegex(PendingEdgeHold,"CORE_IDENTITY_UNAVAILABLE"):
            register_pending_edge(self.factory,NEW,guard=self.guard)

    def test_existing_manual_or_cloudzy_receipt_not_claimed(self):
        for table,columns in [
            ("manual_edge_operations",("ip","status")),
            ("cloudzy_edge_operations",("public_ipv4","status"))
        ]:
            with self.subTest(table=table):
                with self.factory() as db:
                    db.execute(
                        f"INSERT INTO {table} ({','.join(columns)}) VALUES (?,?)",
                        (NEW,"EDGE_READY")
                    )
                with self.assertRaises(PendingEdgeHold):
                    register_pending_edge(self.factory,NEW,guard=self.guard)
                with self.factory() as db:
                    db.execute(f"DELETE FROM {table}")

    def test_bad_port_prevents_registration(self):
        with self.factory() as db:
            db.execute("UPDATE settings SET value='0' WHERE key='port'")
        with self.assertRaisesRegex(PendingEdgeHold,"CUSTOMER_PORT_INVALID"):
            register_pending_edge(self.factory,NEW,guard=self.guard)


class BotWiringTest(unittest.TestCase):
    def test_bot_ip_submit_is_not_an_unconditional_refusal(self):
        path=Path(__file__).resolve().parents[1]/"bot_final_v49-2.py"
        source=path.read_text(encoding="utf-8")
        sec=source.split("elif state == 'HOSTPOOL_ADD_INPUT':",1)[1].split(
            "elif state == 'EDGE_NEW_IP':",1)[0]
        self.assertIn("register_pending_edge",sec)
        self.assertIn("INVENTORY_PENDING", 
            (Path(__file__).resolve().parents[1]/
             "legacy_manual_host_registration.py").read_text("utf-8"))
        self.assertNotIn("ثبت مستقیم IP به‌عنوان Relay فعال",sec)
        self.assertNotIn("_db_set_host_active",sec)
        self.assertNotIn("_cf_switch_public_domain",sec)
        activate=source.split('elif d.startswith("hpact_")',1)[1].split(
            'elif d.startswith("hpdelconfirm_")',1)[0]
        self.assertIn('local_path.get("wg_peer_ok") is True',activate)
        self.assertIn('local_path.get("core_path_ok") is True',activate)
        self.assertIn('service_ok and admin_ok',activate)


if __name__=="__main__":
    unittest.main()
