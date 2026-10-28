"""Phase-2 recovery guards: hermetic SQLite, no Cloudzy/SSH/network writes."""
from contextlib import contextmanager
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from cloudzy_recovery import (
    RecoveryHold, commit_existing_install, commit_standby_resume,
    inspect_inactive_install, recovery_kind, recovery_message,
)


class RecoverySQLiteTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "rec.db"
        with self.db() as db:
            db.executescript("""
                CREATE TABLE cloudzy_edge_operations (
                    id TEXT PRIMARY KEY, status TEXT, actor_id INTEGER,
                    chat_id INTEGER, public_ipv4 TEXT, provider_server_id TEXT,
                    hold_reason TEXT, updated_at INTEGER);
                CREATE TABLE cloudzy_cz06_runs (
                    operation_id TEXT PRIMARY KEY, stage TEXT, actor_id INTEGER,
                    chat_id INTEGER, updated_at INTEGER, detail_code TEXT);
                CREATE TABLE host_pool (
                    host TEXT,active INTEGER,is_default INTEGER,is_standby INTEGER,
                    provider TEXT,provider_instance_id TEXT);
                CREATE TABLE ssh_accounts (username TEXT,host TEXT);
                CREATE TABLE settings (key TEXT PRIMARY KEY,value TEXT);
                CREATE TABLE cloudzy_cz04a_actions (status TEXT);
                CREATE TABLE cloudzy_cz04b_operations (status TEXT);
                CREATE TABLE cloudzy_cz07_jobs (status TEXT);
                CREATE TABLE failover_operations (status TEXT);
            """)
            db.execute(
                "INSERT INTO cloudzy_edge_operations VALUES "
                "('purchase-1','HOLD_PROVISION',7,8,'8.8.8.8',"
                "'provider-1','PARTIAL_OR_UNVERIFIED_LEGACY_INSTALL',100)")
            db.execute("INSERT INTO cloudzy_cz06_runs VALUES "
                       "('purchase-1','HOLD',7,8,100,'INSTALL_REQUIRES_RECONCILIATION')")
            db.execute("INSERT INTO host_pool VALUES "
                       "('8.8.8.8',0,0,0,'cloudzy','provider-1')")
            db.executemany("INSERT INTO settings VALUES (?,?)", [
                ("hosts", "source.example"), ("dns_current_ip", "source.example"),
                ("core_wg_public_ip", "9.9.9.9"),
                ("auto_failover_mode", "0"), ("phase6h_auto_failover_enabled", "0"),
                ("edge_egress_v1_onboard_enabled", "0"),
            ])

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path)
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def receipt(self):
        with self.db() as db:
            db.row_factory = sqlite3.Row
            return dict(db.execute("SELECT * FROM cloudzy_edge_operations").fetchone())

    def test_recovery_status_is_readable_and_no_auto_install_is_offered(self):
        op = self.receipt()
        self.assertEqual(recovery_kind(op, {"stage": "HOLD"}),
                         "EXISTING_INSTALL_CHECK")
        self.assertIn("همان VPS", recovery_message(op))
        self.assertEqual(recovery_kind({"status": "PROVISIONING"}), "IN_PROGRESS")
        self.assertEqual(recovery_kind({"status": "CREATE_UNCERTAIN"}),
                         "NEEDS_PROVIDER_CHECK")
        self.assertEqual(recovery_kind({"status": "EDGE_READY"},
                                       {"stage": "HOLD"}), "STANDBY_RECHECK")

    def test_existing_installed_edge_can_be_adopted_once_atomically(self):
        with self.db() as db:
            self.assertEqual(inspect_inactive_install(db, self.receipt())["ip"], "8.8.8.8")
        self.assertEqual(
            commit_existing_install(self.db, "purchase-1",
                                    actor=7, chat=8, now=120), "EDGE_READY")
        with self.db() as db:
            self.assertEqual(db.execute(
                "SELECT status,hold_reason FROM cloudzy_edge_operations"
            ).fetchone(), ("EDGE_READY", None))
            self.assertEqual(db.execute(
                "SELECT stage,detail_code FROM cloudzy_cz06_runs"
            ).fetchone(), ("EDGE_READY", "RECOVERED_INSTALLED_EDGE"))
            self.assertEqual(db.execute(
                "SELECT kind FROM cloudzy_edge_recovery_audit"
            ).fetchone()[0], "VERIFIED_EXISTING_INSTALL")
        with self.assertRaises(RecoveryHold):
            commit_existing_install(self.db, "purchase-1", actor=7, chat=8, now=130)
        self.assertEqual(self.receipt()["status"], "EDGE_READY")

    def test_recovery_denies_duplicate_host_provider_and_assigned_users(self):
        for update, expected in [
            ("INSERT INTO host_pool VALUES ('8.8.8.9',0,0,0,'cloudzy','provider-1')",
             "RECOVERY_HOST_NOT_ISOLATED"),
            ("UPDATE host_pool SET active=1 WHERE host='8.8.8.8'",
             "RECOVERY_HOST_NOT_ISOLATED"),
            ("INSERT INTO ssh_accounts VALUES ('client','8.8.8.8')",
             "RECOVERY_USERS_ASSIGNED"),
            ("UPDATE settings SET value='8.8.8.8' WHERE key='dns_current_ip'",
             "RECOVERY_ROUTE_ALREADY_REFERENCES_EDGE"),
            ("UPDATE settings SET value='1' WHERE key='auto_failover_mode'",
             "RECOVERY_AUTOMATION_OR_K2_ACTIVE"),
            ("INSERT INTO cloudzy_cz04a_actions VALUES('HOLD')",
             "RECOVERY_OTHER_OPERATION_RUNNING"),
            ("INSERT INTO cloudzy_cz07_jobs VALUES('MIGRATING')",
             "RECOVERY_OTHER_OPERATION_RUNNING"),
        ]:
            with self.subTest(update=update):
                with self.db() as db:
                    db.execute("SAVEPOINT scenario")
                    db.execute(update)
                    with self.assertRaisesRegex(RecoveryHold, expected):
                        inspect_inactive_install(db, self.receipt())
                    db.execute("ROLLBACK TO scenario")
                    db.execute("RELEASE scenario")
                self.assertEqual(self.receipt()["status"], "HOLD_PROVISION")

    def test_actor_mismatch_and_stage_change_are_fail_closed(self):
        with self.assertRaisesRegex(RecoveryHold, "RECOVERY_OWNER_MISMATCH"):
            commit_existing_install(self.db, "purchase-1", actor=44, chat=8, now=150)
        with self.db() as db:
            db.execute("UPDATE cloudzy_cz06_runs SET stage='STANDBY_VERIFYING'")
        with self.assertRaisesRegex(RecoveryHold, "RECOVERY_QUICK_STAGE_CHANGED"):
            commit_existing_install(self.db, "purchase-1", actor=7, chat=8, now=150)
        self.assertEqual(self.receipt()["status"], "HOLD_PROVISION")

    def test_standby_resume_cas_requires_both_ready_receipt_and_hold_run(self):
        with self.db() as db:
            db.execute("UPDATE cloudzy_edge_operations SET status='EDGE_READY'")
        self.assertEqual(
            commit_standby_resume(self.db, "purchase-1",
                                  actor=7, chat=8, now=150), "STANDBY_VERIFYING")
        with self.db() as db:
            self.assertEqual(db.execute("SELECT stage FROM cloudzy_cz06_runs").fetchone()[0],
                             "STANDBY_VERIFYING")
        with self.assertRaises(RecoveryHold):
            commit_standby_resume(self.db, "purchase-1", actor=7, chat=8, now=170)

    def test_completed_transport_does_not_block_existing_install_recovery(self):
        with self.db() as db:
            db.execute("INSERT INTO cloudzy_cz07_jobs VALUES ('MOVED')")
            proof = inspect_inactive_install(db, self.receipt())
            self.assertEqual(proof["ip"], "8.8.8.8")
        with self.db() as db:
            db.execute("UPDATE cloudzy_cz07_jobs SET status='VERIFYING'")
            with self.assertRaisesRegex(
                    RecoveryHold, "RECOVERY_OTHER_OPERATION_RUNNING"):
                inspect_inactive_install(db, self.receipt())

    def test_completed_transport_does_not_block_standby_resume(self):
        with self.db() as db:
            db.execute("UPDATE cloudzy_edge_operations SET status='EDGE_READY'")
            db.execute("INSERT INTO cloudzy_cz07_jobs VALUES ('MOVED')")
        self.assertEqual(
            commit_standby_resume(
                self.db, "purchase-1", actor=7, chat=8, now=150),
            "STANDBY_VERIFYING")
        with self.db() as db:
            self.assertEqual(db.execute(
                "SELECT stage FROM cloudzy_cz06_runs"
            ).fetchone()[0], "STANDBY_VERIFYING")

    def test_verifying_migration_still_blocks_standby_resume(self):
        with self.db() as db:
            db.execute("UPDATE cloudzy_edge_operations SET status='EDGE_READY'")
            db.execute("INSERT INTO cloudzy_cz07_jobs VALUES ('VERIFYING')")
        with self.assertRaisesRegex(
                RecoveryHold, "RECOVERY_OTHER_OPERATION_RUNNING"):
            commit_standby_resume(
                self.db, "purchase-1", actor=7, chat=8, now=150)
        with self.db() as db:
            self.assertEqual(db.execute(
                "SELECT stage FROM cloudzy_cz06_runs"
            ).fetchone()[0], "HOLD")

    def test_standby_resume_blocks_other_leases_and_non_owner(self):
        with self.db() as db:
            db.execute("UPDATE cloudzy_edge_operations SET status='EDGE_READY'")
            db.execute("INSERT INTO cloudzy_cz04b_operations VALUES('HOLD')")
        with self.assertRaisesRegex(RecoveryHold, "RECOVERY_OTHER_OPERATION_RUNNING"):
            commit_standby_resume(self.db, "purchase-1", actor=7, chat=8, now=140)
        with self.db() as db:
            db.execute("DELETE FROM cloudzy_cz04b_operations")
        with self.assertRaisesRegex(RecoveryHold, "RECOVERY_EDGE_NOT_READY_OR_OWNER_CHANGED"):
            commit_standby_resume(self.db, "purchase-1", actor=9, chat=8, now=140)


if __name__ == "__main__":
    unittest.main()
