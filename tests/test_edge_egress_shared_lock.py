"""D1-C2: shared Phase 6G persisted-lock and transactional legacy-write fences."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta
import json
import sqlite3
import sys
import unittest

from edge_egress_handoff import is_egress_recovery_hold
from edge_egress_lifecycle import PROTECTED_SETTING_KEY, PROTECTED_SETTING_DEFAULT, legacy_failover_gate
from safe_failover import (
    FAILOVER_STATUS_RUNNING, FAILOVER_STATUS_FAILED,
    FAILOVER_STATUS_ABORTED_STALE, FAILOVER_MODE_MANUAL,
)

if sys.version_info >= (3, 12):
    from test_edge_egress_bot_integration import get_function


def memory_database():
    conn = sqlite3.connect(":memory:")
    conn.executescript("""
    CREATE TABLE failover_operations (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       mode TEXT, source_host TEXT, target_host TEXT, status TEXT,
       started_at TEXT, updated_at TEXT, finished_at TEXT,
       detail_json TEXT, error TEXT
    );
    CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE host_pool (
      host TEXT PRIMARY KEY, active INTEGER, is_default INTEGER, is_standby INTEGER,
      consecutive_fails INTEGER, disabled_reason TEXT, disabled_at TEXT,
      last_status TEXT, last_check TEXT
    );
    CREATE TABLE ssh_accounts (
      username TEXT PRIMARY KEY, host TEXT, service_type TEXT, status TEXT
    );
    INSERT INTO settings(key,value) VALUES ('edge_egress_protected_mode','0');
    INSERT INTO host_pool(host,active,is_default,is_standby)
      VALUES ('172.86.94.174',1,1,0), ('216.126.229.12',1,0,1);
    INSERT INTO ssh_accounts(username,host,service_type,status)
      VALUES ('nvl0557','172.86.94.174','ssh','🟢 فعال');
    """)
    conn.commit()
    return conn


class PureHoldClassifierTests(unittest.TestCase):
    def test_unresolved_cutover_phases_are_never_stale_recoverable(self):
        for phase in (
            "ARM_FAIL_CLOSED", "SELECT_TARGET_EGRESS", "VERIFY_CUSTOMER_EGRESS",
            "SOURCE_ACCOUNT_CAS", "EDGE_ONLY_DNS_CUTOVER", "VERIFY_FINAL",
            "EGRESS_RECOVERY_REQUIRED",
        ):
            with self.subTest(phase=phase):
                self.assertTrue(is_egress_recovery_hold(json.dumps({"phase": phase})))

    def test_preparation_and_legacy_phases_keep_existing_stale_semantics(self):
        for data in (
            None, "", "{}", "not valid JSON", json.dumps({"phase": "CANDIDATE_STAGE"}),
            json.dumps({"phase": "REBUILD_COMPLETE"}),
            json.dumps({"phase": "SUCCEEDED"}),
        ):
            with self.subTest(data=data):
                self.assertFalse(is_egress_recovery_hold(data))


@unittest.skipIf(sys.version_info < (3, 12), "Main NVL bot requires Python 3.12+")
class Phase6GSharedLockTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_database()

        @contextmanager
        def db_conn():
            try:
                yield self.conn
                self.conn.commit()
            except Exception:
                self.conn.rollback()
                raise

        self.ctx = db_conn
        self.old = (datetime.now() - timedelta(days=4)).strftime("%Y-%m-%d %H:%M:%S")
        self.fn = get_function("_db_acquire_failover_lock", {
            "db_conn": self.ctx,
            "datetime": datetime,
            "is_egress_recovery_hold": is_egress_recovery_hold,
            "_parse_flexible_datetime": datetime.fromisoformat,
            "FAILOVER_LOCK_STALE_SECONDS": 300,
            "FAILOVER_MODE_MANUAL": FAILOVER_MODE_MANUAL,
            "FAILOVER_STATUS_RUNNING": FAILOVER_STATUS_RUNNING,
            "FAILOVER_STATUS_ABORTED_STALE": FAILOVER_STATUS_ABORTED_STALE,
        })

    def tearDown(self):
        self.conn.close()

    def insert_lock(self, phase):
        cur = self.conn.execute(
            "INSERT INTO failover_operations "
            "(mode,source_host,target_host,status,started_at,updated_at,detail_json)"
            "VALUES (?,?,?,?,?,?,?)",
            (FAILOVER_MODE_MANUAL, "172.86.94.174", "216.126.229.12",
             FAILOVER_STATUS_RUNNING, self.old, self.old,
             json.dumps({"phase": phase})),
        )
        self.conn.commit()
        return cur.lastrowid

    def test_old_protected_lock_remains_busy_after_timeout(self):
        for phase in ("ARM_FAIL_CLOSED", "EDGE_ONLY_DNS_CUTOVER",
                      "EGRESS_RECOVERY_REQUIRED"):
            with self.subTest(phase=phase):
                self.conn.execute("DELETE FROM failover_operations")
                self.conn.commit()
                old_id = self.insert_lock(phase)
                operation_id, busy_id = self.fn("172.86.94.174", "216.126.229.12")
                self.assertIsNone(operation_id)
                self.assertEqual(busy_id, old_id)
                rows = self.conn.execute("SELECT status FROM failover_operations").fetchall()
                self.assertEqual(rows, [(FAILOVER_STATUS_RUNNING,)])

    def test_ordinary_legacy_stale_lock_still_recovers(self):
        old_id = self.insert_lock("REBUILD_COMPLETE")
        new_id, busy = self.fn("172.86.94.174", "216.126.229.12")
        self.assertIsNone(busy)
        self.assertNotEqual(new_id, old_id)
        self.assertEqual(
            self.conn.execute("SELECT status FROM failover_operations WHERE id=?",
                              (old_id,)).fetchone()[0],
            FAILOVER_STATUS_ABORTED_STALE,
        )
        self.assertEqual(
            self.conn.execute("SELECT status FROM failover_operations WHERE id=?",
                              (new_id,)).fetchone()[0],
            FAILOVER_STATUS_RUNNING,
        )

    def test_fresh_lock_still_rejects_concurrent_attempt(self):
        old_id = self.insert_lock("REBUILD_COMPLETE")
        self.conn.execute(
            "UPDATE failover_operations SET updated_at=? WHERE id=?",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), old_id),
        )
        self.conn.commit()
        op_id, busy = self.fn("172.86.94.174", "216.126.229.12")
        self.assertIsNone(op_id)
        self.assertEqual(busy, old_id)


@unittest.skipIf(sys.version_info < (3, 12), "Main NVL bot requires Python 3.12+")
class ProtectedLegacyDbMutationTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_database()

        @contextmanager
        def db_conn():
            try:
                yield self.conn
                self.conn.commit()
            except Exception:
                self.conn.rollback()
                raise
        self.db_conn = db_conn
        self.guard = get_function("_db_assert_legacy_host_mutation_allowed", {
            "PROTECTED_SETTING_KEY": PROTECTED_SETTING_KEY,
            "PROTECTED_SETTING_DEFAULT": PROTECTED_SETTING_DEFAULT,
            "legacy_failover_gate": legacy_failover_gate,
        })

        env = {
            "db_conn": db_conn,
            "_db_assert_legacy_host_mutation_allowed": self.guard,
            "_db_assert_account_write_allowed": lambda c: None,
            "datetime": datetime,
        }
        self.default = get_function("_db_set_default_host", env)
        self.bulk = get_function("_db_set_all_accounts_host", env)
        self.set_active = get_function("_db_set_host_active", env)
        self.set_setting = get_function("_db_update_setting", env)

    def tearDown(self):
        self.conn.close()

    def protected(self):
        self.conn.execute(
            "UPDATE settings SET value='1' WHERE key='edge_egress_protected_mode'")
        self.conn.commit()

    def test_protected_mode_denies_default_bulk_activation_and_host_config(self):
        self.protected()
        for action in (
            lambda: self.default("216.126.229.12"),
            lambda: self.bulk("216.126.229.12"),
            lambda: self.set_active("172.86.94.174", False),
            lambda: self.set_setting("dns_current_ip", "209.200.246.198"),
            lambda: self.set_setting("hosts", "216.126.229.12"),
        ):
            with self.subTest(action=str(action)), self.assertRaises(RuntimeError):
                action()
        self.assertEqual(
            self.conn.execute("SELECT host FROM host_pool WHERE is_default=1").fetchone()[0],
            "172.86.94.174",
        )
        self.assertEqual(
            self.conn.execute("SELECT host FROM ssh_accounts WHERE username='nvl0557'").fetchone()[0],
            "172.86.94.174",
        )

    def test_default_zero_keeps_existing_default_host_behavior(self):
        self.default("216.126.229.12")
        self.assertEqual(
            self.conn.execute("SELECT host FROM host_pool WHERE is_default=1").fetchone()[0],
            "216.126.229.12",
        )
        self.bulk("216.126.229.12")
        self.assertEqual(
            self.conn.execute("SELECT host FROM ssh_accounts WHERE username='nvl0557'").fetchone()[0],
            "216.126.229.12",
        )


if __name__ == "__main__":
    unittest.main()
