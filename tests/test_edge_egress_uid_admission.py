"""F2: per-account admission defaults to denial on uncertain evidence."""
import sqlite3
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace

from edge_egress_uid_admission import AdmissionResult, decide_account, main
from edge_egress_uid_runtime_store import install_runtime_schema
from edge_egress_protected_mapping import install_protected_mapping_schema


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.c = sqlite3.connect(":memory:")
        self.c.executescript("""
            CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
            INSERT INTO settings VALUES('edge_egress_protected_mode','0');
            CREATE TABLE failover_operations(id INTEGER PRIMARY KEY,status TEXT);
            INSERT INTO failover_operations VALUES(42,'SUCCEEDED');
        """)
        install_runtime_schema(self.c)
        install_protected_mapping_schema(self.c)

    def tearDown(self):
        self.c.close()

    def protect(self, state="PROTECTED"):
        self.c.execute("""
            INSERT INTO edge_egress_uid_runtime
            (username,uid,edge_id,edge_ipv4,route_table,priority,dns_port,
             state,last_operation_id)
            VALUES('nvl0557',1644,'fra1','216.126.229.12',1780,1780,
                   10553,?,42)
        """, (state,))
        self.c.execute("""
            INSERT INTO edge_egress_uid_bindings
            (username,uid,edge_id,edge_ipv4,status)
            VALUES('nvl0557',1644,'fra1','216.126.229.12','PROTECTED')
        """)

    def decide(self, username="nvl0557", uid=1644, verified=True):
        return decide_account(self.c, username, uid, lambda row: verified)

    def test_legacy_user_unchanged_when_registry_migrated_and_flag_off(self):
        self.assertEqual(self.decide().result, AdmissionResult.ALLOW_LEGACY)

    def test_pending_or_frozen_or_hold_must_not_authenticate(self):
        for state in ("BLOCKED", "ROUTED_UNVERIFIED", "FROZEN", "HOLD"):
            with self.subTest(state=state):
                self.c.execute("DELETE FROM edge_egress_uid_runtime")
                self.c.execute("DELETE FROM edge_egress_uid_bindings")
                self.protect(state)
                self.assertEqual(self.decide().result, AdmissionResult.DENY)

    def test_verified_kernel_and_db_mapping_allow_only_matching_uid(self):
        self.protect()
        self.assertEqual(self.decide(verified=True).result,
                         AdmissionResult.ALLOW_PROTECTED)
        for uid in (0,1645):
            self.assertEqual(self.decide(uid=uid).result, AdmissionResult.DENY)
        self.assertEqual(self.decide(verified=False).result, AdmissionResult.DENY)

    def test_running_6g_lock_denies_new_protected_sessions(self):
        self.protect()
        self.c.execute("UPDATE failover_operations SET status='RUNNING'")
        self.assertEqual(self.decide().result, AdmissionResult.DENY)

    def test_stale_mapping_or_missing_runtime_denied(self):
        self.protect()
        self.c.execute("DELETE FROM edge_egress_uid_runtime")
        self.assertEqual(self.decide().result, AdmissionResult.DENY)

    def test_global_protected_mode_never_implicitly_allows_new_users(self):
        self.c.execute(
            "UPDATE settings SET value='1' WHERE key='edge_egress_protected_mode'")
        self.assertEqual(self.decide().result, AdmissionResult.DENY)

    def test_invalid_runtime_schema_and_unavailable_db_fail_closed(self):
        self.c.execute("DROP TABLE edge_egress_uid_runtime")
        self.assertEqual(self.decide().result, AdmissionResult.DENY)
        self.c.execute("DROP TABLE edge_egress_uid_bindings")
        self.assertEqual(self.decide().result, AdmissionResult.DENY)

    def test_root_break_glass_never_needs_core_sqlite(self):
        with patch("edge_egress_uid_admission.os.geteuid", return_value=0), \
             patch.dict("os.environ", {"PAM_TYPE":"account","PAM_USER":"root"}), \
             patch("edge_egress_uid_admission.pwd.getpwnam",
                   return_value=SimpleNamespace(pw_uid=0)), \
             patch("edge_egress_uid_admission.sqlite3.connect",
                   side_effect=AssertionError("root must not need DB")):
            self.assertEqual(main(),0)

    def test_broken_kernel_probe_cannot_allow_protected_user(self):
        self.protect()
        result = decide_account(self.c,"nvl0557",1644,
                                Mock(side_effect=OSError("kernel unavailable")))
        self.assertEqual(result.result, AdmissionResult.DENY)


if __name__ == "__main__":
    unittest.main()
