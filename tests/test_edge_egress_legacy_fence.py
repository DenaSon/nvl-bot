"""F1: no legacy Core DNS/host mutation once any protected mapping exists."""
import sqlite3
import unittest

from edge_egress_legacy_fence import (
    LEGACY_PROTECTED_BINDINGS_BLOCKED,
    assert_legacy_mutation_safe,
    has_protected_bindings,
    any_protected_bindings,
)


class LegacyFenceTests(unittest.TestCase):
    def test_old_database_without_mapping_remains_compatible(self):
        with sqlite3.connect(":memory:") as conn:
            self.assertFalse(has_protected_bindings(conn))
            assert_legacy_mutation_safe(conn)

    def test_empty_mapping_remains_compatible(self):
        with sqlite3.connect(":memory:") as conn:
            conn.execute("CREATE TABLE edge_egress_uid_bindings "
                         "(username TEXT, status TEXT)")
            self.assertFalse(has_protected_bindings(conn))
            assert_legacy_mutation_safe(conn)

    def test_one_protected_mapping_blocks_mutation_even_if_global_flag_off(self):
        with sqlite3.connect(":memory:") as conn:
            conn.execute("CREATE TABLE edge_egress_uid_bindings "
                         "(username TEXT, status TEXT)")
            conn.execute("INSERT INTO edge_egress_uid_bindings VALUES "
                         "('nvl0557', 'PROTECTED')")
            self.assertTrue(has_protected_bindings(conn))
            with self.assertRaisesRegex(RuntimeError, LEGACY_PROTECTED_BINDINGS_BLOCKED):
                assert_legacy_mutation_safe(conn)

    def test_malformed_mapping_fails_closed(self):
        with sqlite3.connect(":memory:") as conn:
            conn.execute("CREATE TABLE edge_egress_uid_bindings (username TEXT)")
            with self.assertRaises(sqlite3.OperationalError):
                has_protected_bindings(conn)

    def test_callable_db_factory(self):
        database = sqlite3.connect(":memory:")
        try:
            def db_conn():
                return database
            # Context-managed connection still works and retains in-memory db.
            self.assertFalse(any_protected_bindings(db_conn))
        finally:
            database.close()


if __name__ == "__main__":
    unittest.main()
