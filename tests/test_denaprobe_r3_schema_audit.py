"""Offline R3 clean-rollout schema/DB audit. No live DB, network or secrets."""
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from denaprobe_ingest import collector, schema_audit
from ops.denaprobe_sqlite_online_backup import snapshot


class TestCleanR3Schema(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.base = Path(t.name)
        self.previous = self.base / "telemetry.sqlite3"
        self.new = self.base / "telemetry-r3.sqlite3"

    def test_new_schema_has_all_versions_and_no_historical_rows(self):
        # Old legacy DB remains immutable and readable in an adjacent file.
        collector.initialize(self.previous)
        collector.register_target(self.previous, 1, "old-relay.invalid", 2252)
        old = self.previous.read_bytes()
        result = schema_audit.fresh_prepare(self.new)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["quick_check"], "ok")
        self.assertEqual(result["journal"], "wal")
        self.assertFalse(result["missing_tables"])
        self.assertFalse(result["missing_columns"])
        for name in ("telemetry_events", "dpt2_events", "dp3_incidents",
                     "dp3_delivery", "dpt2_latest", "dp3_states"):
            self.assertEqual(result["rows"][name], 0, name)
        self.assertEqual(self.previous.read_bytes(), old)

    def test_fresh_initializer_refuses_existing_database(self):
        schema_audit.fresh_prepare(self.new)
        with self.assertRaises(FileExistsError):
            schema_audit.fresh_prepare(self.new)
        with self.assertRaises(FileExistsError):
            schema_audit.fresh_prepare(self.previous)

    def test_read_only_audit_rejects_legacy_only_database(self):
        collector.initialize(self.previous)
        status = schema_audit.audit(self.previous)
        self.assertEqual(status["status"], "FAIL")
        self.assertIn("dpt2_events", status["missing_tables"])
        self.assertIn("dp3_incidents", status["missing_tables"])
        with sqlite3.connect(self.previous) as db:
            self.assertEqual(db.execute("PRAGMA quick_check").fetchone()[0], "ok")

    def test_online_backup_preserves_wal_history_and_refuses_overwrite(self):
        collector.initialize(self.previous)
        collector.register_target(self.previous, 1, "archived-relay.invalid", 2252)
        private_dir = self.base / "private-archive"
        private_dir.mkdir(mode=0o700)
        os.chmod(private_dir, 0o700)
        backup = private_dir / "legacy.sqlite3"
        result = snapshot(self.previous, backup)
        self.assertEqual(result["status"], "VERIFIED")
        with sqlite3.connect(backup) as db:
            self.assertEqual(
                db.execute("SELECT hostname FROM targets").fetchone()[0],
                "archived-relay.invalid")
            self.assertEqual(db.execute("PRAGMA quick_check").fetchone()[0], "ok")
        with self.assertRaises(FileExistsError):
            snapshot(self.previous, backup)
        self.assertTrue(self.previous.is_file())

    def test_audit_does_not_hide_missing_columns(self):
        schema_audit.fresh_prepare(self.new)
        with sqlite3.connect(self.new) as db:
            db.execute("ALTER TABLE dp3_operator_labels RENAME TO moved_labels")
        status = schema_audit.audit(self.new)
        self.assertEqual(status["status"], "FAIL")
        self.assertIn("dp3_operator_labels", status["missing_tables"])


if __name__ == "__main__":
    unittest.main()
