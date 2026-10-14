"""Read-only K2 Core inventory must not start a service or write DB."""
from __future__ import annotations

from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from ops.k2_final_readiness import ReadOnlyInventoryHold, _trusted_db, main


class K2CoreReadinessCliTests(unittest.TestCase):
    def test_nonroot_and_missing_db_hold(self):
        with patch("ops.k2_final_readiness.os.geteuid", return_value=1000):
            self.assertEqual(main(["--edge-id", "fra1"]), 2)
        with patch("ops.k2_final_readiness.os.geteuid", return_value=0):
            self.assertEqual(main([
                "--edge-id", "fra1", "--db", "/definitely/not/present/nvl.db"
            ]), 2)

    def test_source_is_strictly_sqlite_readonly(self):
        source = (Path(__file__).resolve().parents[1] /
                  "ops/k2_final_readiness.py").read_text(encoding="utf-8")
        for must in ("?mode=ro", "PRAGMA query_only=ON",
                     "inspect_local_stage", "read_transfer_preview"):
            self.assertIn(must, source)
        for unsafe in ("subprocess", "os.system", "systemctl start", "iptables -",
                       "DELETE FROM", "UPDATE ssh_accounts",
                       "INSERT INTO", "cf_update_dns_record_sync") :
            self.assertNotIn(unsafe, source)

    def test_malformed_or_missing_evidence_is_hold(self):
        with self.assertRaises(ReadOnlyInventoryHold):
            _trusted_db(Path("/definitely/not/present/nvl.db"))
        with tempfile.TemporaryDirectory() as temp:
            import os
            db = Path(temp) / "db.sqlite"
            with sqlite3.connect(db) as conn:
                conn.execute("CREATE TABLE settings(key TEXT,value TEXT)")
            with patch("ops.k2_final_readiness.os.geteuid", return_value=0):
                self.assertEqual(main(["--edge-id","fra1","--db",str(db)]), 2)


if __name__ == "__main__":
    unittest.main()
