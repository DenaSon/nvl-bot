"""Integration of the exact bot Phase-6G callbacks into an empty LAB journal.

No host/SSH/network operations. Tests run on a temporary SQLite database.
"""
from contextlib import contextmanager
from pathlib import Path
import hashlib
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from edge_egress_r1_lab_6g_bootstrap import (
    compile_pinned_bot_callbacks, git_blob_sha,
    REVIEWED_BOT_GIT_BLOB, JOURNAL_SCHEMA,
    Lab6GUnsafe, install_empty_journal,
    DEFAULT_DATABASE,
)

BOT = Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"


class GitBlobTests(unittest.TestCase):
    def test_git_blob_format_matches_git_algorithm(self):
        data = b"hello"
        expected = hashlib.sha1(b"blob 5\0hello").hexdigest()
        self.assertEqual(git_blob_sha(data), expected)

    def test_exact_bundled_bot_is_the_pinned_source(self):
        data = BOT.read_bytes()
        self.assertEqual(git_blob_sha(data), REVIEWED_BOT_GIT_BLOB)

    def test_changed_bot_byte_refused_before_execution(self):
        with self.assertRaisesRegex(Lab6GUnsafe, "BOT_GIT_BLOB_MISMATCH"):
            compile_pinned_bot_callbacks(BOT.read_bytes() + b"\n#", lambda: None)


class RealPhase6GTests(unittest.TestCase):
    def test_original_bot_lock_and_update_run_on_real_sqlite(self):
        with tempfile.TemporaryDirectory() as temp:
            db = Path(temp) / "journal.db"
            with sqlite3.connect(db) as conn:
                conn.executescript(JOURNAL_SCHEMA)
            @contextmanager
            def db_conn():
                conn = sqlite3.connect(db, timeout=5)
                try:
                    yield conn
                    conn.commit()
                except Exception:
                    conn.rollback()
                    raise
                finally:
                    conn.close()

            acquire, update = compile_pinned_bot_callbacks(BOT.read_bytes(), db_conn)
            operation_id, busy = acquire("107.189.16.36", "216.126.229.12")
            self.assertIsInstance(operation_id, int)
            self.assertIsNone(busy)
            another, busy_id = acquire("107.189.16.36", "216.126.229.12")
            self.assertIsNone(another)
            self.assertEqual(busy_id, operation_id)
            update(
                operation_id,
                status="SUCCEEDED",
                detail={"kind": "EGRESS_UID_RUNTIME", "phase": "TEST"},
                finished=True,
                require_running=True,
            )
            with sqlite3.connect(db) as conn:
                rows = conn.execute(
                    "SELECT id,status,source_host,target_host,detail_json "
                    "FROM failover_operations"
                ).fetchall()
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0][:4], (
                    operation_id, "SUCCEEDED", "107.189.16.36", "216.126.229.12"
                ))
            with self.assertRaisesRegex(RuntimeError, "NO_LONGER_RUNNING"):
                update(operation_id, status="FAILED", require_running=True)
            next_id, busy = acquire("107.189.16.36", "216.126.229.12")
            self.assertIsNone(busy)
            self.assertGreater(next_id, operation_id)

    def test_install_refuses_foreign_host_without_touching_db(self):
        with patch("edge_egress_r1_lab_6g_bootstrap.lab_host_attested",
                   return_value=False):
            with self.assertRaisesRegex(Lab6GUnsafe, "IDENTITY_NOT_ATTESTED"):
                install_empty_journal()
        # Test must not create /root/master_bot.db; no fixed-path IO in CI.


if __name__ == "__main__":
    unittest.main()
