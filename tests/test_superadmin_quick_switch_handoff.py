"""Recover Quick Switch jobs across active Super Admins; preserve original owner."""
import asyncio
from contextlib import contextmanager
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock

from manual_quick_switch import ManualQuickSwitch, QuickSwitchHold
from manual_quick_switch_ui import ManualQuickSwitchUI


class FakeDns:
    def snapshot(self):
        return []

    def set_all(self, records, host):
        raise AssertionError("DNS must not be touched by access tests")


class SuperAdminHandoffTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "core.db"

        @contextmanager
        def db():
            with sqlite3.connect(self.path) as conn:
                yield conn

        self.db = db
        with self.db() as conn:
            conn.execute("CREATE TABLE bot_access(telegram_id INTEGER,role TEXT,active INTEGER)")
            conn.executemany("INSERT INTO bot_access VALUES(?,?,?)", [
                (7, "super_admin", 1), (8, "super_admin", 1),
                (9, "admin", 1), (10, "super_admin", 0),
            ])
        self.engine = ManualQuickSwitch(
            db_conn=self.db, dns=FakeDns(),
            check_target=lambda *_: True, guard=lambda *_: None,
        )
        self.record = {"id": "job-1", "actor": "7", "kind": "QUICK", "status": "DONE"}

    def test_other_active_superadmin_can_recover_and_owner_stays_original(self):
        self.assertTrue(self.engine.operator_allowed(self.record, 7))
        self.assertTrue(self.engine.operator_allowed(self.record, 8))
        self.engine._audit_other_operator(self.record, 8, "RESUME_READ_AND_RECONCILE")
        with self.db() as conn:
            rows = conn.execute(
                "SELECT job_id,original_actor,executing_actor,action "
                "FROM manual_quick_operator_audit"
            ).fetchall()
        self.assertEqual(rows, [("job-1", "7", "8", "RESUME_READ_AND_RECONCILE")])
        self.assertEqual(self.record["actor"], "7")

    def test_revoked_inactive_and_non_superadmin_cannot_take_over(self):
        for actor in (9, 10, 999, 1947045855):
            with self.subTest(actor=actor):
                self.assertFalse(self.engine.operator_allowed(self.record, actor))
                with self.assertRaises(QuickSwitchHold):
                    self.engine._audit_other_operator(self.record, actor, "RESUME")
        with self.db() as conn:
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM sqlite_master "
                             "WHERE type='table' AND name='manual_quick_operator_audit'").fetchone()[0],
                0,
            )

    def test_resume_done_job_by_another_admin_is_idempotent(self):
        self.engine.get = lambda job: self.record if job == "job-1" else None
        result = asyncio.run(self.engine._resume_once("job-1", actor=8))
        self.assertEqual(result, "DONE")
        with self.db() as conn:
            # An already-settled job is a no-op, not a new action receipt.
            found = conn.execute("SELECT COUNT(*) FROM sqlite_master "
                                 "WHERE name='manual_quick_operator_audit'").fetchone()[0]
        self.assertEqual(found, 0)

    def test_shared_status_offers_recovery_buttons(self):
        ui = ManualQuickSwitchUI(
            engine=self.engine, db=self.db, admin_ids=lambda: [7, 8],
            enabled=lambda: True,
        )
        ui._inventory = lambda: ("192.0.2.1", ["192.0.2.2"], 2)
        ui.engine.latest = lambda: {
            "id": "job-1", "kind": "QUICK", "actor": "7", "status": "HOLD",
            "source": "192.0.2.1", "target": "192.0.2.2",
            "account_count": 2, "error_code": "",
        }
        ui._view = AsyncMock(return_value=1)
        asyncio.run(ui._status(SimpleNamespace(), 8))
        rows = ui._view.await_args.args[3]
        callbacks = [callback for row in rows for _, callback in row]
        self.assertIn("apps_edge_quick_resume_job-1", callbacks)
        self.assertIn("apps_edge_quick_retry_review_job-1", callbacks)
        self.assertIn("apps_edge_quick_force_review_job-1", callbacks)


if __name__ == "__main__":
    unittest.main()
