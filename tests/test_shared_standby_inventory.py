"""Super Admins share read-only Edge inventory without gaining operation ownership."""
import asyncio
from contextlib import contextmanager
import sqlite3
from tempfile import TemporaryDirectory
from pathlib import Path
import unittest
from unittest.mock import AsyncMock, patch

from manual_edge_journal import ManualEdgeHold, ManualEdgeJournal
from manual_edge_wizard import ManualEdgeWizard


class SharedStandbyInventoryTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "ops.sqlite3"

        @contextmanager
        def db():
            with sqlite3.connect(self.path) as conn:
                yield conn

        self.db = db
        with self.db() as conn:
            conn.execute("CREATE TABLE bot_access(telegram_id INTEGER, role TEXT, active INTEGER)")
            conn.executemany("INSERT INTO bot_access VALUES(?,?,?)", [
                (7, "super_admin", 1), (8, "super_admin", 1),
                (9, "admin", 1), (10, "super_admin", 0),
            ])
            conn.execute(
                "CREATE TABLE host_pool(host TEXT PRIMARY KEY, active INTEGER, "
                "is_default INTEGER, is_standby INTEGER, provider TEXT)"
            )
            conn.execute("CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT)")
        self.journal = ManualEdgeJournal(self.db)
        self.first = self.journal.start(7, 7)
        self.second = self.journal.start(8, 8)

    def _wizard(self):
        wizard = ManualEdgeWizard(
            db=self.db, preflight=AsyncMock(), provision=AsyncMock(),
            verify=AsyncMock(), probe=AsyncMock(), nat=AsyncMock(),
            queue=object(),
            shared_superadmin=lambda actor, chat: actor in (7, 8) and actor == chat,
        )
        wizard._view = AsyncMock(return_value=1)
        return wizard

    def test_shared_list_includes_other_admin_operations(self):
        for actor in (7, 8):
            items = self.journal.list_shared(actor, actor)
            self.assertEqual({p["id"] for p in items}, {self.first, self.second})
        self.assertEqual(len(self.journal.list_by_owner(7, 7)), 1)

    def test_db_role_and_private_identity_required(self):
        for actor, chat in [(9, 9), (10, 10), (7, 8), (999, 999)]:
            with self.subTest(actor=actor, chat=chat):
                with self.assertRaisesRegex(ManualEdgeHold, "SHARED_SUPERADMIN_REQUIRED"):
                    self.journal.list_shared(actor, chat)

    def test_shared_inventory_is_paginated(self):
        self.assertEqual(len(self.journal.list_shared(7, 7, limit=1, offset=0)), 1)
        self.assertEqual(len(self.journal.list_shared(7, 7, limit=1, offset=1)), 1)

    def test_nonowner_detail_is_read_only(self):
        wizard = self._wizard()
        with patch.object(wizard, "_legacy_wg_ui_enabled", return_value=True):
            asyncio.run(wizard._show(None, 7, 7))
            rendered_rows = wizard._view.await_args.args[2]
            destinations = [dest for row in rendered_rows for _, dest in row]
            self.assertIn("apps_edge_manual_detail_" + self.first, destinations)
            self.assertIn("apps_edge_manual_detail_" + self.second, destinations)
            asyncio.run(wizard._detail(None, 7, 7, self.second))
            rendered_text, rendered_rows = wizard._view.await_args.args[1:]
            self.assertIn("فقط مشاهده", rendered_text)
            actions = [dest for row in rendered_rows for _, dest in row]
            self.assertNotIn("apps_edge_manual_standby_" + self.second, actions)
            self.assertNotIn("apps_edge_manual_cancel_" + self.second, actions)

    def test_owner_cas_is_unchanged_and_blocks_nonowner_mutation(self):
        with self.assertRaisesRegex(ManualEdgeHold, "MANUAL_OPERATION_CHANGED"):
            self.journal.set_server(self.first, 8, 8, "8.8.8.8", 22)


if __name__ == "__main__":
    unittest.main()
