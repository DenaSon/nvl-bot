"""AWG-first admin UI and retired provider callback contract (no real SSH/DNS)."""
import asyncio
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from manual_edge_wizard import ManualEdgeWizard


class AWGFirstWizardTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dbpath = Path(self.temp.name) / "edge.db"
        self.db = lambda: sqlite3.connect(self.dbpath)
        self.wizard = ManualEdgeWizard(
            db=self.db,
            preflight=lambda: (2252, "legacy"),
            awg_preflight=lambda: (2252, "awg"),
            provision=lambda *a: None, awg_provision=lambda *a: None,
            awg_check=lambda *a: False,
            verify=lambda *a: False, probe=lambda *a: False,
            nat=lambda *a: False, queue=None,
            is_core_host=lambda *a: False,
        )
        self.wizard._view = AsyncMock(return_value="VIEW")
        self.query = object()
        self.context = SimpleNamespace(user_data={})
        self.app = SimpleNamespace(bot=object())

    async def callback(self, name):
        return await self.wizard.handle(
            self.query, self.context, name, role="admin",
            actor=77, chat=77, app=self.app,
        )

    async def test_disabled_flag_no_legacy_create_and_no_state(self):
        with patch.dict(os.environ, {
            "NVL_AWG_NEW_EDGE_ENABLED": "1",
            "NVL_LEGACY_WG_UI_ENABLED": "0",
        }):
            labels = str(self.wizard._new_edge_buttons())
            self.assertIn("AWG", labels)
            self.assertNotIn("WireGuard", labels)
            self.assertNotIn("AmneziaWG", labels)
            await self.callback("apps_edge_manual_new")
            self.assertIn("LEGACY_WG_NOT_AVAILABLE",
                          str(self.wizard._view.call_args))
            with self.db() as db:
                table=db.execute(
                    "SELECT 1 FROM sqlite_master "
                    "WHERE name='manual_edge_operations'"
                ).fetchone()
            self.assertIsNone(table)

    async def test_old_legacy_operation_detail_blocked_with_flag_off(self):
        old=self.wizard.journal.start(77,77)
        new=self.wizard.journal.start(90,90,tunnel_backend="amneziawg")
        with patch.dict(os.environ, {
            "NVL_AWG_NEW_EDGE_ENABLED":"1",
            "NVL_LEGACY_WG_UI_ENABLED":"0",
        }):
            self.assertEqual(self.wizard.journal.latest(77,77,backend="amneziawg"),
                             None)
            self.assertEqual(self.wizard.journal.latest(90,90,backend="amneziawg")["id"],
                             new)
            await self.callback("apps_edge_manual_detail_" + old)
            self.assertIn("LEGACY_WG_NOT_AVAILABLE",
                          str(self.wizard._view.call_args))

    async def test_opt_in_legacy_button_returns(self):
        with patch.dict(os.environ, {
            "NVL_AWG_NEW_EDGE_ENABLED":"1",
            "NVL_LEGACY_WG_UI_ENABLED":"1",
        }):
            rows=self.wizard._new_edge_buttons()
            self.assertEqual(rows[1][0][1],"apps_edge_manual_new")


class ProviderRetirementTests(unittest.TestCase):
    def test_cloudzy_provider_entrypoints_no_longer_in_live_router(self):
        script=(Path(__file__).resolve().parents[1] /
                "bot_final_v49-2.py").read_text(encoding="utf-8")
        self.assertNotIn("_cloudzy_admin_panel = CloudzyAdminPanel()",script)
        self.assertNotIn("_cloudzy_quick_edge = QuickEdgeWizard(",script)
        self.assertNotIn("await _cloudzy_quick_edge.handle_callback(",script)
        self.assertNotIn("await _cloudzy_admin_panel.handle_callback(",script)
        self.assertIn('if d.startswith("apps_cz_") or d.startswith("u7:")',script)
        self.assertIn('"apps_edge_quick_home",role=role',script)


if __name__ == "__main__":
    unittest.main()
