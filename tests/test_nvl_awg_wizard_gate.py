"""AWG wizard feature gate and legacy compatibility (no SSH, DNS or bot)."""
import os
import pathlib
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from manual_edge_journal import ManualEdgeJournal
from manual_edge_wizard import ManualEdgeWizard, ManualWizardHold


class AWGWizardGateTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)
        dbpath = pathlib.Path(self.root.name) / "journal.db"
        self.db = lambda: sqlite3.connect(dbpath)
        self.wizard = ManualEdgeWizard(
            db=self.db,
            preflight=lambda: (2252, "legacy"),
            awg_preflight=lambda: (2252, "awg"),
            provision=lambda *a: None,
            awg_provision=lambda *a: None,
            verify=lambda *a: False,
            probe=lambda *a: False,
            nat=lambda *a: False,
            queue=None,
            is_core_host=lambda *a: False,
        )

    def test_flag_off_preserves_legacy_button_and_blocks_awg_preflight(self):
        with patch.dict(os.environ, {"NVL_AWG_NEW_EDGE_ENABLED": "0"}):
            self.assertFalse(self.wizard._awg_available())
            self.assertEqual(
                self.wizard._new_edge_buttons(),
                [[("➕ افزودن سرور جدید", "apps_edge_manual_new")]],
            )
            with self.assertRaisesRegex(ManualWizardHold, "AWG_CORE_NOT_READY"):
                self.wizard._preflight_for({"tunnel_backend":"amneziawg"})
            self.assertEqual(
                self.wizard._preflight_for({"tunnel_backend":"wireguard"})()[1],
                "legacy",
            )

    def test_flag_on_permits_isolated_awg_wizard_not_automatic_standby(self):
        with patch.dict(os.environ, {"NVL_AWG_NEW_EDGE_ENABLED": "1"}):
            self.assertTrue(self.wizard._awg_available())
            self.assertEqual(
                self.wizard._new_edge_buttons()[0][0][1],
                "apps_edge_manual_new_awg",
            )
            self.assertEqual(
                self.wizard._preflight_for({"tunnel_backend":"amneziawg"})()[1],
                "awg",
            )

    def test_journal_backend_is_explicit_and_legacy_remains_default(self):
        first = self.wizard.journal.start(111, 111)
        second = self.wizard.journal.start(222, 222, tunnel_backend="amneziawg")
        with self.db() as db:
            rows = db.execute(
                "SELECT tunnel_backend FROM manual_edge_operations "
                "WHERE id IN (?,?) ORDER BY actor",
                (first, second),
            ).fetchall()
        self.assertEqual(rows, [("wireguard",), ("amneziawg",)])

    def test_unknown_backend_refused_before_any_journal_mutation(self):
        with self.assertRaisesRegex(Exception, "EDGE_BACKEND_UNSUPPORTED"):
            self.wizard.journal.start(111, 111, tunnel_backend="unknown")
        with self.db() as db:
            found = db.execute(
                "SELECT name FROM sqlite_master WHERE name='manual_edge_operations'"
            ).fetchone()
        self.assertIsNone(found)


if __name__ == "__main__":
    unittest.main()
