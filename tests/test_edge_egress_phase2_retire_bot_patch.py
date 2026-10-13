"""Offline CI check for pinned Phase-2 Telegram delete integration patch."""
import ast
from pathlib import Path
import unittest

from ops.k2_apply_phase2_retire_bot_patch import patch_source

ROOT = Path(__file__).resolve().parents[1]


class Phase2BotPatchTests(unittest.TestCase):
    def test_patch_applies_once_to_current_bot_and_parses(self):
        text = (ROOT / "bot_final_v49-2.py").read_text(encoding="utf-8")
        changed = patch_source(text)
        self.assertNotEqual(text, changed)
        ast.parse(changed)
        self.assertEqual(changed.count('elif d.startswith("hpeg_retire_open_")'), 1)
        self.assertEqual(changed.count('"hpeg_retire_yes_"'), 2)
        self.assertEqual(changed.count("is_managed_egress_deletion, db_conn, host"), 2)
        self.assertIn('"🗑 حذف ایمن Edge"', changed)
        with self.assertRaises(ValueError):
            patch_source(changed)

    def test_delete_callback_stays_admin_only(self):
        text = (ROOT / "bot_final_v49-2.py").read_text(encoding="utf-8")
        changed = patch_source(text)
        start = changed.index('    elif d.startswith("hpeg_retire_open_")')
        end = changed.index('    elif d == "hpeg_status"', start)
        block = changed[start:end]
        self.assertIn("if role != 'admin':", block)
        self.assertIn("context.user_data.pop('egress_retire_ticket', None)", block)
        self.assertIn("plan_egress_retirement, db_conn, edge_id", block)
        self.assertIn("apply_egress_retire_metadata, db_conn, ticket", block)


if __name__ == "__main__":
    unittest.main()
