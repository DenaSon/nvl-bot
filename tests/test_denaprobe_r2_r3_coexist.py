"""The current R3 admin Rich view must not remove the deployed R2 quality report."""
from pathlib import Path
import ast
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CoexistenceTests(unittest.TestCase):
    def test_current_bot_advertises_both_legacy_history_and_r3(self):
        source = (ROOT / "bot_final_v49-2.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        bodies = {
            n.name: ast.get_source_segment(source, n)
            for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        menu = bodies["_build_admin_programs_kb"]
        callback = bodies["callback_handler"]
        self.assertIn('callback_data="apps_dpt_24"', menu)
        self.assertIn('callback_data=_DP3_ENTRY', menu)
        self.assertEqual(menu.count('"📡 پایش DenaProbe"'), 1)
        self.assertIn('"📊 گزارش DenaProbe"', menu)
        self.assertIn("denaprobe_admin_dashboard", callback)
        self.assertIn('d == "apps_dp3_home"', callback)
        self.assertIn('active_admin_ids=active_admin_ids', callback)

    def test_legacy_report_still_has_distinct_history_windows(self):
        from denaprobe_admin_dashboard import CALLBACKS
        self.assertEqual(CALLBACKS, frozenset(("apps_dpt_24", "apps_dpt_168")))


if __name__ == "__main__":
    unittest.main()
