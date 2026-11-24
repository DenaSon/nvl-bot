"""Regression for safe additive Core bot integration: no live file edits."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ops"))
from denaprobe_r3_stage_bot import integrate, IntegrationError


class TestStageBot(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.release = (ROOT / "bot_final_v49-2.py").read_text(encoding="utf-8")

    def legacy_sample(self):
        """Current UI policy with only the R3 runtime hooks removed."""
        source = self.release
        a = source.index("# DenaProbe R3: optional admin dashboard")
        b = source.index("def _cloudzy_markup(rows):", a)
        source = source[:a] + source[b:]
        a = source.index('    if d == "apps_dp3_home" or d.startswith("dp3:"):')
        b = source.index("    if d == 'apps_home':", a)
        source = source[:a] + source[b:]
        a = source.index("async def _post_init(app):\n")
        b = source.index(
            "    # K2 Single shares this application's existing root process",
            a,
        )
        source = source[:a] + "async def _post_init(app):\n" + source[b:]
        source = source.replace(
            ", ('dp3_monitor_task', '📡 DenaProbe R3')", "", 1
        )
        return source

    def test_merge_adds_runtime_hooks_and_preserves_local_customization(self):
        old = self.legacy_sample()
        marker = "# CORE_SPECIFIC_LOCAL_SETTING__KEEP"
        old = old.replace("def _cloudzy_markup(rows):",
                          marker + "\ndef _cloudzy_markup(rows):", 1)
        merged = integrate(old, self.release)
        self.assertIn(marker, merged)
        self.assertEqual(merged.count('NVL_DENAPROBE_R3_ALERTS_ENABLED'), 1)
        self.assertEqual(merged.count('app.bot_data.get("dp3_monitor_task")'), 1)
        menu = merged[merged.index("def _build_admin_programs_kb("):
                      merged.index("async def _show_admin_programs_hub")]
        self.assertNotIn("_DP3_ENTRY", menu)
        self.assertNotIn("apps_dpt_24", menu)
        self.assertIn('if d == "apps_dp3_home"', merged)
        self.assertIn('"apps_dpt_24"', merged)
        self.assertNotIn("<<<<<<<", merged)

    def test_historical_visible_release_still_stages_its_menu_hook(self):
        anchor = "    return rows\n"
        begin = "def _build_admin_programs_kb("
        end = "async def _show_admin_programs_hub"

        def historical_menu(source, with_r3):
            start = source.index(begin)
            stop = source.index(end, start)
            menu = source[start:stop]
            additions = (
                '    if actor == chat and actor in active_admin_ids:\n'
                '        rows.insert(0, [InlineKeyboardButton("Edge", callback_data="apps_edge_quick_home")])\n'
                '        rows.insert(1, [InlineKeyboardButton("DPT", callback_data="apps_dpt_24")])\n'
            )
            if with_r3:
                additions += (
                    '        if globals().get("_DP3_ENABLED", False):\n'
                    '            rows.insert(1, [InlineKeyboardButton("📡 پایش DenaProbe", callback_data=_DP3_ENTRY)])\n'
                )
            return source[:start] + menu.replace(anchor, additions + anchor, 1) + source[stop:]

        old = historical_menu(self.legacy_sample(), False)
        release = historical_menu(self.release, True)
        merged = integrate(old, release)
        self.assertIn('callback_data=_DP3_ENTRY', merged)
        with self.assertRaisesRegex(IntegrationError, "manual diff required"):
            integrate(old, self.release)

    def test_existing_r3_is_rejected(self):
        with self.assertRaises(IntegrationError):
            integrate(self.release, self.release)

    def test_unrelated_preexisting_label_is_not_rejected(self):
        old = '# LABEL_NOTE = "📡 پایش DenaProbe"\n' + self.legacy_sample()
        merged = integrate(old, self.release)
        self.assertIn("LABEL_NOTE", merged)


if __name__ == "__main__":
    unittest.main()
