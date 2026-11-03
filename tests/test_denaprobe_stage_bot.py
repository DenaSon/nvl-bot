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
        """Representative pre-R3 main bot from approved source minus additions."""
        source = self.release
        a = source.index("# DenaProbe R3: optional admin dashboard")
        b = source.index("def _cloudzy_markup(rows):", a)
        source = source[:a] + source[b:]
        a = source.index('        if globals().get("_DP3_ENABLED", False):')
        b = source.index("    return rows", a)
        source = source[:a] + source[b:]
        a = source.index('    if d == "apps_dp3_home" or d.startswith("dp3:"):')
        b = source.index('    if d in ("apps_cz_rich_home", ', a)
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

    def test_merge_adds_five_hooks_and_preserves_local_customization(self):
        old = self.legacy_sample()
        marker = "# CORE_SPECIFIC_LOCAL_SETTING__KEEP"
        old = old.replace("def _cloudzy_markup(rows):",
                          marker + "\ndef _cloudzy_markup(rows):", 1)
        merged = integrate(old, self.release)
        self.assertIn(marker, merged)
        self.assertEqual(merged.count('NVL_DENAPROBE_R3_ALERTS_ENABLED'), 1)
        self.assertEqual(merged.count('app.bot_data.get("dp3_monitor_task")'), 1)
        self.assertIn('📡 پایش DenaProbe', merged)
        self.assertIn('if d == "apps_dp3_home"', merged)
        self.assertNotIn("<<<<<<<", merged)

    def test_existing_legacy_dena_probe_menu_entry_is_preserved(self):
        old = self.legacy_sample()
        menu_start = old.index("def _build_admin_programs_kb(")
        menu_end = old.index("async def _show_admin_programs_hub", menu_start)
        menu = old[menu_start:menu_end]
        anchor = "    return rows\n"
        self.assertEqual(menu.count(anchor), 1)
        legacy = (
            '    rows.insert(1, [InlineKeyboardButton('
            '"📡 پایش DenaProbe", callback_data="legacy_probe_status")])\n'
        )
        menu = menu.replace(anchor, legacy + anchor, 1)
        old = old[:menu_start] + menu + old[menu_end:]
        merged = integrate(old, self.release)
        segment = merged[
            merged.index("def _build_admin_programs_kb("):
            merged.index("async def _show_admin_programs_hub")
        ]
        self.assertIn('callback_data="legacy_probe_status"', segment)
        self.assertIn('"📡 پایش DenaProbe"', segment)
        self.assertIn('"📡 وضعیت اتصال"', segment)
        self.assertIn("callback_data=_DP3_ENTRY", segment)
        self.assertEqual(segment.count('"📡 پایش DenaProbe"'), 1)
        self.assertEqual(segment.count('"📡 وضعیت اتصال"'), 1)

    def test_existing_r3_is_rejected(self):
        with self.assertRaises(IntegrationError):
            integrate(self.release, self.release)

    def test_unrelated_preexisting_label_is_not_rejected(self):
        old = '# LABEL_NOTE = "📡 پایش DenaProbe"\n' + self.legacy_sample()
        merged = integrate(old, self.release)
        self.assertIn("LABEL_NOTE", merged)


if __name__ == "__main__":
    unittest.main()
