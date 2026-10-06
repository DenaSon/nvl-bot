import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
BOT_PATH = ROOT / "bot_final_v49-2.py"


class V120D1MonitoringUITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")

    def _region(self, start, end):
        a = self.source.index(start)
        b = self.source.index(end, a)
        return self.source[a:b]

    def test_admin_home_keeps_filtering_but_moves_marzban_monitor_to_programs(self):
        region = self._region(
            "async def show_main_menu",
            "async def cmd_start",
        )
        self.assertIn("🛡 بررسی فیلترینگ", region)
        self.assertIn("🧩 برنامه‌ها", region)
        self.assertNotIn(
            "['🛡 بررسی فیلترینگ', '🛰 بررسی مرزبان']",
            region,
        )

    def test_filtering_button_removed_from_server_settings(self):
        region = self._region(
            "def _build_server_settings_kb():",
            "def _normalize_ssh_port",
        )
        self.assertNotIn("🛡 وضعیت فیلترینگ", region)
        self.assertNotIn('callback_data="hp_filtering"', region)

    def test_filtering_home_button_reuses_existing_monitor(self):
        region = self._region(
            "# 🛡 گارد منوها",
            "# 🚨 گارد اجباری بودن برند نماینده",
        )
        self.assertIn("🛡 بررسی فیلترینگ", region)
        handler = self._region(
            "if text in main_menus and is_auth(context):",
            "elif text in ('🛠 V2Ray / Marzban'",
        )
        self.assertIn(
            "await _render_filtering_monitor_panel(update.message)",
            handler,
        )
        self.assertIn(
            "await _render_marzban_monitor_panel(update.message)",
            handler,
        )

    def test_filtering_panel_returns_home_not_settings(self):
        region = self._region(
            "async def _render_filtering_monitor_panel",
            "async def _render_filtering_edge_detail",
        )
        self.assertIn("🏠 منوی اصلی", region)
        self.assertNotIn("بازگشت به تنظیمات", region)

    def test_marzban_panel_is_programs_dashboard_with_drilldowns(self):
        region = self._region(
            "async def _render_marzban_monitor_panel",
            "async def cmd_marzban_monitor",
        )
        self.assertIn('back_callback="apps_home"', region)
        self.assertIn("↩️ برنامه‌ها", region)
        self.assertIn("🖥 نودها", region)
        self.assertIn("🌐 هاست‌ها", region)
        self.assertIn("🌍 وضعیت منطقه‌ای", region)
        self.assertIn("🕘 رخدادها", region)
        self.assertIn('callback_data="apps_marzban_monitor"', region)

    def test_marzban_command_reuses_same_ui(self):
        region = self._region(
            "async def cmd_marzban_monitor",
            "async def _post_init",
        )
        self.assertIn(
            "await _render_marzban_monitor_panel(update.effective_message)",
            region,
        )

    def test_blocked_alert_recipient_is_expected_warning(self):
        region = self._region(
            "async def _deliver_marzban_monitor_alerts",
            "async def _marzban_regional_filter_loop",
        )
        self.assertIn("bot was blocked by the user", region)
        self.assertIn("reason=BOT_BLOCKED", region)

    def test_release_marker(self):
        self.assertIn(
            'BOT_VERSION_TAG = "V123B32M-2026-10-06-safe-node-move"',
            self.source,
        )


if __name__ == "__main__":
    unittest.main()
