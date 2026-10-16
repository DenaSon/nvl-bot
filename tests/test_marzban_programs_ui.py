import pathlib
import unittest


BOT_PATH = pathlib.Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"


class MarzbanProgramsUITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")

    def _region(self, start, end):
        a = self.source.index(start)
        b = self.source.index(end, a)
        return self.source[a:b]

    def test_programs_is_canonical_marzban_infrastructure_hub(self):
        region = self._region(
            "def _build_admin_programs_kb",
            "_MIGRATION_INPUT_STATES =",
        )
        for label, callback in (
            ("🖥 نودها", "apps_marzban_nodes"),
            ("🌐 هاست‌ها", "apps_marzban_hosts"),
            ("🚚 انتقال Marzban", "apps_marzban_transfer"),
            ("🛰 مانیتورینگ", "apps_marzban_monitor"),
        ):
            self.assertIn(label, region)
            self.assertIn(callback, region)
        self.assertIn("🧩 <b>برنامه‌ها</b>", region)
        self.assertIn("مدیریت خروجی", region)

    def test_v2ray_dashboard_no_longer_owns_nodes_or_hosts(self):
        region = self._region(
            "async def _show_marzban_admin_dashboard",
            "async def _show_marzban_users",
        )
        self.assertIn("V2Ray / Marzban › کاربران", region)
        self.assertIn("🧩 زیرساخت Marzban", region)
        self.assertIn('callback_data="apps_home"', region)
        self.assertNotIn('callback_data="mza_inbounds"', region)
        self.assertNotIn('callback_data="mza_nodes"', region)

    def test_hosts_screen_returns_to_programs(self):
        region = self._region(
            "async def _show_marzban_inbounds",
            "async def _show_marzban_inbound_detail",
        )
        self.assertIn("برنامه‌ها › Marzban Hosts", region)
        self.assertIn("↩️ برنامه‌ها", region)
        self.assertIn('callback_data="apps_home"', region)

    def test_programs_routes_hosts_and_monitoring(self):
        region = self._region(
            "# ---------------- Programs / operational tools ----------------",
            "elif d == 'apps_mig_start':",
        )
        self.assertIn("elif d == 'apps_marzban_hosts':", region)
        self.assertIn("await _show_marzban_inbounds(query, context)", region)
        self.assertIn("elif d == 'apps_marzban_monitor':", region)
        self.assertIn('page="summary"', region)
        self.assertIn("elif d == 'apps_mzm_nodes':", region)
        self.assertIn("elif d == 'apps_mzm_hosts':", region)
        self.assertIn("elif d == 'apps_mzm_regional':", region)
        self.assertIn("elif d == 'apps_mzm_events':", region)

    def test_monitor_renderer_is_page_aware_and_returns_to_programs(self):
        region = self._region(
            "async def _render_marzban_monitor_panel",
            "async def cmd_marzban_monitor",
        )
        self.assertIn('page="summary"', region)
        self.assertIn('back_callback="apps_home"', region)
        self.assertIn('back_label="↩️ برنامه‌ها"', region)
        self.assertIn('"summary": marzban_observability.render_dashboard_report', region)
        self.assertIn('"nodes": marzban_observability.render_nodes_report', region)
        self.assertIn('"hosts": marzban_observability.render_hosts_report', region)
        self.assertIn('"regional": marzban_observability.render_regional_report', region)
        self.assertIn('"events": marzban_observability.render_events_report', region)
        self.assertIn("callback_data=back_callback", region)


if __name__ == "__main__":
    unittest.main()
