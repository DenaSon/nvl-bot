import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
BOT_PATH = ROOT / "bot_final_v49-2.py"
RUNTIME_PATH = ROOT / "radar_runtime.py"


class RadarV3BotIntegrationTests(unittest.TestCase):
    def test_bot_wires_radar_ui_and_snapshot_callback(self):
        source = BOT_PATH.read_text(encoding="utf-8")
        self.assertIn("import radar_notifications", source)
        self.assertIn("import radar_ui", source)
        self.assertIn("on_snapshot=_handle_radar_snapshot", source)
        self.assertIn('callback_data="flt_radar"', source)
        self.assertIn("async def _render_radar_monitor_panel", source)
        self.assertIn("radar_ui.render_summary", source)
        self.assertIn("radar_ui.render_detail", source)

    def test_radar_notification_adapter_does_not_touch_failover(self):
        source = BOT_PATH.read_text(encoding="utf-8")
        start = source.index("async def _handle_radar_snapshot")
        end = source.index("async def _render_radar_monitor_panel", start)
        adapter = source[start:end]
        self.assertIn("_notify_admins(", adapter)
        for forbidden in (
            "_safe_manual_failover(",
            "_phase6h_auto_failover_tick(",
            "_db_set_default_host(",
            "_update_cloudflare_dns(",
            "_activate_standby_for_filtered_edge(",
        ):
            self.assertNotIn(forbidden, adapter)

    def test_runtime_callback_is_optional_and_post_persistence(self):
        source = RUNTIME_PATH.read_text(encoding="utf-8")
        self.assertIn("on_snapshot: Optional[Callable", source)
        self.assertIn("if self.on_snapshot is not None:", source)
        persist_pos = source.index("await asyncio.to_thread(self.persist, snapshot)")
        callback_pos = source.index("if self.on_snapshot is not None:")
        self.assertLess(persist_pos, callback_pos)


if __name__ == "__main__":
    unittest.main()
