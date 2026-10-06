import pathlib
import unittest

from incident_observability import (
    REASON_WIDESPREAD_NETWORK_OUTAGE,
    normalize_auto_block_reason,
    reason_label_fa,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]
BOT_PATH = ROOT / "bot_final_v49-2.py"


class RadarV4IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")

    def region(self, start, end):
        a = self.source.index(start)
        b = self.source.index(end, a)
        return self.source[a:b]

    def test_auto_tick_uses_fresh_radar_correlation_gate(self):
        region = self.region(
            "async def _phase6h_auto_failover_tick",
            "async def _regional_filter_tick",
        )
        self.assertIn(
            "radar_runtime.load_latest_radar_snapshot",
            region,
        )
        self.assertIn(
            "incident_correlation.evaluate_incident_correlation",
            region,
        )
        self.assertIn(
            "external_context_blocks_auto_failover=radar_auto_inhibit",
            region,
        )
        self.assertIn(
            "RADAR_FAILOVER_CONTEXT_MAX_AGE_SECONDS",
            region,
        )

    def test_manual_failover_engine_has_no_radar_gate(self):
        region = self.region(
            "async def _safe_manual_failover(",
            "async def _activate_standby_for_filtered_edge",
        )
        self.assertNotIn("radar_auto_inhibit", region)
        self.assertNotIn("incident_correlation", region)
        self.assertNotIn("load_latest_radar_snapshot", region)

    def test_radar_outage_block_does_not_duplicate_incident_notification(self):
        region = self.region(
            "async def _incident_mark_failover_blocked",
            "async def _phase6h_auto_failover_tick",
        )
        self.assertIn(
            "if reason == REASON_WIDESPREAD_NETWORK_OUTAGE:",
            region,
        )
        self.assertIn("return", region)

    def test_radar_outage_notification_explains_auto_gate(self):
        region = self.region(
            "def _radar_notification_message",
            "async def _handle_radar_snapshot",
        )
        self.assertIn("Radar Safety Gate", region)
        self.assertIn("انتقال دستی", region)

    def test_reason_is_normalized_and_human_readable(self):
        self.assertEqual(
            normalize_auto_block_reason("WIDESPREAD_NETWORK_OUTAGE"),
            REASON_WIDESPREAD_NETWORK_OUTAGE,
        )
        label = reason_label_fa(REASON_WIDESPREAD_NETWORK_OUTAGE)
        self.assertIn("اختلال گسترده", label)
        self.assertIn("انتقال خودکار", label)


if __name__ == "__main__":
    unittest.main()
