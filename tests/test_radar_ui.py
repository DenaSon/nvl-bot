import unittest

import radar_ui


class RadarUiTests(unittest.TestCase):
    def snapshot(self, state="NORMAL"):
        return {
            "state": state,
            "reason": "NO_ACTIVE_INCIDENT",
            "provider_status": "OK",
            "observed_at": "2026-10-06T20:00:00Z",
            "anomaly_count": 1,
            "active_anomaly_count": 0,
            "outage_count": 2,
            "active_outage_count": 0,
            "confidence_level": 7,
            "traffic": {
                "value": 82.5,
                "previous_value": 100.0,
                "delta_pct": -17.5,
                "unit": "requests",
            },
            "latency": {"value": 25.0, "unit": "ms"},
            "dns": {"value": 12.0, "unit": "ms"},
            "bandwidth": {"value": 80.0, "unit": "Mbps"},
            "source_statuses": {
                "traffic_anomalies": "OK",
                "outages": "OK",
                "netflows": "OK",
                "latency": "OK",
                "dns": "OK",
                "bandwidth": "OK",
            },
        }

    def test_summary_shows_compact_iran_context(self):
        text = radar_ui.render_summary(
            self.snapshot("DEGRADED"),
            {"status": "OK"},
        )
        self.assertIn("وضعیت اینترنت ایران", text)
        self.assertIn("اختلال نسبی", text)
        self.assertIn("-17.5%", text)
        self.assertIn("25 ms", text)
        self.assertIn("80 Mbps", text)

    def test_summary_handles_no_snapshot(self):
        text = radar_ui.render_summary(
            None,
            {"status": "CONFIG_ERROR"},
        )
        self.assertIn("هنوز داده‌ای ثبت نشده", text)
        self.assertIn("تنظیم نشده", text)

    def test_detail_contains_sources_and_history(self):
        current = self.snapshot("OUTAGE")
        older = self.snapshot("NORMAL")
        older["observed_at"] = "2026-10-06T19:50:00Z"

        text = radar_ui.render_detail(
            current,
            {"status": "OK", "last_error": ""},
            (current, older),
        )
        self.assertIn("اختلال گسترده", text)
        self.assertIn("Traffic Anomalies", text)
        self.assertIn("IQI Latency", text)
        self.assertIn("تاریخچه اخیر", text)
        self.assertIn("19:50:00Z", text)

    def test_detail_escapes_provider_error(self):
        text = radar_ui.render_detail(
            self.snapshot(),
            {"status": "ERROR", "last_error": "<bad&error>"},
            (),
        )
        self.assertNotIn("<bad&error>", text)
        self.assertIn("&lt;bad&amp;error&gt;", text)


if __name__ == "__main__":
    unittest.main()
