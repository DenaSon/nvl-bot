import pathlib
import sqlite3
import unittest
from datetime import datetime, timedelta, timezone

import marzban_asset_discovery as discovery
import marzban_local_health as local_health
import marzban_observability as obs
import marzban_regional_filtering as regional
from regional_filtering import (
    REGIONAL_STATE_CLEAR,
    REGIONAL_STATE_LIKELY,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]
BOT_PATH = ROOT / "bot_final_v49-2.py"


def stamp(dt):
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class V122BHistoryTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        discovery.install_schema(self.conn)
        local_health.install_schema(self.conn)
        regional.install_schema(self.conn)
        obs.install_schema(self.conn)
        self.asset_key = "MARZBAN_NODE:1"

    def tearDown(self):
        self.conn.close()

    def _health(self, when, *, healthy=True, latency=50.0):
        state = (
            local_health.STATE_LOCAL_HEALTHY
            if healthy
            else local_health.STATE_SERVICE_DOWN
        )
        reason = (
            local_health.REASON_OK
            if healthy
            else local_health.REASON_TCP_UNREACHABLE
        )
        return local_health.AssetHealth(
            self.asset_key,
            discovery.ASSET_NODE,
            state,
            reason,
            healthy,
            stamp(when),
            latency if healthy else None,
            {},
        )

    def test_samples_are_idempotent_for_same_asset_and_timestamp(self):
        now = datetime(2026, 10, 6, 0, 0, tzinfo=timezone.utc)
        item = self._health(now)

        first = obs.record_health_samples(self.conn, [item], {})
        second = obs.record_health_samples(self.conn, [item], {})

        self.assertEqual(first, 1)
        self.assertEqual(second, 0)
        count = self.conn.execute(
            "SELECT COUNT(*) FROM marzban_monitor_samples"
        ).fetchone()[0]
        self.assertEqual(count, 1)

    def test_metrics_compute_latency_uptime_failures_and_last_failure(self):
        now = datetime(2026, 10, 6, 0, 30, tzinfo=timezone.utc)
        regional_map = {
            self.asset_key: {
                "filter_state": REGIONAL_STATE_CLEAR,
                "filter_reason": regional.REASON_DIRECT_ENDPOINTS,
            }
        }

        rows = []
        for minute in range(31):
            when = now - timedelta(minutes=30 - minute)
            healthy = minute not in (10, 11)
            rows.append(
                self._health(
                    when,
                    healthy=healthy,
                    latency=40.0 + minute if healthy else None,
                )
            )
        obs.record_health_samples(self.conn, rows, regional_map)

        metrics = obs.asset_metrics(self.conn, self.asset_key, now=now)

        self.assertEqual(metrics["samples_24h"], 31)
        self.assertEqual(metrics["failures_24h"], 1)
        self.assertAlmostEqual(metrics["uptime_24h"], 29 / 31 * 100, places=2)
        self.assertEqual(
            metrics["last_failure_at"],
            stamp(now - timedelta(minutes=19)),
        )
        self.assertIsNotNone(metrics["latency_15m"])
        self.assertIsNotNone(metrics["latency_1h"])
        self.assertIsNotNone(metrics["latency_24h"])

    def test_retention_prunes_history_older_than_14_days(self):
        now = datetime(2026, 10, 20, 0, 0, tzinfo=timezone.utc)
        old = self._health(now - timedelta(days=15))
        fresh = self._health(now)

        obs.record_health_samples(self.conn, [old, fresh], {})

        rows = self.conn.execute(
            "SELECT sampled_at FROM marzban_monitor_samples ORDER BY sampled_at"
        ).fetchall()
        self.assertEqual(rows, [(stamp(now),)])


class V122BScoreAndIncidentTests(unittest.TestCase):
    def test_score_is_high_for_healthy_clear_stable_low_latency_asset(self):
        score = obs.health_score(
            {"healthy": True, "latency_ms": 45.0},
            {"filter_state": REGIONAL_STATE_CLEAR},
            {
                "samples_24h": 30,
                "coverage_seconds": 7200,
                "uptime_24h": 100.0,
                "latency_1h": 50.0,
            },
        )
        self.assertEqual(score["score"], 100)
        self.assertEqual(score["icon"], "🟢")
        self.assertEqual(
            score["components"],
            {"local": 45, "regional": 25, "uptime": 20, "latency": 10},
        )

    def test_score_is_fail_closed_for_local_down_and_regional_likely(self):
        score = obs.health_score(
            {"healthy": False, "latency_ms": None},
            {"filter_state": REGIONAL_STATE_LIKELY},
            {
                "samples_24h": 30,
                "coverage_seconds": 7200,
                "uptime_24h": 50.0,
                "latency_1h": 1200.0,
            },
        )
        self.assertLess(score["score"], 30)
        self.assertEqual(score["icon"], "🔴")

    def test_current_incidents_prioritize_live_failures_and_provider_limits(self):
        asset = discovery.MarzbanAsset(
            asset_key="MARZBAN_PUBLIC_HOST:VLESS:0",
            asset_type=discovery.ASSET_PUBLIC_HOST,
            source_id="VLESS:0",
            name="ignored ({USERNAME})",
            address="203.0.113.10",
            port=8443,
            resolved_ips=("203.0.113.10",),
            metadata={"inbound_tag": "VLESS TCP REALITY", "is_disabled": False},
        )
        incidents = obs.current_incidents(
            [asset],
            {asset.asset_key: {"healthy": True}},
            {
                asset.asset_key: {
                    "filter_state": REGIONAL_STATE_LIKELY,
                    "checked_at": "2026-10-06T00:00:00Z",
                }
            },
            {"provider_status": "LIMITED"},
            {asset.asset_key: {"samples_24h": 0}},
            now=datetime(2026, 10, 6, 0, 1, tzinfo=timezone.utc),
        )

        self.assertTrue(any(i["label"] == "VLESS Reality" for i in incidents))
        self.assertTrue(
            any(i["message"] == "اختلال منطقه‌ای محتمل" for i in incidents)
        )
        self.assertTrue(any(i["label"] == "Regional Probe" for i in incidents))
        self.assertEqual(incidents[0]["severity"], 3)


class V122BIntegrationShapeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")
        cls.module = (ROOT / "marzban_observability.py").read_text(encoding="utf-8")

    def test_runtime_records_history_in_existing_local_health_cycle(self):
        start = self.source.index("async def _marzban_local_health_tick")
        end = self.source.index("async def _marzban_local_health_loop", start)
        region = self.source[start:end]
        self.assertIn("marzban_local_health.persist_health_snapshot", region)
        self.assertIn("marzban_observability.record_health_samples", region)
        self.assertNotIn("probe_tcp(", region)

    def test_final_runtime_marker_is_v122b(self):
        self.assertIn(
            'BOT_VERSION_TAG = "V122B-2026-10-06-monitoring-metrics"',
            self.source,
        )
        self.assertIn("V122B Marzban Observability", self.source)

    def test_operator_ui_exposes_score_uptime_latency_and_incidents(self):
        self.assertIn("Node Health Score", self.module)
        self.assertIn("Latency avg", self.module)
        self.assertIn("Uptime:", self.module)
        self.assertIn("Failures 24h", self.module)
        self.assertIn("موارد نیازمند توجه", self.module)

    def test_metrics_module_stays_observability_only(self):
        lower = self.module.lower()
        for forbidden in (
            "modify_node(",
            "update_host(",
            "set_node_enabled(",
            "reconnect_node(",
            "_safe_manual_failover(",
            "_phase6h_auto_failover_tick(",
            "_cf_switch_public_domain(",
            "subprocess.",
            "paramiko.",
        ):
            self.assertNotIn(forbidden, lower)


if __name__ == "__main__":
    unittest.main()
