import asyncio
import pathlib
import tempfile
import unittest
from datetime import datetime, timezone

from cloudflare_radar import (
    CloudflareRadarRateLimited,
    RadarMeta,
    RadarOutage,
    RadarTimeSeries,
    RadarTrafficAnomaly,
)
from radar_runtime import (
    PROVIDER_STATUS_OK,
    PROVIDER_STATUS_PARTIAL,
    PROVIDER_STATUS_RATE_LIMITED,
    RadarMonitor,
    collect_radar_context,
    ensure_radar_schema,
    get_radar_provider_runtime,
    load_latest_radar_snapshot,
    persist_radar_snapshot,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]
RUNTIME_PATH = ROOT / "radar_runtime.py"
BOT_PATH = ROOT / "bot_final_v49-2.py"

NOW = datetime(2026, 10, 6, 20, 0, tzinfo=timezone.utc)


def meta(unit="ms"):
    return RadarMeta(
        agg_interval="FIFTEEN_MINUTES",
        confidence_level=7,
        last_updated="2026-10-06T19:55:00Z",
        normalization="RAW_VALUES",
        units=(("*", unit),),
        date_ranges=(("2026-10-06T00:00:00Z", "2026-10-06T20:00:00Z"),),
    )


def series(metric, value, *, unit="ms"):
    return RadarTimeSeries(
        metric=metric,
        scope="LOCATION:IR",
        timestamps=("2026-10-06T19:45:00Z", "2026-10-06T20:00:00Z"),
        series=(("p50", (value - 1, value)),),
        meta=meta(unit),
    )


class FakeClient:
    def __init__(self):
        self.calls = []

    def get_traffic_anomalies(self, **kwargs):
        self.calls.append(("traffic_anomalies", kwargs))
        return ()

    def get_outages(self, **kwargs):
        self.calls.append(("outages", kwargs))
        return ()

    def get_netflows(self, **kwargs):
        self.calls.append(("netflows", kwargs))
        return series("NETFLOWS", 100.0, unit="requests")

    def get_iqi(self, metric, **kwargs):
        self.calls.append((metric.lower(), kwargs))
        unit = "Mbps" if metric == "BANDWIDTH" else "ms"
        return series(metric, 20.0, unit=unit)


class RateLimitedClient(FakeClient):
    def get_traffic_anomalies(self, **kwargs):
        self.calls.append(("traffic_anomalies", kwargs))
        raise CloudflareRadarRateLimited("limited", retry_after=10)


class PartialClient(FakeClient):
    def get_netflows(self, **kwargs):
        self.calls.append(("netflows", kwargs))
        raise RuntimeError("programming error")


class RadarRuntimeCollectionTests(unittest.TestCase):
    def test_full_collection_is_ok_and_normal(self):
        client = FakeClient()
        result = collect_radar_context(client=client, location="IR", now=NOW)

        self.assertEqual(result.provider_status, PROVIDER_STATUS_OK)
        self.assertEqual(result.state, "NORMAL")
        self.assertEqual(len(client.calls), 6)
        self.assertEqual(client.calls[0][1]["location"], "IR")
        self.assertEqual(result.latency.value, 20.0)

    def test_rate_limit_short_circuits_remaining_calls(self):
        client = RateLimitedClient()
        result = collect_radar_context(client=client, location="IR", now=NOW)

        self.assertEqual(result.provider_status, PROVIDER_STATUS_RATE_LIMITED)
        self.assertEqual(result.state, "UNKNOWN")
        self.assertEqual(len(client.calls), 1)
        statuses = result.source_status_dict()
        self.assertEqual(statuses["traffic_anomalies"], "RATE_LIMITED")
        self.assertEqual(statuses["outages"], "SKIPPED")


class RadarRuntimePersistenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(pathlib.Path(self.tmp.name) / "radar.db")

    def tearDown(self):
        self.tmp.cleanup()

    def test_schema_and_snapshot_round_trip(self):
        ensure_radar_schema(self.db_path)
        snapshot = collect_radar_context(client=FakeClient(), now=NOW)
        row_id = persist_radar_snapshot(self.db_path, snapshot, retention_days=14)

        self.assertGreater(row_id, 0)
        latest = load_latest_radar_snapshot(self.db_path)
        self.assertEqual(latest["state"], "NORMAL")
        self.assertEqual(latest["provider_status"], "OK")
        self.assertEqual(latest["latency"]["value"], 20.0)

        runtime = get_radar_provider_runtime(self.db_path)
        self.assertEqual(runtime["status"], "OK")
        self.assertEqual(runtime["success_streak"], 1)
        self.assertEqual(runtime["error_streak"], 0)

    def test_provider_health_streak_tracks_partial_round(self):
        good = collect_radar_context(client=FakeClient(), now=NOW)
        persist_radar_snapshot(self.db_path, good)

        class MetricFailureClient(FakeClient):
            def get_netflows(self, **kwargs):
                self.calls.append(("netflows", kwargs))
                from cloudflare_radar import CloudflareRadarError
                raise CloudflareRadarError("metric failed")

        partial = collect_radar_context(client=MetricFailureClient(), now=NOW)
        self.assertEqual(partial.provider_status, PROVIDER_STATUS_PARTIAL)
        persist_radar_snapshot(self.db_path, partial)

        runtime = get_radar_provider_runtime(self.db_path)
        self.assertEqual(runtime["status"], "PARTIAL")
        self.assertEqual(runtime["success_streak"], 0)
        self.assertEqual(runtime["error_streak"], 1)

    def test_bot_wires_radar_monitor_into_clean_lifecycle(self):
        source = BOT_PATH.read_text(encoding="utf-8")
        self.assertIn("import radar_runtime", source)
        self.assertIn(
            "radar_monitor = radar_runtime.RadarMonitor(DB_PATH)",
            source,
        )
        self.assertIn(
            "app.bot_data['radar_monitor_task'] = asyncio.create_task("
            "radar_monitor.loop(app))",
            source,
        )
        self.assertIn(
            "('radar_monitor_task', '🌐 Cloudflare Radar Network Context')",
            source,
        )

    def test_runtime_source_has_no_operational_side_effect_hooks(self):
        source = RUNTIME_PATH.read_text(encoding="utf-8")
        for forbidden in (
            "_db_set_host_active(",
            "_db_set_default_host(",
            "_db_set_all_accounts_host(",
            "_update_cloudflare_dns(",
            "_cf_switch_public_domain(",
            "_activate_standby_for_filtered_edge(",
            "promote_edge_to_core",
            "demote_core_to_edge",
            "_notify_admins(",
        ):
            self.assertNotIn(forbidden, source)


class FakeApp:
    def __init__(self):
        self.bot_data = {}


class RadarMonitorAsyncTests(unittest.IsolatedAsyncioTestCase):
    async def test_tick_updates_cache_and_persistence(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(pathlib.Path(tmp) / "radar.db")
            monitor = RadarMonitor(
                db_path,
                client=FakeClient(),
                interval_seconds=60,
                initial_delay_seconds=0,
            )
            app = FakeApp()

            result = await monitor.tick(app)

            self.assertEqual(result.state, "NORMAL")
            self.assertEqual(app.bot_data["radar_network_context"]["state"], "NORMAL")
            self.assertEqual(app.bot_data["radar_provider_health"]["status"], "OK")
            self.assertIsNotNone(load_latest_radar_snapshot(db_path))


if __name__ == "__main__":
    unittest.main()
