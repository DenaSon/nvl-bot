import unittest
from datetime import datetime, timezone

from cloudflare_radar import (
    RadarMeta,
    RadarOutage,
    RadarTimeSeries,
    RadarTrafficAnomaly,
)
from radar_context import (
    NETWORK_STATE_DEGRADED,
    NETWORK_STATE_NORMAL,
    NETWORK_STATE_OUTAGE,
    NETWORK_STATE_UNKNOWN,
    derive_network_context,
)


NOW = datetime(2026, 10, 6, 20, 0, tzinfo=timezone.utc)


def meta(unit="ms", confidence=7):
    return RadarMeta(
        agg_interval="FIFTEEN_MINUTES",
        confidence_level=confidence,
        last_updated="2026-10-06T19:55:00Z",
        normalization="RAW_VALUES",
        units=(("*", unit),),
        date_ranges=(("2026-10-06T00:00:00Z", "2026-10-06T20:00:00Z"),),
    )


def series(metric, values, *, unit="ms"):
    return RadarTimeSeries(
        metric=metric,
        scope="LOCATION:IR",
        timestamps=(
            "2026-10-06T19:45:00Z",
            "2026-10-06T20:00:00Z",
        ),
        series=(("p50", tuple(values)),),
        meta=meta(unit),
    )


def anomaly(*, status="VERIFIED", start="2026-10-06T19:00:00Z", end=None):
    return RadarTrafficAnomaly(
        uuid="a1",
        status=status,
        anomaly_type="LOCATION",
        start_date=start,
        end_date=end,
        location_code="IR",
        location_name="Iran",
        asn=None,
        asn_name=None,
        visible_in_data_sources=("NET",),
    )


def outage(*, start="2026-10-06T19:00:00Z", end=None):
    return RadarOutage(
        annotation_id="o1",
        event_type="OUTAGE",
        description="test outage",
        data_source="NET",
        scope="Iran",
        start_date=start,
        end_date=end,
        outage_cause="NETWORK_PROBLEM",
        outage_type="NATIONWIDE",
        locations=("IR",),
        asns=(),
        tags=("LOCATION",),
    )


class RadarContextTests(unittest.TestCase):
    def base(self, **overrides):
        data = {
            "provider_status": "OK",
            "provider_error": None,
            "source_statuses": {
                "traffic_anomalies": "OK",
                "outages": "OK",
                "netflows": "OK",
                "latency": "OK",
                "dns": "OK",
                "bandwidth": "OK",
            },
            "now": NOW,
        }
        data.update(overrides)
        return derive_network_context(**data)

    def test_active_outage_is_outage(self):
        result = self.base(outages=(outage(),))
        self.assertEqual(result.state, NETWORK_STATE_OUTAGE)
        self.assertEqual(result.active_outage_count, 1)

    def test_verified_active_anomaly_is_degraded(self):
        result = self.base(anomalies=(anomaly(),))
        self.assertEqual(result.state, NETWORK_STATE_DEGRADED)
        self.assertEqual(result.active_anomaly_count, 1)

    def test_ended_events_do_not_keep_context_degraded(self):
        result = self.base(
            anomalies=(anomaly(end="2026-10-06T18:00:00Z"),),
            outages=(outage(end="2026-10-06T18:00:00Z"),),
        )
        self.assertEqual(result.state, NETWORK_STATE_NORMAL)
        self.assertEqual(result.active_anomaly_count, 0)
        self.assertEqual(result.active_outage_count, 0)

    def test_unverified_anomaly_never_degrades(self):
        result = self.base(
            anomalies=(anomaly(status="UNVERIFIED"),),
        )
        self.assertEqual(result.state, NETWORK_STATE_NORMAL)

    def test_missing_primary_evidence_is_unknown(self):
        result = self.base(
            provider_status="PARTIAL",
            source_statuses={
                "traffic_anomalies": "ERROR",
                "outages": "OK",
                "netflows": "OK",
            },
        )
        self.assertEqual(result.state, NETWORK_STATE_UNKNOWN)

    def test_metrics_are_context_only_and_do_not_create_outage(self):
        result = self.base(
            netflows=series("NETFLOWS", (100.0, 1.0), unit="requests"),
            latency=series("LATENCY", (10.0, 90.0)),
            dns=series("DNS", (5.0, 50.0)),
            bandwidth=series("BANDWIDTH", (100.0, 5.0), unit="Mbps"),
        )
        self.assertEqual(result.state, NETWORK_STATE_NORMAL)
        self.assertEqual(result.traffic.value, 1.0)
        self.assertEqual(result.traffic.previous_value, 100.0)
        self.assertAlmostEqual(result.traffic.delta_pct, -99.0)
        self.assertEqual(result.latency.value, 90.0)
        self.assertEqual(result.bandwidth.unit, "Mbps")

    def test_decision_serializes_source_status_and_confidence(self):
        result = self.base(
            latency=series("LATENCY", (10.0, 11.0)),
            bandwidth=series("BANDWIDTH", (20.0, 21.0), unit="Mbps"),
        )
        payload = result.to_dict()
        self.assertEqual(payload["source_statuses"]["outages"], "OK")
        self.assertEqual(payload["confidence_level"], 7)
        self.assertEqual(payload["scope_value"], "IR")


if __name__ == "__main__":
    unittest.main()
