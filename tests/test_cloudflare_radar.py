import pathlib
import unittest
import urllib.parse

from cloudflare_radar import (
    CloudflareRadarAuthError,
    CloudflareRadarClient,
    CloudflareRadarError,
    CloudflareRadarRateLimited,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]
PROVIDER_PATH = ROOT / "cloudflare_radar.py"


class FakeRadarTransport:
    def __init__(self):
        self.calls = []
        self.responses = []

    def queue(self, payload):
        self.responses.append(payload)

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append((method, url, headers, body, timeout))
        if not self.responses:
            raise AssertionError(
                f"unexpected call: {method} {url}"
            )
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


def timeseries_payload(series, *, confidence=7):
    return {
        "success": True,
        "result": {
            "meta": {
                "aggInterval": "FIFTEEN_MINUTES",
                "confidenceInfo": {
                    "annotations": [],
                    "level": confidence,
                },
                "dateRange": [
                    {
                        "startTime": "2026-10-06T00:00:00Z",
                        "endTime": "2026-10-07T00:00:00Z",
                    }
                ],
                "lastUpdated": "2026-10-06T20:00:00Z",
                "normalization": "RAW_VALUES",
                "units": [
                    {
                        "name": "*",
                        "value": "requests",
                    }
                ],
            },
            "serie_0": {
                "timestamps": [
                    "2026-10-06T19:45:00Z",
                    "2026-10-06T20:00:00Z",
                ],
                **series,
            },
        },
    }


class RadarV1ClientTests(unittest.TestCase):
    def setUp(self):
        self.transport = FakeRadarTransport()
        self.sleeps = []
        self.client = CloudflareRadarClient(
            "radar-secret",
            transport=self.transport,
            sleeper=self.sleeps.append,
            retries=2,
            backoff_base=0.5,
            backoff_max=8,
        )

    def test_requires_dedicated_token(self):
        with self.assertRaisesRegex(
            CloudflareRadarError,
            "token is not configured",
        ):
            CloudflareRadarClient("")

    def test_traffic_anomalies_use_iran_verified_defaults(self):
        self.transport.queue(
            {
                "success": True,
                "result": {
                    "trafficAnomalies": [
                        {
                            "uuid": "anomaly-1",
                            "status": "VERIFIED",
                            "type": "LOCATION",
                            "startDate": "2026-10-06T18:00:00Z",
                            "endDate": None,
                            "locationDetails": {
                                "code": "IR",
                                "name": "Iran",
                            },
                            "asnDetails": None,
                            "visibleInDataSources": ["NET"],
                        }
                    ]
                },
            }
        )

        result = self.client.get_traffic_anomalies()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].location_code, "IR")
        self.assertEqual(result[0].status, "VERIFIED")

        method, url, headers, body, timeout = (
            self.transport.calls[0]
        )
        query = urllib.parse.parse_qs(
            urllib.parse.urlparse(url).query
        )
        self.assertEqual(method, "GET")
        self.assertIsNone(body)
        self.assertEqual(query["location"], ["IR"])
        self.assertEqual(query["dateRange"], ["1d"])
        self.assertEqual(query["status"], ["VERIFIED"])
        self.assertEqual(
            headers["Authorization"],
            "Bearer radar-secret",
        )
        self.assertNotIn("radar-secret", repr(result))
        self.assertGreater(timeout, 0)

    def test_netflows_parses_numeric_series_and_metadata(self):
        self.transport.queue(
            timeseries_payload(
                {"values": ["100", "82.5"]},
                confidence=8,
            )
        )
        result = self.client.get_netflows()

        self.assertEqual(result.metric, "NETFLOWS")
        self.assertEqual(result.scope, "LOCATION:IR")
        self.assertEqual(
            result.series_dict()["values"],
            (100.0, 82.5),
        )
        self.assertEqual(
            result.meta.confidence_level,
            8,
        )
        self.assertEqual(
            result.meta.agg_interval,
            "FIFTEEN_MINUTES",
        )

        query = urllib.parse.parse_qs(
            urllib.parse.urlparse(
                self.transport.calls[0][1]
            ).query
        )
        self.assertEqual(
            query["aggInterval"],
            ["15m"],
        )
        self.assertEqual(
            query["product"],
            ["ALL"],
        )

    def test_iqi_preserves_dynamic_percentile_series(self):
        self.transport.queue(
            timeseries_payload(
                {
                    "p25": ["10", "11"],
                    "p50": ["20", "21"],
                    "p75": ["30", "31"],
                }
            )
        )
        result = self.client.get_iqi("latency")

        self.assertEqual(result.metric, "LATENCY")
        self.assertEqual(
            result.series_dict()["p50"],
            (20.0, 21.0),
        )

        query = urllib.parse.parse_qs(
            urllib.parse.urlparse(
                self.transport.calls[0][1]
            ).query
        )
        self.assertEqual(
            query["metric"],
            ["LATENCY"],
        )
        self.assertEqual(
            query["location"],
            ["IR"],
        )

    def test_iqi_timestamp_only_shape_does_not_invent_values(self):
        self.transport.queue(
            timeseries_payload({})
        )
        result = self.client.get_iqi("DNS")

        self.assertEqual(
            result.timestamps[-1],
            "2026-10-06T20:00:00Z",
        )
        self.assertEqual(
            result.series,
            (),
        )

    def test_outages_normalize_provider_annotations(self):
        self.transport.queue(
            {
                "success": True,
                "result": {
                    "annotations": [
                        {
                            "id": "550",
                            "eventType": "OUTAGE",
                            "description": "example",
                            "dataSource": "NET",
                            "scope": "Iran",
                            "startDate": "2026-10-06T18:00:00Z",
                            "endDate": None,
                            "locations": ["IR"],
                            "asns": [58224],
                            "tags": ["LOCATION"],
                            "outage": {
                                "outageCause": (
                                    "NETWORK_PROBLEM"
                                ),
                                "outageType": "NATIONWIDE",
                            },
                        }
                    ]
                },
            }
        )

        result = self.client.get_outages()

        self.assertEqual(
            result[0].outage_type,
            "NATIONWIDE",
        )
        self.assertEqual(
            result[0].outage_cause,
            "NETWORK_PROBLEM",
        )
        self.assertEqual(
            result[0].asns,
            ("58224",),
        )

    def test_rate_limit_retries_with_retry_after(self):
        self.transport.queue(
            CloudflareRadarRateLimited(
                "limited",
                retry_after=2.0,
            )
        )
        self.transport.queue(
            timeseries_payload(
                {"values": ["1", "2"]}
            )
        )

        result = self.client.get_netflows()

        self.assertEqual(
            result.series_dict()["values"],
            (1.0, 2.0),
        )
        self.assertEqual(
            len(self.transport.calls),
            2,
        )
        self.assertEqual(
            self.sleeps,
            [2.0],
        )

    def test_auth_failure_is_not_retried(self):
        self.transport.queue(
            CloudflareRadarAuthError("forbidden")
        )

        with self.assertRaises(
            CloudflareRadarAuthError
        ):
            self.client.get_netflows()

        self.assertEqual(
            len(self.transport.calls),
            1,
        )
        self.assertEqual(
            self.sleeps,
            [],
        )

    def test_invalid_success_payload_fails_closed(self):
        self.transport.queue(
            {
                "success": False,
                "errors": [{"code": 1000}],
            }
        )

        with self.assertRaisesRegex(
            CloudflareRadarError,
            "API failed",
        ):
            self.client.get_outages()

    def test_scope_can_use_asn_without_location_filter(self):
        self.transport.queue(
            timeseries_payload(
                {"values": ["5", "6"]}
            )
        )

        result = self.client.get_netflows(
            asn="AS58224"
        )
        self.assertEqual(
            result.scope,
            "ASN:58224",
        )

        query = urllib.parse.parse_qs(
            urllib.parse.urlparse(
                self.transport.calls[0][1]
            ).query
        )
        self.assertEqual(
            query["asn"],
            ["58224"],
        )
        self.assertNotIn(
            "location",
            query,
        )

    def test_invalid_scope_and_metric_stop_before_network(self):
        with self.assertRaises(
            CloudflareRadarError
        ):
            self.client.get_netflows(
                location="IRAN"
            )

        with self.assertRaises(
            CloudflareRadarError
        ):
            self.client.get_iqi(
                "PACKET_LOSS"
            )

        self.assertEqual(
            self.transport.calls,
            [],
        )

    def test_radar_core_has_no_operational_side_effect_hooks(self):
        source = PROVIDER_PATH.read_text(
            encoding="utf-8"
        )
        for forbidden in (
            "_db_set_host_active(",
            "_db_set_default_host(",
            "_db_set_all_accounts_host(",
            "_update_cloudflare_dns(",
            "_cf_switch_public_domain(",
            "_activate_standby_for_filtered_edge(",
            "promote_edge_to_core",
            "demote_core_to_edge",
            "failover_operations",
        ):
            self.assertNotIn(
                forbidden,
                source,
            )


if __name__ == "__main__":
    unittest.main()
