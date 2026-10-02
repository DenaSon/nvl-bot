import pathlib
import unittest
import urllib.parse

from checkhost_probe import (
    CheckHostClient,
    CheckHostNode,
    RegionalTcpProbe,
    TcpNodeEvidence,
    normalize_tcp_node_result,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]
PROVIDER_PATH = ROOT / "checkhost_probe.py"


def node(name="ir1.node.check-host.net", city="Tehran", asn="AS1"):
    return CheckHostNode(
        name=name,
        country_code="ir",
        country="Iran",
        city=city,
        ip="192.0.2.1",
        asn=asn,
    )


class Phase6DCheckHostParsingTests(unittest.TestCase):
    def test_tcp_success_is_normalized_in_milliseconds(self):
        result = normalize_tcp_node_result(
            node(),
            [{"address": "1.1.1.1", "time": 0.081599}],
        )
        self.assertTrue(result.ok)
        self.assertFalse(result.pending)
        self.assertEqual(result.address, "1.1.1.1")
        self.assertAlmostEqual(result.latency_ms, 81.599, places=3)
        self.assertIsNone(result.error)

    def test_tcp_error_is_a_completed_failure(self):
        result = normalize_tcp_node_result(
            node(),
            [{"error": "Connection timed out"}],
        )
        self.assertFalse(result.ok)
        self.assertFalse(result.pending)
        self.assertEqual(result.error, "Connection timed out")

    def test_message_shape_is_also_preserved_as_failure(self):
        result = normalize_tcp_node_result(
            node(),
            [None, {"message": "Connect timeout"}],
        )
        self.assertFalse(result.ok)
        self.assertFalse(result.pending)
        self.assertEqual(result.error, "Connect timeout")

    def test_null_result_is_pending_not_failure(self):
        result = normalize_tcp_node_result(node(), None)
        self.assertIsNone(result.ok)
        self.assertTrue(result.pending)
        self.assertIsNone(result.error)


class Phase6DCheckHostClientTests(unittest.TestCase):
    def test_discovery_filters_iran_nodes_and_preserves_metadata(self):
        def transport(url, timeout):
            self.assertTrue(url.endswith("/nodes/hosts"))
            return {
                "nodes": {
                    "ir2.node.check-host.net": {
                        "asn": "AS209279",
                        "ip": "195.182.38.164",
                        "location": ["ir", "Iran", "Isfahan"],
                    },
                    "de1.node.check-host.net": {
                        "asn": "AS24940",
                        "ip": "46.4.143.48",
                        "location": ["de", "Germany", "Falkenstein"],
                    },
                    "ir1.node.check-host.net": {
                        "asn": "AS47430",
                        "ip": "185.105.238.209",
                        "location": ["ir", "Iran", "Tehran"],
                    },
                }
            }

        client = CheckHostClient(transport=transport)
        nodes = client.discover_nodes("ir")

        self.assertEqual(
            [item.name for item in nodes],
            ["ir1.node.check-host.net", "ir2.node.check-host.net"],
        )
        self.assertEqual(nodes[0].city, "Tehran")
        self.assertEqual(nodes[0].asn, "AS47430")

    def test_start_tcp_check_uses_repeated_node_parameters(self):
        captured = {}

        def transport(url, timeout):
            captured["url"] = url
            return {
                "ok": 1,
                "request_id": "req-1",
                "permanent_link": "https://check-host.net/check-report/req-1",
                "nodes": {
                    "ir1.node.check-host.net": [
                        "ir", "Iran", "Tehran", "185.105.238.209", "AS47430"
                    ],
                    "ir2.node.check-host.net": [
                        "ir", "Iran", "Isfahan", "195.182.38.164", "AS209279"
                    ],
                },
            }

        client = CheckHostClient(transport=transport)
        selected = (
            node("ir1.node.check-host.net", "Tehran", "AS47430"),
            node("ir2.node.check-host.net", "Isfahan", "AS209279"),
        )
        request_id, link, response_nodes = client.start_tcp_check(
            "203.0.113.10", 2252, selected
        )

        parsed = urllib.parse.urlparse(captured["url"])
        query = urllib.parse.parse_qs(parsed.query)
        self.assertEqual(parsed.path, "/check-tcp")
        self.assertEqual(query["host"], ["203.0.113.10:2252"])
        self.assertEqual(
            query["node"],
            ["ir1.node.check-host.net", "ir2.node.check-host.net"],
        )
        self.assertEqual(request_id, "req-1")
        self.assertEqual(link, "https://check-host.net/check-report/req-1")
        self.assertEqual(response_nodes[1].city, "Isfahan")

    def test_poll_waits_for_pending_nodes_then_returns_complete_evidence(self):
        calls = {"result": 0}

        def transport(url, timeout):
            if "/check-result/" not in url:
                raise AssertionError(url)
            calls["result"] += 1
            if calls["result"] == 1:
                return {
                    "ir1.node.check-host.net": [
                        {"address": "203.0.113.10", "time": 0.08}
                    ],
                    "ir2.node.check-host.net": None,
                }
            return {
                "ir1.node.check-host.net": [
                    {"address": "203.0.113.10", "time": 0.08}
                ],
                "ir2.node.check-host.net": [
                    {"error": "Connection timed out"}
                ],
            }

        client = CheckHostClient(
            transport=transport,
            sleeper=lambda _: None,
            poll_interval=0,
            poll_timeout=10,
        )
        selected = (
            node("ir1.node.check-host.net", "Tehran", "AS1"),
            node("ir2.node.check-host.net", "Isfahan", "AS2"),
        )
        result = client.poll_tcp_result(
            "req-2",
            selected,
            target_host="203.0.113.10",
            target_port=2252,
        )

        self.assertEqual(calls["result"], 2)
        self.assertEqual(result.successful_nodes, 1)
        self.assertEqual(result.failed_nodes, 1)
        self.assertEqual(result.pending_nodes, 0)

    def test_poll_timeout_preserves_pending_as_unknown(self):
        clock_values = iter([0.0, 20.0])

        def monotonic():
            return next(clock_values)

        def transport(url, timeout):
            return {"ir1.node.check-host.net": None}

        client = CheckHostClient(
            transport=transport,
            sleeper=lambda _: None,
            monotonic=monotonic,
            poll_timeout=1,
        )
        result = client.poll_tcp_result(
            "req-3",
            (node(),),
            target_host="203.0.113.10",
            target_port=2252,
        )

        self.assertEqual(result.pending_nodes, 1)
        self.assertEqual(result.failed_nodes, 0)
        self.assertIsNone(result.evidence[0].ok)

    def test_probe_tcp_keeps_provider_layer_free_of_filter_verdicts(self):
        calls = []

        def transport(url, timeout):
            calls.append(url)
            if url.endswith("/nodes/hosts"):
                return {
                    "nodes": {
                        "ir1.node.check-host.net": {
                            "asn": "AS1",
                            "ip": "192.0.2.1",
                            "location": ["ir", "Iran", "Tehran"],
                        },
                        "ir2.node.check-host.net": {
                            "asn": "AS2",
                            "ip": "192.0.2.2",
                            "location": ["ir", "Iran", "Shiraz"],
                        },
                    }
                }
            if "/check-tcp?" in url:
                return {
                    "ok": 1,
                    "request_id": "req-4",
                    "nodes": {
                        "ir1.node.check-host.net": [
                            "ir", "Iran", "Tehran", "192.0.2.1", "AS1"
                        ],
                        "ir2.node.check-host.net": [
                            "ir", "Iran", "Shiraz", "192.0.2.2", "AS2"
                        ],
                    },
                }
            if "/check-result/" in url:
                return {
                    "ir1.node.check-host.net": [
                        {"address": "203.0.113.10", "time": 0.05}
                    ],
                    "ir2.node.check-host.net": [
                        {"error": "Connection timed out"}
                    ],
                }
            raise AssertionError(url)

        result = CheckHostClient(
            transport=transport,
            sleeper=lambda _: None,
            poll_interval=0,
        ).probe_tcp("203.0.113.10", 2252)

        self.assertEqual(result.total_nodes, 2)
        self.assertEqual(result.successful_nodes, 1)
        self.assertEqual(result.failed_nodes, 1)
        self.assertEqual(result.failed_asns, ("AS2",))
        self.assertEqual(result.failed_cities, ("Shiraz",))
        self.assertAlmostEqual(result.completed_success_ratio, 0.5)


class Phase6DRegionalAggregateTests(unittest.TestCase):
    def test_aggregate_counts_distinct_city_and_asn_evidence(self):
        result = RegionalTcpProbe(
            request_id="req-5",
            permanent_link=None,
            target_host="203.0.113.10",
            target_port=2252,
            evidence=(
                TcpNodeEvidence(
                    "ir1", "ir", "Iran", "Tehran", "192.0.2.1", "AS1",
                    True, False, latency_ms=80.0,
                ),
                TcpNodeEvidence(
                    "ir2", "ir", "Iran", "Shiraz", "192.0.2.2", "AS2",
                    False, False, error="timeout",
                ),
                TcpNodeEvidence(
                    "ir3", "ir", "Iran", "Shiraz", "192.0.2.3", "AS3",
                    False, False, error="timeout",
                ),
                TcpNodeEvidence(
                    "ir4", "ir", "Iran", "Qom", "192.0.2.4", "AS4",
                    None, True,
                ),
            ),
        )

        self.assertEqual(result.total_nodes, 4)
        self.assertEqual(result.completed_nodes, 3)
        self.assertEqual(result.successful_nodes, 1)
        self.assertEqual(result.failed_nodes, 2)
        self.assertEqual(result.pending_nodes, 1)
        self.assertEqual(result.failed_asns, ("AS2", "AS3"))
        self.assertEqual(result.failed_cities, ("Shiraz",))
        self.assertAlmostEqual(result.completed_success_ratio, 1 / 3)

    def test_provider_source_has_no_operational_side_effect_hooks(self):
        source = PROVIDER_PATH.read_text(encoding="utf-8")
        for forbidden in (
            "_db_set_host_active(",
            "_db_set_default_host(",
            "_db_set_all_accounts_host(",
            "_update_cloudflare_dns(",
            "_cf_switch_public_domain(",
            "_activate_standby_for_filtered_edge(",
            "promote_edge_to_core",
            "demote_core_to_edge",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
