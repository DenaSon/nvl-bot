import pathlib
import unittest

from checkhost_probe import CheckHostNode, RegionalTcpProbe, TcpNodeEvidence
from regional_probe_provider import (
    CheckHostRegionalProbeProvider,
    RegionalProbeError,
    RegionalProbeLimited,
    RegionalProbeNode,
    build_regional_probe_provider,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]
BOT_PATH = ROOT / "bot_final_v49-2.py"
PROVIDER_PATH = ROOT / "regional_probe_provider.py"


class _FakeCheckHostClient:
    def discover_nodes(self, country_code):
        if country_code == "limit":
            from checkhost_probe import CheckHostLimitExceeded
            raise CheckHostLimitExceeded("limited")
        return (
            CheckHostNode("ir1", "ir", "Iran", "Tehran", "1.1.1.1", "AS1"),
            CheckHostNode("ir2", "ir", "Iran", "Shiraz", "2.2.2.2", "AS2"),
        )

    def start_tcp_check(self, host, port, nodes):
        return "req-1", "https://example.invalid/req-1", tuple(nodes)

    def poll_tcp_result(self, request_id, nodes, *, target_host, target_port, permanent_link=None):
        evidence = tuple(
            TcpNodeEvidence(
                node=node.name,
                country_code=node.country_code,
                country=node.country,
                city=node.city,
                ip=node.ip,
                asn=node.asn,
                ok=True,
                pending=False,
                latency_ms=10.0,
                address=target_host,
            )
            for node in nodes
        )
        return RegionalTcpProbe(
            request_id=request_id,
            permanent_link=permanent_link,
            target_host=target_host,
            target_port=target_port,
            evidence=evidence,
        )


class V119AProviderAbstractionTests(unittest.TestCase):
    def test_factory_defaults_to_check_host(self):
        provider = build_regional_probe_provider("check-host")
        self.assertIsInstance(provider, CheckHostRegionalProbeProvider)
        self.assertEqual(provider.name, "check-host")

    def test_unknown_provider_is_fail_closed(self):
        with self.assertRaises(ValueError):
            build_regional_probe_provider("not-configured")

    def test_checkhost_nodes_are_normalized(self):
        provider = CheckHostRegionalProbeProvider()
        provider.client = _FakeCheckHostClient()
        nodes = provider.discover_nodes("ir")
        self.assertEqual(len(nodes), 2)
        self.assertIsInstance(nodes[0], RegionalProbeNode)
        self.assertEqual(nodes[0].asn, "AS1")

    def test_checkhost_probe_is_normalized(self):
        provider = CheckHostRegionalProbeProvider()
        provider.client = _FakeCheckHostClient()
        nodes = provider.discover_nodes("ir")
        result = provider.probe_tcp("203.0.113.10", 2252, nodes)
        self.assertEqual(result.provider, "check-host")
        self.assertEqual(result.request_id, "req-1")
        self.assertEqual(result.completed_nodes, 2)
        self.assertEqual(result.successful_nodes, 2)

    def test_limit_is_translated_to_provider_neutral_exception(self):
        provider = CheckHostRegionalProbeProvider()
        provider.client = _FakeCheckHostClient()
        with self.assertRaises(RegionalProbeLimited):
            provider.discover_nodes("limit")

    def test_provider_module_has_no_operational_side_effects(self):
        source = PROVIDER_PATH.read_text(encoding="utf-8")
        for forbidden in (
            "sqlite3",
            "_db_",
            "_safe_manual_failover",
            "_cf_switch_public_domain",
            "subprocess",
        ):
            self.assertNotIn(forbidden, source)


class V119AFastDetectionStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")

    def _region(self, start_marker, end_marker):
        start = self.source.index(start_marker)
        end = self.source.index(end_marker, start)
        return self.source[start:end]

    def test_release_marker(self):
        self.assertIn(
            'BOT_VERSION_TAG = "V120D.2-2026-10-04-clean-monitoring-data"',
            self.source,
        )

    def test_default_regional_interval_is_one_minute(self):
        self.assertIn(
            'REGIONAL_FILTER_MONITOR_INTERVAL_SECONDS = _phase6c_env_int("NVL_REGIONAL_PROBE_INTERVAL", 60)',
            self.source,
        )

    def test_default_confirmation_threshold_is_two(self):
        self.assertIn(
            'EDGE_FILTER_CONFIRM_THRESHOLD = _phase6c_env_int("NVL_FILTER_CONFIRM_THRESHOLD", 2)',
            self.source,
        )

    def test_regional_monitor_targets_only_default_edge(self):
        region = self._region(
            "def _db_get_regional_monitor_targets():",
            "def _db_get_recent_regional_node_results(",
        )
        self.assertIn("WHERE active=1 AND is_default=1 LIMIT 1", region)
        self.assertNotIn("ORDER BY is_default DESC", region)

    def test_runtime_uses_provider_abstraction_not_checkhost_client(self):
        self.assertIn("build_regional_probe_provider", self.source)
        runtime = self._region(
            "def _new_regional_probe_provider():",
            "async def _phase6h_auto_failover_tick(app, ready_candidate_override=None):",
        )
        self.assertIn("provider.probe_tcp", runtime)
        self.assertNotIn("CheckHostClient", runtime)
        self.assertNotIn("CheckHostError", runtime)

    def test_first_likely_round_gets_fast_confirmation(self):
        region = self._region(
            "async def _regional_filter_tick(app):",
            "async def _regional_filter_probe_one_now",
        )
        self.assertIn("REGIONAL_FAST_CONFIRM_DELAY_SECONDS", region)
        self.assertIn("decision.state == FILTER_STATE_LIKELY", region)
        self.assertIn("0 < streak < EDGE_FILTER_CONFIRM_THRESHOLD", region)
        self.assertGreaterEqual(region.count("_regional_filter_probe_edge("), 2)

    def test_phase6h_evaluates_after_default_probe(self):
        region = self._region(
            "async def _regional_filter_tick(app):",
            "async def _regional_filter_probe_one_now",
        )
        self.assertIn("await _phase6h_auto_failover_tick(", region)
        self.assertNotIn("round_provider_ok", region)
        self.assertNotIn("for index,", region)

    def test_fast_sentinel_is_15_seconds_and_two_failures(self):
        self.assertIn(
            'FAST_SENTINEL_INTERVAL_SECONDS = _phase6c_env_int("NVL_FAST_SENTINEL_INTERVAL", 15)',
            self.source,
        )
        self.assertIn(
            'FAST_SENTINEL_CONFIRM_FAILURES = _phase6c_env_int("NVL_FAST_SENTINEL_CONFIRM_FAILURES", 2)',
            self.source,
        )
        region = self._region(
            "async def _fast_default_sentinel_tick(app):",
            "async def _fast_default_sentinel_loop(app):",
        )
        self.assertIn("_tcp_health_check", region)
        self.assertIn("_probe_wireguard_edge_sync", region)
        self.assertIn("await _regional_filter_tick(app)", region)
        self.assertNotIn("_safe_manual_failover", region)
        self.assertNotIn("_cf_switch_public_domain", region)

    def test_probe_lock_prevents_duplicate_provider_runs(self):
        region = self._region(
            "async def _regional_filter_tick(app):",
            "async def _regional_filter_probe_one_now",
        )
        self.assertIn("_regional_probe_lock(app)", region)
        self.assertIn("PROBE_ALREADY_RUNNING", region)

    def test_fast_sentinel_task_has_clean_lifecycle(self):
        post_init = self._region(
            "async def _post_init(app):",
            "async def _post_shutdown(app):",
        )
        shutdown = self._region(
            "async def _post_shutdown(app):",
            "if __name__ == '__main__':",
        )
        self.assertIn("fast_default_sentinel_task", post_init)
        self.assertIn("fast_default_sentinel_task", shutdown)


if __name__ == "__main__":
    unittest.main()
