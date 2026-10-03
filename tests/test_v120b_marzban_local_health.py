import pathlib
import sqlite3
import unittest

import marzban_asset_discovery as discovery
import marzban_local_health as health


ROOT = pathlib.Path(__file__).resolve().parents[1]
BOT_PATH = ROOT / "bot_final_v49-2.py"
MODULE_PATH = ROOT / "marzban_local_health.py"


def make_asset(
    key,
    kind,
    port,
    *,
    resolved=("203.0.113.10",),
    metadata=None,
    source_id="1",
):
    return discovery.MarzbanAsset(
        asset_key=key,
        asset_type=kind,
        source_id=source_id,
        name=key,
        address="example.test",
        port=port,
        resolved_ips=tuple(resolved),
        metadata=dict(metadata or {}),
    )


class FakeService:
    configured = True

    def __init__(self, system_ok=True, nodes_ok=True, node_status="connected"):
        self.system_ok = system_ok
        self.nodes_ok = nodes_ok
        self.node_status = node_status

    async def get_system_stats(self):
        return (True, {"version": "0.8.4"}) if self.system_ok else (False, "api failed")

    async def get_nodes(self):
        if not self.nodes_ok:
            return False, "nodes api failed"
        return True, [{"id": 7, "status": self.node_status}]


class ProbeHarness:
    def __init__(self, failures=()):
        self.failures = set(failures)
        self.calls = []

    async def __call__(self, host, port, timeout):
        self.calls.append((host, port))
        ok = (host, port) not in self.failures
        return health.TcpProbe(
            host=host,
            port=port,
            ok=ok,
            latency_ms=10.0 if ok else None,
            error=None if ok else "timeout",
        )


class V120BLocalHealthTests(unittest.IsolatedAsyncioTestCase):
    async def test_main_healthy_requires_tcp_and_api(self):
        main = make_asset("MARZBAN_MAIN:main", discovery.ASSET_MAIN, 2053)
        result = (await health.collect_local_health(
            [main], FakeService(), probe_func=ProbeHarness()
        ))[0]
        self.assertEqual(result.health_state, health.STATE_LOCAL_HEALTHY)
        self.assertTrue(result.healthy)

    async def test_main_api_failure_is_distinct(self):
        main = make_asset("MARZBAN_MAIN:main", discovery.ASSET_MAIN, 2053)
        result = (await health.collect_local_health(
            [main], FakeService(system_ok=False), probe_func=ProbeHarness()
        ))[0]
        self.assertEqual(result.health_state, health.STATE_API_DOWN)
        self.assertEqual(result.health_reason, health.REASON_MAIN_API_UNAVAILABLE)

    async def test_dns_failure_is_distinct(self):
        main = make_asset(
            "MARZBAN_MAIN:main",
            discovery.ASSET_MAIN,
            2053,
            resolved=(),
            metadata={"resolution_error": "dns failed"},
        )
        result = (await health.collect_local_health(
            [main], FakeService(), probe_func=ProbeHarness()
        ))[0]
        self.assertEqual(result.health_state, health.STATE_DNS_ERROR)

    async def test_node_uses_live_status_and_two_control_ports(self):
        node = make_asset(
            "MARZBAN_NODE:7",
            discovery.ASSET_NODE,
            62050,
            source_id="7",
            metadata={"node_id": 7, "status": "connected", "api_port": 62051},
        )
        harness = ProbeHarness()
        result = (await health.collect_local_health(
            [node], FakeService(), probe_func=harness
        ))[0]
        self.assertEqual(result.health_state, health.STATE_LOCAL_HEALTHY)
        self.assertIn(("203.0.113.10", 62050), harness.calls)
        self.assertIn(("203.0.113.10", 62051), harness.calls)
        self.assertEqual(result.evidence["node_status_source"], "inventory")

    async def test_node_live_disconnected_wins_when_main_api_reachable(self):
        main = make_asset("MARZBAN_MAIN:main", discovery.ASSET_MAIN, 2053)
        node = make_asset(
            "MARZBAN_NODE:7",
            discovery.ASSET_NODE,
            62050,
            source_id="7",
            metadata={"node_id": 7, "status": "connected", "api_port": 62051},
        )
        results = await health.collect_local_health(
            [main, node],
            FakeService(node_status="error"),
            probe_func=ProbeHarness(),
        )
        node_result = next(r for r in results if r.asset_type == discovery.ASSET_NODE)
        self.assertEqual(node_result.health_state, health.STATE_NODE_DISCONNECTED)
        self.assertEqual(node_result.evidence["node_status_source"], "live_api")

    async def test_node_api_port_failure_is_control_down(self):
        main = make_asset("MARZBAN_MAIN:main", discovery.ASSET_MAIN, 2053)
        node = make_asset(
            "MARZBAN_NODE:7",
            discovery.ASSET_NODE,
            62050,
            source_id="7",
            metadata={"node_id": 7, "status": "connected", "api_port": 62051},
        )
        results = await health.collect_local_health(
            [main, node],
            FakeService(),
            probe_func=ProbeHarness({("203.0.113.10", 62051)}),
        )
        node_result = next(r for r in results if r.asset_type == discovery.ASSET_NODE)
        self.assertEqual(node_result.health_state, health.STATE_CONTROL_DOWN)
        self.assertEqual(node_result.health_reason, health.REASON_NODE_API_UNREACHABLE)

    async def test_public_host_uses_customer_port(self):
        public = make_asset(
            "MARZBAN_PUBLIC_HOST:VLESS:0",
            discovery.ASSET_PUBLIC_HOST,
            8443,
        )
        harness = ProbeHarness()
        result = (await health.collect_local_health(
            [public], FakeService(), probe_func=harness
        ))[0]
        self.assertEqual(result.health_state, health.STATE_LOCAL_HEALTHY)
        self.assertIn(("203.0.113.10", 8443), harness.calls)

    async def test_disabled_public_host_is_neutral_and_not_probed(self):
        public = make_asset(
            "MARZBAN_PUBLIC_HOST:VLESS:0",
            discovery.ASSET_PUBLIC_HOST,
            8443,
            metadata={"is_disabled": True},
        )
        harness = ProbeHarness()
        result = (await health.collect_local_health(
            [public], FakeService(), probe_func=harness
        ))[0]
        self.assertEqual(result.health_state, health.STATE_DISABLED)
        self.assertIsNone(result.healthy)
        self.assertNotIn(("203.0.113.10", 8443), harness.calls)

    async def test_disabled_node_is_neutral_even_without_dns(self):
        node = make_asset(
            "MARZBAN_NODE:7",
            discovery.ASSET_NODE,
            62050,
            source_id="7",
            resolved=(),
            metadata={"node_id": 7, "status": "disabled", "api_port": 62051},
        )
        result = (await health.collect_local_health(
            [node], FakeService(), probe_func=ProbeHarness()
        ))[0]
        self.assertEqual(result.health_state, health.STATE_DISABLED)
        self.assertIsNone(result.healthy)

    async def test_shared_endpoint_is_probed_once(self):
        a = make_asset("MARZBAN_PUBLIC_HOST:A:0", discovery.ASSET_PUBLIC_HOST, 443)
        b = make_asset("MARZBAN_PUBLIC_HOST:B:0", discovery.ASSET_PUBLIC_HOST, 443)
        harness = ProbeHarness()
        await health.collect_local_health([a, b], FakeService(), probe_func=harness)
        self.assertEqual(harness.calls.count(("203.0.113.10", 443)), 1)

    async def test_main_tcp_down_skips_api_calls_and_keeps_node_local_evidence(self):
        main = make_asset("MARZBAN_MAIN:main", discovery.ASSET_MAIN, 2053)
        node = make_asset(
            "MARZBAN_NODE:7",
            discovery.ASSET_NODE,
            62050,
            source_id="7",
            metadata={"node_id": 7, "status": "connected", "api_port": 62051},
        )
        harness = ProbeHarness({("203.0.113.10", 2053)})
        results = await health.collect_local_health(
            [main, node], FakeService(), probe_func=harness
        )
        main_result = next(r for r in results if r.asset_type == discovery.ASSET_MAIN)
        node_result = next(r for r in results if r.asset_type == discovery.ASSET_NODE)
        self.assertEqual(main_result.health_state, health.STATE_SERVICE_DOWN)
        self.assertEqual(node_result.health_state, health.STATE_LOCAL_HEALTHY)
        self.assertEqual(node_result.evidence["node_status_source"], "inventory")


class V120BPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        health.install_schema(self.conn)

    def tearDown(self):
        self.conn.close()

    def row(self, state, healthy, stamp, reason=health.REASON_OK):
        return health.AssetHealth(
            "MARZBAN_MAIN:main",
            discovery.ASSET_MAIN,
            state,
            reason,
            healthy,
            stamp,
            10.0 if healthy else None,
            {"x": 1},
        )

    def test_state_since_changes_only_on_transition(self):
        health.persist_health_snapshot(
            self.conn,
            [self.row(health.STATE_LOCAL_HEALTHY, True, "2026-10-03T21:00:00Z")],
        )
        health.persist_health_snapshot(
            self.conn,
            [self.row(health.STATE_LOCAL_HEALTHY, True, "2026-10-03T21:01:00Z")],
        )
        current = health.list_health(self.conn)["MARZBAN_MAIN:main"]
        self.assertEqual(current["state_since"], "2026-10-03T21:00:00Z")
        self.assertEqual(current["last_success_at"], "2026-10-03T21:01:00Z")

        health.persist_health_snapshot(
            self.conn,
            [self.row(
                health.STATE_SERVICE_DOWN,
                False,
                "2026-10-03T21:02:00Z",
                health.REASON_TCP_UNREACHABLE,
            )],
        )
        current = health.list_health(self.conn)["MARZBAN_MAIN:main"]
        self.assertEqual(current["state_since"], "2026-10-03T21:02:00Z")
        self.assertEqual(current["last_failure_at"], "2026-10-03T21:02:00Z")

    def test_unknown_does_not_destroy_last_success(self):
        health.persist_health_snapshot(
            self.conn,
            [self.row(health.STATE_LOCAL_HEALTHY, True, "2026-10-03T21:00:00Z")],
        )
        health.persist_health_snapshot(
            self.conn,
            [self.row(
                health.STATE_UNKNOWN,
                None,
                "2026-10-03T21:01:00Z",
                health.REASON_PORT_UNKNOWN,
            )],
        )
        current = health.list_health(self.conn)["MARZBAN_MAIN:main"]
        self.assertEqual(current["last_success_at"], "2026-10-03T21:00:00Z")
        self.assertIsNone(current["last_failure_at"])


class V120BRuntimeShapeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bot = BOT_PATH.read_text(encoding="utf-8")
        cls.module = MODULE_PATH.read_text(encoding="utf-8")

    def test_schema_and_task_lifecycle_are_wired(self):
        self.assertIn("marzban_local_health.install_schema(conn)", self.bot)
        init = self.bot.index("async def _post_init(app):")
        shutdown = self.bot.index("async def _post_shutdown(app):", init)
        main = self.bot.index("if __name__ == '__main__':", shutdown)
        self.assertIn("marzban_local_health_task", self.bot[init:shutdown])
        self.assertIn("marzban_local_health_task", self.bot[shutdown:main])

    def test_bounded_defaults(self):
        self.assertIn('NVL_MARZBAN_LOCAL_HEALTH_INTERVAL", 60', self.bot)
        self.assertIn('NVL_MARZBAN_LOCAL_HEALTH_TIMEOUT", 5', self.bot)
        self.assertIn('NVL_MARZBAN_LOCAL_HEALTH_CONCURRENCY", 10', self.bot)

    def test_module_has_no_regional_alert_or_mutation_calls(self):
        for forbidden in (
            "regional_filtering",
            "checkhost",
            "send_message(",
            "modify_node(",
            "update_host(",
            "set_node_enabled(",
            "reconnect_node(",
            "_safe_manual_failover(",
            "_cf_switch_public_domain(",
        ):
            self.assertNotIn(forbidden, self.module)


if __name__ == "__main__":
    unittest.main()
