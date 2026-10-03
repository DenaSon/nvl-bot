import pathlib
import sqlite3
import unittest

import marzban_asset_discovery as discovery


ROOT = pathlib.Path(__file__).resolve().parents[1]
BOT_PATH = ROOT / "bot_final_v49-2.py"
MODULE_PATH = ROOT / "marzban_asset_discovery.py"


def fake_resolver(address):
    mapping = {
        "gate.nvlsup.xyz": ("144.172.115.27",),
        "node.example.com": ("203.0.113.10",),
        "edge.example.com": ("203.0.113.10",),
        "second.example.com": ("203.0.113.20",),
    }
    if address not in mapping:
        raise OSError("dns miss")
    return mapping[address]


def sample_payloads():
    nodes = [
        {
            "id": 7,
            "name": "Healthy Node",
            "address": "node.example.com",
            "port": 62050,
            "api_port": 62051,
            "status": "connected",
            "usage_coefficient": 1.0,
            "xray_version": "25.1.1",
        }
    ]
    inbounds = {
        "vless": [
            {
                "tag": "VLESS TCP REALITY",
                "protocol": "vless",
                "network": "tcp",
                "tls": "reality",
                "port": 8443,
            }
        ]
    }
    hosts = {
        "VLESS TCP REALITY": [
            {
                "remark": "Node public host",
                "address": "edge.example.com",
                "port": None,
                "is_disabled": False,
                "security": "inbound_default",
            }
        ]
    }
    return nodes, hosts, inbounds


class V120AAssetDiscoveryTests(unittest.TestCase):
    def test_discovers_main_nodes_and_public_hosts(self):
        nodes, hosts, inbounds = sample_payloads()
        snapshot = discovery.discover_assets(
            "https://gate.nvlsup.xyz:2053",
            nodes,
            hosts,
            inbounds,
            resolver=fake_resolver,
            observed_at="2026-10-03T20:00:00Z",
        )

        self.assertEqual(len(snapshot.assets), 3)
        by_type = {asset.asset_type: asset for asset in snapshot.assets}

        main = by_type[discovery.ASSET_MAIN]
        self.assertEqual(main.address, "gate.nvlsup.xyz")
        self.assertEqual(main.port, 2053)
        self.assertEqual(main.resolved_ips, ("144.172.115.27",))

        node = by_type[discovery.ASSET_NODE]
        self.assertEqual(node.asset_key, "MARZBAN_NODE:7")
        self.assertEqual(node.port, 62050)
        self.assertEqual(node.metadata["api_port"], 62051)
        self.assertEqual(node.metadata["status"], "connected")

        host = by_type[discovery.ASSET_PUBLIC_HOST]
        self.assertEqual(
            host.asset_key,
            "MARZBAN_PUBLIC_HOST:VLESS TCP REALITY:0",
        )
        self.assertEqual(host.port, 8443)
        self.assertEqual(host.metadata["port_source"], "inbound")

    def test_explicit_public_host_port_wins_over_inbound_port(self):
        nodes, hosts, inbounds = sample_payloads()
        hosts["VLESS TCP REALITY"][0]["port"] = 443
        snapshot = discovery.discover_assets(
            "https://gate.nvlsup.xyz:2053",
            nodes,
            hosts,
            inbounds,
            resolver=fake_resolver,
        )
        host = next(
            a for a in snapshot.assets
            if a.asset_type == discovery.ASSET_PUBLIC_HOST
        )
        self.assertEqual(host.port, 443)
        self.assertEqual(host.metadata["port_source"], "host")

    def test_disabled_public_host_remains_in_inventory(self):
        nodes, hosts, inbounds = sample_payloads()
        hosts["VLESS TCP REALITY"][0]["is_disabled"] = True
        snapshot = discovery.discover_assets(
            "https://gate.nvlsup.xyz:2053",
            nodes,
            hosts,
            inbounds,
            resolver=fake_resolver,
        )
        host = next(
            a for a in snapshot.assets
            if a.asset_type == discovery.ASSET_PUBLIC_HOST
        )
        self.assertIs(host.metadata["is_disabled"], True)

    def test_dns_failure_does_not_drop_logical_asset(self):
        nodes, hosts, inbounds = sample_payloads()
        nodes[0]["address"] = "missing.example.com"
        snapshot = discovery.discover_assets(
            "https://gate.nvlsup.xyz:2053",
            nodes,
            hosts,
            inbounds,
            resolver=fake_resolver,
        )
        node = next(
            a for a in snapshot.assets if a.asset_type == discovery.ASSET_NODE
        )
        self.assertEqual(node.resolved_ips, ())
        self.assertIn("resolution_error", node.metadata)

    def test_invalid_authoritative_payload_fails_closed(self):
        _nodes, hosts, inbounds = sample_payloads()
        with self.assertRaises(discovery.AssetDiscoveryError):
            discovery.discover_assets(
                "https://gate.nvlsup.xyz:2053",
                {"unexpected": []},
                hosts,
                inbounds,
                resolver=fake_resolver,
            )

    def test_endpoint_projection_deduplicates_same_ip_and_port(self):
        nodes, hosts, inbounds = sample_payloads()
        nodes[0]["port"] = 8443
        snapshot = discovery.discover_assets(
            "https://gate.nvlsup.xyz:2053",
            nodes,
            hosts,
            inbounds,
            resolver=fake_resolver,
        )
        endpoints = discovery.deduplicated_endpoints(snapshot.assets)
        shared = [
            endpoint
            for endpoint in endpoints
            if endpoint.host == "203.0.113.10" and endpoint.port == 8443
        ]
        self.assertEqual(len(shared), 1)
        self.assertEqual(len(shared[0].asset_keys), 2)


class V120AInventoryPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        discovery.install_schema(self.conn)

    def tearDown(self):
        self.conn.close()

    def _snapshot(self):
        nodes, hosts, inbounds = sample_payloads()
        return discovery.discover_assets(
            "https://gate.nvlsup.xyz:2053",
            nodes,
            hosts,
            inbounds,
            resolver=fake_resolver,
            observed_at="2026-10-03T20:00:00Z",
        )

    def test_first_snapshot_adds_all_assets(self):
        snapshot = self._snapshot()
        diff = discovery.sync_inventory(
            self.conn,
            snapshot.assets,
            observed_at=snapshot.observed_at,
        )
        self.assertEqual(len(diff.added), 3)
        self.assertEqual(diff.changed, ())
        self.assertEqual(diff.removed, ())
        self.assertEqual(len(discovery.list_active_assets(self.conn)), 3)

    def test_node_address_change_is_changed_not_remove_add(self):
        first = self._snapshot()
        discovery.sync_inventory(
            self.conn,
            first.assets,
            observed_at=first.observed_at,
        )

        nodes, hosts, inbounds = sample_payloads()
        nodes[0]["address"] = "second.example.com"
        second = discovery.discover_assets(
            "https://gate.nvlsup.xyz:2053",
            nodes,
            hosts,
            inbounds,
            resolver=fake_resolver,
            observed_at="2026-10-03T20:05:00Z",
        )
        diff = discovery.sync_inventory(
            self.conn,
            second.assets,
            observed_at=second.observed_at,
        )
        self.assertIn("MARZBAN_NODE:7", diff.changed)
        self.assertNotIn("MARZBAN_NODE:7", diff.added)
        self.assertNotIn("MARZBAN_NODE:7", diff.removed)

    def test_missing_asset_is_soft_retired(self):
        first = self._snapshot()
        discovery.sync_inventory(self.conn, first.assets)
        remaining = tuple(
            asset
            for asset in first.assets
            if asset.asset_type != discovery.ASSET_PUBLIC_HOST
        )
        diff = discovery.sync_inventory(
            self.conn,
            remaining,
            observed_at="2026-10-03T20:05:00Z",
        )
        self.assertEqual(
            diff.removed,
            ("MARZBAN_PUBLIC_HOST:VLESS TCP REALITY:0",),
        )
        self.assertEqual(len(discovery.list_active_assets(self.conn)), 2)

    def test_reappearing_asset_is_reported_as_added(self):
        first = self._snapshot()
        discovery.sync_inventory(self.conn, first.assets)
        remaining = tuple(
            asset
            for asset in first.assets
            if asset.asset_type != discovery.ASSET_PUBLIC_HOST
        )
        discovery.sync_inventory(self.conn, remaining)
        diff = discovery.sync_inventory(self.conn, first.assets)
        self.assertIn(
            "MARZBAN_PUBLIC_HOST:VLESS TCP REALITY:0",
            diff.added,
        )


class FakeMarzbanService:
    configured = True
    url = "https://gate.nvlsup.xyz:2053"

    def __init__(self, fail_hosts=False):
        self.fail_hosts = fail_hosts
        self.calls = []

    async def get_nodes(self):
        self.calls.append("get_nodes")
        return True, sample_payloads()[0]

    async def get_hosts(self):
        self.calls.append("get_hosts")
        if self.fail_hosts:
            return False, "temporary api error"
        return True, sample_payloads()[1]

    async def get_inbounds(self):
        self.calls.append("get_inbounds")
        return True, sample_payloads()[2]

    async def modify_node(self, *args, **kwargs):
        raise AssertionError("V120-A must never mutate nodes")

    async def update_host(self, *args, **kwargs):
        raise AssertionError("V120-A must never mutate hosts")


class V120AReadOnlyServiceTests(unittest.IsolatedAsyncioTestCase):
    async def test_service_discovery_uses_read_only_calls(self):
        service = FakeMarzbanService()
        snapshot = await discovery.discover_from_service(
            service,
            resolver=fake_resolver,
        )
        self.assertEqual(
            service.calls,
            ["get_nodes", "get_hosts", "get_inbounds"],
        )
        self.assertEqual(len(snapshot.assets), 3)

    async def test_partial_api_failure_raises_before_inventory_sync(self):
        conn = sqlite3.connect(":memory:")
        discovery.install_schema(conn)
        nodes, hosts, inbounds = sample_payloads()
        seed = discovery.discover_assets(
            FakeMarzbanService.url,
            nodes,
            hosts,
            inbounds,
            resolver=fake_resolver,
        )
        discovery.sync_inventory(conn, seed.assets)
        before = conn.execute(
            "SELECT COUNT(*) FROM marzban_assets WHERE active=1"
        ).fetchone()[0]

        with self.assertRaises(discovery.AssetDiscoveryError):
            await discovery.discover_from_service(
                FakeMarzbanService(fail_hosts=True),
                resolver=fake_resolver,
            )

        after = conn.execute(
            "SELECT COUNT(*) FROM marzban_assets WHERE active=1"
        ).fetchone()[0]
        self.assertEqual(before, after)
        conn.close()


class V120ARuntimeShapeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bot = BOT_PATH.read_text(encoding="utf-8")
        cls.module = MODULE_PATH.read_text(encoding="utf-8")

    def test_runtime_installs_inventory_schema(self):
        self.assertIn(
            "marzban_asset_discovery.install_schema(conn)",
            self.bot,
        )

    def test_runtime_has_discovery_task_lifecycle(self):
        init_start = self.bot.index("async def _post_init(app):")
        shutdown_start = self.bot.index(
            "async def _post_shutdown(app):",
            init_start,
        )
        main_start = self.bot.index(
            "if __name__ == '__main__':",
            shutdown_start,
        )
        self.assertIn(
            "marzban_asset_discovery_task",
            self.bot[init_start:shutdown_start],
        )
        self.assertIn(
            "marzban_asset_discovery_task",
            self.bot[shutdown_start:main_start],
        )

    def test_v120a_module_has_no_mutation_or_failover_paths(self):
        for forbidden in (
            "modify_node(",
            "update_host(",
            "set_node_enabled(",
            "reconnect_node(",
            "failover",
            "cloudflare",
            "regional_filtering",
        ):
            self.assertNotIn(forbidden, self.module.lower())

    def test_discovery_defaults_to_five_minutes(self):
        self.assertIn(
            'NVL_MARZBAN_ASSET_DISCOVERY_INTERVAL", 300',
            self.bot,
        )


if __name__ == "__main__":
    unittest.main()
