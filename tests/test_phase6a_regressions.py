import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
BOT_PATH = ROOT / "bot_final_v49-2.py"


class Phase6APortHealthSeparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")
        cls.failover = (ROOT / "core_side_failover.sh").read_text(encoding="utf-8")
        cls.sync_edges = (ROOT / "sync_bot_to_edges.sh").read_text(encoding="utf-8")
        cls.update_edges = (ROOT / "update_all_edges_endpoint.sh").read_text(encoding="utf-8")
        cls.relay = (ROOT / "setup_edge_relay.sh").read_text(encoding="utf-8")

    def test_phase6a_features_survive_current_version(self):
        self.assertIn("BOT_VERSION_TAG =", self.source)
        self.assertIn("admin_ssh_port", self.source)
        self.assertIn("service_port", self.source)
        self.assertIn("def _db_record_admin_host_check", self.source)

    def test_host_pool_has_explicit_service_and_admin_fields(self):
        for column in (
            "service_port",
            "admin_ssh_port",
            "admin_consecutive_fails",
            "admin_last_check",
            "admin_last_status",
            "service_last_check",
            "service_last_status",
        ):
            self.assertIn(
                f"ALTER TABLE host_pool ADD COLUMN {column}",
                self.source,
            )

    def test_migration_separates_legacy_port_semantics(self):
        self.assertIn("_legacy_service_port", self.source)
        self.assertIn("_legacy_ssh == _legacy_service_port", self.source)
        self.assertIn("_admin_port = 22", self.source)
        self.assertIn(
            "UPDATE host_pool SET admin_ssh_port=? WHERE host=?",
            self.source,
        )

    def test_explicit_port_helpers_exist(self):
        for helper in (
            "def _db_get_host_service_port(",
            "def _db_get_host_service_port_map(",
            "def _db_set_host_service_port(",
            "def _db_get_host_admin_ssh_port(",
            "def _db_get_host_admin_ssh_port_map(",
            "def _db_set_host_admin_ssh_port(",
        ):
            self.assertIn(helper, self.source)

    def test_legacy_ambiguous_helpers_have_no_live_callsites(self):
        self.assertEqual(self.source.count("_db_get_host_ssh_port("), 1)
        self.assertEqual(self.source.count("_db_get_host_ssh_port_map("), 1)
        self.assertEqual(self.source.count("_db_set_host_ssh_port("), 1)

    def test_customer_output_uses_service_port(self):
        self.assertIn(
            "_db_get_host_service_port, dns_target.strip() or host, port",
            self.source,
        )
        self.assertIn(
            "_db_get_host_service_port, dns_target.strip() or primary_host, prt",
            self.source,
        )

    def test_management_paths_use_admin_port(self):
        for fragment in (
            "_db_get_host_admin_ssh_port, host, 22",
            "_db_get_host_admin_ssh_port, target_ip, 22",
            "_db_get_host_admin_ssh_port, ip, 22",
            "_db_get_host_admin_ssh_port, target_host, 22",
            "_db_get_host_admin_ssh_port_map",
        ):
            self.assertIn(fragment, self.source)

    def test_admin_port_change_does_not_mutate_customer_service_port(self):
        start = self.source.index("elif state == 'SSH_PORT_ROOT_PASSWORD':")
        end = self.source.index("elif state == 'PORT_INPUT':", start)
        region = self.source[start:end]
        self.assertIn("_db_set_host_admin_ssh_port", region)
        self.assertNotIn("_db_update_setting, 'port'", region)
        self.assertNotIn("_db_set_host_service_port", region)
        self.assertIn("پورت سرویس مشتری تغییر نکرده است", region)

    def test_service_and_admin_health_are_independent(self):
        start = self.source.index("async def _host_health_tick(app):")
        end = self.source.index("async def _host_health_loop(app):", start)
        region = self.source[start:end]
        self.assertIn("_db_get_host_service_port_map", region)
        self.assertIn("_db_get_host_admin_ssh_port_map", region)
        self.assertIn("_tcp_health_check(host, service_port)", region)
        self.assertIn("_check_ssh_reachable(host, admin_port)", region)
        self.assertIn("_db_record_host_check", region)
        self.assertIn("_db_record_admin_host_check", region)
        self.assertIn("if service_ok or new_fails < HOST_HEALTH_FAIL_THRESHOLD:", region)
        self.assertNotIn("_db_set_host_active", region)
        self.assertIn("_notify_admins", region)
        self.assertNotIn("admin_fails < HOST_HEALTH_FAIL_THRESHOLD", region)

    def test_manual_reactivation_requires_service_health_not_admin_health(self):
        start = self.source.index('elif d.startswith("hpact_")')
        end = self.source.index('elif d.startswith("hpdelconfirm_")', start)
        region = self.source[start:end]
        self.assertIn("_db_get_host_service_port", region)
        self.assertIn("_db_get_host_admin_ssh_port", region)
        self.assertIn("if service_ok:", region)
        self.assertIn("_db_set_host_active, host, True", region)
        self.assertIn("_db_record_admin_host_check", region)

    def test_failover_management_probe_never_tries_customer_port(self):
        start = self.failover.index('echo "🔹 ۲)')
        end = self.failover.index('echo "🔹 ۳)', start)
        region = self.failover[start:end]
        self.assertIn("admin_ssh_port", region)
        self.assertNotIn("DEFAULT_CUSTOMER_PORT", region)
        self.assertNotIn('for p in 22 "$DEFAULT_CUSTOMER_PORT"', region)
        self.assertNotIn('for p in 22 "$DEFAULT_CUSTOMER_PORT" "$CUSTOMER_SSH_PORT"', region)

    def test_sync_management_probe_never_tries_customer_port(self):
        self.assertIn("admin_ssh_port", self.sync_edges)
        self.assertNotIn("DEFAULT_CUSTOMER_PORT", self.sync_edges)
        self.assertIn("local p=\"22\"", self.sync_edges)

    def test_endpoint_update_management_probe_never_tries_customer_port(self):
        self.assertIn("admin_ssh_port", self.update_edges)
        self.assertNotIn("DEFAULT_CUSTOMER_PORT", self.update_edges)
        self.assertIn("local p=\"22\"", self.update_edges)

    def test_active_relay_topology_remains_explicit(self):
        self.assertIn("CUSTOMER_SSH_PORT", self.relay)
        self.assertIn("DNAT", self.relay)
        self.assertIn("Match LocalPort 22", self.relay)


if __name__ == "__main__":
    unittest.main()
