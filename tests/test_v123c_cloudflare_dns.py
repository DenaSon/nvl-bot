import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
BOT = ROOT / "bot_final_v49-2.py"
ENV = ROOT / ".env.example"


class V123CSourceRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT.read_text(encoding="utf-8")
        cls.env = ENV.read_text(encoding="utf-8")

    def _region(self, start, end):
        a = self.source.index(start)
        b = self.source.index(end, a)
        return self.source[a:b]

    def test_runtime_marker_and_cloudflare_module_are_wired(self):
        self.assertIn(
            'BOT_VERSION_TAG = "V124-2026-10-07-critical-only-regional-notifications"',
            self.source,
        )
        self.assertIn("import cloudflare_dns", self.source)
        self.assertIn("def _mza_cloudflare_dns_client", self.source)
        self.assertIn("NVL_CLOUDFLARE_API_TOKEN", self.env)
        self.assertIn("NVL_CLOUDFLARE_ZONE_ID", self.env)

    def test_move_preview_locks_provider_record_before_cutover(self):
        region = self._region(
            "elif d.startswith('mza_nmove_cutover_'):",
            "elif d.startswith('mza_nmove_confirm_'):",
        )
        self.assertIn("cf_client.inspect_a_record", region)
        self.assertIn('"cf_record_id"', region)
        self.assertIn('"cf_fingerprint"', region)
        self.assertIn("Cloudflare  <b>✅ A record verified</b>", region)
        self.assertIn("resolve_single_ipv4", region)

    def test_move_confirm_rechecks_cloudflare_before_pending_and_remote_move(self):
        region = self._region(
            "elif d.startswith('mza_nmove_confirm_'):",
            "elif d.startswith('mza_nmove_finalize_'):",
        )
        cf_recheck = region.index("cf_client.inspect_a_record")
        pending = region.index("_db_upsert_marzban_node_public_profile")
        move = region.index("service.move_node_public_profile(")
        switch = region.index("cf_client.switch_a_record")
        self.assertLess(cf_recheck, pending)
        self.assertLess(pending, move)
        self.assertLess(move, switch)
        self.assertIn("_mza_rollback_node_move_to_old", region)
        self.assertIn("Cloudflare update شکست خورد", region)

    def test_move_no_longer_requires_manual_dns_change(self):
        region = self._region(
            "elif d.startswith('mza_nmove_confirm_'):",
            "elif d.startswith('mza_nedit_name_'):",
        )
        self.assertNotIn("حالا DNS Public Endpoint را به IP مقصد جدید تغییر دهید", region)
        self.assertNotIn("DNS را تغییر دادم", region)
        self.assertIn("DNS را دستی تغییر ندهید", region)
        self.assertIn("Automated Safe Node Move", region)

    def test_finalize_is_provider_aware_and_safe_retry_is_stale_guarded(self):
        region = self._region(
            "elif d.startswith('mza_nmove_finalize_'):",
            "elif d.startswith('mza_nedit_name_'):",
        )
        inspect = region.index("cf_client.inspect_a_record")
        retry = region.index("cf_client.switch_a_record")
        mapping = region.index("_db_upsert_marzban_node_public_profile")
        self.assertLess(inspect, retry)
        self.assertLess(retry, mapping)
        self.assertIn("expected_fingerprint=cf_now.get", region)
        self.assertIn("provider_ok", region)
        self.assertIn("resolver propagation", region)

    def test_create_public_endpoint_allows_missing_record_but_never_overwrites_existing(self):
        region = self._region(
            "if state == 'MZA_NODE_CREATE_PUBLIC_INPUT':",
            "if state == 'MZA_NODE_CREATE_PORTS_INPUT':",
        )
        self.assertIn("cf_client.inspect_a_record", region)
        self.assertIn('cf_mode = "create"', region)
        self.assertIn('cf_mode = "existing"', region)
        self.assertIn("implicit overwrite", region)
        self.assertNotIn("create_a_record", region)

    def test_create_confirm_checks_duplicate_before_cloudflare_create_and_node_post(self):
        region = self._region(
            "elif d.startswith('mza_ncreate_confirm_'):",
            "elif d == 'mza_nodes':",
        )
        duplicate = region.index("find_duplicate_node")
        dns_create = region.index("cf_client.create_a_record")
        resolver = region.index("preflight_public_endpoint")
        node_post = region.index("service.create_node(")
        self.assertLess(duplicate, dns_create)
        self.assertLess(dns_create, resolver)
        self.assertLess(resolver, node_post)
        self.assertIn("provider_ready", region)
        self.assertIn("Node POST اجرا نشد", region)


if __name__ == "__main__":
    unittest.main()
