import pathlib
import unittest
from datetime import datetime

from filtering_runtime import (
    PROVIDER_STATUS_LIMITED,
    TRANSITION_CRITICAL,
    TRANSITION_DEGRADED,
    TRANSITION_NONE,
    TRANSITION_RECOVERED,
    TRANSITION_WARNING,
    classify_filter_transition,
    provider_backoff_seconds,
    provider_backoff_until,
)
from regional_filtering import (
    REGIONAL_STATE_CLEAR,
    REGIONAL_STATE_LIKELY,
    REGIONAL_STATE_POSSIBLE,
    REGIONAL_STATE_UNKNOWN,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]
BOT_PATH = ROOT / "bot_final_v49-2.py"


class Phase6FRuntimePolicyTests(unittest.TestCase):
    def test_transition_clear_to_possible_is_warning(self):
        t = classify_filter_transition(REGIONAL_STATE_CLEAR, REGIONAL_STATE_POSSIBLE)
        self.assertEqual(t.kind, TRANSITION_WARNING)
        self.assertTrue(t.notify)

    def test_transition_possible_to_likely_is_critical(self):
        t = classify_filter_transition(REGIONAL_STATE_POSSIBLE, REGIONAL_STATE_LIKELY)
        self.assertEqual(t.kind, TRANSITION_CRITICAL)

    def test_transition_likely_to_clear_is_recovered(self):
        t = classify_filter_transition(REGIONAL_STATE_LIKELY, REGIONAL_STATE_CLEAR)
        self.assertEqual(t.kind, TRANSITION_RECOVERED)

    def test_transition_likely_to_unknown_is_degraded_not_recovered(self):
        t = classify_filter_transition(REGIONAL_STATE_LIKELY, REGIONAL_STATE_UNKNOWN)
        self.assertEqual(t.kind, TRANSITION_DEGRADED)

    def test_initial_population_is_quiet(self):
        t = classify_filter_transition(None, REGIONAL_STATE_CLEAR)
        self.assertEqual(t.kind, TRANSITION_NONE)
        self.assertFalse(t.notify)

    def test_same_state_is_quiet(self):
        t = classify_filter_transition(REGIONAL_STATE_POSSIBLE, REGIONAL_STATE_POSSIBLE)
        self.assertEqual(t.kind, TRANSITION_NONE)

    def test_provider_backoff_is_exponential_and_capped(self):
        self.assertEqual(provider_backoff_seconds(1, base_seconds=300, max_seconds=3600), 300)
        self.assertEqual(provider_backoff_seconds(2, base_seconds=300, max_seconds=3600), 600)
        self.assertEqual(provider_backoff_seconds(3, base_seconds=300, max_seconds=3600), 1200)
        self.assertEqual(provider_backoff_seconds(4, base_seconds=300, max_seconds=3600), 2400)
        self.assertEqual(provider_backoff_seconds(5, base_seconds=300, max_seconds=3600), 3600)
        self.assertEqual(provider_backoff_seconds(10, base_seconds=300, max_seconds=3600), 3600)

    def test_provider_backoff_until_uses_same_policy(self):
        now = datetime(2026, 10, 3, 0, 0, 0)
        until = provider_backoff_until(now, 2, base_seconds=300, max_seconds=3600)
        self.assertEqual((until - now).total_seconds(), 600)


class Phase6FBotIntegrationStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")

    def _region(self, start_marker, end_marker):
        start = self.source.index(start_marker)
        end = self.source.index(end_marker, start)
        return self.source[start:end]

    def test_phase6f_schema_is_additive(self):
        for column in (
            "filter_state",
            "regional_filter_state",
            "regional_filter_reason",
            "regional_total_nodes",
            "regional_completed_nodes",
            "regional_successful_nodes",
            "regional_failed_nodes",
            "regional_pending_nodes",
            "regional_success_ratio",
            "regional_failed_asns",
            "regional_failed_cities",
            "regional_last_request_id",
            "regional_provider_status",
            "regional_provider_error",
            "regional_state_updated_at",
        ):
            self.assertIn(f"ADD COLUMN {column}", self.source)

    def test_phase6e_state_is_fed_into_observability_runtime(self):
        region = self._region(
            "def _db_recompute_host_observability(",
            "def _db_record_observability_probe(",
        )
        self.assertIn("regional_filter_state=regional_filter_state", region)
        self.assertIn('"filter_state"', region)
        self.assertIn("filter_state=?", region)

    def test_regional_round_is_aggregated_before_persistence(self):
        region = self._region(
            "def _db_record_regional_round(",
            "def _db_record_regional_provider_status(",
        )
        self.assertIn("regional_decision.summary", region)
        self.assertIn("regional_filter_state=?", region)
        self.assertIn("'regional_node'", region)
        self.assertIn("'regional_service'", region)

    def test_only_consecutive_likely_rounds_build_confirmation_streak(self):
        region = self._region(
            "def _db_record_regional_round(",
            "def _db_record_regional_provider_status(",
        )
        self.assertIn(
            "elif regional_decision.state == FILTER_STATE_LIKELY",
            region,
        )
        self.assertIn(
            "POSSIBLE/UNKNOWN break a LIKELY streak",
            region,
        )
        self.assertIn(
            '"filter_consecutive_failures=0, "',
            region,
        )

    def test_provider_limit_never_becomes_edge_failure(self):
        region = self._region(
            "async def _regional_provider_enter_limited(",
            "async def _regional_provider_mark_ok(",
        )
        self.assertIn("PROVIDER_STATUS_LIMITED", region)
        self.assertNotIn("_db_record_regional_round", region)
        self.assertNotIn("regional_service_ok=0", region)

    def test_provider_limit_streak_resets_only_after_full_scheduled_round(self):
        probe_region = self._region(
            "async def _regional_filter_probe_edge(",
            "async def _regional_filter_tick(app):",
        )
        self.assertNotIn("_regional_provider_mark_ok", probe_region)

        tick_region = self._region(
            "async def _regional_filter_tick(app):",
            "async def _regional_filter_probe_one_now",
        )
        self.assertIn("round_provider_ok = True", tick_region)
        self.assertIn("if round_provider_ok:", tick_region)
        self.assertIn("await _regional_provider_mark_ok(app)", tick_region)

    def test_runtime_targets_exclude_core_before_provider_check(self):
        region = self._region(
            "async def _regional_filter_tick(app):",
            "async def _regional_filter_probe_one_now",
        )
        self.assertIn("_is_current_core_host", region)
        self.assertIn("client.discover_nodes", region)
        self.assertIn("REGIONAL_FILTER_EDGE_GAP_SECONDS", region)

    def test_phase6f_probe_runtime_has_no_failover_side_effects(self):
        region = self._region(
            "async def _regional_filter_probe_edge(",
            "async def _regional_filter_tick(app):",
        )
        for forbidden in (
            "_db_set_default_host",
            "_db_set_all_accounts_host",
            "_update_cloudflare_dns",
            "_cf_switch_public_domain",
            "_activate_standby_for_filtered_edge",
            "_db_set_host_active",
            "promote_edge_to_core",
            "demote_core_to_edge",
        ):
            self.assertNotIn(forbidden, region)

    def test_legacy_v89_tick_is_signal_only(self):
        region = self._region(
            "async def _filter_detect_tick(app):",
            "async def _filter_detect_loop(app):",
        )
        self.assertIn("Traffic Anomaly Signal", region)
        for forbidden in (
            "_db_set_default_host",
            "_db_set_all_accounts_host",
            "_update_cloudflare_dns",
            "_cf_switch_public_domain",
            "_activate_standby_for_filtered_edge",
            "_db_mark_ip_switch_now",
        ):
            self.assertNotIn(forbidden, region)

    def test_phase6h_preserves_explicit_auto_setting_but_legacy_signal_stays_passive(self):
        region = self._region(
            "async def _post_init(app):",
            "async def _post_shutdown(app):",
        )
        self.assertIn("'phase6h_auto_failover_enabled', '0'", region)
        self.assertNotIn("_db_update_setting, 'phase6h_auto_failover_enabled', '0'", region)
        self.assertIn("regional_filter_task", region)

        legacy = self._region(
            "async def _filter_detect_tick(app):",
            "async def _filter_detect_loop(app):",
        )
        self.assertNotIn("_safe_manual_failover", legacy)
        self.assertNotIn("_phase6h_auto_failover_tick", legacy)

    def test_phase6f_task_is_cancelled_cleanly(self):
        region = self._region(
            "async def _post_shutdown(app):",
            "if __name__ == '__main__':",
        )
        self.assertIn("regional_filter_task", region)

    def test_filtering_monitor_ui_exists(self):
        for fragment in (
            "Filtering Monitor",
            'callback_data="hp_filtering"',
            'd == "hp_filtering"',
            'd.startswith("flt_detail_")',
            'd.startswith("flt_check_")',
            'd.startswith("flt_probe_")',
            "Auto Failover",
        ):
            self.assertIn(fragment, self.source)

    def test_legacy_action_callbacks_are_guarded(self):
        region = self._region(
            'elif d == "hp_failover_toggle"',
            'elif d.startswith("hpdns_")',
        )
        self.assertIn("_db_update_setting, 'auto_failover_mode', '0'", region)
        self.assertIn("_db_update_setting, 'phase6h_auto_failover_enabled', '0'", region)
        self.assertIn("Automatic Filtering Failover", region)
        self.assertNotIn("_activate_standby_for_filtered_edge(", region)

    def test_runtime_uses_actual_service_port(self):
        region = self._region(
            "async def _regional_filter_tick(app):",
            "async def _regional_filter_loop(app):",
        )
        self.assertIn("service_port", region)
        self.assertIn("_db_get_host_service_port", region)
        self.assertNotIn("admin_ssh_port", region)


if __name__ == "__main__":
    unittest.main()
