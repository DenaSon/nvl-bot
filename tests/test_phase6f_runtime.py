import pathlib
import unittest
from datetime import datetime

from filtering_runtime import (
    PROVIDER_STATUS_ERROR,
    PROVIDER_STATUS_LIMITED,
    provider_error_alert_due,
    provider_recovery_ready,
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

    def test_provider_error_alert_requires_threshold_and_repeat_window(self):
        self.assertFalse(provider_error_alert_due(1, threshold=3))
        self.assertFalse(provider_error_alert_due(2, threshold=3))
        self.assertTrue(provider_error_alert_due(3, threshold=3))
        self.assertFalse(
            provider_error_alert_due(
                4,
                seconds_since_last_alert=120,
                threshold=3,
                repeat_seconds=1800,
            )
        )
        self.assertTrue(
            provider_error_alert_due(
                4,
                seconds_since_last_alert=1800,
                threshold=3,
                repeat_seconds=1800,
            )
        )

    def test_provider_recovery_requires_two_valid_successes_after_error(self):
        self.assertFalse(
            provider_recovery_ready(PROVIDER_STATUS_ERROR, 1, threshold=2)
        )
        self.assertTrue(
            provider_recovery_ready(PROVIDER_STATUS_ERROR, 2, threshold=2)
        )
        self.assertTrue(provider_recovery_ready("OK", 1, threshold=2))


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

    def test_differential_audit_schema_exists(self):
        self.assertIn(
            "CREATE TABLE IF NOT EXISTS regional_differential_checks",
            self.source,
        )
        self.assertIn(
            "def _db_record_differential_check(",
            self.source,
        )
        self.assertIn(
            "def _db_get_differential_control_candidate(",
            self.source,
        )

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

    def test_unknown_round_preserves_last_valid_regional_evidence_and_streak(self):
        region = self._region(
            "def _db_record_regional_round(",
            "def _db_record_regional_provider_status(",
        )
        self.assertIn(
            "if regional_decision.state == FILTER_STATE_UNKNOWN",
            region,
        )
        self.assertIn(
            "regional_decision.state == FILTER_STATE_UNKNOWN",
            region,
        )
        self.assertIn(
            "regional_state_updated_at is intentionally untouched",
            region,
        )
        self.assertIn(
            "elif regional_decision.state == FILTER_STATE_LIKELY",
            region,
        )

    def test_provider_notifications_are_debounced_and_recovery_is_stable(self):
        region = self._region(
            "async def _regional_provider_enter_error(",
            "def _new_regional_probe_provider",
        )
        self.assertIn("regional_provider_error_streak", region)
        self.assertIn("REGIONAL_PROVIDER_ERROR_ALERT_THRESHOLD", region)
        self.assertIn("provider_error_alert_due", region)
        self.assertIn("regional_provider_success_streak", region)
        self.assertIn("REGIONAL_PROVIDER_RECOVERY_SUCCESS_THRESHOLD", region)
        self.assertIn("provider_recovery_ready", region)

    def test_provider_limit_never_becomes_edge_failure(self):
        region = self._region(
            "async def _regional_provider_enter_limited(",
            "async def _regional_provider_mark_ok(",
        )
        self.assertIn("PROVIDER_STATUS_LIMITED", region)
        self.assertNotIn("_db_record_regional_round", region)
        self.assertNotIn("regional_service_ok=0", region)

    def test_provider_state_resets_after_successful_default_probe(self):
        probe_region = self._region(
            "async def _regional_filter_probe_edge(",
            "async def _phase6h_auto_failover_tick(app, ready_candidate_override=None):",
        )
        self.assertNotIn("_regional_provider_mark_ok", probe_region)

        tick_region = self._region(
            "async def _regional_filter_tick(app):",
            "async def _regional_filter_probe_one_now",
        )
        self.assertIn('await _regional_provider_mark_ok(app, result.get("regional_decision"))', tick_region)
        self.assertNotIn("round_provider_ok", tick_region)

    def test_runtime_targets_default_and_excludes_core_before_provider_check(self):
        target_region = self._region(
            "def _db_get_regional_monitor_targets():",
            "def _db_get_recent_regional_node_results(",
        )
        self.assertIn("active=1 AND is_default=1", target_region)

        region = self._region(
            "async def _regional_filter_tick(app):",
            "async def _regional_filter_probe_one_now",
        )
        self.assertIn("_is_current_core_host", region)
        self.assertIn("provider.discover_nodes", region)
        self.assertNotIn("REGIONAL_FILTER_EDGE_GAP_SECONDS", region)

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
