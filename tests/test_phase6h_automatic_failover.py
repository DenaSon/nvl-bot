import pathlib
import unittest

from automatic_failover import (
    AUTO_FAILOVER_REASON_ATTEMPT_COOLDOWN,
    AUTO_FAILOVER_REASON_CONFIDENCE_NOT_HIGH,
    AUTO_FAILOVER_REASON_DISABLED,
    AUTO_FAILOVER_REASON_NO_STANDBY,
    AUTO_FAILOVER_REASON_PROVIDER_NOT_OK,
    AUTO_FAILOVER_REASON_READY,
    AUTO_FAILOVER_REASON_SWITCH_COOLDOWN,
    evaluate_auto_failover,
    is_safe_standby_evidence,
    rank_safe_standbys,
)
from safe_failover import FAILOVER_MODE_AUTO


ROOT = pathlib.Path(__file__).resolve().parents[1]
BOT_PATH = ROOT / "bot_final_v49-2.py"


def ready_kwargs():
    return dict(
        enabled=True,
        source_is_default=True,
        source_is_standby=False,
        filter_state="LIKELY",
        filter_confidence="HIGH",
        diagnostic_reason="FILTER_SUSPECTED",
        failure_streak=3,
        confirm_threshold=3,
        provider_status="OK",
        seconds_since_last_switch=float("inf"),
        switch_cooldown_seconds=1800,
        seconds_since_last_attempt=float("inf"),
        attempt_cooldown_seconds=900,
        safe_standby_count=1,
    )


class Phase6HPolicyTests(unittest.TestCase):
    def test_ready_requires_all_high_confidence_gates(self):
        decision = evaluate_auto_failover(**ready_kwargs())
        self.assertTrue(decision.eligible)
        self.assertEqual(decision.reason, AUTO_FAILOVER_REASON_READY)

    def test_auto_is_opt_in(self):
        kwargs = ready_kwargs()
        kwargs["enabled"] = False
        decision = evaluate_auto_failover(**kwargs)
        self.assertFalse(decision.eligible)
        self.assertEqual(decision.reason, AUTO_FAILOVER_REASON_DISABLED)

    def test_medium_confidence_cannot_trigger(self):
        kwargs = ready_kwargs()
        kwargs["filter_confidence"] = "MEDIUM"
        decision = evaluate_auto_failover(**kwargs)
        self.assertFalse(decision.eligible)
        self.assertEqual(decision.reason, AUTO_FAILOVER_REASON_CONFIDENCE_NOT_HIGH)

    def test_provider_must_be_healthy(self):
        kwargs = ready_kwargs()
        kwargs["provider_status"] = "LIMITED"
        decision = evaluate_auto_failover(**kwargs)
        self.assertFalse(decision.eligible)
        self.assertEqual(decision.reason, AUTO_FAILOVER_REASON_PROVIDER_NOT_OK)

    def test_switch_cooldown_blocks_flapping(self):
        kwargs = ready_kwargs()
        kwargs["seconds_since_last_switch"] = 120
        decision = evaluate_auto_failover(**kwargs)
        self.assertFalse(decision.eligible)
        self.assertEqual(decision.reason, AUTO_FAILOVER_REASON_SWITCH_COOLDOWN)

    def test_attempt_cooldown_blocks_repeated_failed_attempts(self):
        kwargs = ready_kwargs()
        kwargs["seconds_since_last_attempt"] = 120
        decision = evaluate_auto_failover(**kwargs)
        self.assertFalse(decision.eligible)
        self.assertEqual(decision.reason, AUTO_FAILOVER_REASON_ATTEMPT_COOLDOWN)

    def test_safe_standby_is_required(self):
        kwargs = ready_kwargs()
        kwargs["safe_standby_count"] = 0
        decision = evaluate_auto_failover(**kwargs)
        self.assertFalse(decision.eligible)
        self.assertEqual(decision.reason, AUTO_FAILOVER_REASON_NO_STANDBY)

    def test_standby_requires_clear_and_all_control_paths(self):
        good = {
            "filter_state": "CLEAR",
            "service_ok": True,
            "admin_ok": True,
            "wg_peer_ok": True,
            "core_path_ok": True,
            "external_service_ok": True,
        }
        self.assertTrue(is_safe_standby_evidence(good))

        for key in (
            "service_ok",
            "admin_ok",
            "wg_peer_ok",
            "core_path_ok",
            "external_service_ok",
        ):
            bad = dict(good)
            bad[key] = None
            self.assertFalse(is_safe_standby_evidence(bad), key)

        unknown = dict(good)
        unknown["filter_state"] = "UNKNOWN"
        self.assertFalse(is_safe_standby_evidence(unknown))

    def test_rank_safe_standbys_prefers_lower_latency_and_rejects_unsafe(self):
        base = {
            "filter_state": "CLEAR",
            "service_ok": True,
            "admin_ok": True,
            "wg_peer_ok": True,
            "core_path_ok": True,
            "external_service_ok": True,
        }
        health = {
            "10.0.0.2": {**base, "avg_latency_ms": 50},
            "10.0.0.3": {**base, "avg_latency_ms": 20},
            "10.0.0.4": {**base, "filter_state": "POSSIBLE", "avg_latency_ms": 1},
        }
        self.assertEqual(
            rank_safe_standbys(["10.0.0.2", "10.0.0.3", "10.0.0.4"], health),
            ("10.0.0.3", "10.0.0.2"),
        )

    def test_auto_operation_mode_is_distinct(self):
        self.assertEqual(FAILOVER_MODE_AUTO, "AUTO")


class Phase6HIntegrationShapeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")

    def _region(self, start, end):
        a = self.source.index(start)
        b = self.source.index(end, a)
        return self.source[a:b]

    def test_settings_has_direct_filtering_entry(self):
        settings = self._region(
            "def _build_server_settings_kb():",
            "def _normalize_ssh_port",
        )
        self.assertIn(
            'InlineKeyboardButton("🛡 وضعیت فیلترینگ", callback_data="hp_filtering")',
            settings,
        )

    def test_monitor_exposes_explicit_auto_opt_in(self):
        region = self._region(
            "async def _render_filtering_monitor_panel",
            "async def _render_filtering_edge_detail",
        )
        self.assertIn("Filtering Monitor — Phase 6H", region)
        self.assertIn("flt_auto_enable", region)
        self.assertIn("flt_auto_disable", region)
        self.assertIn("LIKELY + HIGH", region)

    def test_admin_confirmation_is_required_to_enable_auto(self):
        region = self._region(
            'elif d == "hp_filtering"',
            'elif d.startswith("flt_page_")',
        )
        self.assertIn('d == "flt_auto_enable"', region)
        self.assertIn('callback_data="flt_auto_enable_yes"', region)
        self.assertIn("_db_update_setting, 'auto_failover_mode', '1'", region)
        self.assertIn("_db_update_setting, 'auto_failover_mode', '0'", region)

    def test_scheduled_round_calls_6h_only_after_provider_success(self):
        region = self._region(
            "async def _regional_filter_tick(app):",
            "async def _regional_filter_probe_one_now",
        )
        provider_pos = region.index("await _regional_provider_mark_ok(app)")
        auto_pos = region.index("await _phase6h_auto_failover_tick(app)")
        self.assertLess(provider_pos, auto_pos)
        self.assertIn("if round_provider_ok:", region)

    def test_6h_uses_phase6g_engine_and_auto_mode(self):
        region = self._region(
            "async def _phase6h_auto_failover_tick(app):",
            "async def _regional_filter_tick(app):",
        )
        self.assertIn("evaluate_auto_failover(", region)
        self.assertIn("rank_safe_standbys(", region)
        self.assertIn("_db_mark_auto_failover_attempt_now", region)
        self.assertIn("_safe_manual_failover(", region)
        self.assertIn("mode=FAILOVER_MODE_AUTO", region)

    def test_shared_engine_persists_requested_mode(self):
        region = self._region(
            "async def _safe_manual_failover(",
            "async def _activate_standby_for_filtered_edge",
        )
        self.assertIn("mode=FAILOVER_MODE_MANUAL", region)
        self.assertIn("mode=mode", region)
        self.assertIn('_db_acquire_failover_lock', region)
        self.assertIn("target_route_active", region)
        self.assertIn("_db_rollback_failover_account_state", region)

    def test_legacy_traffic_anomaly_cannot_trigger_6h(self):
        region = self._region(
            "async def _filter_detect_tick(app):",
            "async def _filter_detect_loop(app):",
        )
        self.assertNotIn("_phase6h_auto_failover_tick", region)
        self.assertNotIn("_safe_manual_failover", region)

    def test_auto_default_remains_off_and_startup_does_not_force_state(self):
        self.assertIn("('auto_failover_mode', '0')", self.source)
        post_init = self._region(
            "async def _post_init(app):",
            "async def _post_shutdown(app):",
        )
        self.assertNotIn("_db_update_setting, 'auto_failover_mode', '0'", post_init)


if __name__ == "__main__":
    unittest.main()
