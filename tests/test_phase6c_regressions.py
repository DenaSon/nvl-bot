import pathlib
import unittest

from edge_observability import (
    DIAG_ADMIN_ONLY_FAILURE,
    DIAG_CORE_LOCAL,
    DIAG_ALL_PATHS_HEALTHY,
    DIAG_CORE_PATH_FAILURE,
    DIAG_EXTERNAL_REACHABILITY_FAILURE,
    DIAG_FILTER_SUSPECTED,
    DIAG_INSUFFICIENT_EVIDENCE,
    DIAG_REGIONAL_REACHABILITY_FAILURE,
    DIAG_SERVICE_PATH_FAILURE,
    DIAG_WIREGUARD_PATH_FAILURE,
    FILTER_CONFIDENCE_HIGH,
    FILTER_CONFIDENCE_LOW,
    FILTER_CONFIDENCE_MEDIUM,
    PROBE_REASON_CONNECTION_REFUSED,
    PROBE_REASON_NETWORK_UNREACHABLE,
    PROBE_REASON_TIMEOUT,
    derive_observability,
    normalize_probe_error,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]
BOT_PATH = ROOT / "bot_final_v49-2.py"


class Phase6CClassifierTests(unittest.TestCase):
    def test_local_paths_healthy_without_regional_evidence(self):
        d = derive_observability(True, True, True, True)
        self.assertEqual(d.diagnostic_reason, DIAG_ALL_PATHS_HEALTHY)
        self.assertIsNone(d.filter_suspected)

    def test_admin_only_failure_is_not_filtering(self):
        d = derive_observability(True, False, True, True)
        self.assertEqual(d.diagnostic_reason, DIAG_ADMIN_ONLY_FAILURE)
        self.assertIsNone(d.filter_suspected)

    def test_wireguard_failure_wins_before_filtering(self):
        d = derive_observability(True, True, False, False, True, False, 5, 0)
        self.assertEqual(d.diagnostic_reason, DIAG_WIREGUARD_PATH_FAILURE)
        self.assertFalse(d.filter_suspected)

    def test_core_path_failure_is_not_filtering(self):
        d = derive_observability(True, True, True, False, True, False, 5, 0)
        self.assertEqual(d.diagnostic_reason, DIAG_CORE_PATH_FAILURE)
        self.assertFalse(d.filter_suspected)

    def test_confirmed_filter_remains_unresolved_during_unrelated_wg_failure(self):
        d = derive_observability(
            True, True, False, False, True, None,
            previous_filter_suspected=True,
        )
        self.assertEqual(d.diagnostic_reason, DIAG_WIREGUARD_PATH_FAILURE)
        self.assertTrue(d.filter_suspected)
        self.assertEqual(d.filter_confidence, FILTER_CONFIDENCE_LOW)

    def test_service_failure_is_not_filtering(self):
        d = derive_observability(False, True, True, True, True, False, 5, 0)
        self.assertEqual(d.diagnostic_reason, DIAG_SERVICE_PATH_FAILURE)
        self.assertFalse(d.filter_suspected)

    def test_one_regional_failure_cannot_confirm_filtering(self):
        d = derive_observability(
            True, True, True, True, True, False,
            regional_failure_streak=1,
            confirm_threshold=3,
        )
        self.assertEqual(d.diagnostic_reason, DIAG_REGIONAL_REACHABILITY_FAILURE)
        self.assertFalse(d.filter_suspected)
        self.assertEqual(d.filter_confidence, FILTER_CONFIDENCE_LOW)

    def test_repeated_regional_failure_with_independent_success_confirms_filtering(self):
        d = derive_observability(
            True, True, True, True, True, False,
            regional_failure_streak=3,
            confirm_threshold=3,
        )
        self.assertEqual(d.diagnostic_reason, DIAG_FILTER_SUSPECTED)
        self.assertTrue(d.filter_suspected)
        self.assertEqual(d.filter_confidence, FILTER_CONFIDENCE_HIGH)

    def test_repeated_regional_failure_without_external_probe_is_medium_confidence(self):
        d = derive_observability(
            True, True, True, True, None, False,
            regional_failure_streak=3,
            confirm_threshold=3,
        )
        self.assertTrue(d.filter_suspected)
        self.assertEqual(d.filter_confidence, FILTER_CONFIDENCE_MEDIUM)

    def test_external_and_regional_failure_never_confirms_filtering(self):
        d = derive_observability(
            True, True, True, True, False, False,
            regional_failure_streak=5,
            confirm_threshold=3,
        )
        self.assertEqual(d.diagnostic_reason, DIAG_EXTERNAL_REACHABILITY_FAILURE)
        self.assertFalse(d.filter_suspected)
        self.assertEqual(d.filter_confidence, FILTER_CONFIDENCE_LOW)

    def test_external_and_regional_failure_together_do_not_newly_confirm_filtering(self):
        d = derive_observability(
            True, True, True, True, False, False,
            regional_failure_streak=5,
            confirm_threshold=3,
        )
        self.assertEqual(d.diagnostic_reason, DIAG_EXTERNAL_REACHABILITY_FAILURE)
        self.assertFalse(d.filter_suspected)

    def test_regional_and_external_failure_cannot_newly_confirm_filtering(self):
        d = derive_observability(
            True, True, True, True, False, False,
            regional_failure_streak=10,
            confirm_threshold=3,
        )
        self.assertEqual(d.diagnostic_reason, DIAG_EXTERNAL_REACHABILITY_FAILURE)
        self.assertFalse(d.filter_suspected)
        self.assertEqual(d.filter_confidence, FILTER_CONFIDENCE_LOW)

    def test_confirmed_filter_survives_unrelated_wireguard_failure(self):
        d = derive_observability(
            True, True, False, False, None, None,
            previous_filter_suspected=True,
        )
        self.assertEqual(d.diagnostic_reason, DIAG_WIREGUARD_PATH_FAILURE)
        self.assertTrue(d.filter_suspected)
        self.assertEqual(d.filter_confidence, FILTER_CONFIDENCE_LOW)

    def test_confirmed_filter_is_not_cleared_by_missing_regional_evidence(self):
        d = derive_observability(
            True, True, True, True, True, None,
            previous_filter_suspected=True,
        )
        self.assertEqual(d.diagnostic_reason, DIAG_FILTER_SUSPECTED)
        self.assertTrue(d.filter_suspected)

    def test_confirmed_filter_requires_recovery_threshold(self):
        sticky = derive_observability(
            True, True, True, True, True, True,
            regional_success_streak=1,
            recovery_threshold=2,
            previous_filter_suspected=True,
        )
        self.assertEqual(sticky.diagnostic_reason, DIAG_FILTER_SUSPECTED)
        self.assertTrue(sticky.filter_suspected)

        recovered = derive_observability(
            True, True, True, True, True, True,
            regional_success_streak=2,
            recovery_threshold=2,
            previous_filter_suspected=True,
        )
        self.assertEqual(recovered.diagnostic_reason, DIAG_ALL_PATHS_HEALTHY)
        self.assertFalse(recovered.filter_suspected)

    def test_external_failure_is_diagnostic_not_filter_confirmation(self):
        d = derive_observability(True, True, True, True, False, None)
        self.assertEqual(d.diagnostic_reason, DIAG_EXTERNAL_REACHABILITY_FAILURE)
        self.assertFalse(d.filter_suspected)

    def test_incomplete_local_evidence_stays_insufficient(self):
        d = derive_observability(True, True, None, None)
        self.assertEqual(d.diagnostic_reason, DIAG_INSUFFICIENT_EVIDENCE)
        self.assertIsNone(d.filter_suspected)

    def test_probe_error_normalization(self):
        self.assertEqual(normalize_probe_error("timed out"), PROBE_REASON_TIMEOUT)
        self.assertEqual(normalize_probe_error("Connection refused"), PROBE_REASON_CONNECTION_REFUSED)
        self.assertEqual(normalize_probe_error("No route to host"), PROBE_REASON_NETWORK_UNREACHABLE)


class Phase6CIntegrationRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")

    def test_current_release_marker_is_present(self):
        self.assertIn(
            'BOT_VERSION_TAG = "V121E-2026-10-04-failover-simulation"',
            self.source,
        )

    def test_core_is_excluded_from_phase6c_edge_probes(self):
        recompute_start = self.source.index("def _db_recompute_host_observability(")
        recompute_end = self.source.index("def _db_record_observability_probe(", recompute_start)
        recompute_region = self.source[recompute_start:recompute_end]
        self.assertIn("if _is_current_core_host(host):", recompute_region)
        self.assertIn("DIAG_CORE_LOCAL", recompute_region)
        self.assertIn("wg_peer_ok=NULL", recompute_region)
        self.assertIn("core_path_ok=NULL", recompute_region)

        tick_start = self.source.index("async def _host_health_tick(app):")
        tick_end = self.source.index("async def _host_health_loop(app):", tick_start)
        tick_region = self.source[tick_start:tick_end]
        guard = "if not await asyncio.to_thread(_is_current_core_host, host):"
        self.assertIn(guard, tick_region)
        guard_pos = tick_region.index(guard)
        probe_pos = tick_region.index("_probe_wireguard_edge_sync", guard_pos)
        self.assertGreater(probe_pos, guard_pos)

    def test_core_local_diagnostic_constant_is_stable(self):
        self.assertEqual(DIAG_CORE_LOCAL, "CORE_LOCAL")

    def test_phase6c_schema_is_additive(self):
        for column in (
            "wg_peer_ok",
            "wg_last_handshake_at",
            "core_path_ok",
            "external_service_ok",
            "regional_service_ok",
            "diagnostic_reason",
            "filter_suspected",
            "filter_confidence",
            "filter_reason",
            "filter_consecutive_failures",
            "filter_consecutive_successes",
            "filter_cooldown_until",
        ):
            self.assertIn(f"ADD COLUMN {column}", self.source)
        self.assertIn("CREATE TABLE IF NOT EXISTS host_probe_results", self.source)

    def test_configurable_phase6c_thresholds_exist(self):
        for name in (
            "EDGE_OBSERVABILITY_PROBE_TIMEOUT_SECONDS",
            "WG_HANDSHAKE_MAX_AGE_SECONDS",
            "EDGE_FILTER_CONFIRM_THRESHOLD",
            "EDGE_FILTER_RECOVERY_THRESHOLD",
            "EDGE_FILTER_COOLDOWN_SECONDS",
        ):
            self.assertIn(name, self.source)

    def test_provider_neutral_probe_ingestion_exists(self):
        start = self.source.index("def _db_record_observability_probe(")
        end = self.source.index("def _db_get_host_port_health_map(", start)
        region = self.source[start:end]
        self.assertIn('"external_service"', region)
        self.assertIn('"regional_service"', region)
        self.assertIn("source_txt", region)
        self.assertNotIn("cloudzy", region.lower())
        self.assertNotIn("digitalocean", region.lower())

    def test_wireguard_probe_collects_handshake_and_core_path(self):
        start = self.source.index("def _probe_wireguard_edge_sync(")
        end = self.source.index("async def _host_health_tick(app):", start)
        region = self.source[start:end]
        self.assertIn('["wg", "show", "wg0", "latest-handshakes"]', region)
        self.assertIn("WG_HANDSHAKE_MAX_AGE_SECONDS", region)
        self.assertIn('["ping", "-c", "1"', region)
        self.assertIn("wg_last_handshake_at", region)

    def test_wireguard_probe_wakes_idle_peer_before_handshake_freshness_check(self):
        start = self.source.index("def _probe_wireguard_edge_sync(")
        end = self.source.index("async def _host_health_tick(app):", start)
        region = self.source[start:end]
        ping_pos = region.index('["ping", "-c", "1"')
        handshake_pos = region.index('["wg", "show", "wg0", "latest-handshakes"]')
        self.assertLess(ping_pos, handshake_pos)
        self.assertIn("WG_PATH_PROVEN_BY_TUNNEL", region)

    def test_wireguard_probe_stimulates_tunnel_before_reading_handshake(self):
        start = self.source.index("def _probe_wireguard_edge_sync(")
        end = self.source.index("async def _host_health_tick(app):", start)
        region = self.source[start:end]
        ping_pos = region.index('["ping", "-c", "1"')
        handshake_pos = region.index('["wg", "show", "wg0", "latest-handshakes"]')
        self.assertLess(ping_pos, handshake_pos)

    def test_probe_history_has_bounded_retention(self):
        self.assertIn("EDGE_PROBE_HISTORY_RETENTION_DAYS", self.source)
        self.assertIn("def _db_prune_probe_history(", self.source)
        self.assertGreaterEqual(
            self.source.count("_db_prune_probe_history(conn, host)"),
            2,
        )

    def test_health_tick_records_phase6c_evidence_without_replacing_phase6a_threshold(self):
        start = self.source.index("async def _host_health_tick(app):")
        end = self.source.index("async def _host_health_loop(app):", start)
        region = self.source[start:end]
        self.assertIn("_probe_wireguard_edge_sync", region)
        self.assertIn('"wireguard"', region)
        self.assertIn('"core_path"', region)
        self.assertIn(
            "if service_ok or new_fails < HOST_HEALTH_FAIL_THRESHOLD:",
            region,
        )

    def test_phase6c_classifier_persistence_cannot_perform_failover_actions(self):
        start = self.source.index("def _db_recompute_host_observability(")
        end = self.source.index("def _db_record_observability_probe(", start)
        region = self.source[start:end]
        for forbidden in (
            "_db_set_host_active",
            "_cf_switch_public_domain",
            "_activate_standby_for_filtered_edge",
            "_db_set_all_accounts_host",
            "promote_edge_to_core",
            "demote_core_to_edge",
        ):
            self.assertNotIn(forbidden, region)
        self.assertIn("previous is False and proposed is True", region)

    def test_phase6b_health_model_is_still_separate(self):
        start = self.source.index("def _derive_host_health_state(")
        end = self.source.index("def _health_state_icon(", start)
        region = self.source[start:end]
        self.assertNotIn("wireguard", region.lower())
        self.assertNotIn("regional", region.lower())
        self.assertNotIn("filter_suspected", region)

    def test_monitoring_panel_surfaces_phase6c_evidence(self):
        start = self.source.index("async def _render_host_pool_panel(")
        end = self.source.index("async def _host_has_working_persistent_key", start)
        region = self.source[start:end]
        for fragment in (
            "Diagnostic:",
            "WireGuard",
            "Core path",
            "External",
            "Regional",
            "Filtering:",
            "filter_confidence",
            "External check:",
            "Regional check:",
        ):
            self.assertIn(fragment, region)

    def test_monitoring_panel_paginates_before_telegram_message_limit(self):
        start = self.source.index("async def _render_host_pool_panel(")
        end = self.source.index("async def _host_has_working_persistent_key", start)
        region = self.source[start:end]
        for fragment in (
            "page_size = 2",
            "page_pool = pool[page_start:page_end]",
            'callback_data=f"hppage_{page - 1}"',
            'callback_data=f"hppage_{page + 1}"',
            "page_line =",
            "_panel_value",
        ):
            self.assertIn(fragment, region)
        self.assertIn('elif d.startswith("hppage_")', self.source)
        self.assertIn("await _render_host_pool_panel(query, page=page)", self.source)

    def test_diagnostic_transitions_are_logged_without_operational_actions(self):
        start = self.source.index("def _db_recompute_host_observability(")
        end = self.source.index("def _db_record_observability_probe(", start)
        region = self.source[start:end]
        self.assertIn("Phase6C diagnostic transition", region)
        self.assertIn("previous_diagnostic != diagnostic_reason", region)


if __name__ == "__main__":
    unittest.main()
