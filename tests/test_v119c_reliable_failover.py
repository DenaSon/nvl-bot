import pathlib
import unittest
from datetime import datetime, timedelta

from standby_readiness import (
    READINESS_READY,
    evidence_age_seconds,
    evaluate_standby_readiness,
    rank_ready_standbys,
    readiness_diagnostics,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]
BOT_PATH = ROOT / "bot_final_v49-2.py"


def _ts(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def ready_health(now, *, latency=20):
    recent = _ts(now - timedelta(seconds=30))
    return {
        "active": True,
        "filter_state": "CLEAR",
        "service_ok": True,
        "admin_ok": True,
        "wg_peer_ok": True,
        "core_path_ok": True,
        "external_service_ok": True,
        "service_last_check": recent,
        "admin_last_check": recent,
        "wg_last_check": recent,
        "core_path_last_check": recent,
        "external_service_last_check": recent,
        "regional_service_last_check": recent,
        "regional_state_updated_at": recent,
        "avg_latency_ms": latency,
    }


class V119CReadinessPolicyTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 3, 12, 0, 0)

    def test_complete_fresh_clear_standby_is_ready(self):
        verdict = evaluate_standby_readiness(
            ready_health(self.now),
            now=self.now,
            local_max_age_seconds=180,
            regional_max_age_seconds=600,
        )
        self.assertTrue(verdict.ready)
        self.assertEqual(verdict.failures, ())
        self.assertTrue(verdict.local_fresh)
        self.assertTrue(verdict.regional_fresh)
        self.assertTrue(verdict.regional_clear)

    def test_stale_regional_clear_is_not_ready(self):
        health = ready_health(self.now)
        health["regional_state_updated_at"] = _ts(
            self.now - timedelta(seconds=601)
        )
        verdict = evaluate_standby_readiness(
            health,
            now=self.now,
            local_max_age_seconds=180,
            regional_max_age_seconds=600,
        )
        self.assertFalse(verdict.ready)
        self.assertIn("REGIONAL_EVIDENCE_STALE", verdict.failures)

    def test_stale_local_evidence_is_not_ready(self):
        health = ready_health(self.now)
        health["wg_last_check"] = _ts(self.now - timedelta(seconds=181))
        verdict = evaluate_standby_readiness(
            health,
            now=self.now,
            local_max_age_seconds=180,
            regional_max_age_seconds=600,
        )
        self.assertFalse(verdict.ready)
        self.assertTrue(
            any(x.startswith("LOCAL_EVIDENCE_STALE:") for x in verdict.failures)
        )

    def test_inactive_standby_is_never_ready(self):
        health = ready_health(self.now)
        health["active"] = False
        verdict = evaluate_standby_readiness(
            health,
            now=self.now,
            local_max_age_seconds=180,
            regional_max_age_seconds=600,
        )
        self.assertFalse(verdict.ready)
        self.assertIn("INACTIVE", verdict.failures)

    def test_unknown_or_filtered_regional_state_is_not_ready(self):
        for state in ("UNKNOWN", "POSSIBLE", "LIKELY"):
            health = ready_health(self.now)
            health["filter_state"] = state
            verdict = evaluate_standby_readiness(
                health,
                now=self.now,
                local_max_age_seconds=180,
                regional_max_age_seconds=600,
            )
            self.assertFalse(verdict.ready, state)
            self.assertIn("FILTER_NOT_CLEAR", verdict.failures)

    def test_missing_control_plane_gate_is_explained(self):
        health = ready_health(self.now)
        health["core_path_ok"] = False
        health["admin_ok"] = None
        verdict = evaluate_standby_readiness(
            health,
            now=self.now,
            local_max_age_seconds=180,
            regional_max_age_seconds=600,
        )
        self.assertIn("CORE_PATH_NOT_OK", verdict.failures)
        self.assertIn("ADMIN_NOT_OK", verdict.failures)

    def test_rank_ready_standbys_prefers_latency_but_rejects_stale(self):
        h1 = ready_health(self.now, latency=50)
        h2 = ready_health(self.now, latency=15)
        h3 = ready_health(self.now, latency=1)
        h3["regional_state_updated_at"] = _ts(
            self.now - timedelta(seconds=900)
        )
        ranked = rank_ready_standbys(
            ("10.0.0.2", "10.0.0.3", "10.0.0.4"),
            {
                "10.0.0.2": h1,
                "10.0.0.3": h2,
                "10.0.0.4": h3,
            },
            now=self.now,
            local_max_age_seconds=180,
            regional_max_age_seconds=600,
        )
        self.assertEqual(ranked, ("10.0.0.3", "10.0.0.2"))

    def test_readiness_diagnostics_only_returns_unsafe_hosts(self):
        good = ready_health(self.now)
        bad = ready_health(self.now)
        bad["service_ok"] = False
        result = readiness_diagnostics(
            ("good", "bad"),
            {"good": good, "bad": bad},
            now=self.now,
            local_max_age_seconds=180,
            regional_max_age_seconds=600,
        )
        self.assertNotIn("good", result)
        self.assertIn("bad", result)
        self.assertIn("SERVICE_NOT_OK", result["bad"])

    def test_evidence_age_missing_is_infinite(self):
        self.assertEqual(evidence_age_seconds(None, self.now), float("inf"))

    def test_provider_attempt_timestamp_cannot_freshen_regional_evidence(self):
        health = ready_health(self.now)
        health["regional_state_updated_at"] = _ts(
            self.now - timedelta(seconds=900)
        )
        health["regional_service_last_check"] = _ts(self.now)
        verdict = evaluate_standby_readiness(
            health,
            now=self.now,
            local_max_age_seconds=180,
            regional_max_age_seconds=600,
        )
        self.assertFalse(verdict.ready)
        self.assertIn("REGIONAL_EVIDENCE_STALE", verdict.failures)


class V119CIntegrationShapeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")

    def _region(self, start, end):
        a = self.source.index(start)
        b = self.source.index(end, a)
        return self.source[a:b]

    def test_release_marker(self):
        self.assertIn(
            'BOT_VERSION_TAG = "V121E-2026-10-04-failover-simulation"',
            self.source,
        )

    def test_retry_cooldown_is_reduced_but_switch_cooldown_remains_long(self):
        self.assertIn(
            'NVL_AUTO_FAILOVER_ATTEMPT_COOLDOWN_SECONDS", 180',
            self.source,
        )
        self.assertIn(
            'NVL_AUTO_FAILOVER_SWITCH_COOLDOWN_SECONDS", 1800',
            self.source,
        )

    def test_warm_standby_watchdog_defaults_are_bounded(self):
        for fragment in (
            'NVL_STANDBY_READINESS_INTERVAL", 60',
            'NVL_STANDBY_LOCAL_MAX_AGE", 180',
            'NVL_STANDBY_REGIONAL_REFRESH_INTERVAL", 300',
            'NVL_STANDBY_REGIONAL_MAX_AGE", 600',
            'NVL_STANDBY_FAILOVER_TARGET_MAX_AGE", 180',
            'NVL_STANDBY_REGIONAL_MAX_PER_CYCLE", 1',
            'NVL_STANDBY_FAILOVER_REFRESH_MAX_TARGETS", 2',
        ):
            self.assertIn(fragment, self.source)

    def test_watchdog_refreshes_local_and_slow_regional_readiness(self):
        region = self._region(
            "async def _standby_readiness_tick(app):",
            "async def _standby_readiness_loop(app):",
        )
        self.assertIn("_probe_standby_local_readiness", region)
        self.assertIn("_refresh_standby_regional_slow", region)
        self.assertIn("rank_ready_standbys(", region)
        self.assertIn("_publish_standby_readiness_state", region)
        for forbidden in (
            "_safe_manual_failover(",
            "_cf_switch_public_domain(",
            "_db_commit_failover_account_state(",
        ):
            self.assertNotIn(forbidden, region)

    def test_standby_generic_provider_error_does_not_poison_global_state(self):
        region = self._region(
            "async def _regional_filter_probe_edge(",
            "async def _standby_health_snapshot",
        )
        self.assertIn("affect_global_provider=True", region)
        self.assertIn("if affect_global_provider:", region)
        self.assertIn("global_provider_state_unchanged=True", region)

    def test_confirmed_filter_runs_on_demand_standby_refresh_before_policy(self):
        region = self._region(
            "async def _regional_filter_tick(app):",
            "async def _regional_filter_probe_one_now",
        )
        refresh_pos = region.index("_refresh_standbys_for_confirmed_filter")
        policy_pos = region.index("_phase6h_auto_failover_tick")
        self.assertLess(refresh_pos, policy_pos)

    def test_on_demand_refresh_is_bounded_and_only_after_confirmation(self):
        region = self._region(
            "async def _refresh_standbys_for_confirmed_filter",
            "async def _incident_mark_failover_blocked",
        )
        self.assertIn("confirmed = (", region)
        self.assertIn("STANDBY_FAILOVER_REFRESH_MAX_TARGETS", region)
        self.assertIn("STANDBY_FAILOVER_TARGET_MAX_AGE_SECONDS", region)
        self.assertIn("affect_global_provider=False", region)
        self.assertIn("notify_transition=False", region)
        self.assertIn("needs_regional_refresh", region)

    def test_phase6h_uses_all_configured_but_only_active_fresh_candidates(self):
        region = self._region(
            "async def _phase6h_auto_failover_tick(app, ready_candidate_override=None):",
            "async def _regional_filter_tick(app):",
        )
        self.assertIn("_db_get_all_standby_hosts", region)
        self.assertIn("_db_get_standby_hosts", region)
        self.assertIn("rank_ready_standbys(", region)
        self.assertIn("ready_candidate_override", region)
        self.assertIn("STANDBY_LOCAL_EVIDENCE_MAX_AGE_SECONDS", region)
        self.assertIn("STANDBY_REGIONAL_EVIDENCE_MAX_AGE_SECONDS", region)
        self.assertNotIn("rank_safe_standbys(", region)

    def test_auto_preflight_requires_clear_and_fresh_regional_target(self):
        preflight = self._region(
            "async def _safe_manual_failover_preflight(",
            "async def _run_phase6g_rebuild_helper",
        )
        self.assertIn("require_clear_filter: bool = False", preflight)
        self.assertIn("TARGET_FILTER_STATE_NOT_CLEAR", preflight)
        self.assertIn("TARGET_REGIONAL_EVIDENCE_STALE", preflight)

        engine = self._region(
            "async def _safe_manual_failover(",
            "async def _activate_standby_for_filtered_edge",
        )
        self.assertIn("require_clear_filter=automatic", engine)

    def test_post_rebuild_verify_rechecks_wg_and_core_before_db_commit(self):
        region = self._region(
            "async def _safe_manual_failover(",
            "async def _activate_standby_for_filtered_edge",
        )
        verify_pos = region.index("verify_path = await asyncio.to_thread")
        commit_pos = region.index("_db_commit_failover_account_state")
        self.assertLess(verify_pos, commit_pos)
        self.assertIn("verify_wg_ok", region)
        self.assertIn("verify_core_path_ok", region)
        self.assertIn("POST_REBUILD_TARGET_REGIONAL_EVIDENCE_INVALID", region)
        self.assertIn("latest_regional_age", region)

    def test_readiness_notifications_are_state_change_debounced(self):
        region = self._region(
            "async def _publish_standby_readiness_state",
            "async def _refresh_standby_regional_slow",
        )
        self.assertIn('phase6h_standby_readiness_state', region)
        self.assertIn("if previous == state:", region)
        self.assertIn("NO_STANDBY", region)
        self.assertIn("Safe Standby", region)

    def test_enabling_auto_immediately_kicks_readiness_check(self):
        region = self._region(
            'elif d == "flt_auto_enable_yes"',
            'elif d.startswith("flt_page_")',
        )
        self.assertIn("phase6h_standby_readiness_state", region)
        self.assertIn("_standby_readiness_tick(context.application)", region)

    def test_watchdog_task_has_clean_lifecycle(self):
        init_region = self._region(
            "async def _post_init(app):",
            "async def _post_shutdown(app):",
        )
        shutdown_region = self._region(
            "async def _post_shutdown(app):",
            "if __name__ == '__main__':",
        )
        self.assertIn("standby_readiness_task", init_region)
        self.assertIn("standby_readiness_task", shutdown_region)

    def test_monitor_panel_exposes_ready_standby_count(self):
        region = self._region(
            "async def _render_filtering_monitor_panel",
            "async def _render_filtering_edge_detail",
        )
        self.assertIn("Warm Standby:", region)
        self.assertIn("standby_ready", region)
        self.assertIn("Standby ✅ Ready", region)
        self.assertIn("Standby ⚠️ Not Ready", region)


if __name__ == "__main__":
    unittest.main()
