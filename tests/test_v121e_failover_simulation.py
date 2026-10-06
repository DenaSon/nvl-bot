import pathlib
import unittest

from automatic_failover import (
    AUTO_FAILOVER_REASON_DIFFERENTIAL_NOT_CONFIRMED,
    AUTO_FAILOVER_REASON_DIFFERENTIAL_STALE,
    AUTO_FAILOVER_REASON_FILTER_NOT_LIKELY,
    AUTO_FAILOVER_REASON_NO_STANDBY,
    AUTO_FAILOVER_REASON_READY,
    evaluate_auto_failover,
)
from incident_observability import (
    REASON_DIFFERENTIAL_NOT_CONFIRMED,
    REASON_DIFFERENTIAL_STALE,
    reason_label_fa,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]
BOT_PATH = ROOT / "bot_final_v49-2.py"


def decision_kwargs():
    return dict(
        enabled=True,
        source_is_default=True,
        source_is_standby=False,
        filter_state="CLEAR",
        filter_confidence="NONE",
        diagnostic_reason="HEALTHY",
        differential_confirmed=False,
        differential_age_seconds=float("inf"),
        differential_max_age_seconds=120,
        failure_streak=0,
        confirm_threshold=2,
        provider_status="OK",
        seconds_since_last_switch=float("inf"),
        switch_cooldown_seconds=1800,
        seconds_since_last_attempt=float("inf"),
        attempt_cooldown_seconds=180,
        safe_standby_count=0,
    )


class ControlledFailoverSimulationTests(unittest.TestCase):
    def test_timeline_stays_fail_closed_until_fresh_confirmation_and_ready_standby(self):
        # T0: normal state.
        t0 = decision_kwargs()
        d0 = evaluate_auto_failover(**t0)
        self.assertFalse(d0.eligible)
        self.assertEqual(d0.reason, AUTO_FAILOVER_REASON_FILTER_NOT_LIKELY)

        # T1: first regional suspicion; still not actionable.
        t1 = decision_kwargs()
        t1.update(
            filter_state="POSSIBLE",
            filter_confidence="MEDIUM",
            diagnostic_reason="FILTER_SUSPECTED",
            failure_streak=1,
        )
        d1 = evaluate_auto_failover(**t1)
        self.assertFalse(d1.eligible)
        self.assertEqual(d1.reason, AUTO_FAILOVER_REASON_FILTER_NOT_LIKELY)

        # T2: strong source evidence exists, but differential confirmation is pending.
        t2 = decision_kwargs()
        t2.update(
            filter_state="LIKELY",
            filter_confidence="HIGH",
            diagnostic_reason="FILTER_SUSPECTED",
            failure_streak=2,
            differential_confirmed=False,
            differential_age_seconds=5,
        )
        d2 = evaluate_auto_failover(**t2)
        self.assertFalse(d2.eligible)
        self.assertEqual(
            d2.reason,
            AUTO_FAILOVER_REASON_DIFFERENTIAL_NOT_CONFIRMED,
        )

        # T3: the same current round has a fresh target-specific confirmation.
        # No ready Standby means the system still refuses to move traffic.
        t3 = dict(t2)
        t3.update(
            differential_confirmed=True,
            differential_age_seconds=10,
            safe_standby_count=0,
        )
        d3 = evaluate_auto_failover(**t3)
        self.assertFalse(d3.eligible)
        self.assertEqual(d3.reason, AUTO_FAILOVER_REASON_NO_STANDBY)

        # T4: a fresh, safe Standby is available. Only now may the shared
        # failover engine be invoked by the runtime.
        t4 = dict(t3)
        t4["safe_standby_count"] = 1
        d4 = evaluate_auto_failover(**t4)
        self.assertTrue(d4.eligible)
        self.assertEqual(d4.reason, AUTO_FAILOVER_REASON_READY)

        # T5 safety regression: old confirmation cannot authorize a later move.
        t5 = dict(t4)
        t5["differential_age_seconds"] = 121
        d5 = evaluate_auto_failover(**t5)
        self.assertFalse(d5.eligible)
        self.assertEqual(d5.reason, AUTO_FAILOVER_REASON_DIFFERENTIAL_STALE)

    def test_new_block_reasons_have_persian_operator_text(self):
        self.assertNotEqual(
            reason_label_fa(REASON_DIFFERENTIAL_NOT_CONFIRMED),
            REASON_DIFFERENTIAL_NOT_CONFIRMED,
        )
        self.assertNotEqual(
            reason_label_fa(REASON_DIFFERENTIAL_STALE),
            REASON_DIFFERENTIAL_STALE,
        )


class V121EIntegrationShapeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")

    def _region(self, start, end):
        a = self.source.index(start)
        b = self.source.index(end, a)
        return self.source[a:b]

    def test_release_marker(self):
        self.assertIn(
            'BOT_VERSION_TAG = "V123B32M-2026-10-06-safe-node-move"',
            self.source,
        )

    def test_runtime_reads_latest_differential_audit(self):
        region = self._region(
            "def _db_get_latest_differential_confirmation",
            "def _db_get_recent_regional_node_results",
        )
        self.assertIn("regional_differential_checks", region)
        self.assertIn("source_request_id", region)
        self.assertIn("ORDER BY id DESC LIMIT 1", region)

    def test_auto_failover_binds_confirmation_to_current_round(self):
        region = self._region(
            "async def _phase6h_auto_failover_tick",
            "async def _regional_filter_tick",
        )
        self.assertIn("differential_matches_current_round", region)
        self.assertIn('source_health.get("regional_last_request_id")', region)
        self.assertIn("differential_confirmed=differential_confirmed", region)
        self.assertIn(
            "differential_max_age_seconds=DIFFERENTIAL_CONFIRMATION_MAX_AGE_SECONDS",
            region,
        )

    def test_operator_filtering_panel_has_no_development_labels(self):
        region = self._region(
            "async def _render_filtering_monitor_panel",
            "async def _render_filtering_edge_detail",
        )
        self.assertIn("پایش اختلال و فیلترینگ", region)
        self.assertIn("انتقال خودکار", region)
        self.assertNotIn("Phase 6", region)
        self.assertNotIn("V121", region)
        self.assertNotIn("Filtering Monitor", region)
        self.assertNotIn("Automatic Filtering Failover", region)


if __name__ == "__main__":
    unittest.main()
