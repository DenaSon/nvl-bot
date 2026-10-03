import pathlib
import unittest

from incident_observability import (
    INCIDENT_STATE_CONFIRMING,
    INCIDENT_STATE_FILTER_CONFIRMED,
    INCIDENT_STATE_SUSPECTED,
    REASON_CONFIRMATION_PENDING,
    REASON_FILTER_CONFIRMED,
    REASON_NO_SAFE_STANDBY,
    REASON_NO_STANDBY,
    REASON_REGIONAL_SUSPECTED,
    classify_filter_incident,
    normalize_auto_block_reason,
    should_notify_incident,
    standby_safety_failures,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]
BOT_PATH = ROOT / "bot_final_v49-2.py"


class V119BIncidentPolicyTests(unittest.TestCase):
    def test_possible_opens_suspected_incident(self):
        d = classify_filter_incident(
            filter_state="POSSIBLE",
            confidence="LOW",
            failure_streak=0,
            confirm_threshold=2,
        )
        self.assertEqual(d.state, INCIDENT_STATE_SUSPECTED)
        self.assertEqual(d.reason, REASON_REGIONAL_SUSPECTED)
        self.assertFalse(d.actionable)

    def test_likely_before_threshold_is_confirming(self):
        d = classify_filter_incident(
            filter_state="LIKELY",
            confidence="MEDIUM",
            failure_streak=1,
            confirm_threshold=2,
        )
        self.assertEqual(d.state, INCIDENT_STATE_CONFIRMING)
        self.assertEqual(d.reason, REASON_CONFIRMATION_PENDING)
        self.assertFalse(d.actionable)

    def test_high_confidence_threshold_is_confirmed(self):
        d = classify_filter_incident(
            filter_state="LIKELY",
            confidence="HIGH",
            failure_streak=2,
            confirm_threshold=2,
        )
        self.assertEqual(d.state, INCIDENT_STATE_FILTER_CONFIRMED)
        self.assertEqual(d.reason, REASON_FILTER_CONFIRMED)
        self.assertTrue(d.actionable)

    def test_no_standby_and_no_safe_standby_are_distinct(self):
        self.assertEqual(
            normalize_auto_block_reason(
                "NO_SAFE_STANDBY",
                configured_standby_count=0,
                safe_standby_count=0,
            ),
            REASON_NO_STANDBY,
        )
        self.assertEqual(
            normalize_auto_block_reason(
                "NO_SAFE_STANDBY",
                configured_standby_count=2,
                safe_standby_count=0,
            ),
            REASON_NO_SAFE_STANDBY,
        )

    def test_standby_rejection_explains_each_failed_gate(self):
        failures = standby_safety_failures(
            {
                "filter_state": "POSSIBLE",
                "service_ok": True,
                "admin_ok": False,
                "wg_peer_ok": None,
                "core_path_ok": True,
                "external_service_ok": False,
            }
        )
        self.assertIn("FILTER_NOT_CLEAR", failures)
        self.assertNotIn("SERVICE_NOT_OK", failures)
        self.assertIn("ADMIN_NOT_OK", failures)
        self.assertIn("WG_NOT_OK", failures)
        self.assertNotIn("CORE_PATH_NOT_OK", failures)
        self.assertIn("EXTERNAL_NOT_OK", failures)

    def test_same_state_and_reason_does_not_notify_again(self):
        self.assertFalse(
            should_notify_incident(
                previous_state="FAILOVER_BLOCKED",
                previous_reason="NO_STANDBY",
                new_state="FAILOVER_BLOCKED",
                new_reason="NO_STANDBY",
            )
        )
        self.assertTrue(
            should_notify_incident(
                previous_state="FAILOVER_BLOCKED",
                previous_reason="NO_STANDBY",
                new_state="FAILOVER_BLOCKED",
                new_reason="NO_SAFE_STANDBY",
            )
        )


class V119BIntegrationStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")

    def _region(self, start, end):
        a = self.source.index(start)
        b = self.source.index(end, a)
        return self.source[a:b]

    def test_release_marker(self):
        self.assertIn(
            'BOT_VERSION_TAG = "V119B.0-2026-10-03-incident-observability"',
            self.source,
        )

    def test_incident_schema_and_event_timeline_exist(self):
        self.assertIn("CREATE TABLE IF NOT EXISTS filter_incidents", self.source)
        self.assertIn("CREATE TABLE IF NOT EXISTS filter_incident_events", self.source)
        self.assertIn("last_notified_state", self.source)
        self.assertIn("last_notified_reason", self.source)

    def test_structured_incident_log_is_grep_friendly(self):
        region = self._region(
            "def _incident_log(",
            "async def _notify_incident_once",
        )
        self.assertIn('"NVL_INCIDENT "', region)
        self.assertIn("json.dumps", region)

    def test_filter_transition_opens_and_recovers_incident(self):
        region = self._region(
            "async def _notify_filter_state_transition(",
            "def _probe_state_text",
        )
        self.assertIn("_db_transition_filter_incident", region)
        self.assertIn("INCIDENT_STATE_RECOVERED", region)
        self.assertIn("close=True", region)
        self.assertIn("classify_filter_incident(", region)
        self.assertIn("_notify_incident_once", region)

    def test_provider_error_preserves_edge_state_and_notifies_once(self):
        region = self._region(
            "async def _regional_provider_enter_error(",
            "async def _regional_provider_mark_ok",
        )
        self.assertIn("PROVIDER_STATUS_ERROR", region)
        self.assertIn("previous_status != PROVIDER_STATUS_ERROR", region)
        self.assertIn("فیلترینگ محسوب نمی‌شود", region)
        self.assertNotIn("_db_record_regional_round", region)

    def test_confirmed_filter_block_records_exact_reason(self):
        region = self._region(
            "async def _incident_mark_failover_blocked(",
            "async def _phase6h_auto_failover_tick",
        )
        self.assertIn("standby_safety_failures", region)
        self.assertIn("AUTO_FAILOVER_BLOCKED", region)
        self.assertIn("Standby rejection", region)
        self.assertIn("_notify_incident_once", region)

    def test_no_default_edge_is_operator_visible_when_incident_exists(self):
        region = self._region(
            "async def _phase6h_auto_failover_tick(app):",
            "async def _regional_filter_tick(app):",
        )
        self.assertIn("REASON_NO_DEFAULT_EDGE", region)
        self.assertIn("Default Edge: <b>تعریف نشده</b>", region)
        self.assertIn("_db_get_open_filter_incident", region)

    def test_phase6h_only_notifies_block_after_filter_confirmed(self):
        region = self._region(
            "async def _phase6h_auto_failover_tick(app):",
            "async def _regional_filter_tick(app):",
        )
        self.assertIn("filter_confirmed = (", region)
        self.assertIn("if filter_confirmed and incident:", region)

    def test_auto_failover_links_incident_to_phase6g_operation(self):
        region = self._region(
            "async def _phase6h_auto_failover_tick(app):",
            "async def _regional_filter_tick(app):",
        )
        self.assertIn("incident_id=incident.get", region)
        self.assertIn("operation_id = result.get", region)
        self.assertIn("AUTO_FAILOVER_SUCCEEDED", region)
        self.assertIn("AUTO_FAILOVER_FAILED", region)

    def test_safe_engine_accepts_optional_incident_correlation(self):
        region = self._region(
            "async def _safe_manual_failover(",
            "async def _activate_standby_for_filtered_edge",
        )
        self.assertIn("incident_id=None", region)
        self.assertIn("failover_label += f", region)
        self.assertIn('"operation_id": operation_id', region)


if __name__ == "__main__":
    unittest.main()
