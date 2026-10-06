import unittest
from datetime import datetime, timezone

from incident_correlation import (
    CORRELATION_INSUFFICIENT_EVIDENCE,
    CORRELATION_SHARED_NETWORK_FAILURE,
    CORRELATION_TARGET_SPECIFIC_FILTERING,
    CORRELATION_WIDESPREAD_NETWORK_OUTAGE,
    evaluate_incident_correlation,
)


NOW = datetime(2026, 10, 6, 20, 0, tzinfo=timezone.utc)


def radar(state, observed_at="2026-10-06T19:55:00Z"):
    return {
        "state": state,
        "observed_at": observed_at,
    }


class IncidentCorrelationTests(unittest.TestCase):
    def test_fresh_radar_outage_inhibits_auto_even_with_target_specific_diff(self):
        result = evaluate_incident_correlation(
            differential_confirmed=True,
            differential_verdict="TARGET_SPECIFIC_REGIONAL_FAILURE",
            radar_snapshot=radar("OUTAGE"),
            radar_max_age_seconds=1200,
            now=NOW,
        )
        self.assertEqual(
            result.classification,
            CORRELATION_WIDESPREAD_NETWORK_OUTAGE,
        )
        self.assertTrue(result.failover_inhibited)
        self.assertTrue(result.radar_fresh)

    def test_stale_radar_outage_does_not_block_target_specific_diff(self):
        result = evaluate_incident_correlation(
            differential_confirmed=True,
            differential_verdict="TARGET_SPECIFIC_REGIONAL_FAILURE",
            radar_snapshot=radar("OUTAGE", "2026-10-06T19:00:00Z"),
            radar_max_age_seconds=1200,
            now=NOW,
        )
        self.assertEqual(
            result.classification,
            CORRELATION_TARGET_SPECIFIC_FILTERING,
        )
        self.assertFalse(result.failover_inhibited)
        self.assertFalse(result.radar_fresh)

    def test_degraded_radar_does_not_block_target_specific_diff(self):
        result = evaluate_incident_correlation(
            differential_confirmed=True,
            differential_verdict="TARGET_SPECIFIC_REGIONAL_FAILURE",
            radar_snapshot=radar("DEGRADED"),
            now=NOW,
        )
        self.assertEqual(
            result.classification,
            CORRELATION_TARGET_SPECIFIC_FILTERING,
        )
        self.assertFalse(result.failover_inhibited)

    def test_normal_radar_does_not_create_filtering_without_diff(self):
        result = evaluate_incident_correlation(
            differential_confirmed=False,
            differential_verdict="INSUFFICIENT_DIFFERENTIAL_EVIDENCE",
            radar_snapshot=radar("NORMAL"),
            now=NOW,
        )
        self.assertEqual(
            result.classification,
            CORRELATION_INSUFFICIENT_EVIDENCE,
        )
        self.assertFalse(result.failover_inhibited)

    def test_shared_differential_is_shared_failure(self):
        result = evaluate_incident_correlation(
            differential_confirmed=False,
            differential_verdict="SHARED_REGIONAL_FAILURE",
            radar_snapshot=radar("NORMAL"),
            now=NOW,
        )
        self.assertEqual(
            result.classification,
            CORRELATION_SHARED_NETWORK_FAILURE,
        )
        self.assertTrue(result.failover_inhibited)

    def test_missing_radar_never_blocks_valid_target_specific_diff(self):
        result = evaluate_incident_correlation(
            differential_confirmed=True,
            differential_verdict="TARGET_SPECIFIC_REGIONAL_FAILURE",
            radar_snapshot=None,
            now=NOW,
        )
        self.assertEqual(
            result.classification,
            CORRELATION_TARGET_SPECIFIC_FILTERING,
        )
        self.assertFalse(result.failover_inhibited)


if __name__ == "__main__":
    unittest.main()
