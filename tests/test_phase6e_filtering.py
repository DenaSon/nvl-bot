import pathlib
import unittest

from checkhost_probe import TcpNodeEvidence
from edge_observability import (
    DIAG_ALL_PATHS_HEALTHY,
    DIAG_EXTERNAL_REACHABILITY_FAILURE,
    DIAG_FILTER_SUSPECTED,
    DIAG_REGIONAL_REACHABILITY_FAILURE,
    FILTER_CONFIDENCE_HIGH,
    FILTER_CONFIDENCE_LOW,
    FILTER_CONFIDENCE_MEDIUM,
    FILTER_STATE_CLEAR,
    FILTER_STATE_LIKELY,
    FILTER_STATE_POSSIBLE,
    FILTER_STATE_UNKNOWN,
    derive_observability,
)
from regional_filtering import (
    REGIONAL_REASON_DIVERSE_FAILURE,
    REGIONAL_REASON_HEALTHY_QUORUM,
    REGIONAL_REASON_INSUFFICIENT_COVERAGE,
    REGIONAL_REASON_LIMITED_FAILURE,
    REGIONAL_REASON_MAJORITY_DIVERSE_FAILURE,
    REGIONAL_STATE_CLEAR,
    REGIONAL_STATE_LIKELY,
    REGIONAL_STATE_POSSIBLE,
    REGIONAL_STATE_UNKNOWN,
    classify_regional_evidence,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]
CLASSIFIER_PATH = ROOT / "regional_filtering.py"


def evidence(
    *,
    ok,
    node,
    city,
    asn,
    pending=False,
):
    return TcpNodeEvidence(
        node=node,
        country_code="ir",
        country="Iran",
        city=city,
        ip="192.0.2.1",
        asn=asn,
        ok=ok,
        pending=pending,
        latency_ms=80.0 if ok is True else None,
        address="203.0.113.10" if ok is True else None,
        error="timeout" if ok is False else None,
    )


def iran_round(failed_indexes=(), pending_indexes=()):
    cities = [
        "Tehran",
        "Isfahan",
        "Shiraz",
        "Shiraz",
        "Tehran",
        "Qom",
        "Tehran",
        "Tehran",
    ]
    asns = [
        "AS47430",
        "AS209279",
        "AS213953",
        "AS212077",
        "AS214431",
        "AS206596",
        "AS213727",
        "AS214361",
    ]
    failed_indexes = set(failed_indexes)
    pending_indexes = set(pending_indexes)
    rows = []
    for i in range(8):
        if i in pending_indexes:
            ok = None
            pending = True
        else:
            ok = i not in failed_indexes
            pending = False
        rows.append(
            evidence(
                ok=ok,
                node=f"ir{i + 1}.node.check-host.net",
                city=cities[i],
                asn=asns[i],
                pending=pending,
            )
        )
    return tuple(rows)


class Phase6ERegionalRoundClassifierTests(unittest.TestCase):
    def test_all_eight_iran_nodes_healthy_is_clear(self):
        d = classify_regional_evidence(iran_round())
        self.assertEqual(d.state, REGIONAL_STATE_CLEAR)
        self.assertEqual(d.reason, REGIONAL_REASON_HEALTHY_QUORUM)
        self.assertTrue(d.regional_service_ok)
        self.assertEqual(d.summary.completed_nodes, 8)
        self.assertEqual(len(d.summary.completed_asns), 8)
        self.assertEqual(len(d.summary.completed_cities), 4)

    def test_single_failed_node_is_limited_failure_but_still_clear(self):
        d = classify_regional_evidence(iran_round(failed_indexes={0}))
        self.assertEqual(d.state, REGIONAL_STATE_CLEAR)
        self.assertEqual(d.reason, REGIONAL_REASON_LIMITED_FAILURE)
        self.assertTrue(d.regional_service_ok)
        self.assertEqual(d.summary.failed_nodes, 1)

    def test_two_failed_independent_asns_is_possible(self):
        d = classify_regional_evidence(iran_round(failed_indexes={0, 1}))
        self.assertEqual(d.state, REGIONAL_STATE_POSSIBLE)
        self.assertEqual(d.reason, REGIONAL_REASON_DIVERSE_FAILURE)
        self.assertFalse(d.regional_service_ok)
        self.assertEqual(d.summary.failed_nodes, 2)
        self.assertEqual(len(d.summary.failed_asns), 2)
        self.assertAlmostEqual(d.summary.failure_ratio, 0.25)

    def test_four_of_eight_failures_is_possible_not_likely(self):
        d = classify_regional_evidence(iran_round(failed_indexes={0, 1, 2, 5}))
        self.assertEqual(d.state, REGIONAL_STATE_POSSIBLE)
        self.assertEqual(d.summary.failed_nodes, 4)
        self.assertAlmostEqual(d.summary.failure_ratio, 0.5)

    def test_five_of_eight_diverse_failures_is_likely(self):
        d = classify_regional_evidence(iran_round(failed_indexes={0, 1, 2, 4, 5}))
        self.assertEqual(d.state, REGIONAL_STATE_LIKELY)
        self.assertEqual(d.reason, REGIONAL_REASON_MAJORITY_DIVERSE_FAILURE)
        self.assertFalse(d.regional_service_ok)
        self.assertEqual(d.summary.failed_nodes, 5)
        self.assertGreaterEqual(len(d.summary.failed_asns), 4)
        self.assertGreaterEqual(len(d.summary.failed_cities), 2)

    def test_pending_nodes_are_unknown_not_failures(self):
        d = classify_regional_evidence(
            iran_round(pending_indexes={0, 1, 2, 3, 4})
        )
        self.assertEqual(d.state, REGIONAL_STATE_UNKNOWN)
        self.assertEqual(d.reason, REGIONAL_REASON_INSUFFICIENT_COVERAGE)
        self.assertIsNone(d.regional_service_ok)
        self.assertEqual(d.summary.failed_nodes, 0)
        self.assertEqual(d.summary.pending_nodes, 5)

    def test_insufficient_asn_diversity_is_unknown(self):
        rows = tuple(
            evidence(
                ok=True,
                node=f"n{i}",
                city="Tehran" if i < 2 else "Shiraz",
                asn="AS1",
            )
            for i in range(4)
        )
        d = classify_regional_evidence(rows)
        self.assertEqual(d.state, REGIONAL_STATE_UNKNOWN)
        self.assertEqual(d.reason, REGIONAL_REASON_INSUFFICIENT_COVERAGE)

    def test_two_failures_same_asn_do_not_become_possible(self):
        rows = list(iran_round())
        rows[0] = evidence(
            ok=False, node="ir1", city="Tehran", asn="AS-X"
        )
        rows[1] = evidence(
            ok=False, node="ir2", city="Isfahan", asn="AS-X"
        )
        d = classify_regional_evidence(rows)
        self.assertEqual(d.state, REGIONAL_STATE_CLEAR)
        self.assertEqual(d.reason, REGIONAL_REASON_LIMITED_FAILURE)

    def test_classifier_is_provider_neutral_and_side_effect_free(self):
        source = CLASSIFIER_PATH.read_text(encoding="utf-8")
        for forbidden in (
            "check-host.net",
            "urllib",
            "requests.",
            "aiohttp",
            "sqlite3",
            "_db_",
            "_update_cloudflare_dns",
            "_activate_standby_for_filtered_edge",
            "_db_set_all_accounts_host",
            "promote_edge_to_core",
            "demote_core_to_edge",
        ):
            self.assertNotIn(forbidden, source)


class Phase6EObservabilityIntegrationTests(unittest.TestCase):
    def test_possible_round_does_not_escalate_even_with_long_failure_streak(self):
        d = derive_observability(
            True,
            True,
            True,
            True,
            True,
            False,
            regional_failure_streak=10,
            confirm_threshold=3,
            regional_filter_state=REGIONAL_STATE_POSSIBLE,
        )
        self.assertEqual(d.diagnostic_reason, DIAG_REGIONAL_REACHABILITY_FAILURE)
        self.assertFalse(d.filter_suspected)
        self.assertEqual(d.filter_confidence, FILTER_CONFIDENCE_LOW)
        self.assertEqual(d.filter_state, FILTER_STATE_POSSIBLE)

    def test_likely_round_before_temporal_threshold_is_only_possible_final_state(self):
        d = derive_observability(
            True,
            True,
            True,
            True,
            True,
            False,
            regional_failure_streak=1,
            confirm_threshold=3,
            regional_filter_state=REGIONAL_STATE_LIKELY,
        )
        self.assertEqual(d.diagnostic_reason, DIAG_REGIONAL_REACHABILITY_FAILURE)
        self.assertFalse(d.filter_suspected)
        self.assertEqual(d.filter_confidence, FILTER_CONFIDENCE_MEDIUM)
        self.assertEqual(d.filter_state, FILTER_STATE_POSSIBLE)

    def test_repeated_likely_round_with_external_success_becomes_high_confidence_likely(self):
        d = derive_observability(
            True,
            True,
            True,
            True,
            True,
            False,
            regional_failure_streak=3,
            confirm_threshold=3,
            regional_filter_state=REGIONAL_STATE_LIKELY,
        )
        self.assertEqual(d.diagnostic_reason, DIAG_FILTER_SUSPECTED)
        self.assertTrue(d.filter_suspected)
        self.assertEqual(d.filter_confidence, FILTER_CONFIDENCE_HIGH)
        self.assertEqual(d.filter_state, FILTER_STATE_LIKELY)

    def test_repeated_likely_round_without_external_control_is_still_high_confidence(self):
        d = derive_observability(
            True,
            True,
            True,
            True,
            None,
            False,
            regional_failure_streak=3,
            confirm_threshold=3,
            regional_filter_state=REGIONAL_STATE_LIKELY,
        )
        self.assertEqual(d.diagnostic_reason, DIAG_FILTER_SUSPECTED)
        self.assertTrue(d.filter_suspected)
        self.assertEqual(d.filter_confidence, FILTER_CONFIDENCE_HIGH)
        self.assertEqual(d.filter_state, FILTER_STATE_LIKELY)

    def test_external_failure_is_diagnostic_only_and_does_not_erase_regional_filter(self):
        d = derive_observability(
            True,
            True,
            True,
            True,
            False,
            False,
            regional_failure_streak=5,
            confirm_threshold=3,
            regional_filter_state=REGIONAL_STATE_LIKELY,
        )
        self.assertEqual(d.diagnostic_reason, DIAG_EXTERNAL_REACHABILITY_FAILURE)
        self.assertTrue(d.filter_suspected)
        self.assertEqual(d.filter_confidence, FILTER_CONFIDENCE_HIGH)
        self.assertEqual(d.filter_state, FILTER_STATE_LIKELY)

    def test_wireguard_failure_is_diagnostic_only_for_regional_filter(self):
        d = derive_observability(
            True,
            True,
            False,
            False,
            True,
            False,
            regional_failure_streak=3,
            confirm_threshold=3,
            regional_filter_state=REGIONAL_STATE_LIKELY,
        )
        self.assertEqual(d.diagnostic_reason, "WIREGUARD_PATH_FAILURE")
        self.assertTrue(d.filter_suspected)
        self.assertEqual(d.filter_confidence, FILTER_CONFIDENCE_HIGH)
        self.assertEqual(d.filter_state, FILTER_STATE_LIKELY)

    def test_regional_recovery_does_not_require_local_paths_to_be_healthy(self):
        d = derive_observability(
            True,
            True,
            False,
            False,
            False,
            True,
            regional_success_streak=2,
            recovery_threshold=2,
            previous_filter_suspected=True,
            regional_filter_state=REGIONAL_STATE_CLEAR,
        )
        self.assertFalse(d.filter_suspected)
        self.assertEqual(d.filter_state, FILTER_STATE_CLEAR)
        self.assertEqual(d.diagnostic_reason, "WIREGUARD_PATH_FAILURE")

    def test_unknown_regional_round_stays_unknown(self):
        d = derive_observability(
            True,
            True,
            True,
            True,
            True,
            None,
            regional_filter_state=REGIONAL_STATE_UNKNOWN,
        )
        self.assertEqual(d.filter_state, FILTER_STATE_UNKNOWN)
        self.assertIsNone(d.filter_suspected)

    def test_clear_round_maps_to_clear_state(self):
        d = derive_observability(
            True,
            True,
            True,
            True,
            True,
            True,
            regional_success_streak=1,
            regional_filter_state=REGIONAL_STATE_CLEAR,
        )
        self.assertEqual(d.diagnostic_reason, DIAG_ALL_PATHS_HEALTHY)
        self.assertFalse(d.filter_suspected)
        self.assertEqual(d.filter_state, FILTER_STATE_CLEAR)

    def test_confirmed_filter_stays_likely_until_recovery_threshold(self):
        sticky = derive_observability(
            True,
            True,
            True,
            True,
            True,
            True,
            regional_success_streak=1,
            recovery_threshold=2,
            previous_filter_suspected=True,
            regional_filter_state=REGIONAL_STATE_CLEAR,
        )
        self.assertTrue(sticky.filter_suspected)
        self.assertEqual(sticky.filter_state, FILTER_STATE_LIKELY)

        recovered = derive_observability(
            True,
            True,
            True,
            True,
            True,
            True,
            regional_success_streak=2,
            recovery_threshold=2,
            previous_filter_suspected=True,
            regional_filter_state=REGIONAL_STATE_CLEAR,
        )
        self.assertFalse(recovered.filter_suspected)
        self.assertEqual(recovered.filter_state, FILTER_STATE_CLEAR)

    def test_legacy_phase6c_caller_remains_backwards_compatible(self):
        d = derive_observability(
            True,
            True,
            True,
            True,
            True,
            False,
            regional_failure_streak=3,
            confirm_threshold=3,
        )
        self.assertTrue(d.filter_suspected)
        self.assertEqual(d.filter_confidence, FILTER_CONFIDENCE_HIGH)
        self.assertEqual(d.filter_state, FILTER_STATE_LIKELY)


if __name__ == "__main__":
    unittest.main()
