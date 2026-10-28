"""Phase-8 fault matrix manifest integrity and explicit selection tests."""
import unittest

from cloudzy_phase8_matrix import SCENARIOS, build_suite, main


class Phase8MatrixTests(unittest.TestCase):
    def test_scenarios_are_unique_traceable_and_cover_required_boundaries(self):
        names = [s.boundary for s in SCENARIOS]
        self.assertEqual(len(names), len(set(names)))
        self.assertGreaterEqual(len(names), 25)
        self.assertEqual({s.stage for s in SCENARIOS}, {
            "PURCHASE", "INSTALL", "STANDBY", "DNS", "MIGRATION",
            "BUSINESS", "TELEGRAM", "FIELD_GATE",
        })
        self.assertTrue(all(s.test_id.startswith("tests.test_cloudzy_")
                            for s in SCENARIOS))

    def test_every_scenario_resolves_to_exactly_one_real_unit_case(self):
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario.boundary):
                suite = build_suite(names=(scenario.boundary,))
                self.assertEqual(suite.countTestCases(), 1)

    def test_invalid_selection_is_denied(self):
        with self.assertRaisesRegex(ValueError, "PHASE8_UNKNOWN_SCENARIO"):
            build_suite(names=("BUY_WITHOUT_APPROVAL",))
        self.assertEqual(main(["--scenario", "BUY_WITHOUT_APPROVAL"]), 2)

    def test_selected_hermetic_scenario_can_run_without_live_provider(self):
        self.assertEqual(main([
            "--scenario", "NATIVE_AND_UNIFIED_COMMIT_FAIL",
            "--scenario", "NO_SELF_ATTESTED_CLIENT_PROOF",
        ]),0)


if __name__=="__main__":
    unittest.main()
