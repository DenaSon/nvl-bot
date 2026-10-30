"""Fail-closed CI selection must never silently skip an unknown source change."""
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from ops.ci_test_selector import decide, make_plan


ALL = {
    "test_manual_edge_phase3.py",
    "test_manual_edge_html_ui.py",
    "test_manual_quick_switch.py",
    "test_manual_quick_switch_ui.py",
    "test_legacy_manual_host_registration.py",
    "test_nvl_legacy_manual_route_audit.py",
    "test_edge_egress_provision.py",
    "test_edge_egress_k2_release_bundle.py",
    "test_edge_egress_k2_runtime_release.py",
    "test_edge_egress_k2_canary_backup_gate.py",
    "test_edge_egress_shared_lock.py",
    "test_edge_egress_uid_dns.py",
    "test_cloudzy_cz07_acceptance.py",
    "test_cloudzy_cz04a.py",
    "test_marzban_node_bootstrap.py",
    "test_radar_runtime.py",
    "test_incident_correlation.py",
    "test_ci_test_selector.py",
}


class TestImpactSelector(TestCase):
    def decide(self, *changes):
        return decide(list(changes), ALL)

    def test_manual_edge_edit_selects_relevant_suite_not_all(self):
        mode, selected, root, reason = self.decide("manual_edge_html.py")
        self.assertEqual(mode, "targeted")
        self.assertIn("test_manual_edge_phase3.py", selected)
        self.assertIn("test_manual_quick_switch_ui.py", selected)
        self.assertLess(len(selected), len(ALL))
        self.assertIn("test_manual_edge_phase3.py", root)
        self.assertIn("test_edge_egress_k2_release_bundle.py", root)

    def test_quick_switch_and_legacy_registration_cover_related_tests(self):
        for file in ("manual_quick_switch.py",
                     "legacy_manual_host_registration.py"):
            with self.subTest(file=file):
                mode, tests, _, _ = self.decide(file)
                self.assertEqual(mode, "targeted")
                self.assertIn("test_manual_quick_switch.py", tests)

    def test_egress_and_cloudzy_are_separately_targeted(self):
        mode, tests, roots, _ = self.decide("edge_egress_uid_dns.py")
        self.assertEqual(mode, "targeted")
        self.assertIn("test_edge_egress_uid_dns.py", tests)
        self.assertIn("test_edge_egress_provision.py", roots)
        mode, tests, roots, _ = self.decide("cloudzy_cz07_queue.py")
        self.assertEqual(mode, "targeted")
        self.assertIn("test_cloudzy_cz07_acceptance.py", tests)
        self.assertIn("test_manual_quick_switch.py", tests)
        self.assertIn("test_cloudzy_cz07_acceptance.py", roots)

    def test_changed_test_only_runs_that_file(self):
        mode, tests, roots, _ = self.decide(
            "tests/test_manual_edge_html_ui.py")
        self.assertEqual(mode, "targeted")
        self.assertEqual(tests, ["test_manual_edge_html_ui.py"])
        self.assertIn("test_edge_egress_k2_release_bundle.py", roots)

    def test_critical_test_only_still_runs_privileged_copy(self):
        _, tests, roots, _ = self.decide(
            "tests/test_edge_egress_provision.py")
        self.assertEqual(tests, ["test_edge_egress_provision.py"])
        self.assertIn("test_edge_egress_provision.py", roots)

    def test_multi_domain_union_has_no_duplicates(self):
        mode, tests, roots, _ = self.decide(
            "manual_edge_wizard.py", "cloudzy_cz07_queue.py")
        self.assertEqual(mode, "targeted")
        self.assertIn("test_cloudzy_cz04a.py", tests)
        self.assertIn("test_manual_edge_phase3.py", tests)
        self.assertEqual(len(tests), len(set(tests)))
        self.assertEqual(len(roots), len(set(roots)))

    def test_unclassified_or_shared_changes_force_full(self):
        for path in ("bot_final_v49-2.py", "requirements.txt",
                     ".github/workflows/python-checks.yml",
                     "ops/ci_test_selector.py", "brand_new_module.py",
                     "server_migration/core.py",
                     "tests/support/fake_egress_command.py",
                     "ops/edge_egress_host_worker.py"):
            with self.subTest(file=path):
                mode, tests, root, _ = self.decide(path)
                self.assertEqual(mode, "full")
                self.assertEqual(len(tests), len(ALL))
                self.assertEqual(len(root), len(ALL))

    def test_removed_test_fails_closed(self):
        mode, _, _, _ = self.decide("tests/test_removed_module.py")
        self.assertEqual(mode, "full")

    def test_no_matching_domain_tests_fails_closed(self):
        mode, _, _, _ = decide(["marzban_node_bootstrap.py"],
                               {"test_unrelated.py"})
        self.assertEqual(mode, "full")

    def test_documentation_only_skips_unit_tests_not_release_checks(self):
        mode, tests, root, _ = self.decide(
            "README.md", "docs/NVL_EDGE_GUIDE.md")
        self.assertEqual((mode, tests, root), ("skip", [], []))

    def test_invalid_or_unavailable_diff_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / "tests"
            d.mkdir()
            (d / "test_x.py").write_text("pass", encoding="utf-8")
            with patch("ops.ci_test_selector.changed_files",
                       side_effect=ValueError("invalid sha")):
                plan = make_plan("pull_request", "bad", "bad", Path(td))
            self.assertEqual(plan["mode"], "full")
            self.assertEqual(plan["tests"], ["test_x.py"])

    def test_daily_and_manual_always_full(self):
        with tempfile.TemporaryDirectory() as td:
            d=Path(td)/"tests"
            d.mkdir()
            (d/"test_x.py").write_text("pass",encoding="utf-8")
            for event in ("schedule","workflow_dispatch"):
                with self.subTest(event=event):
                    plan=make_plan(event,"","",Path(td))
                    self.assertEqual(plan["mode"],"full")
                    self.assertEqual(plan["tests"],["test_x.py"])
                    self.assertEqual(plan["root"],["test_x.py"])
