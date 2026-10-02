import ast
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
BOT_PATH = ROOT / "bot_final_v49-2.py"


class Phase6BUnifiedHealthModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)

        selected = []
        for node in cls.tree.body:
            if isinstance(node, ast.Assign):
                names = [
                    target.id
                    for target in node.targets
                    if isinstance(target, ast.Name)
                ]
                if any(
                    name.startswith("HEALTH_STATE_")
                    or name.startswith("HEALTH_REASON_")
                    for name in names
                ):
                    selected.append(node)
            elif isinstance(node, ast.FunctionDef) and node.name == "_derive_host_health_state":
                selected.append(node)

        module = ast.Module(body=selected, type_ignores=[])
        ast.fix_missing_locations(module)
        cls.ns = {}
        exec(compile(module, "<phase6b-health-model>", "exec"), cls.ns)
        cls.derive = cls.ns["_derive_host_health_state"]

    def test_v114_marker_is_present(self):
        self.assertIn(
            'BOT_VERSION_TAG = "V114-2026-10-02-phase6b-unified-health-model"',
            self.source,
        )

    def test_schema_is_additive_and_typed(self):
        for column in (
            "service_ok",
            "admin_ok",
            "health_state",
            "health_reason",
            "health_updated_at",
            "health_since",
            "last_success_at",
        ):
            self.assertIn(
                f"ALTER TABLE host_pool ADD COLUMN {column}",
                self.source,
            )

    def test_classifier_unknown_when_evidence_is_incomplete(self):
        expected = ("UNKNOWN", "INSUFFICIENT_EVIDENCE")
        self.assertEqual(self.derive(None, None), expected)
        self.assertEqual(self.derive(True, None), expected)
        self.assertEqual(self.derive(None, True), expected)
        self.assertEqual(self.derive(False, None), expected)
        self.assertEqual(self.derive(None, False), expected)

    def test_classifier_healthy(self):
        self.assertEqual(
            self.derive(True, True),
            ("HEALTHY", "ALL_CHECKS_PASS"),
        )

    def test_classifier_degraded_when_only_admin_is_down(self):
        self.assertEqual(
            self.derive(True, False),
            ("DEGRADED", "ADMIN_SSH_DOWN"),
        )

    def test_classifier_unhealthy_when_service_is_down_but_admin_is_up(self):
        self.assertEqual(
            self.derive(False, True),
            ("UNHEALTHY", "SERVICE_DOWN"),
        )

    def test_classifier_offline_when_both_planes_are_down(self):
        self.assertEqual(
            self.derive(False, False),
            ("OFFLINE", "SERVICE_AND_ADMIN_DOWN"),
        )

    def test_classifier_does_not_parse_human_status_text(self):
        node = next(
            node
            for node in self.tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_derive_host_health_state"
        )
        region = ast.get_source_segment(self.source, node) or ""
        self.assertNotIn("service_last_status", region)
        self.assertNotIn("admin_last_status", region)
        self.assertNotIn("سالم", region)
        self.assertNotIn("ناموفق", region)

    def test_service_probe_persists_typed_evidence_and_last_success(self):
        start = self.source.index("def _db_record_host_check(")
        end = self.source.index("def _db_record_admin_host_check(", start)
        region = self.source[start:end]
        self.assertIn("service_ok=1", region)
        self.assertIn("service_ok=0", region)
        self.assertIn("last_success_at=?", region)
        self.assertIn("_db_recompute_host_health(host)", region)

    def test_admin_probe_persists_typed_evidence(self):
        start = self.source.index("def _db_record_admin_host_check(")
        end = self.source.index("def _db_set_host_active(", start)
        region = self.source[start:end]
        self.assertIn("admin_ok=1", region)
        self.assertIn("admin_ok=0", region)
        self.assertIn("_db_recompute_host_health(host)", region)
        self.assertNotIn("_db_set_host_active", region)

    def test_health_since_only_resets_on_state_transition(self):
        start = self.source.index("def _db_recompute_host_health(")
        end = self.source.index("def _db_get_host_port_health_map(", start)
        region = self.source[start:end]
        self.assertIn("changed = previous_state != new_state", region)
        self.assertIn(
            "health_since = now if changed or not previous_since else previous_since",
            region,
        )
        self.assertIn("health_updated_at=?", region)

    def test_phase6b_does_not_replace_existing_service_failover_threshold(self):
        start = self.source.index("async def _host_health_tick(app):")
        end = self.source.index("async def _host_health_loop(app):", start)
        region = self.source[start:end]
        self.assertIn(
            "if service_ok or new_fails < HOST_HEALTH_FAIL_THRESHOLD:",
            region,
        )
        self.assertIn("_db_set_host_active", region)
        self.assertNotIn("if overall_state", region)
        self.assertNotIn("if health_state", region)

    def test_monitoring_panel_shows_overall_state_and_membership_separately(self):
        start = self.source.index("async def _render_host_pool_panel(query):")
        end = self.source.index("async def _host_has_working_persistent_key", start)
        region = self.source[start:end]
        self.assertIn("Overall: <b>{esc(overall_state)}</b>", region)
        self.assertIn("health_reason", region)
        self.assertIn('membership = "ACTIVE" if active else "INACTIVE"', region)
        self.assertIn("آخرین موفقیت Service", region)

    def test_latency_is_evidence_only_not_a_classifier_input_yet(self):
        node = next(
            node
            for node in self.tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_derive_host_health_state"
        )
        region = ast.get_source_segment(self.source, node) or ""
        self.assertNotIn("latency", region)


if __name__ == "__main__":
    unittest.main()
