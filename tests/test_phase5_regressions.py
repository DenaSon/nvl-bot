import ast
import pathlib
import unittest


BOT_PATH = pathlib.Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"


class Phase5InboundHostRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)

    def test_phase5_renderers_exist(self):
        names = {
            node.name
            for node in self.tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        for name in (
            "_show_marzban_inbounds",
            "_show_marzban_inbound_detail",
            "_show_marzban_host_detail",
            "_mza_load_host_target",
            "_mza_show_host_edit_confirm",
        ):
            self.assertIn(name, names)

    def test_inbound_and_host_callbacks_remain_behind_admin_guard(self):
        guard = self.source.index("if d.startswith('mza_') and role != 'admin':")
        inbound_route = self.source.index("elif d == 'mza_inbounds':")
        host_route = self.source.index("elif d.startswith('mza_host_'):")
        host_edit = self.source.index("elif d.startswith('mza_hedit_'):")
        host_confirm = self.source.index("elif d.startswith('mza_hconfirm_'):")
        self.assertLess(guard, inbound_route)
        self.assertLess(guard, host_route)
        self.assertLess(guard, host_edit)
        self.assertLess(guard, host_confirm)

    def test_host_text_state_is_explicitly_cancelled_and_handled(self):
        self.assertGreaterEqual(self.source.count("MZA_HOST_FIELD_INPUT"), 3)
        self.assertIn("_mza_clear_host_pending(context)", self.source)

    def test_node_and_host_confirmation_domains_are_isolated(self):
        self.assertIn("node_edit_starter =", self.source)
        self.assertIn("host_edit_starter = d.startswith('mza_hedit_')", self.source)
        self.assertIn(
            "if not d.startswith('mza_nedit_confirm_') and not node_edit_starter:",
            self.source,
        )
        self.assertIn(
            "if not d.startswith('mza_hconfirm_') and not host_edit_starter:",
            self.source,
        )
        self.assertIn("context.user_data.pop('mza_node_pending_changes', None)", self.source)

    def test_host_mutations_use_service_layer_and_stale_snapshot(self):
        self.assertIn("service.update_host(", self.source)
        self.assertIn("expected_host=pending.get('expected_host')", self.source)
        self.assertIn("marzban_admin.host_snapshot(resolved[\"host\"])", self.source)
        self.assertNotIn('api_request("PUT", "/api/hosts"', self.source)
        self.assertNotIn("api_request('PUT', '/api/hosts'", self.source)

    def test_inbounds_are_read_only_in_phase5_ui(self):
        self.assertIn("service.get_inbounds()", self.source)
        self.assertIn("service.get_hosts()", self.source)
        self.assertNotIn("mza_inbound_delete", self.source)
        self.assertNotIn("mza_inbound_edit", self.source)

    def test_phase5_features_survive_current_version(self):
        self.assertIn("BOT_VERSION_TAG =", self.source)
        self.assertIn("mza_inbounds", self.source)
        self.assertIn("mza_host_", self.source)
        self.assertIn("mza_hedit_", self.source)


if __name__ == "__main__":
    unittest.main()
