import ast
import pathlib
import unittest


BOT_PATH = pathlib.Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"


class Phase4NodeManagementRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)

    def test_node_detail_renderer_exists(self):
        names = {
            node.name
            for node in self.tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        self.assertIn("_show_marzban_nodes", names)
        self.assertIn("_show_marzban_node_detail", names)
        self.assertIn("_mza_show_node_edit_confirm", names)

    def test_node_callbacks_remain_behind_admin_guard(self):
        guard = self.source.index("if d.startswith('mza_') and role != 'admin':")
        node_detail = self.source.index("elif d.startswith('mza_node_'):")
        node_status = self.source.index("elif d.startswith('mza_ntoggle_'):")
        node_edit = self.source.index("elif d.startswith('mza_nedit_confirm_'):")
        self.assertLess(guard, node_detail)
        self.assertLess(guard, node_status)
        self.assertLess(guard, node_edit)

    def test_node_edit_states_are_explicitly_cancelled(self):
        for state in (
            "MZA_NODE_NAME_INPUT",
            "MZA_NODE_ADDRESS_INPUT",
            "MZA_NODE_PORTS_INPUT",
            "MZA_NODE_RATIO_INPUT",
        ):
            self.assertGreaterEqual(self.source.count(state), 3)

    def test_mutations_use_service_layer(self):
        self.assertIn("service.set_node_enabled(node_id, enabling)", self.source)
        self.assertIn("service.reconnect_node(node_id)", self.source)
        self.assertIn("service.update_node_settings(node_id, **pending)", self.source)
        self.assertNotIn('api_request("PUT", f"/api/node/', self.source)

    def test_phase4_version_tag_is_present(self):
        self.assertIn(
            'BOT_VERSION_TAG = "V106-2026-10-02-marzban-node-management"',
            self.source,
        )


if __name__ == "__main__":
    unittest.main()
