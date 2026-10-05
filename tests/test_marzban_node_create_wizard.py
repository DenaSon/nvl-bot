import pathlib
import unittest


BOT_PATH = pathlib.Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"


class MarzbanNodeCreateWizardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")

    def _region(self, start, end):
        a = self.source.index(start)
        b = self.source.index(end, a)
        return self.source[a:b]

    def test_node_list_exposes_create_entry_without_losing_empty_state(self):
        region = self._region(
            "async def _show_marzban_nodes",
            "async def _show_marzban_node_detail",
        )
        self.assertIn("➕ افزودن نود جدید", region)
        self.assertIn('callback_data="mza_ncreate"', region)
        self.assertIn("node_buttons = []", region)
        self.assertIn("if not node_buttons:", region)
        self.assertIn("هیچ نودی ثبت نشده است.", region)

    def test_wizard_has_all_text_input_stages(self):
        for state in (
            "MZA_NODE_CREATE_NAME_INPUT",
            "MZA_NODE_CREATE_ADDRESS_INPUT",
            "MZA_NODE_CREATE_PORTS_INPUT",
            "MZA_NODE_CREATE_RATIO_INPUT",
        ):
            self.assertIn(state, self.source)
        self.assertIn("_MZA_NODE_CREATE_TEXT_STATES", self.source)
        self.assertIn("_mza_node_create_draft", self.source)
        self.assertIn("_mza_clear_node_create", self.source)

    def test_wizard_collects_official_marzban_node_create_fields(self):
        region = self._region(
            "async def _mza_show_node_create_review",
            "_MZA_CREATE_TEXT_STATES =",
        )
        for token in (
            'draft.get("name")',
            'draft.get("address")',
            'draft.get("port", 62050)',
            'draft.get("api_port", 62051)',
            'draft.get("usage_coefficient", 1.0)',
            'draft.get("add_as_new_host", True)',
            "Add as New Host",
        ):
            self.assertIn(token, region)

    def test_add_as_new_host_has_explicit_yes_no_choice(self):
        self.assertIn('callback_data="mza_ncreate_host_yes"', self.source)
        self.assertIn('callback_data="mza_ncreate_host_no"', self.source)
        self.assertIn(
            "draft[\"add_as_new_host\"] = d == 'mza_ncreate_host_yes'",
            self.source,
        )

    def test_confirm_uses_nonce_expiry_and_double_submit_guard(self):
        region = self._region(
            "elif d.startswith('mza_ncreate_confirm_'):",
            "elif d == 'mza_nodes':",
        )
        self.assertIn("confirm_nonce", region)
        self.assertIn("draft_age > 1800", region)
        self.assertIn("mza_node_create_busy", region)
        self.assertIn("درخواست ساخت قبلی هنوز در حال پردازش است", region)

    def test_confirm_calls_service_layer_not_raw_node_post(self):
        region = self._region(
            "elif d.startswith('mza_ncreate_confirm_'):",
            "elif d == 'mza_nodes':",
        )
        self.assertIn("service = await _get_marzban_admin_service()", region)
        self.assertIn("ok_create, result = await service.create_node(", region)
        self.assertIn('add_as_new_host=payload["add_as_new_host"]', region)
        self.assertNotIn('api_request("POST", "/api/node"', region)

    def test_post_success_verify_failure_is_never_blindly_retried(self):
        region = self._region(
            "elif d.startswith('mza_ncreate_confirm_'):",
            "elif d == 'mza_nodes':",
        )
        self.assertIn("created_but_unverified", region)
        self.assertIn('bool(result.get("created"))', region)
        self.assertIn("POST دوباره اجرا نمی‌شود", region)
        uncertain_start = region.index("if created_but_unverified:")
        uncertain_end = region.index("context.user_data.pop", uncertain_start)
        uncertain_region = region[uncertain_start:uncertain_end]
        self.assertNotIn("service.create_node(", uncertain_region)

    def test_create_callbacks_remain_admin_only(self):
        guard = self.source.index("if d.startswith('mza_') and role != 'admin':")
        create = self.source.index("elif d == 'mza_ncreate':")
        confirm = self.source.index("elif d.startswith('mza_ncreate_confirm_'):")
        self.assertLess(guard, create)
        self.assertLess(guard, confirm)

    def test_leaving_node_create_flow_clears_pending_draft(self):
        region = self._region(
            "# Leaving a text-input screen through an inline button",
            "# Confirmation messages can outlive the screen",
        )
        self.assertIn("node_create_starter", region)
        self.assertIn("_mza_clear_node_create(context)", region)

    def test_origin_aware_navigation_is_preserved(self):
        region = self._region(
            "elif d.startswith('mza_ncreate_confirm_'):",
            "elif d == 'mza_nodes':",
        )
        self.assertIn("_mza_nodes_list_callback(context)", region)
        self.assertIn("mza_ncreate_cancel", self.source)


if __name__ == "__main__":
    unittest.main()
