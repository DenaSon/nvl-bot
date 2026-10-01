import ast
import pathlib
import unittest


BOT_PATH = pathlib.Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"


class Phase55UserCreationRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)

    def test_v108_marker_and_create_action_exist(self):
        self.assertIn(
            'BOT_VERSION_TAG = "V108-2026-10-02-marzban-user-creation"',
            self.source,
        )
        create_button = self.source.index(
            'InlineKeyboardButton("➕ ساخت کاربر V2Ray", callback_data="mza_create")'
        )
        users_button = self.source.index(
            'InlineKeyboardButton("👥 کاربران", callback_data="mza_users_0")'
        )
        self.assertLess(create_button, users_button)

    def test_create_callbacks_remain_behind_admin_guard(self):
        guard = self.source.index("if d.startswith('mza_') and role != 'admin':")
        create_route = self.source.index("elif d == 'mza_create':")
        confirm_route = self.source.index("elif d.startswith('mza_create_confirm_'):")
        self.assertLess(guard, create_route)
        self.assertLess(guard, confirm_route)

    def test_requested_volume_presets_and_custom_modes_exist(self):
        for callback in (
            "mza_cvol_1",
            "mza_cvol_5",
            "mza_cvol_15",
            "mza_cvol_20",
            "mza_cvol_custom",
            "mza_cvol_unlimited",
        ):
            self.assertIn(callback, self.source)

    def test_expiry_and_first_use_modes_exist(self):
        for token in (
            "mza_cexp_days",
            "mza_cexp_date",
            "mza_cexp_unlimited",
            "mza_cstart_now",
            "mza_cstart_first",
            '"status": "on_hold"',
            "on_hold_expire_duration",
        ):
            self.assertIn(token, self.source)
        self.assertIn("_mza_parse_exact_expiry_date", self.source)
        self.assertIn("_mza_jalali_to_gregorian", self.source)

    def test_dynamic_inbounds_and_manual_selection_exist(self):
        self.assertIn("service.get_inbounds()", self.source)
        self.assertIn("marzban_admin.flatten_marzban_inbounds", self.source)
        self.assertIn("mza_cinb_all", self.source)
        self.assertIn("mza_cinb_manual", self.source)
        self.assertIn("mza_cinbt_", self.source)
        self.assertIn("selected_inbound_tags=selected", self.source)

    def test_confirm_uses_service_layer_and_double_submit_guard(self):
        self.assertIn("service.create_user(", self.source)
        self.assertIn("mza_create_busy", self.source)
        self.assertIn("confirm_nonce", self.source)
        self.assertIn("created_but_unverified", self.source)
        self.assertNotIn('api_request("POST", "/api/user"', self.source)

    def test_subscription_name_is_saved_without_fake_sales_row(self):
        self.assertIn("_db_set_subscription_name, username, subname", self.source)
        create_start = self.source.index("elif d.startswith('mza_create_confirm_'):")
        create_end = self.source.index("elif d == 'mza_nodes':", create_start)
        create_region = self.source[create_start:create_end]
        self.assertNotIn("_db_finalize_v2ray_user", create_region)
        self.assertNotIn("INSERT INTO ssh_accounts", create_region)

    def test_create_text_states_are_admin_only(self):
        self.assertIn("if state in _MZA_CREATE_TEXT_STATES:", self.source)
        self.assertIn("MZA_CREATE_USERNAME_INPUT", self.source)
        self.assertIn("MZA_CREATE_SUBNAME_INPUT", self.source)
        self.assertIn("MZA_CREATE_VOLUME_INPUT", self.source)
        self.assertIn("MZA_CREATE_DAYS_INPUT", self.source)
        self.assertIn("MZA_CREATE_DATE_INPUT", self.source)


if __name__ == "__main__":
    unittest.main()
