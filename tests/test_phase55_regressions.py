import ast
import pathlib
import unittest


BOT_PATH = pathlib.Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"


class Phase55UserCreationRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)

    def test_phase55_features_survive_current_version(self):
        self.assertIn("BOT_VERSION_TAG =", self.source)
        create_button = self.source.index('callback_data="mza_create"')
        users_button = self.source.index('callback_data="mza_users_0"')
        self.assertLess(create_button, users_button)
        self.assertIn("mza_create_confirm_", self.source)

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

    def test_confirm_expires_and_never_double_answers_callback(self):
        self.assertIn("draft_age > 1800", self.source)
        self.assertIn('"started_at": time.time()', self.source)
        create_start = self.source.index("elif d.startswith('mza_create_confirm_'):")
        create_end = self.source.index("elif d == 'mza_nodes':", create_start)
        create_region = self.source[create_start:create_end]
        self.assertNotIn("await query.answer(", create_region)

    def test_subscription_name_is_mirrored_to_marzban_note(self):
        self.assertIn('note=draft.get("subscription_name") or ""', self.source)
        self.assertIn("unverified_subname = draft.get(\"subscription_name\")", self.source)

    def test_subscription_name_is_saved_without_fake_sales_row(self):
        self.assertIn("_db_set_subscription_name, username, subname", self.source)
        create_start = self.source.index("elif d.startswith('mza_create_confirm_'):")
        create_end = self.source.index("elif d == 'mza_nodes':", create_start)
        create_region = self.source[create_start:create_end]
        self.assertNotIn("_db_finalize_v2ray_user", create_region)
        self.assertNotIn("INSERT INTO ssh_accounts", create_region)

    def test_jalali_conversion_handles_normal_and_esfand_dates(self):
        wanted_functions = {
            "_idiv",
            "_imod",
            "_jal_cal",
            "_gregorian_to_jdn",
            "_mza_jdn_to_gregorian",
            "_mza_jalali_to_gregorian",
        }
        nodes = []
        for node in self.tree.body:
            if isinstance(node, ast.Assign):
                if any(
                    isinstance(target, ast.Name) and target.id == "_JALALI_BREAKS"
                    for target in node.targets
                ):
                    nodes.append(node)
            elif isinstance(node, ast.FunctionDef) and node.name in wanted_functions:
                nodes.append(node)

        module = ast.Module(body=nodes, type_ignores=[])
        ast.fix_missing_locations(module)
        namespace = {}
        exec(compile(module, str(BOT_PATH), "exec"), namespace)

        convert = namespace["_mza_jalali_to_gregorian"]
        self.assertEqual(convert(1405, 7, 10), (2026, 10, 2))
        self.assertEqual(convert(1405, 9, 15), (2026, 12, 6))
        self.assertEqual(convert(1404, 12, 29), (2026, 3, 20))
        with self.assertRaises(ValueError):
            convert(1404, 12, 30)

    def test_create_text_states_are_admin_only(self):
        self.assertIn("if state in _MZA_CREATE_TEXT_STATES:", self.source)
        self.assertIn("MZA_CREATE_USERNAME_INPUT", self.source)
        self.assertIn("MZA_CREATE_SUBNAME_INPUT", self.source)
        self.assertIn("MZA_CREATE_VOLUME_INPUT", self.source)
        self.assertIn("MZA_CREATE_DAYS_INPUT", self.source)
        self.assertIn("MZA_CREATE_DATE_INPUT", self.source)


if __name__ == "__main__":
    unittest.main()
