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
            "MZA_NODE_CREATE_PUBLIC_INPUT",
            "MZA_NODE_CREATE_PORTS_INPUT",
            "MZA_NODE_CREATE_RATIO_INPUT",
        ):
            self.assertIn(state, self.source)
        self.assertIn("_MZA_NODE_CREATE_TEXT_STATES", self.source)
        self.assertIn("_mza_node_create_draft", self.source)
        self.assertIn("_mza_clear_node_create", self.source)

    def test_wizard_uses_fixed_nvl_public_host_profile(self):
        region = self._region(
            "async def _mza_show_node_create_review",
            "_MZA_CREATE_TEXT_STATES =",
        )
        for token in (
            'draft.get("name")',
            'draft.get("address")',
            'draft.get("public_address")',
            'draft.get("port", 62050)',
            'draft.get("api_port", 62051)',
            'draft.get("usage_coefficient", 1.0)',
            "add_as_new_host=False",
            "NVL_NODE_PUBLIC_HOST_TAGS",
            "Public Host profile · NVL",
        ):
            self.assertIn(token, region)

    def test_old_public_host_callbacks_are_fail_safe(self):
        self.assertIn("d in ('mza_ncreate_host_yes', 'mza_ncreate_host_no')", self.source)
        self.assertIn('draft["add_as_new_host"] = False', self.source)
        self.assertNotIn('InlineKeyboardButton("✅ بله، اضافه کن"', self.source)

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
        self.assertIn("add_as_new_host=False", region)
        self.assertIn("service.reconcile_node_public_hosts(", region)
        self.assertIn("NVL_NODE_PUBLIC_HOST_TAGS", region)
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
            "# 🛡 Central V2Ray authorization boundary.",
        )
        self.assertIn("node_create_starter", region)
        self.assertIn("_mza_clear_node_create(context)", region)

    def test_duplicate_precheck_has_dedicated_no_post_result(self):
        region = self._region(
            "elif d.startswith('mza_ncreate_confirm_'):",
            "elif d == 'mza_nodes':",
        )
        self.assertIn("duplicate_precheck", region)
        self.assertIn('result.get("stage") == "precheck"', region)
        self.assertIn('result.get("duplicate")', region)
        self.assertIn("Duplicate precheck قبل از POST", region)
        self.assertIn("مشاهده Node موجود", region)

    def test_success_exposes_post_create_diagnostics_and_setup(self):
        region = self._region(
            "elif d.startswith('mza_ncreate_confirm_'):",
            "elif d == 'mza_nodes':",
        )
        self.assertIn("Post-create diagnostics", region)
        self.assertIn("diagnostic_label", region)
        self.assertIn("xray_version", region)
        self.assertIn("Public Hosts", region)
        self.assertIn("NVL profile", region)
        self.assertIn('callback_data=f"mza_nsetup_{node_id}"', region)

    def test_node_detail_exposes_certificate_and_setup_entry(self):
        region = self._region(
            "async def _show_marzban_node_detail",
            "_MZA_HOST_EDIT_TOKENS =",
        )
        self.assertIn("📜 راه‌اندازی دستی", region)
        self.assertIn("🚀 راه‌اندازی خودکار", region)
        self.assertIn('callback_data=f"mza_nsetup_{node_id}"', region)

    def test_setup_callback_fetches_official_node_settings(self):
        region = self._region(
            "elif d.startswith('mza_nsetup_'):",
            "elif d == 'mza_inbounds':",
        )
        self.assertIn("service.get_node(node_id)", region)
        self.assertIn("service.get_node_settings()", region)
        self.assertIn("Client Certificate", region)
        self.assertIn("/var/lib/marzban-node/cert.pem", region)
        self.assertIn("SERVICE_PORT=", region)
        self.assertIn("XRAY_API_PORT=", region)
        self.assertIn("SERVICE_PROTOCOL=rest", region)
        self.assertIn("بروزرسانی Diagnostics", region)

    def test_wizard_explains_node_address_without_overloading_screen(self):
        region = self._region(
            "if state in _MZA_NODE_CREATE_TEXT_STATES:",
            "node_input_states = {",
        )
        self.assertIn("مرحله ۲ از ۵ · آدرس واقعی Node", region)
        self.assertIn("خود سرور Node", region)
        self.assertIn("پنل اصلی Marzban", region)
        self.assertIn("203.0.113.20", region)

    def test_wizard_explains_ports_ratio_and_applies_managed_host_policy(self):
        region = self._region(
            "if state in _MZA_NODE_CREATE_TEXT_STATES:",
            "node_input_states = {",
        )
        self.assertIn("مرحله ۴ از ۵ · پورت‌های نود", region)
        self.assertIn("Service Port", region)
        self.assertIn("Xray API Port", region)
        self.assertIn("مرحله ۵ از ۵ · Usage Ratio", region)
        self.assertIn("اگر سیاست خاصی", region)
        self.assertIn('draft["add_as_new_host"] = False', region)
        self.assertIn("_mza_show_node_create_review(update.message, context)", region)
        self.assertIn("مرحله ۳ از ۵ · دامنه عمومی Node", region)
        self.assertIn("argus.nvlsup.xyz", region)

    def test_v123a_rechecks_dns_before_post_and_uses_public_address_for_hosts(self):
        region = self._region(
            "elif d.startswith('mza_ncreate_confirm_'):",
            "elif d == 'mza_nodes':",
        )
        self.assertIn("preflight_public_endpoint", region)
        self.assertIn("DNS Preflight قبل از ساخت", region)
        self.assertIn("public_address=public_address", region)
        preflight_pos = region.index("preflight_public_endpoint")
        post_pos = region.index("service.create_node(")
        self.assertLess(preflight_pos, post_pos)

    def test_v123a_persists_pending_ownership_before_host_write_then_promotes(self):
        region = self._region(
            "elif d.startswith('mza_ncreate_confirm_'):",
            "elif d == 'mza_nodes':",
        )
        first_persist = region.index("_db_upsert_marzban_node_public_profile")
        reconcile_pos = region.index("service.reconcile_node_public_hosts(")
        second_persist = region.index(
            "_db_upsert_marzban_node_public_profile",
            first_persist + 1,
        )
        self.assertLess(first_persist, reconcile_pos)
        self.assertLess(reconcile_pos, second_persist)
        self.assertIn('"pending"', region)
        self.assertIn('"verified"', region)
        self.assertIn("managed_remark", region)
        self.assertIn("Node را دوباره نسازید", region)

    def test_v123b33_schema_and_managed_safe_delete_are_present(self):
        self.assertIn("CREATE TABLE IF NOT EXISTS marzban_node_public_profiles", self.source)
        self.assertIn("profile_state TEXT NOT NULL DEFAULT 'pending'", self.source)
        self.assertIn("_db_get_marzban_node_public_profile", self.source)
        self.assertIn('{"pending", "verified", "deleting"}', self.source)
        self.assertIn("_db_delete_marzban_node_public_profile", self.source)
        delete_region = self._region(
            "elif d.startswith('mza_ndelete_confirm_'):",
            "elif d.startswith('mza_nreconnect_'):",
        )
        self.assertIn("preview_node_public_profile_delete", delete_region)
        self.assertIn("preflight_public_endpoint_detached", delete_region)
        self.assertIn("delete_node_public_profile", delete_region)
        self.assertIn("cleanup_managed_public_hosts", self.source)
        self.assertNotIn("حذف این Node در V123A عمداً قفل است", delete_region)

    def test_node_detail_exposes_permanent_delete_action(self):
        region = self._region(
            "async def _show_marzban_node_detail",
            "_MZA_HOST_EDIT_TOKENS =",
        )
        self.assertIn("🗑 حذف دائمی نود", region)
        self.assertIn('callback_data=f"mza_ndelete_{node_id}"', region)

    def test_node_delete_has_explicit_confirmation_and_verified_service_call(self):
        region = self._region(
            "elif d.startswith('mza_ndelete_confirm_'):",
            "elif d.startswith('mza_nreconnect_'):",
        )
        self.assertIn("mza_node_delete_pending", region)
        self.assertIn("age > 600", region)
        self.assertIn("mza_node_delete_busy", region)
        self.assertIn("ok_delete, result = await service.delete_node(node_id)", region)
        self.assertIn("cleanup_incomplete", region)
        self.assertIn("Public Hostهای باقی‌مانده", region)
        self.assertIn("hosts_deleted", region)
        self.assertIn("خود VPS", region)

    def test_node_delete_previews_and_cascades_only_generated_hosts(self):
        region = self._region(
            "elif d.startswith('mza_ndelete_confirm_'):",
            "elif d.startswith('mza_nreconnect_'):",
        )
        self.assertIn("service.get_hosts()", region)
        self.assertIn("find_node_generated_hosts", region)
        self.assertIn("Public Host مرتبط", region)
        self.assertIn("auto-generated", region)
        self.assertIn("Hostهای دستی یا صرفاً هم‌آدرس حذف نخواهند شد", region)

    def test_delete_verify_uncertainty_never_blindly_retries(self):
        region = self._region(
            "elif d.startswith('mza_ndelete_confirm_'):",
            "elif d.startswith('mza_nreconnect_'):",
        )
        self.assertIn("deleted_but_unverified", region)
        self.assertIn("درخواست DELETE دوباره اجرا نمی‌شود", region)
        uncertain_start = region.index("if deleted_but_unverified:")
        uncertain_end = region.index("await query.edit_message_text(", uncertain_start + 50)
        self.assertNotIn("service.delete_node(", region[uncertain_start:uncertain_end])

    def test_v123b32_unlocks_managed_address_only_through_safe_move_and_keeps_legacy_confirm_locked(self):
        self.assertIn("V123B.3.1 · Rename Managed Node", self.source)
        self.assertIn("mza_nrename_confirm_", self.source)
        self.assertIn("V123B.3.2 · Safe Node Move / Change IP", self.source)
        self.assertIn("MZA_NODE_MOVE_ADDRESS_INPUT", self.source)
        self.assertIn("mza_nmove_confirm_", self.source)
        confirm_region = self._region(
            "elif d.startswith('mza_nedit_confirm_'):",
            "elif d.startswith('mza_hedit_'):",
        )
        self.assertIn("_db_get_marzban_node_public_profile", confirm_region)
        self.assertIn('{"name", "address"}.intersection(pending)', confirm_region)
        self.assertIn("تاییدیه قدیمی اجرا نشد", confirm_region)

    def test_origin_aware_navigation_is_preserved(self):
        region = self._region(
            "elif d.startswith('mza_ncreate_confirm_'):",
            "elif d == 'mza_nodes':",
        )
        self.assertIn("_mza_nodes_list_callback(context)", region)
        self.assertIn("mza_ncreate_cancel", self.source)


if __name__ == "__main__":
    unittest.main()