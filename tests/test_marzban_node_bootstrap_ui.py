import pathlib
import unittest


BOT_PATH = pathlib.Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"


class MarzbanNodeBootstrapUITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")

    def _region(self, start, end):
        a = self.source.index(start)
        b = self.source.index(end, a)
        return self.source[a:b]

    def test_node_detail_prefers_automatic_setup_but_keeps_manual_fallback(self):
        region = self._region(
            "async def _show_marzban_node_detail",
            "_MZA_HOST_EDIT_TOKENS =",
        )
        self.assertIn("🚀 راه‌اندازی خودکار", region)
        self.assertIn('callback_data=f"mza_nboot_{node_id}"', region)
        self.assertIn("📜 راه‌اندازی دستی", region)
        self.assertIn('callback_data=f"mza_nsetup_{node_id}"', region)

    def test_post_create_success_exposes_preflight_first(self):
        region = self._region(
            "elif d.startswith('mza_ncreate_confirm_'):",
            "elif d == 'mza_nodes':",
        )
        self.assertIn("🚀 راه‌اندازی خودکار", region)
        self.assertIn("SSH و آمادگی سرور بدون هیچ تغییری بررسی شود", region)

    def test_bootstrap_callbacks_are_behind_admin_guard(self):
        guard = self.source.index("if d.startswith('mza_') and role != 'admin':")
        bootstrap = self.source.index("elif d.startswith('mza_nboot_fp_'):")
        self.assertLess(guard, bootstrap)

    def test_bootstrap_offers_default_and_custom_ssh_port(self):
        region = self._region(
            "elif d.startswith('mza_nboot_fp_'):",
            "elif d.startswith('mza_nsetup_'):",
        )
        self.assertIn("mza_nboot_port22_", region)
        self.assertIn("mza_nboot_portcustom_", region)
        self.assertIn("✅ پورت 22", region)
        self.assertIn("✏️ پورت دیگر", region)

    def test_fingerprint_is_confirmed_before_password_stage(self):
        region = self._region(
            "elif d.startswith('mza_nboot_fp_'):",
            "elif d.startswith('mza_nsetup_'):",
        )
        self.assertIn("confirm_host_key(session, nonce)", region)
        self.assertIn("Pinned Host Key", region)
        self.assertIn("MZA_NODE_BOOTSTRAP_PASSWORD_INPUT", region)
        self.assertIn("Fingerprint را تایید می‌کنم", self.source)

    def test_password_input_never_enters_user_data_and_message_is_deleted(self):
        region = self._region(
            "# 🚀 Marzban Node bootstrap Phase 6 input.",
            "# 🔍 Phase 2 Marzban admin search",
        )
        self.assertIn("await update.message.delete()", region)
        self.assertIn("marzban_node_bootstrap.set_password(session, text)", region)
        self.assertIn("marzban_node_bootstrap.run_preflight", region)
        self.assertNotIn("user_data['password']", region)
        self.assertNotIn('user_data["password"]', region)
        self.assertIn("رمز SSH از حافظه NVL پاک شد", region)

    def test_phase6_explicitly_states_read_only_scope(self):
        region = self._region(
            "elif d.startswith('mza_nboot_fp_'):",
            "elif d.startswith('mza_nsetup_'):",
        )
        self.assertIn("هیچ package، certificate یا config را تغییر نمی‌دهد", region)

    def test_ready_preflight_exposes_phase7_install_action(self):
        region = self._region(
            "def _mza_node_bootstrap_report_kb",
            "async def _mza_wait_node_connected",
        )
        self.assertIn("Phase 7", region)
        self.assertIn('callback_data=f"mza_ninstall_{node_id}"', region)
        self.assertIn("if ready:", region)

    def test_node_detail_recovers_phase7_cta_from_ready_session(self):
        helper = self._region(
            "def _mza_phase7_ready_session",
            "def _mza_nodes_origin_is_apps",
        )
        self.assertIn("marzban_node_bootstrap.get_session", helper)
        self.assertIn('"PREFLIGHT_COMPLETE"', helper)
        self.assertIn('"INSTALL_FAILED"', helper)

        detail = self._region(
            "async def _show_marzban_node_detail",
            "_MZA_HOST_EDIT_TOKENS =",
        )
        self.assertIn("phase7_ready = _mza_phase7_ready_session", detail)
        self.assertIn("🚀 نصب Marzban-node · Phase 7", detail)
        self.assertIn('callback_data=f"mza_ninstall_{node_id}"', detail)
        self.assertIn("🔄 اجرای دوباره Preflight", detail)

    def test_phase7_callback_requires_phase6_session_and_reprompts_password(self):
        region = self._region(
            "elif d.startswith('mza_ninstall_cancel_'):",
            "elif d.startswith('mza_nboot_fp_'):",
        )
        self.assertIn("marzban_node_bootstrap.require_session", region)
        self.assertIn("marzban_node_install.prepare_install(session)", region)
        self.assertIn("MZA_NODE_INSTALL_PASSWORD_INPUT", region)
        self.assertIn("رمز root را دوباره ارسال کنید", region)
        self.assertIn("Pinned Host Key", region)

    def test_phase7_password_is_deleted_never_persisted_and_scrubbed_on_abort(self):
        region = self._region(
            "# 🚀 Marzban Node bootstrap Phase 6 input.",
            "# 🔍 Phase 2 Marzban admin search",
        )
        self.assertIn("MZA_NODE_INSTALL_PASSWORD_INPUT", region)
        self.assertIn("marzban_node_install.set_install_password(session, text)", region)
        self.assertIn("await update.message.delete()", region)
        self.assertNotIn("user_data['password']", region)
        self.assertNotIn('user_data["password"]', region)
        self.assertIn("session.scrub_secret()", region)

    def test_phase7_reloads_node_and_certificate_before_remote_mutation(self):
        region = self._region(
            "if state == 'MZA_NODE_INSTALL_PASSWORD_INPUT':",
            "# Password is intentionally copied only into the in-memory bootstrap",
        )
        self.assertIn("service.get_node(session.node_id)", region)
        self.assertIn("service.get_node_settings()", region)
        self.assertIn("اطلاعات Node بعد از Preflight تغییر کرده", region)
        self.assertIn("هیچ نصب Remote شروع نشد", region)
        self.assertIn("marzban_node_install.run_install", region)

    def test_phase7_api_prefetch_failure_scrubs_secret_before_remote_install(self):
        region = self._region(
            "if state == 'MZA_NODE_INSTALL_PASSWORD_INPUT':",
            "# Password is intentionally copied only into the in-memory bootstrap",
        )
        self.assertIn("except Exception as exc:", region)
        self.assertIn("ارتباط با Marzban قبل از نصب ناموفق بود", region)
        self.assertIn("session.scrub_secret()", region)
        self.assertIn("هیچ نصب Remote شروع نشد", region)

    def test_phase7_reconnects_and_polls_authoritative_marzban_status(self):
        region = self._region(
            "if state == 'MZA_NODE_INSTALL_PASSWORD_INPUT':",
            "# Password is intentionally copied only into the in-memory bootstrap",
        )
        self.assertIn("await service.reconnect_node(session.node_id)", region)
        self.assertIn("_mza_wait_node_connected", region)
        self.assertIn("timeout=45", region)
        helper = self._region(
            "async def _mza_wait_node_connected",
            "def _mza_node_install_result_text",
        )
        self.assertIn('== "connected"', helper)
        self.assertIn("await asyncio.sleep(2)", helper)

    def test_phase7_flow_is_kept_inside_bootstrap_session_cleanup_domain(self):
        region = self._region(
            "# Leaving a text-input screen through an inline button",
            "# 🛡 Central V2Ray authorization boundary.",
        )
        self.assertIn("d.startswith('mza_nboot_')", region)
        self.assertIn("d.startswith('mza_ninstall_')", region)
        self.assertIn("d.startswith('mza_node_')", region)
        self.assertIn("MZA_NODE_INSTALL_PASSWORD_INPUT", region)

    def test_leaving_bootstrap_flow_cancels_in_memory_session(self):
        region = self._region(
            "# Leaving a text-input screen through an inline button",
            "# 🛡 Central V2Ray authorization boundary.",
        )
        self.assertIn("node_bootstrap_starter", region)
        self.assertIn(
            "marzban_node_bootstrap.cancel_session(query.message.chat_id)",
            region,
        )
        self.assertIn("MZA_NODE_BOOTSTRAP_PORT_INPUT", region)
        self.assertIn("MZA_NODE_BOOTSTRAP_PASSWORD_INPUT", region)


if __name__ == "__main__":
    unittest.main()
