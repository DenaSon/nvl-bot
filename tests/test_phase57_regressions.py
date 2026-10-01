import pathlib
import unittest


BOT_PATH = pathlib.Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"


class Phase57ModernV2RaySalesRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")
        start = cls.source.index('    elif d == "v2ray_buy_menu":')
        end = cls.source.index('    elif d == "v2ru_custom_users":', start)
        cls.sales_entry_region = cls.source[start:end]

    def test_v110_marker_is_present(self):
        self.assertIn(
            'BOT_VERSION_TAG = "V110-2026-10-02-modern-v2ray-sales-wizard"',
            self.source,
        )

    def test_visible_v2ray_sales_entry_is_one_guided_wizard(self):
        self.assertIn("فروش › V2Ray › مرحله ۱: حجم", self.sales_entry_region)
        self.assertIn('InlineKeyboardButton("♾ حجم نامحدود"', self.sales_entry_region)
        self.assertIn('callback_data=f"v2ru_vol_{volume_presets[i]}"', self.sales_entry_region)
        self.assertIn('InlineKeyboardButton("✏️ حجم دلخواه"', self.sales_entry_region)

    def test_legacy_top_level_product_split_is_not_visible(self):
        self.assertNotIn("♾ نامحدود (زمان‌دار)", self.sales_entry_region)
        self.assertNotIn("📦 حجمی (بدون انقضای زمان)", self.sales_entry_region)

    def test_unlimited_volume_continues_as_wizard_step_two(self):
        self.assertIn("فروش › V2Ray › حجم نامحدود › مرحله ۲", self.sales_entry_region)
        self.assertIn("👤 ۱ کاربر · ۳۰ روز", self.sales_entry_region)
        self.assertIn("👤 ۱ کاربر · ۶۰ روز", self.sales_entry_region)
        self.assertIn("👥 ۲ کاربر · ۳۰ روز", self.sales_entry_region)
        self.assertIn("👥 ۲ کاربر · ۶۰ روز", self.sales_entry_region)
        self.assertIn('callback_data="v2ray_buy_menu"', self.sales_entry_region)

    def test_agent_and_admin_still_share_same_v2ray_sales_entry(self):
        self.assertIn('InlineKeyboardButton("🚀 فروش V2Ray", callback_data="v2ray_buy_menu")', self.source)
        self.assertIn("SSH و V2Ray هر دو از همین مسیر فروش و کیف پول نمایندگی استفاده می‌کنند.", self.source)

    def test_existing_agent_settlement_invariants_remain_present(self):
        self.assertIn("v2_bp = ainf[16]", self.source)
        self.assertIn("v2_vol_bp = ainf[17]", self.source)
        self.assertIn("UPDATE agents SET balance = balance - ?", self.source)
        self.assertIn("_db_distribute_commission", self.source)
        self.assertIn("_apply_agent_cashback_if_eligible", self.source)
        self.assertIn("_db_increment_lifetime_sold", self.source)

    def test_sale_provisioning_uses_verified_marzban_service_layer(self):
        self.assertIn("async def _provision_v2ray_sale_user", self.source)
        self.assertIn("service = await _get_marzban_admin_service()", self.source)
        self.assertIn("ok, result = await service.create_user(", self.source)
        self.assertIn("selected_inbound_tags=None", self.source)
        self.assertIn("ok_sub, sub_url = await service.get_subscription_url(username)", self.source)
        self.assertIn('"created": True', self.source)
        self.assertIn("_db_mark_reserved_v2ray_sale", self.source)

    def test_sale_paths_no_longer_call_legacy_create_user(self):
        self.assertNotIn(
            "await v2ray_engine.create_user(m_url, m_user, m_pwd, un",
            self.source,
        )

    def test_uncertain_remote_create_is_not_blindly_retried(self):
        self.assertIn("created_uncertain", self.source)
        self.assertIn("Never POST the same sale again.", self.source)
        self.assertIn("رکورد رزرو محلی برای بازیابی نگه داشته شد", self.source)

    def test_direct_marzban_creation_remains_admin_only_and_separate(self):
        self.assertIn("if d.startswith('mza_') and role != 'admin':", self.source)
        self.assertIn("elif d == 'mza_create':", self.source)
        self.assertIn("ساخت مستقیم User در این بخش، فروش یا فاکتور ثبت نمی‌کند.", self.source)


if __name__ == "__main__":
    unittest.main()
