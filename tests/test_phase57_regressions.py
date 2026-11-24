import ast
import asyncio
import pathlib
from types import SimpleNamespace
import unittest


BOT_PATH = pathlib.Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"


class Phase57ModernV2RaySalesRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")
        start = cls.source.index('    elif d == "v2ray_buy_menu":')
        end = cls.source.index('    elif d == "v2ru_custom_users":', start)
        cls.sales_entry_region = cls.source[start:end]

    def test_phase57_features_survive_current_version(self):
        self.assertIn("BOT_VERSION_TAG =", self.source)
        self.assertIn("فروش › V2Ray › مرحله ۱: حجم", self.source)
        self.assertIn("async def _provision_v2ray_sale_user", self.source)

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


class SharedSalesNavigationTests(unittest.IsolatedAsyncioTestCase):
    async def test_roles_share_feature_gated_v2ray_sale_entry(self):
        tree = ast.parse(BOT_PATH.read_text(encoding="utf-8"))
        node = next(n for n in tree.body if isinstance(n, ast.AsyncFunctionDef)
                    and n.name == "_show_buy_start")
        settings = {"sell_ssh": "1", "sell_bulk": "1", "sell_v2ray_unlimit": "1",
                    "sell_v2ray_vol": "1"}
        views = []
        layouts = []
        async def reply(text, *, reply_markup, parse_mode):
            self.assertIn("<b>فروش اشتراک</b>", text)
            self.assertEqual(parse_mode, "HTML")
            layouts.append(reply_markup)
            views.append({cb for row in reply_markup for cb in row})
        ns = {"asyncio": asyncio,
              "_db_get_setting": lambda key, default: settings.get(key, default),
              "_db_get_favs": lambda: [(1, 2)],
              "InlineKeyboardButton": lambda label, callback_data: callback_data,
              "InlineKeyboardMarkup": lambda rows: rows}
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(BOT_PATH), "exec"), ns)
        handler = ns["_show_buy_start"]
        update = SimpleNamespace(message=SimpleNamespace(reply_text=reply))
        for enabled in (True, False):
            settings["sell_v2ray_unlimit"] = settings["sell_v2ray_vol"] = "1" if enabled else "0"
            for role in ("admin", "agent"):
                await handler(update, SimpleNamespace(user_data={"role": role}))
                self.assertIn("buy_direct", views[-1])
                self.assertEqual("v2ray_buy_menu" in views[-1], enabled)
                self.assertIn("nav:sale_favorites", views[-1])
            self.assertEqual(views[-2], views[-1])
            for rows in layouts[-2:]:
                self.assertEqual(rows[-1], ["uact_back_to_menu"])
                self.assertEqual(rows[0], ["buy_direct", "v2ray_buy_menu"] if enabled else ["buy_direct"])
                self.assertEqual(rows[1], ["nav:sale_favorites", "buy_bulk_start"])
                self.assertTrue(all(1 <= len(row) <= 2 for row in rows))


if __name__ == "__main__":
    unittest.main()
