import pathlib
import unittest


BOT_PATH = pathlib.Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"


class Phase56NavigationRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")

    def test_phase56_features_survive_current_version(self):
        self.assertIn("BOT_VERSION_TAG =", self.source)
        self.assertIn("➕ فروش / ساخت اشتراک", self.source)
        self.assertIn("👥 کاربران", self.source)
        self.assertIn("🛠 V2Ray / Marzban", self.source)

    def test_admin_home_is_domain_based(self):
        for label in (
            "➕ فروش / ساخت اشتراک",
            "👥 کاربران",
            "🤝 نمایندگان",
            "📊 گزارش‌ها",
            "💰 مالی و کارت‌ها",
            "⚙️ تنظیمات",
            "🛠 V2Ray / Marzban",
            "📦 بکاپ",
        ):
            self.assertIn(label, self.source)

    def test_agent_home_exposes_one_sales_entry_and_owned_users(self):
        self.assertIn("['➕ فروش اشتراک', '👥 کاربران']", self.source)
        self.assertIn("['💰 کیف پول و حساب', '💳 شارژ حساب']", self.source)
        self.assertIn(
            'SSH و V2Ray هر دو از همین مسیر فروش و کیف پول نمایندگی استفاده می‌کنند.',
            self.source,
        )

    def test_sales_hub_exposes_ssh_and_v2ray_without_parallel_logic(self):
        self.assertIn('callback_data="buy_direct"', self.source)
        self.assertIn('callback_data="v2ray_buy_menu"', self.source)
        self.assertIn('InlineKeyboardButton("🔐 فروش SSH"', self.source)
        self.assertIn('InlineKeyboardButton("🚀 فروش V2Ray"', self.source)
        self.assertIn('elif d == "v2ray_buy_menu":', self.source)
        # Existing V2Ray purchase path still prices against agent context.
        self.assertIn("if role == 'agent':", self.source)
        self.assertIn("v2_vol_bp = ainf[17]", self.source)

    def test_old_reply_keyboard_labels_remain_aliases(self):
        for old_label in (
            "🛒 خرید اشتراک",
            "👥 مدیریت کاربران",
            "💼 مدیریت نماینده‌ها",
            "📊 آمار و لاگ",
            "💳 تنظیمات مالی",
            "⚙️ تنظیمات سرور",
            "🛠 مدیریت V2Ray",
            "📦 دریافت بکاپ",
            "💳 شارژ حساب (کارت به کارت)",
            "📊 اطلاعات حساب",
            "✏️ تغییر نام برند",
        ):
            self.assertIn(old_label, self.source)

    def test_user_hub_is_a_navigation_level_for_admin_and_agent(self):
        self.assertIn("async def _show_users_hub", self.source)
        self.assertIn('"umanage_ssh"', self.source)
        self.assertIn('"umanage_v2ray"', self.source)
        self.assertIn('"umanage_v2ray_vol"', self.source)
        self.assertIn('back_cb = f"agm_det_{agent_filter}" if agent_filter is not None else "users_hub"', self.source)
        self.assertIn('elif d == "users_hub" and role in (\'admin\', \'agent\'):', self.source)

    def test_user_navigation_callbacks_are_role_guarded(self):
        self.assertIn('d.startswith("umanage_")', self.source)
        self.assertIn("role not in ('admin', 'agent')", self.source)
        self.assertIn(
            "دسترسی به مدیریت کاربران برای این نقش مجاز نیست.",
            self.source,
        )

    def test_back_and_home_mean_different_levels(self):
        self.assertIn('InlineKeyboardButton("🏠 منوی اصلی", callback_data="uact_back_to_menu")', self.source)
        self.assertIn('InlineKeyboardButton("↩️ انتخاب سرویس", callback_data="buy_back_start")', self.source)
        self.assertIn('InlineKeyboardButton("↩️ نوع پلن V2Ray", callback_data="v2ray_buy_menu")', self.source)

    def test_marzban_direct_create_is_visually_separated_from_sales(self):
        self.assertIn(
            'InlineKeyboardButton("➕ ساخت مستقیم User", callback_data="mza_create")',
            self.source,
        )
        self.assertIn(
            "ساخت مستقیم User در این بخش، فروش یا فاکتور ثبت نمی‌کند.",
            self.source,
        )
        self.assertIn("🛠 <b>V2Ray / Marzban</b>", self.source)

    def test_user_lists_have_breadcrumb_style_titles(self):
        self.assertIn('panel_title = f"👥 کاربران من › {srv_name}"', self.source)
        self.assertIn('panel_title = f"👥 کاربران › {srv_name}"', self.source)
        self.assertIn('panel_title = f"🤝 نمایندگان › {esc(agent_name)} › {srv_name}"', self.source)


    def test_agent_visible_action_buttons_drop_possessive_mine(self):
        for rendered in (
            "kb.append([\'💳 کارت اختصاصی\'])",
            '("🔐 SSH", "umanage_ssh")',
            '("🚀 V2Ray مدت‌دار", "umanage_v2ray")',
            '("📦 V2Ray حجمی", "umanage_v2ray_vol")',
            'InlineKeyboardButton("🗑 حذف کارت", callback_data="agself_card_clear")',
            'InlineKeyboardButton("✏️ ثبت کارت", callback_data="agself_card_set")',
            'InlineKeyboardButton("👥 زیرمجموعه‌ها", callback_data="mysubs_1")',
        ):
            self.assertIn(rendered, self.source)

        for old_rendered in (
            "kb.append([\'💳 کارت اختصاصی من\'])",
            'InlineKeyboardButton("🗑 حذف کارت من", callback_data="agself_card_clear")',
            'InlineKeyboardButton("✏️ ثبت کارت من", callback_data="agself_card_set")',
            'InlineKeyboardButton("👥 زیرمجموعه‌های من", callback_data="mysubs_1")',
        ):
            self.assertNotIn(old_rendered, self.source)


if __name__ == "__main__":
    unittest.main()
