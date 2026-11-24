"""UI-01 contracts: verify real menu routing instead of decorative labels."""
import ast
import asyncio
from types import SimpleNamespace
from pathlib import Path
import unittest

BOT = Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"


class NavigationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = BOT.read_text(encoding="utf-8")
        tree = ast.parse(source)
        wanted = {"_nav_home_rows", "_nav_settings_rows", "_nav_finance_rows",
                  "_nav_callback_allowed", "_build_server_settings_kb"}
        nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in wanted]
        cls.ns = {"InlineKeyboardButton": lambda label, callback_data: callback_data}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(BOT), "exec"), cls.ns)

    def test_role_home_and_required_brand_onboarding(self):
        home = self.ns["_nav_home_rows"]
        self.assertEqual(sum(map(len, home("admin"))), 6)
        self.assertIn("🌐 زیرساخت", sum(home("admin"), []))
        self.assertIn("⚙️ تنظیمات", sum(home("agent"), []))
        self.assertIn("📊 گزارش‌ها", sum(home("agent"), []))
        self.assertIn("💰 کیف پول", sum(home("agent"), []))
        self.assertEqual(home("agent", brand_ready=False), [["✏️ نام برند"], ["❌ خروج"]])
        self.assertNotIn("🌐 زیرساخت", sum(home("accountant"), []))

    def test_settings_permissions(self):
        settings = self.ns["_nav_settings_rows"]
        def callbacks(rows):
            return {cb for row in rows for _, cb in row}
        self.assertIn("nav:backup", callbacks(settings("admin")))
        self.assertNotIn("super_admin_users_menu", callbacks(settings("admin")))
        self.assertIn("super_admin_users_menu", callbacks(settings("admin", superadmin=True)))
        self.assertNotIn("nav:agent_card", callbacks(settings("agent")))
        self.assertIn("nav:agent_card", callbacks(settings("agent", card_allowed=True)))
        self.assertNotIn("nav:backup", callbacks(settings("agent")))
        self.assertEqual(settings("accountant"), [])

    def test_finance_permissions_and_feature_flags(self):
        finance = self.ns["_nav_finance_rows"]
        def callbacks(rows):
            return {cb for row in rows for _, cb in row}
        self.assertNotIn("nvl_fin:menu", callbacks(finance("admin", accounting_enabled=True)))
        self.assertNotIn("nvl_fin:menu", callbacks(finance("admin", superadmin=True)))
        self.assertIn("nvl_fin:menu", callbacks(finance("admin", superadmin=True, accounting_enabled=True)))
        self.assertNotIn("fin_menu", callbacks(finance("agent", superadmin=True)))
        self.assertEqual(finance("accountant"), [])

    def test_monitoring_has_one_infrastructure_entry_and_parent(self):
        home = self.ns["_nav_home_rows"]("admin")
        self.assertNotIn("🛡 بررسی فیلترینگ", sum(home, []))
        callbacks = sum(self.ns["_build_server_settings_kb"](), [])
        self.assertEqual(callbacks.count("hp_filtering"), 1)
        self.assertEqual(callbacks.count("apps_home"), 1)
        source = BOT.read_text(encoding="utf-8")
        start = source.index("async def _render_filtering_monitor_panel")
        end = source.index("async def _render_filtering_edge_detail", start)
        self.assertIn('callback_data="srv_menu_back"', source[start:end])

    def test_new_callback_role_boundary(self):
        allowed = self.ns["_nav_callback_allowed"]
        for role in ("agent", "accountant", None):
            self.assertFalse(allowed("nav:backup", role))
        self.assertTrue(allowed("nav:backup", "admin"))
        self.assertFalse(allowed("nav:agent_card", "admin"))
        self.assertTrue(allowed("nav:agent_card", "agent"))
        self.assertTrue(allowed("nav:agent_reports", "agent"))
        self.assertFalse(allowed("nav:agent_reports", "admin"))
        self.assertTrue(allowed("nav:sale_favorites", "admin"))
        self.assertTrue(allowed("nav:sale_favorites", "agent"))
        self.assertFalse(allowed("nav:sale_favorites", "accountant"))
        self.assertFalse(allowed("nav:settings", "accountant"))
        self.assertFalse(allowed("nav:unknown", "admin"))


class LegacyNavigationCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT.read_text(encoding="utf-8")

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

    def test_user_navigation_callbacks_are_role_guarded(self):
        self.assertIn('d.startswith("umanage_")', self.source)
        self.assertIn("role not in ('admin', 'agent')", self.source)
        self.assertIn(
            "دسترسی به مدیریت کاربران برای این نقش مجاز نیست.",
            self.source,
        )

    def test_marzban_direct_create_is_visually_separated_from_sales(self):
        self.assertIn(
            'InlineKeyboardButton("➕ ساخت مستقیم User", callback_data="mza_create")',
            self.source,
        )
        self.assertIn(
            "ساخت مستقیم User در این بخش، فروش یا فاکتور ثبت نمی‌کند.",
            self.source,
        )
        self.assertIn("🛠 <b>V2Ray / Marzban › کاربران</b>", self.source)


class ResellerReportTests(unittest.IsolatedAsyncioTestCase):
    async def test_reports_use_only_authenticated_reseller_scope(self):
        tree = ast.parse(BOT.read_text(encoding="utf-8"))
        func = next(n for n in tree.body
                    if isinstance(n, ast.AsyncFunctionDef)
                    and n.name == "_show_nav_agent_reports")
        calls = []
        views = []
        def stats(aid, service=None):
            calls.append((aid, service))
            return (1, 2, 3, 4, 5)
        async def render(target, title, rows):
            views.append((title, rows))
        ns = {"asyncio": asyncio, "_db_get_sales_stats": stats, "_nav_render": render}
        exec(compile(ast.Module(body=[func], type_ignores=[]), str(BOT), "exec"), ns)
        handler = ns["_show_nav_agent_reports"]
        await handler(object(), SimpleNamespace(user_data={"role": "admin", "agent_id": 7}))
        await handler(object(), SimpleNamespace(user_data={"role": "agent", "agent_id": 0}))
        self.assertEqual(calls, [])
        await handler(object(), SimpleNamespace(user_data={"role": "agent", "agent_id": 7}))
        self.assertEqual(calls, [(7, None), (7, "ssh"), (7, "v2ray")])
        self.assertEqual(len(views), 1)
        self.assertIn("V2Ray", views[0][0])
        self.assertIn("info_online", {cb for row in views[0][1] for _, cb in row})


class SaleFavoritesNavigationTests(unittest.IsolatedAsyncioTestCase):
    async def test_favorites_obey_sales_flag_and_keep_existing_callbacks(self):
        tree = ast.parse(BOT.read_text(encoding="utf-8"))
        func = next(n for n in tree.body
                    if isinstance(n, ast.AsyncFunctionDef)
                    and n.name == "_show_nav_sale_favorites")
        views = []
        state = {"enabled": "0"}
        async def render(target, title, rows):
            views.append(rows)
        ns = {"asyncio": asyncio,
              "_db_get_setting": lambda *args: state["enabled"],
              "_db_get_favs": lambda: [(1, 2)],
              "_nav_render": render}
        exec(compile(ast.Module(body=[func], type_ignores=[]), str(BOT), "exec"), ns)
        handler = ns["_show_nav_sale_favorites"]
        ctx = SimpleNamespace(user_data={"role": "agent", "agent_id": 7})
        await handler(object(), ctx)
        self.assertEqual({cb for row in views[-1] for _, cb in row}, {"buy_back_start"})
        state["enabled"] = "1"
        await handler(object(), ctx)
        self.assertEqual({cb for row in views[-1] for _, cb in row}, {"buy_back_start", "buyfav_1_2"})
