import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
BOT_PATH = ROOT / "bot_final_v49-2.py"


class StandbyDrillSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")

    def _region(self, start, end):
        a = self.source.index(start)
        b = self.source.index(end, a)
        return self.source[a:b]

    def test_standby_role_rejects_unsafe_hosts(self):
        region = self._region(
            'elif d.startswith("hpstandby_")',
            'elif d == "hp_failover_toggle"',
        )
        self.assertIn("_db_count_explicit_active_ssh_accounts", region)
        self.assertIn("سرور اصلی نمی‌تواند هم‌زمان جایگزین باشد", region)
        self.assertIn("سرور هسته نمی‌تواند جایگزین باشد", region)
        self.assertIn("حساب فعال دارد", region)
        self.assertIn("_db_set_host_standby, host, True", region)

        default_guard = region.index("if bool(row[7]):")
        account_guard = region.index("_db_count_explicit_active_ssh_accounts")
        mutation = region.index("_db_set_host_standby, host, True")
        self.assertLess(default_guard, mutation)
        self.assertLess(account_guard, mutation)

    def test_drill_is_exposed_from_filter_detail(self):
        region = self._region(
            "async def _render_filtering_edge_detail",
            "async def _render_filtering_probe_details",
        )
        self.assertIn("🧪 آزمون آمادگی انتقال", region)
        self.assertIn('callback_data=f"flt_drill_{host}"', region)

    def test_drill_uses_strict_live_preflight_without_failover_execution(self):
        region = self._region(
            'elif d.startswith("flt_drill_pick_")',
            'elif d.startswith("flt_drill_")',
        )
        self.assertIn("_safe_manual_failover_preflight(", region)
        self.assertIn("require_clear_filter=True", region)
        self.assertIn("هیچ تغییری در مسیر، حساب‌ها یا دیتابیس انجام نمی‌شود", region)
        self.assertNotIn("_safe_manual_failover(", region)
        self.assertNotIn("_cf_switch_public_domain", region)
        self.assertNotIn("_db_commit_failover_account_state", region)
        self.assertNotIn("_db_commit_relay_failover_state", region)
        self.assertIn("target_relay_ok", region)

    def test_drill_reports_readable_persian_safety_failures(self):
        helper = self._region(
            "def _failover_preflight_error_label_fa",
            "def _filter_state_icon",
        )
        self.assertIn("تنظیمات دامنه و Cloudflare کامل نیست", helper)
        self.assertIn("دسترسی مدیریتی سرور جایگزین در دسترس نیست", helper)
        self.assertIn("ارتباط WireGuard سرور جایگزین سالم نیست", helper)
        self.assertIn("مسیر ارتباط سرور جایگزین با هسته سالم نیست", helper)
        self.assertIn("مسیر رلهٔ سرور جایگزین به سرور هسته کامل یا معتبر نیست", helper)
        self.assertNotIn("حساب فعال صریح", helper)

    def test_drill_reports_relay_not_account_migration(self):
        region = self._region(
            'elif d.startswith("flt_drill_pick_")',
            'elif d.startswith("flt_drill_")',
        )
        self.assertIn("مسیر رله به هسته", region)
        self.assertNotIn("حساب‌های قابل انتقال", region)

        manual = self._region(
            'elif d.startswith("flt_failover_pick_")',
            'elif d.startswith("flt_failover_") and role == \'admin\':',
        )
        self.assertIn("حساب‌های کاربران روی سرور هسته باقی می‌مانند", manual)
        self.assertNotIn("بازسازی کامل حساب‌ها", manual)

    def test_relevant_telegram_paths_do_not_show_development_phase_labels(self):
        host_panel = self._region(
            "async def _render_host_pool_panel",
            "def _failover_preflight_error_label_fa",
        )
        manual = self._region(
            'elif d.startswith("flt_failover_pick_")',
            'elif d.startswith("flt_failover_") and role == \'admin\':',
        )
        self.assertNotIn("Phase 6H", host_panel)
        self.assertNotIn("Safe Manual Failover", manual)
        self.assertNotIn("Phase 6G", manual)


if __name__ == "__main__":
    unittest.main()
