import pathlib
import unittest


BOT_PATH = pathlib.Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"


class Phase572V2RayVolumeExpiryRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")

    def test_v112_marker_is_present(self):
        self.assertIn(
            'BOT_VERSION_TAG = "V112-2026-10-02-v2ray-volume-expiry"',
            self.source,
        )

    def test_volume_sale_has_expiry_step(self):
        self.assertIn("async def _show_v2_vol_expiry_step", self.source)
        self.assertIn("فروش › V2Ray › مرحله ۲: انقضا", self.source)
        for callback in (
            "v2vexp_1",
            "v2vexp_15",
            "v2vexp_30",
            "v2vexp_60",
            "v2vexp_0",
        ):
            self.assertIn(callback, self.source)

    def test_volume_and_custom_volume_both_enter_expiry_step(self):
        self.assertGreaterEqual(
            self.source.count("_show_v2_vol_expiry_step("),
            4,
        )
        self.assertIn("context.user_data['v2_vol_gb'] = int(val)", self.source)
        self.assertIn("context.user_data['v2_vol_gb'] = gb", self.source)

    def test_expiry_is_required_before_final_purchase(self):
        self.assertIn(
            "if not gb or 'v2_vol_expiry_days' not in context.user_data:",
            self.source,
        )

    def test_expiry_selection_is_persisted_in_wizard_state(self):
        self.assertIn(
            "context.user_data['v2_vol_expiry_days'] = int(raw_days)",
            self.source,
        )
        self.assertIn("raw_days not in {"0", "1", "15", "30", "60"}", self.source)

    def test_marzban_expire_is_zero_only_for_unlimited_time(self):
        self.assertIn(
            "int((datetime.now() + timedelta(days=expiry_days)).timestamp())",
            self.source,
        )
        self.assertIn("if expiry_days > 0", self.source)

    def test_local_expire_date_matches_selected_days(self):
        self.assertIn(
            "(datetime.now() + timedelta(days=expiry_days)).strftime("%Y-%m-%d")",
            self.source,
        )
        self.assertIn('else "نامحدود"', self.source)

    def test_review_invoice_and_logs_include_expiry(self):
        self.assertIn('expiry_label = "نامحدود زمانی" if expiry_days == 0 else f"{expiry_days} روز"', self.source)
        self.assertIn("📅 انقضا: {expiry_invoice}", self.source)
        self.assertIn('f"{gb} گیگ - {expiry_txt}"', self.source)

    def test_volume_price_formula_is_still_per_gb_only(self):
        self.assertIn("v2_vol_bp = ainf[17]", self.source)
        self.assertIn("retail_dec = base_price_dec * Decimal(gb)", self.source)


if __name__ == "__main__":
    unittest.main()
