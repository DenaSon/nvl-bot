import pathlib
import unittest


BOT_PATH = pathlib.Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"


class Phase571V2RayOneGbMinimumRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")

    def test_v111_marker_is_present(self):
        self.assertIn(
            'BOT_VERSION_TAG = "V111-2026-10-02-v2ray-1gb-minimum"',
            self.source,
        )

    def test_new_sales_wizard_starts_at_one_gb(self):
        self.assertIn(
            "volume_presets = (1, 5, 10, 20, 50, 100)",
            self.source,
        )
        self.assertIn("فروش › V2Ray › مرحله ۱: حجم", self.source)

    def test_custom_sale_volume_accepts_one_to_one_hundred_gb(self):
        self.assertIn("if not (1 <= gb <= 100):", self.source)
        self.assertIn("حجم باید بین 1 تا 100 گیگ باشد", self.source)

    def test_legacy_volume_screen_is_compatible_with_one_gb(self):
        self.assertIn(
            "vols = [1, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 100]",
            self.source,
        )
        self.assertIn("بازه مجاز: 1 تا 100 گیگ", self.source)

    def test_add_volume_accepts_one_to_one_hundred_gb(self):
        self.assertIn(
            "if not val.isdigit() or not (1 <= int(val) <= 100):",
            self.source,
        )
        self.assertIn(
            "vols = [1, 5, 10, 20, 30, 40, 50]",
            self.source,
        )
        self.assertIn("فقط عدد بین 1 تا 100 گیگ بفرستید", self.source)

    def test_old_ten_gb_floor_is_gone(self):
        self.assertNotIn("10 <= gb <= 100", self.source)
        self.assertNotIn("10 <= int(val) <= 100", self.source)


if __name__ == "__main__":
    unittest.main()
