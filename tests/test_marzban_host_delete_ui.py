import pathlib
import unittest


BOT_PATH = pathlib.Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"


class MarzbanHostDeleteUITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")

    def _region(self, start, end):
        a = self.source.index(start)
        b = self.source.index(end, a)
        return self.source[a:b]

    def test_host_detail_exposes_permanent_delete(self):
        region = self._region(
            "async def _show_marzban_host_detail",
            "async def _mza_show_host_edit_confirm",
        )
        self.assertIn("🗑 حذف دائمی Host", region)
        self.assertIn('callback_data=f"mza_hdelete_{host_token}"', region)

    def test_host_delete_uses_snapshot_nonce_and_expiry(self):
        region = self._region(
            "elif d.startswith('mza_hdelete_confirm_'):",
            "elif d.startswith('mza_htoggle_'):",
        )
        self.assertIn("mza_host_delete_pending", region)
        self.assertIn("expected_host", region)
        self.assertIn("age > 600", region)
        self.assertIn("mza_host_delete_busy", region)
        self.assertIn("service.delete_host(", region)

    def test_host_delete_verify_uncertainty_is_not_blindly_retried(self):
        region = self._region(
            "elif d.startswith('mza_hdelete_confirm_'):",
            "elif d.startswith('mza_htoggle_'):",
        )
        self.assertIn("applied_but_unverified", region)
        self.assertIn("درخواست حذف دوباره اجرا نمی‌شود", region)
        uncertain = region.index("if applied_but_unverified:")
        self.assertNotIn(
            "service.delete_host(",
            region[uncertain:],
        )

    def test_host_delete_flow_preserves_pending_state_until_confirm(self):
        region = self._region(
            "# Leaving a text-input screen through an inline button",
            "# 🛡 Central V2Ray authorization boundary.",
        )
        self.assertIn("host_delete_starter", region)
        self.assertIn("or host_delete_starter", region)
        self.assertIn("and not host_delete_starter", region)

    def test_host_delete_remains_admin_only(self):
        guard = self.source.index("if d.startswith('mza_') and role != 'admin':")
        delete_cb = self.source.index("elif d.startswith('mza_hdelete_confirm_'):")
        self.assertLess(guard, delete_cb)


if __name__ == "__main__":
    unittest.main()
