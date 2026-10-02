import unittest

import v2ray_engine


class MarzbanAuthDiagnosticsTests(unittest.TestCase):
    def tearDown(self):
        v2ray_engine.clear_token_cache()

    def test_normalize_plain_panel_url(self):
        self.assertEqual(
            v2ray_engine.normalize_marzban_base_url("https://panel.example.com/"),
            "https://panel.example.com",
        )

    def test_normalize_terminal_api_suffix(self):
        self.assertEqual(
            v2ray_engine.normalize_marzban_base_url("https://panel.example.com/api/"),
            "https://panel.example.com",
        )

    def test_do_not_strip_real_subpath(self):
        self.assertEqual(
            v2ray_engine.normalize_marzban_base_url("https://example.com/marzban"),
            "https://example.com/marzban",
        )

    def test_auth_401_is_actionable(self):
        msg = v2ray_engine._format_auth_failure(
            401, {"detail": "Incorrect username or password"}
        )
        self.assertIn("HTTP 401", msg)
        self.assertIn("Incorrect username or password", msg)

    def test_auth_404_explains_base_url(self):
        msg = v2ray_engine._format_auth_failure(404, "Not Found")
        self.assertIn("HTTP 404", msg)
        self.assertIn("MARZBAN_URL", msg)

    def test_auth_failure_truncates_untrusted_body(self):
        msg = v2ray_engine._format_auth_failure(502, "x" * 1000)
        self.assertLess(len(msg), 300)
        self.assertIn("HTTP 502", msg)

    def test_cache_key_uses_normalized_url_and_trimmed_user(self):
        self.assertEqual(
            v2ray_engine._token_cache_key("https://panel.example.com/api/", " admin "),
            ("https://panel.example.com", "admin"),
        )


if __name__ == "__main__":
    unittest.main()
