import io
import unittest

import qrcode
from PIL import Image

from ssh_credential_ui import (
    credential_fields_text,
    napsternet_qr_png,
    ssh_connection_action_rows,
)


class TestSSHCredentialUI(unittest.TestCase):
    def test_credential_text_is_visible_escaped_and_ordered(self):
        rendered = credential_fields_text("host<&", "user", "p<&", 2252)
        self.assertIn("<code>host&lt;&amp;</code>", rendered)
        self.assertIn("<code>user</code>", rendered)
        self.assertIn("<code>p&lt;&amp;</code>", rendered)
        self.assertIn("<code>2252</code>", rendered)
        self.assertLess(rendered.index("سرور"), rendered.index("نام کاربری"))
        self.assertLess(rendered.index("نام کاربری"), rendered.index("رمز عبور"))

    def test_copy_buttons_retain_fields_and_do_not_copy_long_link(self):
        rows = ssh_connection_action_rows(
            "nevel-1362", "pass-secret", "n1.nvlsup.com", 2252,
            qr_callback="uact_niinv_nevel-1362",
            text_callback="uact_nitxtinv_nevel-1362",
        )
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0][0].callback_data, "uact_niinv_nevel-1362")
        self.assertEqual(rows[0][1].callback_data, "uact_nitxtinv_nevel-1362")
        self.assertTrue(all(button.copy_text is None for button in rows[0]))
        self.assertEqual(
            [button.copy_text.text for row in rows[1:] for button in row],
            ["nevel-1362", "pass-secret", "n1.nvlsup.com", "2252"],
        )

    def test_oversized_copy_value_is_omitted(self):
        rows = ssh_connection_action_rows(
            "u", "x" * 257, "example.com", 22,
            qr_callback="q", text_callback="t",
        )
        values = [button.copy_text.text for row in rows[1:] for button in row]
        self.assertNotIn("x" * 257, values)
        self.assertEqual(values, ["u", "example.com", "22"])

    def test_qr_encodes_full_512_character_npvt_uri_as_png(self):
        link = "npvt-ssh://" + "A" * (512 - len("npvt-ssh://"))
        result = napsternet_qr_png(link)
        self.assertEqual(result.getvalue()[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(result.tell(), 0)
        image = Image.open(result)
        self.assertEqual(image.format, "PNG")
        self.assertEqual(image.size[0], image.size[1])
        self.assertGreater(image.width, 200)

        expected = qrcode.QRCode(
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=8,
            border=4,
        )
        expected.add_data(link, optimize=0)
        expected.make(fit=True)
        expected_buffer = io.BytesIO()
        expected.make_image(fill_color="black", back_color="white").save(
            expected_buffer, format="PNG"
        )
        self.assertEqual(result.getvalue(), expected_buffer.getvalue())

    def test_qr_rejects_non_npvt_payload(self):
        with self.assertRaises(ValueError):
            napsternet_qr_png("https://example.com")


if __name__ == "__main__":
    unittest.main()
