"""Phase-1 Cloudzy UX is presentation-only and never changes journals."""
import unittest

from cloudzy_phase1_ui import (
    cz07_issue, receipt_result, receipt_title, technical_receipt,
)
from cloudzy_cz06_orchestrator import progress_html


class Phase1UIContracts(unittest.TestCase):
    def test_ready_install_is_not_an_automatic_standby(self):
        receipt = {"id": "abc", "status": "EDGE_READY", "public_ipv4": "8.8.8.8"}
        self.assertIn("مسیر دستی", receipt_result(receipt, None))
        self.assertIn("تأیید نهایی", receipt_result(receipt, {"stage": "HOLD"}))
        self.assertIn("CZ-07", receipt_result(receipt, {"stage": "READY"}))

    def test_hold_reason_is_actionable_without_claiming_success(self):
        receipt = {"status": "HOLD_PROVISION", "hold_reason": "EDGE_APT_LOCK_BUSY"}
        message = receipt_result(receipt, {"stage": "HOLD"})
        self.assertIn("APT", message)
        self.assertIn("تکرار نکنید", message)
        self.assertIn("نصب Edge", receipt_title("HOLD_PROVISION"))

    def test_unknown_codes_are_safe_and_technical_details_are_escaped(self):
        receipt = {"id": "<bad>", "status": "HOLD_UNKNOWN",
                   "hold_reason": "<hidden>", "provider_server_id": "p&1"}
        details = technical_receipt(receipt, {"stage": "HOLD", "detail_code": "<fail>"})
        self.assertNotIn("<bad>", details)
        self.assertNotIn("<hidden>", details)
        self.assertIn("&lt;bad&gt;", details)
        self.assertIn("p&amp;1", details)
        self.assertIn("پیش‌نیاز", cz07_issue("SOMETHING_NEW")[0])

    def test_standby_hold_preserves_proven_installed_steps_only(self):
        run = {"stage": "HOLD", "operation_id": "one",
               "updated_at": 1, "detail_code": ""}
        installed = progress_html(run, {"status": "EDGE_READY", "public_ipv4": "8.8.8.8"}, now=100)
        self.assertIn("✅ نصب و بررسی Edge", installed)
        self.assertIn("⚠️ فعال‌سازی Standby", installed)
        unproven = progress_html(run, {"status": "HOLD_PROVISION"}, now=100)
        self.assertNotIn("✅ نصب و بررسی Edge", unproven)


if __name__ == "__main__":
    unittest.main()
