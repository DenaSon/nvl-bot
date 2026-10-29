"""Phase 3 native Rich UI contract: NO HTML/keyboard fallback."""
import unittest
from unittest.mock import patch

from manual_edge_rich import (
    ManualRichDelivery, ManualRichHold, render_manual_card,
)
from cloudzy_rich_transport import RichBotAPI, RichDeliveryHold


class RichRenderTests(unittest.TestCase):
    def test_farsi_title_status_buttons_are_native_rich_blocks(self):
        card = render_manual_card(
            "🛟 <b>سرور دستی</b>\nIP: <code>8.8.8.8</code>\n"
            "وضعیت: <b>آماده انتقال</b>",
            [[("🔁 بررسی انتقال کاربران", "apps_edge_manual_review_123")],
             [("↩️ مدیریت Edge", "apps_cz_home")]],
        )
        self.assertTrue(card["is_rtl"])
        self.assertTrue(card["skip_entity_detection"])
        blocks = card["blocks"]
        self.assertEqual(blocks[0]["type"], "heading")
        self.assertIn("سرور دستی", blocks[0]["text"])
        self.assertNotIn("<b>", str(blocks))
        self.assertIn("آماده انتقال", str(blocks))
        buttons = [b for x in blocks if x["type"] == "buttons"
                   for b in x["buttons"]]
        self.assertEqual(buttons[0]["callback_data"],
                         "apps_edge_manual_review_123")
        self.assertEqual(len(buttons), 2)

    def test_telegram_webapp_remains_secure_while_rich_card_is_native(self):
        card = render_manual_card(
            "۱/۴ · <b>مشخصات سرور</b>",
            [[("📝 مشخصات سرور", {"web_app": {
                "url": "https://secure.example/manual-edge/form?ticket=nonce"}})],
             [("✅ اطلاعات را ثبت کردم", "apps_edge_manual_form_done_abc")],
             [("انصراف", "apps_edge_manual_cancel")]],
        )
        buttons = [b for x in card["blocks"] if x["type"] == "buttons"
                   for b in x["buttons"]]
        self.assertEqual(buttons[0]["web_app"]["url"],
                         "https://secure.example/manual-edge/form?ticket=nonce")
        self.assertNotIn("reply_markup", card)
        self.assertNotIn("parse_mode", card)
        self.assertNotIn("html", str(card).lower())
        self.assertEqual(buttons[-1]["style"], "danger")

    def test_cz07_recovery_and_dashboard_navigation_are_preserved(self):
        card = render_manual_card("🔄 وضعیت انتقال",
            [[("بررسی و بازیابی صف", "apps_cz7_status")],
             [("برنامه‌ها", "apps_home")]])
        self.assertEqual(
            [b["callback_data"] for x in card["blocks"]
             if x["type"] == "buttons" for b in x["buttons"]],
            ["apps_cz7_status", "apps_home"],
        )

    def test_invalid_or_overlong_callbacks_fail_closed(self):
        for action in ("purchase_now", "apps_edge_manual_"+"x"*70,
                       "apps_cz7_"+"x"*65):
            with self.subTest(action=action), self.assertRaises(ManualRichHold):
                render_manual_card("عنوان", [[("اجرا", action)]])
        for url in ("http://example/manual-edge/form?ticket=a",
                    "https://example/other?ticket=a",
                    "https://evil:password@example/manual-edge/form?ticket=a"):
            with self.subTest(url=url), self.assertRaises(ManualRichHold):
                render_manual_card("عنوان", [[("📝", {"web_app":{"url":url}})]])

    def test_render_rejects_unparsed_angle_brackets_and_nul(self):
        for value in ("IP <bad", "x\x00y"):
            with self.subTest(value=value), self.assertRaises(ManualRichHold):
                render_manual_card(value, [[("بازگشت", "apps_cz_home")]])


class RichDeliveryTests(unittest.IsolatedAsyncioTestCase):
    class Context:
        def __init__(self):
            self.user_data = {}

    async def test_send_once_then_edit_same_rich_card_without_plain_html(self):
        calls = []
        def fake_transport(method, body):
            calls.append((method, body))
            return {"message_id": 501}
        delivery = ManualRichDelivery(
            "123:TEST_TOKEN",
            api_factory=lambda token: RichBotAPI(
                token, transport=fake_transport))
        context = self.Context()
        first = await delivery.show(
            chat=33, context=context, text="🛟 Edge دستی",
            rows=[[("➕ افزودن", "apps_edge_manual_new")]])
        second = await delivery.show(
            chat=33, context=context, text="✅ سرور آماده است",
            rows=[[("🔄 وضعیت", "apps_edge_manual_home")]])
        self.assertEqual((first, second), (501, 501))
        self.assertEqual([name for name, _ in calls],
                         ["sendRichMessage", "editMessageText"])
        self.assertEqual(
            calls[0][1]["rich_message"]["blocks"][-1]["type"],
            "buttons")
        self.assertTrue(calls[0][1]["protect_content"])
        self.assertEqual(
            calls[1][1]["rich_message"]["blocks"][0]["type"],
            "heading")
        self.assertEqual(context.user_data["manual_edge_rich_pointer"], 501)

    async def test_uncertain_telegram_edit_is_not_downgraded_or_replayed(self):
        calls = []
        def fake_transport(method, body):
            calls.append(method)
            if method == "editMessageText":
                raise RichDeliveryHold("TELEGRAM_DELIVERY_UNCERTAIN")
            return {"message_id": 44}
        delivery = ManualRichDelivery(
            "123:TEST_TOKEN",
            api_factory=lambda token: RichBotAPI(token, transport=fake_transport))
        context=self.Context()
        await delivery.show(chat=33,context=context,text="شروع",rows=[])
        with self.assertRaises(RichDeliveryHold):
            await delivery.show(chat=33,context=context,text="انجام",rows=[])
        self.assertEqual(calls, ["sendRichMessage", "editMessageText"])


if __name__ == "__main__":
    unittest.main()
