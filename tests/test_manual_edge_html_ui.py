"""Telegram HTML manual Edge navigation; no Rich message edit or server effects."""
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock

from manual_edge_html import ManualHtmlDelivery
from manual_edge_rich import ManualRichHold
from telegram import InlineKeyboardMarkup, WebAppInfo


class HTMLDeliveryTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.send = AsyncMock(return_value=SimpleNamespace(message_id=1701))
        self.edit = AsyncMock()
        self.bot = SimpleNamespace(send_message=self.send, edit_message_text=self.edit)
        self.delivery = ManualHtmlDelivery(self.bot)
        self.context = SimpleNamespace(
            user_data={"manual_edge_rich_pointer":44},
        )

    async def test_native_html_and_keyboard_keep_callbacks_and_farsi(self):
        mid=await self.delivery.show(
            chat=77,context=self.context,
            text="🛟 <b>سرورهای دستی</b>\nIP: <code>8.8.8.8</code>",
            rows=[[("🚀 تبدیل به رله اصلی", "apps_edge_quick_select_8.8.8.8")],
                  [("↩️ مدیریت Edge","apps_cz_home")]],
        )
        self.assertEqual(mid,1701)
        kwargs=self.send.await_args.kwargs
        self.assertEqual(kwargs["parse_mode"],"HTML")
        self.assertEqual(kwargs["chat_id"],77)
        self.assertIn("<b>سرورهای دستی</b>",kwargs["text"])
        self.assertIsInstance(kwargs["reply_markup"],InlineKeyboardMarkup)
        self.assertEqual(
            kwargs["reply_markup"].inline_keyboard[0][0].callback_data,
            "apps_edge_quick_select_8.8.8.8")
        self.assertTrue(kwargs["protect_content"])
        self.edit.assert_not_awaited()
        self.assertEqual(self.context.user_data["manual_edge_rich_pointer"],44)

    async def test_navigating_old_cards_never_edits_or_requires_pointer(self):
        await self.delivery.show(
            chat=77,context=self.context,text="اول",
            rows=[[("رفرش","apps_edge_manual_home")]])
        await self.delivery.show(
            chat=77,context=self.context,text="دوم",
            rows=[[("بازگشت","apps_cz_home")]])
        self.assertEqual(self.send.await_count,2)
        self.edit.assert_not_awaited()
        self.assertEqual(self.context.user_data["manual_edge_rich_pointer"],44)

    async def test_legacy_https_webapp_validation_and_native_button(self):
        await self.delivery.send(
            chat=77,text="🔐 <b>فرم امن</b>",
            rows=[[("📝 ورود",{ "web_app": {
                "url":"https://secure.example/manual-edge/form?ticket=abc"}})]],
        )
        webapp=self.send.await_args.kwargs["reply_markup"].inline_keyboard[0][0].web_app
        self.assertIsInstance(webapp,WebAppInfo)
        self.assertEqual(webapp.url,
            "https://secure.example/manual-edge/form?ticket=abc")

    async def test_rejects_untrusted_callback_markup_and_invalid_html(self):
        for action in ("delete_everything", "apps_edge_manual_"+"x"*70):
            with self.subTest(action=action),self.assertRaises(ManualRichHold):
                await self.delivery.send(chat=77,text="تست",
                                         rows=[[("اقدام",action)]])
        with self.assertRaises(ManualRichHold):
            await self.delivery.send(chat=77,text="غیرمجاز <script>",
                                     rows=[[("بازگشت","apps_edge_manual_home")]])
        self.send.assert_not_awaited()

    async def test_uncertain_send_never_retries_and_does_not_mutate_context(self):
        self.send.side_effect=RuntimeError("TELEGRAM_DELIVERY_UNCERTAIN")
        with self.assertRaisesRegex(RuntimeError,"DELIVERY_UNCERTAIN"):
            await self.delivery.show(
                chat=77,context=self.context,text="خطا",
                rows=[[("بازگشت","apps_edge_manual_home")]])
        self.send.assert_awaited_once()
        self.edit.assert_not_awaited()
        self.assertEqual(self.context.user_data["manual_edge_rich_pointer"],44)

    async def test_standalone_background_delivery_has_normal_html_action(self):
        mid=await self.delivery.send(
            chat=77,text="✅ <b>نصب انجام شد</b>",
            rows=[[("وضعیت","apps_edge_manual_home")]])
        self.assertEqual(mid,1701)
        self.assertEqual(self.send.await_args.kwargs["parse_mode"],"HTML")


if __name__=="__main__":
    unittest.main()
