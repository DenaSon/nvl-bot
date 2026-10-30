"""Ordinary HTML+inline Telegram transport, navigation and failure safety."""
import unittest
from types import SimpleNamespace

from cloudzy_rich_transport import RichDeliveryHold
from manual_edge_html import ManualHtmlBotAPI, ManualHtmlDelivery
from manual_edge_rich import ManualRichHold


class HTMLDeliveryTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.calls=[]
        self.error=None
        def transport(method,body):
            self.calls.append((method,body))
            if self.error:
                raise self.error
            return {"message_id":1701}
        self.bot=SimpleNamespace(token="123:TEST_TOKEN")
        self.delivery=ManualHtmlDelivery(
            self.bot,api_factory=lambda token:ManualHtmlBotAPI(
                token,transport=transport))
        self.context=SimpleNamespace(user_data={
            "manual_edge_rich_pointer":44})

    async def test_native_html_keyboard_farsi_callbacks(self):
        mid=await self.delivery.show(
            chat=77,context=self.context,
            text="🛟 <b>سرورهای دستی</b>\nIP: <code>8.8.8.8</code>",
            rows=[[("🚀 تبدیل به رله اصلی","apps_edge_quick_select_8.8.8.8")],
                  [("↩️ مدیریت Edge","apps_cz_home")]],
        )
        self.assertEqual(mid,1701)
        self.assertEqual([x[0] for x in self.calls],["sendMessage"])
        body=self.calls[0][1]
        self.assertEqual(body["parse_mode"],"HTML")
        self.assertEqual(body["chat_id"],77)
        self.assertIn("<b>سرورهای دستی</b>",body["text"])
        self.assertEqual(
            body["reply_markup"]["inline_keyboard"][0][0]["callback_data"],
            "apps_edge_quick_select_8.8.8.8")
        self.assertTrue(body["protect_content"])
        self.assertEqual(self.context.user_data["manual_edge_rich_pointer"],44)

    async def test_stale_rich_pointer_does_not_edit(self):
        for text in ("اول","دوم"):
            await self.delivery.show(chat=77,context=self.context,text=text,
                rows=[[("بازگشت","apps_edge_manual_home")]])
        self.assertEqual([x[0] for x in self.calls],
                         ["sendMessage","sendMessage"])
        self.assertEqual(self.context.user_data["manual_edge_rich_pointer"],44)

    async def test_webapp_https_and_callback_validation(self):
        await self.delivery.send(chat=77,text="🔐 <b>فرم امن</b>",
            rows=[[("📝 فرم",{"web_app":{
                "url":"https://secure.example/manual-edge/form?ticket=abc"}})]])
        webapp=self.calls[0][1]["reply_markup"]["inline_keyboard"][0][0]["web_app"]
        self.assertEqual(webapp["url"],
                         "https://secure.example/manual-edge/form?ticket=abc")
        for action in ("delete_everything","apps_edge_manual_"+"x"*70):
            with self.assertRaises(ManualRichHold):
                await self.delivery.send(chat=77,text="تست",rows=[[("اجرا",action)]])
        for url in ("http://bad/manual-edge/form?ticket=a",
                    "https://example/other?ticket=a"):
            with self.assertRaises(ManualRichHold):
                await self.delivery.send(chat=77,text="تست",rows=[[("فرم",
                    {"web_app":{"url":url}})]])
        with self.assertRaises(ManualRichHold):
            await self.delivery.send(chat=77,text="غیرمجاز <script>",
                                     rows=[[("بازگشت","apps_edge_manual_home")]])
        self.assertEqual(len(self.calls),1)

    async def test_uncertain_delivery_is_not_retried(self):
        self.error=RichDeliveryHold("TELEGRAM_DELIVERY_UNCERTAIN")
        with self.assertRaises(RichDeliveryHold):
            await self.delivery.show(chat=77,context=self.context,text="خطا",
                rows=[[("بازگشت","apps_edge_manual_home")]])
        self.assertEqual(len(self.calls),1)
        self.assertEqual(self.context.user_data["manual_edge_rich_pointer"],44)

    async def test_invalid_receipt_is_rejected_without_state_change(self):
        self.delivery.api._transport=lambda *_: {"ok":True}
        with self.assertRaisesRegex(RichDeliveryHold,"RECEIPT_UNVERIFIED"):
            await self.delivery.send(chat=77,text="رسید",
                rows=[[("وضعیت","apps_edge_manual_home")]])

    async def test_background_completion_message_is_html(self):
        await self.delivery.send(
            chat=77,text="✅ <b>نصب انجام شد</b>",
            rows=[[("وضعیت","apps_edge_manual_home")]])
        self.assertEqual(self.calls[0][0],"sendMessage")
        self.assertEqual(self.calls[0][1]["parse_mode"],"HTML")


if __name__=="__main__":
    unittest.main()
