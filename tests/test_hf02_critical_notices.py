"""Critical route notifications: only super-admins and significant outcomes."""
import asyncio
import logging
import pathlib
import re
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from critical_operation_notice import EVENTS, _recipients, format_critical_notice, send_critical_notice

ROOT = pathlib.Path(__file__).resolve().parents[1]


class FakeBot:
    def __init__(self, fail=False):
        self.sent = []
        self.fail = fail

    async def send_message(self, *, chat_id, text, parse_mode):
        self.sent.append((chat_id, text, parse_mode))
        if self.fail:
            raise ConnectionError("INTERNAL_SECRET_TEST")


class CriticalNoticeTests(unittest.TestCase):
    def setUp(self):
        self.bot = FakeBot()
        self.app = SimpleNamespace(bot=self.bot, bot_data={})
        self.log = logging.getLogger("hf02-tests")

    def test_only_explicit_superadmins(self):
        self.assertEqual(_recipients(70, "71,70,0,garbage,-2,72"), (70,71,72))
        self.assertEqual(_recipients(70, ""), (70,))

    def test_invalid_recipients_are_rejected(self):
        self.assertEqual(_recipients("invalid", "invalid,0"), ())

    def test_formatted_messages_contain_tracking_and_not_debug(self):
        for event in EVENTS:
            msg = format_critical_notice(event, "NVL-REF123")
            for key in ("عملیات:", "وضعیت:", "گزارش:", "شناسه پیگیری:", "NVL-REF123"):
                self.assertIn(key,msg)
            for forbidden in ("HF01", "HF02", "traceback", "Core", "_cf_", "192.0.2.5"):
                self.assertNotIn(forbidden,msg)

    def test_reference_escaped(self):
        self.assertIn("&lt;x&gt;",format_critical_notice("ROUTE_CHANGED","<x>"))

    def test_only_superadmin_receives_route_change(self):
        with patch.dict("os.environ", {"NVL_CRITICAL_SUPERADMIN_IDS":"70,71"}):
            ref=asyncio.run(send_critical_notice(self.app,event="ROUTE_CHANGED",primary_super_admin_id=70,logger=self.log))
        self.assertRegex(ref,r"^NVL-[0-9A-F]{16}$")
        self.assertEqual([x[0] for x in self.bot.sent],[70,71])

    def test_blocked_repeats_deduplicated(self):
        async def scenario():
            a=await send_critical_notice(self.app,event="ROUTE_CHANGE_BLOCKED",primary_super_admin_id=70,dedupe_key="x",now=100)
            b=await send_critical_notice(self.app,event="ROUTE_CHANGE_BLOCKED",primary_super_admin_id=70,dedupe_key="x",now=120)
            c=await send_critical_notice(self.app,event="ROUTE_CHANGE_BLOCKED",primary_super_admin_id=70,dedupe_key="x",now=3800)
            return a,b,c
        a,b,c=asyncio.run(scenario())
        self.assertIsNotNone(a)
        self.assertIsNone(b)
        self.assertIsNotNone(c)
        self.assertEqual(len(self.bot.sent),2)

    def test_different_hosts_do_not_share_deduplication(self):
        async def scenario():
            await send_critical_notice(self.app,event="ROUTE_CHANGE_FAILED",primary_super_admin_id=70,dedupe_key="x",now=10)
            await send_critical_notice(self.app,event="ROUTE_CHANGE_FAILED",primary_super_admin_id=70,dedupe_key="y",now=20)
        asyncio.run(scenario())
        self.assertEqual(len(self.bot.sent),2)

    def test_success_always_delivered(self):
        async def scenario():
            await send_critical_notice(self.app,event="ROUTE_CHANGED",primary_super_admin_id=70)
            await send_critical_notice(self.app,event="ROUTE_CHANGED",primary_super_admin_id=70)
        asyncio.run(scenario())
        self.assertEqual(len(self.bot.sent),2)

    def test_telegram_errors_do_not_raise_or_throttle(self):
        self.app.bot = FakeBot(fail=True)
        async def scenario():
            one=await send_critical_notice(self.app,event="ROUTE_CHANGE_FAILED",primary_super_admin_id=70,dedupe_key="x",now=100)
            self.app.bot=FakeBot()
            two=await send_critical_notice(self.app,event="ROUTE_CHANGE_FAILED",primary_super_admin_id=70,dedupe_key="x",now=101)
            return one,two
        a,b=asyncio.run(scenario())
        self.assertIsNone(a)
        self.assertIsNotNone(b)

    def test_no_app_is_safe(self):
        self.assertIsNone(asyncio.run(send_critical_notice(None,event="ROUTE_CHANGED",primary_super_admin_id=70)))


class CriticalWiringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text=(ROOT/"bot_final_v49-2.py").read_text(encoding="utf-8")

    def test_auto_retirement_uses_notice_only_on_critical_route(self):
        x=self.text.split("async def _host_health_tick(app):",1)[1].split("async def _host_health_loop(app):",1)[0]
        self.assertEqual(x.count('"ROUTE_CHANGED"'),1)
        self.assertEqual(x.count('"ROUTE_CHANGE_FAILED"'),1)
        self.assertEqual(x.count('"ROUTE_CHANGE_BLOCKED"'),1)
        self.assertNotIn("یک Service endpoint از سرویس خارج شد",x)
        self.assertNotIn("remaining_active[0]",x)

    def test_manual_path_does_not_notify_on_unrelated_host(self):
        x=self.text.split('elif d.startswith("hpblk_")',1)[1].split('elif d.startswith("hpact_")',1)[0]
        self.assertEqual(x.count('"ROUTE_CHANGED"'),1)
        self.assertEqual(x.count('"ROUTE_CHANGE_FAILED"'),1)
        self.assertEqual(x.count('"ROUTE_CHANGE_BLOCKED"'),1)
