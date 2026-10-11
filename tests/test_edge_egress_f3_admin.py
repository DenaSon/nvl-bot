"""F3 Telegram preview must be admin-only, bounded and read-only."""
import asyncio
from contextlib import contextmanager
import sqlite3
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock

from edge_egress_f3_admin import render_assignment_preview
from edge_egress_f3_readiness import install_readiness_schema
from edge_egress_entrypoints import classify_edge_text
from edge_egress_lifecycle import PROTECTED_SETTING_KEY, PROTECTED_SETTING_DEFAULT

if sys.version_info >= (3,12):
    from test_edge_egress_bot_integration import get_function


class F3PreviewTests(unittest.TestCase):
    def setUp(self):
        self.c=sqlite3.connect(":memory:")
        self.c.executescript("""
            CREATE TABLE ssh_accounts (
              username TEXT,service_type TEXT,status TEXT);
            INSERT INTO ssh_accounts VALUES('nvl0557','ssh','🟢 فعال');
        """)
        install_readiness_schema(self.c)
        self.c.execute(
            "INSERT INTO edge_egress_readiness "
            "(edge_id,edge_ipv4,state,observed_ipv4,witness,probed_at,"
            "expires_at,last_operation_id) "
            "VALUES('fra1','216.126.229.12','VERIFIED_LAB',"
            "'216.126.229.12','PINNED_SHADOW_NAMESPACE',1000,1900,42)"
        )

    def tearDown(self): self.c.close()

    @contextmanager
    def conn(self):
        yield self.c

    def test_lab_verification_denies_real_assignment(self):
        text=render_assignment_preview(self.conn,"nvl0557 fra1")
        self.assertIn("LAB_PROOF_NOT_CUSTOMER_READY",text)
        self.assertIn("Read-only",text)
        self.assertIn("⛔️",text)

    def test_invalid_html_or_long_input_does_not_query(self):
        for value in ("<script> fra1","nvl0557 fra1 <img>","a"*200,
                      "nvl0557 bad edge"):
            with self.subTest(value=value):
                text=render_assignment_preview(
                    lambda: (_ for _ in ()).throw(
                        AssertionError("untrusted user input queried DB")),
                    value,
                )
                self.assertIn("نامعتبر",text)


@unittest.skipIf(sys.version_info < (3,12),"legacy bot AST needs Python 3.12")
class F3BotPreviewTests(unittest.TestCase):
    def test_admin_preview_input_is_one_shot_read_only(self):
        msg=SimpleNamespace(text="nvl0557 fra1",reply_text=AsyncMock())
        ctx=SimpleNamespace(user_data={
            "role":"admin","state":"EGRESS_F3_PLAN_INPUT",
        })
        handler=get_function("text_handler",{
            "classify_edge_text":classify_edge_text,
            "render_assignment_preview":lambda _db, _text:"READ_ONLY_RESULT",
            "db_conn":lambda:None,
            "asyncio":asyncio,
        })
        asyncio.run(handler(
            SimpleNamespace(message=msg,effective_chat=SimpleNamespace(id=1)),
            ctx,
        ))
        msg.reply_text.assert_awaited_once_with(
            "READ_ONLY_RESULT",parse_mode="HTML",
        )
        self.assertNotIn("state",ctx.user_data)

    def test_non_admin_is_denied_even_with_pending_state(self):
        msg=SimpleNamespace(text="nvl0557 fra1",reply_text=AsyncMock())
        ctx=SimpleNamespace(user_data={
            "role":"agent","state":"EGRESS_F3_PLAN_INPUT",
        })
        handler=get_function("text_handler",{
            "classify_edge_text":classify_edge_text,
            "render_assignment_preview":lambda *_:self.fail(
                "non-admin reached Egress preview"),
            "asyncio":asyncio,
        })
        asyncio.run(handler(
            SimpleNamespace(message=msg,effective_chat=SimpleNamespace(id=1)),
            ctx,
        ))
        self.assertIn("مدیر",msg.reply_text.await_args.args[0])
        self.assertNotIn("state",ctx.user_data)


if __name__=="__main__":
    unittest.main()
