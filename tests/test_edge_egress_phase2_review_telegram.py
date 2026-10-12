"""Telegram review/receipt flow cannot execute, replay or cross a chat.

Only isolated callback_handler AST is executed; no bot service, OS, or DB calls.
"""
import asyncio
import sys
import time
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock

from edge_egress_phase2_review import (
    OperatorReview, issue_ticket, acknowledge_ticket, review_html,
)
from edge_egress_v1_console import EgressConsoleHold

if sys.version_info >= (3, 12):
    from test_edge_egress_bot_integration import get_function


@unittest.skipIf(sys.version_info < (3, 12), "bot requires Python 3.12")
class Phase2ReviewCallbackTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.plan = OperatorReview(
            action="EDGE_PREPARE",edge_id="e7",ip="172.86.105.67",
            username="",current_host="",
            blockers=("F2_PAM_BOOT_RESCUE_NOT_ACCEPTED",),
            steps=("بازبینی",),checked_at=int(time.time()),
            digest="a"*64,affected_accounts=0,
        )
        self.msg = SimpleNamespace(reply_text=AsyncMock())
        self.query = SimpleNamespace(
            data="hpeg_review_edge_e7", answer=AsyncMock(),
            edit_message_text=AsyncMock(),message=self.msg,
        )
        self.ctx = SimpleNamespace(user_data={
            "role":"admin", "agent_id":0,
        })
        self.update = SimpleNamespace(
            callback_query=self.query,
            effective_user=SimpleNamespace(id=123),
            effective_chat=SimpleNamespace(id=-987),
        )
        def _read(*args,**kwargs):
            self.calls.append("read")
            return object()
        def _stage(*args,**kwargs):
            self.calls.append("stage")
            return object()
        def _build(*args,**kwargs):
            self.calls.append("build")
            return self.plan
        self.handler = get_function("callback_handler", {
            "is_auth": lambda context: True,
            "asyncio":asyncio,
            "_v2ray_management_target_from_callback":lambda *_:None,
            "classify_edge_callback":lambda *_:None,
            "edge_id_checked":lambda e:e if e=="e7" else (
                (_ for _ in ()).throw(EgressConsoleHold("BAD_EDGE"))),
            "read_egress_dashboard":_read,
            "get_egress_card":lambda *_:object(),
            "inspect_local_stage":_stage,
            "build_egress_operator_review":_build,
            "egress_review_html":review_html,
            "issue_egress_review_ticket":issue_ticket,
            "acknowledge_egress_review_ticket":acknowledge_ticket,
            "db_conn":lambda:None,
            "time":time,
            "re":__import__("re"),
            "esc":lambda x:x,
            "EgressConsoleHold":EgressConsoleHold,
            "log":SimpleNamespace(exception=lambda *_args,**kw:None),
            "InlineKeyboardButton":lambda label,callback_data:
                (label,callback_data),
            "InlineKeyboardMarkup":lambda rows:rows,
        })

    def invoke(self):
        asyncio.run(self.handler(self.update,self.ctx))

    def test_operator_read_receipt_consumes_single_ticket(self):
        self.invoke()
        self.assertEqual(self.calls,["read","stage","build"])
        ticket=self.ctx.user_data["egress_operator_review_ticket"]
        self.assertIn("HOLD",self.query.edit_message_text.await_args.args[0])
        self.query.data="hpeg_ack_"+ticket.token
        self.query.edit_message_text.reset_mock()
        self.invoke()
        self.assertNotIn("egress_operator_review_ticket",self.ctx.user_data)
        self.assertIn("REVIEW_ACKNOWLEDGED_NO_EXECUTION",
                      self.query.edit_message_text.await_args.args[0])
        self.query.edit_message_text.reset_mock()
        self.invoke()
        self.assertIn("HOLD",self.query.edit_message_text.await_args.args[0])
        self.assertEqual(self.calls,["read","stage","build",
                                     "read","stage","build"])

    def test_unchanged_nonce_different_chat_cannot_confirm(self):
        self.invoke()
        ticket=self.ctx.user_data["egress_operator_review_ticket"]
        self.query.data="hpeg_ack_"+ticket.token
        self.update.effective_chat.id=-333
        self.invoke()
        self.assertIn("HOLD",self.query.edit_message_text.await_args.args[0])
        self.assertNotIn("egress_operator_review_ticket",self.ctx.user_data)

    def test_changed_review_blocks_ack(self):
        self.invoke()
        ticket=self.ctx.user_data["egress_operator_review_ticket"]
        self.plan=OperatorReview(**{
            **vars(self.plan),"digest":"b"*64,
        })
        self.query.data="hpeg_ack_"+ticket.token
        self.invoke()
        self.assertIn("HOLD",self.query.edit_message_text.await_args.args[0])

    def test_non_admin_cannot_even_prepare_a_review(self):
        self.ctx.user_data["role"]="agent"
        self.invoke()
        self.msg.reply_text.assert_awaited_once()
        self.assertEqual(self.calls,[])
        self.assertNotIn("egress_operator_review_ticket",self.ctx.user_data)


if __name__=="__main__":
    unittest.main()
