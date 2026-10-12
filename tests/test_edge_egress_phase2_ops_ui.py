"""K2 Phase2-B2: e7 local Stage / per-Edge UID preview / paging contracts."""
import asyncio
from contextlib import contextmanager
from dataclasses import replace
import sqlite3
import sys
import time
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from edge_egress_phase2_console import (
    read_dashboard, get_card, dashboard_html, inspect_local_stage,
    stage_html, preview_uid_html,
)
from edge_egress_v1_console import EgressConsoleHold
from edge_egress_v1_ingress import IngressHold

if sys.version_info >= (3, 12):
    from test_edge_egress_bot_integration import get_function

E7_IP = "172.86.105.67"


class OperatorPreviewTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.addCleanup(self.conn.close)
        self.conn.executescript("""
            CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
            INSERT INTO settings VALUES('edge_egress_protected_mode','0');
            CREATE TABLE host_pool(host TEXT PRIMARY KEY,active INT,is_default INT);
            INSERT INTO host_pool VALUES('172.86.105.67',1,0);
            CREATE TABLE ssh_accounts(username TEXT PRIMARY KEY,host TEXT,
                                      service_type TEXT,status TEXT);
            INSERT INTO ssh_accounts VALUES(
               'nvl0557','104.194.144.195','ssh','🟢 فعال');
            CREATE TABLE failover_operations(id INTEGER,status TEXT);
        """)
        self.p = SimpleNamespace(edge_id="e7",edge_ipv4=E7_IP)
        self.db = lambda: self.conn
        self.board = lambda **args: read_dashboard(
            self.db, ingress_loader=lambda: (self.p,), now=1791844347,
            **args,
        )
        self.card = get_card(self.board(), "e7")

    def test_existing_e7_stage_without_db_allocation_can_be_inspected(self):
        sha = "a" * 64
        spec = SimpleNamespace(edge_id="e7",edge_public_ipv4=E7_IP)
        with patch("ops.edge_egress_v1_transport.stage_hash",
                   return_value=sha) as hashed, patch(
                   "ops.edge_egress_v1_transport.pinned",
                   return_value=(spec,"public_peer")
        ) as pinned, patch(
                   "ops.edge_egress_v1_transport.observe",return_value="UP"
        ) as seen:
            got = inspect_local_stage(
                self.card, geteuid=lambda: 0, now=lambda: 1791844347,
            )
        self.assertEqual(got.stage_state,"LOCAL_UNATTESTED")
        self.assertEqual(got.local_sha256,sha)
        self.assertEqual(got.tunnel_state,"UP")
        self.assertIn("Pin مستقل ندارد",stage_html(self.card,got))
        self.assertIn("F4 READY نیست",stage_html(self.card,got))
        self.assertTrue(hashed.called)
        self.assertTrue(pinned.called)
        self.assertTrue(seen.called)

    def test_mismatch_pin_refuses_tunnel_check_and_no_implicit_pin(self):
        new_card=replace(self.card,stage_pin="b"*64)
        spec=SimpleNamespace(edge_id="e7",edge_public_ipv4=E7_IP)
        with patch("ops.edge_egress_v1_transport.stage_hash",
                   return_value="a"*64), patch(
                   "ops.edge_egress_v1_transport.pinned",
                   return_value=(spec,"public_peer")), patch(
                   "ops.edge_egress_v1_transport.observe",
                   side_effect=AssertionError("observe after tampered pin")):
            got=inspect_local_stage(new_card,geteuid=lambda:0)
        self.assertEqual(got.stage_state,"PIN_MISMATCH")
        self.assertFalse(got.local_sha256)
        self.assertEqual(got.tunnel_state,"NOT_CHECKED")

    def test_missing_ingress_or_no_root_does_not_touch_stage_files(self):
        with patch("ops.edge_egress_v1_transport.stage_hash",
                   side_effect=AssertionError("untrusted read")):
            got=inspect_local_stage(
                replace(self.card,ingress_verified=False),geteuid=lambda:0)
            self.assertEqual(got.stage_state,"HOLD_IDENTITY")
            got=inspect_local_stage(self.card,geteuid=lambda:1000)
            self.assertEqual(got.stage_state,"ROOT_REQUIRED")

    def test_paging_not_limited_to_first_eight(self):
        peers=[self.p]+[
            SimpleNamespace(edge_id=f"e{i}",edge_ipv4=f"172.86.105.{i}")
            for i in range(10,20)
        ]
        first=read_dashboard(self.db,ingress_loader=lambda:peers,page=0)
        second=read_dashboard(self.db,ingress_loader=lambda:peers,page=1)
        self.assertEqual(first.total,11)
        self.assertEqual(len(first.cards),8)
        self.assertEqual(len(second.cards),3)
        self.assertIn("صفحه 2 از 2",dashboard_html(second))
        later=second.cards[-1].edge_id
        exact=read_dashboard(self.db,ingress_loader=lambda:peers,
                             only_edge=later)
        self.assertEqual(get_card(exact,later).edge_id,later)
        for page in (-1,True,129,"1"):
            with self.subTest(page=page), self.assertRaises(EgressConsoleHold):
                read_dashboard(self.db,ingress_loader=lambda:peers,page=page)

    def test_selected_uid_preview_uses_actual_db_and_always_holds(self):
        sql=[]
        self.conn.set_trace_callback(sql.append)
        output=preview_uid_html(self.db,self.card,"nvl0557")
        self.assertIn("nvl0557",output)
        self.assertIn("104.194.144.195",output)
        self.assertIn("e7",output)
        self.assertIn("EDGE_READINESS_SCHEMA_MISSING",output)
        self.assertIn("HOLD",output)
        self.assertFalse(any(
            q.lstrip().upper().startswith(
                ("INSERT","UPDATE","DELETE","ALTER","CREATE","DROP","REPLACE"))
            for q in sql
        ))
        self.conn.execute("INSERT INTO failover_operations VALUES(1,'RUNNING')")
        self.assertIn("SHARED_6G_OPERATION_BUSY",
                      preview_uid_html(self.db,self.card,"nvl0557"))

    def test_untrusted_input_cannot_query_account(self):
        for user in ("","admin;rm","a"*40,"<script>", "nvl0557 e7"):
            with self.subTest(user=user):
                self.assertIn("نامعتبر",preview_uid_html(
                    lambda: (_ for _ in ()).throw(
                        AssertionError("invalid input queried DB")),
                    self.card,user))
        out=preview_uid_html(
            lambda: (_ for _ in ()).throw(
                AssertionError("unsafe edge queried DB")),
            replace(self.card,ingress_verified=False),"nvl0557")
        self.assertIn("INGRESS_NOT_TRUSTED_OR_INACTIVE",out)


@unittest.skipIf(sys.version_info < (3,12), "requires bot Python3.12 syntax")
class Phase2UidTextHandlerTests(unittest.TestCase):
    def call(self,role="admin",deadline=None,username="nvl0557"):
        if deadline is None:
            deadline=time.time()+60
        data={
            "role":role,
            "state":"EGRESS_PHASE2_USER_PREVIEW",
            "egress_preview_edge_id":"e7",
            "egress_preview_expires":deadline,
        }
        q=SimpleNamespace(text=username,reply_text=AsyncMock())
        update=SimpleNamespace(
            message=q,effective_chat=SimpleNamespace(id=1),
            effective_user=SimpleNamespace(id=123),
        )
        globals={
            "classify_edge_text":lambda *_:None,
            "asyncio":asyncio,
            "time":time,
            "edge_id_checked":lambda eid:eid,
            "read_egress_dashboard":lambda *_args,**kw:object(),
            "get_egress_card":lambda *_args:object(),
            "egress_uid_preview_html":lambda *_args:"UID_PREVIEW_HOLD",
            "db_conn":lambda:None,
            "re":__import__("re"),
            "InlineKeyboardButton":lambda label,callback_data:(label,callback_data),
            "InlineKeyboardMarkup":lambda rows:rows,
        }
        fn=get_function("text_handler",globals)
        asyncio.run(fn(update,SimpleNamespace(user_data=data)))
        return q,data

    def test_admin_username_one_shot_no_uid_changes(self):
        q,context=self.call()
        self.assertEqual(q.reply_text.await_args.args[0], "UID_PREVIEW_HOLD")
        self.assertEqual(q.reply_text.await_args.kwargs["parse_mode"], "HTML")
        self.assertTrue(q.reply_text.await_args.kwargs["reply_markup"])
        self.assertEqual(context["egress_review_uid_selector"][:2],
                         ("e7","nvl0557"))
        self.assertNotIn("state",context)
        self.assertNotIn("egress_preview_edge_id",context)

    def test_stale_one_shot_holds_without_query(self):
        q,context=self.call(deadline=time.time()-1)
        self.assertIn("تمام شده",q.reply_text.await_args.args[0])
        self.assertNotIn("state",context)

    def test_non_admin_never_receives_preview(self):
        q,context=self.call(role="agent")
        self.assertIn("فقط مدیر",q.reply_text.await_args.args[0])
        self.assertNotIn("state",context)


if __name__=="__main__":
    unittest.main()
