"""D1-C2B2 read-only admin status view regression tests."""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
import sqlite3
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock

from edge_egress_status import (
    EgressRow, EgressStatus, read_egress_status, render_egress_status_html,
)
from edge_egress_inventory import ensure_schema

if sys.version_info >= (3, 12):
    from test_edge_egress_bot_integration import get_function


@contextmanager
def status_db(*, with_registry=False):
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("CREATE TABLE settings(key TEXT,value TEXT)")
        connection.execute(
            "INSERT INTO settings VALUES ('edge_egress_protected_mode','0')"
        )
        if with_registry:
            ensure_schema(connection)
            connection.execute(
                "INSERT INTO edge_egress_allocations("
                "edge_id,edge_public_ipv4,core_public_ipv4,tunnel_network,"
                "veth_network,route_table,edge_listen_port,edge_uplink,"
                "core_public_key,edge_public_key,status)"
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                ("fra1","216.126.229.12","209.200.246.198",
                 "10.78.100.0/30","10.78.101.0/30",1780,51832,"eth0",
                 "safe-public-core","safe-public-edge","STAGED"),
            )
        yield connection
    finally:
        connection.close()


class StatusReadOnlyTests(unittest.TestCase):
    def test_read_status_does_not_create_schema_or_change_settings(self):
        with status_db() as db:
            sql = []
            db.set_trace_callback(sql.append)
            @contextmanager
            def factory():
                yield db
            status = read_egress_status(factory)
            self.assertEqual(status.protected_setting,"0")
            self.assertFalse(status.schema_installed)
            self.assertEqual(status.registered_count,0)
            self.assertFalse(any(
                s.lstrip().upper().startswith(("INSERT","CREATE","UPDATE","ALTER","DELETE"))
                for s in sql
            ))
            self.assertIsNone(
                db.execute("SELECT name FROM sqlite_master WHERE name='edge_egress_allocations'")
                  .fetchone()
            )

    def test_registered_stage_never_claims_ready(self):
        with status_db(with_registry=True) as db:
            @contextmanager
            def factory():
                yield db
            status = read_egress_status(factory)
            self.assertTrue(status.schema_installed)
            self.assertEqual(status.registered_count,1)
            self.assertEqual(status.registrations[0].state,"STAGED")
            ui=render_egress_status_html(status)
            self.assertIn("STAGED",ui)
            self.assertIn("آزمایشی",ui)
            self.assertNotIn("READY",ui)
            self.assertNotIn("private",ui)
            self.assertNotIn("safe-public-core",ui)

    def test_invalid_flag_html_escaped_and_not_executable(self):
        status=EgressStatus("<b>invalid</b>",True,(
            EgressRow("<script>alert(1)</script>","1.1.1.1","STAGED"),),1)
        ui=render_egress_status_html(status)
        self.assertNotIn("<script>",ui)
        self.assertIn("&lt;script&gt;",ui)
        self.assertIn("نامعتبر",ui)


@unittest.skipIf(sys.version_info < (3,12),"NVL bot requires Python 3.12 syntax")
class AdminStatusCallbackTests(unittest.TestCase):
    def run_handler(self,role):
        status=EgressStatus("0",False,(),0)
        q=SimpleNamespace(
            data="hpeg_status",answer=AsyncMock(),
            edit_message_text=AsyncMock(),
            message=SimpleNamespace(reply_text=AsyncMock())
        )
        callback=get_function("callback_handler",{
            "is_auth": lambda context: True,
            "_v2ray_management_target_from_callback": lambda d,ctx: None,
            "asyncio": asyncio,
            "classify_edge_callback":lambda _:None,
            "read_egress_status": lambda conn: status,
            "render_egress_status_html": render_egress_status_html,
            "db_conn":lambda:None,
            "InlineKeyboardButton":lambda label,callback_data: (label,callback_data),
            "InlineKeyboardMarkup":lambda rows:rows
        })
        ctx=SimpleNamespace(user_data={"role":role,"agent_id":0})
        # Non-admin role here should not reach any actual API or database code.
        asyncio.run(callback(SimpleNamespace(callback_query=q),ctx))
        return q

    def test_admin_can_open_read_only_status(self):
        q=self.run_handler("admin")
        q.answer.assert_awaited_once()
        q.edit_message_text.assert_awaited_once()
        self.assertIn("Egress Manager",q.edit_message_text.await_args.args[0])

    def test_non_admin_gets_denied_without_status_read(self):
        q=self.run_handler("accountant")
        q.message.reply_text.assert_awaited_once()
        q.edit_message_text.assert_not_awaited()


if __name__=="__main__":
    unittest.main()
