"""Native IP+SSH management port+password intake; no Cloudzy/HTTPS effects."""
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock,Mock
import unittest

from manual_edge_wizard import ManualEdgeWizard


class PrivateIntakeTests(unittest.IsolatedAsyncioTestCase):
    def wizard(self):
        calls=[]
        w=ManualEdgeWizard(
            db=lambda:None,preflight=lambda:(2252,"pub"),
            provision=lambda *_:None,verify=lambda *_:None,
            probe=lambda *_:None,nat=lambda *_:None,
            queue=SimpleNamespace(),now=lambda:100,
            is_core_host=lambda ip:False,
            enabled=lambda:False,form_url=lambda:"")
        w._view=AsyncMock(return_value=42)
        w._tls_port=lambda:2088
        w.journal.set_server=lambda *a: calls.append(a)
        w.journal.get=lambda op:{
            "id":op,"status":"READY_INSTALL","actor":77,"chat":77}
        w.journal.cancel_draft=lambda *a: calls.append(("cancel",a))
        return w,calls

    def update(self,password=None,deletion_error=None):
        msg=SimpleNamespace(
            delete=AsyncMock(side_effect=deletion_error),
            reply_text=AsyncMock(return_value=1))
        chat=SimpleNamespace(send_message=AsyncMock(return_value=1))
        return SimpleNamespace(message=msg,effective_chat=chat)

    def context(self,stage,state):
        return SimpleNamespace(user_data={
            "state":state,
            "manual_edge_session":{
                "op":"a"*32,"actor":77,"chat":77,"stage":stage,
                "expires":500
            }
        })

    def app(self):
        coroutines=[]
        def spawn(coro):
            coroutines.append(coro)
            coro.close()
        return SimpleNamespace(
            bot=SimpleNamespace(token="123:TEST"),
            create_task=Mock(side_effect=spawn)),coroutines

    async def test_valid_ip_then_port_records_server_no_webapp(self):
        w,calls=self.wizard()
        u=self.update()
        ctx=self.context("server_ip","MANUAL_EDGE_IP")
        app,_=self.app()
        await w.receive_text(u,ctx,"MANUAL_EDGE_IP","8.8.8.8",
                             actor=77,chat=77,role="admin",app=app)
        self.assertEqual(ctx.user_data["state"],"MANUAL_EDGE_PORT")
        self.assertEqual(ctx.user_data["manual_edge_candidate_ip"],"8.8.8.8")
        await w.receive_text(u,ctx,"MANUAL_EDGE_PORT","22",
                             actor=77,chat=77,role="admin",app=app)
        self.assertEqual(calls,[
            ("a"*32,77,77,"8.8.8.8",22)
        ])
        self.assertNotIn("state",ctx.user_data)
        self.assertNotIn("manual_edge_session",ctx.user_data)
        self.assertIn("اثر انگشت",w._view.await_args.args[1])
        self.assertNotIn("web_app",str(w._view.await_args.args))

    async def test_password_deleted_before_dispatch_never_persisted(self):
        w,calls=self.wizard()
        ctx=self.context("password","MANUAL_EDGE_PASSWORD")
        u=self.update()
        app,coros=self.app()
        secret="/DEMO_ROOT_PASSWORD_DO_NOT_LOG"
        await w.receive_text(u,ctx,"MANUAL_EDGE_PASSWORD",secret,
                             actor=77,chat=77,role="admin",app=app)
        u.message.delete.assert_awaited_once()
        self.assertEqual(len(coros),1)
        self.assertNotIn(secret,str(ctx.user_data))
        self.assertNotIn("state",ctx.user_data)
        self.assertIn("آغاز",w._view.await_args.args[1])

    async def test_bot_routes_command_shaped_secret_before_commandhandlers(self):
        from pathlib import Path
        source=(Path(__file__).resolve().parents[1]/
                "bot_final_v49-2.py").read_text(encoding="utf-8")
        self.assertIn("async def _manual_edge_command_intake",source)
        self.assertIn("raise ApplicationHandlerStop",source)
        sensitive=source.index("filters.TEXT & filters.COMMAND, _manual_edge_command_intake")
        ordinary=source.index('app.add_handler(CommandHandler("start"')
        self.assertLess(sensitive,ordinary)
        self.assertIn("group=-1",source[sensitive:sensitive+140])
        self.assertNotIn('log.error("خطای پردازش‌نشده در آپدیت %s:"',source)
        self.assertIn("type(context.error).__name__",source)


    async def test_delete_failure_never_runs_remote_install(self):
        w,_=self.wizard()
        ctx=self.context("password","MANUAL_EDGE_PASSWORD")
        u=self.update(deletion_error=RuntimeError("CANNOT_DELETE"))
        app,coros=self.app()
        await w.receive_text(
            u,ctx,"MANUAL_EDGE_PASSWORD","secret",
            actor=77,chat=77,role="admin",app=app)
        self.assertFalse(coros)
        self.assertNotIn("state",ctx.user_data)
        u.effective_chat.send_message.assert_awaited_once()

    async def test_expired_password_session_is_deleted_and_not_retried(self):
        w,_=self.wizard()
        ctx=self.context("password","MANUAL_EDGE_PASSWORD")
        ctx.user_data["manual_edge_session"]["expires"]=99
        u=self.update()
        app,coros=self.app()
        await w.receive_text(u,ctx,"MANUAL_EDGE_PASSWORD","secret",
                             actor=77,chat=77,role="admin",app=app)
        u.message.delete.assert_awaited_once()
        self.assertFalse(coros)
        self.assertNotIn("state",ctx.user_data)

    async def test_group_and_nonadmin_rejected(self):
        for role,actor,chat in [
            ("member",77,77),("admin",77,79)
        ]:
            with self.subTest(role=role,chat=chat):
                w,calls=self.wizard()
                ctx=self.context("server_ip","MANUAL_EDGE_IP")
                u=self.update()
                app,_=self.app()
                await w.receive_text(
                    u,ctx,"MANUAL_EDGE_IP","8.8.8.8",
                    actor=actor,chat=chat,role=role,app=app)
                self.assertEqual(calls,[])
                self.assertNotIn("state",ctx.user_data)

    async def test_cancel_unblocks_draft_without_install(self):
        w,calls=self.wizard()
        ctx=self.context("server_ip","MANUAL_EDGE_IP")
        app,_=self.app()
        await w.receive_text(
            self.update(),ctx,"MANUAL_EDGE_IP","/cancel",
            actor=77,chat=77,role="admin",app=app)
        self.assertEqual(calls,[("cancel",("a"*32,77,77))])
        self.assertNotIn("state",ctx.user_data)


if __name__=="__main__":
    unittest.main()
