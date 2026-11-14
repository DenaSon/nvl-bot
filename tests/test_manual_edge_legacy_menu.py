"""Manual Edge entrypoint is native, owner-bound and without Cloudzy/WebApp."""
import asyncio
import os
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
import unittest

from manual_edge_wizard import ManualEdgeWizard
from manual_edge_rich import ManualRichHold, render_manual_card


class ManualEdgeEntryTests(unittest.TestCase):
    def wizard(self):
        wizard=ManualEdgeWizard(
            db=lambda: None,preflight=lambda:(2252,"ssh-pub"),
            provision=lambda *_: None,verify=lambda *_: None,
            probe=lambda *_: None,nat=lambda *_: None,
            queue=SimpleNamespace(),enabled=lambda:False,form_url=lambda:"")
        wizard.journal.latest=lambda *_,**kwargs: None
        wizard.journal.start=lambda *_,**kwargs: "a"*32
        wizard._view=AsyncMock(return_value=1)
        return wizard

    def invoke(self,wizard,data,role="admin",actor=77,chat=77,context=None):
        ctx=context or SimpleNamespace(user_data={})
        asyncio.run(wizard.handle(
            SimpleNamespace(),ctx,data,role=role,
            actor=actor,chat=chat,
            app=SimpleNamespace(bot=SimpleNamespace(token="123:TEST"))))
        return wizard._view.await_args.args,ctx

    def test_owner_sees_only_awg_when_legacy_flag_disabled(self):
        w=self.wizard()
        w.awg_preflight=lambda: (2252,"awg")
        w.awg_provision=lambda *a: None
        with patch.dict(os.environ, {"NVL_LEGACY_WG_UI_ENABLED":"0",
                                     "NVL_AWG_NEW_EDGE_ENABLED":"1"}):
            (q,txt,rows),_=self.invoke(w,"apps_edge_manual_home")
            self.assertIn("مدیریت Edge",txt)
            self.assertEqual(rows[0][0][1],"apps_edge_manual_new_awg")
            self.assertNotIn("WireGuard",str(rows))
            rendered=render_manual_card(txt,rows)
            self.assertNotIn("web_app",str(rendered))
            w._view.reset_mock()
            (q,txt,rows),ctx=self.invoke(w,"apps_edge_manual_new")
            self.assertIn("متوقف شد",txt)
            self.assertNotIn("state",ctx.user_data)
            w._view.reset_mock()
            (q,txt,rows),ctx=self.invoke(w,"apps_edge_manual_new_awg")
            self.assertIn("IP عمومی",txt)
            self.assertEqual(ctx.user_data["state"],"MANUAL_EDGE_IP")

    def test_legacy_reenables_only_with_explicit_flag(self):
        w=self.wizard()
        with patch.dict(os.environ, {"NVL_LEGACY_WG_UI_ENABLED":"1",
                                     "NVL_AWG_NEW_EDGE_ENABLED":"0"}):
            (q,txt,rows),_=self.invoke(w,"apps_edge_manual_home")
            self.assertEqual(rows[0][0][1],"apps_edge_manual_new")
            w._view.reset_mock()
            (q,txt,rows),ctx=self.invoke(w,"apps_edge_manual_new")
            self.assertIn("IP عمومی",txt)
            self.assertEqual(ctx.user_data["state"],"MANUAL_EDGE_IP")

    def test_nonadmin_or_group_sees_no_registration_action(self):
        for role,actor,chat in [("member",77,77),("admin",77,78)]:
            with self.subTest(role=role,actor=actor,chat=chat):
                w=self.wizard()
                (_,txt,rows),_=self.invoke(w,"apps_edge_manual_home",
                                           role=role,actor=actor,chat=chat)
                self.assertIn("فقط مدیر",txt)
                self.assertNotIn("apps_edge_manual_new",str(rows))

    def test_old_webapp_callback_never_recovers_credential(self):
        w=self.wizard()
        (_,txt,rows),_=self.invoke(w,"apps_edge_manual_form_done_abc")
        self.assertIn("عملیات متوقف شد",txt)
        self.assertNotIn("web_app",str(rows))

    def test_legacy_mutating_callbacks_remain_fenced(self):
        for bad in ("hpdef_1.2.3.4","hpdef_migrate_1.2.3.4",
                    "hpdefmig_yes_1.2.3.4","hp_del"):
            with self.subTest(bad=bad),self.assertRaises(ManualRichHold):
                render_manual_card("تست",[[("اجرا",bad)]])


if __name__=="__main__":
    unittest.main()
