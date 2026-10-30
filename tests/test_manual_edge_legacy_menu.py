"""Manual Edge entrypoint is native, owner-bound and without Cloudzy/WebApp."""
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock
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
        wizard.journal.latest=lambda *_: None
        wizard.journal.start=lambda *_: "a"*32
        wizard._view=AsyncMock(return_value=1)
        return wizard

    def invoke(self,wizard,data,role="admin",actor=77,chat=77,context=None):
        ctx=context or SimpleNamespace(user_data={})
        asyncio.run(wizard.handle(
            SimpleNamespace(),ctx,data,role=role,
            actor=actor,chat=chat,
            app=SimpleNamespace(bot=SimpleNamespace(token="123:TEST"))))
        return wizard._view.await_args.args,ctx

    def test_owner_sees_new_wizard_even_when_legacy_flag_disabled(self):
        w=self.wizard()
        (q,txt,rows),_=self.invoke(w,"apps_edge_manual_home")
        self.assertIn("مدیریت سرورها",txt)
        self.assertEqual(rows[0][0][1],"apps_edge_manual_new")
        rendered=render_manual_card(txt,rows)
        self.assertNotIn("web_app",str(rendered))
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
