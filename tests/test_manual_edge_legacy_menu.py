"""Regression: existing manual Edge IP route is usable without WebApp or opt-in.

The optional fresh-VPS SSH bootstrap stays separate. No DB, DNS, account or
Cloudzy provider operations are executed by this navigation test.
"""
import asyncio
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock

from manual_edge_wizard import ManualEdgeWizard
from manual_edge_rich import ManualRichHold, render_manual_card


class LegacyManualEntryTests(unittest.TestCase):
    def _wizard(self):
        def forbidden(*_args, **_kwargs):
            raise AssertionError("LEGACY_MENU_MUST_NOT_MUTATE_OR_PROBE")
        wizard = ManualEdgeWizard(
            db=forbidden, preflight=forbidden, provision=forbidden,
            verify=forbidden, probe=forbidden, nat=forbidden,
            queue=SimpleNamespace(), enabled=lambda: False,
            form_url=lambda: "",
        )
        wizard._view=AsyncMock(return_value=1)
        return wizard

    def _invoke(self, wizard, data, *, role="admin", actor=77, chat=77):
        asyncio.run(wizard.handle(
            SimpleNamespace(), SimpleNamespace(user_data={}), data,
            role=role, actor=actor, chat=chat,
            app=SimpleNamespace(bot=SimpleNamespace(token="123:TEST_TOKEN")),
        ))
        return wizard._view.await_args.args

    def test_disabled_fresh_install_still_exposes_existing_legacy_actions(self):
        for cb in ("apps_edge_manual_home", "apps_edge_manual_new"):
            with self.subTest(cb=cb):
                wizard=self._wizard()
                args=self._invoke(wizard,cb)
                self.assertIn("مدیریت دستی Edge", args[1])
                self.assertNotIn("فعال نشده", args[1])
                buttons=[entry[1] for row in args[2] for entry in row]
                self.assertEqual(buttons, ["hp_add","hp_menu","apps_cz_home"])
                self.assertNotIn("web_app",str(args[2]))
                # Exercise the REAL Rich rendering validation rather than
                # just mocking its delivery: hp* callbacks must be accepted.
                rich=render_manual_card(args[1],args[2])
                callbacks=[
                    button["callback_data"]
                    for block in rich["blocks"] if block["type"]=="buttons"
                    for button in block["buttons"]
                ]
                self.assertEqual(callbacks,buttons)

    def test_rich_renderer_does_not_allow_disabled_legacy_mutations(self):
        for bad in ("hpdef_1.2.3.4", "hpdef_migrate_1.2.3.4",
                    "hpdefmig_yes_1.2.3.4", "hp_del", "hp_addedge"):
            with self.subTest(callback=bad), self.assertRaises(ManualRichHold):
                render_manual_card("بررسی", [[("اجرا",bad)]])

    def test_unauthorized_does_not_expose_legacy_mutating_cta(self):
        for role,actor,chat in [("member",77,77),("admin",77,78)]:
            with self.subTest(role=role,actor=actor,chat=chat):
                wizard=self._wizard()
                args=self._invoke(wizard,"apps_edge_manual_home",
                                  role=role,actor=actor,chat=chat)
                self.assertIn("فقط مدیر",args[1])
                self.assertNotIn("hp_add",str(args[2]))
                self.assertNotIn("hp_menu",str(args[2]))

    def test_stale_bootstrap_callback_never_restarts_installer(self):
        wizard=self._wizard()
        args=self._invoke(wizard,"apps_edge_manual_password_op-old")
        self.assertIn("مدیریت دستی Edge",args[1])
        self.assertIn("hp_menu",[button[1] for row in args[2] for button in row])


if __name__=="__main__":
    unittest.main()
