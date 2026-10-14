"""M4 actual existing-bot wizard; small Persian UI, admin role before scan."""
from __future__ import annotations
from pathlib import Path
import re
import unittest

from edge_egress_k2_m4_telegram import (
    M4UIHold,parse_callback,select_input,home_html,home_buttons,
    prompt_html,preview_html,preview_buttons,failure_html,
)
from edge_egress_k2_m4_operator import inspect_telegram_migration
from edge_egress_k2_migration_inventory import (
    LiveIngressWitness,select_migration,
)
from tests.test_edge_egress_k2_migration_inventory import (
    K2M1InventoryTests,NOW,SOURCE,TARGET,
)


class M4PresentationTests(unittest.TestCase):
    def test_callback_is_bounded_and_edge_scoped(self):
        self.assertEqual(parse_callback("hpeg_m4_home_e9"),("home","e9"))
        for v in (
            "hpeg_m4_home_../e9","hpeg_m4_execute_e9",
            "hpeg_m4_home_e9;rm -rf","hpeg_m4_single_",
            "hpeg_m4_yes_e9","hpeg_m4_home_"+("a"*75),
        ):
            with self.subTest(v=v),self.assertRaises(M4UIHold):
                parse_callback(v)

    def test_one_and_ten_are_strictly_selected(self):
        s=select_input("SINGLE","nvl0555","e9")
        self.assertEqual(s.usernames,("nvl0555",))
        b=select_input("BATCH","nvl0555، nvl0557\nnvl0558","e9")
        self.assertEqual(b.usernames,("nvl0555","nvl0557","nvl0558"))
        for mode,raw in (
            ("SINGLE","nvl0555,nvl0557"),
            ("BATCH","nvl0555,nvl0555"),
            ("BATCH","nvl0555; echo ROOT"),
            ("BATCH",",".join("nvl%04d"%i for i in range(11))),
            ("SINGLE","@nvl0555"),
            ("BATCH","*"),
        ):
            with self.subTest(mode=mode,raw=raw),self.assertRaises(M4UIHold):
                select_input(mode,raw,"e9")

    def test_two_column_ui_short_and_without_implementation_words(self):
        rows=home_buttons("e9")
        self.assertTrue(all(len(row)<=2 for row in rows))
        self.assertEqual(rows[0][0][1],"hpeg_m4_single_e9")
        self.assertEqual(rows[0][1][1],"hpeg_m4_batch_e9")
        self.assertIn("انتقال کاربران",home_html("e9"))
        self.assertIn("nvl0555",prompt_html("e9","SINGLE"))
        self.assertIn("۱۰",prompt_html("e9","BATCH"))
        for callback in (x[1] for row in rows+preview_buttons("e9") for x in row):
            self.assertLessEqual(len(callback.encode()),64)
        for word in ("P3", "F4", "6G", "BootGuard", "UID"):
            self.assertNotIn(word,home_html("e9"))

    def test_untrusted_username_html_never_injected(self):
        self.assertNotIn("<script>",failure_html())


class M4OperatorReadOnlyTests(unittest.TestCase):
    def setUp(self):
        self.fx=K2M1InventoryTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)

    def test_absent_witness_must_be_hold_even_if_db_host_looks_valid(self):
        selection=select_input("SINGLE","nvl0555","e9")
        preview=inspect_telegram_migration(
            self.fx.db,selection,now=NOW,
            uid_lookup=lambda n:self.fx.uids[n],geteuid=lambda:1000,
            session_provider=None,
        )
        self.assertFalse(preview.inventory_clear)
        self.assertIn("SOURCE_INGRESS_NOT_ATTESTED",
                      preview.selected_issues)
        self.assertIn("نیازمند بررسی",preview_html(preview))
        self.assertFalse(preview.can_execute)

    def test_attested_source_without_session_provider_still_hold(self):
        selection=select_input("SINGLE","nvl0555","e9")
        witness=lambda name:LiveIngressWitness(
            name,"s8",SOURCE,NOW-1,"INDEPENDENT_LIVE",
        )
        snapshot=inspect_telegram_migration(
            self.fx.db,selection,now=NOW,
            uid_lookup=lambda name:self.fx.uids[name],
            source_provider=witness,geteuid=lambda:1000,
        )
        self.assertIn("SESSION_STATE_NOT_ATTESTED",snapshot.selected_issues)
        self.assertFalse(snapshot.inventory_clear)

    def test_independent_source_session_and_f4_preview_never_executes(self):
        selection=select_input("SINGLE","nvl0555","e9")
        witness=lambda name:LiveIngressWitness(
            name,"s8",SOURCE,NOW-1,"INDEPENDENT_LIVE",
        )
        snapshot=inspect_telegram_migration(
            self.fx.db,selection,now=NOW,
            uid_lookup=lambda name:self.fx.uids[name],
            source_provider=witness,
            session_provider=lambda n,u:0,geteuid=lambda:1000,
        )
        self.assertTrue(snapshot.inventory_clear)
        self.assertFalse(snapshot.can_execute)
        self.assertIn("غیرفعال",preview_html(snapshot))


class M4BotBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bot=(Path(__file__).resolve().parents[1]/
                 "bot_final_v49-2.py").read_text(encoding="utf-8")

    def test_existing_callback_handler_and_admin_gate(self):
        start=self.bot.index('    elif d.startswith("hpeg_m4_"):')
        end=self.bot.index('    elif d.startswith("hpeg_transfer_"):',start)
        handler=self.bot[start:end]
        self.assertIn("k2_m4_parse_callback(d)",handler)
        self.assertLess(handler.index("if role != 'admin':"),
                        handler.index("k2_m4_readonly_preview"))
        self.assertIn("k2_m4_preview_html",handler)
        self.assertNotIn("Existing6GGuardedExecutor(",handler)
        self.assertNotIn("run_migration_wave(",handler)
        self.assertNotIn("subprocess",handler)

    def test_text_handler_before_legacy_edge_wizard_and_admin_checked(self):
        start=self.bot.index("    if state in ('K2_M4_SINGLE', 'K2_M4_BATCH'):")
        end=self.bot.index("    # D1-C2B: a protected-mode legacy Edge",start)
        handler=self.bot[start:end]
        self.assertLess(handler.index("if role != 'admin':"),
                        handler.index("k2_m4_readonly_preview"))
        self.assertIn("k2_m4_select_input(mode,text,target)",handler)
        self.assertNotIn("ExecutionTicket",handler)
        self.assertNotIn("passwd",handler)

    def test_existing_edge_transfer_panel_links_to_new_ui(self):
        from edge_egress_k2_final_integration import (
            transfer_preview_buttons,TransferPreview,
        )
        # Binding is part of real imported production presenter.
        import inspect
        self.assertIn("hpeg_m4_home_",inspect.getsource(transfer_preview_buttons))

if __name__=="__main__":
    unittest.main()
